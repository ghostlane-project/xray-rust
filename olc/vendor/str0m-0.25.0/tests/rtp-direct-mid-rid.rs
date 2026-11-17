use std::collections::VecDeque;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::rtp::{ExtensionValues, RtpWrite, Ssrc};
use str0m::{Event, RtcError};

mod common;
use common::{connect_l_r, init_crypto_default, init_log, progress};

#[test]
pub fn rtp_direct_mid_rid() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();

    let mid = "aud".into();
    let rid = "hi".into();

    // In this example we are using MID and RID to identify the incoming media.
    let ssrc_tx: Ssrc = 42.into();

    l.direct_api().declare_media(mid, MediaKind::Audio);

    l.direct_api()
        .declare_stream_tx(ssrc_tx, None, mid, Some(rid));

    r.direct_api()
        .declare_media(mid, MediaKind::Audio)
        .expect_rid_rx(rid);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();

    let to_write: Vec<&[u8]> = vec![
        // 1
        &[0x1, 0x2, 0x3, 0x4],
        // 3
        &[0x9, 0xa, 0xb, 0xc],
        // 2
        &[0x5, 0x6, 0x7, 0x8],
    ];

    let mut to_write: VecDeque<_> = to_write.into();

    let mut write_at = l.last + Duration::from_millis(300);

    let mut counts: Vec<u64> = vec![0, 3, 1];

    loop {
        if l.start + l.duration() > write_at {
            write_at = l.last + Duration::from_millis(300);
            if let Some(packet) = to_write.pop_front() {
                let wallclock = l.start + l.duration();

                let mut direct = l.direct_api();
                let stream = direct.stream_tx(&ssrc).unwrap();

                let count = counts.remove(0);
                let time = (count * 1000 + 47_000_000) as u32;
                let seq_no = (47_000 + count).into();

                let exts = ExtensionValues {
                    audio_level: Some(-42 - count as i8),
                    voice_activity: Some(false),
                    ..Default::default()
                };

                stream.write_rtp(RtpWrite::new(pt, seq_no, time, wallclock, packet).ext_vals(exts));
            }
        }

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }

    let media: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::RtpPacket(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(media.len(), 3);

    assert!(l.media(mid).is_some());
    assert!(l.direct_api().stream_tx_by_mid(mid, None).is_some());
    l.direct_api().remove_media(mid);
    assert!(l.media(mid).is_none());
    assert!(l.direct_api().stream_tx_by_mid(mid, None).is_none());

    assert!(r.media(mid).is_some());
    assert!(r.direct_api().stream_rx_by_mid(mid, None).is_some());
    r.direct_api().remove_media(mid);
    assert!(r.media(mid).is_none());
    assert!(r.direct_api().stream_rx_by_mid(mid, None).is_none());

    Ok(())
}

/// Six seconds of video on a stream named by a mid and a rid, with no RTX;
/// what the receiver saw of the two on each packet, in order.
fn mid_and_rid_seen(keep: bool) -> Result<Vec<(bool, bool)>, RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();

    let mid = "vid".into();
    let rid = "l".into();
    let ssrc_tx: Ssrc = 43.into();

    l.direct_api().declare_media(mid, MediaKind::Video);
    l.direct_api()
        .declare_stream_tx(ssrc_tx, None, mid, Some(rid))
        .set_mid_rid_on_every_packet(keep);
    r.direct_api()
        .declare_media(mid, MediaKind::Video)
        .expect_rid_rx(rid);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let pt = l.params_vp8().pt();
    let mut seq = 1000_u64;
    let mut write_at = l.last;
    while l.duration() < Duration::from_secs(6) {
        if l.last >= write_at {
            write_at = l.last + Duration::from_millis(50);
            let wallclock = l.last;
            l.direct_api().stream_tx(&ssrc_tx).unwrap().write_rtp(RtpWrite::new(
                pt,
                seq.into(),
                seq as u32 * 4500,
                wallclock,
                [0x90, 0x80, seq as u8, 7],
            ));
            seq += 1;
        }
        progress(&mut l, &mut r)?;
    }

    Ok(r.events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::RtpPacket(p) => Some((
                p.header.ext_vals.mid == Some(mid),
                p.header.ext_vals.rid == Some(rid),
            )),
            _ => None,
        })
        .collect())
}

/// XRAY-PATCH: a stream told to keep them carries its mid and rid on every
/// packet, receiver reports or not. Left alone it drops both once the
/// receiver has reported on its SSRC, as upstream does.
#[test]
pub fn mid_and_rid_stay_on_every_packet_when_kept() -> Result<(), RtcError> {
    let upstream = mid_and_rid_seen(false)?;
    assert!(upstream.len() > 100, "{} packets", upstream.len());
    assert_eq!(upstream.first(), Some(&(true, true)));
    assert_eq!(
        upstream.last(),
        Some(&(false, false)),
        "no receiver report bound the SSRC in six seconds: the test proves nothing"
    );

    let kept = mid_and_rid_seen(true)?;
    assert!(kept.len() > 100, "{} packets", kept.len());
    let bare = kept.iter().filter(|seen| **seen != (true, true)).count();
    assert_eq!(bare, 0, "{bare} of {} packets without their mid or rid", kept.len());
    Ok(())
}

/// XRAY-PATCH: a send stream says how many written packets it still holds:
/// all of them until the session is polled, none once they have gone out.
#[test]
pub fn a_stream_counts_the_packets_it_holds() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();

    let mid = "vid".into();
    let ssrc_tx: Ssrc = 44.into();

    l.direct_api().declare_media(mid, MediaKind::Video);
    l.direct_api().declare_stream_tx(ssrc_tx, None, mid, None);
    r.direct_api().declare_media(mid, MediaKind::Video);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let pt = l.params_vp8().pt();
    assert_eq!(l.direct_api().stream_tx(&ssrc_tx).unwrap().queued_packets(), 0);
    let wallclock = l.last;
    for seq in 2000_u64..2005 {
        l.direct_api().stream_tx(&ssrc_tx).unwrap().write_rtp(RtpWrite::new(
            pt,
            seq.into(),
            seq as u32 * 4500,
            wallclock,
            [0x90, 0x80, seq as u8, 7],
        ));
    }
    assert_eq!(l.direct_api().stream_tx(&ssrc_tx).unwrap().queued_packets(), 5);

    let until = l.duration() + Duration::from_secs(1);
    while l.duration() < until {
        progress(&mut l, &mut r)?;
    }
    assert_eq!(l.direct_api().stream_tx(&ssrc_tx).unwrap().queued_packets(), 0);
    let arrived = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::RtpPacket(_)))
        .count();
    assert_eq!(arrived, 5);
    Ok(())
}
