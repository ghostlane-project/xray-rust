//! Probes (b) and (c): str0m as the WebRTC end of a real carrier join, with the signalling
//! done by the engine's own Go code (go/mtslink, go/vkcalls drop-ins). The Go side runs
//! this and drives it over stdin/stdout, one line each way, SDP hex-encoded:
//!
//!   in  `OFFER mtslink`          out `OFFER <sdp-hex> <audio-player-mid>`
//!       MTS Link's layout (the engine's buildPeerConnection): the published VP9 camera,
//!       a microphone line, the one audio player, nine video receive slots.
//!   in  `ANSWER <sdp-hex>`       the SFU's answer to that offer
//!   in  `REMOTE_OFFER <sdp-hex>` out `ANSWER <sdp-hex>` (VK Calls: the SFU offers)
//!
//! then prints `ICE <state>`, `CONNECTED <ms>`, `MEM <phase> <json>`, the STUN/DTLS taps,
//! and `RESULT <json>` once it held the connection `--hold` seconds (counting RTP and
//! channels) or gave up after `--timeout`; exit 0 only when ICE and DTLS connected.
//!
//! Flags: --dtls dimpl|boring, --version 12|13|auto (12), --stun str0m|chrome (chrome),
//! --role client|server (client: an incoming actpass offer is answered as the DTLS client,
//! as Chrome answers and as VK's shaped answer says), --host-ip, --hold 10, --timeout 45.

use std::io::{BufRead, Write};
use std::net::IpAddr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use olc_spike_probe::peer::{rtc_config, Peer};
use olc_spike_probe::util::{chrome_ice_creds, default_ipv4, hex, unhex, Args};
use olc_spike_probe::{crypto, mem};
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::media::{Direction, MediaKind};
use str0m::Event;

fn main() {
    let code = match run() {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(e) => {
            eprintln!("FAIL: {e}");
            say(&format!("RESULT {{\"probe\":\"sdp-bridge\",\"connected\":false,\"error\":{}}}", serde_json::Value::from(e)));
            1
        }
    };
    std::process::exit(code);
}

/// One line to the driver, flushed.
fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

#[derive(Default)]
struct Tally {
    connected_ms: Option<u128>,
    ice: Vec<String>,
    media_added: usize,
    rtp_rx: usize,
    rtp_bytes: usize,
    channels: Vec<String>,
    keyframe_requests: usize,
}

fn run() -> Result<bool, String> {
    let args = Args::from_env();
    let dtls = args.or("dtls", "dimpl");
    let version = args.or("version", "12");
    let client_role = args.or("role", "client") == "client";
    let hold = Duration::from_secs(args.num("hold", 10)? as u64);
    let limit = Duration::from_secs(args.num("timeout", 45)? as u64);
    if args.or("stun", "chrome") == "chrome" {
        is::stun::set_stun_profile(is::stun::StunProfile::Chrome);
    }
    let ip: IpAddr = match args.get("host-ip") {
        Some(s) => s.parse().map_err(|_| format!("--host-ip: {s}"))?,
        None => default_ipv4().ok_or("no default IPv4 interface")?,
    };
    mem::report("start");

    let provider = crypto::provider(&dtls)?;
    let creds = chrome_ice_creds();
    let mut peer = Peer::with_config("carrier", ip, rtc_config(&provider, crypto::version(&version)?, &creds), creds.clone())
        .map_err(|e| format!("socket: {e}"))?;
    peer.add_host_candidate()?;

    // The driver's lines arrive on a thread of their own; the loop below never blocks on them.
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let start = Instant::now();
    let mut pending: Option<SdpPendingOffer> = None;
    let mut t = Tally::default();
    let mut negotiated = false;
    loop {
        if start.elapsed() > limit {
            break;
        }
        if let Some(c) = t.connected_ms {
            if start.elapsed() > Duration::from_millis(c as u64) + hold {
                break;
            }
        }
        while let Ok(line) = rx.try_recv() {
            let (cmd, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
            match cmd {
                "OFFER" if rest.trim() == "mtslink" => {
                    let mut api = peer.rtc.sdp_api();
                    // The web client's order (engine/mtslink buildPeerConnection).
                    let _camera = api.add_media(MediaKind::Video, Direction::SendOnly, Some("olc".into()), Some("olc-camera".into()), None);
                    let _mic = api.add_media(MediaKind::Audio, Direction::SendRecv, Some("olc".into()), Some("olc-mic".into()), None);
                    let player = api.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
                    for _ in 0..9 {
                        api.add_media(MediaKind::Video, Direction::RecvOnly, None, None, None);
                    }
                    let (offer, p) = api.apply().ok_or("str0m made no offer")?;
                    pending = Some(p);
                    let sdp = offer.to_sdp_string();
                    eprintln!("LOCAL_OFFER m-lines={} bytes={}", sdp.matches("\nm=").count(), sdp.len());
                    say(&format!("OFFER {} {player}", hex(sdp.as_bytes())));
                }
                "ANSWER" => {
                    let sdp = String::from_utf8(unhex(rest)?).map_err(|e| e.to_string())?;
                    eprintln!("REMOTE_ANSWER m-lines={} ice-lite={}", sdp.matches("\nm=").count(), sdp.contains("a=ice-lite"));
                    let answer = SdpAnswer::from_sdp_string(&sdp).map_err(|e| format!("the SFU's answer does not parse: {e}"))?;
                    let p = pending.take().ok_or("ANSWER before OFFER")?;
                    peer.rtc.sdp_api().accept_answer(p, answer).map_err(|e| format!("str0m refused the SFU's answer: {e}"))?;
                    negotiated = true;
                }
                "REMOTE_OFFER" => {
                    let raw = String::from_utf8(unhex(rest)?).map_err(|e| e.to_string())?;
                    eprintln!("REMOTE_OFFER m-lines={} ice-lite={} bytes={}", raw.matches("\nm=").count(), raw.contains("a=ice-lite"), raw.len());
                    let sdp = if client_role { raw.replace("a=setup:actpass", "a=setup:passive") } else { raw };
                    let offer = SdpOffer::from_sdp_string(&sdp).map_err(|e| format!("the SFU's offer does not parse: {e}"))?;
                    let answer = peer.rtc.sdp_api().accept_offer(offer).map_err(|e| format!("str0m refused the SFU's offer: {e}"))?;
                    let out = answer.to_sdp_string();
                    eprintln!("LOCAL_ANSWER m-lines={} bytes={}", out.matches("\nm=").count(), out.len());
                    say(&format!("ANSWER {}", hex(out.as_bytes())));
                    negotiated = true;
                }
                "QUIT" => return finish(&peer, &t, start),
                other => return Err(format!("unknown command {other:?}")),
            }
        }
        peer.pump()?;
        let got = peer.receive()?;
        peer.tick()?;
        while let Some(e) = peer.events.pop_front() {
            match e {
                Event::Connected => {
                    let ms = start.elapsed().as_millis();
                    t.connected_ms = Some(ms);
                    say(&format!("CONNECTED {ms}"));
                    mem::report("connected");
                }
                Event::IceConnectionStateChange(s) => {
                    t.ice.push(format!("{s:?}"));
                    say(&format!("ICE {s:?}"));
                }
                Event::MediaAdded(_) => t.media_added += 1,
                Event::RtpPacket(p) => {
                    t.rtp_rx += 1;
                    t.rtp_bytes += p.payload.len();
                }
                Event::KeyframeRequest(_) => t.keyframe_requests += 1,
                Event::ChannelOpen(_, label) => t.channels.push(label),
                _ => {}
            }
        }
        if !got {
            let wait = peer.timeout.saturating_duration_since(Instant::now()).min(Duration::from_millis(5));
            std::thread::sleep(if negotiated { wait } else { Duration::from_millis(5) });
        }
    }
    finish(&peer, &t, start)
}

fn finish(peer: &Peer, t: &Tally, start: Instant) -> Result<bool, String> {
    peer.taps.print("carrier");
    for h in crypto::handshakes_json() {
        eprintln!("HANDSHAKE {h}");
    }
    let m = mem::report("end");
    let ok = t.connected_ms.is_some();
    say(&format!(
        "RESULT {{\"probe\":\"sdp-bridge\",\"connected\":{ok},\"connected_ms\":{},\"elapsed_ms\":{},\"ice\":{},\"media_added\":{},\"rtp_rx\":{},\"rtp_bytes\":{},\"keyframe_requests\":{},\"channels\":{},\"tx_bytes\":{},\"rx_bytes\":{},\"mem\":{}}}",
        t.connected_ms.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
        start.elapsed().as_millis(),
        serde_json::Value::from(t.ice.clone()),
        t.media_added,
        t.rtp_rx,
        t.rtp_bytes,
        t.keyframe_requests,
        serde_json::Value::from(t.channels.clone()),
        peer.tx_bytes,
        peer.rx_bytes,
        m.json()
    ));
    Ok(ok)
}
