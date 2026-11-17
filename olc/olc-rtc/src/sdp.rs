// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! What a remote description may need done to it before str0m takes it,
//! where str0m asks more of an SDP's order than pion does.
//!
//! pion finds a section by its mid and never looks at where it stands.
//! str0m holds two rules, both libwebrtc's:
//!
//! - the mids of `a=group:BUNDLE` come in the order of the sections
//!   (`Mid order not matching a=group`; RFC 9143 lets the two differ);
//! - a section keeps its place from one description to the next
//!   (`Changed order for m-line with mid`): a later offer may add sections
//!   only behind the ones it had.
//!
//! An SFU that puts a newcomer's section among the old ones, or adds its
//! mid at the end of the group wherever the section stands (the Go
//! engine's VK tests do both, `offerWithPeer`), is taken by pion and
//! refused by str0m. [`in_order`] gives str0m the same description with
//! the sections it knows first, in the order it knows them. That changes
//! nothing on the wire: every section is one bundle's, and an engine whose
//! answer to the far end is not str0m's own (VK Calls shapes its answer
//! from the offer) answers in the far end's order all the same.

/// The mids of `sdp`'s media sections, in their order. A section without
/// one gives an empty name.
#[must_use]
pub fn section_mids(sdp: &str) -> Vec<String> {
    split(sdp)
        .1
        .iter()
        .map(|s| mid_of(s).unwrap_or_default().to_owned())
        .collect()
}

/// `sdp` with its media sections in the order str0m will take after the
/// descriptions before it: those whose mids `earlier` names first, in
/// `earlier`'s order, then the rest as they come; and the mids of its
/// `a=group:BUNDLE` line in that same order. `earlier` is
/// [`section_mids`] of the description last applied, empty for the first.
///
/// The text comes back as it is when it has no media section, when a
/// section has no mid or two share one, or when a mid of `earlier` is
/// missing (str0m then judges the description itself). The group line is
/// left alone when it does not name exactly the sections' mids (a rejected
/// section is left out of it).
#[must_use]
pub fn in_order(sdp: &str, earlier: &[String]) -> String {
    let (session, sections) = split(sdp);
    let Some(mids) = sections
        .iter()
        .map(|s| mid_of(s))
        .collect::<Option<Vec<&str>>>()
    else {
        return sdp.to_owned();
    };
    let distinct = mids.iter().enumerate().all(|(i, m)| !mids[..i].contains(m));
    let all_kept = earlier.iter().all(|e| mids.contains(&e.as_str()));
    if sections.is_empty() || !distinct || !all_kept {
        return sdp.to_owned();
    }
    let mut order: Vec<usize> = earlier
        .iter()
        .filter_map(|e| mids.iter().position(|m| m == e))
        .collect();
    order.extend((0..mids.len()).filter(|i| !earlier.iter().any(|e| e == mids[*i])));

    let end = if sdp.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = String::with_capacity(sdp.len() + end.len());
    out.push_str(&grouped(session, &mids, &order));
    for (n, i) in order.iter().enumerate() {
        out.push_str(sections[*i]);
        // The last section may end without a line end; it may no longer be
        // the last.
        if !sections[*i].ends_with('\n') && n + 1 < order.len() {
            out.push_str(end);
        }
    }
    out
}

/// The session part and the media sections of `sdp`, each section from its
/// `m=` line to the next one's.
fn split(sdp: &str) -> (&str, Vec<&str>) {
    let mut starts: Vec<usize> = Vec::new();
    if sdp.starts_with("m=") {
        starts.push(0);
    }
    starts.extend(sdp.match_indices("\nm=").map(|(i, _)| i + 1));
    let Some(first) = starts.first().copied() else {
        return (sdp, Vec::new());
    };
    starts.push(sdp.len());
    (
        &sdp[..first],
        starts.windows(2).map(|w| &sdp[w[0]..w[1]]).collect(),
    )
}

fn mid_of(section: &str) -> Option<&str> {
    section
        .lines()
        .find_map(|l| l.strip_prefix("a=mid:"))
        .map(str::trim)
        .filter(|m| !m.is_empty())
}

/// The session part with its BUNDLE group's mids in `order`.
fn grouped(session: &str, mids: &[&str], order: &[usize]) -> String {
    const GROUP: &str = "a=group:BUNDLE ";
    let Some(line) = session.lines().find(|l| l.starts_with(GROUP)) else {
        return session.to_owned();
    };
    let listed: Vec<&str> = line[GROUP.len()..].split_whitespace().collect();
    let same = listed.len() == mids.len() && mids.iter().all(|m| listed.contains(m));
    if !same {
        return session.to_owned();
    }
    let ordered: Vec<&str> = order.iter().map(|i| mids[*i]).collect();
    session.replacen(line, &format!("{GROUP}{}", ordered.join(" ")), 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SDP: &str = "v=0\r\na=group:BUNDLE 0 1 2\r\nm=audio 9 X 0\r\na=mid:0\r\n\
                       m=video 9 X 96\r\na=mid:2\r\na=sendonly\r\nm=video 9 X 97\r\na=mid:1\r\n";

    fn names(mids: &[&str]) -> Vec<String> {
        mids.iter().map(|m| (*m).to_owned()).collect()
    }

    #[test]
    fn the_group_follows_the_sections() {
        assert_eq!(section_mids(SDP), names(&["0", "2", "1"]));
        assert_eq!(
            in_order(SDP, &[]),
            SDP.replace("BUNDLE 0 1 2", "BUNDLE 0 2 1")
        );
        // Bare line feeds stay bare.
        let lf = SDP.replace("\r\n", "\n");
        assert_eq!(
            in_order(&lf, &[]),
            lf.replace("BUNDLE 0 1 2", "BUNDLE 0 2 1")
        );
    }

    #[test]
    fn known_sections_come_first_in_the_order_known() {
        let want = "v=0\r\na=group:BUNDLE 0 1 2\r\nm=audio 9 X 0\r\na=mid:0\r\n\
                    m=video 9 X 97\r\na=mid:1\r\nm=video 9 X 96\r\na=mid:2\r\na=sendonly\r\n";
        assert_eq!(in_order(SDP, &names(&["0", "1"])), want);
        // What is in order already is not touched.
        assert_eq!(in_order(want, &names(&["0", "1"])), want);
        assert_eq!(in_order(want, &names(&["0", "1", "2"])), want);
        // A last section without its line end gets one when it moves up.
        let cut = SDP.strip_suffix("\r\n").unwrap();
        assert_eq!(in_order(cut, &names(&["0", "1"])), want);
    }

    #[test]
    fn what_cannot_be_ordered_is_left_alone() {
        for (sdp, earlier) in [
            // No media.
            ("v=0\r\ns=-\r\n", vec![]),
            ("", vec![]),
            // A section without a mid.
            (
                "v=0\r\nm=audio 9 X 0\r\nm=video 9 X 96\r\na=mid:1\r\n",
                vec![],
            ),
            // Two sections with one mid.
            (
                "v=0\r\nm=audio 9 X 0\r\na=mid:1\r\nm=video 9 X 96\r\na=mid:1\r\n",
                vec![],
            ),
            // A section known before is gone.
            (SDP, names(&["0", "7"])),
        ] {
            assert_eq!(in_order(sdp, &earlier), sdp);
        }
        // The sections move and the group stays when it leaves a section
        // out, or names one that is not there.
        for group in ["BUNDLE 0 1", "BUNDLE 0 1 2 7"] {
            let sdp = SDP.replace("BUNDLE 0 1 2", group);
            let moved = in_order(&sdp, &names(&["0", "1"]));
            assert!(moved.contains(&format!("a=group:{group}\r\n")), "{moved}");
            assert_eq!(section_mids(&moved), names(&["0", "1", "2"]));
        }
    }
}
