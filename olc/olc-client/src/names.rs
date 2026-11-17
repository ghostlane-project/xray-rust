// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The display name a participant shows in the room (`internal/names` at
//! 2d4266af): a first name and a surname drawn from the engine's own
//! dictionaries, so the tunnel's participant reads like an ordinary
//! attendee. `data/names` and `data/surnames` are the engine's
//! `internal/names/data` files, byte for byte (Apache-2.0, the olcRTC
//! authors).
//!
//! # Memory
//!
//! The dictionaries are the binary's own read-only data (18.7 KB); a draw
//! walks them and keeps nothing on the heap but the name it returns.

use rand::Rng;

/// `data/names`: one first name a line.
const FIRST: &str = include_str!("../data/names");
/// `data/surnames`: one surname a line.
const LAST: &str = include_str!("../data/surnames");

/// Go's fallback for an empty dictionary (`names.go:113`).
pub const FALLBACK: &str = "anonymous user";

/// The non-empty, trimmed lines of a dictionary (`parseLines`).
fn entries(raw: &str) -> impl Iterator<Item = &str> + Clone {
    raw.split('\n').map(str::trim).filter(|l| !l.is_empty())
}

/// One entry drawn uniformly, or `None` from an empty dictionary.
fn draw(raw: &str) -> Option<&str> {
    let all = entries(raw);
    let n = all.clone().count();
    if n == 0 {
        return None;
    }
    all.clone().nth(rand::thread_rng().gen_range(0..n))
}

/// `names.Generate`: `<first> <last>`, or [`FALLBACK`].
#[must_use]
pub fn generate() -> String {
    match (draw(FIRST), draw(LAST)) {
        (Some(first), Some(last)) => format!("{first} {last}"),
        _ => FALLBACK.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn the_dictionaries_are_the_engines() {
        // The counts of internal/names/data at 2d4266af.
        assert_eq!(entries(FIRST).count(), 735);
        assert_eq!(entries(LAST).count(), 576);
        assert_eq!(entries(FIRST).next(), Some("Аарон"));
        assert_eq!(entries(LAST).next(), Some("Абакумов"));
    }

    #[test]
    fn lines_are_trimmed_and_blank_ones_skipped() {
        // TestParseLines.
        assert_eq!(
            entries(" Alice \n\n Bob\n").collect::<Vec<_>>(),
            ["Alice", "Bob"]
        );
        assert_eq!(draw("\n \n"), None);
    }

    #[test]
    fn a_name_is_a_first_name_and_a_surname_from_the_dictionaries() {
        let first: HashSet<&str> = entries(FIRST).collect();
        let last: HashSet<&str> = entries(LAST).collect();
        let mut seen = HashSet::new();
        for _ in 0..64 {
            let name = generate();
            assert_ne!(name, FALLBACK);
            let surname = name.rsplit(' ').next().unwrap();
            let given = &name[..name.len() - surname.len() - 1];
            assert!(
                first.contains(given),
                "{given:?} is not a first name of the dictionary"
            );
            assert!(
                last.contains(surname),
                "{surname:?} is not a surname of the dictionary"
            );
            seen.insert(name);
        }
        assert!(seen.len() > 32, "64 draws gave only {} names", seen.len());
    }
}
