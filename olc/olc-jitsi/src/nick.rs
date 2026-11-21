// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Names and hosts the engine tidies before the library sees them
//! (`internal/engine/jitsi/nick.go`, `keepalive.go:124-136`).

/// The longest nick, in bytes (`maxNickLen`).
const MAX_NICK: usize = 16;

/// The Latin spelling of a Cyrillic letter (`cyrillicToLatin`).
fn translit(c: char) -> Option<&'static str> {
    Some(match c {
        'А' => "A",
        'а' => "a",
        'Б' => "B",
        'б' => "b",
        'В' => "V",
        'в' => "v",
        'Г' => "G",
        'г' => "g",
        'Д' => "D",
        'д' => "d",
        'Е' => "E",
        'е' => "e",
        'Ё' => "Yo",
        'ё' => "yo",
        'Ж' => "Zh",
        'ж' => "zh",
        'З' => "Z",
        'з' => "z",
        'И' => "I",
        'и' => "i",
        'Й' => "Y",
        'й' => "y",
        'К' => "K",
        'к' => "k",
        'Л' => "L",
        'л' => "l",
        'М' => "M",
        'м' => "m",
        'Н' => "N",
        'н' => "n",
        'О' => "O",
        'о' => "o",
        'П' => "P",
        'п' => "p",
        'Р' => "R",
        'р' => "r",
        'С' => "S",
        'с' => "s",
        'Т' => "T",
        'т' => "t",
        'У' => "U",
        'у' => "u",
        'Ф' => "F",
        'ф' => "f",
        'Х' => "Kh",
        'х' => "kh",
        'Ц' => "Ts",
        'ц' => "ts",
        'Ч' => "Ch",
        'ч' => "ch",
        'Ш' => "Sh",
        'ш' => "sh",
        'Щ' => "Shch",
        'щ' => "shch",
        'Ъ' | 'ъ' | 'Ь' | 'ь' => "",
        'Ы' => "Y",
        'ы' => "y",
        'Э' => "E",
        'э' => "e",
        'Ю' => "Yu",
        'ю' => "yu",
        'Я' => "Ya",
        'я' => "ya",
        _ => return None,
    })
}

/// A display name as a 7-bit slug: Cyrillic transliterated, other
/// non-ASCII dropped, runs of anything else one `-`, at most 16 bytes, no
/// `-` at either end (`sanitiseNick`).
#[must_use]
pub fn sanitise_nick(raw: &str) -> String {
    let mut b = String::with_capacity(MAX_NICK);
    let mut prev_dash = false;
    for c in raw.chars() {
        if b.len() >= MAX_NICK {
            break;
        }
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            b.push(c);
            prev_dash = false;
            continue;
        }
        if let Some(lat) = translit(c) {
            for l in lat.chars() {
                if b.len() >= MAX_NICK {
                    break;
                }
                b.push(l);
            }
            prev_dash = false;
            continue;
        }
        if !prev_dash && !b.is_empty() {
            b.push('-');
            prev_dash = true;
        }
    }
    b.trim_matches('-').to_owned()
}

/// A host without its scheme, path and outer slashes (`normaliseHost`).
#[must_use]
pub fn normalise_host(raw: &str) -> &str {
    let mut raw = raw.trim();
    if let Some(i) = raw.find("://") {
        raw = &raw[i + 3..];
    }
    raw = raw.strip_prefix("//").unwrap_or(raw);
    raw = raw.strip_suffix('/').unwrap_or(raw);
    match raw.find('/') {
        Some(i) => &raw[..i],
        None => raw,
    }
}

/// The XMPP domain of a bound JID, where the web host may differ from it;
/// `fallback` when the JID names none (`xmppDomain`).
#[must_use]
pub fn xmpp_domain<'a>(jid: &'a str, fallback: &'a str) -> &'a str {
    let Some((_, rest)) = jid.split_once('@') else {
        return fallback;
    };
    let domain = rest.split_once('/').map_or(rest, |(d, _)| d);
    if domain.is_empty() {
        fallback
    } else {
        domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TestSanitiseNick` (`internal/engine/jitsi/jitsi_test.go:245`).
    #[test]
    fn the_nick_table() {
        let cases = [
            ("alice", "alice"),
            ("Alice Smith", "Alice-Smith"),
            ("Конрад Олег", "Konrad-Oleg"),
            ("olcrtc-bot42", "olcrtc-bot42"),
            ("  bob  ", "bob"),
            ("$$$ %%%", ""),
            ("verylongnicknamethatexceedslimit", "verylongnickname"),
        ];
        for (raw, want) in cases {
            assert_eq!(sanitise_nick(raw), want, "{raw:?}");
        }
    }

    #[test]
    fn more_nicks() {
        // 16 bytes at most, a transliteration cut where it stands.
        assert_eq!(
            sanitise_nick("Щщщщщщщщщщ"),
            "ShchshchshchshchS".get(..16).unwrap()
        );
        assert_eq!(sanitise_nick("a!!!b"), "a-b");
        assert_eq!(sanitise_nick("日本語"), "");
        assert_eq!(sanitise_nick("--a--"), "a");
        assert_eq!(sanitise_nick("Ёж ъь"), "Yozh");
        assert_eq!(sanitise_nick("user_1"), "user_1");
        assert_eq!(sanitise_nick(&"a-".repeat(20)), "a-a-a-a-a-a-a-a");
    }

    /// `TestNormaliseHost` (`jitsi_test.go:21`).
    #[test]
    fn the_host_table() {
        let h = "meet.example.com";
        for (raw, want) in [
            (h.to_owned(), h),
            (format!("https://{h}"), h),
            (format!("https://{h}/"), h),
            (format!("https://{h}/path"), h),
            (format!("//{h}"), h),
            (format!("  https://{h}  "), h),
            (String::new(), ""),
        ] {
            assert_eq!(normalise_host(&raw), want, "{raw:?}");
        }
        assert_eq!(normalise_host("h/a/b"), "h");
    }

    /// `TestXMPPDomainTargetsVirtualhost` (`keepalive_test.go:295`).
    #[test]
    fn the_ping_goes_to_the_virtualhost() {
        let cases = [
            (
                "8307a4f4@meet.jitsi/T4i4s0jt",
                "meet.mamba.group",
                "meet.jitsi",
            ),
            ("uuid@meet.jitsi", "meet.mamba.group", "meet.jitsi"),
            ("", "meet.mamba.group", "meet.mamba.group"),
            ("node-only", "meet.handyweb.org", "meet.handyweb.org"),
            ("node@/resource", "meet.small-dm.ru", "meet.small-dm.ru"),
            ("node@meet.jitsi/", "fallback.host", "meet.jitsi"),
        ];
        for (jid, fallback, want) in cases {
            assert_eq!(xmpp_domain(jid, fallback), want, "{jid:?}");
        }
    }
}
