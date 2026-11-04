//! Имя и текст пресета `found-*`.

use super::{Found, NaiveStamp};
use crate::bypass::preset::{strip_assignments, FOUND_KEYS};
use crate::bypass::settings::valid_strategy_name;

const MAX_NAME: usize = 64;

/// `found-<основа>-<ГГГГММДД-ЧЧММ>`, при занятости — `-2`, `-3`, …; не длиннее 64 символов.
pub fn preset_name(base: &str, at: NaiveStamp, taken: &dyn Fn(&str) -> bool) -> String {
    let stamp = format!("{:04}{:02}{:02}-{:02}{:02}", at.y, at.mo, at.d, at.h, at.mi);
    let mut n = 1u32;
    loop {
        let suffix = if n == 1 {
            format!("-{stamp}")
        } else {
            format!("-{stamp}-{n}")
        };
        // "found-" + основа + суффикс ≤ 64.
        let room = MAX_NAME.saturating_sub("found-".len() + suffix.len());
        let base: String = base.chars().take(room).collect();
        let name = format!("found-{base}{suffix}");
        debug_assert!(valid_strategy_name(&name) || base.is_empty());
        if !taken(&name) {
            return name;
        }
        n += 1;
    }
}

/// Текст основы без прежних `FOUND_*` и с новым блоком в конце.
pub fn preset_text(base_text: &str, found: &Found, header: &str) -> String {
    // Основа уже разобрана при выборе; при ошибке границ оставляем текст как есть.
    let mut out =
        strip_assignments(base_text, &FOUND_KEYS).unwrap_or_else(|_| base_text.to_string());
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("# {header}\n"));
    for (key, val) in [
        ("FOUND_YOUTUBE", &found.youtube),
        ("FOUND_TLS", &found.tls),
        ("FOUND_HTTP", &found.http),
    ] {
        out.push_str(&format!("{key}=\"{}\"\n", val.as_deref().unwrap_or("")));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bypass::preset::parse_preset;

    fn at() -> NaiveStamp {
        NaiveStamp {
            y: 2026,
            mo: 11,
            d: 4,
            h: 19,
            mi: 46,
            s: 20,
        }
    }

    #[test]
    fn name_basic() {
        assert_eq!(
            preset_name("alt", at(), &|_| false),
            "found-alt-20261104-1946"
        );
    }

    #[test]
    fn name_suffix() {
        let taken = |n: &str| n == "found-alt-20261104-1946" || n == "found-alt-20261104-1946-2";
        assert_eq!(
            preset_name("alt", at(), &taken),
            "found-alt-20261104-1946-3"
        );
    }

    #[test]
    fn name_truncates() {
        let n = preset_name(&"a".repeat(70), at(), &|_| false);
        assert_eq!(n.len(), 64);
        assert!(n.ends_with("-20261104-1946"));
        assert!(valid_strategy_name(&n));
        let first = n.clone();
        let n2 = preset_name(&"a".repeat(70), at(), &|c| c == first);
        assert!(n2.len() <= 64 && n2.ends_with("-20261104-1946-2"));
    }

    #[test]
    fn text_keeps_base() {
        let base = "# alt\nNFQWS_ARGS=\"--a\n--b\"\n";
        let f = Found {
            tls: Some("--lua-desync=T".into()),
            ..Default::default()
        };
        let t = preset_text(base, &f, "Найдено");
        assert!(t.starts_with(base));
        assert!(t.ends_with(
            "# Найдено\nFOUND_YOUTUBE=\"\"\nFOUND_TLS=\"--lua-desync=T\"\nFOUND_HTTP=\"\"\n"
        ));
        assert_eq!(parse_preset(&t).unwrap().found_tls, "--lua-desync=T");
    }

    #[test]
    fn text_replaces_old_found() {
        let f = Found {
            tls: Some("--new1".into()),
            ..Default::default()
        };
        for base in [
            "NFQWS_ARGS=\"--a\"\nFOUND_TLS=\"--old\"\n",
            "FOUND_TLS=\"--old\n --old2\"\nNFQWS_ARGS=\"--a\"",
        ] {
            let t = preset_text(base, &f, "h");
            assert_eq!(t.matches("FOUND_TLS=").count(), 1, "{t}");
            assert!(!t.contains("--old"));
            let p = parse_preset(&t).unwrap();
            assert_eq!(p.found_tls, "--new1");
            assert_eq!(p.tcp, "--a");
        }
    }
}
