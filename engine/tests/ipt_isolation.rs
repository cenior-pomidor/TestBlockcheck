//! Архитектурный барьер вокруг iptables (наследник `nft_isolation`, issue #66 upstream).
//!
//! `blockcheckw` однажды уничтожил firewall роутера, потому что вызвать nft можно было откуда
//! угодно и как угодно. Здесь то же правило для Android: всё общение с iptables живёт в
//! `src/firewall/ipt.rs`, где операция выражается типами (`IptBatch`, `Table`), а не строкой.
//! А nft на Android нет вовсе — его вызов где бы то ни было означает регресс.

use std::path::{Path, PathBuf};

/// Все `.rs` в каталоге, рекурсивно.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Ищем ВЫЗОВЫ бинаря и его имя литералом. Упоминание в тексте для человека безобидно.
fn invokes(line: &str, binary: &str) -> bool {
    line.contains(&format!(r#"Command::new("{binary}")"#))
        || line.contains(&format!(r#"["{binary}""#))
        || line.contains(&format!(r#"= "{binary}";"#))
}

fn offenders(binary: &str, allowed: Option<&Path>) -> Vec<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files
        .iter()
        .filter(|p| allowed.is_none_or(|a| p.as_path() != a))
        .flat_map(|path| {
            let body = std::fs::read_to_string(path).unwrap_or_default();
            body.lines()
                .enumerate()
                .filter(|(_, line)| invokes(line, binary))
                .map(|(i, line)| format!("  {}:{}: {}", path.display(), i + 1, line.trim()))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn iptables_is_invoked_only_from_the_ipt_module() {
    let ipt = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/firewall/ipt.rs");
    for binary in ["iptables", "iptables-restore"] {
        let found = offenders(binary, Some(&ipt));
        assert!(
            found.is_empty(),
            "{binary} вызывается в обход src/firewall/ipt.rs:\n{}",
            found.join("\n")
        );
    }
}

#[test]
fn nft_is_not_invoked_anywhere() {
    let found = offenders("nft", None);
    assert!(
        found.is_empty(),
        "на Android nftables нет, а nft вызывается:\n{}",
        found.join("\n")
    );
}
