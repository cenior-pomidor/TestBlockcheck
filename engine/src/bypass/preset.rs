//! Разбор пресета `.conf` nfqws2-android без шелла.
//!
//! Пресет оригинала — шелл-файл с присваиваниями `КЛЮЧ="…"` (значение может занимать
//! несколько строк). Отсюда берутся только шесть ключей стратегии и необязательные лимиты
//! пакетов `NFQWS2_{TCP,UDP}_PKT_{OUT,IN}` (`get_strategy_packet_limits`); остальное —
//! настройки владельца, они живут отдельно. Значения возвращаются **сырыми**: известные
//! переменные (`KNOWN_VARS`) раскрывает `args::expand`, переменные, объявленные в самом
//! файле (как `ARGS_BLOCK16` в `MartinBacker.conf`), подставляются здесь.

use std::collections::HashMap;
use std::fmt;

/// Переменные окружения пресета, которые раскрывает сборка командной строки.
pub const KNOWN_VARS: [&str; 7] = [
    "LUA_DIR",
    "BLOBS_DIR",
    "LISTS_DIR",
    "LOG_DIR",
    "MODE_LIST",
    "MODE_ALL",
    "MODE_AUTO",
];

/// Лимиты пакетов, заданные пресетом поверх `PKT_LIMIT_*`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PktOverrides {
    pub tcp_out: Option<u16>,
    pub tcp_in: Option<u16>,
    pub udp_out: Option<u16>,
    pub udp_in: Option<u16>,
}

/// Стратегия из пресета: шесть ключей, значения сырые.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preset {
    pub base: String,
    pub tcp: String,
    pub quic: String,
    pub udp: String,
    pub ipset: String,
    pub custom: String,
    pub limits: PktOverrides,
}

/// Ошибка разбора с номером строки (с 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresetError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for PresetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "строка {}: {}", self.line, self.message)
    }
}

impl std::error::Error for PresetError {}

fn err(line: usize, message: impl Into<String>) -> PresetError {
    PresetError {
        line,
        message: message.into(),
    }
}

fn is_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(ch) if ch == '_' || ch.is_ascii_alphabetic())
        && c.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// Подставить переменные, объявленные в файле; известные оставить как есть; прочие — ошибка.
fn substitute(
    value: &str,
    line: usize,
    locals: &HashMap<String, String>,
) -> Result<String, PresetError> {
    let mut out = String::with_capacity(value.len());
    let bytes: Vec<char> = value.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != '$' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let (name, next) = if bytes.get(i + 1) == Some(&'{') {
            let end = bytes[i + 2..]
                .iter()
                .position(|&c| c == '}')
                .ok_or_else(|| err(line, "незакрытая ${…}"))?;
            (
                bytes[i + 2..i + 2 + end].iter().collect::<String>(),
                i + 3 + end,
            )
        } else {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] == '_' || bytes[j].is_ascii_alphanumeric()) {
                j += 1;
            }
            (bytes[i + 1..j].iter().collect::<String>(), j)
        };
        if name.is_empty() {
            out.push('$');
            i += 1;
            continue;
        }
        if KNOWN_VARS.contains(&name.as_str()) {
            out.push('$');
            out.push_str(&name);
        } else if let Some(v) = locals.get(&name) {
            out.push_str(v);
        } else {
            return Err(err(line, format!("неизвестная переменная ${name}")));
        }
        i = next;
    }
    Ok(out)
}

fn pkt_value(line: usize, raw: &str) -> Result<u16, PresetError> {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    match digits.parse::<u16>() {
        Ok(n) if (1..=100).contains(&n) => Ok(n),
        _ => Err(err(
            line,
            format!("лимит пакетов — число от 1 до 100: {raw}"),
        )),
    }
}

/// Разобрать текст пресета.
pub fn parse_preset(text: &str) -> Result<Preset, PresetError> {
    let mut preset = Preset::default();
    let mut locals: HashMap<String, String> = HashMap::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let lineno = i + 1;
        let raw = lines[i];
        let trimmed = raw.trim_start();
        // Лимиты пакетов оригинал читает и из закомментированных строк.
        let uncommented = trimmed.trim_start_matches(['#', ' ', '\t']);
        for (key, slot) in [
            ("NFQWS2_TCP_PKT_OUT=", 0usize),
            ("NFQWS2_TCP_PKT_IN=", 1),
            ("NFQWS2_UDP_PKT_OUT=", 2),
            ("NFQWS2_UDP_PKT_IN=", 3),
        ] {
            if let Some(v) = uncommented.strip_prefix(key) {
                let n = pkt_value(lineno, v)?;
                let l = &mut preset.limits;
                *[&mut l.tcp_out, &mut l.tcp_in, &mut l.udp_out, &mut l.udp_in][slot] = Some(n);
            }
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }
        let Some((name, rest)) = trimmed.split_once('=') else {
            return Err(err(lineno, format!("не присваивание: {}", trimmed.trim())));
        };
        if !is_name(name) {
            return Err(err(lineno, format!("не присваивание: {}", trimmed.trim())));
        }
        let (value, end_line) = if let Some(after) = rest.strip_prefix('"') {
            // Значение до закрывающей кавычки, возможно на следующих строках.
            let mut acc = String::new();
            let mut cur = after;
            let mut j = i;
            loop {
                if let Some(pos) = cur.find('"') {
                    acc.push_str(&cur[..pos]);
                    let tail = cur[pos + 1..].trim();
                    if !tail.is_empty() && !tail.starts_with('#') {
                        return Err(err(j + 1, format!("лишнее после кавычки: {tail}")));
                    }
                    break;
                }
                acc.push_str(cur);
                acc.push('\n');
                j += 1;
                if j >= lines.len() {
                    return Err(err(lineno, format!("незакрытая кавычка у {name}")));
                }
                cur = lines[j];
            }
            (acc, j)
        } else {
            let v = rest.split('#').next().unwrap_or("").trim();
            (v.trim_matches('\'').to_string(), i)
        };
        let value = substitute(&value, lineno, &locals)?;
        match name {
            "NFQWS_BASE_ARGS" => preset.base = value.clone(),
            "NFQWS_ARGS" => preset.tcp = value.clone(),
            "NFQWS_ARGS_QUIC" => preset.quic = value.clone(),
            "NFQWS_ARGS_UDP" => preset.udp = value.clone(),
            "NFQWS_ARGS_IPSET" => preset.ipset = value.clone(),
            "NFQWS_ARGS_CUSTOM" => preset.custom = value.clone(),
            _ => {}
        }
        if !KNOWN_VARS.contains(&name) {
            locals.insert(name.to_string(), value);
        }
        i = end_line + 1;
    }
    Ok(preset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundled() -> Vec<(String, String)> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../module/strategies");
        let mut out: Vec<(String, String)> = std::fs::read_dir(dir)
            .expect("module/strategies")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "conf"))
            .map(|p| {
                (
                    p.file_stem().unwrap().to_string_lossy().into_owned(),
                    std::fs::read_to_string(&p).unwrap(),
                )
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn every_bundled_preset_parses() {
        let all = bundled();
        assert_eq!(all.len(), 28);
        for (name, text) in all {
            let p = parse_preset(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(!p.tcp.trim().is_empty(), "{name}: пустой NFQWS_ARGS");
        }
    }

    #[test]
    fn local_variable_is_inlined() {
        let (_, text) = bundled()
            .into_iter()
            .find(|(n, _)| n == "MartinBacker")
            .unwrap();
        let p = parse_preset(&text).unwrap();
        assert!(!p.tcp.contains("ARGS_BLOCK16") && !p.udp.contains("ARGS_BLOCK16"));
        assert!(format!("{}{}{}", p.tcp, p.quic, p.custom).contains("$LISTS_DIR/ipset_amazon.list"));
    }

    #[test]
    fn multiline_value_and_comments() {
        let text = "# шапка\nNFQWS_ARGS=\"--a\n  # внутри\n  --b\"\n";
        let p = parse_preset(text).unwrap();
        assert_eq!(p.tcp, "--a\n  # внутри\n  --b");
    }

    #[test]
    fn unknown_variable_is_an_error_with_line() {
        let text = "A=1\nB=2\n\nNFQWS_ARGS=\"--x=$FOO\"\n";
        let e = parse_preset(text).unwrap_err();
        assert_eq!(e.line, 4);
        assert!(e.message.contains("FOO"), "{e}");
    }

    #[test]
    fn pkt_overrides_are_read_from_comment_lines() {
        let text = "# NFQWS2_TCP_PKT_OUT=8\nNFQWS2_UDP_PKT_IN=3\nNFQWS_ARGS=\"--x\"\n";
        let p = parse_preset(text).unwrap();
        assert_eq!(p.limits.tcp_out, Some(8));
        assert_eq!(p.limits.udp_in, Some(3));
        assert_eq!(p.limits.tcp_in, None);
    }

    /// Ревью 2а: лимит 0 дал бы `--connbytes 1:0`.
    #[test]
    fn pkt_override_out_of_range_is_an_error() {
        let e = parse_preset("NFQWS2_TCP_PKT_OUT=0\nNFQWS_ARGS=\"--x\"\n").unwrap_err();
        assert_eq!(e.line, 1);
        assert!(parse_preset("NFQWS2_UDP_PKT_IN=101\n").is_err());
    }

    #[test]
    fn global_keys_are_ignored() {
        let p = parse_preset("AUTOSTART=0\nNFQWS_ARGS=\"--x\"\n").unwrap();
        assert_eq!(p.tcp, "--x");
        assert_eq!(p.base, "");
    }

    #[test]
    fn known_variables_stay_symbolic() {
        let p = parse_preset("NFQWS_BASE_ARGS=\"--lua-init=@$LUA_DIR/zapret-lib.lua\"\n").unwrap();
        assert_eq!(p.base, "--lua-init=@$LUA_DIR/zapret-lib.lua");
    }

    /// Текст из редактора WebUI (`editorToText`) разбирается в те же поля, что отдал `ctl strategy get`.
    #[test]
    fn editor_roundtrip() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../module/tests");
        let text = std::fs::read_to_string(format!("{dir}/webui/editor-roundtrip.conf")).unwrap();
        let get: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{dir}/ctl-samples/strategy-get.json")).unwrap(),
        )
        .unwrap();
        let p = parse_preset(&text).unwrap();
        let f = &get["fields"];
        for (key, got) in [
            ("NFQWS_BASE_ARGS", &p.base),
            ("NFQWS_ARGS", &p.tcp),
            ("NFQWS_ARGS_QUIC", &p.quic),
            ("NFQWS_ARGS_UDP", &p.udp),
            ("NFQWS_ARGS_IPSET", &p.ipset),
            ("NFQWS_ARGS_CUSTOM", &p.custom),
        ] {
            assert_eq!(f[key].as_str().unwrap(), got, "{key}");
        }
    }
}
