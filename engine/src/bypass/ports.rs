//! Порты перехвата: семантика функций портов nfqws2-android (`lib/common.sh`).

/// Вес списка портов для `-m multiport`: порт — 1, диапазон `a:b` / `a-b` — 2. Предел — 15.
pub fn weight(list: &str) -> usize {
    list.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            if p.contains(':') || p.contains('-') {
                2
            } else {
                1
            }
        })
        .sum()
}

use super::preset::Preset;
use super::settings::Settings;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Порты, которые реально ставятся в правила.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePorts {
    pub tcp: String,
    pub udp: String,
}

/// `-` → `:` (как `tr '-' ':'` оригинала).
pub fn normalize(list: &str) -> String {
    list.replace('-', ":")
}

/// `port_list_add` (`lib/common.sh:509`).
pub fn add(list: &str, extra: &[&str]) -> String {
    // awk: x+0 у «a:b» даёт a; hi — число после двоеточия.
    fn lo(x: &str) -> i64 {
        num(x.split(':').next().unwrap_or(""))
    }
    fn hi(x: &str) -> i64 {
        match x.split_once(':') {
            Some((_, h)) => num(h),
            None => num(x),
        }
    }
    let have: Vec<&str> = list.split(',').collect();
    let add: Vec<&str> = extra.iter().copied().filter(|x| !x.is_empty()).collect();
    let mut out: Vec<&str> = Vec::new();
    for a in &have {
        if a.is_empty() {
            continue;
        }
        let covered = add
            .iter()
            .any(|b| a != b && lo(a) >= lo(b) && hi(a) <= hi(b));
        if !covered {
            out.push(a);
        }
    }
    for b in &add {
        let dup = have
            .iter()
            .any(|a| !a.is_empty() && lo(b) >= lo(a) && hi(b) <= hi(a));
        if !dup {
            out.push(b);
        }
    }
    out.join(",")
}

/// Число в начале строки, как `x + 0` в awk.
fn num(x: &str) -> i64 {
    let d: String = x
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    d.parse().unwrap_or(0)
}

/// `port_list_without` (`lib/common.sh:533`).
pub fn without(list: &str, port: &str) -> String {
    // printf ',%s,' | sed "s/,PORT,/,/g; s/^,//; s/,$//"
    let framed = format!(",{list},");
    let s = framed.replace(&format!(",{port},"), ",");
    let s = s.strip_prefix(',').unwrap_or(&s);
    s.strip_suffix(',').unwrap_or(s).to_string()
}

/// `collect_capture_ports` (`lib/common.sh:643`).
pub fn from_filters(args: &str, proto: Proto) -> String {
    let want = match proto {
        Proto::Tcp => "--filter-tcp=",
        Proto::Udp => "--filter-udp=",
    };
    let mut items: Vec<String> = Vec::new();
    for tok in args.split(|c: char| c.is_whitespace() || c == '"') {
        if let Some(val) = tok.strip_prefix(want) {
            for p in val.split(',') {
                let p = p.replace('-', ":");
                if !p.is_empty() && !items.contains(&p) {
                    items.push(p);
                }
            }
        }
    }
    items.sort_by_key(|p| num(p));
    items.join(",")
}

/// Части списка с весом не больше 15, порядок сохранён.
pub fn chunks(list: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur: Vec<&str> = Vec::new();
    let mut w = 0;
    for p in list.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let pw = weight(p);
        if w + pw > 15 && !cur.is_empty() {
            out.push(cur.join(","));
            cur.clear();
            w = 0;
        }
        cur.push(p);
        w += pw;
    }
    if !cur.is_empty() {
        out.push(cur.join(","));
    }
    out
}

/// Порты правил по настройкам и пресету — как `_firewall_start` (`lib/common.sh:1453–1474`).
pub fn effective(s: &Settings, preset: &Preset) -> EffectivePorts {
    let filters = format!(
        "{} {} {} {}",
        preset.tcp, preset.quic, preset.udp, preset.custom
    );
    let mut tcp = if s.auto_ports {
        let t = from_filters(&filters, Proto::Tcp);
        if t.is_empty() {
            "80,443".to_string()
        } else {
            t
        }
    } else {
        normalize(&s.tcp_ports)
    };
    let mut udp = if s.auto_ports {
        from_filters(&filters, Proto::Udp)
    } else {
        normalize(&s.udp_ports)
    };
    if s.block_quic {
        udp = without(&udp, "443");
    }
    if s.calls_bypass {
        udp = add(&udp, &["590:1400", "3478:3482"]);
        tcp = add(&tcp, &["5222"]);
    }
    EffectivePorts { tcp, udp }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weight_counts_ranges_twice() {
        assert_eq!(weight(""), 0);
        assert_eq!(weight("443"), 1);
        assert_eq!(weight("443,590:600,1400,3478-3481"), 6);
        assert_eq!(
            weight("443,590:600,1400,3478:3481,5349,19294:19344,49152:65535"),
            11
        );
    }
    #[test]
    fn effective_ports_match_upstream() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../module/strategies");
        let golden = include_str!("../../tests/fixtures/bypass/ports.jsonl");
        let mut n = 0;
        for line in golden.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let name = v["preset"].as_str().unwrap();
            let text = std::fs::read_to_string(format!("{dir}/{name}.conf")).unwrap();
            let preset = crate::bypass::preset::parse_preset(&text).unwrap();
            let mut s = Settings::default();
            s.auto_ports = v["auto_ports"] == 1;
            s.block_quic = v["block_quic"] == 1;
            s.calls_bypass = v["calls"] == 1;
            let got = effective(&s, &preset);
            assert_eq!(got.tcp, v["tcp"].as_str().unwrap(), "tcp: {line}");
            assert_eq!(got.udp, v["udp"].as_str().unwrap(), "udp: {line}");
            n += 1;
        }
        assert_eq!(n, 224);
    }

    #[test]
    fn chunks_never_exceed_15() {
        let list: Vec<String> = (1000..1024).map(|p| p.to_string()).collect();
        let parts = chunks(&list.join(","));
        assert_eq!(parts.len(), 2);
        assert!(parts.iter().all(|p| weight(p) <= 15));
        assert_eq!(parts.join(","), list.join(","));
        assert_eq!(chunks("443"), vec!["443".to_string()]);
        assert!(chunks("").is_empty());
    }

    #[test]
    fn add_and_without_follow_upstream() {
        assert_eq!(add("443,590:600,1400", &["590:1400"]), "443,590:1400");
        assert_eq!(add("80,5222", &["5222"]), "80,5222");
        assert_eq!(without("443,4430,1443", "443"), "4430,1443");
        assert_eq!(normalize("590-600,443"), "590:600,443");
    }
}
