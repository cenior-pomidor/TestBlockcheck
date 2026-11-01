//! Настройки модуля: `/data/adb/bcw/settings.conf`, строки `КЛЮЧ=значение`.
//!
//! Имена и умолчания — как в `defaults/nfqws2.conf` nfqws2-android (таблица §4.2 спецификации).

/// Режим списков (`NFQWS_EXTRA_ARGS` оригинала).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListMode {
    List,
    All,
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub default_strategy: String,
    pub mode: ListMode,
    pub tcp_ports: String,
    pub udp_ports: String,
    pub auto_ports: bool,
    pub pkt_limit_out: u16,
    pub pkt_limit_in: u16,
    pub block_quic: bool,
    pub meta_quic_reject: bool,
    pub calls_bypass: bool,
    pub tcp_mss_clamp: u16,
    pub nat_fix: bool,
    pub autostart: bool,
    pub watchdog: bool,
    pub home_wifi: bool,
    pub net_strategy: bool,
    pub log_level: u8,
    pub log_max_kb: u32,
}

/// Ключи в порядке таблицы §4.2.
pub const KEYS: [&str; 18] = [
    "DEFAULT_STRATEGY",
    "MODE",
    "TCP_PORTS",
    "UDP_PORTS",
    "AUTO_PORTS",
    "PKT_LIMIT_OUT",
    "PKT_LIMIT_IN",
    "BLOCK_QUIC",
    "META_QUIC_REJECT",
    "CALLS_BYPASS",
    "TCP_MSS_CLAMP",
    "NAT_FIX",
    "AUTOSTART",
    "WATCHDOG",
    "HOME_WIFI",
    "NET_STRATEGY",
    "LOG_LEVEL",
    "LOG_MAX_KB",
];

impl Default for Settings {
    fn default() -> Self {
        Settings {
            default_strategy: "default".into(),
            mode: ListMode::Auto,
            tcp_ports: "80,443,1984,2053,2083,2087,2096,5222,8443".into(),
            udp_ports: "443,590:600,1400,3478:3481,5349,19294:19344,49152:65535".into(),
            auto_ports: false,
            pkt_limit_out: 15,
            pkt_limit_in: 15,
            block_quic: false,
            meta_quic_reject: true,
            calls_bypass: false,
            tcp_mss_clamp: 0,
            nat_fix: true,
            autostart: true,
            watchdog: true,
            home_wifi: false,
            net_strategy: false,
            log_level: 0,
            log_max_kb: 512,
        }
    }
}

impl ListMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ListMode::List => "list",
            ListMode::All => "all",
            ListMode::Auto => "auto",
        }
    }
}

fn flag(key: &str, v: &str) -> Result<bool, String> {
    match v {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(format!("{key}: допустимо 0 или 1, получено «{v}»")),
    }
}

fn number<T: std::str::FromStr + PartialOrd + std::fmt::Display>(
    key: &str,
    v: &str,
    lo: T,
    hi: T,
) -> Result<T, String> {
    match v.parse::<T>() {
        Ok(n) if n >= lo && n <= hi => Ok(n),
        _ => Err(format!(
            "{key}: нужно число от {lo} до {hi}, получено «{v}»"
        )),
    }
}

fn port_list(key: &str, v: &str) -> Result<String, String> {
    let ok = !v.is_empty()
        && v.split(',').all(|p| {
            let parts: Vec<&str> = p.split([':', '-']).collect();
            (1..=2).contains(&parts.len())
                && parts
                    .iter()
                    .all(|x| x.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n)))
        });
    if !ok {
        return Err(format!(
            "{key}: список портов через запятую, диапазон — a:b, получено «{v}»"
        ));
    }
    let w = super::ports::weight(v);
    if w > 15 {
        return Err(format!(
            "{key}: не больше 15 портов в правиле (диапазон считается за два), здесь {w}"
        ));
    }
    Ok(v.to_string())
}

/// Имя пресета: `[A-Za-z0-9_-]{1,64}`.
pub fn valid_strategy_name(v: &str) -> bool {
    (1..=64).contains(&v.len())
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

impl Settings {
    /// Установить значение с проверкой; при ошибке настройки не меняются.
    pub fn set(&mut self, key: &str, v: &str) -> Result<(), String> {
        let v = v.trim();
        match key {
            "DEFAULT_STRATEGY" => {
                if !valid_strategy_name(v) {
                    return Err(format!(
                        "DEFAULT_STRATEGY: имя из латиницы, цифр, _ и -, до 64 символов, получено «{v}»"
                    ));
                }
                self.default_strategy = v.to_string();
            }
            "MODE" => {
                self.mode = match v {
                    "list" => ListMode::List,
                    "all" => ListMode::All,
                    "auto" => ListMode::Auto,
                    _ => {
                        return Err(format!(
                            "MODE: допустимо list, all или auto, получено «{v}»"
                        ))
                    }
                }
            }
            "TCP_PORTS" => self.tcp_ports = port_list(key, v)?,
            "UDP_PORTS" => self.udp_ports = port_list(key, v)?,
            "AUTO_PORTS" => self.auto_ports = flag(key, v)?,
            "PKT_LIMIT_OUT" => self.pkt_limit_out = number(key, v, 1u16, 100)?,
            "PKT_LIMIT_IN" => self.pkt_limit_in = number(key, v, 1u16, 100)?,
            "BLOCK_QUIC" => self.block_quic = flag(key, v)?,
            "META_QUIC_REJECT" => self.meta_quic_reject = flag(key, v)?,
            "CALLS_BYPASS" => self.calls_bypass = flag(key, v)?,
            "TCP_MSS_CLAMP" => {
                let n = number(key, v, 0u16, 1460)?;
                if (2..88).contains(&n) {
                    return Err(format!(
                        "TCP_MSS_CLAMP: 0 — выкл., 1 — 536, иначе от 88 до 1460, получено «{v}»"
                    ));
                }
                self.tcp_mss_clamp = n;
            }
            "NAT_FIX" => self.nat_fix = flag(key, v)?,
            "AUTOSTART" => self.autostart = flag(key, v)?,
            "WATCHDOG" => self.watchdog = flag(key, v)?,
            "HOME_WIFI" => self.home_wifi = flag(key, v)?,
            "NET_STRATEGY" => self.net_strategy = flag(key, v)?,
            "LOG_LEVEL" => self.log_level = number(key, v, 0u8, 1)?,
            "LOG_MAX_KB" => self.log_max_kb = number(key, v, 64u32, 4096)?,
            _ => return Err(format!("неизвестная настройка {key}")),
        }
        Ok(())
    }

    /// Значение настройки в виде строки файла.
    pub fn get(&self, key: &str) -> Option<String> {
        let b = |x: bool| if x { "1" } else { "0" }.to_string();
        Some(match key {
            "DEFAULT_STRATEGY" => self.default_strategy.clone(),
            "MODE" => self.mode.as_str().into(),
            "TCP_PORTS" => self.tcp_ports.clone(),
            "UDP_PORTS" => self.udp_ports.clone(),
            "AUTO_PORTS" => b(self.auto_ports),
            "PKT_LIMIT_OUT" => self.pkt_limit_out.to_string(),
            "PKT_LIMIT_IN" => self.pkt_limit_in.to_string(),
            "BLOCK_QUIC" => b(self.block_quic),
            "META_QUIC_REJECT" => b(self.meta_quic_reject),
            "CALLS_BYPASS" => b(self.calls_bypass),
            "TCP_MSS_CLAMP" => self.tcp_mss_clamp.to_string(),
            "NAT_FIX" => b(self.nat_fix),
            "AUTOSTART" => b(self.autostart),
            "WATCHDOG" => b(self.watchdog),
            "HOME_WIFI" => b(self.home_wifi),
            "NET_STRATEGY" => b(self.net_strategy),
            "LOG_LEVEL" => self.log_level.to_string(),
            "LOG_MAX_KB" => self.log_max_kb.to_string(),
            _ => return None,
        })
    }

    pub fn render(&self) -> String {
        let mut out = String::from(
            "# Настройки модуля bcw. Правьте через WebUI или `bcw ctl settings set`.\n",
        );
        for k in KEYS {
            out.push_str(&format!("{k}={}\n", self.get(k).unwrap_or_default()));
        }
        out
    }

    /// MSS для `TCPMSS --set-mss`: 0 — выкл., 1 — 536 (как в оригинале).
    pub fn mss_value(&self) -> Option<u16> {
        match self.tcp_mss_clamp {
            0 => None,
            1 => Some(536),
            n => Some(n),
        }
    }
}

/// Разобрать файл; второе — предупреждения о строках, заменённых умолчанием.
pub fn parse(text: &str) -> (Settings, Vec<String>) {
    let mut s = Settings::default();
    let mut warns = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            warns.push(format!(
                "settings.conf, строка {}: не «КЛЮЧ=значение», пропущена",
                i + 1
            ));
            continue;
        };
        if let Err(e) = s.set(k.trim(), v.trim().trim_matches('"')) {
            warns.push(format!(
                "settings.conf, строка {}: {e}; взято умолчание",
                i + 1
            ));
        }
    }
    (s, warns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec() {
        let s = Settings::default();
        assert_eq!(s.default_strategy, "default");
        assert_eq!(s.mode, ListMode::Auto);
        assert_eq!(s.tcp_ports, "80,443,1984,2053,2083,2087,2096,5222,8443");
        assert_eq!(
            s.udp_ports,
            "443,590:600,1400,3478:3481,5349,19294:19344,49152:65535"
        );
        assert!(!s.auto_ports);
        assert_eq!((s.pkt_limit_out, s.pkt_limit_in), (15, 15));
        assert!(!s.block_quic && s.meta_quic_reject && !s.calls_bypass);
        assert_eq!(s.tcp_mss_clamp, 0);
        assert!(s.nat_fix && s.autostart && s.watchdog);
        assert!(!s.home_wifi && !s.net_strategy);
        assert_eq!((s.log_level, s.log_max_kb), (0, 512));
    }

    #[test]
    fn roundtrip() {
        let mut s = Settings::default();
        s.set("MODE", "list").unwrap();
        s.set("BLOCK_QUIC", "1").unwrap();
        s.set("DEFAULT_STRATEGY", "alt4").unwrap();
        let (back, warns) = parse(&s.render());
        assert!(warns.is_empty(), "{warns:?}");
        assert_eq!(back, s);
    }

    #[test]
    fn garbage_line_falls_back_with_warning() {
        let (s, warns) = parse("PKT_LIMIT_OUT=abc\nAUTOSTART=0\n");
        assert_eq!(s.pkt_limit_out, 15);
        assert!(!s.autostart);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(warns[0].contains("PKT_LIMIT_OUT"));
    }

    #[test]
    fn unknown_key_and_junk_warn_but_do_not_break() {
        let (s, warns) = parse("FOO=1\nмусор\n# комментарий\n\nWATCHDOG=0\n");
        assert!(!s.watchdog);
        assert_eq!(warns.len(), 2, "{warns:?}");
    }

    #[test]
    fn set_rejects_out_of_range() {
        let mut s = Settings::default();
        for (k, v) in [
            ("PKT_LIMIT_OUT", "0"),
            ("PKT_LIMIT_IN", "101"),
            ("LOG_MAX_KB", "10"),
            ("TCP_MSS_CLAMP", "50"),
            ("TCP_MSS_CLAMP", "1461"),
            ("MODE", "x"),
            ("BLOCK_QUIC", "2"),
            ("DEFAULT_STRATEGY", "../x"),
            ("TCP_PORTS", "80,abc"),
            ("NO_SUCH", "1"),
        ] {
            assert!(s.set(k, v).is_err(), "{k}={v} должен быть отвергнут");
        }
        assert_eq!(s, Settings::default(), "отвергнутое не меняет настройки");
    }

    #[test]
    fn set_rejects_more_than_15_multiport_weight() {
        let mut s = Settings::default();
        let ports: Vec<String> = (1000..1016).map(|p| p.to_string()).collect();
        assert!(s.set("TCP_PORTS", &ports.join(",")).is_err());
        assert!(s.set("TCP_PORTS", &ports[..15].join(",")).is_ok());
    }

    #[test]
    fn mss_one_means_536() {
        let mut s = Settings::default();
        assert_eq!(s.mss_value(), None);
        s.set("TCP_MSS_CLAMP", "1").unwrap();
        assert_eq!(s.mss_value(), Some(536));
        s.set("TCP_MSS_CLAMP", "1200").unwrap();
        assert_eq!(s.mss_value(), Some(1200));
    }
}
