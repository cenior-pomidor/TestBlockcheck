//! Какая сейчас сеть и что из этого следует (§3.3 спецификации).
//!
//! Разбор — как `current_ssid` и `_raw_network_id` nfqws2-android (`lib/common.sh:2108`,
//! `2247`); ключ — как `current_network_key` (`lib/common.sh:2263`), эталон —
//! `tests/fixtures/bypass/netkeys.jsonl`.

use super::settings::Settings;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    Wifi { ssid: String },
    Mobile { operator: Option<String> },
    Offline,
}

/// Вывод `cmd wifi status`: `None` — это не его вывод; `Some(None)` — не подключено.
pub fn parse_cmd_wifi(out: &str) -> Option<Option<String>> {
    if !out.contains("Wifi is ") {
        return None;
    }
    let ssid = out.lines().find_map(|l| {
        l.trim_end()
            .strip_prefix("Wifi is connected to \"")
            .and_then(|r| r.strip_suffix('"'))
            .map(str::to_string)
    });
    Some(ssid.filter(|s| valid_ssid(s)))
}

fn valid_ssid(s: &str) -> bool {
    !matches!(s, "" | "<unknown ssid>" | "<none>" | "0x")
}

/// `dumpsys wifi` (старые Android): SSID из `mWifiInfo` в состоянии `COMPLETED`.
pub fn parse_dumpsys_wifi(out: &str) -> Option<String> {
    let line = out
        .lines()
        .find(|l| l.contains("mWifiInfo SSID: ") && l.contains("Supplicant state: COMPLETED"))?;
    let after = line.split("mWifiInfo SSID: ").nth(1)?;
    let raw = after.split(", BSSID:").next()?;
    let s = raw
        .strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .unwrap_or(raw);
    valid_ssid(s).then(|| s.to_string())
}

/// Оператор из `getprop gsm.operator.alpha`, запасной — `gsm.sim.operator.alpha`.
pub fn operator_from_getprop(alpha: &str, sim_alpha: &str) -> Option<String> {
    let first = |v: &str| v.split(',').next().unwrap_or("").trim().to_string();
    let a = first(alpha);
    let op = if a.is_empty() { first(sim_alpha) } else { a };
    (!op.is_empty()).then_some(op)
}

/// `kind_safe` или `kind_safe_hex`, если пришлось заменять байты (как `tr -c` + `od -tx1`).
fn encode(kind: &str, val: &str) -> String {
    let safe: String = val
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"._-".contains(&b) {
                b as char
            } else {
                '_'
            }
        })
        .collect();
    if safe == val {
        format!("{kind}_{safe}")
    } else {
        let hex: String = val.bytes().map(|b| format!("{b:02x}")).collect();
        format!("{kind}_{safe}_{hex}")
    }
}

impl Network {
    /// Ключ сети для `networks.tsv`.
    pub fn key(&self) -> String {
        match self {
            Network::Wifi { ssid } => encode("wifi", ssid),
            Network::Mobile { operator: Some(op) } => encode("cell", op),
            Network::Mobile { operator: None } => "cellular".into(),
            Network::Offline => "offline".into(),
        }
    }

    /// Подпись для человека.
    pub fn title(&self) -> String {
        match self {
            Network::Wifi { ssid } => format!("Wi-Fi «{ssid}»"),
            Network::Mobile { operator: Some(op) } => format!("Мобильная ({op})"),
            Network::Mobile { operator: None } => "Мобильная".into(),
            Network::Offline => "Нет сети".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Pause { ssid: String },
    Resume { strategy: String },
    Restart { strategy: String },
    Nothing,
}

pub struct DecisionInput<'a> {
    pub settings: &'a Settings,
    pub network: &'a Network,
    /// С какой стратегией обход работает сейчас (`None` — не работает).
    pub running_strategy: Option<&'a str>,
    /// Сейчас пауза дома.
    pub paused: bool,
    pub home: &'a [String],
    /// «Включить здесь сейчас» нажато в этой сети.
    pub resumed_ssid: Option<&'a str>,
    /// Сохранённые сети: (ключ, пресет).
    pub saved: &'a [(String, String)],
}

/// Что делать при этой сети.
pub fn decide(i: &DecisionInput) -> Decision {
    if *i.network == Network::Offline {
        return Decision::Nothing;
    }
    if let Network::Wifi { ssid } = i.network {
        let at_home = i.settings.home_wifi
            && i.home.iter().any(|h| h == ssid)
            && i.resumed_ssid != Some(ssid.as_str());
        if at_home {
            return if i.paused {
                Decision::Nothing
            } else {
                Decision::Pause { ssid: ssid.clone() }
            };
        }
    }
    let key = i.network.key();
    let strategy = i
        .settings
        .net_strategy
        .then(|| {
            i.saved
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, s)| s.clone())
        })
        .flatten()
        .unwrap_or_else(|| i.settings.default_strategy.clone());
    if i.paused {
        Decision::Resume { strategy }
    } else if i.running_strategy != Some(strategy.as_str()) {
        Decision::Restart { strategy }
    } else {
        Decision::Nothing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_wifi_connected_disconnected_foreign() {
        let on = "Wifi is enabled\nWifi scanning is always available\n\
                  Wifi is connected to \"Home 5G\"\nWifiInfo: SSID: \"Home 5G\", BSSID: …\n";
        assert_eq!(parse_cmd_wifi(on), Some(Some("Home 5G".into())));
        let off = "Wifi is enabled\nWifi is not connected\n";
        assert_eq!(parse_cmd_wifi(off), Some(None));
        assert_eq!(parse_cmd_wifi("Unknown command: wifi\n"), None);
        assert_eq!(parse_cmd_wifi(""), None);
    }

    #[test]
    fn dumpsys_fallback() {
        let out = "mWifiInfo SSID: \"Dacha\", BSSID: 00:11, MAC: x, Supplicant state: COMPLETED, RSSI: -50\n";
        assert_eq!(parse_dumpsys_wifi(out), Some("Dacha".into()));
        let idle = "mWifiInfo SSID: <unknown ssid>, BSSID: x, Supplicant state: DISCONNECTED\n";
        assert_eq!(parse_dumpsys_wifi(idle), None);
    }

    #[test]
    fn unknown_ssid_is_not_wifi() {
        for bad in ["<unknown ssid>", "", "<none>", "0x"] {
            let out = format!("Wifi is enabled\nWifi is connected to \"{bad}\"\n");
            assert_eq!(parse_cmd_wifi(&out), Some(None), "{bad:?}");
        }
    }

    #[test]
    fn operator_first_item_and_fallback() {
        assert_eq!(
            operator_from_getprop("MegaFon,", ""),
            Some("MegaFon".into())
        );
        assert_eq!(operator_from_getprop("", "MTS RUS"), Some("MTS RUS".into()));
        assert_eq!(operator_from_getprop(" ", ""), None);
    }

    #[test]
    fn ssid_key_matches_upstream() {
        let golden = include_str!("../../tests/fixtures/bypass/netkeys.jsonl");
        for line in golden.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let raw = v["raw"].as_str().unwrap();
            let net = if let Some(s) = raw.strip_prefix("wifi:") {
                Network::Wifi { ssid: s.into() }
            } else if let Some(o) = raw.strip_prefix("cell:") {
                Network::Mobile {
                    operator: Some(o.into()),
                }
            } else {
                Network::Mobile { operator: None }
            };
            assert_eq!(net.key(), v["key"].as_str().unwrap(), "{raw}");
        }
        assert_eq!(Network::Offline.key(), "offline");
    }

    #[test]
    fn titles() {
        assert_eq!(
            Network::Wifi {
                ssid: "Дом".into()
            }
            .title(),
            "Wi-Fi «Дом»"
        );
        assert_eq!(
            Network::Mobile {
                operator: Some("MegaFon".into())
            }
            .title(),
            "Мобильная (MegaFon)"
        );
        assert_eq!(Network::Mobile { operator: None }.title(), "Мобильная");
        assert_eq!(Network::Offline.title(), "Нет сети");
    }

    fn input<'a>(
        s: &'a Settings,
        n: &'a Network,
        running: Option<&'a str>,
        paused: bool,
        home: &'a [String],
        resumed: Option<&'a str>,
        saved: &'a [(String, String)],
    ) -> DecisionInput<'a> {
        DecisionInput {
            settings: s,
            network: n,
            running_strategy: running,
            paused,
            home,
            resumed_ssid: resumed,
            saved,
        }
    }

    #[test]
    fn decide_table() {
        let mut s = Settings::default();
        s.home_wifi = true;
        let home = vec!["Home".to_string()];
        let wifi = Network::Wifi {
            ssid: "Home".into(),
        };
        let cafe = Network::Wifi {
            ssid: "Cafe".into(),
        };
        let none: Vec<(String, String)> = vec![];

        // Дома — пауза; уже на паузе — ничего.
        assert_eq!(
            decide(&input(
                &s,
                &wifi,
                Some("default"),
                false,
                &home,
                None,
                &none
            )),
            Decision::Pause {
                ssid: "Home".into()
            }
        );
        assert_eq!(
            decide(&input(&s, &wifi, None, true, &home, None, &none)),
            Decision::Nothing
        );
        // Дома, но «включить здесь» нажато — не пауза.
        assert_eq!(
            decide(&input(
                &s,
                &wifi,
                Some("default"),
                false,
                &home,
                Some("Home"),
                &none
            )),
            Decision::Nothing
        );
        // Ушёл из дома — продолжить со стратегией по умолчанию.
        assert_eq!(
            decide(&input(&s, &cafe, None, true, &home, None, &none)),
            Decision::Resume {
                strategy: "default".into()
            }
        );
        // Пауза дома выключена — дом как обычная сеть.
        let mut s2 = s.clone();
        s2.home_wifi = false;
        assert_eq!(
            decide(&input(
                &s2,
                &wifi,
                Some("default"),
                false,
                &home,
                None,
                &none
            )),
            Decision::Nothing
        );

        // Стратегии по сетям.
        let saved = vec![(cafe.key(), "alt4".to_string())];
        s.net_strategy = true;
        assert_eq!(
            decide(&input(
                &s,
                &cafe,
                Some("default"),
                false,
                &home,
                None,
                &saved
            )),
            Decision::Restart {
                strategy: "alt4".into()
            }
        );
        assert_eq!(
            decide(&input(&s, &cafe, Some("alt4"), false, &home, None, &saved)),
            Decision::Nothing
        );
        s.net_strategy = false;
        assert_eq!(
            decide(&input(&s, &cafe, Some("alt4"), false, &home, None, &saved)),
            Decision::Restart {
                strategy: "default".into()
            }
        );

        // Нет сети — ничего.
        assert_eq!(
            decide(&input(
                &s,
                &Network::Offline,
                Some("alt4"),
                false,
                &home,
                None,
                &saved
            )),
            Decision::Nothing
        );
    }
}
