//! Данные модуля в `/data/adb/bcw/` (§4 спецификации): настройки, списки, перекрытия
//! пресетов, сохранённые сети, домашние Wi-Fi. Записи атомарные.

use std::io;
use std::path::PathBuf;

use super::layout::Layout;
use super::network::Network;
use super::preset::{parse_preset, Preset};
use super::settings::{self, valid_strategy_name, Settings};
use crate::system::atomic::write_atomic;

/// Списки, которые правит владелец.
pub const LIST_NAMES: [&str; 5] = ["user", "auto", "exclude", "ipset", "ipset_exclude"];

/// Списки доменов для поиска стратегии; в `ctl lists` не показываются.
pub const SEARCH_LIST_NAMES: [&str; 2] = ["search-general", "search-youtube"];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StrategyInfo {
    pub name: String,
    pub author: String,
    pub source: String,
    pub builtin: bool,
    pub modified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SavedNetwork {
    pub key: String,
    pub title: String,
    pub strategy: String,
}

pub struct Store {
    pub layout: Layout,
}

impl Store {
    pub fn new(layout: Layout) -> Store {
        Store { layout }
    }

    /// Каталоги данных; умолчания списков и настроек — только если файла ещё нет.
    pub fn init_data_dir(&self) -> io::Result<()> {
        let l = &self.layout;
        for d in [
            l.data_lists(),
            l.data_strategies(),
            l.logs_dir(),
            l.state_dir(),
            l.tmp_dir(),
        ] {
            std::fs::create_dir_all(d)?;
        }
        for name in LIST_NAMES.into_iter().chain(SEARCH_LIST_NAMES) {
            let to = l.data_lists().join(format!("{name}.list"));
            if !to.exists() {
                let from = l.defaults_dir().join("lists").join(format!("{name}.list"));
                let text = std::fs::read_to_string(&from).unwrap_or_default();
                write_atomic(&to, &text)?;
            }
        }
        if !l.settings_file().exists() {
            write_atomic(&l.settings_file(), &Settings::default().render())?;
        }
        Ok(())
    }

    pub fn settings(&self) -> (Settings, Vec<String>) {
        match std::fs::read_to_string(self.layout.settings_file()) {
            Ok(t) => settings::parse(&t),
            Err(_) => (Settings::default(), Vec::new()),
        }
    }

    pub fn save_settings(&self, s: &Settings) -> io::Result<()> {
        write_atomic(&self.layout.settings_file(), &s.render())
    }

    fn builtin_path(&self, name: &str) -> PathBuf {
        self.layout.module_strategies().join(format!("{name}.conf"))
    }

    fn override_path(&self, name: &str) -> PathBuf {
        self.layout.data_strategies().join(format!("{name}.conf"))
    }

    fn names_in(dir: &std::path::Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| {
                        let n = e.file_name().to_string_lossy().into_owned();
                        n.strip_suffix(".conf").map(str::to_string)
                    })
                    .filter(|n| valid_strategy_name(n))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    pub fn strategies(&self) -> Vec<StrategyInfo> {
        let meta = std::fs::read_to_string(self.layout.module_strategies().join("meta.tsv"))
            .unwrap_or_default();
        let lookup = |name: &str| {
            meta.lines()
                .filter(|l| !l.starts_with('#'))
                .map(|l| l.split('\t').collect::<Vec<_>>())
                .find(|f| f.first() == Some(&name))
                .map(|f| {
                    (
                        f.get(1).unwrap_or(&"").to_string(),
                        f.get(2).unwrap_or(&"").to_string(),
                    )
                })
                .unwrap_or_default()
        };
        let builtin = Self::names_in(&self.layout.module_strategies());
        let user = Self::names_in(&self.layout.data_strategies());
        let mut out: Vec<StrategyInfo> = builtin
            .iter()
            .map(|n| {
                let (author, source) = lookup(n);
                StrategyInfo {
                    name: n.clone(),
                    author,
                    source,
                    builtin: true,
                    modified: user.contains(n),
                }
            })
            .collect();
        out.extend(
            user.iter()
                .filter(|n| !builtin.contains(n))
                .map(|n| StrategyInfo {
                    name: n.clone(),
                    author: String::new(),
                    source: String::new(),
                    builtin: false,
                    modified: false,
                }),
        );
        out
    }

    fn check_name(name: &str) -> Result<(), String> {
        if valid_strategy_name(name) {
            Ok(())
        } else {
            Err(format!(
                "имя стратегии из латиницы, цифр, _ и -, до 64 символов: «{name}»"
            ))
        }
    }

    /// Текст пресета: перекрытие из данных главнее модульного.
    pub fn preset_text(&self, name: &str) -> Result<String, String> {
        Self::check_name(name)?;
        for p in [self.override_path(name), self.builtin_path(name)] {
            if let Ok(t) = std::fs::read_to_string(&p) {
                return Ok(t);
            }
        }
        Err(format!("стратегии «{name}» нет"))
    }

    pub fn load_preset(&self, name: &str) -> Result<Preset, String> {
        let text = self.preset_text(name)?;
        parse_preset(&text).map_err(|e| format!("стратегия «{name}», {e}"))
    }

    pub fn save_preset(&self, name: &str, text: &str) -> Result<(), String> {
        Self::check_name(name)?;
        parse_preset(text).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(self.layout.data_strategies()).map_err(|e| e.to_string())?;
        write_atomic(&self.override_path(name), text).map_err(|e| e.to_string())
    }

    pub fn reset_preset(&self, name: &str) -> Result<(), String> {
        Self::check_name(name)?;
        if !self.builtin_path(name).is_file() {
            return Err(format!(
                "«{name}» — не встроенная стратегия, возвращать нечего"
            ));
        }
        match std::fs::remove_file(self.override_path(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn delete_preset(&self, name: &str) -> Result<(), String> {
        Self::check_name(name)?;
        if self.builtin_path(name).is_file() {
            return Err(format!(
                "встроенную стратегию «{name}» удалить нельзя, только вернуть к исходнику"
            ));
        }
        std::fs::remove_file(self.override_path(name))
            .map_err(|_| format!("стратегии «{name}» нет"))
    }

    pub fn list_path(&self, name: &str) -> Result<PathBuf, String> {
        if LIST_NAMES.contains(&name) || SEARCH_LIST_NAMES.contains(&name) {
            Ok(self.layout.data_lists().join(format!("{name}.list")))
        } else {
            Err(format!(
                "нет такого списка: «{name}»; есть {}",
                LIST_NAMES.join(", ")
            ))
        }
    }

    pub fn read_list(&self, name: &str) -> Result<String, String> {
        let p = self.list_path(name)?;
        Ok(std::fs::read_to_string(p).unwrap_or_default())
    }

    pub fn write_list(&self, name: &str, text: &str) -> Result<(), String> {
        let p = self.list_path(name)?;
        write_atomic(&p, text).map_err(|e| e.to_string())
    }

    /// Строк без пустых и комментариев (`list_count` оригинала).
    pub fn list_count(&self, name: &str) -> usize {
        self.read_list(name)
            .unwrap_or_default()
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            })
            .count()
    }

    /// Сохранённые сети и предупреждения о пропущенных битых строках.
    pub fn networks(&self) -> (Vec<SavedNetwork>, Vec<String>) {
        let text = std::fs::read_to_string(self.layout.networks_file()).unwrap_or_default();
        let mut nets = Vec::new();
        let mut warns = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() == 3 && !f[0].is_empty() && valid_strategy_name(f[2]) {
                nets.push(SavedNetwork {
                    key: f[0].into(),
                    title: f[1].into(),
                    strategy: f[2].into(),
                });
            } else {
                warns.push(format!(
                    "networks.tsv, строка {}: не «ключ<TAB>подпись<TAB>стратегия», пропущена",
                    i + 1
                ));
            }
        }
        (nets, warns)
    }

    fn save_networks(&self, nets: &[SavedNetwork]) -> io::Result<()> {
        let text: String = nets
            .iter()
            .map(|n| {
                format!(
                    "{}\t{}\t{}\n",
                    n.key,
                    n.title.replace(['\t', '\n'], " "),
                    n.strategy
                )
            })
            .collect();
        write_atomic(&self.layout.networks_file(), &text)
    }

    pub fn set_network(&self, net: &Network, strategy: &str) -> io::Result<()> {
        self.set_network_entry(&net.key(), &net.title(), strategy)
    }

    /// Запись сети по ключу и подписи (из `ctl`, где известен только статус службы).
    pub fn set_network_entry(&self, key: &str, title: &str, strategy: &str) -> io::Result<()> {
        let (mut nets, _) = self.networks();
        nets.retain(|n| n.key != key);
        nets.push(SavedNetwork {
            key: key.into(),
            title: title.into(),
            strategy: strategy.into(),
        });
        self.save_networks(&nets)
    }

    /// Как `set_network_entry`, но существующая запись меняется на своём месте (порядок
    /// строк сохраняется — для применения найденного и точного отката).
    pub fn put_network_entry(&self, key: &str, title: &str, strategy: &str) -> io::Result<()> {
        let (mut nets, _) = self.networks();
        match nets.iter_mut().find(|n| n.key == key) {
            Some(n) => {
                n.title = title.into();
                n.strategy = strategy.into();
            }
            None => nets.push(SavedNetwork {
                key: key.into(),
                title: title.into(),
                strategy: strategy.into(),
            }),
        }
        self.save_networks(&nets)
    }

    pub fn delete_network(&self, key: &str) -> io::Result<()> {
        let (mut nets, _) = self.networks();
        nets.retain(|n| n.key != key);
        self.save_networks(&nets)
    }

    pub fn home(&self) -> Vec<String> {
        let text = std::fs::read_to_string(self.layout.home_file()).unwrap_or_default();
        let mut out: Vec<String> = Vec::new();
        for l in text.lines() {
            let t = l.trim_end_matches('\r');
            if !t.trim().is_empty() && !t.starts_with('#') && !out.iter().any(|x| x == t) {
                out.push(t.to_string());
            }
        }
        out
    }

    fn save_home(&self, list: &[String]) -> io::Result<()> {
        let text: String = list.iter().map(|s| format!("{s}\n")).collect();
        write_atomic(&self.layout.home_file(), &text)
    }

    pub fn add_home(&self, ssid: &str) -> io::Result<()> {
        let mut h = self.home();
        if !h.iter().any(|x| x == ssid) {
            h.push(ssid.to_string());
        }
        self.save_home(&h)
    }

    pub fn remove_home(&self, ssid: &str) -> io::Result<()> {
        let mut h = self.home();
        h.retain(|x| x != ssid);
        self.save_home(&h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn copy_dir(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for e in std::fs::read_dir(from).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if p.is_dir() {
                copy_dir(&p, &to.join(e.file_name()));
            } else {
                std::fs::copy(&p, to.join(e.file_name())).unwrap();
            }
        }
    }

    /// Временный модуль (копия strategies/ и defaults/) и пустые данные.
    fn store(tag: &str) -> (Store, PathBuf) {
        let root = std::env::temp_dir().join(format!("bcw-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let module = Path::new(env!("CARGO_MANIFEST_DIR")).join("../module");
        for d in ["strategies", "defaults"] {
            copy_dir(&module.join(d), &root.join("mod").join(d));
        }
        let s = Store::new(Layout {
            module_dir: root.join("mod"),
            data_dir: root.join("data"),
        });
        s.init_data_dir().unwrap();
        (s, root)
    }

    #[test]
    fn search_lists_seeded() {
        let (s, root) = store("search-seed");
        assert_eq!(
            s.read_list("search-general").unwrap(),
            "rutracker.org\ndiscord.com\nx.com\ninstagram.com\n"
        );
        assert_eq!(
            s.read_list("search-youtube").unwrap(),
            "www.youtube.com\ni.ytimg.com\nredirector.googlevideo.com\n"
        );
        s.write_list("search-general", "mine.org\n").unwrap();
        s.init_data_dir().unwrap();
        assert_eq!(s.read_list("search-general").unwrap(), "mine.org\n");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn search_list_rw() {
        let (s, root) = store("search-rw");
        s.write_list("search-youtube", "a.com\n").unwrap();
        assert_eq!(s.read_list("search-youtube").unwrap(), "a.com\n");
        assert!(s.list_path("nope").is_err());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn init_copies_default_lists_once() {
        let (s, root) = store("init");
        assert!(s.layout.settings_file().is_file());
        for l in LIST_NAMES {
            assert!(s.list_path(l).unwrap().is_file(), "{l}");
        }
        s.write_list("user", "example.org\n").unwrap();
        s.init_data_dir().unwrap();
        assert_eq!(s.read_list("user").unwrap(), "example.org\n");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn override_wins_and_reset_restores() {
        let (s, root) = store("override");
        let original = s.load_preset("alt").unwrap();
        s.save_preset("alt", "NFQWS_ARGS=\"--filter-tcp=443 --x\"\n")
            .unwrap();
        assert_eq!(s.load_preset("alt").unwrap().tcp, "--filter-tcp=443 --x");
        let info = s
            .strategies()
            .into_iter()
            .find(|i| i.name == "alt")
            .unwrap();
        assert!(info.builtin && info.modified);
        assert_eq!(info.author, "Flowseal");
        s.reset_preset("alt").unwrap();
        assert_eq!(s.load_preset("alt").unwrap(), original);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn user_preset_is_listed_and_deletable() {
        let (s, root) = store("user");
        s.save_preset("my-1", "NFQWS_ARGS=\"--filter-tcp=443\"\n")
            .unwrap();
        let info = s
            .strategies()
            .into_iter()
            .find(|i| i.name == "my-1")
            .unwrap();
        assert!(!info.builtin && !info.modified);
        assert_eq!(s.strategies().iter().filter(|i| i.builtin).count(), 28);
        s.delete_preset("my-1").unwrap();
        assert!(s.load_preset("my-1").is_err());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn broken_override_reports_line() {
        let (s, root) = store("broken");
        let e = s
            .save_preset("alt", "A=1\nNFQWS_ARGS=\"--x=$NOPE\"\n")
            .unwrap_err();
        assert!(e.contains("строка 2"), "{e}");
        // А если битый файл всё же лежит (правка руками) — загрузка говорит, где ошибка.
        std::fs::create_dir_all(s.layout.data_strategies()).unwrap();
        std::fs::write(
            s.layout.data_strategies().join("alt.conf"),
            "NFQWS_ARGS=\"--x\n",
        )
        .unwrap();
        let e = s.load_preset("alt").unwrap_err();
        assert!(e.contains("alt") && e.contains("строка 1"), "{e}");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cannot_delete_builtin() {
        let (s, root) = store("builtin");
        assert!(s.delete_preset("alt").is_err());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn bad_name_rejected() {
        let (s, root) = store("names");
        let long = "a".repeat(65);
        for n in ["../x", "", long.as_str(), "a b"] {
            assert!(s.save_preset(n, "NFQWS_ARGS=\"--x\"\n").is_err(), "{n:?}");
            assert!(s.load_preset(n).is_err(), "{n:?}");
        }
        assert!(s.read_list("../etc").is_err());
        assert!(s.write_list("general", "x").is_err());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn networks_upsert_and_skip_broken_line() {
        let (s, root) = store("nets");
        let cafe = Network::Wifi {
            ssid: "Café".into(),
        };
        s.set_network(&cafe, "alt").unwrap();
        s.set_network(&cafe, "alt4").unwrap();
        let mobile = Network::Mobile {
            operator: Some("MegaFon".into()),
        };
        s.set_network(&mobile, "default").unwrap();
        let mut text = std::fs::read_to_string(s.layout.networks_file()).unwrap();
        text.push_str("мусор без табуляций\n");
        std::fs::write(s.layout.networks_file(), text).unwrap();
        let (nets, warns) = s.networks();
        assert_eq!(nets.len(), 2, "{nets:?}");
        assert_eq!(warns.len(), 1);
        let c = nets.iter().find(|n| n.key == cafe.key()).unwrap();
        assert_eq!(
            (c.title.as_str(), c.strategy.as_str()),
            ("Wi-Fi «Café»", "alt4")
        );
        s.delete_network(&cafe.key()).unwrap();
        assert_eq!(s.networks().0.len(), 1);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn put_network_keeps_order() {
        let (s, root) = store("put");
        s.set_network_entry("a", "A", "alt").unwrap();
        s.set_network_entry("b", "B", "alt4").unwrap();
        let before = std::fs::read_to_string(s.layout.networks_file()).unwrap();
        s.put_network_entry("a", "A", "default").unwrap();
        assert_eq!(
            std::fs::read_to_string(s.layout.networks_file()).unwrap(),
            "a\tA\tdefault\nb\tB\talt4\n"
        );
        s.put_network_entry("a", "A", "alt").unwrap();
        assert_eq!(
            std::fs::read_to_string(s.layout.networks_file()).unwrap(),
            before
        );
        s.put_network_entry("c", "C", "alt").unwrap();
        assert_eq!(s.networks().0.last().unwrap().key, "c");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn home_add_remove_dedup() {
        let (s, root) = store("home");
        assert!(s.home().is_empty());
        s.add_home("Home").unwrap();
        s.add_home("Home").unwrap();
        s.add_home("Дача 5G").unwrap();
        assert_eq!(s.home(), vec!["Home".to_string(), "Дача 5G".to_string()]);
        s.remove_home("Home").unwrap();
        assert_eq!(s.home(), vec!["Дача 5G".to_string()]);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn list_count_ignores_comments() {
        let (s, root) = store("count");
        s.write_list("ipset", "# заголовок\n\n1.1.1.1\n  \n8.8.8.0/24\n")
            .unwrap();
        assert_eq!(s.list_count("ipset"), 2);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn settings_roundtrip_through_file() {
        let (s, root) = store("settings");
        let (mut st, warns) = s.settings();
        assert!(warns.is_empty());
        st.block_quic = true;
        s.save_settings(&st).unwrap();
        assert!(s.settings().0.block_quic);
        std::fs::remove_dir_all(root).ok();
    }
}
