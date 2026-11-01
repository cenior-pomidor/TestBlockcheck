use std::fmt;
use std::path::PathBuf;
use std::sync::RwLock;

/// nfqws2 по умолчанию — из установленного модуля nfqws2-android (собран из zapret2 v1.0.5.2,
/// `--filter-mark` в нём есть).
pub const DEFAULT_NFQWS2: &str = "/data/adb/modules/nfqws2-android/bin/nfqws2";

/// Lua-библиотеки движка по умолчанию — оттуда же.
pub const DEFAULT_LUA_DIR: &str = "/data/adb/modules/nfqws2-android/lua";

/// Рабочий каталог: замок, отчёты прогонов. На Android нет `/var/run` и `/tmp` у root-shell.
pub const DEFAULT_WORK_DIR: &str = "/data/adb/bcw";

/// Боевая очередь по умолчанию: не 200 (magisk-zapret2) и не 300 (nfqws2-android).
pub const DEFAULT_QNUM: u16 = 777;

/// Пути процесса. Ставятся один раз разбором командной строки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub nfqws2: PathBuf,
    pub lua_dir: PathBuf,
    pub work_dir: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            nfqws2: DEFAULT_NFQWS2.into(),
            lua_dir: DEFAULT_LUA_DIR.into(),
            work_dir: DEFAULT_WORK_DIR.into(),
        }
    }
}

static PATHS: RwLock<Option<Paths>> = RwLock::new(None);

/// Объявить пути процесса (до всякой работы с файлами).
pub fn set_paths(paths: Paths) {
    if let Ok(mut slot) = PATHS.write() {
        *slot = Some(paths);
    }
}

/// Пути процесса; не заданы — умолчания.
pub fn paths() -> Paths {
    match PATHS.read() {
        Ok(slot) => slot.clone().unwrap_or_default(),
        Err(_) => Paths::default(),
    }
}

/// Префикс наших цепочек iptables (`bcw_raw`, `bcw_out`, …). Не должен совпадать с чужими:
/// nfqws2-android использует `nfqws_*`, иначе их цепочки попали бы под нашу уборку.
pub const DEFAULT_CHAIN_PREFIX: &str = "bcw";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode {
    Auto,
    System,
    Doh,
}

impl fmt::Display for DnsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsMode::Auto => write!(f, "auto"),
            DnsMode::System => write!(f, "system"),
            DnsMode::Doh => write!(f, "doh"),
        }
    }
}

pub fn parse_dns_mode(s: &str) -> Result<DnsMode, String> {
    match s.to_lowercase().as_str() {
        "auto" => Ok(DnsMode::Auto),
        "system" => Ok(DnsMode::System),
        "doh" => Ok(DnsMode::Doh),
        _ => Err(format!(
            "unknown dns mode: '{s}'. expected: auto, system, doh"
        )),
    }
}

/// КЛЮЧИ ЯДРА — пространства имён, которые задаёт тот, кто нас позвал.
///
/// Глобально, как и раскладка марки ([`crate::nfqws2::space`]), и по той же причине: очередь
/// и таблица — свойства ПРОЦЕССА, одни на весь прогон, а читают их и пайплайн, и преflight,
/// и уборщик остатков. Ставится один раз разбором командной строки, до всякой работы с ядром.
///
/// Зачем вообще: у оркестратора эти пространства уже заняты, и заняты плотно — его очереди,
/// очереди стенда, пул слотов. Умолчание, которое нельзя сдвинуть, означало бы, что подбор
/// либо встанет на чужую очередь, либо не запустится вовсе.
mod kernel_keys {
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::RwLock;

    pub(super) static QNUM: AtomicU16 = AtomicU16::new(super::DEFAULT_QNUM);
    pub(super) static SMOKE_BASE: AtomicU16 = AtomicU16::new(65_526);
    pub(super) static TABLE: RwLock<String> = RwLock::new(String::new());

    pub(super) fn table() -> String {
        match TABLE.read() {
            Ok(name) if !name.is_empty() => name.clone(),
            // Пусто (не задавали) или отравлен (упал сосед) — умолчание. Имя таблицы не
            // тот предмет, ради которого стоит ронять прогон.
            _ => super::DEFAULT_CHAIN_PREFIX.to_string(),
        }
    }

    pub(super) fn set_table(name: &str) {
        if let Ok(mut slot) = TABLE.write() {
            *slot = name.to_string();
        }
    }

    pub(super) fn qnum() -> u16 {
        QNUM.load(Ordering::Relaxed)
    }

    pub(super) fn smoke_base() -> u16 {
        SMOKE_BASE.load(Ordering::Relaxed)
    }
}

/// Объявить ключи ядра (ставится разбором командной строки).
pub fn set_kernel_keys(qnum: u16, chain_prefix: &str, smoke_qnum_base: u16) {
    kernel_keys::QNUM.store(qnum, std::sync::atomic::Ordering::Relaxed);
    kernel_keys::SMOKE_BASE.store(smoke_qnum_base, std::sync::atomic::Ordering::Relaxed);
    kernel_keys::set_table(chain_prefix);
}

/// Боевая очередь этого прогона.
pub fn qnum() -> u16 {
    kernel_keys::qnum()
}

/// Начало диапазона дымовых очередей (длина — [`SMOKE_QUEUE_COUNT`]).
pub fn smoke_qnum_base() -> u16 {
    kernel_keys::smoke_base()
}

/// Сколько очередей в дымовом диапазоне.
pub const SMOKE_QUEUE_COUNT: u16 = 10;

/// Префикс наших цепочек iptables в этом прогоне.
pub fn chain_prefix() -> String {
    kernel_keys::table()
}

#[derive(Debug, Clone)]
pub struct CoreConfig {
    pub worker_count: usize,
    /// Сколько стратегий держать загруженными в одном процессе nfqws2 (#68).
    /// Не то же самое, что `worker_count`: это ёмкость плана, а `worker_count` —
    /// сколько проб этого плана летит одновременно.
    pub profiles_per_instance: usize,
    pub base_qnum: u16,
    pub chain_prefix: String,
    pub nfqws2_path: String,
    pub lua_dir: PathBuf,
    pub request_timeout: u64,
    pub nfqws2_uid: u32,
    pub nfqws2_gid: u32,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            worker_count: 8,
            profiles_per_instance: MAX_PROFILES_PER_INSTANCE,
            base_qnum: qnum(),
            chain_prefix: chain_prefix(),
            nfqws2_path: paths().nfqws2.to_string_lossy().into_owned(),
            lua_dir: paths().lua_dir,
            request_timeout: 2,
            // На Android нет `nobody` в /etc/passwd; nfqws2-android тоже запускает движок от root.
            nfqws2_uid: 0,
            nfqws2_gid: 0,
        }
    }
}

/// Потолок числа профилей в одном плане: поле стратегии в метке — восемь бит, номера
/// `1…254`, а `255` — метка контроля (`nfqws2::space`).
pub const MAX_PROFILES_PER_INSTANCE: usize = crate::nfqws2::space::MAX_PROFILE_INDEX as usize;

pub fn validate_parallelism(
    worker_count: usize,
    profiles_per_instance: usize,
) -> Result<(), String> {
    if worker_count == 0 {
        return Err(
            "--workers 0 (may have come from saved configuration, not just the flag): \
             the probe semaphore will never hand out a permit, and the process will hang \
             forever — AFTER the NFQUEUE rules are already in place"
                .to_string(),
        );
    }
    if profiles_per_instance == 0 {
        return Err(
            "--profiles-per-instance 0: a plan with no profiles cannot test anything".to_string(),
        );
    }
    if profiles_per_instance > MAX_PROFILES_PER_INSTANCE {
        return Err(format!(
            "--profiles-per-instance {profiles_per_instance} exceeds the ceiling of \
             {MAX_PROFILES_PER_INSTANCE}: the profile number does not fit in the mark"
        ));
    }
    if worker_count > profiles_per_instance {
        return Err(format!(
            "--workers {worker_count} exceeds --profiles-per-instance {profiles_per_instance} \
             (--workers may have come from saved configuration, not just the flag): \
             the plan cannot serve that many probes at once. Fix: raise \
             --profiles-per-instance to at least {worker_count} (ceiling {MAX_PROFILES_PER_INSTANCE}), \
             or pass -w to reset the saved --workers value"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod parallelism_tests {
    use super::validate_parallelism;

    #[test]
    fn the_profile_ceiling_is_254() {
        assert!(validate_parallelism(8, 254).is_ok());
        assert!(validate_parallelism(8, 255).is_err());
    }

    #[test]
    fn workers_may_not_exceed_loaded_profiles() {
        assert!(validate_parallelism(200, 100).is_err());
    }

    #[test]
    fn zero_workers_is_rejected() {
        let err = validate_parallelism(0, 1024).expect_err("0 воркеров обязано быть ошибкой");
        assert!(
            err.contains("0"),
            "сообщение должно называть нулевое значение: {err}"
        );
    }

    #[test]
    fn profiles_may_not_outgrow_the_mark() {
        use super::MAX_PROFILES_PER_INSTANCE;
        assert!(validate_parallelism(8, MAX_PROFILES_PER_INSTANCE).is_ok());
        assert!(validate_parallelism(8, MAX_PROFILES_PER_INSTANCE + 1).is_err());
        assert!(validate_parallelism(8, 0).is_err());
    }

    #[test]
    fn defaults_are_consistent() {
        let c = super::CoreConfig::default();
        assert!(validate_parallelism(c.worker_count, c.profiles_per_instance).is_ok());
        assert_eq!(c.profiles_per_instance, 254);
    }
}

impl CoreConfig {
    /// Окружение для запуска движка.
    pub fn nfqws2_env(&self) -> crate::nfqws2::plan::Env {
        crate::nfqws2::plan::Env {
            binary: self.nfqws2_path.clone().into(),
            lua: vec![
                self.lua_dir.join("zapret-lib.lua"),
                self.lua_dir.join("zapret-antidpi.lua"),
            ],
            uid: self.nfqws2_uid,
            gid: self.nfqws2_gid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Http,
    HttpsTls12,
    HttpsTls13,
}

impl Protocol {
    pub fn all() -> Vec<Protocol> {
        vec![Protocol::Http, Protocol::HttpsTls12, Protocol::HttpsTls13]
    }

    pub fn port(self) -> u16 {
        match self {
            Protocol::Http => 80,
            Protocol::HttpsTls12 | Protocol::HttpsTls13 => 443,
        }
    }

    pub fn test_func_name(self) -> &'static str {
        match self {
            Protocol::Http => "http_test_http",
            Protocol::HttpsTls12 => "http_test_https_tls12",
            Protocol::HttpsTls13 => "http_test_https_tls13",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Http => write!(f, "HTTP"),
            Protocol::HttpsTls12 => write!(f, "HTTPS/TLS1.2"),
            Protocol::HttpsTls13 => write!(f, "HTTPS/TLS1.3"),
        }
    }
}

pub fn parse_protocols(s: &str) -> Result<Vec<Protocol>, String> {
    let mut protocols = Vec::new();
    for token in s.split(',') {
        let token = token.trim();
        let protocol = match token {
            "http" => Protocol::Http,
            "tls12" => Protocol::HttpsTls12,
            "tls13" => Protocol::HttpsTls13,
            _ => {
                return Err(format!(
                    "unknown protocol: '{token}'. expected: http, tls12, tls13"
                ))
            }
        };
        protocols.push(protocol);
    }
    if protocols.is_empty() {
        return Err("no protocols specified".to_string());
    }
    Ok(protocols)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_defaults() {
        let c = CoreConfig::default();
        assert_eq!(c.nfqws2_path, DEFAULT_NFQWS2);
        assert_eq!(
            (
                c.nfqws2_uid,
                c.nfqws2_gid,
                c.base_qnum,
                c.profiles_per_instance
            ),
            (0, 0, 777, 254)
        );
        assert_eq!(c.chain_prefix, "bcw");
    }

    #[test]
    fn nfqws2_env_uses_lua_dir() {
        let env = CoreConfig::default().nfqws2_env();
        let lua = std::path::Path::new(DEFAULT_LUA_DIR);
        assert_eq!(
            env.lua,
            [lua.join("zapret-lib.lua"), lua.join("zapret-antidpi.lua")]
        );
        assert_eq!((env.uid, env.gid), (0, 0));
        assert_eq!(env.binary, std::path::Path::new(DEFAULT_NFQWS2));
    }

    #[test]
    fn default_chain_prefix_does_not_collide_with_foreign_ones() {
        // nfqws2-android: nfqws_*; nzapret и прочие модули — свои имена
        for foreign in ["nfqws", "zapret", "zapret2"] {
            assert_ne!(DEFAULT_CHAIN_PREFIX, foreign);
        }
        assert_eq!(CoreConfig::default().chain_prefix, DEFAULT_CHAIN_PREFIX);
    }

    #[test]
    fn test_parse_protocols_all() {
        let result = parse_protocols("http,tls12,tls13").unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], Protocol::Http);
        assert_eq!(result[1], Protocol::HttpsTls12);
        assert_eq!(result[2], Protocol::HttpsTls13);
    }

    #[test]
    fn test_parse_protocols_single() {
        let result = parse_protocols("tls13").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], Protocol::HttpsTls13);
    }

    #[test]
    fn test_parse_protocols_with_spaces() {
        let result = parse_protocols("http, tls12").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], Protocol::Http);
        assert_eq!(result[1], Protocol::HttpsTls12);
    }

    #[test]
    fn test_parse_protocols_unknown() {
        let result = parse_protocols("http,quic");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("quic"));
    }

    #[test]
    fn test_protocol_all() {
        let all = Protocol::all();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_parse_dns_mode_valid() {
        assert_eq!(parse_dns_mode("auto").unwrap(), DnsMode::Auto);
        assert_eq!(parse_dns_mode("system").unwrap(), DnsMode::System);
        assert_eq!(parse_dns_mode("doh").unwrap(), DnsMode::Doh);
        assert_eq!(parse_dns_mode("DOH").unwrap(), DnsMode::Doh);
        assert_eq!(parse_dns_mode("Auto").unwrap(), DnsMode::Auto);
    }

    #[test]
    fn test_parse_dns_mode_invalid() {
        assert!(parse_dns_mode("plain").is_err());
        assert!(parse_dns_mode("").is_err());
    }

    #[test]
    fn test_dns_mode_display() {
        assert_eq!(DnsMode::Auto.to_string(), "auto");
        assert_eq!(DnsMode::System.to_string(), "system");
        assert_eq!(DnsMode::Doh.to_string(), "doh");
    }

    #[test]
    fn env_carries_both_lua_scripts_and_the_binary() {
        let config = CoreConfig::default();
        let env = config.nfqws2_env();
        assert_eq!(env.lua.len(), 2, "движку нужны обе библиотеки");
        assert!(env.lua[0].to_string_lossy().ends_with("zapret-lib.lua"));
        assert!(env.lua[1].to_string_lossy().ends_with("zapret-antidpi.lua"));
        // binary — путь к самому бинарю, а не к каталогу zapret_base: если
        // конверсия перепутает поля, здесь бы прошёл каталог вместо файла.
        assert_eq!(
            env.binary,
            std::path::PathBuf::from(&config.nfqws2_path),
            "env.binary обязан быть путём к бинарю nfqws2, а не к zapret_base"
        );
        assert_eq!(env.uid, config.nfqws2_uid);
        assert_eq!(env.gid, config.nfqws2_gid);
    }
}
