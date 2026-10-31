//! `bcw doctor` — проверка телефона перед первым прогоном.
//!
//! Отвечает на один вопрос: годится ли ЭТО устройство для подбора — до того, как подбор
//! поставит хоть одно правило. Вывод машинный (JSON в stdout, его покажет экран модуля) и
//! человеческий (таблица в stderr). Ничего не меняет: правила проверяются `--test`, без
//! применения.

use std::net::SocketAddr;
use std::time::Duration;

use serde::Serialize;

use blockcheckw::config::{chain_prefix, paths, CoreConfig};
use blockcheckw::firewall::ipt::{IptRun, SystemIpt};
use blockcheckw::firewall::rules::{static_batches, ChainNames};
use blockcheckw::network::{doh, http_client};
use blockcheckw::nfqws2::mark::{control_mark, ProfileMark};
use blockcheckw::nfqws2::run::SystemNfqws2;

/// Версия формата отчёта `doctor`.
pub const SCHEMA: u32 = 1;

/// Опции ядра, без которых подбор не работает (спека §5.6).
pub const KERNEL_OPTIONS: [&str; 7] = [
    "NETFILTER_XT_TARGET_NFQUEUE",
    "NETFILTER_XT_MATCH_CONNBYTES",
    "NETFILTER_XT_TARGET_CONNMARK",
    "NETFILTER_XT_MATCH_CONNMARK",
    "NETFILTER_XT_TARGET_CT",
    "IP_NF_MANGLE",
    "IP_NF_RAW",
];

const LUA_FILES: [&str; 2] = ["zapret-lib.lua", "zapret-antidpi.lua"];
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const NEED_ROOT: &str = "нужен root";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Fail,
    /// Не наблюдали: это не приговор устройству.
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: String,
    pub status: Status,
    pub detail: String,
}

impl Check {
    fn new(id: impl Into<String>, status: Status, detail: impl Into<String>) -> Self {
        Check {
            id: id.into(),
            status,
            detail: detail.into(),
        }
    }

    fn of(id: &str, ok: bool, detail: impl Into<String>) -> Self {
        Check::new(id, if ok { Status::Ok } else { Status::Fail }, detail)
    }
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub schema: u32,
    /// Истинно, если ни одна проверка не провалилась. `Unknown` не роняет: «не знаем» и
    /// «нельзя» — разные вещи.
    pub ok: bool,
    pub checks: Vec<Check>,
}

impl DoctorReport {
    pub fn from_checks(checks: Vec<Check>) -> Self {
        DoctorReport {
            schema: SCHEMA,
            ok: checks.iter().all(|c| c.status != Status::Fail),
            checks,
        }
    }
}

/// Проверки опций ядра по тексту `/proc/config.gz`. `None` — конфиг ядра не опубликован.
pub fn kernel_checks(config: Option<&str>) -> Vec<Check> {
    KERNEL_OPTIONS
        .iter()
        .map(|opt| {
            let id = format!("kernel:{opt}");
            let Some(config) = config else {
                return Check::new(id, Status::Unknown, "/proc/config.gz недоступен");
            };
            let key = format!("CONFIG_{opt}=");
            let value = config
                .lines()
                .find_map(|line| line.trim().strip_prefix(key.as_str()))
                .map(str::trim);
            match value {
                Some(v @ ("y" | "m")) => Check::new(id, Status::Ok, v),
                Some(v) => Check::new(id, Status::Fail, v),
                None => Check::new(id, Status::Fail, "не задана"),
            }
        })
        .collect()
}

/// Номера занятых очередей NFQUEUE из `/proc/net/netfilter/nfnetlink_queue`.
pub fn busy_queues(procfs: &str) -> Vec<u16> {
    procfs
        .lines()
        .filter_map(|line| line.split_whitespace().next()?.parse().ok())
        .collect()
}

/// Таблица для человека.
pub fn render_table(report: &DoctorReport) -> String {
    let width = report.checks.iter().map(|c| c.id.len()).max().unwrap_or(0);
    let mut out = String::new();
    for c in &report.checks {
        let status = match c.status {
            Status::Ok => "ok",
            Status::Fail => "FAIL",
            Status::Unknown => "?",
        };
        out.push_str(&format!(
            "  {:<width$}  {:<4}  {}\n",
            c.id, status, c.detail
        ));
    }
    out.push_str(if report.ok {
        "  итог: устройство готово к подбору\n"
    } else {
        "  итог: есть провалы — подбор на этом устройстве не заработает\n"
    });
    out
}

/// Текст `/proc/config.gz`: распаковать тем, что есть в системе (на Android — toybox).
async fn read_kernel_config() -> Option<String> {
    use blockcheckw::system::process::run_process;
    for argv in [
        &["zcat", "/proc/config.gz"][..],
        &["gzip", "-dc", "/proc/config.gz"][..],
    ] {
        if let Ok(r) = run_process(argv, 5_000).await {
            if r.exit_code == 0 && !r.stdout.is_empty() {
                return Some(r.stdout);
            }
        }
    }
    None
}

/// Уходит ли в сеть сокет с меткой `mark`: первый резолвер, до которого удалось
/// соединиться на 443, — свидетель.
async fn route_check(id: &str, mark: u32) -> Check {
    let mut tried = Vec::new();
    for server in doh::servers() {
        let Ok(ip) = server.ip.parse::<std::net::Ipv4Addr>() else {
            continue;
        };
        let addr = SocketAddr::from((ip, 443));
        match tokio::time::timeout(CONNECT_TIMEOUT, http_client::marked_tcp_connect(addr, mark))
            .await
        {
            Ok(Ok(_)) => return Check::new(id, Status::Ok, format!("0x{mark:08X} → {addr}")),
            Ok(Err(e)) => tried.push(format!("{addr}: {e}")),
            Err(_) => tried.push(format!("{addr}: таймаут")),
        }
    }
    Check::new(
        id,
        Status::Fail,
        format!("метка 0x{mark:08X} не уходит в сеть: {}", tried.join("; ")),
    )
}

async fn doh_check() -> Check {
    for server in doh::servers() {
        if let Some(ips) = doh::doh_resolve("example.com", &server).await {
            if !ips.is_empty() {
                return Check::new(
                    "doh",
                    Status::Ok,
                    format!("{} ({})", server.host, server.ip),
                );
            }
        }
    }
    Check::new(
        "doh",
        Status::Fail,
        "ни один DoH-резолвер не ответил — задайте свой ключом --doh",
    )
}

async fn rules_check() -> Check {
    for batch in static_batches(&ChainNames::new(&chain_prefix())) {
        let table = batch.table().name();
        if let Err(e) = SystemIpt.restore_test(batch).await {
            return Check::new("rules_test", Status::Fail, format!("{table}: {e}"));
        }
    }
    Check::new(
        "rules_test",
        Status::Ok,
        "raw и mangle разобраны iptables-restore --test",
    )
}

async fn neighbours_check() -> Check {
    let conflicts = super::detect_bypass_conflicts(&chain_prefix()).await;
    let queues = std::fs::read_to_string(blockcheckw::nfqws2::ready::PROCFS_PATH)
        .map(|s| busy_queues(&s))
        .unwrap_or_default();
    Check::new(
        "neighbours",
        Status::Ok,
        format!(
            "цепочки с очередью: [{}]; nfqws2 running: {}; занятые очереди: {:?}",
            conflicts.foreign_queue_chains.join(", "),
            conflicts.has_nfqws2_processes,
            queues,
        ),
    )
}

/// Все проверки по порядку спеки.
pub async fn run() -> DoctorReport {
    let root = nix::unistd::geteuid().is_root();
    let mut checks = vec![Check::of(
        "root",
        root,
        if root {
            "uid 0"
        } else {
            "запустите через su -c"
        },
    )];
    checks.extend(kernel_checks(read_kernel_config().await.as_deref()));

    if !root {
        for id in [
            "iptables",
            "iptables_restore",
            "rules_test",
            "nfqws2",
            "filter_mark",
            "lua",
            "route_control",
            "route_profile",
            "doh",
            "neighbours",
        ] {
            checks.push(Check::new(id, Status::Unknown, NEED_ROOT));
        }
        return DoctorReport::from_checks(checks);
    }

    let iptables = super::which(blockcheckw::firewall::ipt::IPTABLES);
    let restore = super::which(blockcheckw::firewall::ipt::IPTABLES_RESTORE);
    checks.push(Check::of("iptables", iptables, "в PATH"));
    checks.push(Check::of("iptables_restore", restore, "в PATH"));
    checks.push(if iptables && restore {
        rules_check().await
    } else {
        Check::new("rules_test", Status::Unknown, "нет iptables")
    });

    let paths = paths();
    let nfqws2 = paths.nfqws2.is_file();
    checks.push(Check::of(
        "nfqws2",
        nfqws2,
        format!("{} (ключ --nfqws2)", paths.nfqws2.display()),
    ));
    checks.push(if nfqws2 {
        match SystemNfqws2::probe_sync(&CoreConfig::default().nfqws2_env()) {
            Ok(_) => Check::new("filter_mark", Status::Ok, "--filter-mark поддерживается"),
            Err(e) => Check::new("filter_mark", Status::Fail, e.to_string()),
        }
    } else {
        Check::new("filter_mark", Status::Unknown, "нет nfqws2")
    });
    let missing: Vec<&str> = LUA_FILES
        .iter()
        .copied()
        .filter(|f| !paths.lua_dir.join(f).is_file())
        .collect();
    checks.push(Check::of(
        "lua",
        missing.is_empty(),
        if missing.is_empty() {
            format!("{} (ключ --lua-dir)", paths.lua_dir.display())
        } else {
            format!("нет {} в {}", missing.join(", "), paths.lua_dir.display())
        },
    ));

    checks.push(route_check("route_control", control_mark()).await);
    let profile = ProfileMark::new(1)
        .expect("единица — валидный номер стратегии")
        .so_mark();
    checks.push(route_check("route_profile", profile).await);
    checks.push(doh_check().await);
    checks.push(neighbours_check().await);

    DoctorReport::from_checks(checks)
}

/// Точка входа подкоманды: JSON в stdout, таблица в stderr, код выхода по итогу.
pub async fn run_doctor_cmd() -> ! {
    let report = run().await;
    eprint!("{}", render_table(&report));
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("doctor report serialization")
    );
    std::process::exit(if report.ok { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_of<'a>(checks: &'a [Check], id: &str) -> &'a Status {
        &checks
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("нет проверки {id}: {checks:?}"))
            .status
    }

    #[test]
    fn kernel_checks_read_y_and_m() {
        let cfg = "CONFIG_NETFILTER_XT_TARGET_NFQUEUE=y\n\
                   CONFIG_NETFILTER_XT_MATCH_CONNBYTES=m\n\
                   # CONFIG_IP_NF_RAW is not set\n";
        let c = kernel_checks(Some(cfg));
        assert_eq!(c.len(), 7);
        assert_eq!(
            *status_of(&c, "kernel:NETFILTER_XT_TARGET_NFQUEUE"),
            Status::Ok
        );
        assert_eq!(
            *status_of(&c, "kernel:NETFILTER_XT_MATCH_CONNBYTES"),
            Status::Ok
        );
        assert_eq!(*status_of(&c, "kernel:IP_NF_RAW"), Status::Fail);
        assert_eq!(*status_of(&c, "kernel:IP_NF_MANGLE"), Status::Fail);
    }

    /// Нет `/proc/config.gz` — не знаем, а не «нет модуля»: ядро могло собрать его и без
    /// публикации конфига.
    #[test]
    fn missing_kernel_config_is_unknown_not_fail() {
        let c = kernel_checks(None);
        assert_eq!(c.len(), 7);
        assert!(c.iter().all(|c| c.status == Status::Unknown), "{c:?}");
    }

    #[test]
    fn report_is_ok_only_without_failures() {
        let check = |status| Check {
            id: "x".into(),
            status,
            detail: String::new(),
        };
        assert!(DoctorReport::from_checks(vec![check(Status::Ok), check(Status::Unknown)]).ok);
        assert!(!DoctorReport::from_checks(vec![check(Status::Ok), check(Status::Fail)]).ok);
    }

    #[test]
    fn busy_queues_are_read_from_procfs_format() {
        let procfs =
            "  300  12345     0 2 65531     0     0        0  1\n  777 999 0 2 65531 0 0 0 1\n";
        assert_eq!(busy_queues(procfs), [300, 777]);
        assert!(busy_queues("").is_empty());
    }

    #[test]
    fn report_json_shape() {
        let report = DoctorReport::from_checks(vec![
            Check {
                id: "root".into(),
                status: Status::Ok,
                detail: "uid 0".into(),
            },
            Check {
                id: "kernel:IP_NF_RAW".into(),
                status: Status::Fail,
                detail: String::new(),
            },
            Check {
                id: "doh".into(),
                status: Status::Unknown,
                detail: "нужен root".into(),
            },
        ]);
        let v: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert_eq!(v["schema"], 1);
        assert_eq!(v["ok"], false);
        let statuses: Vec<&str> = v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                assert!(c.get("id").is_some() && c.get("detail").is_some());
                c["status"].as_str().unwrap()
            })
            .collect();
        assert_eq!(statuses, ["ok", "fail", "unknown"]);
    }
}
