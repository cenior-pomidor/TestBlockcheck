pub mod benchmark;
pub mod check;
pub mod ctl;
pub mod doctor;
pub mod scan;
pub mod search;
pub mod status;
pub mod svc;
pub mod universal;

use std::sync::Arc;

use console::style;
use tokio::sync::Mutex;

use blockcheckw::firewall::ipt::{
    IptRun, IptRunSync, SystemIpt, SystemIptSync, Table, IPTABLES, IPTABLES_RESTORE,
};
use blockcheckw::firewall::rules::OwnedChainsMarker;
use blockcheckw::ui::WARN;

/// Write JSON to stdout, silently ignoring BrokenPipe (downstream closed).
pub fn print_stdout_graceful(data: &str, con: &blockcheckw::ui::Console) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match out
        .write_all(data.as_bytes())
        .and_then(|_| out.write_all(b"\n"))
    {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(e) => con.error(&format!("stdout write error: {e}")),
    }
}

// ── Соседи по ядру ──────────────────────────────────────────────────────────

/// Кто рядом: чужие цепочки mangle с очередью и процессы nfqws2. Только наблюдение — на
/// Android обходом владеет пользователь, и трогать его модуль мы не вправе.
pub struct BypassConflicts {
    pub has_nfqws2_processes: bool,
    pub foreign_queue_chains: Vec<String>,
}

impl BypassConflicts {
    pub fn is_empty(&self) -> bool {
        !self.has_nfqws2_processes && self.foreign_queue_chains.is_empty()
    }
}

/// Чужие цепочки с `-j NFQUEUE` по выводу `iptables -t mangle -S`: без своих, без повторов,
/// в порядке появления.
pub fn foreign_queue_chains(save: &str, own_prefix: &str) -> Vec<String> {
    let own = format!("{own_prefix}_");
    let mut found: Vec<String> = Vec::new();
    for line in save.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("-A") {
            continue;
        }
        let Some(chain) = words.next() else { continue };
        let queues = line
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|w| w == ["-j", "NFQUEUE"]);
        if queues && !chain.starts_with(&own) && !found.iter().any(|c| c == chain) {
            found.push(chain.to_string());
        }
    }
    found
}

fn pgrep_has_matches(exit_code: i32, stdout: &str) -> bool {
    exit_code == 0 && !stdout.trim().is_empty()
}

/// Посмотреть, кто рядом. Ничего не меняет.
pub async fn detect_bypass_conflicts(own_prefix: &str) -> BypassConflicts {
    use blockcheckw::system::process::run_process;

    let mut conflicts = BypassConflicts {
        has_nfqws2_processes: false,
        foreign_queue_chains: Vec::new(),
    };

    if let Ok(result) = run_process(&["pgrep", "-x", "nfqws2"], 3_000).await {
        conflicts.has_nfqws2_processes = pgrep_has_matches(result.exit_code, &result.stdout);
    }

    if let Ok(out) = SystemIpt.cmd(Table::Mangle, &["-S".to_string()]).await {
        if out.ok {
            conflicts.foreign_queue_chains = foreign_queue_chains(&out.stdout, own_prefix);
        }
    }

    conflicts
}

/// Сказать о соседях: в консоль и машинно (`neighbours`). Наши пробы идут мимо их цепочек
/// (изоляция по метке), но человеку и продукту полезно знать, что рядом работает обход.
///
/// Службу обхода на Android мы не останавливаем никогда.
pub async fn handle_bypass_conflicts(own_prefix: &str, con: &blockcheckw::ui::Console) {
    let conflicts = detect_bypass_conflicts(own_prefix).await;
    if !conflicts.is_empty() {
        con.warn(&format!(
            "рядом работает обход (цепочек с очередью: {}, процессы nfqws2: {}) — не трогаю; \
             наши пробы идут мимо его цепочек",
            conflicts.foreign_queue_chains.len(),
            if conflicts.has_nfqws2_processes {
                "есть"
            } else {
                "нет"
            },
        ));
        blockcheckw::machine::emit_neighbours(
            &conflicts.foreign_queue_chains,
            conflicts.has_nfqws2_processes,
        );
    }
}

// ── Shared cleanup state ────────────────────────────────────────────────────

/// Shared state for Ctrl+C handler: our iptables chains to drop.
pub type CleanupState = Arc<Mutex<CleanupInfo>>;

pub struct CleanupInfo {
    /// Метка НАШИХ цепочек: единственное, что аварийные пути вправе снести.
    pub chains: OwnedChainsMarker,
    /// Strategies found so far, so a Ctrl+C / SIGTERM mid-scan still writes them.
    pub scan_progress: Option<ScanProgressState>,
}

fn emergency_cleanup_sync(info: &CleanupInfo) {
    // Drop queue rules before terminating their listeners so packets are not
    // sent to an unbound NFQUEUE during emergency shutdown.
    blockcheckw::firewall::rules::drop_chains_sync(&SystemIptSync, &info.chains);
    blockcheckw::system::process::start_kill_all_background_processes();
}

// ── Scan progress (interrupt-safe result accumulator) ────────────────────────

/// Sink that `run_parallel` pushes each AVAILABLE strategy's args into as it is
/// discovered, so found strategies are never lost to an interrupt.
pub type SuccessSink = Arc<std::sync::Mutex<Vec<Vec<String>>>>;

/// Shared, signal-handler-visible view of what a scan has found so far.
pub type ScanProgressState = Arc<std::sync::Mutex<ScanProgress>>;

struct CurrentProto {
    protocol: blockcheckw::config::Protocol,
    found: SuccessSink,
}

/// Accumulates scan results across protocols. The signal handler reads
/// [`snapshot`](ScanProgress::snapshot) to write a report before exiting, so an
/// interrupt mid-protocol still persists everything found up to that point.
pub struct ScanProgress {
    pub domain: String,
    pub output: Option<String>,
    pub block_type: blockcheckw::dto::BlockType,
    pub dns_spoofed: blockcheckw::dto::DnsSpoofed,
    blocked: Vec<blockcheckw::config::Protocol>,
    completed: Vec<blockcheckw::pipeline::report::ProtocolSummary>,
    current: Option<CurrentProto>,
    /// Сколько кандидатов доведено до вердикта — наращивает исполнитель по ходу прогона.
    tried: Arc<std::sync::atomic::AtomicUsize>,
    /// Сколько кандидатов набрано по начатым протоколам.
    candidates: usize,
}

impl ScanProgress {
    pub fn new(domain: String, output: Option<String>) -> ScanProgressState {
        Arc::new(std::sync::Mutex::new(ScanProgress {
            domain,
            output,
            block_type: blockcheckw::dto::BlockType::NotBlocked,
            dns_spoofed: blockcheckw::dto::DnsSpoofed::Unchecked,
            blocked: Vec::new(),
            completed: Vec::new(),
            current: None,
            tried: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            candidates: 0,
        }))
    }

    /// Record the blocked protocols detected at baseline, so an interrupted
    /// scan persists the same `blocked` list as a completed run (#49).
    pub fn set_blocked(&mut self, blocked: Vec<blockcheckw::config::Protocol>) {
        self.blocked = blocked;
    }

    /// Record the network-layer block verdict so an interrupted scan persists
    /// the same `block_type` as a completed run.
    pub fn set_block_type(&mut self, block_type: blockcheckw::dto::BlockType) {
        self.block_type = block_type;
    }

    /// Record the DNS-spoofing flag so an interrupted scan persists it too.
    pub fn set_dns_spoofed(&mut self, dns_spoofed: blockcheckw::dto::DnsSpoofed) {
        self.dns_spoofed = dns_spoofed;
    }

    /// Счётчик проверенных — отдаётся исполнителю (`RunParams::completed`).
    pub fn tried_counter(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        self.tried.clone()
    }

    /// Учесть корпус начатого протокола.
    pub fn add_candidates(&mut self, n: usize) {
        self.candidates += n;
    }

    /// `(проверено, всего)` — для `run.tried` / `run.total` отчёта.
    pub fn counts(&self) -> (usize, usize) {
        (
            self.tried.load(std::sync::atomic::Ordering::Relaxed),
            self.candidates,
        )
    }

    /// Start a protocol; returns the sink to hand to `run_parallel`.
    pub fn begin_protocol(&mut self, protocol: blockcheckw::config::Protocol) -> SuccessSink {
        let found: SuccessSink = Arc::new(std::sync::Mutex::new(Vec::new()));
        self.current = Some(CurrentProto {
            protocol,
            found: found.clone(),
        });
        found
    }

    /// Fold the in-progress protocol into the completed set (called when it
    /// finishes normally). Empty protocols are kept to mirror the summary shown.
    pub fn finish_protocol(&mut self) {
        if let Some(c) = self.current.take() {
            let strategies = c.found.lock().unwrap().clone();
            self.completed
                .push(blockcheckw::pipeline::report::ProtocolSummary {
                    protocol: c.protocol,
                    strategies,
                });
        }
    }

    /// Everything found so far, including the in-progress protocol's partial
    /// results. This is what makes an interrupted scan still produce a report.
    pub fn snapshot(&self) -> Vec<blockcheckw::pipeline::report::ProtocolSummary> {
        let mut out = self.completed.clone();
        if let Some(c) = &self.current {
            let found = c.found.lock().unwrap().clone();
            if !found.is_empty() {
                out.push(blockcheckw::pipeline::report::ProtocolSummary {
                    protocol: c.protocol,
                    strategies: found,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod scan_progress_tests {
    use super::ScanProgress;
    use blockcheckw::config::Protocol;

    fn args(s: &str) -> Vec<String> {
        s.split(' ').map(String::from).collect()
    }

    #[test]
    fn snapshot_empty_when_nothing_found() {
        let p = ScanProgress::new("ex.com".into(), None);
        assert!(p.lock().unwrap().snapshot().is_empty());
    }

    #[test]
    fn snapshot_includes_completed_protocol() {
        let p = ScanProgress::new("ex.com".into(), None);
        {
            let mut g = p.lock().unwrap();
            let sink = g.begin_protocol(Protocol::HttpsTls12);
            sink.lock().unwrap().push(args("--dpi-desync=fake"));
            g.finish_protocol();
        }
        let snap = p.lock().unwrap().snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].strategies, vec![args("--dpi-desync=fake")]);
    }

    #[test]
    fn snapshot_includes_in_progress_partial() {
        // THE #41 bug: interrupted mid-protocol must still expose found strategies.
        let p = ScanProgress::new("ex.com".into(), None);
        let sink = p.lock().unwrap().begin_protocol(Protocol::HttpsTls12);
        sink.lock().unwrap().push(args("--dpi-desync=split2"));
        // deliberately NO finish_protocol — simulating an interrupt
        let snap = p.lock().unwrap().snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].strategies, vec![args("--dpi-desync=split2")]);
    }

    #[test]
    fn snapshot_skips_empty_in_progress() {
        let p = ScanProgress::new("ex.com".into(), None);
        let _sink = p.lock().unwrap().begin_protocol(Protocol::HttpsTls12);
        assert!(p.lock().unwrap().snapshot().is_empty());
    }

    /// Приёмка на телефоне: в отчёте должно быть, сколько кандидатов проверено и сколько
    /// было, — и у прогона, оборванного `--timeout` или сигналом, тоже. Счётчик живой:
    /// его наращивает исполнитель, а не итог протокола.
    #[test]
    fn counts_track_the_live_counter_and_every_protocol_corpus() {
        let p = ScanProgress::new("ex.com".into(), None);
        let tried = p.lock().unwrap().tried_counter();
        p.lock().unwrap().add_candidates(8648);
        tried.fetch_add(100, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(p.lock().unwrap().counts(), (100, 8648));
        p.lock().unwrap().add_candidates(10);
        assert_eq!(p.lock().unwrap().counts(), (100, 8658));
    }
}

/// Create shared cleanup state and spawn signal handlers (SIGINT + SIGTERM) that will:
/// drop our iptables chains and kill our engines.
pub fn spawn_cleanup_handler(chain_prefix: &str) -> CleanupState {
    let state = Arc::new(Mutex::new(CleanupInfo {
        chains: OwnedChainsMarker::planned(chain_prefix),
        scan_progress: None,
    }));

    // Panic hook: drop our chains synchronously if we crash.
    let panic_state = state.clone();
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Best-effort synchronous cleanup
        blockcheckw::network::via::Via::cleanup_sync();
        if let Ok(guard) = panic_state.try_lock() {
            emergency_cleanup_sync(&guard);
        }
        prev_hook(info);
    }));

    // SIGTERM handler — same cleanup as Ctrl+C
    let sigterm_state = state.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        sigterm.recv().await;
        graceful_cleanup("SIGTERM", &sigterm_state, 143).await;
    });

    // SIGINT (Ctrl+C) handler
    let sigint_state = state.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            // Spawn force-quit listener + delayed hint
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                eprintln!(
                    "  {} press Ctrl+C again for emergency cleanup",
                    style("→").dim()
                );
            });
            let force_state = sigint_state.clone();
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    blockcheckw::system::process::begin_background_shutdown();
                    blockcheckw::network::via::Via::cleanup_sync();
                    if let Ok(guard) = force_state.try_lock() {
                        eprintln!("\n  emergency cleanup");
                        emergency_cleanup_sync(&guard);
                        std::process::exit(137);
                    }
                    eprintln!("\n  network cleanup already in progress; waiting for safe shutdown");
                }
            });
            graceful_cleanup("Ctrl+C", &sigint_state, 130).await;
        }
    });

    state
}

/// Shared graceful cleanup logic for SIGINT and SIGTERM.
async fn graceful_cleanup(signal_name: &str, state: &CleanupState, exit_code: i32) {
    // Make shutdown atomic with BackgroundProcess::spawn. No plan may start a
    // new nfqws2 instance after this point.
    blockcheckw::system::process::begin_background_shutdown();

    eprintln!(
        "\n{}",
        style(format!("=== {signal_name} — cleaning up ==="))
            .bold()
            .cyan()
    );

    blockcheckw::network::via::Via::cleanup_all().await;
    let info = state.lock().await;

    blockcheckw::firewall::rules::drop_chains(&SystemIpt, &info.chains).await;
    eprintln!(
        "  {} iptables chains '{}_*' dropped",
        style("OK").green().bold(),
        blockcheckw::config::chain_prefix(),
    );
    // With queue rules gone, explicitly kill and reap every child we spawned.
    // process::exit below skips destructors, so kill_on_drop alone is not enough.
    blockcheckw::system::process::kill_all_background_processes().await;
    // Persist partial results only after network state is safe. A second Ctrl+C
    // may skip the report, but must never leave queue rules behind.
    if let Some(progress) = &info.scan_progress {
        let (domain, output, block_type, dns_spoofed, blocked, summary, counts) = {
            let p = progress.lock().unwrap();
            (
                p.domain.clone(),
                p.output.clone(),
                p.block_type,
                p.dns_spoofed,
                p.blocked.clone(),
                p.snapshot(),
                p.counts(),
            )
        };
        if !summary.is_empty() {
            match scan::write_scan_reports(
                &domain,
                output.as_deref(),
                block_type,
                dns_spoofed,
                &blocked,
                &summary,
                counts,
            ) {
                Ok(w) => eprintln!(
                    "  {} partial results saved: {} strategies → {}",
                    style("OK").green().bold(),
                    w.count,
                    style(&w.scan_path).cyan(),
                ),
                Err(e) => eprintln!("  {}failed to save partial results: {e}", WARN),
            }
        }
    }
    std::process::exit(exit_code);
}

/// Register the scan's result accumulator so the signal handler can write a
/// report from whatever was found if the scan is interrupted.
pub async fn set_scan_progress(state: &CleanupState, progress: ScanProgressState) {
    state.lock().await.scan_progress = Some(progress);
}

// ── Instance lock ───────────────────────────────────────────────────────────

/// Создать рабочий каталог (вместе с родителями) с правами только для root. Существующий
/// каталог — чужой (`--work-dir /data/local/tmp`): права на нём не трогаем (review M5).
pub fn ensure_work_dir(work_dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if work_dir.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(work_dir)?;
    std::fs::set_permissions(work_dir, std::fs::Permissions::from_mode(0o700))
}

/// Подсказка «что дальше» после `scan` / `universal`.
pub fn check_hint(path: &str, domain: &str) -> String {
    format!(">>> Next step: bcw check --from-file {path} -d {domain} <<<")
}

/// Каталог отчётов этого прогона: `<work_dir>/runs/<дата-время>/`, один на процесс.
pub fn run_dir() -> std::path::PathBuf {
    static RUN_DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    RUN_DIR
        .get_or_init(|| {
            let dir = blockcheckw::config::paths()
                .work_dir
                .join("runs")
                .join(chrono_local_prefix());
            let _ = std::fs::create_dir_all(&dir);
            dir
        })
        .clone()
}

/// Путь отчёта по умолчанию в каталоге этого прогона.
pub fn default_report_path(name: &str) -> String {
    run_dir().join(name).to_string_lossy().into_owned()
}

/// Куда `check` кладёт прочитанный из пайпа вход: каталог прогона, а не временный каталог.
pub fn stdin_buffer_path() -> std::path::PathBuf {
    run_dir().join("stdin.json")
}

/// Имя замка экземпляра в абстрактном пространстве unix-сокетов.
const INSTANCE_LOCK_NAME: &str = "bcw.instance";

/// Замок экземпляра — абстрактный unix-сокет: он общий на сетевое пространство имён, ровно
/// как наши правила iptables и марки, и не зависит ни от `--work-dir`, ни от файловой
/// системы (review I4). Освобождается ядром вместе с процессом — даже после `SIGKILL`.
pub fn bind_instance_lock(name: &str) -> std::io::Result<std::os::unix::net::UnixListener> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    std::os::unix::net::UnixListener::bind_addr(&addr)
}

/// Opaque lock handle — keeps the abstract socket bound until dropped.
pub struct InstanceLock(#[allow(dead_code)] std::os::unix::net::UnixListener);

/// Взять замок экземпляра; если он занят — ждать (так работает пайп `scan | check`: `check`
/// входит, когда `scan` завершился). Прочие ошибки — выход.
pub fn acquire_instance_lock() -> InstanceLock {
    let mut announced = false;
    loop {
        match bind_instance_lock(INSTANCE_LOCK_NAME) {
            Ok(listener) => return InstanceLock(listener),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                if !announced {
                    eprintln!(
                        "  {} waiting for another bcw instance to finish...",
                        style("WAIT:").yellow().bold(),
                    );
                    announced = true;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => {
                eprintln!(
                    "  {} cannot take the instance lock: {e}",
                    style("ERROR:").red().bold(),
                );
                std::process::exit(1);
            }
        }
    }
}

// ── Prerequisites check ─────────────────────────────────────────────────────

/// Свидетельства, добытые преflight'ом. Носит тот, кто их получил: собрать
/// `Plan` без него невозможно — см. `nfqws2::plan::FilterMark`.
pub struct Prerequisites {
    pub filter_mark: blockcheckw::nfqws2::plan::FilterMark,
}

/// Check that required binaries and kernel features are available.
/// Exits with code 6 (matching vanilla blockcheck2) if something is missing.
pub fn check_prerequisites(con: &blockcheckw::ui::Console) -> Prerequisites {
    use blockcheckw::config::CoreConfig;
    use blockcheckw::nfqws2::run::SystemNfqws2;
    use blockcheckw::nfqws2::Error as Nfqws2Error;

    con.section("Checking prerequisites");

    let config = CoreConfig::default();
    let mut ok = true;

    // nfqws2 binary
    if std::path::Path::new(&config.nfqws2_path).is_file() {
        con.ok(&format!("nfqws2: {}", style(&config.nfqws2_path).dim()));
    } else {
        con.error(&format!(
            "nfqws2 not found at {}",
            style(&config.nfqws2_path).cyan()
        ));
        con.println("       point to the binary with --nfqws2 <PATH>");
        ok = false;
    }

    // iptables: оба бинаря на месте и таблица mangle читается
    for binary in [IPTABLES, IPTABLES_RESTORE] {
        if which(binary) {
            con.ok(binary);
        } else {
            con.error(&format!("{binary} not found in PATH"));
            ok = false;
        }
    }
    if ok {
        match SystemIptSync.cmd(Table::Mangle, &["-S".to_string(), "OUTPUT".to_string()]) {
            Ok(true) => con.ok("iptables -t mangle"),
            _ => {
                con.error("iptables is not usable (`iptables -w -t mangle -S OUTPUT` failed)");
                con.println(
                    "       run as root (su -c) and check that the kernel has iptable_mangle",
                );
                ok = false;
            }
        }
    }

    // 4. Движок понимает --filter-mark (нужна сборка ≥ v1.0.5)
    let witness = if ok {
        match SystemNfqws2::probe_sync(&config.nfqws2_env()) {
            Ok(w) => {
                con.ok("nfqws2 --filter-mark");
                Some(w)
            }
            Err(e) => {
                con.error(&format!("{e}"));
                // Подсказка про версию уместна только для NoFilterMark — на
                // Spawn (нет прав, чужая архитектура) или таймауте она
                // указывала бы не на ту причину.
                if matches!(e, Nfqws2Error::NoFilterMark) {
                    con.println("       update zapret2 to v1.0.5 or newer");
                }
                ok = false;
                None
            }
        }
    } else {
        None
    };

    // 5. Дымовой запуск: lua-версия, архитектура, nfnetlink_queue, CAP_NET_ADMIN
    if let Some(w) = &witness {
        match SystemNfqws2::smoke_sync(&config.nfqws2_env(), w) {
            Ok(()) => con.ok("nfqws2 starts and binds a queue"),
            Err(e) => {
                con.error(&format!("{e}"));
                ok = false;
            }
        }
    }

    if !ok {
        std::process::exit(6);
    }

    // 6. БОЕВАЯ очередь свободна.
    //
    // Дымовой запуск (шаг 5) доказывает исправность бинаря на СВОЕЙ очереди из дальнего
    // диапазона и о боевой не говорит ничего. Занятая боевая очередь означала бы, что
    // правила поедут в очередь с чужим слушателем: пакеты уходят не нам, и подбор молча
    // мерит чужой мир. Своих остатков здесь уже нет — их снял идемпотентный вход. Чужой
    // обход на Android не трогается никогда, поэтому отказ уместен всегда (лечится `--qnum`).
    //
    // Отказ машинный: оркестратору нужен КОД и ИМЯ занятой очереди, а не строка для глаз.
    if queue_is_taken(blockcheckw::nfqws2::plan::QueueNum::new(config.base_qnum)) {
        con.error(&format!(
            "боевая очередь {} занята чужим слушателем",
            config.base_qnum
        ));
        println!(
            "{{\"outcome\":\"broken\",\"reason\":\"queue_busy\",\"queue\":{}}}",
            config.base_qnum
        );
        std::process::exit(blockcheckw::dto::EXIT_QUEUE_BUSY);
    }

    Prerequisites {
        filter_mark: witness.expect("ok означает, что свидетельство есть"),
    }
}

/// Занята ли очередь прямо сейчас. Читаем procfs тем же способом, что и исполнитель
/// (`nfqws2::run`): недоступный procfs означает «не знаем», и тогда не мешаем — остановит
/// нас сам движок, когда не сможет забиндиться.
fn queue_is_taken(queue: blockcheckw::nfqws2::plan::QueueNum) -> bool {
    std::fs::read_to_string(blockcheckw::nfqws2::ready::PROCFS_PATH)
        .map(|procfs| blockcheckw::nfqws2::ready::queue_bound(&procfs, queue))
        .unwrap_or(false)
}

/// Check whether `name` is an executable on `PATH`.
///
/// We walk `$PATH` ourselves instead of shelling out to the `which` command:
/// on minimal targets (busybox / OpenWrt routers) `which` is often absent, and
/// the spawn then fails — which previously got misreported as "not found".
fn which(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| which_in(name, &path))
        .unwrap_or(false)
}

fn which_in(name: &str, path: &std::ffi::OsStr) -> bool {
    if name.is_empty() {
        return false;
    }
    std::env::split_paths(path).any(|dir| is_executable_file(&dir.join(name)))
}

fn is_executable_file(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod which_tests {
    use super::which_in;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn tmp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("bcw_which_{tag}_{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(dir: &Path, name: &str, mode: u32) {
        let p = dir.join(name);
        fs::write(&p, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn finds_executable_in_path() {
        let dir = tmp_dir("found");
        write_file(&dir, "faketool", 0o755);
        let path = OsString::from(&dir);
        assert!(which_in("faketool", &path));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_binary_returns_false() {
        let dir = tmp_dir("missing");
        let path = OsString::from(&dir);
        assert!(!which_in("nope_not_here", &path));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn non_executable_file_returns_false() {
        let dir = tmp_dir("nonexec");
        write_file(&dir, "plain", 0o644);
        let path = OsString::from(&dir);
        assert!(!which_in("plain", &path));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn searches_multiple_path_entries() {
        let a = tmp_dir("multi_a");
        let b = tmp_dir("multi_b");
        write_file(&b, "tool", 0o755);
        let path = std::env::join_paths([&a, &b]).unwrap();
        assert!(which_in("tool", &path));
        fs::remove_dir_all(&a).ok();
        fs::remove_dir_all(&b).ok();
    }
}

/// Generate a local-time prefix for report filenames: "2026-03-20_18-30"
pub fn chrono_local_prefix() -> String {
    use std::process::Command;
    let output = Command::new("date").arg("+%Y-%m-%d_%H-%M").output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!("{secs}")
        }
    }
}

#[cfg(test)]
mod conflict_tests {
    use super::{foreign_queue_chains, pgrep_has_matches};

    #[test]
    fn foreign_queue_chains_are_found_and_ours_are_skipped() {
        let save = "-N nfqws_post\n-N bcw_q\n-A nfqws_post -p tcp -j NFQUEUE --queue-num 300\n\
                    -A bcw_q -j NFQUEUE --queue-num 777\n-A nfqws_pre -j NFQUEUE --queue-num 300\n";
        assert_eq!(
            foreign_queue_chains(save, "bcw"),
            ["nfqws_post", "nfqws_pre"]
        );
    }

    #[test]
    fn a_chain_is_listed_once_and_rules_without_queue_are_ignored() {
        let save = "-A nfqws_post -p tcp --dport 80 -j NFQUEUE --queue-num 300\n\
                    -A nfqws_post -p tcp --dport 443 -j NFQUEUE --queue-num 300\n\
                    -A OUTPUT -j nfqws_post\n-A fw_OUTPUT -j ACCEPT\n";
        assert_eq!(foreign_queue_chains(save, "bcw"), ["nfqws_post"]);
    }

    #[test]
    fn pgrep_success_with_pid_means_process_found() {
        assert!(pgrep_has_matches(0, "1234\n"));
    }

    #[test]
    fn pgrep_empty_or_failed_means_process_not_found() {
        assert!(!pgrep_has_matches(0, "\n"));
        assert!(!pgrep_has_matches(1, ""));
        assert!(!pgrep_has_matches(1, "unexpected output\n"));
    }
}

#[cfg(test)]
mod work_dir_tests {
    use super::{bind_instance_lock, ensure_work_dir, stdin_buffer_path};

    /// Review I4: правила и движки у нас общие на всё ядро (сетевое пространство имён),
    /// значит и замок обязан быть на всё ядро, а не на `--work-dir`.
    #[test]
    fn instance_lock_is_exclusive_regardless_of_work_dir() {
        let name = format!("bcw.test.{}", std::process::id());
        let first = bind_instance_lock(&name).expect("первый экземпляр");
        assert!(
            bind_instance_lock(&name).is_err(),
            "второй экземпляр не должен войти"
        );
        drop(first);
        assert!(
            bind_instance_lock(&name).is_ok(),
            "замок освобождается с владельцем"
        );
    }

    /// Review I3: буфер `scan | check` — в каталоге прогона (рабочий каталог root), а не во
    /// временном каталоге, которого на Android нет.
    #[test]
    fn stdin_buffer_lives_in_run_dir() {
        let path = stdin_buffer_path();
        assert!(
            path.starts_with(blockcheckw::config::paths().work_dir),
            "{path:?}"
        );
        assert_eq!(path.file_name().unwrap(), "stdin.json");
    }

    /// Review M5: существующий каталог пользователя (`--work-dir /data/local/tmp`) не наш —
    /// права на нём не трогаем, иначе `adb push` перестанет туда писать.
    #[test]
    fn existing_work_dir_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("bcw-wd-keep-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o771)).unwrap();
        ensure_work_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(mode, 0o771);
    }

    #[test]
    fn work_dir_is_created_on_demand() {
        use std::os::unix::fs::PermissionsExt;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("bcw-wd-{}-{stamp}", std::process::id()));
        let dir = root.join("a").join("b");
        assert!(!dir.exists());
        ensure_work_dir(&dir).unwrap();
        assert!(dir.is_dir());
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod hint_tests {
    use super::check_hint;

    /// Приёмка на телефоне: подсказка звала `sudo blockcheckw` — на Android нет ни `sudo`,
    /// ни бинаря с таким именем; запускают `su -c` и `bcw`.
    #[test]
    fn check_hint_names_bcw_and_not_sudo() {
        let hint = check_hint("/data/adb/bcw/runs/x/report_vanilla.txt", "rutracker.org");
        assert!(
            hint.contains(
                "bcw check --from-file /data/adb/bcw/runs/x/report_vanilla.txt -d rutracker.org"
            ),
            "{hint}"
        );
        assert!(!hint.contains("sudo"), "{hint}");
        assert!(!hint.contains("blockcheckw"), "{hint}");
    }
}
