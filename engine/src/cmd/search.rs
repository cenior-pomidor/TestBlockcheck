//! `bcw ctl search …` (спека §7.1) и скрытая `bcw search run` — само задание.
//! Обрыв посреди применения доводят `search status` и `search start` (§6.8).

#![allow(async_fn_in_trait)]

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Subcommand;
use serde_json::{json, Value};

use blockcheckw::bypass::layout::Layout;
use blockcheckw::bypass::store::Store;
use blockcheckw::config::CoreConfig;
use blockcheckw::firewall::ipt::SystemIpt;
use blockcheckw::firewall::rules;
use blockcheckw::search::apply::{rollback, SvcLink};
use blockcheckw::search::job::{run_job, JobInput};
use blockcheckw::search::runs::{
    is_id, latest, list, new_id, prune, read_state, read_undo, write_state, Phase, State,
};
use blockcheckw::search::system::{local_now, SystemProbe, SystemSvc, SystemVerifier};
use blockcheckw::search::{Found, NaiveStamp, Outcome};

#[derive(Subcommand, Debug, Clone)]
pub enum SearchAction {
    /// Запустить поиск; основа — после `--` (умолчание — стратегия сети или DEFAULT_STRATEGY).
    Start {
        #[arg(long)]
        enable_net_strategy: bool,
        base: Option<String>,
    },
    /// Ход последнего поиска; доводит прерванный откат.
    Status,
    /// Остановить поиск и дождаться выхода задания (до 30 с).
    Stop,
    /// Последние 10 поисков.
    Runs,
    /// Отчёт поиска целиком.
    Report { id: String },
}

/// Процессы задания: запуск в своей сессии, живость, сигнал группе, часы.
pub trait JobSys {
    fn spawn(&self, args: &[String], log: &Path) -> io::Result<u32>;
    fn alive(&self, pid: u32) -> bool;
    fn term_group(&self, pid: u32) -> io::Result<()>;
    fn now(&self) -> NaiveStamp;
    async fn sleep(&self, d: Duration);
    /// Замок `search start` (и доведения отката): `None` — занят другим `bcw ctl`.
    fn lock(&self) -> Option<Box<dyn std::any::Any>>;
}

/// Имя замка `search start` в абстрактном пространстве unix-сокетов.
const START_LOCK: &str = "bcw.search.start";

const KEEP_RUNS: usize = 10;
const BUSY: &str = "поиск уже идёт";
const NO_NETWORK: &str = "нет сети";
const INTERRUPTED: &str = "поиск прервался";
const INTERRUPTED_APPLY: &str = "поиск прервался посреди применения";
const INTERRUPTED_AFTER_APPLY: &str = "поиск прервался после применения";
const NOT_STARTED: &str = "поиск не запустился";
const NEED_NET_STRATEGY: &str = "включите стратегии по сетям или передайте --enable-net-strategy";
const STOP_WAIT: Duration = Duration::from_secs(30);
const STOP_POLL: Duration = Duration::from_millis(200);
/// Воркеров перебора и срок шагов 2–5 (спека §4).
const WORKERS: usize = 254;
const BUDGET: Duration = Duration::from_secs(300);

type Out = Result<Value, String>;

pub async fn execute<S: SvcLink, J: JobSys>(
    a: &SearchAction,
    store: &Store,
    svc: &S,
    sys: &J,
) -> Out {
    let runs = store.layout.runs_dir();
    match a {
        SearchAction::Start {
            enable_net_strategy,
            base,
        } => {
            // Два одновременных `start` не порождают двух заданий.
            let Some(_lock) = sys.lock() else {
                return Err(BUSY.into());
            };
            start(store, svc, sys, *enable_net_strategy, base.as_deref()).await
        }
        SearchAction::Status => {
            // Замок занят — идёт `start`, он сам доводит откат; здесь не мешаем.
            let recovered = match sys.lock() {
                Some(_lock) => recover(store, svc, sys).await.is_some(),
                None => false,
            };
            let st = latest(&runs).and_then(|d| read_state(&d));
            Ok(json!({ "state": st, "recovered": recovered }))
        }
        SearchAction::Stop => stop(&runs, sys).await,
        SearchAction::Runs => {
            let rows: Vec<Value> = list(&runs)
                .into_iter()
                .map(|s| {
                    json!({
                        "id": s.id,
                        "time": time_of(&s.id),
                        "network_title": s.network_title,
                        "outcome": s.outcome,
                        "error": s.error,
                    })
                })
                .collect();
            Ok(json!({ "runs": rows }))
        }
        SearchAction::Report { id } => {
            let st = is_id(id)
                .then(|| read_state(&runs.join(id)))
                .flatten()
                .ok_or_else(|| format!("нет отчёта поиска «{id}»"))?;
            Ok(json!({ "state": st }))
        }
    }
}

/// Процесс задания жив (pid ещё не записан — не жив).
fn live<J: JobSys>(sys: &J, st: &State) -> bool {
    st.pid != 0 && sys.alive(st.pid)
}

/// Задание идёт: живо и итога ещё нет (в том числе доводит откат).
fn running<J: JobSys>(sys: &J, st: &State) -> bool {
    st.outcome.is_none() && st.error.is_none() && live(sys, st)
}

async fn start<S: SvcLink, J: JobSys>(
    store: &Store,
    svc: &S,
    sys: &J,
    enable_net_strategy: bool,
    base: Option<&str>,
) -> Out {
    let runs = store.layout.runs_dir();
    if let Some(Err(e)) = recover(store, svc, sys).await {
        // Журнал прерванного поиска не доведён — новый поиск затёр бы последний прогон.
        return Err(format!("не удалось откатить прерванный поиск: {e}"));
    }
    if let Some(st) = latest(&runs).and_then(|d| read_state(&d)) {
        if running(sys, &st) {
            return Err(BUSY.into());
        }
    }
    // Найденное назначается сети — без стратегий по сетям оно бы не действовало (спека §6.1).
    if !enable_net_strategy && !store.settings().0.net_strategy {
        return Err(NEED_NET_STRATEGY.into());
    }
    let (key, title) = match svc.status().await {
        Some(st) => match st.network_key {
            Some(k) if k != "offline" => {
                let t = st.network_title.unwrap_or_else(|| k.clone());
                (k, t)
            }
            _ => return Err(NO_NETWORK.into()),
        },
        None => return Err(NO_NETWORK.into()),
    };
    let base = match base.filter(|b| !b.is_empty()) {
        Some(b) => b.to_string(),
        None => default_base(store, &key),
    };
    if store.preset_text(&base).is_err() {
        return Err(format!("нет стратегии {base}"));
    }

    let id = new_id(&sys.now());
    let dir = runs.join(&id);
    std::fs::create_dir_all(&dir).map_err(|e| format!("каталог прогона: {e}"))?;
    let mut st = State {
        schema: 1,
        id: id.clone(),
        pid: 0,
        phase: Phase::Prepare,
        done: 0,
        total: 0,
        elapsed_s: 0,
        domains: Vec::new(),
        outcome: None,
        found: Found::default(),
        network_title: Some(title),
        base: base.clone(),
        error: None,
        check: Vec::new(),
        verify: Vec::new(),
    };
    write_state(&dir, &st).map_err(|e| format!("state.json: {e}"))?;
    prune(&runs, KEEP_RUNS);

    // Значения слитно с ключом: имя основы может начинаться с «-».
    let mut args: Vec<String> = vec![
        "search".into(),
        "run".into(),
        format!("--id={id}"),
        format!("--base={base}"),
    ];
    if enable_net_strategy {
        args.push("--enable-net-strategy".into());
    }
    match sys.spawn(&args, &dir.join("job.log")) {
        Ok(pid) => {
            // Задание само пишет свой pid; не затирать его ход, если оно уже начало.
            if read_state(&dir).is_none_or(|s| s.pid == 0) {
                st.pid = pid;
                let _ = write_state(&dir, &st);
            }
            Ok(json!({ "id": id }))
        }
        Err(e) => {
            let msg = format!("не удалось запустить поиск: {e}");
            st.phase = Phase::Done;
            st.error = Some(msg.clone());
            let _ = write_state(&dir, &st);
            Err(msg)
        }
    }
}

/// Основа по умолчанию: стратегия сети при `NET_STRATEGY=1`, иначе `DEFAULT_STRATEGY`.
fn default_base(store: &Store, key: &str) -> String {
    let (s, _) = store.settings();
    if s.net_strategy {
        if let Some(n) = store.networks().0.into_iter().find(|n| n.key == key) {
            return n.strategy;
        }
    }
    s.default_strategy
}

/// §6.8: последнее задание мертво. Журнал отмены без отметки завершения — полный откат.
/// Итога нет: журнал завершён — итог по диску (пресет назначен сети — «применено», иначе
/// «прервался после применения»); журнала нет — «прервался» (ничего не применялось), а
/// `pid 0` на подготовке — «не запустился». Зовётся только под замком `search start`, так
/// что `pid 0` — не окно запуска, а брошенный `start`. `None` — доводить нечего;
/// `Some(Err)` — откат не удался, журнал так и остался без отметки.
async fn recover<S: SvcLink, J: JobSys>(
    store: &Store,
    svc: &S,
    sys: &J,
) -> Option<Result<(), String>> {
    let dir = latest(&store.layout.runs_dir())?;
    let mut st = read_state(&dir)?;
    if live(sys, &st) {
        return None;
    }
    let rolled = |reason: String| Outcome::RolledBack { reason };
    let (outcome, r) = match read_undo(&dir) {
        Some(u) if !u.finished => match rollback(store, svc, &dir).await {
            Ok(()) => (rolled(INTERRUPTED_APPLY.to_string()), Ok(())),
            Err(e) => (rolled(format!("{INTERRUPTED_APPLY}; откат: {e}")), Err(e)),
        },
        _ if st.outcome.is_some() || st.error.is_some() => return None,
        Some(u) => {
            let on = store.preset_text(&u.preset).is_ok()
                && store
                    .networks()
                    .0
                    .iter()
                    .any(|n| n.key == u.network_key && n.strategy == u.preset);
            let o = if on {
                Outcome::Applied
            } else {
                rolled(INTERRUPTED_AFTER_APPLY.to_string())
            };
            (o, Ok(()))
        }
        None if st.pid == 0 && st.phase == Phase::Prepare => {
            (rolled(NOT_STARTED.to_string()), Ok(()))
        }
        None => (rolled(INTERRUPTED.to_string()), Ok(())),
    };
    st.phase = Phase::Done;
    st.outcome = Some(outcome);
    let _ = write_state(&dir, &st);
    Some(r)
}

async fn stop<J: JobSys>(runs: &Path, sys: &J) -> Out {
    let Some(st) = latest(runs).and_then(|d| read_state(&d)) else {
        return Ok(json!({ "stopped": false }));
    };
    if !running(sys, &st) {
        return Ok(json!({ "stopped": false }));
    }
    sys.term_group(st.pid)
        .map_err(|e| format!("сигнал заданию: {e}"))?;
    let mut waited = Duration::ZERO;
    while waited < STOP_WAIT {
        if !sys.alive(st.pid) {
            return Ok(json!({ "stopped": true }));
        }
        sys.sleep(STOP_POLL).await;
        waited += STOP_POLL;
    }
    if !sys.alive(st.pid) {
        return Ok(json!({ "stopped": true }));
    }
    Err(format!("поиск не остановился за {} с", STOP_WAIT.as_secs()))
}

/// `ГГГГММДД-ЧЧММСС` → время прогона.
fn stamp_of_id(id: &str) -> Option<NaiveStamp> {
    if !is_id(id) {
        return None;
    }
    let n = |r: std::ops::Range<usize>| id[r].parse::<u32>().ok();
    Some(NaiveStamp {
        y: n(0..4)? as i32,
        mo: n(4..6)?,
        d: n(6..8)?,
        h: n(9..11)?,
        mi: n(11..13)?,
        s: n(13..15)?,
    })
}

fn time_of(id: &str) -> Option<String> {
    stamp_of_id(id).map(|t| {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            t.y, t.mo, t.d, t.h, t.mi, t.s
        )
    })
}

/// Настоящие процессы.
pub struct SystemSys;

impl JobSys for SystemSys {
    /// Задание — в своей сессии (`setsid`): WebUI не ждёт его вывода, а `stop` бьёт по
    /// группе. `process_group(0)` не нужен: `setsid` и так даёт группу с pgid = pid, а
    /// лидеру группы `setsid` отказал бы.
    fn spawn(&self, args: &[String], log: &Path) -> io::Result<u32> {
        use std::os::unix::process::CommandExt;
        let out = std::fs::File::create(log)?;
        let err = out.try_clone()?;
        let mut c = std::process::Command::new(std::env::current_exe()?);
        c.args(args)
            .stdin(std::process::Stdio::null())
            .stdout(out)
            .stderr(err);
        // SAFETY: между fork и exec вызывается только async-signal-safe `setsid`.
        unsafe {
            c.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(c.spawn()?.id())
    }

    /// Жив и это наше задание (pid мог достаться другому процессу).
    fn alive(&self, pid: u32) -> bool {
        let Ok(p) = i32::try_from(pid) else {
            return false;
        };
        // SAFETY: сигнал 0 ничего не шлёт, только проверяет pid.
        if p <= 0 || unsafe { libc::kill(p, 0) } != 0 {
            return false;
        }
        ours(std::fs::read(format!("/proc/{pid}/cmdline")))
    }

    fn term_group(&self, pid: u32) -> io::Result<()> {
        let p = i32::try_from(pid).map_err(io::Error::other)?;
        // kill(-1) бьёт по всем процессам, kill(-0) — по своей группе (по нам самим).
        if p <= 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("недопустимый pid задания {pid}"),
            ));
        }
        // SAFETY: обычный kill(2) группе задания.
        if unsafe { libc::kill(-p, libc::SIGTERM) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn now(&self) -> NaiveStamp {
        local_now()
    }

    async fn sleep(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }

    fn lock(&self) -> Option<Box<dyn std::any::Any>> {
        super::bind_instance_lock(START_LOCK)
            .ok()
            .map(|l| Box::new(l) as Box<dyn std::any::Any>)
    }
}

/// Командная строка процесса — наше задание. Нечитаемая — не наше: иначе чужой процесс с
/// тем же pid навсегда держал бы «поиск уже идёт».
fn ours(cmdline: io::Result<Vec<u8>>) -> bool {
    cmdline.is_ok_and(|c| c.windows(10).any(|w| w == b"search\0run"))
}

/// `bcw search run`: одно задание поиска. `SIGTERM`/`SIGINT` поднимают `stop` — задание
/// само останавливается или откатывает применённое; цепочки `bcw_*` снимаются на выходе
/// (и panic-хуком `main`).
pub async fn run_job_cmd(
    id: String,
    base: String,
    enable_net_strategy: bool,
    prereq: &super::Prerequisites,
) {
    use tokio::signal::unix::{signal, SignalKind};
    let store = Store::new(Layout::from_env());
    let dir = store.layout.runs_dir().join(&id);
    let stop = Arc::new(AtomicBool::new(false));
    for kind in [SignalKind::terminate(), SignalKind::interrupt()] {
        let stop = stop.clone();
        match signal(kind) {
            Ok(mut s) => {
                tokio::spawn(async move {
                    while s.recv().await.is_some() {
                        eprintln!("bcw search: сигнал — остановка");
                        stop.store(true, Ordering::SeqCst);
                    }
                });
            }
            Err(e) => eprintln!("bcw search: обработчик сигнала: {e}"),
        }
    }
    let sweep_cfg = CoreConfig {
        worker_count: WORKERS,
        profiles_per_instance: WORKERS,
        ..CoreConfig::default()
    };
    let check_cfg = CoreConfig {
        worker_count: 1,
        profiles_per_instance: 1,
        request_timeout: 3,
        ..CoreConfig::default()
    };
    let chains = match rules::prepare_chains(&SystemIpt, &sweep_cfg.chain_prefix).await {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("iptables: {e}");
            eprintln!("bcw search: {msg}");
            if let Some(mut st) = read_state(&dir) {
                st.phase = Phase::Done;
                st.error = Some(msg);
                let _ = write_state(&dir, &st);
            }
            std::process::exit(1);
        }
    };
    let probe = SystemProbe::new(
        &sweep_cfg,
        &check_cfg,
        &chains,
        &prereq.filter_mark,
        Instant::now() + BUDGET,
        stop.clone(),
    );
    let input = JobInput {
        now: stamp_of_id(&id).unwrap_or_else(local_now),
        id,
        base,
        enable_net_strategy,
        budget: BUDGET,
    };
    let r = run_job(&store, &probe, &SystemSvc, &SystemVerifier, input, stop).await;
    rules::drop_chains(&SystemIpt, &chains.marker()).await;
    blockcheckw::system::process::kill_all_background_processes().await;
    match r {
        Ok(st) => eprintln!("bcw search: итог {:?}", st.outcome),
        Err(e) => {
            eprintln!("bcw search: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockcheckw::bypass::supervisor::Status;
    use blockcheckw::search::runs::{write_undo, CheckRow, DomainState, Undo, VerifyRow};
    use blockcheckw::search::{Group, Proto};
    use std::cell::{Cell, RefCell};
    use std::path::PathBuf;

    const ID: &str = "20261104-194620";
    const KEY: &str = "wifi_Home";

    struct FakeSvc {
        net: Option<&'static str>,
        reloads: Cell<u32>,
    }

    impl FakeSvc {
        fn on() -> FakeSvc {
            FakeSvc {
                net: Some(KEY),
                reloads: Cell::new(0),
            }
        }
    }

    impl SvcLink for FakeSvc {
        async fn status(&self) -> Option<Status> {
            Some(Status {
                state: "running".into(),
                reason: None,
                network_key: Some(self.net.unwrap_or("offline").into()),
                network_title: Some("Wi-Fi «Home»".into()),
                strategy: Some("default".into()),
            })
        }
        async fn reload(&self) -> Result<(), String> {
            self.reloads.set(self.reloads.get() + 1);
            Ok(())
        }
    }

    /// Живы `live`; `dies_at` — с этого момента подделанных часов все мертвы.
    #[derive(Default)]
    struct FakeSys {
        live: Vec<u32>,
        dies_at: Option<Duration>,
        t: Cell<Duration>,
        spawned: RefCell<Vec<(Vec<String>, PathBuf)>>,
        killed: RefCell<Vec<u32>>,
        /// Замок `search start` держит другой `bcw ctl`.
        locked: bool,
    }

    impl JobSys for FakeSys {
        fn spawn(&self, args: &[String], log: &Path) -> io::Result<u32> {
            self.spawned
                .borrow_mut()
                .push((args.to_vec(), log.to_path_buf()));
            Ok(4242)
        }
        fn alive(&self, pid: u32) -> bool {
            self.live.contains(&pid) && self.dies_at.is_none_or(|d| self.t.get() < d)
        }
        fn term_group(&self, pid: u32) -> io::Result<()> {
            self.killed.borrow_mut().push(pid);
            Ok(())
        }
        fn now(&self) -> NaiveStamp {
            NaiveStamp {
                y: 2026,
                mo: 11,
                d: 4,
                h: 19,
                mi: 46,
                s: 20,
            }
        }
        async fn sleep(&self, d: Duration) {
            self.t.set(self.t.get() + d);
        }
        fn lock(&self) -> Option<Box<dyn std::any::Any>> {
            (!self.locked).then(|| Box::new(()) as Box<dyn std::any::Any>)
        }
    }

    fn copy_dir(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for e in std::fs::read_dir(from).unwrap() {
            let e = e.unwrap();
            if e.path().is_dir() {
                copy_dir(&e.path(), &to.join(e.file_name()));
            } else {
                std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
            }
        }
    }

    struct T {
        store: Store,
        root: PathBuf,
    }
    impl Drop for T {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn t(tag: &str) -> T {
        let root = std::env::temp_dir().join(format!("bcw-search-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let module = Path::new(env!("CARGO_MANIFEST_DIR")).join("../module");
        for d in ["strategies", "defaults"] {
            copy_dir(&module.join(d), &root.join("mod").join(d));
        }
        let store = Store::new(Layout {
            module_dir: root.join("mod"),
            data_dir: root.join("data"),
        });
        store.init_data_dir().unwrap();
        T { store, root }
    }

    fn state(id: &str, pid: u32, outcome: Option<Outcome>) -> State {
        State {
            schema: 1,
            id: id.into(),
            pid,
            phase: if outcome.is_some() {
                Phase::Done
            } else {
                Phase::Narrow {
                    group: Group::General,
                }
            },
            done: 120,
            total: 480,
            elapsed_s: 42,
            domains: vec![DomainState {
                group: Group::General,
                domain: "rutracker.org".into(),
                block: Some("sni_blocked".into()),
                left: Some(37),
            }],
            outcome,
            found: Found::default(),
            network_title: Some("Wi-Fi «Home»".into()),
            base: "default".into(),
            error: None,
            check: Vec::new(),
            verify: Vec::new(),
        }
    }

    fn put(s: &Store, st: &State) -> PathBuf {
        let d = s.layout.runs_dir().join(&st.id);
        std::fs::create_dir_all(&d).unwrap();
        write_state(&d, st).unwrap();
        d
    }

    fn undo(preset: &str) -> Undo {
        Undo {
            network_key: KEY.into(),
            prev_strategy: None,
            network_title: "Wi-Fi «Home»".into(),
            prev_net_strategy: false,
            preset: preset.into(),
            added_user_lines: vec![],
            user_list_no_eol: false,
            finished: false,
        }
    }

    fn start(base: Option<&str>) -> SearchAction {
        SearchAction::Start {
            enable_net_strategy: false,
            base: base.map(str::to_string),
        }
    }

    /// `NET_STRATEGY=1`: `start` без `--enable-net-strategy` допустим.
    fn net_on(s: &Store) {
        let (mut st, _) = s.settings();
        st.net_strategy = true;
        s.save_settings(&st).unwrap();
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn start_spawns_detached() {
        let t = t("spawn");
        net_on(&t.store);
        for i in 0..12 {
            put(
                &t.store,
                &state(&format!("20261103-1000{i:02}"), 7, Some(Outcome::NotFound)),
            );
        }
        let sys = FakeSys::default();
        let v = execute(&start(Some("default")), &t.store, &FakeSvc::on(), &sys)
            .await
            .unwrap();
        assert_eq!(v["id"], ID);
        let dir = t.store.layout.runs_dir().join(ID);
        let sp = sys.spawned.borrow().clone();
        assert_eq!(sp.len(), 1);
        assert_eq!(
            sp[0].0,
            args(&["search", "run", "--id=20261104-194620", "--base=default"])
        );
        assert_eq!(sp[0].1, dir.join("job.log"));
        let st = read_state(&dir).unwrap();
        assert_eq!((st.pid, st.phase, st.outcome), (4242, Phase::Prepare, None));
        assert_eq!(st.network_title.as_deref(), Some("Wi-Fi «Home»"));
        let runs = list(&t.store.layout.runs_dir());
        assert_eq!(runs.len(), 10);
        assert_eq!(runs[0].id, ID);

        let sys = FakeSys::default();
        let net = SearchAction::Start {
            enable_net_strategy: true,
            base: Some("alt".into()),
        };
        std::fs::remove_dir_all(&dir).unwrap();
        execute(&net, &t.store, &FakeSvc::on(), &sys).await.unwrap();
        assert_eq!(
            sys.spawned.borrow()[0].0,
            args(&[
                "search",
                "run",
                "--id=20261104-194620",
                "--base=alt",
                "--enable-net-strategy"
            ])
        );
    }

    /// Review Focus 5: второй `start` при живом задании — отказ, журнал прежнего не тронут.
    #[tokio::test]
    async fn start_refuses_running() {
        let t = t("busy");
        let dir = put(&t.store, &state("20261104-100000", 77, None));
        write_undo(&dir, &undo("found-default-20261104-1000")).unwrap();
        let before = std::fs::read(dir.join("undo.json")).unwrap();
        let sys = FakeSys {
            live: vec![77],
            ..Default::default()
        };
        let r = execute(&start(None), &t.store, &FakeSvc::on(), &sys).await;
        assert_eq!(r, Err(BUSY.to_string()));
        assert!(sys.spawned.borrow().is_empty());
        assert_eq!(std::fs::read(dir.join("undo.json")).unwrap(), before);
        assert!(!t.store.layout.runs_dir().join(ID).exists());
    }

    #[tokio::test]
    async fn start_default_base() {
        let t = t("base");
        t.store
            .set_network_entry(KEY, "Wi-Fi «Home»", "alt")
            .unwrap();
        let base_of = |sys: &FakeSys| sys.spawned.borrow()[0].0[3].clone();

        // NET_STRATEGY=0 — DEFAULT_STRATEGY (запуск — с согласием на стратегии по сетям).
        let sys = FakeSys::default();
        let with_net = SearchAction::Start {
            enable_net_strategy: true,
            base: None,
        };
        execute(&with_net, &t.store, &FakeSvc::on(), &sys)
            .await
            .unwrap();
        let (s, _) = t.store.settings();
        assert_eq!(base_of(&sys), format!("--base={}", s.default_strategy));
        std::fs::remove_dir_all(t.store.layout.runs_dir().join(ID)).unwrap();

        // NET_STRATEGY=1 — стратегия сети; пустая основа из WebUI — то же умолчание.
        let (mut s, _) = t.store.settings();
        s.net_strategy = true;
        t.store.save_settings(&s).unwrap();
        let sys = FakeSys::default();
        execute(&start(Some("")), &t.store, &FakeSvc::on(), &sys)
            .await
            .unwrap();
        assert_eq!(base_of(&sys), "--base=alt");

        let sys = FakeSys::default();
        let r = execute(&start(Some("nope")), &t.store, &FakeSvc::on(), &sys).await;
        assert_eq!(r, Err("нет стратегии nope".to_string()));
        let off = FakeSvc {
            net: None,
            reloads: Cell::new(0),
        };
        let r = execute(&start(Some("default")), &t.store, &off, &sys).await;
        assert_eq!(r, Err(NO_NETWORK.to_string()));
        assert!(sys.spawned.borrow().is_empty());
    }

    #[tokio::test]
    async fn status_recovers() {
        let t = t("recover");
        let preset = "found-default-20261104-1000";
        t.store.save_preset(preset, "NFQWS_ARGS=\"\"\n").unwrap();
        t.store
            .set_network_entry(KEY, "Wi-Fi «Home»", preset)
            .unwrap();
        let dir = put(&t.store, &state("20261104-100000", 77, None));
        let mut st = read_state(&dir).unwrap();
        st.phase = Phase::Apply;
        write_state(&dir, &st).unwrap();
        write_undo(&dir, &undo(preset)).unwrap();
        let svc = FakeSvc::on();
        let sys = FakeSys::default();
        let v = execute(&SearchAction::Status, &t.store, &svc, &sys)
            .await
            .unwrap();
        assert_eq!(v["recovered"], true, "{v}");
        let st = read_state(&dir).unwrap();
        assert_eq!(
            st.outcome,
            Some(Outcome::RolledBack {
                reason: INTERRUPTED_APPLY.into()
            })
        );
        assert_eq!(st.phase, Phase::Done);
        assert_eq!(v["state"]["id"], "20261104-100000");
        assert!(read_undo(&dir).unwrap().finished);
        assert!(t.store.preset_text(preset).is_err());
        assert!(t.store.networks().0.iter().all(|n| n.key != KEY));
        assert_eq!(svc.reloads.get(), 1);
        // Повторно — уже нечего доводить.
        let v = execute(&SearchAction::Status, &t.store, &svc, &sys)
            .await
            .unwrap();
        assert_eq!(v["recovered"], false);

        // Задание умерло до применения: итог «прервался», без отката.
        let dir = put(&t.store, &state("20261104-110000", 78, None));
        let v = execute(&SearchAction::Status, &t.store, &svc, &sys)
            .await
            .unwrap();
        assert_eq!(v["recovered"], true);
        assert_eq!(
            read_state(&dir).unwrap().outcome,
            Some(Outcome::RolledBack {
                reason: INTERRUPTED.into()
            })
        );
        assert_eq!(svc.reloads.get(), 1);

        // Живое задание не трогается.
        let dir = put(&t.store, &state("20261104-120000", 79, None));
        let sys = FakeSys {
            live: vec![79],
            ..Default::default()
        };
        let v = execute(&SearchAction::Status, &t.store, &svc, &sys)
            .await
            .unwrap();
        assert_eq!(v["recovered"], false);
        assert_eq!(read_state(&dir).unwrap().outcome, None);
    }

    /// Замок `search start` занят — `status` откат не доводит; `pid 0` на подготовке
    /// (окно запуска под замком) — тоже не трогается.
    #[tokio::test]
    async fn status_skips_recovery_when_locked() {
        let t = t("locked");
        let preset = "found-default-20261104-1000";
        t.store.save_preset(preset, "NFQWS_ARGS=\"\"\n").unwrap();
        let dir = put(&t.store, &state("20261104-100000", 77, None));
        write_undo(&dir, &undo(preset)).unwrap();
        let svc = FakeSvc::on();
        let sys = FakeSys {
            locked: true,
            ..Default::default()
        };
        let v = execute(&SearchAction::Status, &t.store, &svc, &sys)
            .await
            .unwrap();
        assert_eq!(v["recovered"], false);
        assert!(!read_undo(&dir).unwrap().finished);
        assert!(t.store.preset_text(preset).is_ok());
        assert_eq!(read_state(&dir).unwrap().outcome, None);
        assert_eq!(svc.reloads.get(), 0);
        // Тот же замок — у `start`: отказ, задание не запускается.
        let r = execute(&start(Some("default")), &t.store, &svc, &sys).await;
        assert_eq!(r, Err(BUSY.to_string()));
        assert!(sys.spawned.borrow().is_empty());

        let mut st = state("20261104-110000", 0, None);
        st.phase = Phase::Prepare;
        let dir = put(&t.store, &st);
        let v = execute(&SearchAction::Status, &t.store, &svc, &sys)
            .await
            .unwrap();
        assert_eq!(v["recovered"], false);
        assert_eq!(read_state(&dir).unwrap().outcome, None);
    }

    /// M9: `NET_STRATEGY=0` и нет `--enable-net-strategy` — отказ, задание не запускается.
    #[tokio::test]
    async fn start_needs_net_strategy() {
        let t = t("needs-net");
        let sys = FakeSys::default();
        let r = execute(&start(Some("default")), &t.store, &FakeSvc::on(), &sys).await;
        assert_eq!(r, Err(NEED_NET_STRATEGY.to_string()));
        assert_eq!(
            NEED_NET_STRATEGY,
            "включите стратегии по сетям или передайте --enable-net-strategy"
        );
        assert!(sys.spawned.borrow().is_empty());
        assert!(!t.store.layout.runs_dir().join(ID).exists());
    }

    /// I4a: задание умерло после отметки завершения, но до записи итога — итог по диску.
    #[tokio::test]
    async fn status_recovers_after_finish() {
        let t = t("after-finish");
        let preset = "found-default-20261104-1000";
        t.store.save_preset(preset, "NFQWS_ARGS=\"\"\n").unwrap();
        t.store
            .set_network_entry(KEY, "Wi-Fi «Home»", preset)
            .unwrap();
        let mut st = state("20261104-100000", 77, None);
        st.phase = Phase::Verify;
        let dir = put(&t.store, &st);
        let mut u = undo(preset);
        u.finished = true;
        write_undo(&dir, &u).unwrap();
        let svc = FakeSvc::on();
        let sys = FakeSys::default();
        let v = execute(&SearchAction::Status, &t.store, &svc, &sys)
            .await
            .unwrap();
        assert_eq!(v["recovered"], true, "{v}");
        let st = read_state(&dir).unwrap();
        assert_eq!(
            (st.phase, st.outcome),
            (Phase::Done, Some(Outcome::Applied))
        );
        // Применённое не трогается.
        assert!(t.store.preset_text(preset).is_ok());
        assert_eq!(svc.reloads.get(), 0);

        // Откат по стопу завершён, итог не записан: пресета нет — «прервался после применения».
        let mut st = state("20261104-110000", 78, None);
        st.phase = Phase::Rollback;
        let dir = put(&t.store, &st);
        let mut u = undo("found-default-20261104-1100");
        u.finished = true;
        write_undo(&dir, &u).unwrap();
        let v = execute(&SearchAction::Status, &t.store, &svc, &sys)
            .await
            .unwrap();
        assert_eq!(v["recovered"], true);
        assert_eq!(
            read_state(&dir).unwrap().outcome,
            Some(Outcome::RolledBack {
                reason: INTERRUPTED_AFTER_APPLY.into()
            })
        );
        assert_eq!(INTERRUPTED_AFTER_APPLY, "поиск прервался после применения");
        // Итог уже есть — не трогается.
        let v = execute(&SearchAction::Status, &t.store, &svc, &sys)
            .await
            .unwrap();
        assert_eq!(v["recovered"], false);
    }

    /// I4b: `pid 0` на подготовке при свободном замке — `start` не довёл запуск.
    #[tokio::test]
    async fn status_recovers_never_started() {
        let t = t("never-started");
        let mut st = state("20261104-110000", 0, None);
        st.phase = Phase::Prepare;
        let dir = put(&t.store, &st);
        let v = execute(
            &SearchAction::Status,
            &t.store,
            &FakeSvc::on(),
            &FakeSys::default(),
        )
        .await
        .unwrap();
        assert_eq!(v["recovered"], true);
        let st = read_state(&dir).unwrap();
        assert_eq!(st.phase, Phase::Done);
        assert_eq!(
            st.outcome,
            Some(Outcome::RolledBack {
                reason: NOT_STARTED.into()
            })
        );
        assert_eq!(NOT_STARTED, "поиск не запустился");
    }

    /// Откат прерванного поиска не удался — `start` отказывает, журнал остаётся.
    #[tokio::test]
    async fn start_refuses_when_rollback_fails() {
        let t = t("rbfail");
        let dir = put(&t.store, &state("20261104-100000", 77, None));
        let mut u = undo("found-default-20261104-1000");
        u.prev_strategy = Some("alt".into());
        write_undo(&dir, &u).unwrap();
        // networks.tsv не записать: на его месте каталог.
        let nets = t.store.layout.networks_file();
        let _ = std::fs::remove_file(&nets);
        std::fs::create_dir_all(&nets).unwrap();
        let sys = FakeSys::default();
        let r = execute(&start(Some("default")), &t.store, &FakeSvc::on(), &sys).await;
        let e = r.unwrap_err();
        assert!(
            e.starts_with("не удалось откатить прерванный поиск: "),
            "{e}"
        );
        assert!(sys.spawned.borrow().is_empty());
        assert!(!read_undo(&dir).unwrap().finished);
        assert!(!t.store.layout.runs_dir().join(ID).exists());
    }

    #[test]
    fn signals_and_liveness_are_guarded() {
        for pid in [0, 1] {
            assert!(SystemSys.term_group(pid).is_err(), "{pid}");
        }
        assert!(!ours(Err(io::Error::from(io::ErrorKind::PermissionDenied))));
        assert!(!ours(Ok(b"/system/bin/sh\0-c\0".to_vec())));
        assert!(ours(Ok(
            b"/data/adb/modules/bcw/bin/bcw\0search\0run\0--id=x\0".to_vec()
        )));
        assert!(!SystemSys.alive(0));
        assert!(!SystemSys.alive(u32::MAX));
        // Сам тестовый процесс жив, но это не задание поиска.
        assert!(!SystemSys.alive(std::process::id()));
    }

    #[tokio::test]
    async fn stop_signals_group() {
        let t = t("stop");
        put(&t.store, &state("20261104-100000", 77, None));
        let svc = FakeSvc::on();
        let sys = FakeSys {
            live: vec![77],
            dies_at: Some(Duration::from_secs(5)),
            ..Default::default()
        };
        let v = execute(&SearchAction::Stop, &t.store, &svc, &sys)
            .await
            .unwrap();
        assert_eq!(v["stopped"], true);
        assert_eq!(*sys.killed.borrow(), vec![77]);
        assert!(sys.t.get() >= Duration::from_secs(5) && sys.t.get() < Duration::from_secs(6));

        let sys = FakeSys {
            live: vec![77],
            ..Default::default()
        };
        let r = execute(&SearchAction::Stop, &t.store, &svc, &sys).await;
        assert!(r.is_err());
        assert!(sys.t.get() >= STOP_WAIT, "{:?}", sys.t.get());

        // Ничего не идёт — сигнала нет.
        let sys = FakeSys::default();
        let v = execute(&SearchAction::Stop, &t.store, &svc, &sys)
            .await
            .unwrap();
        assert_eq!(v["stopped"], false);
        assert!(sys.killed.borrow().is_empty());
    }

    #[tokio::test]
    async fn runs_and_report() {
        let t = t("runs");
        put(
            &t.store,
            &state("20261104-100000", 7, Some(Outcome::NotFound)),
        );
        put(
            &t.store,
            &state("20261104-110000", 7, Some(Outcome::Applied)),
        );
        let (svc, sys) = (FakeSvc::on(), FakeSys::default());
        let v = execute(&SearchAction::Runs, &t.store, &svc, &sys)
            .await
            .unwrap();
        let runs = v["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0]["id"], "20261104-110000");
        assert_eq!(runs[0]["time"], "2026-11-04 11:00:00");
        assert_eq!(runs[0]["outcome"], "applied");
        let report = |id: &str| SearchAction::Report { id: id.into() };
        let v = execute(&report("20261104-100000"), &t.store, &svc, &sys)
            .await
            .unwrap();
        assert_eq!(v["state"]["outcome"], "not_found");
        for bad in ["../x", "20261104-999999"] {
            assert!(execute(&report(bad), &t.store, &svc, &sys).await.is_err());
        }
    }

    /// Образцы ответов `search` для тестов WebUI (`module/tests/ctl-samples/`).
    /// `UPDATE_SAMPLES=1` переписывает их, без него — сверяет.
    #[tokio::test]
    async fn search_samples_are_current() {
        let t = t("samples");
        net_on(&t.store);
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../module/tests/ctl-samples");
        let update = std::env::var_os("UPDATE_SAMPLES").is_some();
        let mut done = state(
            "20261104-180000",
            7,
            Some(Outcome::Partial {
                failed: Group::Youtube,
            }),
        );
        done.base = "alt".into();
        done.elapsed_s = 187;
        done.done = 12;
        done.total = 12;
        done.domains = vec![
            DomainState {
                group: Group::General,
                domain: "rutracker.org".into(),
                block: Some("sni_blocked".into()),
                left: Some(3),
            },
            DomainState {
                group: Group::General,
                domain: "example.com".into(),
                block: Some("not_blocked".into()),
                left: None,
            },
            DomainState {
                group: Group::Youtube,
                domain: "www.youtube.com".into(),
                block: Some("throttled".into()),
                left: Some(0),
            },
        ];
        done.found = Found {
            youtube: Some("--lua-desync=multisplit:pos=2".into()),
            tls: Some("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls".into()),
            http: Some("--payload=http_req --lua-desync=fake:blob=fake_default_http".into()),
        };
        let row = |group, chain: &str, args: &str, full, median_pct, picked| CheckRow {
            group,
            chain: chain.into(),
            args: args.into(),
            full,
            total: 3,
            median_pct,
            picked,
        };
        done.check = vec![
            row(
                Group::Youtube,
                "tls",
                "--lua-desync=multisplit:pos=2",
                3,
                Some(91),
                true,
            ),
            row(
                Group::Youtube,
                "tls",
                "--lua-desync=multidisorder:pos=1",
                1,
                None,
                false,
            ),
            row(
                Group::General,
                "tls",
                "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls",
                3,
                Some(100),
                true,
            ),
            row(
                Group::General,
                "http",
                "--payload=http_req --lua-desync=fake:blob=fake_default_http",
                2,
                Some(64),
                true,
            ),
        ];
        let vrow = |group, domain: &str, proto, ok, round| VerifyRow {
            group,
            domain: domain.into(),
            proto,
            ok,
            round,
        };
        done.verify = vec![
            vrow(Group::Youtube, "www.youtube.com", Proto::Tls13, false, 1),
            vrow(Group::General, "rutracker.org", Proto::Tls13, true, 1),
            vrow(Group::General, "rutracker.org", Proto::Http, true, 1),
            vrow(Group::General, "rutracker.org", Proto::Tls13, true, 2),
            vrow(Group::General, "rutracker.org", Proto::Http, true, 2),
        ];
        put(&t.store, &done);
        put(
            &t.store,
            &state(
                "20261104-170000",
                7,
                Some(Outcome::RolledBack {
                    reason: "проверка через обход не прошла".into(),
                }),
            ),
        );
        let svc = FakeSvc::on();
        let mut samples: Vec<(&str, Out)> = Vec::new();
        let sys = FakeSys::default();
        samples.push((
            "searchStart",
            execute(&start(Some("default")), &t.store, &svc, &sys).await,
        ));
        // Задание идёт: сужение «Общих».
        let mut cur = state(ID, 4242, None);
        cur.elapsed_s = 63;
        put(&t.store, &cur);
        let sys = FakeSys {
            live: vec![4242],
            ..Default::default()
        };
        samples.push((
            "searchStatus",
            execute(&SearchAction::Status, &t.store, &svc, &sys).await,
        ));
        samples.push((
            "searchRuns",
            execute(&SearchAction::Runs, &t.store, &svc, &sys).await,
        ));
        let report = SearchAction::Report {
            id: "20261104-180000".into(),
        };
        samples.push(("searchReport", execute(&report, &t.store, &svc, &sys).await));
        let mut stale = Vec::new();
        for (name, out) in samples {
            let (line, good) = super::super::ctl::render(out);
            assert!(good, "{name}: {line}");
            let v: Value = serde_json::from_str(&line).unwrap();
            let text = serde_json::to_string_pretty(&v).unwrap() + "\n";
            let path = dir.join(format!("{name}.json"));
            if update {
                std::fs::write(&path, &text).unwrap();
            } else if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
                stale.push(name);
            }
        }
        assert!(
            stale.is_empty(),
            "образцы устарели: {stale:?}; UPDATE_SAMPLES=1 cargo test --bins search_samples"
        );
    }
}
