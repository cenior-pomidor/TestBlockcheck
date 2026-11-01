//! Супервизор службы обхода (§3.2–3.4): состояния, сторож, откат, сеть.
//!
//! Без ввода-вывода и без сна: время приходит аргументом `now`, мир — через трейты
//! `Engine`, `Firewall`, `Probe`. Боевые реализации — `bypass::system`.

#![allow(async_fn_in_trait)]

use std::time::{Duration, Instant};

use super::args::{self, ArgsInput};
use super::logs::{EventKind, Journal, Level};
use super::network::{self, Decision, DecisionInput, Network};
use super::rules::{self, RuleParams};
use super::store::Store;

pub const NET_POLL: Duration = Duration::from_secs(5);
pub const MAX_FAILS: u32 = 5;
pub const FAIL_PAUSE: Duration = Duration::from_secs(60);
pub const ROLLBACK_WINDOW: Duration = Duration::from_secs(10);
pub const STABLE_POLLS: u32 = 2;
/// Раз в сколько тиков (по 5 с) обрезать журналы nfqws2: минута.
pub const LOG_TRIM_TICKS: u64 = 12;

pub trait Engine {
    async fn dry_run(&self, args: &[String]) -> Result<(), String>;
    async fn spawn(&mut self, args: &[String]) -> Result<(), String>;
    fn alive(&mut self) -> bool;
    async fn stop(&mut self);
}

pub trait Firewall {
    async fn apply(&self, p: &RuleParams) -> Result<(), String>;
    async fn remove(&self);
}

pub trait Probe {
    async fn network(&self) -> Network;
    fn neighbour_active(&self) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Running,
    Stopped,
    PausedHome {
        ssid: String,
    },
    BlockedNeighbour,
    /// `retry_at: None` — без повтора (сторож выключен или ошибка стратегии).
    Failed {
        reason: String,
        retry_at: Option<Instant>,
    },
}

impl State {
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Running => "running",
            State::Stopped => "stopped",
            State::PausedHome { .. } => "paused_home",
            State::BlockedNeighbour => "blocked_neighbour",
            State::Failed { .. } => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Command {
    Start,
    Stop,
    Restart,
    Reload,
    HomeResume,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Status {
    pub state: String,
    pub reason: Option<String>,
    pub network_key: Option<String>,
    pub network_title: Option<String>,
    pub strategy: Option<String>,
}

struct Running {
    /// Какую стратегию просили (её сравнивает `decide`): запущенная может быть запасной.
    wanted: String,
    /// Какая запущена на деле.
    strategy: String,
    args: Vec<String>,
    rules: RuleParams,
    started: Instant,
    good: bool,
}

pub struct Supervisor<E, F, P> {
    pub store: Store,
    pub journal: Journal,
    engine: E,
    fw: F,
    probe: P,
    desired_on: bool,
    state: State,
    network: Option<Network>,
    pending: Option<(Network, u32)>,
    running: Option<Running>,
    fails: u32,
    resumed_ssid: Option<String>,
    ticks: u64,
    /// Последние предупреждения о данных по источнику — пишутся в журнал только новые.
    warned_settings: Vec<String>,
    warned_networks: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LastGood {
    strategy: String,
    args: Vec<String>,
}

impl<E: Engine, F: Firewall, P: Probe> Supervisor<E, F, P> {
    /// `boot`: после загрузки желаемое = `AUTOSTART` и записывается; иначе читается из `state/desired`.
    pub fn new(store: Store, journal: Journal, engine: E, fw: F, probe: P, boot: bool) -> Self {
        let (settings, _) = store.settings();
        let path = store.layout.state_dir().join("desired");
        let desired_on = if boot {
            settings.autostart
        } else {
            match std::fs::read_to_string(&path) {
                Ok(t) => t.trim() == "on",
                Err(_) => settings.autostart,
            }
        };
        let sup = Supervisor {
            store,
            journal,
            engine,
            fw,
            probe,
            desired_on,
            state: State::Stopped,
            network: None,
            pending: None,
            running: None,
            fails: 0,
            resumed_ssid: None,
            ticks: 0,
            warned_settings: Vec::new(),
            warned_networks: Vec::new(),
        };
        sup.write_desired();
        sup
    }

    fn write_desired(&self) {
        let dir = self.store.layout.state_dir();
        let _ = std::fs::create_dir_all(&dir);
        let _ = crate::system::atomic::write_atomic(
            &dir.join("desired"),
            if self.desired_on { "on\n" } else { "off\n" },
        );
    }

    fn log(&self, kind: EventKind, level: Level, text: &str) {
        if let Err(e) = self.journal.event(kind, level, text) {
            tracing::warn!(error = %e, "не удалось записать service.log");
        }
    }

    pub fn status(&self) -> Status {
        let reason = match &self.state {
            State::Failed { reason, .. } => Some(reason.clone()),
            State::PausedHome { ssid } => Some(format!("домашний Wi-Fi «{ssid}»")),
            State::BlockedNeighbour => Some("включён nfqws2-android".into()),
            _ => None,
        };
        Status {
            state: self.state.as_str().into(),
            reason,
            network_key: self.network.as_ref().map(Network::key),
            network_title: self.network.as_ref().map(Network::title),
            strategy: self.running.as_ref().map(|r| r.strategy.clone()),
        }
    }

    /// Принять наблюдение сети; смена засчитывается после `STABLE_POLLS` одинаковых опросов.
    /// `true` — принята смена сети.
    fn observe(&mut self, n: Network) -> bool {
        // Первое наблюдение и выход из «нет сети» принимаются сразу: дребезг — это метания
        // между сетями, а появление сети ждать незачем.
        if matches!(self.network, None | Some(Network::Offline)) && n != Network::Offline {
            if self.network.is_some() {
                self.log(EventKind::NetworkChange, Level::Info, &n.title());
            }
            let changed = self.network.is_some();
            self.network = Some(n);
            self.pending = None;
            return changed;
        }
        if self.network.is_none() {
            self.network = Some(n);
            return false;
        }
        if self.network.as_ref() == Some(&n) {
            self.pending = None;
            return false;
        }
        let count = match &self.pending {
            Some((p, c)) if *p == n => c + 1,
            _ => 1,
        };
        if count >= STABLE_POLLS {
            self.log(EventKind::NetworkChange, Level::Info, &n.title());
            if let (Some(r), Network::Wifi { ssid }) = (&self.resumed_ssid, &n) {
                if r != ssid {
                    self.resumed_ssid = None;
                }
            } else if self.resumed_ssid.is_some() {
                self.resumed_ssid = None;
            }
            self.network = Some(n);
            self.pending = None;
            true
        } else {
            self.pending = Some((n, count));
            false
        }
    }

    async fn halt(&mut self) {
        if self.running.take().is_some() {
            self.engine.stop().await;
        }
        self.fw.remove().await;
    }

    pub async fn tick(&mut self, now: Instant) {
        self.ticks += 1;
        if self.ticks.is_multiple_of(LOG_TRIM_TICKS) {
            let (settings, _) = self.store.settings();
            self.journal.max_kb = settings.log_max_kb;
            for f in super::logs::NFQWS2_FILES {
                let p = self.journal.dir.join(f);
                if let Err(e) = super::logs::trim_in_place(&p, settings.log_max_kb) {
                    tracing::warn!(error = %e, file = f, "не удалось обрезать журнал");
                }
            }
        }
        if self.probe.neighbour_active() {
            if self.state != State::BlockedNeighbour {
                self.halt().await;
                self.state = State::BlockedNeighbour;
                self.log(
                    EventKind::Error,
                    Level::Error,
                    "включён nfqws2-android — обход bcw не запускается",
                );
            }
            return;
        }
        if self.state == State::BlockedNeighbour {
            self.state = State::Stopped;
        }
        let n = self.probe.network().await;
        let changed = self.observe(n);
        if !self.desired_on {
            if self.running.is_some() {
                self.halt().await;
            }
            self.state = State::Stopped;
            return;
        }
        if let State::Failed { retry_at, .. } = &self.state {
            // Без повтора — до смены сети (там другая стратегия) или `Reload`.
            match retry_at {
                Some(t) if now >= *t => self.state = State::Stopped,
                None if changed => self.state = State::Stopped,
                _ => return,
            }
        }
        if let Some(r) = &self.running {
            let (started, good) = (r.started, r.good);
            if !self.engine.alive() {
                self.on_death(now).await;
                return;
            }
            if !good && now.duration_since(started) >= ROLLBACK_WINDOW {
                self.mark_good();
            }
        }
        let _ = self.decide_and_act(now).await;
    }

    fn mark_good(&mut self) {
        if let Some(r) = &mut self.running {
            r.good = true;
            let lg = LastGood {
                strategy: r.strategy.clone(),
                args: r.args.clone(),
            };
            let path = self.store.layout.state_dir().join("last_good");
            if let Ok(json) = serde_json::to_string(&lg) {
                let _ = crate::system::atomic::write_atomic(&path, &json);
            }
        }
        self.fails = 0;
    }

    fn last_good(&self) -> Option<LastGood> {
        let t = std::fs::read_to_string(self.store.layout.state_dir().join("last_good")).ok()?;
        serde_json::from_str(&t).ok()
    }

    async fn on_death(&mut self, now: Instant) {
        let Some(r) = self.running.take() else { return };
        let (settings, _) = self.store.settings();
        if !r.good {
            if let Some(lg) = self.last_good().filter(|lg| lg.args != r.args) {
                self.log(
                    EventKind::Rollback,
                    Level::Error,
                    &format!(
                        "«{}» упала в первые 10 с — возврат к «{}»",
                        r.strategy, lg.strategy
                    ),
                );
                let preset = self.store.load_preset(&lg.strategy).unwrap_or_default();
                let params = rules::params(&settings, &preset);
                let _ = self
                    .launch(r.wanted, lg.strategy, lg.args, params, now)
                    .await;
                return;
            }
        }
        if !settings.watchdog {
            self.fw.remove().await;
            let reason = "nfqws2 завершился, сторож выключен".to_string();
            self.log(EventKind::Error, Level::Error, &reason);
            self.state = State::Failed {
                reason,
                retry_at: None,
            };
            return;
        }
        self.fails += 1;
        if self.fails >= MAX_FAILS {
            self.fails = 0;
            self.fw.remove().await;
            let reason = format!("nfqws2 падает: {MAX_FAILS} раз подряд, новая попытка через 60 с");
            self.log(EventKind::Error, Level::Error, &reason);
            self.state = State::Failed {
                reason,
                retry_at: Some(now + FAIL_PAUSE),
            };
            return;
        }
        self.log(
            EventKind::Restart,
            Level::Error,
            &format!("сторож: nfqws2 не работает, перезапуск №{}", self.fails),
        );
        let _ = self
            .launch(r.wanted, r.strategy, r.args, r.rules, now)
            .await;
    }

    /// Записать предупреждения, которых не было в прошлый раз.
    fn warn_new(&self, before: &[String], now: &[String]) {
        for w in now.iter().filter(|w| !before.contains(w)) {
            self.log(EventKind::Error, Level::Error, w);
        }
    }

    fn saved(&mut self) -> Vec<(String, String)> {
        let (nets, warns) = self.store.networks();
        self.warn_new(&self.warned_networks, &warns);
        self.warned_networks = warns;
        nets.into_iter().map(|n| (n.key, n.strategy)).collect()
    }

    async fn decide_and_act(&mut self, now: Instant) -> Result<(), String> {
        let (settings, warns) = self.store.settings();
        self.warn_new(&self.warned_settings, &warns);
        self.warned_settings = warns;
        let home = self.store.home();
        let saved = self.saved();
        let net = self
            .network
            .clone()
            .unwrap_or(Network::Mobile { operator: None });
        let paused = matches!(self.state, State::PausedHome { .. });
        let running = self.running.as_ref().map(|r| r.wanted.clone());
        let d = network::decide(&DecisionInput {
            settings: &settings,
            network: &net,
            running_strategy: running.as_deref(),
            paused,
            home: &home,
            resumed_ssid: self.resumed_ssid.as_deref(),
            saved: &saved,
        });
        match d {
            Decision::Pause { ssid } => {
                self.halt().await;
                self.log(
                    EventKind::Pause,
                    Level::Info,
                    &format!("домашний Wi-Fi «{ssid}»"),
                );
                self.state = State::PausedHome { ssid };
                Ok(())
            }
            Decision::Resume { strategy } => {
                self.log(EventKind::Resume, Level::Info, &net.title());
                self.state = State::Stopped;
                self.start(&strategy, now).await
            }
            Decision::Restart { strategy } => self.start(&strategy, now).await,
            Decision::Nothing => Ok(()),
        }
    }

    /// Кого пробовать: просимую, затем `DEFAULT_STRATEGY`, затем «default».
    fn candidates(&self, wanted: &str) -> Vec<String> {
        let (settings, _) = self.store.settings();
        let mut names = vec![wanted.to_string()];
        for n in [settings.default_strategy.as_str(), "default"] {
            if !names.iter().any(|x| x == n) {
                names.push(n.to_string());
            }
        }
        names
    }

    /// Аргументы и правила одной стратегии.
    fn build_one(&self, name: &str) -> Result<(Vec<String>, RuleParams), String> {
        let (settings, _) = self.store.settings();
        let preset = self.store.load_preset(name)?;
        let calls =
            std::fs::read_to_string(self.store.layout.defaults_dir().join("calls-bypass.conf"))
                .unwrap_or_default();
        let args = args::build(&ArgsInput {
            preset: &preset,
            settings: &settings,
            layout: &self.store.layout,
            ipset_nonempty: self.store.list_count("ipset") > 0,
            calls_conf: &calls,
        })?;
        Ok((args, rules::params(&settings, &preset)))
    }

    /// Первая из кандидатов, что собирается (без проверки nfqws2) — для сравнения в `Reload`.
    fn prepare(&self, wanted: &str) -> Option<(String, Vec<String>, RuleParams)> {
        self.candidates(wanted)
            .into_iter()
            .find_map(|n| self.build_one(&n).ok().map(|(a, p)| (n, a, p)))
    }

    /// Запустить просимую стратегию; не собралась или не прошла `--dry-run` — запасную.
    /// `Err` — просимая не запустилась (даже если работает запасная): текст уходит в `ctl`.
    async fn start(&mut self, wanted: &str, now: Instant) -> Result<(), String> {
        let mut first_err: Option<String> = None;
        for name in self.candidates(wanted) {
            let (args, params) = match self.build_one(&name) {
                Ok(x) => x,
                Err(e) => {
                    self.log(
                        EventKind::Error,
                        Level::Error,
                        &format!("{e}; беру запасную стратегию"),
                    );
                    first_err.get_or_insert(e);
                    continue;
                }
            };
            if let Err(e) = self.engine.dry_run(&args).await {
                let msg = format!("стратегия «{name}» не прошла проверку nfqws2: {e}");
                self.log(EventKind::Error, Level::Error, &msg);
                first_err.get_or_insert(msg);
                continue;
            }
            // Запасная совпала с уже работающей — не дёргать nfqws2.
            let same = self
                .running
                .as_ref()
                .is_some_and(|r| r.args == args && r.rules == params);
            if same {
                if let Some(r) = &mut self.running {
                    r.wanted = wanted.to_string();
                }
                self.state = State::Running;
            } else {
                self.launch(wanted.to_string(), name.clone(), args, params, now)
                    .await?;
            }
            return match first_err {
                Some(e) => Err(format!("{e}; работает «{name}»")),
                None => Ok(()),
            };
        }
        self.fail_start(first_err.unwrap_or_else(|| format!("стратегия «{wanted}» не собралась")))
    }

    fn fail_start(&mut self, msg: String) -> Result<(), String> {
        self.log(EventKind::Error, Level::Error, &msg);
        if self.running.is_none() {
            self.state = State::Failed {
                reason: msg.clone(),
                retry_at: None,
            };
        }
        Err(msg)
    }

    async fn launch(
        &mut self,
        wanted: String,
        strategy: String,
        args: Vec<String>,
        params: RuleParams,
        now: Instant,
    ) -> Result<(), String> {
        if self.running.take().is_some() {
            self.engine.stop().await;
        }
        if let Err(e) = self.fw.apply(&params).await {
            self.fw.remove().await;
            let reason = format!("правила iptables не встали: {e}");
            self.log(EventKind::Error, Level::Error, &reason);
            self.state = State::Failed {
                reason: reason.clone(),
                retry_at: Some(now + FAIL_PAUSE),
            };
            return Err(reason);
        }
        if let Err(e) = self.engine.spawn(&args).await {
            self.fw.remove().await;
            let reason = format!("nfqws2 не запустился: {e}");
            self.log(EventKind::Error, Level::Error, &reason);
            self.state = State::Failed {
                reason: reason.clone(),
                retry_at: Some(now + FAIL_PAUSE),
            };
            return Err(reason);
        }
        let title = self
            .network
            .as_ref()
            .map(Network::title)
            .unwrap_or_default();
        self.log(
            EventKind::Start,
            Level::Info,
            &format!("стратегия «{strategy}», {title}"),
        );
        self.running = Some(Running {
            wanted,
            strategy,
            args,
            rules: params,
            started: now,
            good: false,
        });
        self.state = State::Running;
        Ok(())
    }

    pub async fn command(&mut self, c: Command, now: Instant) -> Result<Status, String> {
        match c {
            Command::Start => {
                self.desired_on = true;
                self.write_desired();
                self.fails = 0;
                if matches!(self.state, State::Failed { .. }) {
                    self.state = State::Stopped;
                }
                if self.network.is_none() {
                    let n = self.probe.network().await;
                    self.observe(n);
                }
                if self.state != State::BlockedNeighbour {
                    self.decide_and_act(now).await?;
                }
            }
            Command::Stop => {
                self.desired_on = false;
                self.write_desired();
                self.halt().await;
                self.state = State::Stopped;
                self.log(EventKind::Stop, Level::Info, "остановлено владельцем");
            }
            Command::Restart => {
                if self.desired_on && self.state != State::BlockedNeighbour {
                    self.halt().await;
                    self.state = State::Stopped;
                    self.log(EventKind::Restart, Level::Info, "по команде");
                    self.decide_and_act(now).await?;
                }
            }
            Command::Reload => {
                if self.desired_on && self.state != State::BlockedNeighbour {
                    if matches!(self.state, State::Failed { .. }) {
                        self.state = State::Stopped;
                    }
                    self.reload(now).await?;
                }
            }
            Command::HomeResume => {
                if let State::PausedHome { ssid } = &self.state {
                    self.resumed_ssid = Some(ssid.clone());
                    self.state = State::Stopped;
                    self.decide_and_act(now).await?;
                }
            }
        }
        Ok(self.status())
    }

    /// Перечитать данные; перезапуск — только если итог изменился.
    async fn reload(&mut self, now: Instant) -> Result<(), String> {
        let Some(r) = &self.running else {
            return self.decide_and_act(now).await;
        };
        let current = (r.wanted.clone(), r.args.clone(), r.rules.clone());
        // Сначала — не пора ли на паузу (домашние сети могли измениться).
        let (settings, _) = self.store.settings();
        let home = self.store.home();
        let saved = self.saved();
        let net = self
            .network
            .clone()
            .unwrap_or(Network::Mobile { operator: None });
        let d = network::decide(&DecisionInput {
            settings: &settings,
            network: &net,
            running_strategy: None,
            paused: false,
            home: &home,
            resumed_ssid: self.resumed_ssid.as_deref(),
            saved: &saved,
        });
        let wanted = match d {
            Decision::Restart { strategy } | Decision::Resume { strategy } => strategy,
            Decision::Pause { .. } | Decision::Nothing => return self.decide_and_act(now).await,
        };
        let next = self
            .prepare(&wanted)
            .map(|(_, a, p)| (wanted.clone(), a, p));
        if next.as_ref() == Some(&current) {
            return Ok(());
        }
        self.start(&wanted, now).await
    }

    /// Остановить обход, не меняя желаемого (SIGTERM службы).
    pub async fn shutdown(&mut self) {
        self.halt().await;
        self.state = State::Stopped;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bypass::layout::Layout;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct World {
        alive: bool,
        spawned: Vec<Vec<String>>,
        stops: usize,
        applies: usize,
        removes: usize,
        dry_run_fail_if_contains: Option<String>,
        network: Option<Network>,
        neighbour: bool,
    }
    type W = Arc<Mutex<World>>;

    struct FEngine(W);
    struct FFw(W);
    struct FProbe(W);

    impl Engine for FEngine {
        async fn dry_run(&self, args: &[String]) -> Result<(), String> {
            let w = self.0.lock().unwrap();
            match &w.dry_run_fail_if_contains {
                Some(n) if args.iter().any(|a| a.contains(n.as_str())) => {
                    Err(format!("bad arg {n}"))
                }
                _ => Ok(()),
            }
        }
        async fn spawn(&mut self, args: &[String]) -> Result<(), String> {
            let mut w = self.0.lock().unwrap();
            w.spawned.push(args.to_vec());
            w.alive = true;
            Ok(())
        }
        fn alive(&mut self) -> bool {
            self.0.lock().unwrap().alive
        }
        async fn stop(&mut self) {
            let mut w = self.0.lock().unwrap();
            w.alive = false;
            w.stops += 1;
        }
    }
    impl Firewall for FFw {
        async fn apply(&self, _p: &RuleParams) -> Result<(), String> {
            self.0.lock().unwrap().applies += 1;
            Ok(())
        }
        async fn remove(&self) {
            self.0.lock().unwrap().removes += 1;
        }
    }
    impl Probe for FProbe {
        async fn network(&self) -> Network {
            self.0
                .lock()
                .unwrap()
                .network
                .clone()
                .unwrap_or(Network::Mobile {
                    operator: Some("MegaFon".into()),
                })
        }
        fn neighbour_active(&self) -> bool {
            self.0.lock().unwrap().neighbour
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

    struct Env {
        sup: Supervisor<FEngine, FFw, FProbe>,
        w: W,
        root: PathBuf,
        t0: Instant,
    }

    impl Drop for Env {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn env(tag: &str, prepare: impl FnOnce(&Store)) -> Env {
        let root = std::env::temp_dir().join(format!("bcw-sup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let module = Path::new(env!("CARGO_MANIFEST_DIR")).join("../module");
        for d in ["strategies", "defaults"] {
            copy_dir(&module.join(d), &root.join("mod").join(d));
        }
        let layout = Layout {
            module_dir: root.join("mod"),
            data_dir: root.join("data"),
        };
        let store = Store::new(layout.clone());
        store.init_data_dir().unwrap();
        prepare(&store);
        let w: W = Arc::default();
        let journal = Journal {
            dir: layout.logs_dir(),
            max_kb: 512,
        };
        let sup = Supervisor::new(
            store,
            journal,
            FEngine(w.clone()),
            FFw(w.clone()),
            FProbe(w.clone()),
            true,
        );
        Env {
            sup,
            w,
            root,
            t0: Instant::now(),
        }
    }

    fn at(e: &Env, secs: u64) -> Instant {
        e.t0 + Duration::from_secs(secs)
    }

    fn log(e: &Env) -> String {
        std::fs::read_to_string(e.sup.journal.dir.join("service.log")).unwrap_or_default()
    }

    fn set(store: &Store, k: &str, v: &str) {
        let (mut s, _) = store.settings();
        s.set(k, v).unwrap();
        store.save_settings(&s).unwrap();
    }

    fn uses_preset(args: &[String], blob: &str) -> bool {
        args.iter().any(|a| a.contains(blob))
    }

    #[tokio::test]
    async fn start_applies_rules_then_spawns() {
        let mut e = env("start", |_| {});
        e.sup.tick(at(&e, 0)).await;
        let w = e.w.lock().unwrap();
        assert_eq!((w.applies, w.spawned.len()), (1, 1));
        assert!(w.spawned[0].contains(&"--qnum=300".to_string()));
        drop(w);
        let st = e.sup.status();
        assert_eq!(st.state, "running");
        assert_eq!(st.strategy.as_deref(), Some("default"));
        assert_eq!(st.network_title.as_deref(), Some("Мобильная (MegaFon)"));
    }

    #[tokio::test]
    async fn autostart_off_stays_stopped_until_start() {
        let mut e = env("autostart", |s| set(s, "AUTOSTART", "0"));
        e.sup.tick(at(&e, 0)).await;
        assert_eq!(e.sup.status().state, "stopped");
        assert_eq!(e.w.lock().unwrap().spawned.len(), 0);
        e.sup.command(Command::Start, at(&e, 5)).await.unwrap();
        assert_eq!(e.sup.status().state, "running");
        let desired =
            std::fs::read_to_string(e.sup.store.layout.state_dir().join("desired")).unwrap();
        assert_eq!(desired.trim(), "on");
    }

    #[tokio::test]
    async fn stop_kills_and_removes_rules() {
        let mut e = env("stop", |_| {});
        e.sup.tick(at(&e, 0)).await;
        e.sup.command(Command::Stop, at(&e, 5)).await.unwrap();
        {
            let w = e.w.lock().unwrap();
            assert!(!w.alive);
            assert!(w.removes >= 1);
        }
        assert_eq!(e.sup.status().state, "stopped");
        e.sup.tick(at(&e, 10)).await;
        assert_eq!(
            e.w.lock().unwrap().spawned.len(),
            1,
            "остановленный не стартует сам"
        );
        assert!(log(&e).contains(" stop "));
    }

    #[tokio::test]
    async fn watchdog_restarts_dead_engine() {
        let mut e = env("watchdog", |_| {});
        e.sup.tick(at(&e, 0)).await;
        e.sup.tick(at(&e, 15)).await; // проработал 10 с — рабочая
        e.w.lock().unwrap().alive = false;
        e.sup.tick(at(&e, 20)).await;
        assert_eq!(e.w.lock().unwrap().spawned.len(), 2);
        assert_eq!(e.sup.status().state, "running");
        assert!(log(&e).contains(" restart "));
    }

    #[tokio::test]
    async fn five_fails_enter_failed_then_retry_after_60s() {
        let mut e = env("fails", |_| {});
        e.sup.tick(at(&e, 0)).await;
        e.sup.tick(at(&e, 15)).await;
        let mut t = 20;
        for _ in 0..5 {
            e.w.lock().unwrap().alive = false;
            e.sup.tick(at(&e, t)).await;
            t += 5;
        }
        assert_eq!(e.sup.status().state, "failed");
        let n = e.w.lock().unwrap().spawned.len();
        e.sup.tick(at(&e, t + 10)).await;
        assert_eq!(e.w.lock().unwrap().spawned.len(), n, "до 60 с не пробуем");
        e.sup.tick(at(&e, t + 65)).await;
        assert_eq!(e.w.lock().unwrap().spawned.len(), n + 1);
        assert_eq!(e.sup.status().state, "running");
    }

    #[tokio::test]
    async fn watchdog_off_goes_failed_at_once() {
        let mut e = env("wdoff", |s| set(s, "WATCHDOG", "0"));
        e.sup.tick(at(&e, 0)).await;
        e.sup.tick(at(&e, 15)).await;
        e.w.lock().unwrap().alive = false;
        e.sup.tick(at(&e, 20)).await;
        assert_eq!(e.sup.status().state, "failed");
        e.sup.tick(at(&e, 200)).await;
        assert_eq!(e.w.lock().unwrap().spawned.len(), 1);
    }

    #[tokio::test]
    async fn crash_within_10s_rolls_back_to_last_good() {
        let mut e = env("rollback", |_| {});
        e.sup.tick(at(&e, 0)).await;
        e.sup.tick(at(&e, 15)).await; // default — рабочая
        set(&e.sup.store, "DEFAULT_STRATEGY", "alt");
        e.sup.command(Command::Reload, at(&e, 20)).await.unwrap();
        assert!(uses_preset(
            e.w.lock().unwrap().spawned.last().unwrap(),
            "quic_initial_www_google_com.bin"
        ));
        e.w.lock().unwrap().alive = false; // упала через 5 с
        e.sup.tick(at(&e, 25)).await;
        let w = e.w.lock().unwrap();
        let first = w.spawned[0].clone();
        assert_eq!(
            w.spawned.last().unwrap(),
            &first,
            "вернулись к последней рабочей"
        );
        drop(w);
        assert!(log(&e).contains(" rollback "), "{}", log(&e));
    }

    #[tokio::test]
    async fn dry_run_error_keeps_previous_and_reports() {
        let mut e = env("dryrun", |_| {});
        e.sup.tick(at(&e, 0)).await;
        e.w.lock().unwrap().dry_run_fail_if_contains = Some("quic_initial_www_google_com".into());
        set(&e.sup.store, "DEFAULT_STRATEGY", "alt");
        let r = e.sup.command(Command::Reload, at(&e, 5)).await;
        assert!(r.is_err(), "ошибка проверки уходит в ответ");
        let w = e.w.lock().unwrap();
        assert_eq!(w.spawned.len(), 1);
        assert!(w.alive, "прежний nfqws2 не тронут");
        drop(w);
        assert_eq!(e.sup.status().strategy.as_deref(), Some("default"));
        assert!(log(&e).contains("bad arg"));
    }

    #[tokio::test]
    async fn home_pause_and_resume() {
        let mut e = env("home", |s| {
            set(s, "HOME_WIFI", "1");
            s.add_home("Home").unwrap();
        });
        e.w.lock().unwrap().network = Some(Network::Wifi {
            ssid: "Home".into(),
        });
        e.sup.tick(at(&e, 0)).await;
        assert_eq!(e.sup.status().state, "paused_home");
        assert_eq!(e.w.lock().unwrap().spawned.len(), 0);
        e.sup.command(Command::HomeResume, at(&e, 5)).await.unwrap();
        assert_eq!(e.sup.status().state, "running");
        // Ушёл и вернулся — снова пауза.
        e.w.lock().unwrap().network = Some(Network::Wifi {
            ssid: "Cafe".into(),
        });
        e.sup.tick(at(&e, 10)).await;
        e.sup.tick(at(&e, 15)).await;
        e.w.lock().unwrap().network = Some(Network::Wifi {
            ssid: "Home".into(),
        });
        e.sup.tick(at(&e, 20)).await;
        e.sup.tick(at(&e, 25)).await;
        assert_eq!(e.sup.status().state, "paused_home");
        assert!(log(&e).contains(" pause "));
    }

    #[tokio::test]
    async fn network_change_needs_two_equal_polls() {
        let mut e = env("flap", |s| {
            set(s, "NET_STRATEGY", "1");
            s.set_network(
                &Network::Wifi {
                    ssid: "Cafe".into(),
                },
                "alt",
            )
            .unwrap();
        });
        e.sup.tick(at(&e, 0)).await; // мобильная, default
        for (t, net) in [
            (
                5,
                Network::Wifi {
                    ssid: "Cafe".into(),
                },
            ),
            (
                10,
                Network::Mobile {
                    operator: Some("MegaFon".into()),
                },
            ),
            (
                15,
                Network::Wifi {
                    ssid: "Cafe".into(),
                },
            ),
        ] {
            e.w.lock().unwrap().network = Some(net);
            e.sup.tick(at(&e, t)).await;
        }
        assert_eq!(
            e.w.lock().unwrap().spawned.len(),
            1,
            "дребезг перезапустил обход"
        );
        e.sup.tick(at(&e, 20)).await; // второй раз подряд Cafe
        assert_eq!(e.w.lock().unwrap().spawned.len(), 2);
        assert_eq!(e.sup.status().strategy.as_deref(), Some("alt"));
    }

    #[tokio::test]
    async fn offline_does_nothing() {
        let mut e = env("offline", |_| {});
        e.sup.tick(at(&e, 0)).await;
        e.w.lock().unwrap().network = Some(Network::Offline);
        for t in [5, 10, 15] {
            e.sup.tick(at(&e, t)).await;
        }
        let w = e.w.lock().unwrap();
        assert_eq!((w.spawned.len(), w.stops), (1, 0));
    }

    #[tokio::test]
    async fn boot_without_network_still_starts_and_leaving_offline_is_immediate() {
        let mut e = env("boot-offline", |s| {
            set(s, "NET_STRATEGY", "1");
            s.set_network(
                &Network::Wifi {
                    ssid: "Cafe".into(),
                },
                "alt",
            )
            .unwrap();
        });
        e.w.lock().unwrap().network = Some(Network::Offline);
        e.sup.tick(at(&e, 0)).await;
        assert_eq!(e.sup.status().state, "running");
        assert_eq!(e.sup.status().strategy.as_deref(), Some("default"));
        e.w.lock().unwrap().network = Some(Network::Wifi {
            ssid: "Cafe".into(),
        });
        e.sup.tick(at(&e, 5)).await;
        assert_eq!(
            e.sup.status().strategy.as_deref(),
            Some("alt"),
            "сеть появилась — сразу её стратегия"
        );
    }

    /// Ревью 2а, Critical 2: запасная стратегия не должна перезапускаться на каждом тике.
    #[tokio::test]
    async fn fallback_is_stable_over_ticks() {
        let mut e = env("fallback-stable", |s| {
            std::fs::write(
                s.layout.data_strategies().join("mine.conf"),
                "NFQWS_ARGS=\"--x\n",
            )
            .unwrap();
            set(s, "DEFAULT_STRATEGY", "mine");
        });
        for t in [0, 5, 10, 15, 20, 25] {
            e.sup.tick(at(&e, t)).await;
        }
        assert_eq!(
            e.w.lock().unwrap().spawned.len(),
            1,
            "запасная перезапускается по кругу"
        );
        assert_eq!(e.sup.status().strategy.as_deref(), Some("default"));
    }

    /// Ревью 2а, Critical 2: после отката — тишина, а не default, alt, default, alt…
    #[tokio::test]
    async fn rollback_is_stable_over_ticks() {
        let mut e = env("rollback-stable", |_| {});
        e.sup.tick(at(&e, 0)).await;
        e.sup.tick(at(&e, 15)).await;
        set(&e.sup.store, "DEFAULT_STRATEGY", "alt");
        e.sup.command(Command::Reload, at(&e, 20)).await.unwrap();
        e.w.lock().unwrap().alive = false;
        e.sup.tick(at(&e, 25)).await; // откат
        let n = e.w.lock().unwrap().spawned.len();
        for t in [30, 35, 40, 45, 50] {
            e.sup.tick(at(&e, t)).await;
        }
        assert_eq!(
            e.w.lock().unwrap().spawned.len(),
            n,
            "после отката перезапуски по кругу"
        );
        assert_eq!(e.sup.status().state, "running");
    }

    /// Ревью 2а, Important 3: стратегия не прошла --dry-run — запас, как при ошибке разбора.
    #[tokio::test]
    async fn dry_run_failure_falls_back_to_default() {
        let mut e = env("dryrun-fallback", |s| set(s, "DEFAULT_STRATEGY", "alt"));
        e.w.lock().unwrap().dry_run_fail_if_contains = Some("quic_initial_www_google_com".into());
        e.sup.tick(at(&e, 0)).await;
        assert_eq!(e.sup.status().state, "running");
        assert_eq!(e.sup.status().strategy.as_deref(), Some("default"));
        e.sup.tick(at(&e, 5)).await;
        assert_eq!(e.w.lock().unwrap().spawned.len(), 1);
    }

    /// Ревью 2а, Important 3: «failed» без повтора снимается сменой сети.
    #[tokio::test]
    async fn failed_recovers_on_network_change() {
        let mut e = env("failed-net", |_| {});
        e.w.lock().unwrap().dry_run_fail_if_contains = Some("--qnum".into());
        e.sup.tick(at(&e, 0)).await;
        assert_eq!(e.sup.status().state, "failed");
        e.w.lock().unwrap().dry_run_fail_if_contains = None;
        e.w.lock().unwrap().network = Some(Network::Wifi {
            ssid: "Cafe".into(),
        });
        for t in [5, 10, 15] {
            e.sup.tick(at(&e, t)).await;
        }
        assert_eq!(e.sup.status().state, "running");
    }

    /// Ревью 2а, Important 4: журналы nfqws2 обрезаются по LOG_MAX_KB раз в минуту.
    #[tokio::test]
    async fn nfqws2_logs_are_trimmed() {
        let mut e = env("trim", |s| set(s, "LOG_MAX_KB", "64"));
        let p = e.sup.store.layout.logs_dir().join("nfqws2.log");
        std::fs::write(&p, "x".repeat(200 * 1024) + "\n").unwrap();
        for t in 0..13 {
            e.sup.tick(at(&e, t * 5)).await;
        }
        assert!(
            std::fs::metadata(&p).unwrap().len() <= 64 * 1024,
            "не обрезан"
        );
    }

    /// Ревью 2а, Important 5: одна битая строка — одна запись в журнале, а не каждые 5 с.
    #[tokio::test]
    async fn data_warnings_are_logged_once() {
        let mut e = env("warn-once", |s| {
            let mut t = std::fs::read_to_string(s.layout.settings_file()).unwrap();
            t.push_str("мусор\n");
            std::fs::write(s.layout.settings_file(), t).unwrap();
            std::fs::write(s.layout.networks_file(), "битая строка\n").unwrap();
        });
        for t in [0, 5, 10, 15] {
            e.sup.tick(at(&e, t)).await;
        }
        let log = log(&e);
        assert_eq!(log.matches("settings.conf").count(), 1, "{log}");
        assert_eq!(log.matches("networks.tsv").count(), 1, "{log}");
    }

    #[tokio::test]
    async fn neighbour_blocks_start() {
        let mut e = env("neighbour", |_| {});
        e.w.lock().unwrap().neighbour = true;
        e.sup.tick(at(&e, 0)).await;
        assert_eq!(e.sup.status().state, "blocked_neighbour");
        assert_eq!(e.w.lock().unwrap().spawned.len(), 0);
        e.w.lock().unwrap().neighbour = false;
        e.sup.tick(at(&e, 5)).await;
        assert_eq!(e.sup.status().state, "running");
    }

    #[tokio::test]
    async fn broken_preset_falls_back_to_default_strategy() {
        let mut e = env("broken", |s| {
            std::fs::write(
                s.layout.data_strategies().join("mine.conf"),
                "NFQWS_ARGS=\"--x\n",
            )
            .unwrap();
            set(s, "DEFAULT_STRATEGY", "mine");
        });
        e.sup.tick(at(&e, 0)).await;
        assert_eq!(e.sup.status().state, "running");
        assert_eq!(e.sup.status().strategy.as_deref(), Some("default"));
        assert!(log(&e).contains("mine"), "{}", log(&e));
    }

    #[tokio::test]
    async fn reload_without_changes_does_not_restart() {
        let mut e = env("reload", |_| {});
        e.sup.tick(at(&e, 0)).await;
        e.sup.command(Command::Reload, at(&e, 5)).await.unwrap();
        assert_eq!(e.w.lock().unwrap().spawned.len(), 1);
        set(&e.sup.store, "BLOCK_QUIC", "1");
        e.sup.command(Command::Reload, at(&e, 10)).await.unwrap();
        assert_eq!(e.w.lock().unwrap().spawned.len(), 2);
    }

    #[tokio::test]
    async fn restart_after_service_crash_keeps_desired() {
        let mut e = env("desired", |_| {});
        e.sup.command(Command::Stop, at(&e, 0)).await.unwrap();
        let store = Store::new(e.sup.store.layout.clone());
        let journal = e.sup.journal.clone();
        let w = e.w.clone();
        let mut again = Supervisor::new(
            store,
            journal,
            FEngine(w.clone()),
            FFw(w.clone()),
            FProbe(w),
            false,
        );
        again.tick(at(&e, 5)).await;
        assert_eq!(again.status().state, "stopped");
    }
}
