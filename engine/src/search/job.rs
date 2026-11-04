//! Одно задание поиска: подготовка, обе группы, сборка, сверка сети и состояния обхода,
//! применение с проверкой и откатом, срок шагов 2–5, стоп, ход в `state.json` (спека §4, §6).

use std::cell::RefCell;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::apply::{apply, rollback, Plan, SvcLink, Verifier};
use super::assemble::{preset_name, preset_text};
use super::narrow::{search_group, Control, Corpus, GroupResult, Probe};
use super::runs::{write_state, DomainState, Phase, State, VerifyRow};
use super::{Found, Group, NaiveStamp, Outcome, Proto};
use crate::bypass::store::Store;

pub struct JobInput {
    pub id: String,
    pub base: String,
    pub enable_net_strategy: bool,
    /// Срок шагов 2–5 (300 с).
    pub budget: Duration,
    pub now: NaiveStamp,
}

pub trait Clock {
    fn now(&self) -> Instant;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Окружение задания, которое подменяют тесты.
pub struct Runtime<'a> {
    pub stop: Arc<AtomicBool>,
    pub clock: &'a dyn Clock,
    pub corpus: &'a Corpus,
}

pub async fn run_job<P: Probe, S: SvcLink, V: Verifier>(
    store: &Store,
    p: &P,
    svc: &S,
    v: &V,
    input: JobInput,
    stop: Arc<AtomicBool>,
) -> Result<State, String> {
    let corpus = Corpus::builtin();
    let rt = Runtime {
        stop,
        clock: &SystemClock,
        corpus: &corpus,
    };
    run_job_with(store, p, svc, v, input, rt).await
}

pub async fn run_job_with<P: Probe, S: SvcLink, V: Verifier>(
    store: &Store,
    p: &P,
    svc: &S,
    v: &V,
    input: JobInput,
    rt: Runtime<'_>,
) -> Result<State, String> {
    let started = rt.clock.now();
    let dir = store.layout.runs_dir().join(&input.id);
    std::fs::create_dir_all(&dir).map_err(|e| format!("каталог прогона: {e}"))?;
    let st = RefCell::new(State {
        schema: 1,
        id: input.id.clone(),
        pid: std::process::id(),
        phase: Phase::Prepare,
        done: 0,
        total: 0,
        elapsed_s: 0,
        domains: Vec::new(),
        outcome: None,
        found: Found::default(),
        network_title: None,
        base: input.base.clone(),
        error: None,
        check: Vec::new(),
        verify: Vec::new(),
    });
    save(&dir, &st.borrow());

    // Шаг 1: подготовка.
    let prep = match prepare(store, svc, &input).await {
        Ok(x) => x,
        Err(e) => {
            let mut s = st.borrow_mut();
            s.phase = Phase::Done;
            s.error = Some(e.clone());
            save(&dir, &s);
            return Err(e);
        }
    };
    st.borrow_mut().network_title = Some(prep.title.clone());

    // Шаги 2–5: обе группы, общий срок. YouTube — первой: это цель приёмки, и срок не
    // должен уйти на «Общие».
    let deadline = rt.clock.now() + input.budget;
    let mut results: Vec<(Group, GroupResult)> = Vec::new();
    for (group, domains) in [
        (Group::Youtube, &prep.youtube),
        (Group::General, &prep.general),
    ] {
        if rt.stop.load(Ordering::SeqCst) {
            break;
        }
        let prev = {
            let mut s = st.borrow_mut();
            s.phase = Phase::Narrow { group };
            s.done = 0;
            s.total = 0;
            s.elapsed_s = elapsed(rt.clock, started);
            save(&dir, &s);
            s.domains.len()
        };
        let ctl = JobCtl {
            stop: &rt.stop,
            clock: rt.clock,
            started,
            deadline,
            dir: &dir,
            st: &st,
            prev,
        };
        let r = search_group(p, group, domains, rt.corpus, &ctl).await;
        {
            let mut s = st.borrow_mut();
            s.domains.truncate(prev);
            s.domains.extend(r.domains.iter().cloned());
            s.check.extend(r.check.iter().cloned());
            save(&dir, &s);
        }
        results.push((group, r));
    }
    let of = |g: Group| results.iter().find(|(x, _)| *x == g).map(|(_, r)| r);
    let (general, youtube) = (of(Group::General), of(Group::Youtube));
    let found = Found {
        youtube: youtube.and_then(|r| r.tls.clone()),
        tls: general.and_then(|r| r.tls.clone()),
        http: general.and_then(|r| r.http.clone()),
    };
    st.borrow_mut().found = found.clone();

    let outcome = 'out: {
        if rt.stop.load(Ordering::SeqCst) {
            break 'out Outcome::Stopped;
        }
        if found == Found::default() {
            break 'out Outcome::NotFound;
        }
        let taken: Vec<String> = store.strategies().into_iter().map(|i| i.name).collect();
        let preset = preset_name(&input.base, input.now, &|n| taken.iter().any(|t| t == n));
        let header = header(&input.now, &prep.title, &input.base);

        // Перед применением: сеть та же, обход запущен.
        let now = svc.status().await;
        // Стоп — до сохранения пресета в любой ветке (и при незапущенном обходе).
        if rt.stop.load(Ordering::SeqCst) {
            break 'out Outcome::Stopped;
        }
        let Some(now) = now else {
            break 'out Outcome::NetworkChanged;
        };
        if now.network_key.as_deref() != Some(prep.key.as_str()) {
            break 'out Outcome::NetworkChanged;
        }
        if now.state != "running" {
            let text = preset_text(&prep.base_text, &found, &header);
            break 'out match store.save_preset(&preset, &text) {
                Ok(()) => Outcome::SavedNotApplied { state: now.state },
                Err(e) => Outcome::RolledBack {
                    reason: format!("пресет не сохранён: {e}; ничего не изменено"),
                },
            };
        }

        let checks = checks(&found, general, youtube);
        let mut general_blocked: Vec<String> = Vec::new();
        for (g, d, _) in &checks {
            if *g == Group::General && !general_blocked.contains(d) {
                general_blocked.push(d.clone());
            }
        }
        let plan = Plan {
            dir: dir.clone(),
            network_key: prep.key.clone(),
            network_title: prep.title.clone(),
            preset,
            found: found.clone(),
            base_text: prep.base_text.clone(),
            header,
            general_blocked,
            checks,
            enable_net_strategy: input.enable_net_strategy,
        };
        {
            let mut s = st.borrow_mut();
            s.phase = Phase::Apply;
            s.elapsed_s = elapsed(rt.clock, started);
            save(&dir, &s);
        }
        let on_verify = |rows: &[VerifyRow]| {
            let mut s = st.borrow_mut();
            s.phase = Phase::Verify;
            s.verify = rows.to_vec();
            s.elapsed_s = elapsed(rt.clock, started);
            save(&dir, &s);
        };
        let out = apply(store, svc, v, &plan, SERVICE_WAIT, &on_verify).await;
        // Стоп во время применения (журнал уже записан) — полный откат.
        let applied = matches!(out, Outcome::Applied | Outcome::Partial { .. });
        if applied && rt.stop.load(Ordering::SeqCst) {
            {
                let mut s = st.borrow_mut();
                s.phase = Phase::Rollback;
                save(&dir, &s);
            }
            break 'out match rollback(store, svc, &dir).await {
                Ok(()) => Outcome::Stopped,
                Err(e) => Outcome::RolledBack {
                    reason: format!("остановлено; откат: {e}"),
                },
            };
        }
        out
    };

    let mut s = st.into_inner();
    s.phase = Phase::Done;
    s.outcome = Some(outcome);
    s.elapsed_s = elapsed(rt.clock, started);
    save(&dir, &s);
    Ok(s)
}

/// Ожидание службы после применения (спека §6, п. 3).
const SERVICE_WAIT: Duration = Duration::from_secs(20);

struct Prepared {
    key: String,
    title: String,
    base_text: String,
    general: Vec<String>,
    youtube: Vec<String>,
}

async fn prepare<S: SvcLink>(store: &Store, svc: &S, input: &JobInput) -> Result<Prepared, String> {
    let st = svc.status().await.ok_or_else(|| NO_NETWORK.to_string())?;
    let key = match st.network_key {
        Some(k) if k != "offline" => k,
        _ => return Err(NO_NETWORK.into()),
    };
    let title = st.network_title.unwrap_or_else(|| key.clone());
    let base_text = store.preset_text(&input.base)?;
    Ok(Prepared {
        key,
        title,
        base_text,
        general: domains(&store.read_list("search-general")?),
        youtube: domains(&store.read_list("search-youtube")?),
    })
}

const NO_NETWORK: &str = "нет сети";

/// Строки списка без пустых и комментариев.
fn domains(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

fn header(at: &NaiveStamp, title: &str, base: &str) -> String {
    format!(
        "Найдено поиском bcw {:04}-{:02}-{:02} {:02}:{:02}, сеть «{title}», основа {base}",
        at.y, at.mo, at.d, at.h, at.mi
    )
}

/// Проверки через обход: заблокированные на базовой проверке пары тех групп и семейств
/// протоколов, для которых найдена стратегия.
fn checks(
    found: &Found,
    general: Option<&GroupResult>,
    youtube: Option<&GroupResult>,
) -> Vec<(Group, String, Proto)> {
    let mut out = Vec::new();
    for (g, r, tls, http) in [
        (
            Group::General,
            general,
            found.tls.is_some(),
            found.http.is_some(),
        ),
        (Group::Youtube, youtube, found.youtube.is_some(), false),
    ] {
        let Some(r) = r else { continue };
        for (d, p) in &r.blocked {
            let ok = match p {
                Proto::Tls13 | Proto::Tls12 => tls,
                Proto::Http => http,
            };
            if ok {
                out.push((g, d.clone(), *p));
            }
        }
    }
    out
}

fn elapsed(clock: &dyn Clock, started: Instant) -> u64 {
    clock.now().saturating_duration_since(started).as_secs()
}

/// Запись хода; ошибка записи не останавливает поиск.
fn save(dir: &Path, s: &State) {
    let _ = write_state(dir, s);
}

/// Стоп, срок и ход в `state.json` для одной группы.
struct JobCtl<'a> {
    stop: &'a AtomicBool,
    clock: &'a dyn Clock,
    started: Instant,
    deadline: Instant,
    dir: &'a Path,
    st: &'a RefCell<State>,
    /// Сколько доменов в `state.domains` от прежних групп.
    prev: usize,
}

impl Control for JobCtl<'_> {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
    fn expired(&self) -> bool {
        self.clock.now() >= self.deadline
    }
    fn report(&self, d: &[DomainState], done: u64, total: u64) {
        let mut s = self.st.borrow_mut();
        s.domains.truncate(self.prev);
        s.domains.extend(d.iter().cloned());
        s.done = done;
        s.total = total;
        s.elapsed_s = elapsed(self.clock, self.started);
        save(self.dir, &s);
    }
    fn phase(&self, p: Phase) {
        let mut s = self.st.borrow_mut();
        s.phase = p;
        s.elapsed_s = elapsed(self.clock, self.started);
        save(self.dir, &s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bypass::layout::Layout;
    use crate::bypass::supervisor::Status;
    use crate::search::narrow::{Block, Confirmed};
    use crate::search::runs::{read_state, read_undo, Phase};
    use crate::search::{Group, Outcome, Proto};
    use crate::strategy::rank::simplicity_key;
    use std::cell::{Cell, RefCell};
    use std::collections::{HashMap, VecDeque};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;

    const KEY: &str = "wifi:home";
    const BASE: &str = "default";
    const ID: &str = "20261104-194620";
    const PRESET: &str = "found-default-20261104-1946";
    const YT: &str = "www.youtube.com";
    const RT: &str = "rutracker.org";
    const EX: &str = "example.com";

    fn now() -> NaiveStamp {
        NaiveStamp {
            y: 2026,
            mo: 11,
            d: 4,
            h: 19,
            mi: 46,
            s: 20,
        }
    }

    fn input() -> JobInput {
        JobInput {
            id: ID.into(),
            base: BASE.into(),
            enable_net_strategy: false,
            budget: Duration::from_secs(300),
            now: now(),
        }
    }

    fn copy_dir(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for e in fs::read_dir(from).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if p.is_dir() {
                copy_dir(&p, &to.join(e.file_name()));
            } else {
                fs::copy(&p, to.join(e.file_name())).unwrap();
            }
        }
    }

    /// Временный модуль и данные со списками поиска.
    fn store(tag: &str) -> (Store, PathBuf) {
        let root = std::env::temp_dir().join(format!("bcw-job-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let module = Path::new(env!("CARGO_MANIFEST_DIR")).join("../module");
        for d in ["strategies", "defaults"] {
            copy_dir(&module.join(d), &root.join("mod").join(d));
        }
        let s = Store::new(Layout {
            module_dir: root.join("mod"),
            data_dir: root.join("data"),
        });
        s.init_data_dir().unwrap();
        s.write_list(
            "search-general",
            &format!("{RT}\n# комментарий\n\n  {EX}  \n"),
        )
        .unwrap();
        s.write_list("search-youtube", &format!("{YT}\n")).unwrap();
        (s, root)
    }

    fn run_dir(s: &Store) -> PathBuf {
        s.layout.runs_dir().join(ID)
    }

    fn strat(prefix: &str, n: usize) -> Vec<String> {
        (0..n)
            .map(|i| format!("--lua-desync={prefix}{i}"))
            .collect()
    }

    fn corpus() -> Corpus {
        Corpus {
            tls13: strat("t13_", 20),
            tls12: strat("t12_", 10),
            http: strat("h_", 5),
        }
    }

    struct FakeClock(Cell<Instant>);

    impl FakeClock {
        fn new() -> Rc<FakeClock> {
            Rc::new(FakeClock(Cell::new(Instant::now())))
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.0.get()
        }
    }

    struct FakeProbe {
        blocks: HashMap<(String, Proto), Block>,
        clock: Rc<FakeClock>,
        sweep_cost: Duration,
        stop_on_sweep: Option<Arc<AtomicBool>>,
        watch: Option<PathBuf>,
        /// Снимок `state.json` в начале каждого `confirm`.
        watch_confirm: Option<PathBuf>,
        seen: RefCell<Vec<State>>,
        sweeps: Cell<usize>,
    }

    impl FakeProbe {
        fn new(clock: &Rc<FakeClock>) -> FakeProbe {
            FakeProbe {
                blocks: HashMap::new(),
                clock: clock.clone(),
                sweep_cost: Duration::from_secs(1),
                stop_on_sweep: None,
                watch: None,
                watch_confirm: None,
                seen: RefCell::new(Vec::new()),
                sweeps: Cell::new(0),
            }
        }
        fn block(mut self, d: &str, p: Proto, b: Block) -> Self {
            self.blocks.insert((d.into(), p), b);
            self
        }
        /// Заблокированы rutracker.org (TLS 1.3, HTTP) и www.youtube.com (TLS 1.3).
        fn both(clock: &Rc<FakeClock>) -> FakeProbe {
            FakeProbe::new(clock)
                .block(RT, Proto::Tls13, Block::Sni)
                .block(RT, Proto::Http, Block::Sni)
                .block(YT, Proto::Tls13, Block::Sni)
        }
        fn snap(&self) {
            if let Some(d) = &self.watch {
                if let Some(s) = read_state(d) {
                    self.seen.borrow_mut().push(s);
                }
            }
        }
    }

    impl Probe for FakeProbe {
        async fn classify(&self, domain: &str, p: Proto) -> Block {
            self.blocks
                .get(&(domain.to_string(), p))
                .cloned()
                .unwrap_or(Block::NotBlocked)
        }
        async fn sweep(
            &self,
            _domain: &str,
            _p: Proto,
            cands: &[String],
            _data: bool,
            progress: &dyn Fn(u64),
        ) -> Vec<String> {
            self.sweeps.set(self.sweeps.get() + 1);
            let c = &self.clock.0;
            c.set(c.get() + self.sweep_cost);
            if let Some(s) = &self.stop_on_sweep {
                s.store(true, Ordering::SeqCst);
            }
            progress(1);
            self.snap();
            progress(cands.len() as u64);
            self.snap();
            // Проходит первая половина (минимум одна).
            cands[..cands.len().div_ceil(2)].to_vec()
        }
        async fn confirm(&self, _d: &[(String, Proto)], cands: &[String]) -> Vec<Confirmed> {
            if let Some(s) = self.watch_confirm.as_ref().and_then(|d| read_state(d)) {
                self.seen.borrow_mut().push(s);
            }
            cands
                .iter()
                .map(|c| Confirmed {
                    args: c.clone(),
                    full: 3,
                    total: 3,
                    median_share: Some(0.5),
                    simplicity: simplicity_key(c),
                })
                .collect()
        }
    }

    /// Служба: ключи сети по очереди (последний повторяется), стратегия — из `networks.tsv`.
    struct FakeSvc {
        keys: Mutex<VecDeque<String>>,
        state: String,
        alive: bool,
        store: Store,
        reloads: Mutex<u32>,
        stop_on_reload: Option<Arc<AtomicBool>>,
        /// Поднять стоп на этом по счёту `status`.
        stop_on_status: Option<(Arc<AtomicBool>, u32)>,
        statuses: Mutex<u32>,
    }

    impl FakeSvc {
        fn new(s: &Store) -> FakeSvc {
            FakeSvc {
                keys: Mutex::new(VecDeque::from([KEY.to_string()])),
                state: "running".into(),
                alive: true,
                store: Store::new(s.layout.clone()),
                reloads: Mutex::new(0),
                stop_on_reload: None,
                stop_on_status: None,
                statuses: Mutex::new(0),
            }
        }
        fn keys(self, k: &[&str]) -> Self {
            *self.keys.lock().unwrap() = k.iter().map(|s| s.to_string()).collect();
            self
        }
        fn reloads(&self) -> u32 {
            *self.reloads.lock().unwrap()
        }
    }

    impl SvcLink for FakeSvc {
        async fn status(&self) -> Option<Status> {
            let n = {
                let mut c = self.statuses.lock().unwrap();
                *c += 1;
                *c
            };
            if let Some((s, at)) = &self.stop_on_status {
                if *at == n {
                    s.store(true, Ordering::SeqCst);
                }
            }
            if !self.alive {
                return None;
            }
            let key = {
                let mut k = self.keys.lock().unwrap();
                if k.len() > 1 {
                    k.pop_front().unwrap()
                } else {
                    k.front().cloned().unwrap()
                }
            };
            let strategy = self
                .store
                .networks()
                .0
                .into_iter()
                .find(|n| n.key == key)
                .map(|n| n.strategy);
            Some(Status {
                state: self.state.clone(),
                reason: None,
                network_key: Some(key),
                network_title: Some("Wi-Fi «Home»".into()),
                strategy,
            })
        }
        async fn reload(&self) -> Result<(), String> {
            *self.reloads.lock().unwrap() += 1;
            if let Some(s) = &self.stop_on_reload {
                s.store(true, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeVerifier {
        calls: Mutex<Vec<(String, Proto)>>,
    }

    impl Verifier for FakeVerifier {
        async fn through_bypass(&self, domain: &str, p: Proto) -> bool {
            self.calls.lock().unwrap().push((domain.to_string(), p));
            true
        }
    }

    async fn run(
        s: &Store,
        p: &FakeProbe,
        svc: &FakeSvc,
        v: &FakeVerifier,
        inp: JobInput,
        stop: Arc<AtomicBool>,
    ) -> Result<State, String> {
        let c = corpus();
        let clock = p.clock.clone();
        let rt = Runtime {
            stop,
            clock: &*clock,
            corpus: &c,
        };
        run_job_with(s, p, svc, v, inp, rt).await
    }

    fn no_stop() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    fn files_in(d: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    fn strategy_of(s: &Store, key: &str) -> Option<String> {
        s.networks()
            .0
            .into_iter()
            .find(|n| n.key == key)
            .map(|n| n.strategy)
    }

    fn nets_text(s: &Store) -> String {
        fs::read_to_string(s.layout.networks_file()).unwrap_or_default()
    }

    #[tokio::test(start_paused = true)]
    async fn no_network() {
        for (tag, alive, key) in [("offline", true, "offline"), ("dead", false, KEY)] {
            let (s, root) = store(&format!("nonet-{tag}"));
            let before = nets_text(&s);
            let clock = FakeClock::new();
            let p = FakeProbe::both(&clock);
            let mut svc = FakeSvc::new(&s).keys(&[key]);
            svc.alive = alive;
            let v = FakeVerifier::default();
            let r = run_job(&s, &p, &svc, &v, input(), no_stop()).await;
            assert_eq!(r, Err("нет сети".to_string()), "{tag}");
            let st = read_state(&run_dir(&s)).expect("state.json");
            assert_eq!(st.phase, Phase::Done);
            assert_eq!(st.outcome, None);
            assert_eq!(st.error.as_deref(), Some("нет сети"));
            assert_eq!(files_in(&run_dir(&s)), ["state.json"]);
            assert_eq!(p.sweeps.get(), 0);
            assert_eq!(svc.reloads(), 0);
            assert_eq!(nets_text(&s), before);
            fs::remove_dir_all(root).ok();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn both_groups_found() {
        let (s, root) = store("both");
        let clock = FakeClock::new();
        let p = FakeProbe::both(&clock);
        let svc = FakeSvc::new(&s);
        let v = FakeVerifier::default();
        let st = run(&s, &p, &svc, &v, input(), no_stop()).await.unwrap();
        assert_eq!(st.outcome, Some(Outcome::Applied));
        assert_eq!(st.phase, Phase::Done);
        assert!(st.found.youtube.is_some());
        assert!(st.found.tls.is_some());
        assert!(st.found.http.is_some());
        assert_eq!(st.network_title.as_deref(), Some("Wi-Fi «Home»"));
        assert_eq!(st.base, BASE);
        assert_eq!(st.error, None);
        assert_eq!(read_state(&run_dir(&s)), Some(st.clone()));
        assert_eq!(strategy_of(&s, KEY).as_deref(), Some(PRESET));
        let pr = s.load_preset(PRESET).unwrap();
        assert_eq!(Some(pr.found_tls), st.found.tls);
        assert_eq!(Some(pr.found_youtube), st.found.youtube);
        let text = s.preset_text(PRESET).unwrap();
        assert!(
            text.contains(
                "# Найдено поиском bcw 2026-11-04 19:46, сеть «Wi-Fi «Home»», основа default"
            ),
            "{text}"
        );
        assert!(read_undo(&run_dir(&s)).unwrap().finished);
        let mut calls = v.calls.lock().unwrap().clone();
        calls.sort_by_key(|(d, p)| (d.clone(), *p as u8));
        assert_eq!(
            calls,
            [
                (RT.to_string(), Proto::Tls13),
                (RT.to_string(), Proto::Http),
                (YT.to_string(), Proto::Tls13),
            ]
        );
        // Домены обеих групп — с типами блокировки; комментарии и пустые строки отброшены.
        let doms: Vec<(Group, &str, Option<&str>)> = st
            .domains
            .iter()
            .map(|d| (d.group, d.domain.as_str(), d.block.as_deref()))
            .collect();
        assert!(doms.contains(&(Group::General, RT, Some("sni_blocked"))));
        assert!(doms.contains(&(Group::General, EX, Some("not_blocked"))));
        assert!(doms.contains(&(Group::Youtube, YT, Some("sni_blocked"))));
        assert_eq!(doms.len(), 3);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_found() {
        let (s, root) = store("nothing");
        let clock = FakeClock::new();
        let p = FakeProbe::new(&clock);
        let svc = FakeSvc::new(&s);
        let v = FakeVerifier::default();
        let st = run(&s, &p, &svc, &v, input(), no_stop()).await.unwrap();
        assert_eq!(st.outcome, Some(Outcome::NotFound));
        assert_eq!(st.phase, Phase::Done);
        assert_eq!(svc.reloads(), 0);
        assert!(s.load_preset(PRESET).is_err());
        assert!(read_undo(&run_dir(&s)).is_none());
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn network_changed() {
        let (s, root) = store("netchg");
        let before = nets_text(&s);
        let clock = FakeClock::new();
        let p = FakeProbe::both(&clock);
        let svc = FakeSvc::new(&s).keys(&[KEY, "wifi:other"]);
        let v = FakeVerifier::default();
        let st = run(&s, &p, &svc, &v, input(), no_stop()).await.unwrap();
        assert_eq!(st.outcome, Some(Outcome::NetworkChanged));
        assert!(st.found.tls.is_some());
        assert!(s.load_preset(PRESET).is_err());
        assert_eq!(svc.reloads(), 0);
        assert_eq!(nets_text(&s), before);
        assert!(read_undo(&run_dir(&s)).is_none());
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn not_running() {
        let (s, root) = store("notrun");
        let before = nets_text(&s);
        let clock = FakeClock::new();
        let p = FakeProbe::both(&clock);
        let mut svc = FakeSvc::new(&s);
        svc.state = "paused_home".into();
        let v = FakeVerifier::default();
        let st = run(&s, &p, &svc, &v, input(), no_stop()).await.unwrap();
        assert_eq!(
            st.outcome,
            Some(Outcome::SavedNotApplied {
                state: "paused_home".into()
            })
        );
        let pr = s.load_preset(PRESET).unwrap();
        assert_eq!(Some(pr.found_tls), st.found.tls);
        assert_eq!(nets_text(&s), before);
        assert_eq!(svc.reloads(), 0);
        assert!(read_undo(&run_dir(&s)).is_none());
        assert!(v.calls.lock().unwrap().is_empty());
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn stop_before_apply() {
        let (s, root) = store("stop-narrow");
        let before = nets_text(&s);
        let stop = no_stop();
        let clock = FakeClock::new();
        let mut p = FakeProbe::both(&clock);
        p.stop_on_sweep = Some(stop.clone());
        let svc = FakeSvc::new(&s);
        let v = FakeVerifier::default();
        let st = run(&s, &p, &svc, &v, input(), stop).await.unwrap();
        assert_eq!(st.outcome, Some(Outcome::Stopped));
        assert_eq!(st.phase, Phase::Done);
        // Стоп на первой ступени первой группы: вторая не начиналась.
        assert_eq!(p.sweeps.get(), 1);
        assert!(s.load_preset(PRESET).is_err());
        assert_eq!(svc.reloads(), 0);
        assert_eq!(nets_text(&s), before);
        assert!(read_undo(&run_dir(&s)).is_none());
        fs::remove_dir_all(root).ok();
    }

    /// Стоп между перебором и применением (во время сверки со службой) — пресет не
    /// сохраняется, даже когда обход не запущен.
    #[tokio::test(start_paused = true)]
    async fn stop_before_save_not_applied() {
        let (s, root) = store("stop-presave");
        let before = nets_text(&s);
        let stop = no_stop();
        let clock = FakeClock::new();
        let p = FakeProbe::both(&clock);
        let mut svc = FakeSvc::new(&s);
        svc.state = "paused_home".into();
        svc.stop_on_status = Some((stop.clone(), 2));
        let v = FakeVerifier::default();
        let st = run(&s, &p, &svc, &v, input(), stop).await.unwrap();
        assert_eq!(st.outcome, Some(Outcome::Stopped));
        assert!(s.load_preset(PRESET).is_err());
        assert_eq!(nets_text(&s), before);
        assert_eq!(svc.reloads(), 0);
        fs::remove_dir_all(root).ok();
    }

    /// В итоге — цифры `check` обеих групп и строки проверки через обход; во время проверки
    /// шаг — «уточнение» и «проверка через обход».
    #[tokio::test(start_paused = true)]
    async fn check_and_verify_in_state() {
        let (s, root) = store("check-verify");
        let clock = FakeClock::new();
        let p = FakeProbe::both(&clock);
        let svc = FakeSvc::new(&s);
        let v = FakeVerifier::default();
        let st = run(&s, &p, &svc, &v, input(), no_stop()).await.unwrap();
        let chains: Vec<(Group, &str)> = st
            .check
            .iter()
            .filter(|r| r.picked)
            .map(|r| (r.group, r.chain.as_str()))
            .collect();
        assert_eq!(
            chains,
            [
                (Group::Youtube, "tls"),
                (Group::General, "tls"),
                (Group::General, "http")
            ]
        );
        let picked: Vec<&str> = st
            .check
            .iter()
            .filter(|r| r.picked)
            .map(|r| r.args.as_str())
            .collect();
        assert_eq!(
            picked,
            [
                st.found.youtube.as_deref().unwrap(),
                st.found.tls.as_deref().unwrap(),
                st.found.http.as_deref().unwrap()
            ]
        );
        assert!(st.check.iter().all(|r| r.median_pct == Some(50)));
        let mut ver: Vec<(&str, Proto, bool, u8)> = st
            .verify
            .iter()
            .map(|r| (r.domain.as_str(), r.proto, r.ok, r.round))
            .collect();
        ver.sort_by_key(|x| (x.0, x.1 as u8));
        assert_eq!(
            ver,
            [
                (RT, Proto::Tls13, true, 1),
                (RT, Proto::Http, true, 1),
                (YT, Proto::Tls13, true, 1)
            ]
        );
        fs::remove_dir_all(root).ok();
    }

    /// Шаги `check` и «проверка через обход» видны в `state.json`.
    #[tokio::test(start_paused = true)]
    async fn check_and_verify_phases() {
        let (s, root) = store("phases");
        let clock = FakeClock::new();
        let mut p = FakeProbe::both(&clock);
        p.watch_confirm = Some(run_dir(&s));
        let svc = FakeSvc::new(&s);
        let v = PhaseVerifier {
            dir: run_dir(&s),
            seen: RefCell::new(Vec::new()),
        };
        let c = corpus();
        let rt = Runtime {
            stop: no_stop(),
            clock: &*clock,
            corpus: &c,
        };
        run_job_with(&s, &p, &svc, &v, input(), rt).await.unwrap();
        let at_confirm: Vec<Phase> = p.seen.borrow().iter().map(|s| s.phase.clone()).collect();
        let (g, y) = (Group::General, Group::Youtube);
        assert_eq!(
            at_confirm,
            [
                Phase::Check { group: y },
                Phase::Check { group: g },
                Phase::Check { group: g }
            ]
        );
        let seen = v.seen.borrow();
        assert_eq!(seen.len(), 3);
        assert!(seen.iter().all(|p| *p == Phase::Verify), "{seen:?}");
        drop(seen);
        fs::remove_dir_all(root).ok();
    }

    /// Проверка через обход, запоминающая шаг из `state.json`.
    struct PhaseVerifier {
        dir: PathBuf,
        seen: RefCell<Vec<Phase>>,
    }

    impl Verifier for PhaseVerifier {
        async fn through_bypass(&self, _domain: &str, _p: Proto) -> bool {
            if let Some(s) = read_state(&self.dir) {
                self.seen.borrow_mut().push(s.phase);
            }
            true
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stop_during_apply() {
        let (s, root) = store("stop-apply");
        s.set_network_entry(KEY, "Home", "alt").unwrap();
        let stop = no_stop();
        let clock = FakeClock::new();
        let p = FakeProbe::both(&clock);
        let mut svc = FakeSvc::new(&s);
        svc.stop_on_reload = Some(stop.clone());
        let v = FakeVerifier::default();
        let st = run(&s, &p, &svc, &v, input(), stop).await.unwrap();
        assert_eq!(st.outcome, Some(Outcome::Stopped));
        assert_eq!(st.phase, Phase::Done);
        assert!(s.load_preset(PRESET).is_err());
        assert_eq!(strategy_of(&s, KEY).as_deref(), Some("alt"));
        let u = read_undo(&run_dir(&s)).unwrap();
        assert!(u.finished);
        assert_eq!(svc.reloads(), 2);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn budget() {
        let (s, root) = store("budget");
        let clock = FakeClock::new();
        // YouTube (идёт первой): три ступени TLS; «Общие» — одна.
        let mut p = FakeProbe::new(&clock)
            .block(YT, Proto::Tls13, Block::Sni)
            .block(YT, Proto::Tls12, Block::Sni)
            .block(RT, Proto::Tls13, Block::Sni);
        p.sweep_cost = Duration::from_secs(200);
        let svc = FakeSvc::new(&s);
        let v = FakeVerifier::default();
        let st = run(&s, &p, &svc, &v, input(), no_stop()).await.unwrap();
        // 200 с < 300 с — вторая ступень идёт; 400 с — срок вышел, берётся подтверждённое;
        // «Общие» уже не начинаются.
        assert_eq!(p.sweeps.get(), 2);
        assert!(st.found.youtube.is_some());
        assert_eq!(st.found.tls, None);
        assert_eq!(st.outcome, Some(Outcome::Applied));
        assert!(st.elapsed_s >= 400, "{}", st.elapsed_s);
        // Проверяются только группы со стратегией.
        let calls = v.calls.lock().unwrap().clone();
        assert!(!calls.is_empty() && calls.iter().all(|(d, _)| d == YT));
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn progress_written() {
        let (s, root) = store("progress");
        let clock = FakeClock::new();
        let mut p = FakeProbe::both(&clock);
        p.watch = Some(run_dir(&s));
        let svc = FakeSvc::new(&s);
        let v = FakeVerifier::default();
        let _ = run(&s, &p, &svc, &v, input(), no_stop()).await.unwrap();
        let seen = p.seen.borrow();
        let gen: Vec<&State> = seen
            .iter()
            .filter(|s| {
                s.phase
                    == Phase::Narrow {
                        group: Group::General,
                    }
            })
            .collect();
        assert!(gen.len() >= 2, "{seen:?}");
        assert_eq!(gen[0].done, 1);
        assert_eq!(gen[1].done, 20);
        assert_eq!(gen[1].total, 20);
        assert!(gen[0]
            .domains
            .iter()
            .any(|d| d.domain == RT && d.block.as_deref() == Some("sni_blocked")));
        // YouTube идёт первой (цель приёмки): при «Общих» её домены уже в состоянии.
        assert!(gen[0].domains.iter().any(|d| d.domain == YT));
        let first_narrow = seen
            .iter()
            .find(|s| matches!(s.phase, Phase::Narrow { .. }))
            .unwrap();
        assert_eq!(
            first_narrow.phase,
            Phase::Narrow {
                group: Group::Youtube
            }
        );
        assert!(seen.iter().all(|s| s.id == ID && s.outcome.is_none()));
        fs::remove_dir_all(root).ok();
    }
}
