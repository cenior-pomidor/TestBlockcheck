//! Базовая проверка, сужение набора стратегий, `check` и выбор лучшей (спека §4, шаги 2-5).
#![allow(async_fn_in_trait)]

use super::runs::{CheckRow, DomainState, Phase};
use super::{Group, Proto};
use crate::bypass::preset::check_found;
use crate::config::Protocol;
use crate::strategy::generator::generate_strategies;
use crate::strategy::rank::simplicity_key;

/// Сколько самых простых прошедших стратегий отдаётся в `check`.
const CHECK_TOP: usize = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    NotBlocked,
    Sni,
    Throttled,
    Skip(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Confirmed {
    pub args: String,
    pub full: usize,
    pub total: usize,
    pub median_share: Option<f64>,
    pub simplicity: (usize, u32, bool),
}

pub trait Probe {
    async fn classify(&self, domain: &str, p: Proto) -> Block;
    async fn sweep(
        &self,
        domain: &str,
        p: Proto,
        cands: &[String],
        data: bool,
        progress: &dyn Fn(u64),
    ) -> Vec<String>;
    async fn confirm(&self, domains: &[(String, Proto)], cands: &[String]) -> Vec<Confirmed>;
}

#[derive(Clone, Debug, Default)]
pub struct Corpus {
    pub tls13: Vec<String>,
    pub tls12: Vec<String>,
    pub http: Vec<String>,
}

impl Corpus {
    /// Набор из `strategy::generator`: строки аргументов через пробел. Строки, которые нельзя
    /// сохранить в `FOUND_*` (например, с `--lua-init`), отбрасываются.
    pub fn builtin() -> Self {
        let load = |p: Protocol| {
            generate_strategies(p)
                .into_iter()
                .map(|s| s.join(" "))
                .filter(|s| check_found(s).is_ok())
                .collect()
        };
        Corpus {
            tls13: load(Protocol::HttpsTls13),
            tls12: load(Protocol::HttpsTls12),
            http: load(Protocol::Http),
        }
    }
}

pub trait Control {
    fn stopped(&self) -> bool;
    fn expired(&self) -> bool;
    fn report(&self, d: &[DomainState], done: u64, total: u64);
    /// Смена шага внутри группы (сужение ↔ `check`).
    fn phase(&self, p: Phase);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupResult {
    pub domains: Vec<DomainState>,
    /// Заблокированные (`Sni`/`Throttled`) пары базовой проверки, по доменам по порядку.
    pub blocked: Vec<(String, Proto)>,
    pub tls: Option<String>,
    pub http: Option<String>,
    /// Цифры `check` по цепочкам (`tls`, затем `http`).
    pub check: Vec<CheckRow>,
}

impl Block {
    fn name(&self) -> &str {
        match self {
            Block::NotBlocked => "not_blocked",
            Block::Sni => "sni_blocked",
            Block::Throttled => "throttled",
            Block::Skip(n) => n,
        }
    }

    fn blocked(&self) -> bool {
        matches!(self, Block::Sni | Block::Throttled)
    }
}

struct Classified {
    tls13: Block,
    tls12: Block,
    http: Option<Block>,
}

/// Одна ступень: заблокированная пара (домен, протокол).
struct Stage {
    idx: usize,
    domain: String,
    proto: Proto,
    data: bool,
}

enum Chain {
    Stopped,
    Done(Option<String>, Vec<Confirmed>),
}

/// Одна цепочка: первая ступень берёт `full`, остальные - прошедших предыдущую.
/// Затем `check` первых 10 по простоте на всех доменах цепочки и `pick`.
async fn run_chain<P: Probe>(
    p: &P,
    group: Group,
    ctl: &dyn Control,
    states: &mut [DomainState],
    stages: &[Stage],
    full: &[String],
) -> Chain {
    let mut cur: Option<Vec<String>> = None;
    ctl.phase(Phase::Narrow { group });
    for st in stages {
        if ctl.stopped() {
            return Chain::Stopped;
        }
        if ctl.expired() {
            break;
        }
        let cands: &[String] = cur.as_deref().unwrap_or(full);
        let total = cands.len() as u64;
        let found = {
            let snapshot: &[DomainState] = states;
            let progress = |done: u64| ctl.report(snapshot, done, total);
            p.sweep(&st.domain, st.proto, cands, st.data, &progress)
                .await
        };
        states[st.idx].left = Some(found.len() as u64);
        let empty = found.is_empty();
        cur = Some(found);
        if empty {
            return Chain::Done(None, Vec::new());
        }
    }
    let Some(mut survivors) = cur else {
        return Chain::Done(None, Vec::new());
    };
    if ctl.stopped() {
        return Chain::Stopped;
    }
    survivors.sort_by_key(|s| simplicity_key(s));
    survivors.truncate(CHECK_TOP);
    let pairs: Vec<(String, Proto)> = stages.iter().map(|s| (s.domain.clone(), s.proto)).collect();
    ctl.phase(Phase::Check { group });
    let confirmed = p.confirm(&pairs, &survivors).await;
    Chain::Done(pick(&confirmed), confirmed)
}

/// Строки `check` одной цепочки; `picked` — у выбранной.
fn check_rows(group: Group, chain: &str, c: &[Confirmed], pick: Option<&str>) -> Vec<CheckRow> {
    c.iter()
        .map(|x| CheckRow {
            group,
            chain: chain.into(),
            args: x.args.clone(),
            full: x.full,
            total: x.total,
            median_pct: x
                .median_share
                .filter(|m| m.is_finite())
                .map(|m| (m * 100.0).round().clamp(0.0, u32::MAX as f64) as u32),
            picked: pick == Some(x.args.as_str()),
        })
        .collect()
}

pub async fn search_group<P: Probe>(
    p: &P,
    group: Group,
    domains: &[String],
    corpus: &Corpus,
    ctl: &dyn Control,
) -> GroupResult {
    let mut cls = Vec::with_capacity(domains.len());
    for d in domains {
        let tls13 = p.classify(d, Proto::Tls13).await;
        let tls12 = p.classify(d, Proto::Tls12).await;
        let http = if group == Group::General {
            Some(p.classify(d, Proto::Http).await)
        } else {
            None
        };
        cls.push(Classified { tls13, tls12, http });
    }
    let mut states: Vec<DomainState> = domains
        .iter()
        .zip(&cls)
        .map(|(d, c)| {
            let b = if c.tls13.blocked() {
                &c.tls13
            } else if !c.tls12.blocked() && c.http.as_ref().is_some_and(Block::blocked) {
                c.http.as_ref().unwrap_or(&c.tls12)
            } else {
                &c.tls12
            };
            DomainState {
                group,
                domain: d.clone(),
                block: Some(b.name().to_string()),
                left: None,
            }
        })
        .collect();

    let stage = |i: usize, proto: Proto, b: &Block| Stage {
        idx: i,
        domain: domains[i].clone(),
        proto,
        data: *b == Block::Throttled,
    };

    // TLS: домен-мажорно, TLS 1.3 раньше TLS 1.2; первая ступень - первый домен с TLS 1.3.
    let mut tls_stages = Vec::new();
    for (i, c) in cls.iter().enumerate() {
        if c.tls13.blocked() {
            tls_stages.push(stage(i, Proto::Tls13, &c.tls13));
        }
        if c.tls12.blocked() {
            tls_stages.push(stage(i, Proto::Tls12, &c.tls12));
        }
    }
    // Первая ступень - всегда TLS 1.3 первого заблокированного домена (с полным набором).
    if let Some(pos) = tls_stages.iter().position(|s| s.proto == Proto::Tls13) {
        let first = tls_stages.remove(pos);
        tls_stages.insert(0, first);
    }
    let tls_full = if cls.iter().any(|c| c.tls13.blocked()) {
        &corpus.tls13
    } else {
        &corpus.tls12
    };
    let mut http_stages = Vec::new();
    for (i, c) in cls.iter().enumerate() {
        if let Some(b) = c.http.as_ref().filter(|b| b.blocked()) {
            http_stages.push(stage(i, Proto::Http, b));
        }
    }

    let mut blocked = Vec::new();
    for (d, c) in domains.iter().zip(&cls) {
        for (p, b) in [
            (Proto::Tls13, Some(&c.tls13)),
            (Proto::Tls12, Some(&c.tls12)),
            (Proto::Http, c.http.as_ref()),
        ] {
            if b.is_some_and(Block::blocked) {
                blocked.push((d.clone(), p));
            }
        }
    }
    let mut out = GroupResult {
        domains: Vec::new(),
        blocked,
        tls: None,
        http: None,
        check: Vec::new(),
    };
    if !tls_stages.is_empty() {
        match run_chain(p, group, ctl, &mut states, &tls_stages, tls_full).await {
            Chain::Stopped => {
                out.domains = states;
                return out;
            }
            Chain::Done(r, c) => {
                out.check.extend(check_rows(group, "tls", &c, r.as_deref()));
                out.tls = r;
            }
        }
    }
    if !http_stages.is_empty() {
        match run_chain(p, group, ctl, &mut states, &http_stages, &corpus.http).await {
            Chain::Stopped => {
                out.tls = None;
                out.domains = states;
                return out;
            }
            Chain::Done(r, c) => {
                out.check
                    .extend(check_rows(group, "http", &c, r.as_deref()));
                out.http = r;
            }
        }
    }
    out.domains = states;
    out
}

/// Лучшая по `check`: `full/total` по убыванию, затем `median_share` (`None` ниже любого),
/// затем простота. `full == 0` отбрасывается.
pub fn pick(c: &[Confirmed]) -> Option<String> {
    let rate = |x: &Confirmed| {
        if x.total == 0 {
            0.0
        } else {
            x.full as f64 / x.total as f64
        }
    };
    let share = |x: &Confirmed| x.median_share.unwrap_or(f64::NEG_INFINITY);
    c.iter()
        .filter(|x| x.full > 0)
        .min_by(|a, b| {
            rate(b)
                .total_cmp(&rate(a))
                .then_with(|| share(b).total_cmp(&share(a)))
                .then_with(|| a.simplicity.cmp(&b.simplicity))
        })
        .map(|x| x.args.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::rank::simplicity_key;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    #[derive(Debug, Clone, PartialEq)]
    struct SweepCall {
        domain: String,
        proto: Proto,
        cands: Vec<String>,
        data: bool,
    }

    type ConfirmCall = (Vec<(String, Proto)>, Vec<String>);

    #[derive(Default)]
    struct FakeProbe {
        blocks: HashMap<(String, Proto), Block>,
        /// (домен, протокол) -> проходящие стратегии; нет записи — не проходит ни одна.
        pass: HashMap<(String, Proto), Vec<String>>,
        sweeps: RefCell<Vec<SweepCall>>,
        classified: RefCell<Vec<(String, Proto)>>,
        confirms: RefCell<Vec<ConfirmCall>>,
    }

    impl FakeProbe {
        fn block(mut self, d: &str, p: Proto, b: Block) -> Self {
            self.blocks.insert((d.into(), p), b);
            self
        }
        fn pass(mut self, d: &str, p: Proto, s: &[String]) -> Self {
            self.pass.insert((d.into(), p), s.to_vec());
            self
        }
    }

    impl Probe for FakeProbe {
        async fn classify(&self, domain: &str, p: Proto) -> Block {
            self.classified.borrow_mut().push((domain.into(), p));
            self.blocks
                .get(&(domain.to_string(), p))
                .cloned()
                .unwrap_or(Block::NotBlocked)
        }
        async fn sweep(
            &self,
            domain: &str,
            p: Proto,
            cands: &[String],
            data: bool,
            progress: &dyn Fn(u64),
        ) -> Vec<String> {
            self.sweeps.borrow_mut().push(SweepCall {
                domain: domain.into(),
                proto: p,
                cands: cands.to_vec(),
                data,
            });
            progress(cands.len() as u64);
            let ok = self.pass.get(&(domain.to_string(), p));
            cands
                .iter()
                .filter(|c| ok.is_some_and(|v| v.contains(c)))
                .cloned()
                .collect()
        }
        async fn confirm(&self, domains: &[(String, Proto)], cands: &[String]) -> Vec<Confirmed> {
            self.confirms
                .borrow_mut()
                .push((domains.to_vec(), cands.to_vec()));
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

    #[derive(Default)]
    struct FakeCtl {
        stopped_after: Cell<Option<usize>>,
        expired_after: Cell<Option<usize>>,
        stopped_calls: Cell<usize>,
        expired_calls: Cell<usize>,
        reports: RefCell<Vec<(u64, u64)>>,
        phases: RefCell<Vec<Phase>>,
    }

    impl Control for FakeCtl {
        fn stopped(&self) -> bool {
            let n = self.stopped_calls.get();
            self.stopped_calls.set(n + 1);
            self.stopped_after.get().is_some_and(|k| n >= k)
        }
        fn expired(&self) -> bool {
            let n = self.expired_calls.get();
            self.expired_calls.set(n + 1);
            self.expired_after.get().is_some_and(|k| n >= k)
        }
        fn report(&self, _d: &[DomainState], done: u64, total: u64) {
            self.reports.borrow_mut().push((done, total));
        }
        fn phase(&self, p: Phase) {
            self.phases.borrow_mut().push(p);
        }
    }

    fn strat(prefix: &str, n: usize) -> Vec<String> {
        (0..n)
            .map(|i| format!("--lua-desync={prefix}{i}"))
            .collect()
    }

    fn corpus() -> Corpus {
        Corpus {
            tls13: strat("t13_", 40),
            tls12: strat("t12_", 20),
            http: strat("h_", 10),
        }
    }

    fn doms(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn skip_unblocked_and_ip() {
        let c = corpus();
        let p = FakeProbe::default()
            .block("ok", Proto::Tls13, Block::NotBlocked)
            .block("ip", Proto::Tls13, Block::Skip("ip_blocked".into()))
            .block("ip", Proto::Tls12, Block::Skip("ip_blocked".into()));
        let r = search_group(
            &p,
            Group::General,
            &doms(&["ok", "ip"]),
            &c,
            &FakeCtl::default(),
        )
        .await;
        assert!(p.sweeps.borrow().is_empty());
        assert_eq!(r.domains[0].block.as_deref(), Some("not_blocked"));
        assert_eq!(r.domains[1].block.as_deref(), Some("ip_blocked"));
        assert_eq!(r.domains[0].left, None);
        assert_eq!(r.domains[1].left, None);
        assert_eq!((r.tls, r.http), (None, None));
    }

    #[tokio::test]
    async fn empty_group() {
        let p = FakeProbe::default();
        let r = search_group(&p, Group::General, &[], &corpus(), &FakeCtl::default()).await;
        assert_eq!((r.tls, r.http), (None, None));
        assert!(r.domains.is_empty());
        assert!(p.sweeps.borrow().is_empty());
        assert!(p.confirms.borrow().is_empty());
    }

    #[tokio::test]
    async fn narrow_order() {
        let c = corpus();
        let s13a = c.tls13[..10].to_vec();
        let s12a = c.tls12[..5].to_vec();
        // на a/tls12 проходят 5 tls12-стратегий, но на b/tls13 — часть tls13 из s13a.
        let p = FakeProbe::default()
            .block("a", Proto::Tls13, Block::Sni)
            .block("a", Proto::Tls12, Block::Sni)
            .block("b", Proto::Tls13, Block::Sni)
            .pass("a", Proto::Tls13, &s13a)
            .pass("a", Proto::Tls12, &s13a[..6])
            .pass("b", Proto::Tls13, &s13a[..3]);
        let _ = s12a;
        let ctl = FakeCtl::default();
        let r = search_group(&p, Group::General, &doms(&["a", "b"]), &c, &ctl).await;
        let sw = p.sweeps.borrow();
        assert_eq!(sw.len(), 3);
        assert_eq!((sw[0].domain.as_str(), sw[0].proto), ("a", Proto::Tls13));
        assert_eq!(sw[0].cands, c.tls13);
        assert_eq!((sw[1].domain.as_str(), sw[1].proto), ("a", Proto::Tls12));
        assert_eq!(sw[1].cands, s13a);
        assert_eq!((sw[2].domain.as_str(), sw[2].proto), ("b", Proto::Tls13));
        assert_eq!(sw[2].cands, s13a[..6].to_vec());
        assert_eq!(r.domains[0].block.as_deref(), Some("sni_blocked"));
        assert_eq!(r.domains[0].left, Some(6));
        assert_eq!(r.domains[1].left, Some(3));
        assert!(r.tls.is_some());
        assert_eq!(
            r.blocked,
            vec![
                ("a".to_string(), Proto::Tls13),
                ("a".to_string(), Proto::Tls12),
                ("b".to_string(), Proto::Tls13)
            ]
        );
        // прогресс: done/total внутри ступени
        assert_eq!(ctl.reports.borrow()[0], (40, 40));
    }

    #[tokio::test]
    async fn first_stage_is_first_tls13_domain() {
        let c = corpus();
        let p = FakeProbe::default()
            .block("x", Proto::Tls12, Block::Sni)
            .block("a", Proto::Tls13, Block::Sni)
            .pass("a", Proto::Tls13, &c.tls13[..5])
            .pass("x", Proto::Tls12, &c.tls13[..2]);
        let _ = search_group(
            &p,
            Group::General,
            &doms(&["x", "a"]),
            &c,
            &FakeCtl::default(),
        )
        .await;
        let sw = p.sweeps.borrow();
        assert_eq!((sw[0].domain.as_str(), sw[0].proto), ("a", Proto::Tls13));
        assert_eq!(sw[0].cands, c.tls13);
        assert_eq!((sw[1].domain.as_str(), sw[1].proto), ("x", Proto::Tls12));
        assert_eq!(sw[1].cands.len(), 5);
    }

    #[tokio::test]
    async fn tls12_only() {
        let c = corpus();
        let p = FakeProbe::default()
            .block("a", Proto::Tls12, Block::Sni)
            .pass("a", Proto::Tls12, &c.tls12[..2]);
        let r = search_group(&p, Group::General, &doms(&["a"]), &c, &FakeCtl::default()).await;
        let sw = p.sweeps.borrow();
        assert_eq!(sw.len(), 1);
        assert_eq!(sw[0].proto, Proto::Tls12);
        assert_eq!(sw[0].cands, c.tls12);
        assert_eq!(r.domains[0].block.as_deref(), Some("sni_blocked"));
        assert!(r.tls.is_some());
    }

    #[tokio::test]
    async fn throttled_uses_data() {
        let c = corpus();
        let p = FakeProbe::default()
            .block("t", Proto::Tls13, Block::Throttled)
            .block("s", Proto::Tls13, Block::Sni)
            .pass("t", Proto::Tls13, &c.tls13)
            .pass("s", Proto::Tls13, &c.tls13);
        let r = search_group(
            &p,
            Group::General,
            &doms(&["t", "s"]),
            &c,
            &FakeCtl::default(),
        )
        .await;
        let sw = p.sweeps.borrow();
        assert!(sw[0].data);
        assert!(!sw[1].data);
        assert_eq!(r.domains[0].block.as_deref(), Some("throttled"));
    }

    #[tokio::test]
    async fn empty_stage_stops() {
        let c = corpus();
        let p = FakeProbe::default()
            .block("a", Proto::Tls13, Block::Sni)
            .block("a", Proto::Tls12, Block::Sni)
            .block("b", Proto::Tls13, Block::Sni)
            .pass("a", Proto::Tls13, &c.tls13[..4]);
        let r = search_group(
            &p,
            Group::General,
            &doms(&["a", "b"]),
            &c,
            &FakeCtl::default(),
        )
        .await;
        assert_eq!(p.sweeps.borrow().len(), 2);
        assert_eq!(r.tls, None);
        assert!(p.confirms.borrow().is_empty());
        assert_eq!(r.domains[0].left, Some(0));
        assert_eq!(r.domains[1].left, None);
    }

    #[tokio::test]
    async fn check_top10() {
        let c = corpus();
        // 30 прошедших: 15 с двумя действиями (сложнее) и 15 с одним.
        let mut pass = Vec::new();
        for i in 0..15 {
            pass.push(format!("--lua-desync=x{i} --lua-desync=y{i}"));
        }
        for i in 0..15 {
            pass.push(format!("--lua-desync=z{i}"));
        }
        let mut c2 = c.clone();
        c2.tls13 = pass.clone();
        let p = FakeProbe::default()
            .block("a", Proto::Tls13, Block::Sni)
            .block("b", Proto::Tls12, Block::Sni)
            .pass("a", Proto::Tls13, &pass)
            .pass("b", Proto::Tls12, &pass);
        let _ = search_group(
            &p,
            Group::General,
            &doms(&["a", "b"]),
            &c2,
            &FakeCtl::default(),
        )
        .await;
        let cf = p.confirms.borrow();
        assert_eq!(cf.len(), 1);
        let (d, cands) = &cf[0];
        assert_eq!(
            d,
            &vec![
                ("a".to_string(), Proto::Tls13),
                ("b".to_string(), Proto::Tls12)
            ]
        );
        assert_eq!(cands.len(), 10);
        assert!(cands
            .iter()
            .all(|s| s.matches("--lua-desync=").count() == 1));
    }

    #[tokio::test]
    async fn http_chain() {
        let c = corpus();
        let p = FakeProbe::default()
            .block("b", Proto::Http, Block::Sni)
            .block("c", Proto::Http, Block::Sni)
            .pass("b", Proto::Http, &c.http[..5])
            .pass("c", Proto::Http, &c.http[..2]);
        let r = search_group(
            &p,
            Group::General,
            &doms(&["a", "b", "c"]),
            &c,
            &FakeCtl::default(),
        )
        .await;
        assert_eq!(p.sweeps.borrow().len(), 2);
        let sw = p.sweeps.borrow().clone();
        assert_eq!(sw[0].cands, c.http);
        assert_eq!(sw[1].cands, c.http[..5].to_vec());
        assert_eq!(r.tls, None);
        assert!(r.http.is_some());
        assert_eq!(
            r.blocked,
            vec![
                ("b".to_string(), Proto::Http),
                ("c".to_string(), Proto::Http)
            ]
        );
        let cf = p.confirms.borrow();
        assert_eq!(
            cf[0].0,
            vec![
                ("b".to_string(), Proto::Http),
                ("c".to_string(), Proto::Http)
            ]
        );
    }

    #[tokio::test]
    async fn youtube_skips_http() {
        let c = corpus();
        let p2 = FakeProbe::default();
        let _ = search_group(&p2, Group::Youtube, &doms(&["a"]), &c, &FakeCtl::default()).await;
        assert!(p2
            .classified
            .borrow()
            .iter()
            .all(|(_, pr)| *pr != Proto::Http));
        assert_eq!(p2.classified.borrow().len(), 2);
    }

    fn cf(args: &str, full: usize, total: usize, m: Option<f64>) -> Confirmed {
        Confirmed {
            args: args.into(),
            full,
            total,
            median_share: m,
            simplicity: simplicity_key(args),
        }
    }

    #[test]
    fn pick_rules() {
        assert_eq!(pick(&[]), None);
        assert_eq!(pick(&[cf("a", 0, 3, Some(1.0))]), None);
        let r = pick(&[cf("lo", 3, 3, Some(0.8)), cf("hi", 3, 3, Some(0.9))]);
        assert_eq!(r.as_deref(), Some("hi"));
        let r = pick(&[cf("lo", 2, 3, Some(0.99)), cf("hi", 3, 3, None)]);
        assert_eq!(r.as_deref(), Some("hi"));
        let r = pick(&[cf("a", 3, 3, None), cf("b", 3, 3, Some(0.1))]);
        assert_eq!(r.as_deref(), Some("b"));
        let r = pick(&[
            cf("--lua-desync=a --lua-desync=b", 3, 3, Some(0.5)),
            cf("--lua-desync=c", 3, 3, Some(0.5)),
        ]);
        assert_eq!(r.as_deref(), Some("--lua-desync=c"));
    }

    #[tokio::test]
    async fn stop_and_expiry() {
        let c = corpus();
        let mk = || {
            FakeProbe::default()
                .block("a", Proto::Tls13, Block::Sni)
                .block("a", Proto::Tls12, Block::Sni)
                .pass("a", Proto::Tls13, &c.tls13[..8])
                .pass("a", Proto::Tls12, &c.tls13[..4])
        };
        // стоп сразу
        let p = mk();
        let ctl = FakeCtl::default();
        ctl.stopped_after.set(Some(0));
        let r = search_group(&p, Group::General, &doms(&["a"]), &c, &ctl).await;
        assert_eq!((r.tls, r.http), (None, None));
        assert!(p.sweeps.borrow().is_empty());
        assert!(p.confirms.borrow().is_empty());
        // стоп после первой ступени
        let p = mk();
        let ctl = FakeCtl::default();
        ctl.stopped_after.set(Some(1));
        let r = search_group(&p, Group::General, &doms(&["a"]), &c, &ctl).await;
        assert_eq!((r.tls, r.http), (None, None));
        assert_eq!(p.sweeps.borrow().len(), 1);
        assert!(p.confirms.borrow().is_empty());
        // срок вышел после первой ступени: confirm прошедших её
        let p = mk();
        let ctl = FakeCtl::default();
        ctl.expired_after.set(Some(1));
        let r = search_group(&p, Group::General, &doms(&["a"]), &c, &ctl).await;
        assert_eq!(p.sweeps.borrow().len(), 1);
        assert_eq!(p.confirms.borrow()[0].1.len(), 8);
        assert!(r.tls.is_some());
        // срок вышел до первой ступени: ничего
        let p = mk();
        let ctl = FakeCtl::default();
        ctl.expired_after.set(Some(0));
        let r = search_group(&p, Group::General, &doms(&["a"]), &c, &ctl).await;
        assert!(p.sweeps.borrow().is_empty());
        assert!(p.confirms.borrow().is_empty());
        assert_eq!(r.tls, None);
    }

    /// Цифры `check` каждой цепочки — в итоге группы, выбранная отмечена; перед `check` —
    /// шаг «уточнение».
    #[tokio::test]
    async fn check_rows_reported() {
        let c = corpus();
        let p = FakeProbe::default()
            .block("a", Proto::Tls13, Block::Sni)
            .block("a", Proto::Http, Block::Sni)
            .pass("a", Proto::Tls13, &c.tls13[..2])
            .pass("a", Proto::Http, &c.http[..1]);
        let ctl = FakeCtl::default();
        let r = search_group(&p, Group::General, &doms(&["a"]), &c, &ctl).await;
        let rows: Vec<(&str, &str, bool)> = r
            .check
            .iter()
            .map(|x| (x.chain.as_str(), x.args.as_str(), x.picked))
            .collect();
        assert_eq!(
            rows,
            [
                ("tls", c.tls13[0].as_str(), true),
                ("tls", c.tls13[1].as_str(), false),
                ("http", c.http[0].as_str(), true),
            ]
        );
        let x = &r.check[0];
        assert_eq!(
            (x.group, x.full, x.total, x.median_pct),
            (Group::General, 3, 3, Some(50))
        );
        let g = Group::General;
        assert_eq!(
            *ctl.phases.borrow(),
            [
                Phase::Narrow { group: g },
                Phase::Check { group: g },
                Phase::Narrow { group: g },
                Phase::Check { group: g },
            ]
        );
    }

    #[test]
    fn builtin_corpus_nonempty() {
        let c = Corpus::builtin();
        assert!(!c.tls13.is_empty() && !c.tls12.is_empty() && !c.http.is_empty());
    }

    /// Любая стратегия набора сохраняема в `FOUND_*` (иначе её победа ломает сохранение).
    #[test]
    fn builtin_corpus_saveable() {
        let c = Corpus::builtin();
        for s in c.tls13.iter().chain(&c.tls12).chain(&c.http) {
            assert!(crate::bypass::preset::check_found(s).is_ok(), "{s}");
        }
    }
}
