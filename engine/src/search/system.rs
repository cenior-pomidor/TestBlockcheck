//! Настоящие пробы, служба и проверка через обход для задания `bcw search run`.
//! Логики здесь нет — только переход к `pipeline`, `network` и `bypass::ipc`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::apply::{SvcLink, Verifier};
use super::narrow::{Block, Confirmed, Probe};
use super::{NaiveStamp, Proto};
use crate::bypass::ipc::{self, CallError, Request};
use crate::bypass::supervisor::Status;
use crate::config::{CoreConfig, DnsMode};
use crate::dto::VerifiedStrategy;
use crate::error::TaskResult;
use crate::firewall::rules::OwnedChains;
use crate::network::http_client::{
    http_test, http_test_data, interpret_data_transfer_result, interpret_http_result, BodyMode,
    HttpVerdict, DATA_TRANSFER_MIN_BYTES, ROOT_PATH,
};
use crate::network::patience::Patience;
use crate::network::{dns, reachability};
use crate::nfqws2::mark::ProbeMark;
use crate::nfqws2::plan::FilterMark;
use crate::pipeline::reference::References;
use crate::pipeline::runner::{run_parallel, RunParams};
use crate::pipeline::worker_task::HttpTestMode;
use crate::pipeline::{baseline, check};
use crate::strategy::generator::TaggedStrategy;
use crate::strategy::rank::simplicity_key;

/// Проба данных (как в `scan`): медленную, но честную линию не принять за замедление.
const DATA_PROBE_SECS: u64 = 10;
/// Терпение пробы `check` — умолчания `bcw check`.
const CHECK_IDLE: Duration = Duration::from_millis(1000);
const CHECK_CEILING_SECS: u64 = 3;
const CHECK_PASSES: usize = 3;
const IDENTITY_PATH: &str = "/robots.txt";
const IPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Пробы поиска. Ход перебора сообщается не чаще раза в секунду — так же часто пишется
/// `state.json`.
pub struct SystemProbe<'a> {
    pub sweep_cfg: &'a CoreConfig,
    pub check_cfg: &'a CoreConfig,
    pub chains: &'a OwnedChains,
    pub filter_mark: &'a FilterMark,
    /// Срок шагов 2–5 задания.
    pub deadline: Instant,
    pub stop: Arc<AtomicBool>,
    ips: RefCell<HashMap<String, Option<Vec<String>>>>,
}

impl<'a> SystemProbe<'a> {
    pub fn new(
        sweep_cfg: &'a CoreConfig,
        check_cfg: &'a CoreConfig,
        chains: &'a OwnedChains,
        filter_mark: &'a FilterMark,
        deadline: Instant,
        stop: Arc<AtomicBool>,
    ) -> Self {
        SystemProbe {
            sweep_cfg,
            check_cfg,
            chains,
            filter_mark,
            deadline,
            stop,
            ips: RefCell::new(HashMap::new()),
        }
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Адреса домена через DoH (как во встроенном режиме), один раз на домен.
    async fn ips(&self, domain: &str) -> Option<Vec<String>> {
        if let Some(v) = self.ips.borrow().get(domain) {
            return v.clone();
        }
        let v = dns::resolve_domain(domain, DnsMode::Doh)
            .await
            .ok()
            .map(|r| r.ips)
            .filter(|ips| !ips.is_empty());
        self.ips.borrow_mut().insert(domain.to_string(), v.clone());
        v
    }

    /// `None` — стоп раньше, чем `fut` закончился.
    async fn unless_stopped<T>(&self, fut: impl Future<Output = T>) -> Option<T> {
        tokio::pin!(fut);
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                r = &mut fut => return Some(r),
                _ = tick.tick() => if self.stopped() { return None },
            }
        }
    }
}

impl Probe for SystemProbe<'_> {
    async fn classify(&self, domain: &str, p: Proto) -> Block {
        if Instant::now() >= self.deadline {
            return Block::Skip("deadline".into());
        }
        if self.stopped() {
            return Block::Skip("stopped".into());
        }
        let Some(ips) = self.ips(domain).await else {
            return Block::Skip("dns_failed".into());
        };
        let proto = p.to_protocol();
        let timeout = self.sweep_cfg.request_timeout;
        if baseline::test_baseline(domain, proto, timeout, &ips)
            .await
            .is_blocked()
        {
            return if reachability::tcp_reachable(&ips[0], timeout).await {
                Block::Sni
            } else {
                Block::Skip("ip_blocked".into())
            };
        }
        let r = http_test_data(
            proto,
            domain,
            &ips[0],
            ProbeMark::Control.so_mark(),
            DATA_PROBE_SECS,
            BodyMode::LimitedTo(DATA_TRANSFER_MIN_BYTES * 2),
            None,
            ROOT_PATH,
        )
        .await;
        let verdict = interpret_data_transfer_result(&r, domain, DATA_TRANSFER_MIN_BYTES);
        if baseline::is_throttle_verdict(&verdict) {
            Block::Throttled
        } else {
            Block::NotBlocked
        }
    }

    async fn sweep(
        &self,
        domain: &str,
        p: Proto,
        cands: &[String],
        data: bool,
        progress: &dyn Fn(u64),
    ) -> Vec<String> {
        let Some(ips) = self.ips(domain).await else {
            return Vec::new();
        };
        let strategies: Vec<Vec<String>> = cands
            .iter()
            .map(|c| c.split_whitespace().map(str::to_string).collect())
            .collect();
        let completed = Arc::new(AtomicUsize::new(0));
        let pb = indicatif::ProgressBar::hidden();
        let fut = run_parallel(RunParams {
            config: self.sweep_cfg,
            chains: self.chains,
            filter_mark: self.filter_mark,
            domain,
            protocol: p.to_protocol(),
            strategies: &strategies,
            ips: &ips,
            multi: None,
            external_pb: Some(&pb),
            mode: if data {
                HttpTestMode::DataTransfer {
                    min_bytes: DATA_TRANSFER_MIN_BYTES,
                }
            } else {
                HttpTestMode::Standard
            },
            deadline: Some(self.deadline),
            success_sink: None,
            completed: Some(completed.clone()),
        });
        tokio::pin!(fut);
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let results = loop {
            tokio::select! {
                r = &mut fut => break Some(r.0),
                _ = tick.tick() => {
                    if self.stopped() {
                        break None;
                    }
                    progress(completed.load(Ordering::Relaxed) as u64);
                }
            }
        };
        progress(completed.load(Ordering::Relaxed) as u64);
        let ok: Vec<String> = results
            .unwrap_or_default()
            .into_iter()
            .filter(|r| matches!(r.result, TaskResult::Success { .. }))
            .map(|r| r.strategy_args.join(" "))
            .collect();
        cands.iter().filter(|c| ok.contains(c)).cloned().collect()
    }

    async fn confirm(&self, domains: &[(String, Proto)], cands: &[String]) -> Vec<Confirmed> {
        let mut per = Vec::with_capacity(domains.len());
        for (d, p) in domains {
            let left = self.deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || self.stopped() {
                return Vec::new();
            }
            let Some(ips) = self.ips(d).await else {
                return Vec::new();
            };
            let tagged: Vec<TaggedStrategy> = cands
                .iter()
                .map(|c| TaggedStrategy {
                    protocol: p.to_protocol(),
                    args: c.split_whitespace().map(str::to_string).collect(),
                    coverage: 1,
                })
                .collect();
            let refs = References::default();
            let mut con = crate::ui::Console::new();
            let fut = check::run_check(
                self.check_cfg,
                self.chains,
                self.filter_mark,
                d,
                &tagged,
                &ips,
                0,
                CHECK_PASSES,
                Some(left),
                Patience::new(CHECK_IDLE, Duration::from_secs(CHECK_CEILING_SECS)),
                &refs,
                ROOT_PATH,
                IDENTITY_PATH,
                &mut con,
            );
            match self.unless_stopped(fut).await {
                Some(r) => per.push(r.strategies),
                None => return Vec::new(),
            }
        }
        aggregate(cands, &per)
    }
}

/// Итог `check` по всем доменам цепочки — по ХУДШЕМУ домену: `full`/`total` того домена,
/// где доля полной доставки ниже всех, `median_share` — наименьшая (`None`, если на каком-либо
/// домене доли нет). Нет полной доставки хотя бы в одном проходе на каком-либо домене (или
/// строки нет вовсе) — `full = 0`, её отбросит `pick`.
fn aggregate(cands: &[String], per: &[Vec<VerifiedStrategy>]) -> Vec<Confirmed> {
    let rate = |s: &VerifiedStrategy| {
        if s.passes_total == 0 {
            0.0
        } else {
            s.passes_ok as f64 / s.passes_total as f64
        }
    };
    cands
        .iter()
        .map(|c| {
            let rows: Option<Vec<&VerifiedStrategy>> = per
                .iter()
                .map(|v| v.iter().find(|s| s.args == *c))
                .collect();
            let rows = rows.filter(|r| !r.is_empty()).unwrap_or_default();
            let worst = rows
                .iter()
                .copied()
                .min_by(|a, b| rate(a).total_cmp(&rate(b)));
            let (full, total) = worst.map_or((0, 0), |w| (w.passes_ok, w.passes_total));
            let share = rows
                .iter()
                .map(|s| s.median_share)
                .collect::<Option<Vec<f64>>>()
                .and_then(|v| v.into_iter().min_by(f64::total_cmp));
            Confirmed {
                args: c.clone(),
                full,
                total,
                median_share: if rows.is_empty() { None } else { share },
                simplicity: simplicity_key(c),
            }
        })
        .collect()
}

/// Служба `bcw svc` через сокет.
pub struct SystemSvc;

pub fn call_error(e: CallError) -> String {
    match e {
        CallError::NotRunning => "служба не запущена".into(),
        CallError::Timeout => "служба не ответила за 30 с".into(),
        CallError::Bad(e) => format!("ошибка связи со службой: {e}"),
    }
}

impl SvcLink for SystemSvc {
    async fn status(&self) -> Option<Status> {
        ipc::call(&Request::Status, IPC_TIMEOUT)
            .await
            .ok()
            .and_then(|r| r.status)
    }
    async fn reload(&self) -> Result<(), String> {
        match ipc::call(&Request::Reload, IPC_TIMEOUT).await {
            Ok(r) if r.ok => Ok(()),
            Ok(r) => Err(r.error.unwrap_or_else(|| "служба отказала".into())),
            Err(e) => Err(call_error(e)),
        }
    }
}

/// Проверка через обход: без метки, две попытки, успех — не меньше 32 КБ.
pub struct SystemVerifier;

impl Verifier for SystemVerifier {
    async fn through_bypass(&self, domain: &str, p: Proto) -> bool {
        let Ok(r) = dns::resolve_domain(domain, DnsMode::Doh).await else {
            return false;
        };
        let Some(ip) = r.ips.first() else {
            return false;
        };
        for _ in 0..2 {
            if passes(p, domain, ip).await {
                return true;
            }
        }
        false
    }
}

/// Одна попытка через обход. Мера — та же, что у базовой проверки
/// (`pipeline/baseline.rs`, `interpret_baseline`): TLS — получено не меньше
/// `DATA_TRANSFER_MIN_BYTES`; HTTP — проба заголовков (`interpret_http_result` →
/// `Available`): перенаправление на HTTPS законно приходит без тела, порог байтов к нему
/// неприменим.
async fn passes(p: Proto, domain: &str, ip: &str) -> bool {
    let proto = p.to_protocol();
    let v = match p {
        Proto::Http => {
            let res = http_test(proto, domain, ip, 0, DATA_PROBE_SECS, None).await;
            interpret_http_result(&res, domain)
        }
        Proto::Tls13 | Proto::Tls12 => {
            let res = http_test_data(
                proto,
                domain,
                ip,
                0,
                DATA_PROBE_SECS,
                BodyMode::LimitedTo(DATA_TRANSFER_MIN_BYTES * 2),
                None,
                ROOT_PATH,
            )
            .await;
            interpret_data_transfer_result(&res, domain, DATA_TRANSFER_MIN_BYTES)
        }
    };
    matches!(v, HttpVerdict::Available)
}

/// Местное время телефона: смещение из `date +%z` (статический musl не видит базу
/// часовых поясов Android), как у журнала службы.
pub fn local_now() -> NaiveStamp {
    let off = std::process::Command::new("date")
        .arg("+%z")
        .output()
        .ok()
        .and_then(|o| crate::bypass::logs::parse_utc_offset(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or(0);
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    stamp_of(&crate::bypass::logs::format_stamp(epoch, off))
}

/// `YYYY-MM-DD HH:MM:SS` → `NaiveStamp`.
fn stamp_of(s: &str) -> NaiveStamp {
    let n = |r: std::ops::Range<usize>| s.get(r).and_then(|x| x.parse().ok()).unwrap_or(0);
    NaiveStamp {
        y: n(0..4) as i32,
        mo: n(5..7),
        d: n(8..10),
        h: n(11..13),
        mi: n(14..16),
        s: n(17..19),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::narrow::pick;

    fn row(args: &str, ok: usize, share: Option<f64>) -> VerifiedStrategy {
        VerifiedStrategy {
            protocol: "tls12".into(),
            args: args.into(),
            coverage: 1,
            success_rate: 0.0,
            median_latency_ms: 0,
            median_speed_kbps: 0.0,
            passes_ok: ok,
            passes_total: 3,
            median_share: share,
            longest_silence_ms: None,
            observed: "Bytes".into(),
            admits: vec![],
            working: ok == 3,
        }
    }

    #[test]
    fn stamp_parses() {
        // 2026-11-04 16:46:20 UTC, +0300.
        let at = stamp_of(&crate::bypass::logs::format_stamp(1_793_810_780, 10_800));
        assert_eq!(crate::search::runs::new_id(&at), "20261104-194620");
    }

    #[test]
    fn aggregate_takes_worst_domain() {
        let a = "--a".to_string();
        let b = "--b".to_string();
        let c = "--c".to_string();
        let per = vec![
            vec![
                row("--a", 3, Some(0.9)),
                row("--b", 2, Some(0.5)),
                row("--c", 2, Some(0.6)),
            ],
            vec![
                row("--a", 1, Some(0.7)),
                row("--b", 2, Some(0.8)),
                row("--c", 0, None),
            ],
        ];
        let r = aggregate(&[a, b, c], &per);
        // Худший домен, а не сумма: 3/3 + 1/3 → 1/3, доля — наименьшая.
        assert_eq!((r[0].full, r[0].total), (1, 3));
        assert_eq!(r[0].median_share, Some(0.7));
        assert_eq!((r[1].full, r[1].total), (2, 3));
        assert_eq!(r[1].median_share, Some(0.5));
        // Нет полной доставки на одном домене — 0, доли нет.
        assert_eq!(r[2].full, 0);
        assert_eq!(r[2].median_share, None);
        // 2/3 + 2/3 устойчивее, чем 3/3 + 1/3.
        assert_eq!(pick(&r).as_deref(), Some("--b"));
        // Строки нет на домене — 0.
        assert_eq!(aggregate(&["--z".into()], &per)[0].full, 0);
        let half = vec![vec![row("--y", 3, None)], vec![]];
        assert_eq!(aggregate(&["--y".into()], &half)[0].full, 0);
    }
}
