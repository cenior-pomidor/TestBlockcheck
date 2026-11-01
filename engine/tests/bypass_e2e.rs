//! Правила обхода `dpi_*` на реальном ядре (iptables-legacy в CI, локально — что есть).
//!
//! Requires: root. Run: `sudo -E cargo test --test bypass_e2e -- --test-threads=1`
//! Тесты трогают общие стандартные цепочки, поэтому идут по одному (замок `KERNEL`).

use std::net::SocketAddr;

use blockcheckw::bypass::preset::Preset;
use blockcheckw::bypass::rules::{self, POST};
use blockcheckw::bypass::settings::Settings;
use blockcheckw::firewall::ipt::SystemIpt;
use blockcheckw::firewall::rules as search;
use blockcheckw::network::http_client;
use blockcheckw::nfqws2::mark::control_mark;
use blockcheckw::system::process::run_process;

static KERNEL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn params() -> rules::RuleParams {
    rules::params(&Settings::default(), &Preset::default())
}

async fn save(table: &str) -> String {
    run_process(&["iptables-save", "-t", table], 5000)
        .await
        .map(|r| r.stdout)
        .unwrap_or_default()
}

async fn ours_everywhere() -> Vec<String> {
    let mut out = Vec::new();
    for t in ["mangle", "nat", "filter"] {
        out.extend(
            save(t)
                .await
                .lines()
                .filter(|l| l.contains("dpi_"))
                .map(str::to_string),
        );
    }
    out
}

/// Пакеты первого правила цепочки `dpi_post`.
async fn first_rule_packets(chain: &str) -> Option<u64> {
    let out = run_process(
        &[
            "iptables", "-w", "-t", "mangle", "-L", chain, "-v", "-x", "-n",
        ],
        5000,
    )
    .await
    .ok()?;
    out.stdout
        .lines()
        .nth(2)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[tokio::test]
async fn apply_and_remove_leave_no_trace() {
    if !is_root() {
        eprintln!("SKIPPED: requires root");
        return;
    }
    let _k = KERNEL.lock().await;
    rules::apply(&SystemIpt, &params()).await.expect("apply");
    let present = ours_everywhere().await;
    assert!(
        present
            .iter()
            .any(|l| l.contains("-A POSTROUTING -j dpi_post")),
        "{present:#?}"
    );
    assert!(
        present
            .iter()
            .any(|l| l.contains("-A POSTROUTING -j dpi_nat")),
        "{present:#?}"
    );
    assert!(
        present.iter().any(|l| l.contains("-A OUTPUT -j dpi_mquic")),
        "{present:#?}"
    );
    rules::remove(&SystemIpt).await;
    assert!(
        ours_everywhere().await.is_empty(),
        "{:#?}",
        ours_everywhere().await
    );
}

#[tokio::test]
async fn ten_restarts_no_duplicates() {
    if !is_root() {
        eprintln!("SKIPPED: requires root");
        return;
    }
    let _k = KERNEL.lock().await;
    for _ in 0..10 {
        rules::apply(&SystemIpt, &params()).await.expect("apply");
    }
    let mangle = save("mangle").await;
    let count = |needle: &str| mangle.lines().filter(|l| l.contains(needle)).count();
    rules::remove(&SystemIpt).await;
    assert_eq!(count("-A POSTROUTING -j dpi_post"), 1, "{mangle}");
    assert_eq!(count("-A PREROUTING -j dpi_pre"), 1, "{mangle}");
    assert_eq!(
        count("-A dpi_post -m mark --mark 0x40000000/0x40000000 -j MARK"),
        1,
        "{mangle}"
    );
}

#[tokio::test]
async fn bypass_after_search_chains() {
    if !is_root() {
        eprintln!("SKIPPED: requires root");
        return;
    }
    let _k = KERNEL.lock().await;
    let chains = search::prepare_chains(&SystemIpt, "bcw")
        .await
        .expect("prepare_chains");
    rules::apply(&SystemIpt, &params()).await.expect("apply");
    let fixes = search::ensure_order(&SystemIpt, &chains)
        .await
        .expect("ensure_order");
    let post = run_process(
        &["iptables", "-w", "-t", "mangle", "-S", "POSTROUTING"],
        5000,
    )
    .await
    .unwrap()
    .stdout;
    rules::remove(&SystemIpt).await;
    search::drop_chains(&SystemIpt, &chains.marker()).await;
    assert!(
        fixes.is_empty(),
        "обход встал раньше поиска: {fixes:?}\n{post}"
    );
    let order: Vec<&str> = post
        .lines()
        .filter(|l| l.starts_with("-A POSTROUTING"))
        .collect();
    let bcw = order
        .iter()
        .position(|l| l.contains("bcw_"))
        .expect("переход поиска");
    let dpi = order
        .iter()
        .position(|l| l.contains("dpi_post"))
        .expect("переход обхода");
    assert!(bcw < dpi, "{post}");
}

/// Изоляция с нашей стороны: помеченное поиском соединение ловит самое первое правило
/// `dpi_post` и возвращается до очереди; непомеченное его не задевает.
#[tokio::test]
async fn search_control_probe_passes_beside_bypass() {
    if !is_root() {
        eprintln!("SKIPPED: requires root");
        return;
    }
    let _k = KERNEL.lock().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move { while listener.accept().await.is_ok() {} });
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    rules::apply(&SystemIpt, &params()).await.expect("apply");
    let before = first_rule_packets(POST).await;
    drop(http_client::marked_tcp_connect(addr, 0).await);
    let after_plain = first_rule_packets(POST).await;
    drop(http_client::marked_tcp_connect(addr, control_mark()).await);
    let after_marked = first_rule_packets(POST).await;
    rules::remove(&SystemIpt).await;
    server.abort();

    assert_eq!(before, Some(0));
    assert_eq!(
        after_plain,
        Some(0),
        "непомеченное попало в правило изоляции"
    );
    assert!(
        after_marked.unwrap_or(0) > 0,
        "помеченное поиском мимо правила изоляции: {after_marked:?}"
    );
}
