use blockcheckw::config::CoreConfig;
use blockcheckw::pipeline::benchmark;
use blockcheckw::ui;

use blockcheckw::firewall::ipt::SystemIpt;
use blockcheckw::firewall::rules;

use super::{handle_bypass_conflicts, spawn_cleanup_handler, Prerequisites};

pub async fn run_benchmark_cmd(
    time: u64,
    max_workers: Option<u16>,
    domain: &str,
    protocol: &str,
    raw: bool,
    profiles_per_instance: usize,
    prereq: &Prerequisites,
) {
    let con = ui::Console::new();

    let protocol = match blockcheckw::config::parse_protocols(protocol) {
        Ok(p) => p[0],
        Err(e) => {
            con.error(&e.to_string());
            std::process::exit(1);
        }
    };

    let config = CoreConfig::default();
    // Ctrl+C посреди замера снимает наши цепочки, как и в остальных командах.
    let _cleanup = spawn_cleanup_handler(&config.chain_prefix);
    handle_bypass_conflicts(&config.chain_prefix, &con).await;

    // Наши цепочки — до первой пробы (DoH), на весь замер (review C1).
    let chains = match rules::prepare_chains(&SystemIpt, &config.chain_prefix).await {
        Ok(chains) => chains,
        Err(e) => {
            con.error(&format!("iptables: {e}"));
            std::process::exit(
                blockcheckw::dto::Outcome::Broken {
                    reason: blockcheckw::dto::BrokenReason::Firewall,
                }
                .exit_code(),
            );
        }
    };

    let max = max_workers
        .map(|w| w as usize)
        .unwrap_or_else(benchmark::default_max_workers);
    let raw = raw || !console::Term::stderr().is_term();
    benchmark::run_benchmark(
        time,
        max,
        raw,
        domain,
        protocol,
        profiles_per_instance,
        &prereq.filter_mark,
        &chains,
    )
    .await;
    rules::drop_chains(&SystemIpt, &chains.marker()).await;
}
