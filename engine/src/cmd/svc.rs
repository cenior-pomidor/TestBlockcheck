//! `bcw svc run [--boot]` — служба обхода; `bcw svc cleanup` — снять правила обхода.

use std::time::Instant;

use blockcheckw::bypass::ipc::{self, Response, SOCKET_NAME};
use blockcheckw::bypass::layout::Layout;
use blockcheckw::bypass::logs::Journal;
use blockcheckw::bypass::rules;
use blockcheckw::bypass::store::Store;
use blockcheckw::bypass::supervisor::{Supervisor, NET_POLL};
use blockcheckw::bypass::system::{SystemEngine, SystemFirewall, SystemProbe};
use blockcheckw::firewall::ipt::SystemIpt;

pub async fn run(boot: bool) -> ! {
    let layout = Layout::from_env();
    let store = Store::new(layout.clone());
    if let Err(e) = store.init_data_dir() {
        eprintln!("bcw svc: не создать {}: {e}", layout.data_dir.display());
        std::process::exit(1);
    }
    let listener = match ipc::bind(SOCKET_NAME) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!("bcw svc: служба уже запущена");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("bcw svc: сокет {SOCKET_NAME}: {e}");
            std::process::exit(1);
        }
    };
    // Часовой пояс: статический бинарь не видит базу Android, а `date` (bionic) — видит.
    if let Ok(out) = std::process::Command::new("date").arg("+%z").output() {
        if let Some(off) =
            blockcheckw::bypass::logs::parse_utc_offset(&String::from_utf8_lossy(&out.stdout))
        {
            blockcheckw::bypass::logs::set_utc_offset(off);
        }
    }
    let (settings, _) = store.settings();
    let journal = Journal {
        dir: layout.logs_dir(),
        max_kb: settings.log_max_kb,
    };
    // Прошлый экземпляр мог умереть по SIGKILL — его правила снимаем до всего.
    rules::remove(&SystemIpt).await;
    let mut sup = Supervisor::new(
        store,
        journal,
        SystemEngine::new(layout.nfqws2()),
        SystemFirewall,
        SystemProbe::default(),
        boot,
    );
    let mut tick = tokio::time::interval(NET_POLL);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    loop {
        tokio::select! {
            _ = tick.tick() => sup.tick(Instant::now()).await,
            conn = listener.accept() => {
                let Ok((stream, _)) = conn else { continue };
                let sup_ref = &mut sup;
                let _ = ipc::handle_conn_checked(stream, |uid| uid == Some(0), |req| async move {
                    match req {
                        Err(e) => Response { ok: false, error: Some(e), status: None },
                        Ok(r) => match r.command() {
                            None => Response { ok: true, error: None, status: Some(sup_ref.status()) },
                            Some(c) => match sup_ref.command(c, Instant::now()).await {
                                Ok(st) => Response { ok: true, error: None, status: Some(st) },
                                Err(e) => Response { ok: false, error: Some(e), status: Some(sup_ref.status()) },
                            },
                        },
                    }
                })
                .await;
            }
            _ = term.recv() => {
                sup.shutdown().await;
                std::process::exit(0);
            }
            _ = tokio::signal::ctrl_c() => {
                sup.shutdown().await;
                std::process::exit(0);
            }
        }
    }
}

pub async fn cleanup() -> ! {
    rules::remove(&SystemIpt).await;
    std::process::exit(0);
}
