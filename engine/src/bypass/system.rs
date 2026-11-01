//! Боевые реализации трейтов супервизора: nfqws2, iptables, сеть телефона.

use std::path::PathBuf;
use std::time::Duration;

use super::network::{self, Network};
use super::rules::{self, RuleParams};
use super::supervisor::{Engine, Firewall, Probe};
use crate::firewall::ipt::SystemIpt;
use crate::system::process::BackgroundProcess;

/// Выполнить команду без stdin (`cmd` иначе может ждать ввода), с потолком времени.
async fn quiet(args: &[&str], timeout: Duration) -> Option<(i32, String, String)> {
    let (prog, rest) = args.split_first()?;
    let fut = tokio::process::Command::new(prog)
        .args(rest)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(timeout, fut).await.ok()?.ok()?;
    Some((
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

pub struct SystemEngine {
    pub nfqws2: PathBuf,
    proc: Option<BackgroundProcess>,
}

impl SystemEngine {
    pub fn new(nfqws2: PathBuf) -> Self {
        SystemEngine { nfqws2, proc: None }
    }
}

/// Процесс жив и не зомби.
fn pid_alive(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_some_and(|state| state != "Z" && state != "X"),
        Err(_) => false,
    }
}

impl Engine for SystemEngine {
    async fn dry_run(&self, args: &[String]) -> Result<(), String> {
        let bin = self.nfqws2.to_string_lossy().into_owned();
        let mut argv: Vec<&str> = vec![bin.as_str(), "--dry-run"];
        argv.extend(args.iter().map(String::as_str));
        match quiet(&argv, Duration::from_secs(15)).await {
            Some((0, _, _)) => Ok(()),
            Some((code, out, err)) => {
                let text = format!("{}{}", err.trim(), out.trim());
                Err(if text.is_empty() {
                    format!("код {code}")
                } else {
                    text
                })
            }
            None => Err(format!("{bin} не запустился или не ответил за 15 с")),
        }
    }

    async fn spawn(&mut self, args: &[String]) -> Result<(), String> {
        let bin = self.nfqws2.to_string_lossy().into_owned();
        let mut argv: Vec<&str> = vec![bin.as_str()];
        argv.extend(args.iter().map(String::as_str));
        let p = BackgroundProcess::spawn(&argv).map_err(|e| e.to_string())?;
        self.proc = Some(p);
        Ok(())
    }

    fn alive(&mut self) -> bool {
        self.proc
            .as_ref()
            .and_then(BackgroundProcess::pid)
            .is_some_and(pid_alive)
    }

    async fn stop(&mut self) {
        if let Some(mut p) = self.proc.take() {
            p.kill().await;
        }
    }
}

pub struct SystemFirewall;

impl Firewall for SystemFirewall {
    async fn apply(&self, p: &RuleParams) -> Result<(), String> {
        rules::apply(&SystemIpt, p).await.map_err(|e| e.to_string())
    }
    async fn remove(&self) {
        rules::remove(&SystemIpt).await;
    }
}

pub struct SystemProbe {
    /// Каталог модуля-соседа nfqws2-android.
    pub neighbour_dir: PathBuf,
}

impl Default for SystemProbe {
    fn default() -> Self {
        SystemProbe {
            neighbour_dir: "/data/adb/modules/nfqws2-android".into(),
        }
    }
}

/// Устройство маршрута наружу из вывода `ip route get 1.1.1.1`.
pub fn route_dev(out: &str) -> Option<String> {
    let words: Vec<&str> = out.split_whitespace().collect();
    words
        .windows(2)
        .find(|w| w[0] == "dev")
        .map(|w| w[1].to_string())
}

impl Probe for SystemProbe {
    async fn network(&self) -> Network {
        let t = Duration::from_secs(5);
        let dev = quiet(&["ip", "route", "get", "1.1.1.1"], t)
            .await
            .and_then(|(_, out, _)| route_dev(&out));
        let Some(dev) = dev else {
            return Network::Offline;
        };
        if dev.starts_with("wlan") {
            let ssid = match quiet(&["cmd", "wifi", "status"], t).await {
                Some((_, out, _)) => match network::parse_cmd_wifi(&out) {
                    Some(s) => s,
                    None => quiet(&["dumpsys", "wifi"], t)
                        .await
                        .and_then(|(_, o, _)| network::parse_dumpsys_wifi(&o)),
                },
                None => None,
            };
            if let Some(ssid) = ssid {
                return Network::Wifi { ssid };
            }
        }
        let prop = |k: &'static str| async move {
            quiet(&["getprop", k], t)
                .await
                .map(|(_, o, _)| o)
                .unwrap_or_default()
        };
        let alpha = prop("gsm.operator.alpha").await;
        let sim = prop("gsm.sim.operator.alpha").await;
        Network::Mobile {
            operator: network::operator_from_getprop(&alpha, &sim),
        }
    }

    fn neighbour_active(&self) -> bool {
        let d = &self.neighbour_dir;
        d.is_dir() && !d.join("disable").exists() && !d.join("remove").exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_dev_from_ip_route_get() {
        assert_eq!(
            route_dev("1.1.1.1 dev wlan0 table wlan0 src 192.168.1.5 uid 0 \n    cache \n"),
            Some("wlan0".into())
        );
        assert_eq!(
            route_dev("RTNETLINK answers: Network is unreachable\n"),
            None
        );
    }

    #[test]
    fn neighbour_detection() {
        let d = std::env::temp_dir().join(format!("bcw-nb-{}", std::process::id()));
        let p = SystemProbe {
            neighbour_dir: d.clone(),
        };
        assert!(!p.neighbour_active());
        std::fs::create_dir_all(&d).unwrap();
        assert!(p.neighbour_active());
        std::fs::write(d.join("disable"), "").unwrap();
        assert!(!p.neighbour_active());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn own_pid_is_alive() {
        assert!(pid_alive(std::process::id()));
        assert!(!pid_alive(u32::MAX - 1));
    }
}
