//! Каталог `runs/`: id прогона, `state.json` и `undo.json`, хранение последних прогонов.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{Found, Group, NaiveStamp, Outcome};
use crate::system::atomic::write_atomic;

const STATE_FILE: &str = "state.json";
const UNDO_FILE: &str = "undo.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepare,
    Baseline,
    Narrow { group: Group },
    Check { group: Group },
    Apply,
    Verify,
    Rollback,
    Done,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DomainState {
    pub group: Group,
    pub domain: String,
    pub block: Option<String>,
    pub left: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct State {
    pub schema: u32,
    pub id: String,
    pub pid: u32,
    pub phase: Phase,
    pub done: u64,
    pub total: u64,
    pub elapsed_s: u64,
    pub domains: Vec<DomainState>,
    pub outcome: Option<Outcome>,
    pub found: Found,
    pub network_title: Option<String>,
    pub base: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Undo {
    pub network_key: String,
    pub prev_strategy: Option<String>,
    pub network_title: String,
    pub prev_net_strategy: bool,
    pub preset: String,
    pub added_user_lines: Vec<String>,
    /// В `user.list` до добавления не было завершающего перевода строки.
    #[serde(default)]
    pub user_list_no_eol: bool,
    pub finished: bool,
}

/// `ГГГГММДД-ЧЧММСС`.
pub fn new_id(at: &NaiveStamp) -> String {
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        at.y, at.mo, at.d, at.h, at.mi, at.s
    )
}

fn is_id(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 15
        && b[8] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 8 || c.is_ascii_digit())
}

fn write_json<T: Serialize>(path: &Path, v: &T) -> io::Result<()> {
    let s = serde_json::to_string_pretty(v).map_err(io::Error::other)?;
    write_atomic(path, &s)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

pub fn write_state(dir: &Path, s: &State) -> io::Result<()> {
    write_json(&dir.join(STATE_FILE), s)
}

pub fn read_state(dir: &Path) -> Option<State> {
    read_json(&dir.join(STATE_FILE))
}

pub fn write_undo(dir: &Path, u: &Undo) -> io::Result<()> {
    write_json(&dir.join(UNDO_FILE), u)
}

pub fn read_undo(dir: &Path) -> Option<Undo> {
    read_json(&dir.join(UNDO_FILE))
}

/// Каталоги прогонов (подкаталоги с именем-id), новые первыми.
fn run_dirs(runs: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(runs) else {
        return Vec::new();
    };
    let mut v: Vec<(String, PathBuf)> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let n = e.file_name().into_string().ok()?;
            is_id(&n).then(|| (n, e.path()))
        })
        .collect();
    v.sort_by(|a, b| b.0.cmp(&a.0));
    v.into_iter().map(|(_, p)| p).collect()
}

/// Каталог новейшего прогона.
pub fn latest(runs: &Path) -> Option<PathBuf> {
    run_dirs(runs).into_iter().next()
}

/// Состояния прогонов, новые первыми; прогоны без читаемого `state.json` пропускаются.
pub fn list(runs: &Path) -> Vec<State> {
    run_dirs(runs)
        .iter()
        .filter_map(|d| read_state(d))
        .collect()
}

/// Оставляет `keep` новейших прогонов, остальные удаляет целиком.
pub fn prune(runs: &Path, keep: usize) {
    for d in run_dirs(runs).into_iter().skip(keep) {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::{Found, Group, NaiveStamp, Outcome};
    use std::fs;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bcw-runs-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn state(id: &str) -> State {
        State {
            schema: 1,
            id: id.into(),
            pid: 42,
            phase: Phase::Narrow {
                group: Group::Youtube,
            },
            done: 5,
            total: 100,
            elapsed_s: 7,
            domains: vec![DomainState {
                group: Group::General,
                domain: "example.org".into(),
                block: Some("tls".into()),
                left: Some(3),
            }],
            outcome: Some(Outcome::Partial {
                failed: Group::Youtube,
            }),
            found: Found::default(),
            network_title: Some("wifi".into()),
            base: "default".into(),
        }
    }

    #[test]
    fn id_format() {
        let at = NaiveStamp {
            y: 2026,
            mo: 11,
            d: 4,
            h: 19,
            mi: 46,
            s: 20,
        };
        assert_eq!(new_id(&at), "20261104-194620");
        let at = NaiveStamp {
            y: 2026,
            mo: 1,
            d: 2,
            h: 3,
            mi: 4,
            s: 5,
        };
        assert_eq!(new_id(&at), "20260102-030405");
    }

    #[test]
    fn state_roundtrip() {
        let d = tmp("state");
        let s = state("20261104-194620");
        write_state(&d, &s).unwrap();
        assert_eq!(read_state(&d), Some(s));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn undo_roundtrip() {
        let d = tmp("undo");
        let u = Undo {
            network_key: "wifi:abc".into(),
            prev_strategy: Some("old".into()),
            network_title: "Home".into(),
            prev_net_strategy: true,
            preset: "found-default-20261104-1946".into(),
            added_user_lines: vec!["a.org".into()],
            user_list_no_eol: false,
            finished: false,
        };
        write_undo(&d, &u).unwrap();
        assert_eq!(read_undo(&d), Some(u));
        assert!(d.join("undo.json").is_file());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn latest_and_list_order() {
        let d = tmp("order");
        for id in ["20261104-100000", "20261104-120000", "20261103-235959"] {
            let r = d.join(id);
            fs::create_dir_all(&r).unwrap();
            write_state(&r, &state(id)).unwrap();
        }
        fs::create_dir_all(d.join("junk")).unwrap();
        fs::write(d.join("20261105-000000"), "file, not dir").unwrap();
        assert_eq!(latest(&d), Some(d.join("20261104-120000")));
        let ids: Vec<String> = list(&d).into_iter().map(|s| s.id).collect();
        assert_eq!(
            ids,
            ["20261104-120000", "20261104-100000", "20261103-235959"]
        );
        assert_eq!(latest(&d.join("missing")), None);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn prune_keeps_10() {
        let d = tmp("prune");
        for i in 0..12 {
            fs::create_dir_all(d.join(format!("20261104-1000{i:02}"))).unwrap();
        }
        fs::create_dir_all(d.join("junk")).unwrap();
        prune(&d, 10);
        let mut left: Vec<String> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n != "junk")
            .collect();
        left.sort();
        assert_eq!(left.len(), 10);
        assert_eq!(left[0], "20261104-100002");
        assert!(d.join("junk").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn read_state_garbage() {
        let d = tmp("garbage");
        fs::write(d.join("state.json"), "{not json").unwrap();
        fs::write(d.join("undo.json"), "").unwrap();
        assert_eq!(read_state(&d), None);
        assert_eq!(read_undo(&d), None);
        assert_eq!(read_state(&d.join("nope")), None);
        let _ = fs::remove_dir_all(&d);
    }
}
