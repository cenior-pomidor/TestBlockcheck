//! Журналы модуля (§4.4): `service.log` пишет служба, `nfqws2.log` и `auto.log` — nfqws2.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const FILES: [&str; 4] = ["service.log", "nfqws2.log", "nfqws2-debug.log", "auto.log"];
/// Файлы, которые пишет nfqws2 (`--debug=@…`, `--hostlist-auto-debug=…`).
pub const NFQWS2_FILES: [&str; 3] = ["nfqws2.log", "nfqws2-debug.log", "auto.log"];

/// Обрезать файл, открытый другим процессом на дозапись: на месте, без подмены.
pub fn trim_in_place(path: &Path, max_kb: u32) -> io::Result<()> {
    let limit = max_kb as usize * 1024;
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if data.len() <= limit {
        return Ok(());
    }
    let start = data.len() - limit / 2;
    let start = data[start..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|i| start + i + 1)
        .unwrap_or(data.len());
    // Тот же inode: открыть с усечением и записать хвост. nfqws2 пишет с O_APPEND.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    f.write_all(&data[start..])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Start,
    Stop,
    Restart,
    Error,
    NetworkChange,
    Pause,
    Resume,
    Rollback,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Start => "start",
            EventKind::Stop => "stop",
            EventKind::Restart => "restart",
            EventKind::Error => "error",
            EventKind::NetworkChange => "network",
            EventKind::Pause => "pause",
            EventKind::Resume => "resume",
            EventKind::Rollback => "rollback",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Stats {
    pub starts: usize,
    pub restarts: usize,
    pub errors: usize,
    pub auto_added: usize,
}

#[derive(Debug, Clone)]
pub struct Journal {
    pub dir: PathBuf,
    pub max_kb: u32,
}

/// Местное время `YYYY-MM-DD HH:MM:SS`.
pub fn now_stamp() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as libc::time_t)
        .unwrap_or(0);
    // SAFETY: localtime_r пишет только в переданную структуру.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

impl Journal {
    pub fn event(&self, kind: EventKind, level: Level, text: &str) -> io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let path = self.dir.join("service.log");
        let lv = match level {
            Level::Info => "info",
            Level::Error => "error",
        };
        let line = format!(
            "{} {lv} {} {}",
            now_stamp(),
            kind.as_str(),
            text.replace('\n', " ")
        );
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        writeln!(f, "{}", line.trim_end())?;
        drop(f);
        trim(&path, self.max_kb)
    }
}

/// Сверх предела остаётся вторая половина файла, с начала полной строки.
pub fn trim(path: &Path, max_kb: u32) -> io::Result<()> {
    let limit = max_kb as usize * 1024;
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if data.len() <= limit {
        return Ok(());
    }
    let start = data.len() - limit / 2;
    let start = data[start..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|i| start + i + 1)
        .unwrap_or(data.len());
    let tmp = path.with_extension("trim");
    std::fs::write(&tmp, &data[start..])?;
    std::fs::rename(tmp, path)
}

/// Текст журнала: только ошибки и/или последние `tail` строк.
pub fn read(path: &Path, errors_only: bool, tail: Option<usize>) -> io::Result<String> {
    let text = match std::fs::read(path) {
        Ok(d) => String::from_utf8_lossy(&d).into_owned(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(e),
    };
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| !errors_only || is_error(l))
        .collect();
    let from = tail.map(|n| lines.len().saturating_sub(n)).unwrap_or(0);
    Ok(lines[from..].iter().map(|l| format!("{l}\n")).collect())
}

/// Строка-ошибка: наша (`… error …`) или nfqws2 (слово error/fail/fatal в тексте).
fn is_error(line: &str) -> bool {
    let low = line.to_lowercase();
    line.get(20..).is_some_and(|r| r.starts_with("error "))
        || ["error", "fail", "fatal", "ошибка"]
            .iter()
            .any(|w| low.contains(w))
}

pub fn stats(dir: &Path) -> Stats {
    let mut s = Stats::default();
    let service = std::fs::read_to_string(dir.join("service.log")).unwrap_or_default();
    for line in service.lines() {
        let mut f = line.get(20..).unwrap_or("").split_whitespace();
        let (level, kind) = (f.next().unwrap_or(""), f.next().unwrap_or(""));
        match kind {
            "start" => s.starts += 1,
            "restart" => s.restarts += 1,
            _ => {}
        }
        if level == "error" {
            s.errors += 1;
        }
    }
    let auto = std::fs::read_to_string(dir.join("auto.log")).unwrap_or_default();
    s.auto_added = auto.lines().filter(|l| l.contains(" : adding to ")).count();
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bcw-logs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn event_line_format() {
        let d = tmp("fmt");
        let j = Journal {
            dir: d.clone(),
            max_kb: 512,
        };
        j.event(EventKind::Start, Level::Info, "стратегия alt")
            .unwrap();
        let text = std::fs::read_to_string(d.join("service.log")).unwrap();
        let line = text.lines().next().unwrap();
        let (stamp, rest) = line.split_at(19);
        assert_eq!(stamp.len(), 19);
        assert_eq!(&stamp[4..5], "-");
        assert_eq!(rest, " info start стратегия alt");
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn trim_keeps_newest_half_on_line_boundary() {
        let d = tmp("trim");
        let p = d.join("x.log");
        let text: String = (0..3000).map(|i| format!("line {i:05}\n")).collect();
        std::fs::write(&p, &text).unwrap();
        trim(&p, 16).unwrap();
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(after.len() <= 16 * 1024 / 2 + 16, "{}", after.len());
        assert!(after.starts_with("line "), "обрезано посреди строки");
        assert!(after.ends_with("line 02999\n"));
        let small = d.join("s.log");
        std::fs::write(&small, "a\n").unwrap();
        trim(&small, 16).unwrap();
        assert_eq!(std::fs::read_to_string(&small).unwrap(), "a\n");
        std::fs::remove_dir_all(d).ok();
    }

    /// Ревью 2а, Important 4: файлы nfqws2 держит открытыми — обрезать на месте, без
    /// подмены файла (иначе nfqws2 пишет в удалённый inode).
    #[test]
    fn trim_in_place_keeps_the_same_file() {
        use std::os::unix::fs::MetadataExt;
        let d = tmp("inplace");
        let p = d.join("nfqws2.log");
        let text: String = (0..3000).map(|i| format!("line {i:05}\n")).collect();
        std::fs::write(&p, &text).unwrap();
        let ino = std::fs::metadata(&p).unwrap().ino();
        trim_in_place(&p, 16).unwrap();
        let after = std::fs::read_to_string(&p).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().ino(), ino, "файл подменён");
        assert!(after.len() <= 16 * 1024 / 2 + 16);
        assert!(after.starts_with("line ") && after.ends_with("line 02999\n"));
        assert!(NFQWS2_FILES.contains(&"nfqws2-debug.log"));
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn errors_filter_and_tail() {
        let d = tmp("read");
        let j = Journal {
            dir: d.clone(),
            max_kb: 512,
        };
        j.event(EventKind::Start, Level::Info, "1").unwrap();
        j.event(EventKind::Error, Level::Error, "nfqws2 упал")
            .unwrap();
        j.event(EventKind::Restart, Level::Info, "2").unwrap();
        let p = d.join("service.log");
        let errs = read(&p, true, None).unwrap();
        assert_eq!(errs.lines().count(), 1);
        assert!(errs.contains("nfqws2 упал"));
        let last = read(&p, false, Some(2)).unwrap();
        assert_eq!(last.lines().count(), 2);
        assert!(last.lines().last().unwrap().ends_with("restart 2"));
        assert_eq!(read(&d.join("нет.log"), false, None).unwrap(), "");
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn stats_count_kinds_and_auto_added() {
        let d = tmp("stats");
        let j = Journal {
            dir: d.clone(),
            max_kb: 512,
        };
        j.event(EventKind::Start, Level::Info, "").unwrap();
        j.event(EventKind::Start, Level::Info, "").unwrap();
        j.event(EventKind::Restart, Level::Info, "сторож").unwrap();
        j.event(EventKind::Error, Level::Error, "x").unwrap();
        j.event(EventKind::Rollback, Level::Error, "y").unwrap();
        // Строки как пишет zapret2 (`HOSTLIST_DEBUGLOG_APPEND`, nfq2/desync.c).
        std::fs::write(
            d.join("auto.log"),
            "01.11.2026 10:00:00 : rutracker.org : profile 3 (noname) : client 10.0.0.2:5555 : proto tls : fail counter 1/3\n\
             01.11.2026 10:00:05 : rutracker.org : profile 3 (noname) : client 10.0.0.2:5555 : proto tls : adding to /data/adb/bcw/lists/auto.list\n\
             01.11.2026 10:01:00 : x.com : profile 3 (noname) : client 10.0.0.2:5556 : proto tls : NOT adding, duplicate detected\n",
        )
        .unwrap();
        let s = stats(&d);
        assert_eq!(
            s,
            Stats {
                starts: 2,
                restarts: 1,
                errors: 2,
                auto_added: 1
            }
        );
        std::fs::remove_dir_all(d).ok();
    }
}
