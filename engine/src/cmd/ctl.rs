//! `bcw ctl …` — единственный вход для WebUI (§5 спецификации). Ответ — одна строка JSON
//! `{"schema":1,"ok":…}`; код выхода 0, а при `ok:false` — 1.

#![allow(async_fn_in_trait)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Subcommand;
use serde_json::{json, Map, Value};

use blockcheckw::bypass::args::{self, ArgsInput};
use blockcheckw::bypass::ipc::{self, CallError, Request, Response};
use blockcheckw::bypass::layout::Layout;
use blockcheckw::bypass::logs;
use blockcheckw::bypass::preset::parse_preset;
use blockcheckw::bypass::settings::KEYS;
use blockcheckw::bypass::store::{Store, LIST_NAMES};

#[derive(Subcommand, Debug, Clone)]
pub enum CtlCmd {
    /// Состояние службы и сети.
    Status,
    /// Включить обход.
    Start,
    /// Выключить обход.
    Stop,
    /// Перезапустить обход.
    Restart,
    /// Список стратегий.
    Strategies,
    /// Стратегия: get | save | reset | delete | apply.
    Strategy {
        #[command(subcommand)]
        action: StrategyAction,
    },
    /// Настройки: get | set.
    Settings {
        #[command(subcommand)]
        action: SettingsAction,
    },
    /// Списки и число строк.
    Lists,
    /// Список: get | set.
    List {
        #[command(subcommand)]
        action: ListAction,
    },
    /// Сохранённые сети и домашние Wi-Fi.
    Networks,
    /// Сеть: set | delete.
    Network {
        #[command(subcommand)]
        action: NetworkAction,
    },
    /// Домашние Wi-Fi: add | remove | resume.
    Home {
        #[command(subcommand)]
        action: HomeAction,
    },
    /// Журнал: service | nfqws2 | auto | clear.
    Logs {
        /// service, nfqws2, auto или clear.
        file: String,
        #[arg(long)]
        errors: bool,
        #[arg(long)]
        tail: Option<usize>,
    },
    /// Статистика по журналам.
    Stats,
    /// Версии bcw и модуля.
    Version,
    /// Передача больших данных частями: begin | chunk | end.
    Upload {
        #[command(subcommand)]
        action: UploadAction,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum StrategyAction {
    Get {
        name: String,
    },
    Save {
        name: String,
        #[arg(long)]
        from: PathBuf,
    },
    Reset {
        name: String,
    },
    Delete {
        name: String,
    },
    /// Применить: по умолчанию (`--default`) или для текущей сети (`--network`).
    Apply {
        name: String,
        #[arg(long, conflicts_with = "network")]
        default: bool,
        #[arg(long)]
        network: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum SettingsAction {
    Get,
    Set { key: String, value: String },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ListAction {
    Get {
        name: String,
    },
    Set {
        name: String,
        #[arg(long)]
        from: PathBuf,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum NetworkAction {
    Set { key: String, strategy: String },
    Delete { key: String },
}

#[derive(Subcommand, Debug, Clone)]
pub enum HomeAction {
    Add { ssid: String },
    Remove { ssid: String },
    Resume,
}

#[derive(Subcommand, Debug, Clone)]
pub enum UploadAction {
    Begin,
    Chunk { path: PathBuf, data: String },
    End { path: PathBuf },
}

/// Окружение команд: служба и проверка nfqws2.
pub trait CtlEnv {
    async fn call(&self, r: Request) -> Result<Response, CallError>;
    async fn dry_run(&self, args: &[String]) -> Result<(), String>;
}

pub struct SystemEnv {
    pub nfqws2: PathBuf,
}

impl CtlEnv for SystemEnv {
    async fn call(&self, r: Request) -> Result<Response, CallError> {
        ipc::call(&r, Duration::from_secs(30)).await
    }
    async fn dry_run(&self, a: &[String]) -> Result<(), String> {
        use blockcheckw::bypass::supervisor::Engine;
        blockcheckw::bypass::system::SystemEngine::new(self.nfqws2.clone())
            .dry_run(a)
            .await
    }
}

type Out = Result<Value, String>;

fn ok(v: Value) -> Out {
    Ok(v)
}

/// Превратить итог команды в строку JSON ответа.
pub fn render(r: Out) -> (String, bool) {
    let mut m = Map::new();
    m.insert("schema".into(), json!(1));
    let good = r.is_ok();
    match r {
        Ok(Value::Object(fields)) => {
            m.insert("ok".into(), json!(true));
            m.extend(fields);
        }
        Ok(other) => {
            m.insert("ok".into(), json!(true));
            m.insert("result".into(), other);
        }
        Err(e) => {
            m.insert("ok".into(), json!(false));
            m.insert("error".into(), json!(e));
        }
    }
    (Value::Object(m).to_string(), good)
}

const NOT_RUNNING: &str = "служба не запущена";

fn call_error(e: CallError) -> String {
    match e {
        CallError::NotRunning => NOT_RUNNING.into(),
        CallError::Timeout => "служба не ответила за 30 с".into(),
        CallError::Bad(e) => format!("ошибка связи со службой: {e}"),
    }
}

/// Сообщить службе об изменении данных; «служба не запущена» здесь не ошибка.
async fn reload<E: CtlEnv>(env: &E) -> Option<String> {
    match env.call(Request::Reload).await {
        Ok(r) if !r.ok => r.error,
        _ => None,
    }
}

fn with_warning(mut v: Value, warning: Option<String>) -> Value {
    if let (Some(w), Value::Object(m)) = (warning, &mut v) {
        m.insert("warning".into(), json!(w));
    }
    v
}

fn desired(layout: &Layout) -> String {
    std::fs::read_to_string(layout.state_dir().join("desired"))
        .map(|t| t.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

fn write_desired(layout: &Layout, on: bool) -> Result<(), String> {
    std::fs::create_dir_all(layout.state_dir()).map_err(|e| e.to_string())?;
    blockcheckw::system::atomic::write_atomic(
        &layout.state_dir().join("desired"),
        if on { "on\n" } else { "off\n" },
    )
    .map_err(|e| e.to_string())
}

/// Путь передачи: только внутри `tmp_dir()`.
fn upload_path(layout: &Layout, p: &Path) -> Result<PathBuf, String> {
    let tmp = layout.tmp_dir();
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ok = p.parent() == Some(tmp.as_path())
        && name.starts_with("upload-")
        && name[7..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-');
    if ok {
        Ok(p.to_path_buf())
    } else {
        Err(format!("файл передачи должен лежать в {}", tmp.display()))
    }
}

/// Прочитать переданный файл и удалить его.
fn take_upload(layout: &Layout, p: &Path) -> Result<String, String> {
    let p = upload_path(layout, p)?;
    let text = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    let _ = std::fs::remove_file(&p);
    String::from_utf8(text).map_err(|_| "переданный текст не UTF-8".to_string())
}

/// Base64 (стандартный алфавит, с `=`), без внешних зависимостей.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    }
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if clean.len() % 4 != 0 {
        return Err("base64: длина не кратна 4".into());
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks(4) {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 {
            return Err("base64: лишние =".into());
        }
        let mut n: u32 = 0;
        for &c in &chunk[..4 - pad] {
            n = (n << 6) | val(c).ok_or("base64: недопустимый символ")?;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Ok(out)
}

fn status_value(r: &Response, layout: &Layout) -> Value {
    let st = r.status.clone();
    json!({
        "state": st.as_ref().map(|s| s.state.clone()),
        "reason": st.as_ref().and_then(|s| s.reason.clone()),
        "network_key": st.as_ref().and_then(|s| s.network_key.clone()),
        "network_title": st.as_ref().and_then(|s| s.network_title.clone()),
        "strategy": st.as_ref().and_then(|s| s.strategy.clone()),
        "desired": desired(layout),
    })
}

fn module_version(layout: &Layout) -> Option<String> {
    let prop = std::fs::read_to_string(layout.module_dir.join("module.prop")).ok()?;
    prop.lines()
        .find_map(|l| l.strip_prefix("version=").map(str::to_string))
}

/// Выполнить команду.
pub async fn execute<E: CtlEnv>(cmd: &CtlCmd, store: &Store, env: &E) -> Out {
    let layout = &store.layout;
    match cmd {
        CtlCmd::Status => match env.call(Request::Status).await {
            Ok(r) => ok(status_value(&r, layout)),
            Err(CallError::NotRunning) => ok(json!({
                "state": "not_running",
                "reason": NOT_RUNNING,
                "network_key": null,
                "network_title": null,
                "strategy": null,
                "desired": desired(layout),
            })),
            Err(e) => Err(call_error(e)),
        },
        CtlCmd::Start | CtlCmd::Stop | CtlCmd::Restart => {
            let req = match cmd {
                CtlCmd::Start => {
                    write_desired(layout, true)?;
                    Request::Start
                }
                CtlCmd::Stop => {
                    write_desired(layout, false)?;
                    Request::Stop
                }
                _ => Request::Restart,
            };
            let r = env.call(req).await.map_err(call_error)?;
            if r.ok {
                ok(status_value(&r, layout))
            } else {
                Err(r.error.unwrap_or_else(|| "служба отказала".into()))
            }
        }
        CtlCmd::Strategies => {
            let (s, _) = store.settings();
            ok(json!({ "strategies": store.strategies(), "default_strategy": s.default_strategy }))
        }
        CtlCmd::Strategy { action } => strategy(action, store, env).await,
        CtlCmd::Settings { action } => match action {
            SettingsAction::Get => {
                let (s, warnings) = store.settings();
                let mut m = Map::new();
                for k in KEYS {
                    m.insert(k.into(), json!(s.get(k)));
                }
                ok(json!({ "settings": m, "warnings": warnings }))
            }
            SettingsAction::Set { key, value } => {
                let (mut s, _) = store.settings();
                s.set(key, value)?;
                store.save_settings(&s).map_err(|e| e.to_string())?;
                let w = reload(env).await;
                ok(with_warning(json!({ "key": key, "value": s.get(key) }), w))
            }
        },
        CtlCmd::Lists => {
            let (s, _) = store.settings();
            let lists: Vec<Value> = LIST_NAMES
                .iter()
                .map(|n| json!({ "name": n, "count": store.list_count(n) }))
                .collect();
            ok(json!({ "lists": lists, "mode": s.mode.as_str() }))
        }
        CtlCmd::List { action } => match action {
            ListAction::Get { name } => ok(json!({ "name": name, "text": store.read_list(name)? })),
            ListAction::Set { name, from } => {
                store.list_path(name)?;
                let text = take_upload(layout, from)?;
                store.write_list(name, &text)?;
                let w = reload(env).await;
                ok(with_warning(
                    json!({ "name": name, "count": store.list_count(name) }),
                    w,
                ))
            }
        },
        CtlCmd::Networks => {
            let (s, _) = store.settings();
            let (nets, warnings) = store.networks();
            let current = env.call(Request::Status).await.ok().and_then(|r| r.status);
            ok(json!({
                "networks": nets,
                "home": store.home(),
                "net_strategy": s.net_strategy,
                "home_wifi": s.home_wifi,
                "current_key": current.as_ref().and_then(|c| c.network_key.clone()),
                "current_title": current.as_ref().and_then(|c| c.network_title.clone()),
                "warnings": warnings,
            }))
        }
        CtlCmd::Network { action } => {
            match action {
                NetworkAction::Set { key, strategy } => {
                    store.load_preset(strategy)?;
                    let (nets, _) = store.networks();
                    let title = nets
                        .iter()
                        .find(|n| n.key == *key)
                        .map(|n| n.title.clone())
                        .ok_or_else(|| format!("сети «{key}» нет среди сохранённых"))?;
                    store
                        .set_network_entry(key, &title, strategy)
                        .map_err(|e| e.to_string())?;
                }
                NetworkAction::Delete { key } => {
                    store.delete_network(key).map_err(|e| e.to_string())?
                }
            }
            let w = reload(env).await;
            ok(with_warning(json!({ "networks": store.networks().0 }), w))
        }
        CtlCmd::Home { action } => match action {
            HomeAction::Add { ssid } | HomeAction::Remove { ssid } => {
                let ssid = ssid.trim();
                if ssid.is_empty() || ssid.contains('\n') {
                    return Err("имя сети пустое или в несколько строк".into());
                }
                let r = if matches!(action, HomeAction::Add { .. }) {
                    store.add_home(ssid)
                } else {
                    store.remove_home(ssid)
                };
                r.map_err(|e| e.to_string())?;
                let w = reload(env).await;
                ok(with_warning(json!({ "home": store.home() }), w))
            }
            HomeAction::Resume => {
                let r = env.call(Request::HomeResume).await.map_err(call_error)?;
                if r.ok {
                    ok(status_value(&r, layout))
                } else {
                    Err(r.error.unwrap_or_default())
                }
            }
        },
        CtlCmd::Logs { file, errors, tail } => {
            if file == "clear" {
                for f in logs::FILES {
                    let p = layout.logs_dir().join(f);
                    if p.exists() {
                        std::fs::write(&p, "").map_err(|e| e.to_string())?;
                    }
                }
                return ok(json!({ "cleared": logs::FILES }));
            }
            let name = format!("{file}.log");
            if !logs::FILES.contains(&name.as_str()) {
                return Err(format!("журнала «{file}» нет; есть service, nfqws2, auto"));
            }
            let text = logs::read(&layout.logs_dir().join(&name), *errors, *tail)
                .map_err(|e| e.to_string())?;
            ok(json!({ "file": file, "errors_only": errors, "text": text }))
        }
        CtlCmd::Stats => ok(json!({ "stats": logs::stats(&layout.logs_dir()) })),
        CtlCmd::Version => ok(json!({
            "bcw": env!("CARGO_PKG_VERSION"),
            "module": module_version(layout),
        })),
        CtlCmd::Upload { action } => match action {
            UploadAction::Begin => {
                std::fs::create_dir_all(layout.tmp_dir()).map_err(|e| e.to_string())?;
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let p = layout
                    .tmp_dir()
                    .join(format!("upload-{}-{nanos}", std::process::id()));
                std::fs::write(&p, "").map_err(|e| e.to_string())?;
                ok(json!({ "path": p }))
            }
            UploadAction::Chunk { path, data } => {
                let p = upload_path(layout, path)?;
                if !p.is_file() {
                    return Err("передача не начата: сначала upload begin".into());
                }
                let bytes = b64_decode(data)?;
                use std::io::Write;
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&p)
                    .map_err(|e| e.to_string())?;
                f.write_all(&bytes).map_err(|e| e.to_string())?;
                ok(json!({ "path": p, "added": bytes.len() }))
            }
            UploadAction::End { path } => {
                let p = upload_path(layout, path)?;
                let size = std::fs::metadata(&p).map_err(|e| e.to_string())?.len();
                ok(json!({ "path": p, "size": size }))
            }
        },
    }
}

async fn strategy<E: CtlEnv>(action: &StrategyAction, store: &Store, env: &E) -> Out {
    let layout = &store.layout;
    match action {
        StrategyAction::Get { name } => {
            let text = store.preset_text(name)?;
            let p = parse_preset(&text).map_err(|e| format!("стратегия «{name}», {e}"))?;
            let info = store.strategies().into_iter().find(|i| i.name == *name);
            ok(json!({
                "name": name,
                "text": text,
                "fields": {
                    "NFQWS_BASE_ARGS": p.base,
                    "NFQWS_ARGS": p.tcp,
                    "NFQWS_ARGS_QUIC": p.quic,
                    "NFQWS_ARGS_UDP": p.udp,
                    "NFQWS_ARGS_IPSET": p.ipset,
                    "NFQWS_ARGS_CUSTOM": p.custom,
                },
                "builtin": info.as_ref().is_some_and(|i| i.builtin),
                "modified": info.as_ref().is_some_and(|i| i.modified),
            }))
        }
        StrategyAction::Save { name, from } => {
            let text = take_upload(layout, from)?;
            let preset = parse_preset(&text).map_err(|e| e.to_string())?;
            let (s, _) = store.settings();
            let calls = std::fs::read_to_string(layout.defaults_dir().join("calls-bypass.conf"))
                .unwrap_or_default();
            let a = args::build(&ArgsInput {
                preset: &preset,
                settings: &s,
                layout,
                ipset_nonempty: store.list_count("ipset") > 0,
                calls_conf: &calls,
            })?;
            env.dry_run(&a)
                .await
                .map_err(|e| format!("nfqws2 не принял стратегию: {e}"))?;
            store.save_preset(name, &text)?;
            let w = reload(env).await;
            ok(with_warning(json!({ "name": name }), w))
        }
        StrategyAction::Reset { name } => {
            store.reset_preset(name)?;
            let w = reload(env).await;
            ok(with_warning(json!({ "name": name }), w))
        }
        StrategyAction::Delete { name } => {
            store.delete_preset(name)?;
            let w = reload(env).await;
            ok(with_warning(json!({ "name": name }), w))
        }
        StrategyAction::Apply {
            name,
            default,
            network,
        } => {
            store.load_preset(name)?;
            let (mut s, _) = store.settings();
            let to_network = *network || (!*default && s.net_strategy);
            if to_network {
                let st = env
                    .call(Request::Status)
                    .await
                    .map_err(|e| format!("{} — текущая сеть неизвестна", call_error(e)))?
                    .status
                    .ok_or("служба не сообщила текущую сеть")?;
                let (key, title) = match (st.network_key, st.network_title) {
                    (Some(k), Some(t)) if k != "offline" => (k, t),
                    _ => return Err("сейчас нет сети — сохранить стратегию для неё нельзя".into()),
                };
                store
                    .set_network_entry(&key, &title, name)
                    .map_err(|e| e.to_string())?;
            } else {
                s.set("DEFAULT_STRATEGY", name)?;
                store.save_settings(&s).map_err(|e| e.to_string())?;
            }
            let w = reload(env).await;
            ok(with_warning(
                json!({ "name": name, "applied_to": if to_network { "network" } else { "default" } }),
                w,
            ))
        }
    }
}

/// Точка входа `bcw ctl`.
pub async fn run(cmd: CtlCmd) -> ! {
    let layout = Layout::from_env();
    let store = Store::new(layout.clone());
    let _ = store.init_data_dir();
    let env = SystemEnv {
        nfqws2: layout.nfqws2(),
    };
    let (line, good) = render(execute(&cmd, &store, &env).await);
    println!("{line}");
    std::process::exit(if good { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockcheckw::bypass::supervisor::Status;
    use std::sync::Mutex;

    struct Fake {
        status: Option<Status>,
        calls: Mutex<Vec<Request>>,
        dry_run_error: Option<String>,
    }

    impl Fake {
        fn down() -> Fake {
            Fake {
                status: None,
                calls: Mutex::default(),
                dry_run_error: None,
            }
        }
        fn up(state: &str, reason: Option<&str>, strategy: Option<&str>) -> Fake {
            Fake {
                status: Some(Status {
                    state: state.into(),
                    reason: reason.map(str::to_string),
                    network_key: Some("wifi_Home".into()),
                    network_title: Some("Wi-Fi «Home»".into()),
                    strategy: strategy.map(str::to_string),
                }),
                calls: Mutex::default(),
                dry_run_error: None,
            }
        }
    }

    impl CtlEnv for Fake {
        async fn call(&self, r: Request) -> Result<Response, CallError> {
            self.calls.lock().unwrap().push(r);
            match &self.status {
                None => Err(CallError::NotRunning),
                Some(s) => Ok(Response {
                    ok: true,
                    error: None,
                    status: Some(s.clone()),
                }),
            }
        }
        async fn dry_run(&self, _a: &[String]) -> Result<(), String> {
            self.dry_run_error.clone().map_or(Ok(()), Err)
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

    struct T {
        store: Store,
        root: PathBuf,
    }
    impl Drop for T {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn t(tag: &str) -> T {
        let root = std::env::temp_dir().join(format!("bcw-ctl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let module = Path::new(env!("CARGO_MANIFEST_DIR")).join("../module");
        for d in ["strategies", "defaults"] {
            copy_dir(&module.join(d), &root.join("mod").join(d));
        }
        std::fs::write(root.join("mod/module.prop"), "id=bcw\nversion=v0.1.0\n").unwrap();
        let store = Store::new(Layout {
            module_dir: root.join("mod"),
            data_dir: root.join("data"),
        });
        store.init_data_dir().unwrap();
        T { store, root }
    }

    async fn run_json<E: CtlEnv>(cmd: CtlCmd, store: &Store, env: &E) -> Value {
        let (line, _) = render(execute(&cmd, store, env).await);
        serde_json::from_str(&line).unwrap()
    }

    fn b64(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in data.chunks(3) {
            let n = (c[0] as u32) << 16
                | (*c.get(1).unwrap_or(&0) as u32) << 8
                | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..4 {
                if i <= c.len() {
                    out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn all_commands() -> Vec<(&'static str, CtlCmd)> {
        vec![
            ("status", CtlCmd::Status),
            ("strategies", CtlCmd::Strategies),
            (
                "strategy-get",
                CtlCmd::Strategy {
                    action: StrategyAction::Get { name: "alt".into() },
                },
            ),
            (
                "settings-get",
                CtlCmd::Settings {
                    action: SettingsAction::Get,
                },
            ),
            ("lists", CtlCmd::Lists),
            (
                "list-get",
                CtlCmd::List {
                    action: ListAction::Get {
                        name: "user".into(),
                    },
                },
            ),
            ("networks", CtlCmd::Networks),
            (
                "logs",
                CtlCmd::Logs {
                    file: "service".into(),
                    errors: false,
                    tail: None,
                },
            ),
            ("stats", CtlCmd::Stats),
            ("version", CtlCmd::Version),
        ]
    }

    #[tokio::test]
    async fn every_command_prints_schema_1_json() {
        let t = t("schema");
        for (name, cmd) in all_commands() {
            let v = run_json(cmd, &t.store, &Fake::up("running", None, Some("default"))).await;
            assert_eq!(v["schema"], 1, "{name}");
            assert_eq!(v["ok"], true, "{name}: {v}");
        }
    }

    #[tokio::test]
    async fn start_without_service_says_not_running() {
        let t = t("start");
        let v = run_json(CtlCmd::Start, &t.store, &Fake::down()).await;
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"], "служба не запущена");
        assert_eq!(
            desired(&t.store.layout),
            "on",
            "желаемое записано для службы, которая поднимется"
        );
        let st = run_json(CtlCmd::Status, &t.store, &Fake::down()).await;
        assert_eq!(
            (st["ok"].clone(), st["state"].clone()),
            (json!(true), json!("not_running"))
        );
    }

    #[tokio::test]
    async fn settings_set_validates_and_reloads() {
        let t = t("settings");
        let fake = Fake::up("running", None, Some("default"));
        let bad = CtlCmd::Settings {
            action: SettingsAction::Set {
                key: "PKT_LIMIT_OUT".into(),
                value: "0".into(),
            },
        };
        let v = run_json(bad, &t.store, &fake).await;
        assert_eq!(v["ok"], false);
        assert!(
            v["error"].as_str().unwrap().contains("PKT_LIMIT_OUT"),
            "{v}"
        );
        let good = CtlCmd::Settings {
            action: SettingsAction::Set {
                key: "BLOCK_QUIC".into(),
                value: "1".into(),
            },
        };
        let v = run_json(good, &t.store, &fake).await;
        assert_eq!(v["ok"], true, "{v}");
        assert!(t.store.settings().0.block_quic);
        assert!(fake.calls.lock().unwrap().contains(&Request::Reload));
        // Без службы изменение тоже сохраняется.
        let v = run_json(
            CtlCmd::Settings {
                action: SettingsAction::Set {
                    key: "WATCHDOG".into(),
                    value: "0".into(),
                },
            },
            &t.store,
            &Fake::down(),
        )
        .await;
        assert_eq!(v["ok"], true, "{v}");
    }

    #[tokio::test]
    async fn upload_rejects_path_outside_tmp() {
        let t = t("upload-bad");
        let fake = Fake::down();
        // Только пути внутри временного каталога теста: `--from` удаляет прочитанный файл,
        // и сломанная проверка не должна суметь стереть что-то настоящее.
        let victim = t.root.join("victim.txt");
        std::fs::write(&victim, "не трогать\n").unwrap();
        let sneaky = t.store.layout.tmp_dir().join("..").join("settings.conf");
        for p in [victim.clone(), PathBuf::from("upload-x"), sneaky] {
            let v = run_json(
                CtlCmd::List {
                    action: ListAction::Set {
                        name: "user".into(),
                        from: p.clone(),
                    },
                },
                &t.store,
                &fake,
            )
            .await;
            assert_eq!(v["ok"], false, "{}", p.display());
        }
        assert!(victim.exists(), "файл вне tmp удалён");
        assert!(
            t.store.layout.settings_file().exists(),
            "settings.conf удалён"
        );
        let outside = t.store.layout.tmp_dir().parent().unwrap().join("upload-x");
        let v = run_json(
            CtlCmd::Upload {
                action: UploadAction::Chunk {
                    path: outside,
                    data: "AAAA".into(),
                },
            },
            &t.store,
            &fake,
        )
        .await;
        assert_eq!(v["ok"], false);
    }

    #[tokio::test]
    async fn upload_roundtrip_200kb() {
        let t = t("upload");
        let fake = Fake::down();
        let text: String = (0..20_000).map(|i| format!("host{i}.example\n")).collect();
        assert!(text.len() > 200_000);
        let begin = run_json(
            CtlCmd::Upload {
                action: UploadAction::Begin,
            },
            &t.store,
            &fake,
        )
        .await;
        let path = PathBuf::from(begin["path"].as_str().unwrap());
        for part in text.as_bytes().chunks(48 * 1024) {
            let v = run_json(
                CtlCmd::Upload {
                    action: UploadAction::Chunk {
                        path: path.clone(),
                        data: b64(part),
                    },
                },
                &t.store,
                &fake,
            )
            .await;
            assert_eq!(v["ok"], true, "{v}");
        }
        let v = run_json(
            CtlCmd::List {
                action: ListAction::Set {
                    name: "user".into(),
                    from: path.clone(),
                },
            },
            &t.store,
            &fake,
        )
        .await;
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["count"], 20_000);
        assert_eq!(t.store.read_list("user").unwrap(), text);
        assert!(!path.exists(), "файл передачи удалён после чтения");
    }

    #[tokio::test]
    async fn strategy_save_rejects_dry_run_error() {
        let t = t("save");
        let mut fake = Fake::down();
        fake.dry_run_error = Some("unknown option --nope".into());
        let begin = run_json(
            CtlCmd::Upload {
                action: UploadAction::Begin,
            },
            &t.store,
            &fake,
        )
        .await;
        let path = PathBuf::from(begin["path"].as_str().unwrap());
        run_json(
            CtlCmd::Upload {
                action: UploadAction::Chunk {
                    path: path.clone(),
                    data: b64(b"NFQWS_ARGS=\"--nope\"\n"),
                },
            },
            &t.store,
            &fake,
        )
        .await;
        let v = run_json(
            CtlCmd::Strategy {
                action: StrategyAction::Save {
                    name: "mine".into(),
                    from: path,
                },
            },
            &t.store,
            &fake,
        )
        .await;
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("--nope"), "{v}");
        assert!(t.store.load_preset("mine").is_err(), "не сохранено");
    }

    #[tokio::test]
    async fn apply_to_network_needs_service_and_saves_entry() {
        let t = t("apply");
        let v = run_json(
            CtlCmd::Strategy {
                action: StrategyAction::Apply {
                    name: "alt".into(),
                    default: false,
                    network: true,
                },
            },
            &t.store,
            &Fake::down(),
        )
        .await;
        assert_eq!(v["ok"], false);
        let fake = Fake::up("running", None, Some("default"));
        let v = run_json(
            CtlCmd::Strategy {
                action: StrategyAction::Apply {
                    name: "alt".into(),
                    default: false,
                    network: true,
                },
            },
            &t.store,
            &fake,
        )
        .await;
        assert_eq!(v["applied_to"], "network", "{v}");
        let nets = t.store.networks().0;
        assert_eq!(nets[0].key, "wifi_Home");
        assert_eq!(nets[0].strategy, "alt");
        let v = run_json(
            CtlCmd::Strategy {
                action: StrategyAction::Apply {
                    name: "alt4".into(),
                    default: true,
                    network: false,
                },
            },
            &t.store,
            &fake,
        )
        .await;
        assert_eq!(v["applied_to"], "default");
        assert_eq!(t.store.settings().0.default_strategy, "alt4");
    }

    #[test]
    fn b64_decode_matches_encoder() {
        for data in [&b""[..], b"a", b"ab", b"abc", "Привет, мир".as_bytes()] {
            assert_eq!(b64_decode(&b64(data)).unwrap(), data);
        }
        assert!(b64_decode("abc").is_err());
        assert!(b64_decode("ab!c").is_err());
    }

    /// Образцы ответов для тестов WebUI (`module/tests/ctl-samples/`). `UPDATE_SAMPLES=1`
    /// переписывает их, без него — сверяет.
    #[tokio::test]
    async fn ctl_samples_are_current() {
        let t = t("samples");
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../module/tests/ctl-samples");
        let update = std::env::var_os("UPDATE_SAMPLES").is_some();
        std::fs::create_dir_all(&dir).unwrap();
        // Детерминированные данные: сеть, дом, журналы.
        t.store
            .set_network_entry("wifi_Home", "Wi-Fi «Home»", "alt")
            .unwrap();
        t.store.add_home("Home").unwrap();
        std::fs::write(
            t.store.layout.logs_dir().join("service.log"),
            "2026-11-01 10:00:00 info start стратегия «default», Мобильная (MegaFon)\n\
             2026-11-01 10:05:00 error restart сторож: nfqws2 не работает, перезапуск №1\n",
        )
        .unwrap();
        let running = Fake::up("running", None, Some("default"));
        let mut samples: Vec<(String, Value)> = Vec::new();
        for (name, cmd) in all_commands() {
            samples.push((name.into(), run_json(cmd, &t.store, &running).await));
        }
        for (name, fake) in [
            (
                "status-paused",
                Fake::up("paused_home", Some("домашний Wi-Fi «Home»"), None),
            ),
            (
                "status-blocked",
                Fake::up("blocked_neighbour", Some("включён nfqws2-android"), None),
            ),
            (
                "status-failed",
                Fake::up(
                    "failed",
                    Some("nfqws2 падает: 5 раз подряд, новая попытка через 60 с"),
                    None,
                ),
            ),
            ("status-not-running", Fake::down()),
        ] {
            samples.push((name.into(), run_json(CtlCmd::Status, &t.store, &fake).await));
        }
        let root = t.root.to_string_lossy().into_owned();
        let mut stale = Vec::new();
        for (name, v) in samples {
            let text = serde_json::to_string_pretty(&v)
                .unwrap()
                .replace(&root, "<ROOT>")
                + "\n";
            let path = dir.join(format!("{name}.json"));
            if update {
                std::fs::write(&path, &text).unwrap();
            } else if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
                stale.push(name);
            }
        }
        assert!(
            stale.is_empty(),
            "образцы устарели: {stale:?}; UPDATE_SAMPLES=1 cargo test --bins ctl_samples"
        );
    }
}
