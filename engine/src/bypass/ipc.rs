//! Запрос и ответ между `bcw ctl` и `bcw svc` по абстрактному unix-сокету `bcw.svc`.
//! Одна строка JSON в каждую сторону.

use std::time::Duration;

use super::supervisor::{Command, Status};

pub const SOCKET_NAME: &str = "bcw.svc";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    Start,
    Stop,
    Restart,
    Reload,
    HomeResume,
}

impl Request {
    /// Команда супервизору; `None` — только статус.
    pub fn command(self) -> Option<Command> {
        match self {
            Request::Status => None,
            Request::Start => Some(Command::Start),
            Request::Stop => Some(Command::Stop),
            Request::Restart => Some(Command::Restart),
            Request::Reload => Some(Command::Reload),
            Request::HomeResume => Some(Command::HomeResume),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Response {
    pub ok: bool,
    pub error: Option<String>,
    pub status: Option<Status>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    NotRunning,
    Timeout,
    Bad(String),
}

/// Слушать сокет `name` (абстрактное имя).
pub fn bind(name: &str) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    let l = std::os::unix::net::UnixListener::bind_addr(&addr)?;
    l.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(l)
}

/// Прочитать один запрос и ответить тем, что вернёт `f`.
pub async fn handle_conn<F, Fut>(stream: tokio::net::UnixStream, f: F) -> std::io::Result<()>
where
    F: FnOnce(Result<Request, String>) -> Fut,
    Fut: std::future::Future<Output = Response>,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (rd, mut wr) = stream.into_split();
    let mut line = String::new();
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        BufReader::new(rd).read_line(&mut line),
    )
    .await;
    let req = match read {
        Ok(Ok(_)) => serde_json::from_str::<Request>(line.trim())
            .map_err(|e| format!("непонятный запрос к службе: {e}")),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("запрос к службе не пришёл за 5 с".to_string()),
    };
    let resp = f(req).await;
    let mut out = serde_json::to_string(&resp).unwrap_or_else(|_| "{\"ok\":false}".into());
    out.push('\n');
    wr.write_all(out.as_bytes()).await
}

async fn connect(name: &str) -> std::io::Result<tokio::net::UnixStream> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    let s = std::os::unix::net::UnixStream::connect_addr(&addr)?;
    s.set_nonblocking(true)?;
    tokio::net::UnixStream::from_std(s)
}

/// Как `handle_conn`, но сначала спросить `allowed` про uid собеседника (`SO_PEERCRED`);
/// отказ — ответ «только root» без вызова `f`.
pub async fn handle_conn_checked<F, Fut>(
    stream: tokio::net::UnixStream,
    allowed: impl Fn(Option<u32>) -> bool,
    f: F,
) -> std::io::Result<()>
where
    F: FnOnce(Result<Request, String>) -> Fut,
    Fut: std::future::Future<Output = Response>,
{
    let uid = stream.peer_cred().ok().map(|c| c.uid());
    if allowed(uid) {
        handle_conn(stream, f).await
    } else {
        handle_conn(stream, |_| async {
            Response {
                ok: false,
                error: Some("служба принимает команды только от root".into()),
                status: None,
            }
        })
        .await
    }
}

/// Запрос службе по имени сокета.
pub async fn call_at(name: &str, req: &Request, timeout: Duration) -> Result<Response, CallError> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let work = async {
        let mut s = match connect(name).await {
            Ok(s) => s,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) =>
            {
                return Err(CallError::NotRunning)
            }
            Err(e) => return Err(CallError::Bad(e.to_string())),
        };
        let mut msg = serde_json::to_string(req).map_err(|e| CallError::Bad(e.to_string()))?;
        msg.push('\n');
        s.write_all(msg.as_bytes())
            .await
            .map_err(|e| CallError::Bad(e.to_string()))?;
        let mut line = String::new();
        BufReader::new(s)
            .read_line(&mut line)
            .await
            .map_err(|e| CallError::Bad(e.to_string()))?;
        serde_json::from_str::<Response>(line.trim()).map_err(|e| CallError::Bad(e.to_string()))
    };
    match tokio::time::timeout(timeout, work).await {
        Ok(r) => r,
        Err(_) => Err(CallError::Timeout),
    }
}

pub async fn call(req: &Request, timeout: Duration) -> Result<Response, CallError> {
    call_at(SOCKET_NAME, req, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_json_shape() {
        assert_eq!(
            serde_json::to_string(&Request::Start).unwrap(),
            r#"{"cmd":"start"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::HomeResume).unwrap(),
            r#"{"cmd":"home_resume"}"#
        );
        let r: Request = serde_json::from_str(r#"{"cmd":"reload"}"#).unwrap();
        assert_eq!(r, Request::Reload);
    }

    #[tokio::test]
    async fn ipc_roundtrip() {
        let name = format!("bcw.svc.test.{}", std::process::id());
        let listener = bind(&name).unwrap();
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            handle_conn(s, |req| async move {
                assert_eq!(req, Ok(Request::Status));
                Response {
                    ok: true,
                    error: None,
                    status: Some(Status {
                        state: "running".into(),
                        reason: None,
                        network_key: Some("cell_MegaFon".into()),
                        network_title: Some("Мобильная (MegaFon)".into()),
                        strategy: Some("default".into()),
                    }),
                }
            })
            .await
            .unwrap();
        });
        let r = call_at(&name, &Request::Status, Duration::from_secs(2))
            .await
            .unwrap();
        server.await.unwrap();
        assert!(r.ok);
        assert_eq!(r.status.unwrap().state, "running");
    }

    /// Ревью 2а, Important 6: у абстрактного сокета нет прав файла — проверяем uid.
    #[tokio::test]
    async fn foreign_uid_is_refused() {
        let name = format!("bcw.svc.uid.{}", std::process::id());
        let listener = bind(&name).unwrap();
        let me = unsafe { libc::geteuid() };
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            handle_conn_checked(
                s,
                move |uid| {
                    assert_eq!(uid, Some(me), "uid собеседника");
                    false
                },
                |_| async { panic!("запрос чужого uid выполнен") },
            )
            .await
            .unwrap();
        });
        let r = call_at(&name, &Request::Stop, Duration::from_secs(2))
            .await
            .unwrap();
        server.await.unwrap();
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("root"));
    }

    #[tokio::test]
    async fn call_without_server_is_not_running() {
        let name = format!("bcw.svc.none.{}", std::process::id());
        assert_eq!(
            call_at(&name, &Request::Status, Duration::from_secs(1)).await,
            Err(CallError::NotRunning)
        );
    }

    #[tokio::test]
    async fn garbage_request_is_reported() {
        let name = format!("bcw.svc.bad.{}", std::process::id());
        let listener = bind(&name).unwrap();
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            handle_conn(s, |req| async move {
                Response {
                    ok: false,
                    error: req.err(),
                    status: None,
                }
            })
            .await
            .unwrap();
        });
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let mut c = connect(&name).await.unwrap();
        c.write_all(b"{\"cmd\":\"nope\"}\n").await.unwrap();
        let mut line = String::new();
        BufReader::new(c).read_line(&mut line).await.unwrap();
        server.await.unwrap();
        let r: Response = serde_json::from_str(&line).unwrap();
        assert!(!r.ok && r.error.is_some());
    }
}
