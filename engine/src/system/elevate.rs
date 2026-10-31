/// Проверить, что мы root. На Android переподнимать права нечем (`sudo` нет, у `su`
/// KernelSU/Magisk другие ключи), поэтому без root — понятный отказ.
pub fn require_root() {
    if nix::unistd::getuid().is_root() {
        return;
    }
    eprintln!("bcw требует root: запустите через su -c");
    std::process::exit(2);
}

/// Raise RLIMIT_NOFILE so that many parallel workers don't hit "Too many open files".
/// Each worker needs ~6-8 fd (nfqws2 process + TCP socket + nft calls).
/// Default soft limit is often 1024 — not enough for 256+ workers.
pub fn raise_nofile_limit() {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};

    if let Ok((soft, hard)) = getrlimit(Resource::RLIMIT_NOFILE) {
        let target = hard.min(1_048_576); // cap at 1M, use hard limit
        if soft < target {
            if let Err(e) = setrlimit(Resource::RLIMIT_NOFILE, target, hard) {
                tracing::warn!("failed to raise RLIMIT_NOFILE from {soft} to {target}: {e}");
            }
        }
    }
}

/// Change file ownership to the original (pre-sudo) user.
/// When blockcheckw runs as root via sudo, created files belong to root.
/// This makes them undeletable by the normal user. We read SUDO_UID/SUDO_GID
/// and chown the file back to the caller.
pub fn chown_to_caller(path: &str) {
    let uid: u32 = match std::env::var("SUDO_UID") {
        Ok(v) => match v.parse() {
            Ok(n) => n,
            Err(_) => return,
        },
        Err(_) => return,
    };
    let gid: u32 = std::env::var("SUDO_GID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(uid);

    if let Err(e) = nix::unistd::chown(
        path,
        Some(nix::unistd::Uid::from_raw(uid)),
        Some(nix::unistd::Gid::from_raw(gid)),
    ) {
        tracing::warn!("failed to chown {path} to {uid}:{gid}: {e}");
    }
}
