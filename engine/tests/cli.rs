//! CLI-поведение бинаря: запускаем настоящий исполняемый файл.
//!
//! Root не требуется — эти проверки как раз о том, что справка выводится
//! до любых привилегированных действий.

use std::process::{Command, Stdio};

/// Запустить blockcheckw с аргументами, вернуть (stdout + stderr, успех).
fn run(args: &[&str]) -> (String, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_bcw"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("не удалось запустить bcw");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    (combined, out.status.success())
}

/// issue #66: `blockcheckw` без аргументов поднимал права через sudo и печатал
/// диагностику окружения вместо справки.
#[test]
fn bare_invocation_prints_help_only() {
    let (output, ok) = run(&[]);

    assert!(ok, "голый запуск должен завершаться успешно:\n{output}");
    assert!(output.contains("Usage:"), "ожидалась справка:\n{output}");
    assert!(
        !output.contains("Checking prerequisites"),
        "prereq-проверка не должна выполняться без команды:\n{output}"
    );
    assert!(
        !output.contains("elevating with sudo"),
        "справка не должна требовать root:\n{output}"
    );
}

/// bol-van (#66): «неясно, как менять другие параметры типа задержек.
/// Нет ни в --help, ни в доке в явном виде» — флаги живут в сабкомандах,
/// и верхнеуровневая справка обязана на это указывать.
#[test]
fn help_points_to_per_command_flags() {
    let (output, _) = run(&["--help"]);

    assert!(
        output.contains("Examples:"),
        "справке нужны примеры запуска:\n{output}"
    );
    assert!(
        output.contains("<command> --help"),
        "справка должна указывать, где искать флаги команд:\n{output}"
    );
}

/// Встроенный режим на Android включён всегда — ключа больше нет.
#[test]
fn embedded_flag_is_gone() {
    let out = Command::new(env!("CARGO_BIN_EXE_bcw"))
        .args(["--embedded", "status", "--domain-list", "x"])
        .stdin(Stdio::null())
        .output()
        .expect("не удалось запустить bcw");
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("--embedded"));
}

/// На Android не нужны: маршрут через шлюз (policy routing), самообновление (модуль
/// обновляется менеджером), автодополнение shell.
#[test]
fn removed_flags_are_rejected() {
    for args in [
        &["--via", "1.2.3.4", "status", "--domain-list", "x"][..],
        &["--upgrade"][..],
        &["completions", "bash"][..],
        &["scan", "--alive-via", "socks5://h:1"][..],
    ] {
        let (output, ok) = run(args);
        assert!(!ok, "{args:?} должен отвергаться:\n{output}");
        assert!(output.contains("error:"), "{args:?}:\n{output}");
    }
    let (output, ok) = run(&["--version"]);
    assert!(ok, "--version обязан работать:\n{output}");
    assert!(output.contains(env!("CARGO_PKG_VERSION")), "{output}");
}

/// `doctor` — проверка устройства перед первым прогоном; справка не требует root.
#[test]
fn doctor_subcommand_exists() {
    let (output, ok) = run(&["doctor", "--help"]);
    assert!(ok, "doctor --help обязан работать:\n{output}");
    assert!(output.contains("Usage:"), "{output}");
}

/// `bcw svc` без root не трогает iptables, а просит `su -c`.
#[test]
fn svc_cleanup_requires_root() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("SKIPPED: запущено от root");
        return;
    }
    let (output, ok) = run(&["svc", "cleanup"]);
    assert!(!ok, "{output}");
    assert!(output.contains("su -c"), "{output}");
}

#[test]
fn svc_subcommand_exists() {
    let (output, ok) = run(&["svc", "--help"]);
    assert!(ok, "{output}");
    assert!(
        output.contains("run") && output.contains("cleanup"),
        "{output}"
    );
}
