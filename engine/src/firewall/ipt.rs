//! Единственная точка общения с iptables (Android: в ядре нет nftables).
//!
//! Два инварианта держит тип, а не ревьюер:
//!
//! 1. **Один батч — одна транзакция одной таблицы.** [`IptRun::restore`] отправляет
//!    [`IptBatch`] одним `iptables-restore --noflush -w`: при ошибке не применяется ничего.
//! 2. **Блокировка xtables ждётся.** И `iptables-restore`, и `iptables` вызываются с `-w`:
//!    на Android правила одновременно правят netd и модули обхода.

use crate::error::BlockcheckError;
use crate::system::process::{run_process, run_process_stdin};

/// Имена бинарей живут здесь: снаружи модуля про iptables знать нечего.
pub const IPTABLES: &str = "iptables";
pub const IPTABLES_RESTORE: &str = "iptables-restore";

const RESTORE_TIMEOUT_MS: u64 = 15_000;
const CMD_TIMEOUT_MS: u64 = 5_000;
/// Потолок аварийного пути: panic-хук без него уводил роутеры в перезагрузку (a1f98f5).
const SYNC_TIMEOUT_MS: u64 = 3_000;
const SYNC_POLL_MS: u64 = 50;

/// Таблица iptables, которой мы пользуемся.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Table {
    Mangle,
    Raw,
}

impl Table {
    pub fn name(self) -> &'static str {
        match self {
            Table::Mangle => "mangle",
            Table::Raw => "raw",
        }
    }
}

/// Набор строк `iptables-restore` для одной таблицы, применяемый одной транзакцией.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IptBatch {
    table: Table,
    lines: Vec<String>,
}

impl IptBatch {
    pub(crate) fn new(table: Table, lines: Vec<String>) -> Self {
        IptBatch { table, lines }
    }

    pub fn table(&self) -> Table {
        self.table
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Вход для `iptables-restore`.
    pub fn script(&self) -> String {
        let mut s = format!("*{}\n", self.table.name());
        for line in &self.lines {
            s.push_str(line);
            s.push('\n');
        }
        s.push_str("COMMIT\n");
        s
    }

    fn first_line(&self) -> String {
        self.lines
            .first()
            .cloned()
            .unwrap_or_else(|| "(пустой батч)".to_string())
    }
}

/// Командная строка применения батча: никогда не сбрасывает чужие правила.
pub fn restore_argv() -> [&'static str; 3] {
    [IPTABLES_RESTORE, "--noflush", "-w"]
}

/// Командная строка проверки батча: разобрать и собрать, но не применять.
pub fn restore_test_argv() -> [&'static str; 4] {
    [IPTABLES_RESTORE, "--noflush", "--test", "-w"]
}

/// Командная строка одиночной команды над таблицей.
pub fn cmd_argv(table: Table, args: &[String]) -> Vec<String> {
    let mut argv = vec![
        IPTABLES.to_string(),
        "-w".to_string(),
        "-t".to_string(),
        table.name().to_string(),
    ];
    argv.extend(args.iter().cloned());
    argv
}

/// Из вывода `iptables -S <chain>` оставить правила этой цепочки (`-A <chain> …`).
pub fn parse_rules(chain: &str, out: &str) -> Vec<String> {
    let prefix = format!("-A {chain} ");
    out.lines()
        .map(str::trim_end)
        .filter(|line| line.starts_with(&prefix))
        .map(String::from)
        .collect()
}

/// Итог одиночной команды.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CmdOut {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Асинхронный исполнитель — основной путь.
pub trait IptRun {
    /// Один батч — одна транзакция `iptables-restore --noflush -w`.
    fn restore(
        &self,
        batch: IptBatch,
    ) -> impl std::future::Future<Output = Result<(), BlockcheckError>> + Send;

    /// Проверка батча без применения (`--test`).
    fn restore_test(
        &self,
        batch: IptBatch,
    ) -> impl std::future::Future<Output = Result<(), BlockcheckError>> + Send;

    /// Одиночная команда `iptables -w -t <table> …`. Ненулевой код — не ошибка вызова, а
    /// `ok: false`: «такого правила нет» при уборке — обычное дело.
    fn cmd(
        &self,
        table: Table,
        args: &[String],
    ) -> impl std::future::Future<Output = Result<CmdOut, BlockcheckError>> + Send;
}

/// Синхронный исполнитель для panic-хуков, где async-рантайм может быть мёртв.
pub trait IptRunSync {
    fn cmd(&self, table: Table, args: &[String]) -> Result<bool, BlockcheckError>;
}

/// Настоящий iptables.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemIpt;

async fn run_restore(argv: &[&str], batch: &IptBatch) -> Result<(), BlockcheckError> {
    let result = run_process_stdin(argv, &batch.script(), RESTORE_TIMEOUT_MS).await?;
    if result.exit_code != 0 {
        // stderr обязателен: без него человек не узнает, какого модуля ядра не хватило.
        return Err(BlockcheckError::Iptables {
            command: batch.first_line(),
            stderr: result.stderr,
        });
    }
    Ok(())
}

impl IptRun for SystemIpt {
    async fn restore(&self, batch: IptBatch) -> Result<(), BlockcheckError> {
        run_restore(&restore_argv(), &batch).await
    }

    async fn restore_test(&self, batch: IptBatch) -> Result<(), BlockcheckError> {
        run_restore(&restore_test_argv(), &batch).await
    }

    async fn cmd(&self, table: Table, args: &[String]) -> Result<CmdOut, BlockcheckError> {
        let argv = cmd_argv(table, args);
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        let result = run_process(&argv, CMD_TIMEOUT_MS).await?;
        Ok(CmdOut {
            ok: result.exit_code == 0,
            stdout: result.stdout,
            stderr: result.stderr,
        })
    }
}

/// Тот же iptables для аварийных путей: без tokio, с потолком ожидания.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemIptSync;

impl IptRunSync for SystemIptSync {
    fn cmd(&self, table: Table, args: &[String]) -> Result<bool, BlockcheckError> {
        let argv = cmd_argv(table, args);
        let mut child = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| BlockcheckError::ProcessSpawn {
                reason: e.to_string(),
            })?;
        for _ in 0..(SYNC_TIMEOUT_MS / SYNC_POLL_MS) {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status.success()),
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(SYNC_POLL_MS)),
                Err(e) => {
                    return Err(BlockcheckError::ProcessSpawn {
                        reason: e.to_string(),
                    })
                }
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        Err(BlockcheckError::ProcessTimeout {
            timeout_ms: SYNC_TIMEOUT_MS,
        })
    }
}

/// Интерпретатор для тестов: записывает вызовы, ничего не выполняет.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct State {
        restores: Vec<IptBatch>,
        tests: Vec<IptBatch>,
        cmds: Vec<(Table, Vec<String>)>,
        rules: HashMap<(Table, String), Vec<String>>,
        deletes_left: HashMap<(Table, String), usize>,
        fail_restore: Option<String>,
        /// С какого по счёту `restore` (с нуля) начинать отказывать.
        fail_from: Option<(usize, String)>,
        /// Все операции подряд: `restore:<table>`, `test:<table>`, `cmd:<table>:<args>`.
        ops: Vec<String>,
    }

    #[derive(Default)]
    pub struct RecordingIpt {
        state: Mutex<State>,
    }

    impl RecordingIpt {
        pub fn restores(&self) -> Vec<IptBatch> {
            self.state.lock().unwrap().restores.clone()
        }

        pub fn tests(&self) -> Vec<IptBatch> {
            self.state.lock().unwrap().tests.clone()
        }

        pub fn cmds(&self) -> Vec<(Table, Vec<String>)> {
            self.state.lock().unwrap().cmds.clone()
        }

        /// Ответ на `-S <chain>` этой таблицы.
        pub fn set_rules(&self, table: Table, chain: &str, rules: Vec<String>) {
            self.state
                .lock()
                .unwrap()
                .rules
                .insert((table, chain.to_string()), rules);
        }

        /// Операции в порядке поступления — для утверждений о последовательности.
        pub fn ops(&self) -> Vec<String> {
            self.state.lock().unwrap().ops.clone()
        }

        /// `restore` с номером `n` (с нуля) и все следующие отказывают с этим stderr.
        pub fn fail_restore_from(&self, n: usize, stderr: &str) {
            self.state.lock().unwrap().fail_from = Some((n, stderr.to_string()));
        }

        /// Каждый следующий `restore` (и `restore_test`) отказывает с этим stderr.
        pub fn fail_restore(&self, stderr: &str) {
            self.state.lock().unwrap().fail_restore = Some(stderr.to_string());
        }

        /// Первые `times` вызовов `-D <chain>` этой таблицы успешны, дальше — `ok: false`.
        pub fn delete_succeeds(&self, table: Table, chain: &str, times: usize) {
            self.state
                .lock()
                .unwrap()
                .deletes_left
                .insert((table, chain.to_string()), times);
        }

        fn record_restore(&self, batch: IptBatch, test: bool) -> Result<(), BlockcheckError> {
            let mut st = self.state.lock().unwrap();
            let mut failure = st.fail_restore.clone();
            if !test {
                if let Some((from, stderr)) = &st.fail_from {
                    if st.restores.len() >= *from {
                        failure = Some(stderr.clone());
                    }
                }
            }
            let command = batch.first_line();
            let op = format!(
                "{}:{}",
                if test { "test" } else { "restore" },
                batch.table().name()
            );
            st.ops.push(op);
            if test {
                st.tests.push(batch);
            } else {
                st.restores.push(batch);
            }
            match failure {
                Some(stderr) => Err(BlockcheckError::Iptables { command, stderr }),
                None => Ok(()),
            }
        }
    }

    impl IptRun for RecordingIpt {
        async fn restore(&self, batch: IptBatch) -> Result<(), BlockcheckError> {
            self.record_restore(batch, false)
        }

        async fn restore_test(&self, batch: IptBatch) -> Result<(), BlockcheckError> {
            self.record_restore(batch, true)
        }

        async fn cmd(&self, table: Table, args: &[String]) -> Result<CmdOut, BlockcheckError> {
            let mut st = self.state.lock().unwrap();
            st.ops
                .push(format!("cmd:{}:{}", table.name(), args.join(" ")));
            st.cmds.push((table, args.to_vec()));
            let verb = args.first().map(String::as_str);
            let chain = args.get(1).cloned().unwrap_or_default();
            Ok(match verb {
                Some("-S") => CmdOut {
                    ok: true,
                    stdout: st
                        .rules
                        .get(&(table, chain))
                        .map(|rules| rules.join("\n") + "\n")
                        .unwrap_or_default(),
                    stderr: String::new(),
                },
                Some("-D") => {
                    let left = st.deletes_left.entry((table, chain)).or_insert(0);
                    let ok = *left > 0;
                    if ok {
                        *left -= 1;
                    }
                    CmdOut {
                        ok,
                        ..CmdOut::default()
                    }
                }
                _ => CmdOut {
                    ok: true,
                    ..CmdOut::default()
                },
            })
        }
    }

    impl IptRunSync for RecordingIpt {
        fn cmd(&self, table: Table, args: &[String]) -> Result<bool, BlockcheckError> {
            let mut st = self.state.lock().unwrap();
            st.ops
                .push(format!("cmd:{}:{}", table.name(), args.join(" ")));
            st.cmds.push((table, args.to_vec()));
            if args.first().map(String::as_str) == Some("-D") {
                let chain = args.get(1).cloned().unwrap_or_default();
                let left = st.deletes_left.entry((table, chain)).or_insert(0);
                let ok = *left > 0;
                if ok {
                    *left -= 1;
                }
                return Ok(ok);
            }
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_wraps_lines_in_table_and_commit() {
        let b = IptBatch::new(Table::Raw, vec![":bcw_raw - [0:0]".into()]);
        assert_eq!(b.script(), "*raw\n:bcw_raw - [0:0]\nCOMMIT\n");
    }

    #[test]
    fn restore_never_flushes_and_waits_for_lock() {
        assert_eq!(restore_argv(), ["iptables-restore", "--noflush", "-w"]);
    }

    #[test]
    fn restore_test_only_parses() {
        assert_eq!(
            restore_test_argv(),
            ["iptables-restore", "--noflush", "--test", "-w"]
        );
    }

    #[test]
    fn cmd_waits_for_lock_and_names_table() {
        assert_eq!(
            cmd_argv(Table::Mangle, &["-S".into(), "OUTPUT".into()]),
            ["iptables", "-w", "-t", "mangle", "-S", "OUTPUT"]
        );
    }

    #[test]
    fn parse_rules_keeps_only_appends_of_that_chain() {
        let out = "-P OUTPUT ACCEPT\n-N bcw_out\n-A OUTPUT -j bcw_out\n-A OUTPUT -j nfqws_post\n";
        assert_eq!(
            parse_rules("OUTPUT", out),
            ["-A OUTPUT -j bcw_out", "-A OUTPUT -j nfqws_post"]
        );
    }

    #[test]
    fn parse_rules_ignores_chains_sharing_a_prefix() {
        let out = "-A OUTPUT_x -j y\n-A OUTPUT -j bcw_out\n";
        assert_eq!(parse_rules("OUTPUT", out), ["-A OUTPUT -j bcw_out"]);
    }

    #[tokio::test]
    async fn recording_runner_answers_list_and_counts_deletes() {
        use testing::RecordingIpt;
        let r = RecordingIpt::default();
        r.set_rules(Table::Mangle, "OUTPUT", vec!["-A OUTPUT -j bcw_out".into()]);
        r.delete_succeeds(Table::Mangle, "OUTPUT", 1);
        let listed = IptRun::cmd(&r, Table::Mangle, &["-S".into(), "OUTPUT".into()])
            .await
            .unwrap();
        assert_eq!(listed.stdout.trim(), "-A OUTPUT -j bcw_out");
        let del = |c: &str| {
            vec![
                "-D".to_string(),
                c.to_string(),
                "-j".into(),
                "bcw_out".into(),
            ]
        };
        assert!(
            IptRun::cmd(&r, Table::Mangle, &del("OUTPUT"))
                .await
                .unwrap()
                .ok
        );
        assert!(
            !IptRun::cmd(&r, Table::Mangle, &del("OUTPUT"))
                .await
                .unwrap()
                .ok
        );
        assert!(
            !IptRun::cmd(&r, Table::Raw, &del("OUTPUT"))
                .await
                .unwrap()
                .ok
        );
        assert_eq!(r.cmds().len(), 4);
    }

    #[tokio::test]
    async fn recording_runner_fails_restore_with_stderr() {
        use testing::RecordingIpt;
        let r = RecordingIpt::default();
        r.fail_restore("Couldn't load match `connbytes'");
        let err = r
            .restore(IptBatch::new(
                Table::Mangle,
                vec![":bcw_out - [0:0]".into()],
            ))
            .await
            .unwrap_err();
        match err {
            BlockcheckError::Iptables { command, stderr } => {
                assert_eq!(command, ":bcw_out - [0:0]");
                assert!(stderr.contains("connbytes"));
            }
            other => panic!("ожидалась Iptables, получено {other:?}"),
        }
        assert_eq!(r.restores().len(), 1);
    }

    #[tokio::test]
    async fn recording_runner_keeps_test_batches_apart() {
        use testing::RecordingIpt;
        let r = RecordingIpt::default();
        r.restore_test(IptBatch::new(Table::Raw, vec!["x".into()]))
            .await
            .unwrap();
        assert_eq!(r.tests().len(), 1);
        assert!(r.restores().is_empty());
    }
}
