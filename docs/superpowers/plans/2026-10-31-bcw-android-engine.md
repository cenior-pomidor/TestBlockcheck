# Этап 1. Движок `bcw` для Android — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Статический arm64-бинарник `bcw` — форк blockcheckw 0.12.1, который на Android под root ищет стратегии через iptables, не мешая работающему модулю обхода.

**Architecture:** Код blockcheckw импортируется в `engine/` без изменений, затем по шагам: новая раскладка метки (биты 21–29), бэкенд iptables вместо nftables (`firewall/ipt.rs` — исполнитель, `firewall/rules.rs` — правила), перевод вызывающих на него, Android-умолчания (встроенный режим всегда, пути, uid 0, очередь 777), удаление ненужного, DoH-резолверы, `doctor`, интеграционный тест и сборка arm64 в CI.

**Tech Stack:** Rust (edition 2021, tokio, clap, socket2), iptables-legacy (`iptables`, `iptables-restore`), nfqws2 из zapret2 ≥ v1.0.5, GitHub Actions + `cross`.

**Spec:** `docs/superpowers/specs/2026-10-31-bcw-android-engine-design.md`

**Ветка:** вся работа — в ветке `stage1-engine` от `main`; слияние в `main` — в конце, по согласованию.

## Global Constraints

- Все пути кода ниже — относительно `engine/`; команды `cargo` выполняются из `engine/`.
- `DESYNC` = `0x00200000` (бит 21); поле стратегии `PROFILE` = `0x3FC00000` (биты 22–29, сдвиг 22, ширина 8); `OUR_MASK` = `0x3FE00000`; `CONTROL` — индекс `255`, метка `0x3FC00000`.
- Номера стратегий `1…254`; потолок `--profiles-per-instance` и `--workers` — `254`.
- Биты `0–20`, `30`, `31` (`FOREIGN_BITS = 0xC01FFFFF`) не появляются ни в одной нашей метке и маске.
- «Наше соединение» в метке соединения — только бит 21.
- Применение правил — `iptables-restore --noflush -w`, одна транзакция на таблицу; прочие вызовы — `iptables -w -t <table> …`.
- Цепочки: `<p>_raw`, `<p>_out`, `<p>_post`, `<p>_pre`, `<p>_q`, `<p>_qin`, `<p>_ctl`, префикс `<p>` по умолчанию `bcw`.
- Лимит очереди исходящих: `-m connbytes --connbytes 1:10 --connbytes-dir original --connbytes-mode packets`.
- Очередь по умолчанию `777`; без `--queue-bypass`.
- Умолчания путей: nfqws2 `/data/adb/modules/nfqws2-android/bin/nfqws2`, Lua `/data/adb/modules/nfqws2-android/lua`, рабочий каталог `/data/adb/bcw`.
- nfqws2 запускается с `--uid=0:0`.
- Шестнадцатеричные метки в правилах и аргументах печатаются как `0x{:08X}`.
- Цель сборки — `aarch64-unknown-linux-musl`, статически, без UPX. Имя бинаря — `bcw`.
- Корпус стратегий, логика `scan`/`check`, ключи `--stream`/`--progress` не меняются.
- Коммиты заканчиваются строками:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` и
  `Claude-Session: https://claude.ai/code/session_01Baqyxr5urRqCErFcq7qWA7`.

## Review Focus

1. **Путей оригинала на Android нет** (`/var/run`, `/opt/zapret2`, `/etc/passwd`, `~/.config`) — замок, отчёты и рабочие файлы обязаны жить в рабочем каталоге, который создаётся при старте. Тест: Task 6 `lock_path_is_inside_work_dir`, `work_dir_is_created_on_demand`.
2. **Система или сторож модуля обхода сбросили либо переставили правила посреди прогона** — перед каждым планом переходы восстанавливаются. Тест: Task 3 `ensure_order_reinserts_when_foreign_jump_is_first`, `ensure_order_reapplies_static_part_when_jump_is_missing`.
3. **Домен разрешился в IPv6, мусор или пусто** — типизированная ошибка до вызова iptables, ни одной транзакции. Тест: Task 3 `empty_ip_set_is_rejected_before_iptables`, `non_ipv4_is_rejected_before_iptables`.
4. **`iptables-restore` отверг транзакцию** (нет модуля, неверный синтаксис) — ничего не применено частично, ошибка несёт stderr, исход `broken` с причиной `firewall`. Тест: Task 3 `restore_failure_carries_stderr_and_stops`, Task 4 `broken_firewall_serialises_as_firewall`, `broken_firewall_exits_with_code_3`.
5. **Повторная уборка после `SIGKILL`**: переходов два и больше, цепочек нет вовсе — уборка идемпотентна и не падает. Тест: Task 3 `drop_chains_deletes_every_duplicate_jump`, `drop_chains_on_clean_system_is_silent`.

---

### Task 0: Импорт blockcheckw и CI-база

**Files:**
- Create: `engine/**` (дерево blockcheckw `9ac14855e32a406afffd6c45f5d888b53cf8ebac`)
- Create: `engine/UPSTREAM.md`, `.gitmodules`, `.github/workflows/engine.yml`
- Delete (вторым коммитом): `engine/.github/`, `engine/.claude/`, `engine/.githooks/`, `engine/config.json`, `engine/.gitmodules`, `engine/release-please-config.json`, `engine/.release-please-manifest.json`

**Interfaces:**
- Produces: каталог `engine/` с компилируемым крейтом `blockcheckw`; подмодуль `engine/reference/zapret2` на `a1bca5a85e25ab138e9617a560c262fcf53e969a`; workflow `engine.yml` с job `test`.

- [ ] **Step 1:** `git switch -c stage1-engine`; `git clone https://github.com/rcd27/blockcheckw /tmp/up && git -C /tmp/up archive 9ac14855e32a406afffd6c45f5d888b53cf8ebac | tar -x -C engine`.
- [ ] **Step 2:** Коммит «import: blockcheckw 0.12.1 (9ac1485) без изменений».
- [ ] **Step 3:** Удалить файлы из списка Delete; `git submodule add https://github.com/bol-van/zapret2.git engine/reference/zapret2`, `git -C engine/reference/zapret2 checkout a1bca5a85e25ab138e9617a560c262fcf53e969a`.
- [ ] **Step 4:** `engine/UPSTREAM.md`: базовый коммит, ссылка на upstream, лицензия MIT (rcd27), раздел «Отличия» (заполняется по задачам).
- [ ] **Step 5:** `.github/workflows/engine.yml`, job `test`, `defaults.run.working-directory: engine`: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --lib --bins`, `cargo test --test orphan_reaping --test background_shutdown --test cli --test nft_isolation`.
- [ ] **Step 6:** Проверка локально: `cargo test --lib --bins` — PASS (базовая линия до правок).
- [ ] **Step 7:** Коммит «chore: подмодуль zapret2, UPSTREAM.md, CI движка».

### Task 1: Раскладка метки

**Files:**
- Modify: `src/nfqws2/space.rs` (переписать), `src/nfqws2/mark.rs`, `src/nfqws2/dispatch.rs`, `src/nfqws2/plan.rs`, `src/config.rs:134-170`, `src/dto.rs:157-215`, `src/main.rs` (ключи раскладки, умолчания `--workers`/`--profiles-per-instance`)
- Modify (временно, удаляется в Task 5): `src/firewall/nftables.rs` — только чтобы компилировалось с новым `Dispatch`
- Test: тесты в тех же файлах

**Interfaces:**
- Produces (`nfqws2::space`):
  `pub const PROFILE_WIDTH: u32 = 8;` `pub const DEFAULT_PROFILE_SHIFT: u32 = 22;` `pub const DEFAULT_DESYNC_MARK: u32 = 0x0020_0000;` `pub const CONTROL_INDEX: u32 = 255;` `pub const MAX_PROFILE_INDEX: u16 = 254;` `pub const FOREIGN_BITS: u32 = 0xC01F_FFFF;`
  `pub struct MarkSpace` (Copy) с `pub fn new(desync: u32, profile_shift: u32) -> Result<MarkSpace, String>`, `desync()`, `profile_shift()`, `profile_mask()`, `control_mark()`, `our_mask()` → `u32`;
  `pub fn space() -> MarkSpace`, `pub fn set_space(MarkSpace)`, `pub fn parse_mark(&str) -> Result<u32, String>` (как было).
  Удаляются: `MarkRegion`, `BCW_REGIONS`, `FOREIGN_REGIONS`, `INSTRUMENT_BAND`, `INJECT_BAND`, `ceiling_below`, `MAX_PROFILES_CLEAR_OF_NEIGHBOURS`, `NEIGHBOUR_REGION`, `DEFAULT_WORKER_MARK_BASE`, `worker_base`, `restore_mask`, `intrudes_on_neighbours`.
- Produces (`nfqws2::mark`): `desync_mark()`, `profile_mask()`, `control_mark()`, `our_mask()` → `u32`; `ProfileMark::new(index: u16) -> Option<ProfileMark>` (None для `0` и `> 254`), `index() -> u16`, `so_mark() -> u32` (= `index << shift`), `ct_mark() -> u32` (= `so_mark | desync`), `filter_arg() -> String` (= `--filter-mark=0x{so_mark:08X}/0x{profile_mask:08X}`); `ProbeMark::Control.so_mark() == control_mark()` всегда. Удаляются `worker_mark_base`, `restore_mask`, `own_mark`. `set_embedded`/`is_embedded` остаются.
- Produces (`nfqws2::dispatch`): `pub struct Dispatch { pub queue: QueueNum, pub dport: u16 }`, `Plan::dispatch(dport: u16) -> Dispatch`. `OutMatch` и `InRestore` удаляются.
- Produces (`config`): `pub const MAX_PROFILES_PER_INSTANCE: usize = 254;` `CoreConfig::default().profiles_per_instance == 254`.
- Produces (`dto::RunProvenance`): поле `mark_base` заменено на `profile_mask: String`, добавлено `control_mark: String`; `dto::SCHEMA = 2`.
- CLI: `--mark-desync <MARK>` (умолчание `0x00200000`) и `--mark-profile-shift <N>` (умолчание `22`) вместо `--desync-mark` и `--mark-base`; `--workers` — `range(1..=254)`, `--profiles-per-instance` по умолчанию `254`. Проверка `MAX_PROFILES_CLEAR_OF_NEIGHBOURS` в `main.rs` удаляется.

- [ ] **Step 1: Тесты раскладки (`space.rs`)**

```rust
#[test] fn default_layout_matches_spec() {
    let s = MarkSpace::new(DEFAULT_DESYNC_MARK, DEFAULT_PROFILE_SHIFT).unwrap();
    assert_eq!((s.desync(), s.profile_mask(), s.our_mask(), s.control_mark()),
               (0x0020_0000, 0x3FC0_0000, 0x3FE0_0000, 0x3FC0_0000));
}
#[test] fn rejects_zero_desync() { assert!(MarkSpace::new(0, 22).is_err()); }
#[test] fn rejects_desync_in_netd_bits() { assert!(MarkSpace::new(0x0000_0001, 22).is_err()); }
#[test] fn rejects_profile_reaching_bit_30() { assert!(MarkSpace::new(0x0020_0000, 23).is_err()); }
#[test] fn rejects_desync_inside_profile() { assert!(MarkSpace::new(0x0040_0000, 22).is_err()); }
```

- [ ] **Step 2: Тесты меток (`mark.rs`)**

```rust
#[test] fn every_profile_mark_stays_in_our_bits() {
    for i in 1..=254u16 {
        let m = ProfileMark::new(i).unwrap();
        assert_eq!(m.so_mark() & FOREIGN_BITS, 0);
        assert_eq!(m.so_mark() & desync_mark(), 0);
        assert_eq!(m.so_mark() >> 22, u32::from(i));
        assert_ne!(m.ct_mark() & desync_mark(), 0);
        assert_eq!(m.ct_mark() & profile_mask(), m.so_mark());
        assert_ne!(m.so_mark(), control_mark());
    }
}
#[test] fn zero_255_and_above_are_not_profile_marks() {
    assert!(ProfileMark::new(0).is_none() && ProfileMark::new(255).is_none() && ProfileMark::new(300).is_none());
}
#[test] fn filter_arg_spells_shifted_index_and_mask() {
    assert_eq!(ProfileMark::new(7).unwrap().filter_arg(), "--filter-mark=0x01C00000/0x3FC00000");
}
#[test] fn control_probe_carries_control_mark() { assert_eq!(ProbeMark::Control.so_mark(), 0x3FC0_0000); }
```

Старые тесты `own_mark_tests` и тесты на `worker_mark_base`/`PROFILE_MASK = 0xFFFF` удаляются; в `plan.rs` тест потолка переписывается на `254` (`ProfileMark::new(254)` есть, `255` — нет); в `config.rs` — `validate_parallelism(8, 254)` ok, `(8, 255)` err; в `dispatch.rs` остаётся `dispatch_carries_queue_and_port`.

- [ ] **Step 3:** `cargo test --lib nfqws2:: config::` — FAIL (нет новых имён).
- [ ] **Step 4:** Реализовать интерфейсы выше. `MarkSpace::new` отказывает, если `desync == 0`, `desync & FOREIGN_BITS != 0`, `(0xFF << shift) & FOREIGN_BITS != 0` или `shift > 23`, `desync & (0xFF << shift) != 0`. В `nftables.rs` подставить в правила `profile_mask()`/`desync_mark()` вместо удалённых полей (файл живёт до Task 5).
- [ ] **Step 5:** `cargo test --lib && cargo clippy -- -D warnings` — PASS.
- [ ] **Step 6:** Коммит «feat(mark): раскладка Android — DESYNC бит 21, стратегия в битах 22–29».

### Task 2: Исполнитель iptables

**Files:**
- Create: `src/firewall/ipt.rs`
- Modify: `src/firewall/mod.rs` (`pub mod ipt;`), `src/error.rs` (вариант `Iptables`)
- Test: `src/firewall/ipt.rs` (`#[cfg(test)]`)

**Interfaces:**
- Produces:
  - `pub const IPTABLES: &str = "iptables";` `pub const IPTABLES_RESTORE: &str = "iptables-restore";`
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Table { Mangle, Raw }` с `fn name(self) -> &'static str` (`"mangle"`, `"raw"`).
  - `pub struct IptBatch` (поля приватные): `pub(crate) fn new(table: Table, lines: Vec<String>) -> Self`, `pub fn table(&self) -> Table`, `pub fn lines(&self) -> &[String]`, `pub fn script(&self) -> String` (= `"*<table>\n" + lines.join("\n") + "\nCOMMIT\n"`).
  - `pub fn restore_argv() -> [&'static str; 3]` = `["iptables-restore", "--noflush", "-w"]`; `pub fn restore_test_argv() -> [&'static str; 4]` = `["iptables-restore", "--noflush", "--test", "-w"]`; `pub fn cmd_argv(table: Table, args: &[String]) -> Vec<String>` = `["iptables", "-w", "-t", <table>, args…]`.
  - `pub fn parse_rules(chain: &str, out: &str) -> Vec<String>` — из вывода `-S` оставить строки `-A <chain> …`.
  - `pub trait IptRun { fn restore(&self, batch: IptBatch) -> impl Future<Output = Result<(), BlockcheckError>> + Send; fn restore_test(&self, batch: IptBatch) -> impl Future<Output = Result<(), BlockcheckError>> + Send; fn cmd(&self, table: Table, args: &[String]) -> impl Future<Output = Result<CmdOut, BlockcheckError>> + Send; }`, `pub struct CmdOut { pub ok: bool, pub stdout: String, pub stderr: String }`.
  - `pub trait IptRunSync { fn cmd(&self, table: Table, args: &[String]) -> Result<bool, BlockcheckError>; }` (потолок 3 с, как `SYNC_TIMEOUT_MS` в `nft.rs`).
  - `pub struct SystemIpt;` (таймауты 15 с на restore, 5 с на cmd), `pub struct SystemIptSync;`.
  - `BlockcheckError::Iptables { command: String, stderr: String }` — restore с ненулевым кодом возвращает его (`command` = первая строка батча).
  - `#[cfg(test)] pub(crate) mod testing { pub struct RecordingIpt }`: `restores() -> Vec<IptBatch>`, `tests() -> Vec<IptBatch>` (батчи `restore_test`), `cmds() -> Vec<(Table, Vec<String>)>`, `set_rules(table, chain, Vec<String>)` (ответ на `-S chain`), `fail_restore(stderr: &str)`, `delete_succeeds(times: usize)` (ответ `ok: true` на первые `times` вызовов `-D`, затем `ok: false`). По умолчанию `cmd` отвечает `ok: true`, пустой stdout, а `-D` — `ok: false`.

- [ ] **Step 1: Тесты**

```rust
#[test] fn script_wraps_lines_in_table_and_commit() {
    let b = IptBatch::new(Table::Raw, vec![":bcw_raw - [0:0]".into()]);
    assert_eq!(b.script(), "*raw\n:bcw_raw - [0:0]\nCOMMIT\n");
}
#[test] fn restore_never_flushes_and_waits_for_lock() {
    assert_eq!(restore_argv(), ["iptables-restore", "--noflush", "-w"]);
}
#[test] fn restore_test_only_parses() {
    assert_eq!(restore_test_argv(), ["iptables-restore", "--noflush", "--test", "-w"]);
}
#[test] fn cmd_waits_for_lock_and_names_table() {
    assert_eq!(cmd_argv(Table::Mangle, &["-S".into(), "OUTPUT".into()]),
               ["iptables", "-w", "-t", "mangle", "-S", "OUTPUT"]);
}
#[test] fn parse_rules_keeps_only_appends_of_that_chain() {
    let out = "-P OUTPUT ACCEPT\n-N bcw_out\n-A OUTPUT -j bcw_out\n-A OUTPUT -j nfqws_post\n";
    assert_eq!(parse_rules("OUTPUT", out), ["-A OUTPUT -j bcw_out", "-A OUTPUT -j nfqws_post"]);
}
```

- [ ] **Step 2:** `cargo test --lib firewall::ipt` — FAIL.
- [ ] **Step 3:** Реализовать по интерфейсам (`run_process_stdin`/`run_process` из `system::process`, синхронный путь — как `SystemNftSync::run`).
- [ ] **Step 4:** `cargo test --lib firewall::ipt` — PASS.
- [ ] **Step 5:** Коммит «feat(firewall): исполнитель iptables».

### Task 3: Правила iptables

**Files:**
- Create: `src/firewall/rules.rs`
- Modify: `src/firewall/mod.rs` (`pub mod rules;`)
- Test: `src/firewall/rules.rs` (`#[cfg(test)]`, через `RecordingIpt`)

**Interfaces:**
- Consumes: `IptRun`, `IptRunSync`, `IptBatch`, `Table`, `CmdOut` (Task 2); `Dispatch`, `desync_mark()`, `profile_mask()`, `control_mark()`, `our_mask()` (Task 1); `nfqws2::run::Ready` (`queue()`); `BlockcheckError::{Iptables, QueueWitnessMismatch}`.
- Produces:
  - `#[derive(Debug, Clone)] pub struct ChainNames` с `fn new(prefix: &str) -> Self` и `raw()`, `out()`, `post()`, `pre()`, `q()`, `qin()`, `ctl()` → `String` (`"<p>_raw"` …).
  - `pub struct OwnedChains` (не `Clone`): `names(&self) -> &ChainNames`, `marker(&self) -> OwnedChainsMarker`.
  - `#[derive(Debug, Clone)] pub struct OwnedChainsMarker`: `planned(prefix: &str) -> Self`, `names(&self) -> &ChainNames`.
  - `pub fn static_batches(names: &ChainNames) -> [IptBatch; 2]` — `[Raw, Mangle]`, статическая часть спеки §4.1 (`<p>_q`/`<p>_qin` пустые).
  - `pub async fn prepare_chains<R: IptRun>(r: &R, prefix: &str) -> Result<OwnedChains, BlockcheckError>` — сначала `drop_chains` (остатки), затем `restore` обоих батчей `static_batches` по порядку.
  - `pub async fn apply_dispatch<R: IptRun>(r: &R, chains: &OwnedChains, ready: &Ready, d: &Dispatch, ips: &[String]) -> Result<(), BlockcheckError>` — одна транзакция `Mangle`: объявляет `<p>_post`, `<p>_pre`, `<p>_q`, `<p>_qin` и собирает их по спеке §4.1–4.2, правила плана — по строке на IP, перед завершающими ACCEPT.
  - `pub async fn remove_dispatch<R: IptRun>(r: &R, chains: &OwnedChains)` — та же транзакция без правил плана, `<p>_q`/`<p>_qin` пустые; ошибка — `warn!`, не отказ.
  - `pub async fn drop_chains<R: IptRun>(r: &R, m: &OwnedChainsMarker)` и `pub fn drop_chains_sync<R: IptRunSync>(r: &R, m: &OwnedChainsMarker)` — `-D <BUILTIN> -j <наша>` повторять, пока `ok`, для пар `(Raw, OUTPUT, raw)`, `(Mangle, OUTPUT, out)`, `(Mangle, POSTROUTING, post)`, `(Mangle, PREROUTING, pre)`; затем `-F` и `-X` всех семи цепочек; отсутствие — не ошибка.
  - `pub struct Reorder { pub table: Table, pub chain: &'static str, pub reapplied: bool }`; `pub async fn ensure_order<R: IptRun>(r: &R, chains: &OwnedChains) -> Result<Vec<Reorder>, BlockcheckError>` — для четырёх пар читает `-S <BUILTIN>`; если наш переход есть, но не первый — `-D` и `-I <BUILTIN> 1 -j <наша>` (`reapplied: false`); если нашего перехода нет — повторить статическую часть обеих таблиц (`reapplied: true`, по записи на каждую пропавшую пару).
  - `fn validate_ip_set(ips: &[String]) -> Result<(), BlockcheckError>` — перенос из `nftables.rs` (пусто → ошибка, не IPv4 → ошибка).

- [ ] **Step 1: Тесты статической части**

```rust
#[tokio::test] async fn static_part_is_one_transaction_per_table() {
    let r = RecordingIpt::default();
    prepare_chains(&r, "bcw").await.unwrap();
    let t: Vec<Table> = r.restores().iter().map(|b| b.table()).collect();
    assert_eq!(t, [Table::Raw, Table::Mangle]);
}
#[tokio::test] async fn jumps_are_inserted_first() {
    // raw: "-I OUTPUT 1 -j bcw_raw"; mangle: "-I OUTPUT 1 -j bcw_out",
    // "-I POSTROUTING 1 -j bcw_post", "-I PREROUTING 1 -j bcw_pre"
}
#[tokio::test] async fn prepare_sweeps_leftover_jumps_before_restore() {
    // delete_succeeds(1): первый -D ok, далее false; все -D идут раньше первого restore
}
#[tokio::test] async fn desync_packets_are_notracked() {
    // raw содержит "-A bcw_raw -m mark --mark 0x00200000/0x00200000 -j CT --notrack"
}
```

- [ ] **Step 2: Тесты диспетчеризации**

```rust
#[tokio::test] async fn dispatch_rules_match_spec_for_each_ip() {
    // ips ["1.2.3.4","5.6.7.8"], dport 443, Ready::witnessed(QueueNum::new(777)):
    // ровно 2 строки
    // "-A bcw_post -p tcp --dport 443 -d <ip> -m mark ! --mark 0x00000000/0x3FC00000 -m mark ! --mark 0x3FC00000/0x3FC00000 -m connbytes --connbytes 1:10 --connbytes-dir original --connbytes-mode packets -j bcw_q"
    // ровно 2 строки
    // "-A bcw_pre -p tcp --sport 443 -s <ip> --tcp-flags SYN,ACK SYN,ACK -m connmark --mark 0x00200000/0x00200000 -m connmark ! --mark 0x3FC00000/0x3FC00000 -j bcw_qin"
    // и "-A bcw_q -j NFQUEUE --queue-num 777", "-A bcw_qin -j NFQUEUE --queue-num 777"
}
#[tokio::test] async fn dispatch_rules_precede_final_accepts() {
    // индекс любой "-j bcw_q" < индекса "-A bcw_post -m mark ! --mark 0x00000000/0x3FE00000 -j ACCEPT";
    // индекс любой "-j bcw_qin" > индексов двух ICMP-правил и < "-A bcw_pre -m connmark --mark 0x00200000/0x00200000 -j ACCEPT"
}
#[tokio::test] async fn every_mask_is_within_our_bits() {
    // все "0xVVVVVVVV/0xMMMMMMMM", "--nfmask 0x…", "--ctmask 0x…" во всех транзакциях: M & !0x3FE00000 == 0
}
#[tokio::test] async fn our_connection_is_recognised_by_bit_21_only() {
    // каждое НЕотрицательное "-m connmark --mark V/M" имеет V == M == 0x00200000
}
#[tokio::test] async fn control_is_never_queued() {
    // каждая строка с "-j bcw_q" содержит "! --mark 0x3FC00000/0x3FC00000"; в bcw_ctl нет NFQUEUE
}
#[tokio::test] async fn witness_for_another_queue_is_refused() {
    // Ready 778 при Dispatch 777 → QueueWitnessMismatch, новых restore нет
}
#[tokio::test] async fn remove_dispatch_restores_base_and_empties_queues() {
    // последняя транзакция: нет "-j bcw_q"/"-j bcw_qin"/"NFQUEUE", базовые ACCEPT на месте
}
```

- [ ] **Step 3: Тесты Review Focus**

```rust
#[tokio::test] async fn empty_ip_set_is_rejected_before_iptables()      // ips [] → Err, restores() не растёт
#[tokio::test] async fn non_ipv4_is_rejected_before_iptables()          // ["2001:db8::1"] и ["1.2.3.4 -j DROP"] → Err
#[tokio::test] async fn restore_failure_carries_stderr_and_stops()      // fail_restore("Couldn't load match `connbytes'") → Err(Iptables{stderr}), вторая транзакция не отправлена
#[tokio::test] async fn drop_chains_deletes_every_duplicate_jump()      // delete_succeeds(2) на OUTPUT → три -D OUTPUT, затем -F/-X всех 7 цепочек
#[tokio::test] async fn drop_chains_on_clean_system_is_silent()         // все cmd ok:false → не паникует, -F/-X вызваны
#[tokio::test] async fn ensure_order_reinserts_when_foreign_jump_is_first() // set_rules(Mangle,"OUTPUT",["-A OUTPUT -j nfqws_post","-A OUTPUT -j bcw_out"]) → -D и "-I OUTPUT 1 -j bcw_out", Reorder{Mangle,"OUTPUT",false}
#[tokio::test] async fn ensure_order_reapplies_static_part_when_jump_is_missing() // set_rules(Mangle,"OUTPUT",[]) → снова две статические транзакции, reapplied: true
```

- [ ] **Step 4:** `cargo test --lib firewall::rules` — FAIL.
- [ ] **Step 5:** Реализовать по интерфейсам; тексты правил — дословно из спеки §4.1–4.2 с подстановкой префикса, порта, IP и очереди.
- [ ] **Step 6:** `cargo test --lib firewall::rules && cargo clippy -- -D warnings` — PASS.
- [ ] **Step 7:** Коммит «feat(firewall): правила iptables, страж порядка, уборка».

### Task 4: Перевод вызывающих на iptables

**Files:**
- Modify: `src/pipeline/runner.rs`, `src/pipeline/check.rs`, `src/pipeline/test_runner.rs`, `src/cmd/scan.rs`, `src/cmd/universal.rs`, `src/cmd/benchmark.rs`, `src/cmd/mod.rs` (`CleanupInfo`, `emergency_cleanup_sync`, `graceful_cleanup`, `spawn_cleanup_handler`), `src/system/orphans.rs`, `src/main.rs` (panic-хук, снятие остатков), `src/config.rs` (ключи ядра), `src/dto.rs` (`RunProvenance`, `BrokenReason`), `src/machine.rs`
- Test: `src/system/orphans.rs`, `src/dto.rs`, `src/machine.rs`

**Interfaces:**
- Consumes: всё из Task 3.
- Produces:
  - `config`: `pub const DEFAULT_CHAIN_PREFIX: &str = "bcw";`, `pub fn chain_prefix() -> String` (вместо `DEFAULT_NFT_TABLE`/`nft_table()`), `set_kernel_keys(qnum: u16, chain_prefix: &str, smoke_qnum_base: u16)`, `CoreConfig.chain_prefix: String` (вместо `nft_table`). CLI `--chain-prefix <NAME>` вместо `--nft-table`.
  - `dto::RunProvenance.chain_prefix: String` (вместо `nft_table`); `dto::BrokenReason::Firewall` (сериализуется `"firewall"`) вместо `Nft`.
  - `orphans::Signature { chain_prefix: String, qnum: u16, desync_mark: u32 }`; `SweepReport { killed: Vec<i32>, chains_dropped: bool }`; `pub async fn sweep_own<R: IptRun>(r: &R, sig: &Signature) -> SweepReport` — движки по признаку, затем `drop_chains`; `chains_dropped` истинно, если `-S OUTPUT` в `mangle` содержал наш переход.
  - `cmd::CleanupInfo.chains: OwnedChainsMarker` (вместо `nft_table`); аварийные пути вызывают `drop_chains_sync(&SystemIptSync, …)` / `drop_chains(&SystemIpt, …)`.
  - `machine::emit_reorder(table: &str, chain: &str, reapplied: bool)` — `{"event":"reorder","table":…,"chain":…,"reapplied":…}` в stderr при `--progress`.
  - В `runner.rs`, `check.rs`, `test_runner.rs` перед каждым `apply_dispatch` — `ensure_order(&SystemIpt, &chains)`, каждая запись → `emit_reorder` и `tracing::warn!`; ошибка `ensure_order` обрабатывается как ошибка `apply_dispatch` в том же месте.
  - Отказ `prepare_chains` даёт `Outcome::Broken { reason: BrokenReason::Firewall }` там же, где раньше отказ `prepare_table` давал `BrokenReason::Nft` (`pipeline/check.rs:82`, `dto.rs`); код выхода `3`, как у `Nft`.

- [ ] **Step 1: Тесты**

```rust
#[test] fn broken_firewall_serialises_as_firewall() {
    assert_eq!(serde_json::to_string(&BrokenReason::Firewall).unwrap(), "\"firewall\"");
}
#[test] fn broken_firewall_exits_with_code_3() {
    assert_eq!(Outcome::Broken { reason: BrokenReason::Firewall }.exit_code(), 3);
}
#[tokio::test] async fn sweep_own_drops_our_chains_after_engines() {
    // RecordingIpt::set_rules(Mangle,"OUTPUT",["-A OUTPUT -j bcw_out"]) → chains_dropped == true,
    // все -D/-F/-X относятся только к цепочкам "bcw_*"
}
#[test] fn reorder_event_is_ndjson() {
    // строка, собираемая emit_reorder, разбирается как JSON с event == "reorder" (вынести сборку в fn reorder_line)
}
```

- [ ] **Step 2:** `cargo test --lib` — FAIL.
- [ ] **Step 3:** Перевести вызовы `nftables::{prepare_table, apply_dispatch, remove_dispatch, drop_table}` на `rules::{prepare_chains, apply_dispatch, remove_dispatch, drop_chains}`, `SystemNft` → `SystemIpt`, `OwnedTable(Marker)` → `OwnedChains(Marker)`; panic-хук в `main.rs` — `drop_chains_sync(&SystemIptSync, &OwnedChainsMarker::planned(&chain_prefix()))`.
- [ ] **Step 4:** `cargo test --lib --bins && cargo clippy -- -D warnings` — PASS (модуль `nft` пока используется только в `cmd/mod.rs`, Task 5).
- [ ] **Step 5:** Коммит «refactor: прогоны и уборка через iptables».

### Task 5: Соседи, преflight и удаление nftables

**Files:**
- Modify: `src/cmd/mod.rs` (`BypassConflicts`, `detect_bypass_conflicts`, `handle_bypass_conflicts`, `check_prerequisites`)
- Delete: `src/firewall/nft.rs`, `src/firewall/nftables.rs`, вариант `BlockcheckError::Nftables`
- Rename: `tests/nft_isolation.rs` → `tests/ipt_isolation.rs`; `.github/workflows/engine.yml` — имя теста
- Test: `src/cmd/mod.rs`, `tests/ipt_isolation.rs`

**Interfaces:**
- Consumes: `IptRun`, `Table`, `parse_rules` (Task 2).
- Produces:
  - `BypassConflicts { has_nfqws2_processes: bool, foreign_queue_chains: Vec<String> }`.
  - `fn foreign_queue_chains(save: &str, own_prefix: &str) -> Vec<String>` — по выводу `iptables -w -t mangle -S`: имена цепочек, в которых есть `-j NFQUEUE`, кроме начинающихся с `<own_prefix>_`; без повторов, в порядке появления.
  - `detect_bypass_conflicts(own_prefix: &str) -> BypassConflicts` только наблюдает; `handle_bypass_conflicts` всегда идёт путём встроенного режима: `machine::emit_neighbours(&foreign_queue_chains, has_nfqws2_processes)` + предупреждение в консоль, ничего не удаляет и не убивает. Функции ручного разрешения (`resolve_bypass_conflicts_manual`, удаление чужих таблиц, `UserConsent`, `ForeignTable`) удаляются.
  - `check_prerequisites`: вместо nft — `iptables` и `iptables-restore` найдены (`which`), `iptables -w -t mangle -S OUTPUT` успешен; при отсутствии nfqws2 подсказка называет ключ `--nfqws2`.

- [ ] **Step 1: Тесты**

```rust
#[test] fn foreign_queue_chains_are_found_and_ours_are_skipped() {
    let save = "-N nfqws_post\n-N bcw_q\n-A nfqws_post -p tcp -j NFQUEUE --queue-num 300\n\
                -A bcw_q -j NFQUEUE --queue-num 777\n-A nfqws_pre -j NFQUEUE --queue-num 300\n";
    assert_eq!(foreign_queue_chains(save, "bcw"), ["nfqws_post", "nfqws_pre"]);
}
```

`tests/ipt_isolation.rs` — тот же архитектурный барьер, что `nft_isolation.rs`: строки `"iptables"` и `"iptables-restore"` встречаются в `src/` только внутри `src/firewall/ipt.rs`; строки `"nft"` как имени процесса в `src/` нет вовсе.

- [ ] **Step 2:** `cargo test --lib cmd:: && cargo test --test ipt_isolation` — FAIL.
- [ ] **Step 3:** Реализовать; удалить модули nft и все оставшиеся ссылки.
- [ ] **Step 4:** `cargo test --lib --bins && cargo test --test ipt_isolation --test cli && cargo clippy -- -D warnings` — PASS; `grep -rn "nft" src | grep -v -i "nfq"` — пусто (кроме комментариев истории в `UPSTREAM.md`).
- [ ] **Step 5:** Коммит «refactor: соседи по iptables, преflight без nft, nftables удалён».

### Task 6: Android-умолчания

**Files:**
- Modify: `Cargo.toml` (`[[bin]] name = "bcw"`, `path = "src/main.rs"`), `src/main.rs`, `src/config.rs`, `src/cmd/mod.rs` (замок, каталог прогона), `src/cmd/check.rs`, `src/cmd/scan.rs`, `src/cmd/status.rs`, `src/cmd/universal.rs`, `src/system/elevate.rs`, `tests/cli.rs` (`CARGO_BIN_EXE_bcw`)
- Test: `src/config.rs`, `src/cmd/mod.rs`, `tests/cli.rs`

**Interfaces:**
- Produces:
  - `config`: `pub const DEFAULT_NFQWS2: &str = "/data/adb/modules/nfqws2-android/bin/nfqws2";` `pub const DEFAULT_LUA_DIR: &str = "/data/adb/modules/nfqws2-android/lua";` `pub const DEFAULT_WORK_DIR: &str = "/data/adb/bcw";` `pub const DEFAULT_QNUM: u16 = 777;` `#[derive(Debug, Clone)] pub struct Paths { pub nfqws2: PathBuf, pub lua_dir: PathBuf, pub work_dir: PathBuf }`, `pub fn set_paths(Paths)`, `pub fn paths() -> Paths`.
  - `CoreConfig::default()`: `nfqws2_path` из `paths().nfqws2`, `base_qnum` из `qnum()` (умолчание `777`), `nfqws2_uid == 0`, `nfqws2_gid == 0`; поле `zapret_base` удалено; `nfqws2_env().lua == [lua_dir/zapret-lib.lua, lua_dir/zapret-antidpi.lua]`; функции `nfqws2_path(zapret_base)`, `detect_nobody_uid/gid` удалены.
  - CLI (глобальные): `--nfqws2 <PATH>`, `--lua-dir <PATH>`, `--work-dir <PATH>`; ключи `--embedded`, `--no-conflict-cleanup` удалены — `main.rs` всегда вызывает `set_embedded(true)`, `set_auto_yes(true)`, `set_skip_conflict_cleanup(true)` и всегда снимает свои остатки при входе.
  - `cmd`: `pub fn lock_path(work_dir: &Path) -> PathBuf` (= `work_dir/bcw.lock`), `pub fn ensure_work_dir(work_dir: &Path) -> std::io::Result<()>` (`create_dir_all`, права `0700`), `pub fn run_dir() -> PathBuf` (= `work_dir/runs/<chrono_local_prefix()>`, создаётся один раз на процесс через `OnceLock`). Каждое место, где умолчание пути отчёта строилось как `format!("{prefix}_<name>")`, использует `run_dir().join("<name>")` с тем же `<name>` (`check.json`, `scan.json`, `report_vanilla.txt`, `status.json`, `universal.json` и т. д.).
  - `elevate::require_root()`: не root → `eprintln!("bcw требует root: запустите через su -c")`, `exit(2)`; переподъёма через `sudo`/`su` нет.

- [ ] **Step 1: Тесты**

```rust
#[test] fn android_defaults() {
    let c = CoreConfig::default();
    assert_eq!(c.nfqws2_path, DEFAULT_NFQWS2);
    assert_eq!((c.nfqws2_uid, c.nfqws2_gid, c.base_qnum, c.profiles_per_instance), (0, 0, 777, 254));
    assert_eq!(c.chain_prefix, "bcw");
}
#[test] fn nfqws2_env_uses_lua_dir() // lua == [DEFAULT_LUA_DIR/zapret-lib.lua, DEFAULT_LUA_DIR/zapret-antidpi.lua], uid 0
#[test] fn lock_path_is_inside_work_dir() { assert_eq!(lock_path(Path::new("/w")), Path::new("/w/bcw.lock")); }
#[test] fn work_dir_is_created_on_demand() // tempdir/a/b не существует → ensure_work_dir → существует, режим 0o700
```

`tests/cli.rs`: `bare_invocation_prints_help_only` с `CARGO_BIN_EXE_bcw`; новый `embedded_flag_is_gone` — `bcw --embedded status` завершается с ошибкой разбора аргументов (код 2).

- [ ] **Step 2:** `cargo test --lib config:: cmd:: && cargo test --test cli` — FAIL.
- [ ] **Step 3:** Реализовать по интерфейсам; `ensure_work_dir` вызывается в `main.rs` сразу после `require_root()`, до `acquire_instance_lock()`.
- [ ] **Step 4:** `cargo build && test -x target/debug/bcw` и `cargo test --lib --bins && cargo test --test cli` — PASS.
- [ ] **Step 5:** Коммит «feat(android): бинарь bcw, встроенный режим всегда, пути и замок в рабочем каталоге, uid 0, очередь 777».

### Task 7: Удаление ненужного на Android

**Files:**
- Modify: `src/main.rs` (ключи `--via`, `--upgrade`, подкоманда `Completions`, `--alive-via` у `scan`; `--version` печатает версию без сети), `src/cmd/mod.rs` (`ServiceManager`, остановка/запуск zapret2, `stopped_service`), `src/cmd/scan.rs`, `src/cmd/check.rs`, `src/cmd/universal.rs`, `src/cmd/benchmark.rs`, `src/network/mod.rs`
- Delete: `src/network/via.rs`, `src/network/update_check.rs`, `src/cmd/completions.rs`, `scripts/install.sh`; зависимость `clap_complete` из `Cargo.toml`
- Test: `tests/cli.rs`

**Interfaces:**
- Produces: CLI без `--via`, `--alive-via`, `--upgrade`, `completions`; `--reference-via` у `check` остаётся. Поле `CleanupInfo.stopped_service` и функции `restore_service`/`stop_service` удалены.

- [ ] **Step 1: Тест** `removed_flags_are_rejected`: для `["--via","1.2.3.4","status","--domain-list","x"]`, `["--upgrade"]`, `["completions","bash"]`, `["scan","--alive-via","socks5://h:1"]` — запуск не успешен и вывод содержит `error:`; `["--version"]` — успешен, содержит версию из `CARGO_PKG_VERSION`.
- [ ] **Step 2:** `cargo test --test cli` — FAIL.
- [ ] **Step 3:** Удалить по списку, вычистить использования.
- [ ] **Step 4:** `cargo test --lib --bins && cargo test --test cli && cargo clippy -- -D warnings` — PASS.
- [ ] **Step 5:** Коммит «chore(android): убраны via, upgrade, completions, управление службой zapret2».

### Task 8: Свои DoH-резолверы

**Files:**
- Modify: `src/network/doh.rs`, `src/main.rs` (глобальный повторяемый `--doh <SPEC>`)
- Test: `src/network/doh.rs`

**Interfaces:**
- Produces: `DohServer { pub host: String, pub ip: String, pub path: String }` (вместо `&'static str`); `pub fn default_servers() -> Vec<DohServer>` (1.1.1.1/cloudflare-dns.com, 8.8.8.8/dns.google, 9.9.9.9/dns.quad9.net, путь `/dns-query`); `pub fn parse_server(spec: &str) -> Result<DohServer, String>` — `IP` (host = IP) или `IP:HOST`, путь `/dns-query`, IP — IPv4 (`is_ipv4`), HOST — `[A-Za-z0-9.-]+`; `pub fn set_extra_servers(Vec<DohServer>)`; `pub fn servers() -> Vec<DohServer>` — свои первыми, затем умолчания. Все обходы `DOH_SERVERS` идут через `servers()`.

- [ ] **Step 1: Тесты**

```rust
#[test] fn parse_ip_only()  { let s = parse_server("77.88.8.8").unwrap(); assert_eq!((s.ip.as_str(), s.host.as_str(), s.path.as_str()), ("77.88.8.8","77.88.8.8","/dns-query")); }
#[test] fn parse_ip_and_host() { let s = parse_server("77.88.8.8:common.dot.dns.yandex.net").unwrap(); assert_eq!(s.host, "common.dot.dns.yandex.net"); }
#[test] fn rejects_garbage() { for bad in ["", "dns.google", "1.2.3", "1.2.3.4:bad host", "1.2.3.4:a&b"] { assert!(parse_server(bad).is_err(), "{bad}"); } }
#[test] fn extra_servers_go_first() // set_extra_servers([x]) → servers()[0] == x, далее три умолчания
```

- [ ] **Step 2:** `cargo test --lib network::doh` — FAIL.
- [ ] **Step 3:** Реализовать; `main.rs` разбирает `--doh` до любой работы с сетью, ошибка разбора — `exit(2)`.
- [ ] **Step 4:** `cargo test --lib --bins && cargo clippy -- -D warnings` — PASS.
- [ ] **Step 5:** Коммит «feat(dns): ключ --doh для своих резолверов».

### Task 9: Подкоманда `doctor`

**Files:**
- Create: `src/cmd/doctor.rs`
- Modify: `src/cmd/mod.rs` (`pub mod doctor;`), `src/main.rs` (`Command::Doctor` обрабатывается до `require_root()` и без преflight — `doctor` сам и есть проверка)
- Test: `src/cmd/doctor.rs`

**Interfaces:**
- Consumes: `paths()` (Task 6), `doh::servers()`, `doh_resolve` (Task 8), `http_client::marked_tcp_connect(addr, fwmark)`, `control_mark()`, `ProfileMark::new(1)` (Task 1), `SystemNfqws2::probe_sync` (`nfqws2/run.rs`), `foreign_queue_chains` (Task 5), `static_batches`, `ChainNames` (Task 3), `IptRun::restore_test` (Task 2).
- Produces:
  - `#[derive(Serialize)] pub enum Status { Ok, Fail, Unknown }` (`snake_case`); `#[derive(Serialize)] pub struct Check { pub id: String, pub status: Status, pub detail: String }`; `#[derive(Serialize)] pub struct DoctorReport { pub schema: u32 /* 1 */, pub ok: bool, pub checks: Vec<Check> }`; `ok` истинно, если ни одной `Fail`.
  - `pub const KERNEL_OPTIONS: [&str; 7] = ["NETFILTER_XT_TARGET_NFQUEUE", "NETFILTER_XT_MATCH_CONNBYTES", "NETFILTER_XT_TARGET_CONNMARK", "NETFILTER_XT_MATCH_CONNMARK", "NETFILTER_XT_TARGET_CT", "IP_NF_MANGLE", "IP_NF_RAW"];`
  - `pub fn kernel_checks(config: Option<&str>) -> Vec<Check>` — id `kernel:<OPT>`; `CONFIG_<OPT>=y|m` → `Ok`, иначе `Fail`; `None` (нет `/proc/config.gz`) → все `Unknown`.
  - `pub fn busy_queues(procfs: &str) -> Vec<u16>` — номера очередей из первого столбца `/proc/net/netfilter/nfnetlink_queue`.
  - `pub async fn run() -> DoctorReport`, проверки по порядку: `root`; `kernel:*` (`/proc/config.gz` через `gzip -dc` / `zcat`, что найдётся; иначе `Unknown`); `iptables`, `iptables_restore` (найдены); `rules_test` (`restore_test` обоих батчей `static_batches(&ChainNames::new(&chain_prefix()))` — разбор без применения); `nfqws2` (файл есть), `filter_mark` (`probe_sync`), `lua` (два файла в `lua_dir`); `route_control` и `route_profile` — `marked_tcp_connect` к `servers()[i].ip:443` с меткой `control_mark()` и `ProfileMark::new(1).so_mark()`, таймаут 3 с, `Ok` при первом успешном резолвере; `doh` — `doh_resolve("example.com", s)` хотя бы для одного; `neighbours` — всегда `Ok`, `detail` = список `foreign_queue_chains`, `nfqws2 running: <bool>` и занятые очереди (первый столбец `/proc/net/netfilter/nfnetlink_queue`). Без root проверки `iptables*`, `rules_test`, `filter_mark`, `route_*`, `doh`, `neighbours` получают `Unknown` с `detail` «нужен root».
  - Вывод: JSON (`serde_json::to_string_pretty`) в stdout, таблица `id  status  detail` в stderr; код выхода `0` при `ok`, иначе `1`.

- [ ] **Step 1: Тесты**

```rust
#[test] fn kernel_checks_read_y_and_m() {
    let cfg = "CONFIG_NETFILTER_XT_TARGET_NFQUEUE=y\nCONFIG_NETFILTER_XT_MATCH_CONNBYTES=m\n# CONFIG_IP_NF_RAW is not set\n";
    let c = kernel_checks(Some(cfg));
    // NFQUEUE Ok, CONNBYTES Ok, IP_NF_RAW Fail, отсутствующие — Fail; всего 7
}
#[test] fn missing_kernel_config_is_unknown_not_fail() // kernel_checks(None): 7 штук, все Unknown
#[test] fn report_is_ok_only_without_failures()        // Unknown не роняет ok, один Fail роняет
#[test] fn busy_queues_are_read_from_procfs_format() // pub fn busy_queues(procfs: &str) -> Vec<u16>: "  300  12345 0 2 65531 0 0 0  1\n  777 ..." → [300, 777]
#[test] fn report_json_shape() // schema == 1, у checks поля id/status/detail, status сериализуется "ok"/"fail"/"unknown"
```

- [ ] **Step 2:** `cargo test --lib cmd::doctor` — FAIL.
- [ ] **Step 3:** Реализовать.
- [ ] **Step 4:** `cargo test --lib --bins && cargo clippy -- -D warnings` — PASS; `cargo run -- doctor --help` печатает справку.
- [ ] **Step 5:** Коммит «feat(doctor): проверка телефона перед прогоном».

### Task 10: Интеграционный тест на iptables

**Files:**
- Modify: `docker/integration.Dockerfile`, `tests/e2e_infra.rs`, `tests/parallel_benchmark.rs` (только пути и имена API), `.github/workflows/engine.yml` (job `integration`)
- Test: `tests/e2e_infra.rs`

**Interfaces:**
- Consumes: `config::set_paths` (Task 6), `rules::*` (Task 3), `SystemIpt` (Task 2).
- Produces: job `integration`: `actions/checkout` с `submodules: true`; `sudo modprobe nfnetlink_queue xt_NFQUEUE xt_connbytes xt_connmark xt_CONNMARK xt_CT xt_mark iptable_mangle iptable_raw`; `docker build -f docker/integration.Dockerfile -t bcw-it .`; `docker run --rm --privileged bcw-it --test e2e_infra -- --nocapture`.

- [ ] **Step 1:** Dockerfile: пакет `nftables` → `iptables`; после установки `update-alternatives --set iptables /usr/sbin/iptables-legacy` и `update-alternatives --set iptables-restore /usr/sbin/iptables-legacy-restore` (в Ubuntu 24.04 по умолчанию nft-бэкенд); `iptables -V` в слое сборки содержит `legacy`.
- [ ] **Step 2:** В `e2e_infra.rs` общий хелпер `fn e2e_paths()` — `set_paths(Paths { nfqws2: "/opt/zapret2/nfq2/nfqws2".into(), lua_dir: "/opt/zapret2/lua".into(), work_dir: "/tmp/bcw-e2e".into() })`, вызывается первым в каждом тесте; `nft_dispatch_add_remove_rules_on_real_kernel` → `ipt_dispatch_add_remove_rules_on_real_kernel`: `iptables-save` до `prepare_chains` равен `iptables-save` после `drop_chains` (сравнение без строк-комментариев `#` и счётчиков `[n:m]`); `foreign_zapret1_table_survives_our_cleanup` → `foreign_nfqueue_chain_survives_our_cleanup` (чужая цепочка `nfqws_post` с `-j NFQUEUE --queue-num 300` и переходом из `POSTROUTING` остаётся после нашей уборки, а пока наши цепочки стоят — наш переход первый); `nfqws2_receives_marked_traffic`, `autottl_prenat_captures_synack`, `the_mask_is_not_forgotten_and_profiles_are_selective` — на новых API и метках без изменения смысла.
- [ ] **Step 3: Новый тест** `control_probe_skips_foreign_chain`: чужая цепочка `foreign_cnt` в `mangle OUTPUT` (переход вставлен после наших правил: `-A OUTPUT -j foreign_cnt`) с одним правилом `-p tcp --dport 443 -j RETURN`; соединение с меткой `control_mark()` к локальному TLS-слушателю (как в существующих тестах) → счётчик пакетов правила `foreign_cnt` (`iptables -w -t mangle -L foreign_cnt -v -x -n`) равен 0; то же соединение без метки → счётчик > 0.
- [ ] **Step 4:** Локально `docker build -f docker/integration.Dockerfile -t bcw-it . && docker run --rm --privileged bcw-it --test e2e_infra -- --nocapture` — PASS (если хост не даёт модулей — зафиксировать вывод и положиться на CI).
- [ ] **Step 5:** Коммит «test(e2e): интеграция на iptables-legacy, контроль минует чужие цепочки».

### Task 11: Сборка arm64 и документация движка

**Files:**
- Modify: `.github/workflows/engine.yml` (job `build-android`), `engine/UPSTREAM.md` (раздел «Отличия» по задачам 1–10)
- Create: `engine/README.md` (вместо upstream README; upstream README → `engine/README.upstream.md`)

**Interfaces:**
- Produces: артефакт Actions `bcw-aarch64` с файлом `bcw`.

- [ ] **Step 1:** Job `build-android`: `dtolnay/rust-toolchain@stable` с `targets: aarch64-unknown-linux-musl`, `taiki-e/install-action@cross`, `cross build --release --target aarch64-unknown-linux-musl` (в `engine/`), шаг проверки: `file target/aarch64-unknown-linux-musl/release/bcw` содержит `statically linked` и `ARM aarch64`; `actions/upload-artifact` с именем `bcw-aarch64`. UPX не используется.
- [ ] **Step 2:** `engine/README.md`: что это, требования (root через KernelSU, nfqws2 ≥ v1.0.5 — по умолчанию из nfqws2-android), установка (`adb push bcw /data/local/tmp/ && su -c chmod 755 /data/local/tmp/bcw`), ключи Android (`--nfqws2`, `--lua-dir`, `--work-dir`, `--chain-prefix`, `--qnum`, `--doh`, `--mark-desync`, `--mark-profile-shift`), карта битов метки (таблица спеки §3), раздел «Проверка на телефоне» — команды спеки §8.2 дословно, раздел «Скорость» (заполняется по замеру).
- [ ] **Step 3:** Пуш ветки; в Actions зелёные `test`, `integration`, `build-android`; артефакт `bcw-aarch64` скачивается.
- [ ] **Step 4:** Коммит «ci: сборка bcw для aarch64-unknown-linux-musl; README движка».

### Приёмка на телефоне (выполняет владелец)

Не задача для исполнителя: после Task 11 владелец скачивает `bcw-aarch64` и выполняет команды спеки §8.2 (`doctor`, `benchmark -t 15`, `scan | check` на Wi-Fi и мобильной сети при включённом nfqws2-android, `iptables-save` после, `kill -9` + повторный запуск). Вывод присылается в чат; найденные расхождения становятся новыми задачами. Замер скорости записывается в `engine/README.md`. После приёмки — слияние `stage1-engine` в `main`.
