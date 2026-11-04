# Этап 3: поиск стратегий из WebUI — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** вкладка «Поиск» запускает фоновое задание `bcw search run`, которое за ≤ 5 минут подбирает стратегии сужением, собирает пресет `found-*` с ключами `FOUND_*`, назначает его текущей сети, проверяет через обход и откатывает при провале.

**Architecture:** новая библиотечная часть `engine/src/search/` (чистая логика за трейтами `Probe` и `SvcLink`, тестируется подделками) + системная реализация `Probe` поверх `pipeline::{baseline, runner, check}` + команды `bcw search run` и `bcw ctl search …` в `engine/src/cmd/search.rs`. Служба `bcw svc` не меняется; меняется только сборка аргументов nfqws2 (`bypass/args.rs`) — она понимает три новых ключа пресета.

**Tech Stack:** Rust 2021 (tokio, serde_json, clap — уже в `engine/Cargo.toml`), ES-модули WebUI, тесты WebUI на `node` (`module/tests/webui/*.mjs`).

**Spec:** `docs/superpowers/specs/2026-11-04-bcw-search-design.md` — читать вместе с планом; номера § ниже — оттуда.

## Global Constraints

- Только KernelSU, arm64, IPv4; QUIC/UDP не перебираются (спека §1.2).
- Логика — в Rust; WebUI только вызывает `bcw ctl` через `ksu.exec`; аргументы — в `module/webroot/js/commands.js`, значения пользователя после `--`.
- Ответы `bcw ctl` — одна строка JSON с `schema: 1`.
- Воркеров поиска — 254; срок шагов 2–5 — 300 с; `check`: первые 10 по простоте, `passes=3`.
- Порог проверки через обход — `DATA_TRANSFER_MIN_BYTES` (32 768 байт), 2 попытки.
- Ожидание службы после применения — 20 с; `search stop` ждёт выхода задания до 30 с.
- Хранится 10 последних `runs/<id>/`; `id` — `ГГГГММДД-ЧЧММСС` по местному времени телефона.
- Имя пресета — `found-<основа>-<ГГГГММДД-ЧЧММ>`, ≤ 64 символов, только `[A-Za-z0-9_-]`; совпадение → `-2`, `-3`, ….
- Пресеты без `FOUND_*` собираются байт-в-байт как в `v0.1.0`.
- Тесты — только во временных каталогах, с подделками службы, `iptables` и проб; реальные системные пути не трогаются. Не использовать `pkill -f`.
- Сначала падающий тест, потом правка; коммит на каждую задачу; подпись коммита — `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Проверки задачи перед коммитом: `cd engine && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` (для задач WebUI — ещё `for t in module/tests/webui/test_*.mjs; do node "$t"; done`).

## Review Focus

1. Домен из набора с опечаткой / без DNS / заблокирован по IP — пропускается с типом блокировки в итоге, а не роняет поиск (тест в задаче 6).
2. Пустой или из одних комментариев список доменов группы — группа «нет заблокированных», основа не меняется (тест в задаче 6).
3. Основа уже `found-*` (повторный поиск) — прежние `FOUND_*` вычёркиваются, а не дублируются (тест в задаче 4).
4. `user.list` без завершающего перевода строки или с доменом в другом регистре — добавление не склеивает строки и не дублирует домен; откат удаляет только добавленное (тест в задаче 7).
5. Два `search start` подряд / `start` во время доведения отката — второй получает отказ «поиск уже идёт», `undo.json` не перезаписывается (тест в задаче 9).

---

## Карта файлов

| Файл | Ответственность |
|---|---|
| `engine/src/bypass/preset.rs` | ключи `FOUND_YOUTUBE`, `FOUND_TLS`, `FOUND_HTTP`; проверка их токенов |
| `engine/src/bypass/args.rs` | профили из `FOUND_*` в порядке §5 |
| `engine/tests/fixtures/args-v0.1.0/` | эталон аргументов 28 пресетов до правки |
| `engine/src/bypass/store.rs` | списки `search-general`, `search-youtube` |
| `module/defaults/lists/search-*.list` | умолчания наборов |
| `engine/src/search/mod.rs` | общие типы: `Group`, `Proto`, `Block`, `Phase`, `Outcome`, `Found` |
| `engine/src/search/assemble.rs` | текст и имя пресета `found-*` |
| `engine/src/search/runs.rs` | каталог `runs/`, `id`, `state.json`, `undo.json`, хранение 10 |
| `engine/src/search/narrow.rs` | базовая проверка, сужение, `check`, выбор (за трейтом `Probe`) |
| `engine/src/search/apply.rs` | журнал отмены, применение, проверка, частичный успех, откат (за `SvcLink`) |
| `engine/src/search/job.rs` | порядок шагов, срок, «Стоп», смена сети, обход не `running` |
| `engine/src/search/system.rs` | `SystemProbe`, `SystemSvc` — реальные пробы и сокет службы |
| `engine/src/cmd/search.rs` | `bcw search run`, `bcw ctl search …`, доведение отката |
| `engine/src/main.rs`, `engine/src/cmd/ctl.rs` | подкоманды CLI |
| `module/webroot/js/search.js`, `commands.js`, `app.js`, `strategies.js` | вкладка «Поиск», ключи `FOUND_*` в редакторе |
| `module/tests/webui/test_search.mjs`, `test_commands.mjs`, `test_strategies.mjs`, `module/tests/ctl-samples/search*.json` | тесты WebUI |
| `module/README.md`, `module/changelog.md` | приёмка этапа 3 |

---

### Task 1: Ключи `FOUND_*` в пресете и их проверка

**Files:**
- Modify: `engine/src/bypass/preset.rs` (структура `Preset`, `parse_preset`)
- Test: там же, `mod tests`

**Interfaces:**
- Produces: поля `Preset { found_youtube: String, found_tls: String, found_http: String }` (сырые, как остальные); `pub fn check_found(value: &str) -> Result<(), String>`; `pub const FOUND_KEYS: [&str; 3] = ["FOUND_YOUTUBE", "FOUND_TLS", "FOUND_HTTP"]`.

- [ ] **Step 1: Падающие тесты**
  - `found_keys_parsed`: пресет с `FOUND_TLS="--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls"` → `p.found_tls` равно этой строке, `found_youtube`/`found_http` пустые.
  - `found_absent_is_empty`: `parse_preset(include_str!("../../../module/strategies/alt.conf"))` → все три поля пустые.
  - `check_found_rejects`: `check_found` возвращает `Err` для каждой из строк `"--new"`, `"--filter-tcp=443"`, `"--hostlist=/x"`, `"--hostlist-exclude=/x"`, `"--ipset=/x"`, `"--qnum=1"`, `"--user=root"`, `"--debug=1"`, `"--lua-init=@x"`, `"fake"` (токен без `--`); `Ok` для `""` и для первой строки из `report_vanilla` владельца `--payload=tls_client_hello --lua-desync=tcpseg:pos=0,midsld:ip_id=rnd:repeats=20`.
  - `parse_rejects_bad_found`: пресет с `FOUND_TLS="--new"` → `parse_preset` возвращает `PresetError` с номером строки ключа.
- [ ] **Step 2:** `cd engine && cargo test --lib bypass::preset` — FAIL (нет полей/функции).
- [ ] **Step 3:** добавить поля и `check_found`; `parse_preset` вызывает `check_found` для каждого `FOUND_*`. Запрещённые префиксы — ровно список из `check_found_rejects` (`--filter-` и `--hostlist`/`--ipset` — по префиксу).
- [ ] **Step 4:** тот же запуск — PASS; весь `cargo test` — PASS.
- [ ] **Step 5:** коммит `feat(preset): ключи FOUND_* и проверка их токенов`.

### Task 2: Профили `FOUND_*` в аргументах nfqws2

**Files:**
- Create: `engine/tests/fixtures/args-v0.1.0/<пресет>.txt` (28 файлов), `engine/tests/args_golden.rs`
- Modify: `engine/src/bypass/args.rs:86-139`

**Interfaces:**
- Consumes: поля `Preset::found_*` (задача 1).
- Produces: `build()` без изменения сигнатуры.

- [ ] **Step 1: Эталон до правки.** Тест `args_golden` с переменной `UPDATE_GOLDEN=1` записывает, без неё — сверяет: для каждого `module/strategies/*.conf` `build()` при `Settings::default()`, `Layout { module_dir: "/m", data_dir: "/d" }`, `ipset_nonempty` в двух вариантах (`true`/`false`), `calls_conf = ""` — строки через `\n`. Запустить `UPDATE_GOLDEN=1 cargo test --test args_golden`, затем без переменной — PASS. Коммит `test(args): эталон аргументов 28 пресетов v0.1.0`.
- [ ] **Step 2: Падающие тесты** в `args.rs`:
  - `found_order`: пресет `alt` + все три `FOUND_*` = `"--lua-desync=Y"`, `"--lua-desync=T"`, `"--lua-desync=H"`, `ipset_nonempty=true`, `calls_bypass=false` → в `normalize(build())` профили (разделитель `--new`) идут так: `[база+] YouTube`, `CUSTOM`-профили `alt`, UDP, QUIC (ipset), QUIC (режим), `T`+ipset, `T`+режим, `H`+ipset, `H`+режим, `NFQWS_ARGS`+ipset, `NFQWS_ARGS`+режим (последний без `--new` в конце).
  - `found_youtube_profile`: профиль YouTube = `--filter-tcp=443 --filter-l7=tls --hostlist=/m/lists/youtube.list --hostlist-exclude=/d/lists/exclude.list --lua-desync=Y` (с раскрытием `$LISTS_DIR`: файл данных, если есть, иначе модуля — как `expand`).
  - `found_tls_profile`/`found_http_profile`: начинаются с `--filter-tcp=443 --filter-l7=tls` / `--filter-tcp=80 --filter-l7=http`, вариант режима оканчивается аргументами `$MODE_AUTO` при `MODE=auto`.
  - `found_empty_no_profile`: пустой `FOUND_HTTP` → профиля с `--filter-tcp=80 --filter-l7=http` нет.
- [ ] **Step 3:** `cargo test --lib bypass::args` — FAIL.
- [ ] **Step 4:** в `build()` вставить: после блока звонков — профиль YouTube; после QUIC и до `NFQWS_ARGS` — `FOUND_TLS`, `FOUND_HTTP` по образцу `tcp` (ipset-вариант при непустом ipset, затем вариант с `extra`, каждый с `--new`).
- [ ] **Step 5:** `cargo test` — PASS, включая `args_golden` без переменной (пресеты без `FOUND_*` не изменились).
- [ ] **Step 6:** коммит `feat(args): профили FOUND_* в порядке спеки §5`.

### Task 3: Списки наборов доменов

**Files:**
- Create: `module/defaults/lists/search-general.list`, `module/defaults/lists/search-youtube.list`
- Modify: `engine/src/bypass/store.rs:14` и `init_data_dir`, `list_path`

**Interfaces:**
- Produces: `pub const SEARCH_LIST_NAMES: [&str; 2] = ["search-general", "search-youtube"]`; `Store::read_list/write_list/list_path` принимают имена из обоих массивов; `CtlCmd::Lists` по-прежнему перечисляет только `LIST_NAMES`.

- [ ] **Step 1: Падающие тесты** (`store.rs`, временный каталог):
  - `search_lists_seeded`: `init_data_dir()` создаёт `search-general.list` с ровно `rutracker.org\ndiscord.com\nx.com\ninstagram.com\n` и `search-youtube.list` с `www.youtube.com\ni.ytimg.com\nredirector.googlevideo.com\n`; существующий файл не перезаписывается.
  - `search_list_rw`: `write_list("search-youtube", "a.com\n")`, затем `read_list` → `"a.com\n"`; `list_path("nope")` → `Err`.
  - в `ctl.rs` `lists_hides_search`: ответ `CtlCmd::Lists` не содержит `search-general`.
- [ ] **Step 2:** `cargo test` — FAIL.
- [ ] **Step 3:** файлы умолчаний (содержимое — из теста), константа, правка проверок имени.
- [ ] **Step 4:** `cargo test` — PASS; `bash module/tests/test_refs.sh` — PASS (если проверяет состав `defaults/`, дополнить).
- [ ] **Step 5:** коммит `feat(store): списки search-general и search-youtube`.

### Task 4: Общие типы и сборка пресета `found-*`

**Files:**
- Create: `engine/src/search/mod.rs`, `engine/src/search/assemble.rs`
- Modify: `engine/src/lib.rs` (`pub mod search;`)

**Interfaces:**
- Produces (в `search/mod.rs`, все `serde::{Serialize, Deserialize}`, `rename_all = "snake_case"`):
  - `enum Group { General, Youtube }`; `enum Proto { Tls13, Tls12, Http }` + `fn to_protocol(self) -> config::Protocol`;
  - `struct Found { youtube: Option<String>, tls: Option<String>, http: Option<String> }`;
  - `enum Outcome { Applied, Partial { failed: Group }, RolledBack { reason: String }, NotFound, Stopped, NetworkChanged, SavedNotApplied { state: String } }`.
- Produces (в `assemble.rs`):
  - `pub fn preset_name(base: &str, at: NaiveStamp, taken: &dyn Fn(&str) -> bool) -> String`, где `struct NaiveStamp { y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32 }` (местное время, считает вызывающий — через смещение `date +%z`, как журнал службы);
  - `pub fn preset_text(base_text: &str, found: &Found, header: &str) -> String`.

- [ ] **Step 1: Падающие тесты** (`assemble.rs`):
  - `name_basic`: `preset_name("alt", 2026-11-04 19:46:20, |_| false)` → `"found-alt-20261104-1946"`.
  - `name_suffix`: занято `found-alt-20261104-1946` и `…-2` → `"found-alt-20261104-1946-3"`.
  - `name_truncates`: основа из 70 символов `a` → длина результата 64, оканчивается на `-20261104-1946`, `valid_strategy_name` → true.
  - `text_keeps_base`: текст `alt.conf` + `Found { tls: Some("--lua-desync=T"), .. }` → результат начинается с текста основы без изменений, заканчивается блоком `# <header>\nFOUND_YOUTUBE=""\nFOUND_TLS="--lua-desync=T"\nFOUND_HTTP=""\n`, `parse_preset` результата → `found_tls == "--lua-desync=T"`.
  - `text_replaces_old_found`: основа, уже содержащая `FOUND_TLS="--old"` (многострочный вариант тоже), → в результате ровно одно присваивание `FOUND_TLS`, со значением новой строки.
- [ ] **Step 2:** `cargo test --lib search::assemble` — FAIL.
- [ ] **Step 3:** реализовать; вычёркивание прежних `FOUND_*` — по границам присваивания, как их находит `parse_preset` (включая многострочные значения).
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** коммит `feat(search): типы и сборка пресета found-*`.

### Task 5: Каталог прогонов, состояние и журнал отмены

**Files:**
- Create: `engine/src/search/runs.rs`
- Modify: `engine/src/bypass/layout.rs` (`pub fn runs_dir(&self) -> PathBuf` = `data_dir/runs`)

**Interfaces:**
- Produces:
  - `struct State { schema: u32 /*1*/, id: String, pid: u32, phase: Phase, done: u64, total: u64, elapsed_s: u64, domains: Vec<DomainState>, outcome: Option<Outcome>, found: Found, network_title: Option<String>, base: String }`, `enum Phase { Prepare, Baseline, Narrow { group: Group }, Check { group: Group }, Apply, Verify, Rollback, Done }`, `struct DomainState { group: Group, domain: String, block: Option<String>, left: Option<u64> }`;
  - `struct Undo { network_key: String, prev_strategy: Option<String>, network_title: String, prev_net_strategy: bool, preset: String, added_user_lines: Vec<String>, finished: bool }`;
  - `pub fn new_id(at: &NaiveStamp) -> String`; `pub fn write_state(dir: &Path, s: &State) -> io::Result<()>` (через `system::atomic::write_atomic`); `pub fn read_state(dir) -> Option<State>`; то же для `Undo` (`undo.json`); `pub fn latest(runs: &Path) -> Option<PathBuf>`; `pub fn list(runs) -> Vec<State>` (новые первыми); `pub fn prune(runs, keep: usize)`.

- [ ] **Step 1: Падающие тесты:** `id_format` (`20261104-194620`); `state_roundtrip` и `undo_roundtrip` через временный каталог; `latest_and_list_order` (три каталога → `latest` — наибольший `id`, `list` — по убыванию); `prune_keeps_10` (12 каталогов → остаются 10 новейших); `read_state_garbage` (битый JSON → `None`, не паника).
- [ ] **Step 2:** FAIL. **Step 3:** реализовать. **Step 4:** PASS.
- [ ] **Step 5:** коммит `feat(search): каталог runs, state.json и undo.json`.

### Task 6: Базовая проверка, сужение, `check` и выбор

**Files:**
- Create: `engine/src/search/narrow.rs`

**Interfaces:**
- Consumes: `Group`, `Proto`, `Found`, `DomainState` (задачи 4–5).
- Produces:
  - `enum Block { NotBlocked, Sni, Throttled, Skip(String) }` — `Skip` несёт имя `BlockType` (`ip_blocked`, `dns_failed`, …);
  - `struct Confirmed { args: String, full: usize, total: usize, median_share: Option<f64>, simplicity: (usize, u32, bool) }`;
  - `trait Probe { async fn classify(&self, domain: &str, p: Proto) -> Block; async fn sweep(&self, domain: &str, p: Proto, cands: &[String], data: bool, progress: &dyn Fn(u64)) -> Vec<String>; async fn confirm(&self, domains: &[(String, Proto)], cands: &[String]) -> Vec<Confirmed>; }` (`confirm` возвращает по стратегии минимум по доменам: `full` — сколько проходов из `total` дали полную доставку на худшем домене);
  - `struct Corpus { tls13: Vec<String>, tls12: Vec<String>, http: Vec<String> }` (из `strategy::generator`);
  - `pub async fn search_group<P: Probe>(p: &P, group: Group, domains: &[String], corpus: &Corpus, ctl: &dyn Control) -> GroupResult`, где `struct GroupResult { domains: Vec<DomainState>, tls: Option<String>, http: Option<String> }`, `trait Control { fn stopped(&self) -> bool; fn expired(&self) -> bool; fn report(&self, d: &[DomainState], done: u64, total: u64); }`;
  - `pub fn pick(c: &[Confirmed]) -> Option<String>`.

- [ ] **Step 1: Падающие тесты** с `FakeProbe` (таблица «домен → протокол → Block» и множество «домен/протокол → проходящие стратегии»):
  - `skip_unblocked_and_ip`: домены `NotBlocked` и `Skip("ip_blocked")` не попадают в `sweep`, их `DomainState.block` = `"not_blocked"` / `"ip_blocked"`.
  - `empty_group`: пустой список доменов (и список из одних `# …`, отфильтрованный вызывающим) → `GroupResult { tls: None, http: None }`, `sweep` не вызывался.
  - `narrow_order`: домены `a` (TLS 1.3 и 1.2 `Sni`), `b` (TLS 1.3 `Sni`) → вызовы `sweep` строго: `a/tls13` со всеми 4 330 (размер `corpus.tls13`), `a/tls12` только с прошедшими предыдущий, `b/tls13` только с прошедшими обе ступени.
  - `tls12_only`: TLS 1.3 нигде не заблокирован, `a/tls12` `Sni` → первый `sweep` — весь `corpus.tls12`.
  - `throttled_uses_data`: домен `Throttled` → `sweep(..., data = true, ..)`, `Sni` → `data = false`.
  - `empty_stage_stops`: после ступени не осталось стратегий → дальнейших `sweep` нет, `tls: None`.
  - `check_top10`: из 30 прошедших в `confirm` попадают 10 самых простых по `rank::simplicity_key`, домены — все заблокированные группы.
  - `http_chain`: HTTP заблокирован только у `b` → отдельная цепочка по `corpus.http`, результат в `http`; для `Group::Youtube` HTTP не проверяется вовсе (`classify(_, Http)` не вызывается).
  - `pick_rules`: `full = 0` отбрасывается; из `(3/3, 0.9)` и `(3/3, 0.8)` выбирается `0.9`; при равенстве — проще; пусто → `None`.
  - `stop_and_expiry`: `Control::stopped()` → после текущей ступени выход с тем, что есть, без `confirm`; `expired()` во время сужения → `confirm` только того, что уже прошло хоть одну полную ступень; `expired()` после `confirm` → `pick` по подтверждённому.
- [ ] **Step 2:** `cargo test --lib search::narrow` — FAIL.
- [ ] **Step 3:** реализовать алгоритм спеки §4 п. 2–5; порядок доменов — как в списке; ранжирование `pick` — `full/total` по убыванию, затем `median_share` (`None` ниже любого числа), затем `simplicity` по возрастанию.
- [ ] **Step 4:** PASS. **Step 5:** коммит `feat(search): сужение, check и выбор`.

### Task 7: Применение, проверка через обход, откат

**Files:**
- Create: `engine/src/search/apply.rs`

**Interfaces:**
- Consumes: `Store` (`bypass/store.rs`), `Undo`, `runs::{write_undo, read_undo}`, `assemble::preset_text`, `Outcome`, `Group`.
- Produces:
  - `trait SvcLink { async fn status(&self) -> Option<Status>; async fn reload(&self) -> Result<(), String>; }` (`Status` — `bypass::supervisor::Status`);
  - `trait Verifier { async fn through_bypass(&self, domain: &str, p: Proto) -> bool; }`;
  - `pub struct Plan { pub dir: PathBuf, pub network_key: String, pub network_title: String, pub preset: String, pub text: String, pub general_blocked: Vec<String>, pub checks: Vec<(Group, String, Proto)>, pub enable_net_strategy: bool }`;
  - `pub async fn apply<S: SvcLink, V: Verifier>(store: &Store, svc: &S, v: &V, plan: &Plan, wait: Duration) -> Outcome`;
  - `pub async fn rollback<S: SvcLink>(store: &Store, svc: &S, dir: &Path) -> Result<(), String>` (по `undo.json`, идемпотентно, ставит `finished: true`).

- [ ] **Step 1: Падающие тесты** (временный каталог данных + `FakeSvc` со сценарием ответов `status()` + `FakeVerifier` с таблицей):
  - `undo_written_first`: `undo.json` существует и содержит прежнее состояние до первого изменения `networks.tsv` (проверка через `FakeSvc::reload`, который читает каталог).
  - `apply_ok`: служба отвечает `running` с `strategy == preset`, все проверки `true` → `Outcome::Applied`; в `networks.tsv` сеть → пресет; пресет сохранён; `undo.finished == true`.
  - `user_list_add_exact`: `user.list` = `"a.com"` (без `\n`, режим `auto`), `general_blocked = ["A.com", "rutracker.org"]` → `user.list` = `"a.com\nrutracker.org\n"`, `undo.added_user_lines == ["rutracker.org"]`; при `MODE=all` файл не меняется.
  - `net_strategy_on`: `enable_net_strategy = true`, было `NET_STRATEGY=0` → после применения `1`; после `rollback` — снова `0`.
  - `svc_fallback_is_failure`: служба отвечает `running`, но `strategy == "default"` (откат к `last_good`) до истечения `wait` → полный откат, `Outcome::RolledBack`.
  - `partial`: проверки группы YouTube `true`, General `false` → пресет пересохранён с пустыми `FOUND_TLS`/`FOUND_HTTP`, второй `reload`, повторная проверка YouTube `true` → `Outcome::Partial { failed: General }`.
  - `partial_then_fail`: повторная проверка тоже `false` → `Outcome::RolledBack`.
  - `rollback_restores`: после отката `networks.tsv` побайтно равен исходному (и в случае «записи не было» — записи нет), пресет удалён, `user.list` побайтно исходный, ещё один `rollback` — без ошибок и изменений.
- [ ] **Step 2:** FAIL. **Step 3:** реализовать спеку §6 п. 2–6; проверка группы — все её `checks` `true` (в `FakeVerifier` и в системной реализации — 2 попытки). **Step 4:** PASS.
- [ ] **Step 5:** коммит `feat(search): применение, проверка и откат`.

### Task 8: Порядок шагов задания

**Files:**
- Create: `engine/src/search/job.rs`

**Interfaces:**
- Consumes: `narrow::search_group`, `apply::{apply, rollback, Plan}`, `assemble::*`, `runs::*`.
- Produces: `pub struct JobInput { pub id: String, pub base: String, pub enable_net_strategy: bool, pub budget: Duration /*300 с*/, pub now: NaiveStamp }`; `pub async fn run_job<P: Probe, S: SvcLink, V: Verifier>(store: &Store, p: &P, svc: &S, v: &V, input: JobInput, stop: Arc<AtomicBool>) -> Result<State, String>` (`Err` — отказ до шага 1).

- [ ] **Step 1: Падающие тесты** (подделки задач 6–7):
  - `no_network`: `status().network_key == Some("offline")` или служба не отвечает → `Err("нет сети")`, ничего не записано, кроме `state.json`.
  - `both_groups_found`: обе группы нашли → `Found` заполнен, `apply` вызван, `outcome == Applied`, `state.json` на диске — с `Phase::Done`.
  - `nothing_found`: обе группы пусты → `NotFound`, `apply` не вызван, пресет не сохранён.
  - `network_changed`: ключ сети перед применением другой → `NetworkChanged`, пресет не сохранён.
  - `not_running`: состояние службы `paused_home` → пресет сохранён, `networks.tsv` не тронут, `SavedNotApplied { state: "paused_home" }`.
  - `stop_before_apply`: `stop` поднят во время сужения → `Stopped`, ничего не сохранено.
  - `stop_during_apply`: `stop` поднят после записи `undo.json` → полный откат, `Stopped`.
  - `budget`: подделка `Probe` двигает подделку часов; по истечении `budget` берётся подтверждённое (через `Control::expired`).
  - `progress_written`: во время сужения `state.json` содержит `Phase::Narrow`, растущее `done`, `domains` с типами блокировки.
- [ ] **Step 2:** FAIL. **Step 3:** реализовать; часы — через `trait Clock { fn now(&self) -> Instant; }` с системной реализацией по умолчанию. **Step 4:** PASS.
- [ ] **Step 5:** коммит `feat(search): задание поиска — шаги, срок, стоп, смена сети`.

### Task 9: Системные пробы и команды CLI

**Files:**
- Create: `engine/src/search/system.rs`, `engine/src/cmd/search.rs`
- Modify: `engine/src/main.rs` (скрытая `Command::Search { Run { --id, --base, --enable-net-strategy } }`), `engine/src/cmd/ctl.rs` (`CtlCmd::Search { action: SearchAction }`, `enum SearchAction { Start { #[arg(long)] enable_net_strategy: bool, base: Option<String> /*позиционный, после --*/ }, Status, Stop, Runs, Report { id: String } }`), `engine/src/cmd/mod.rs`
- Create: `module/tests/ctl-samples/searchStart.json`, `searchStatus.json`, `searchRuns.json`, `searchReport.json`
- Modify: `module/tests/webui/argv.json` (новые команды)

**Interfaces:**
- Consumes: всё из задач 4–8; `pipeline::baseline::test_baseline`, `pipeline::runner::run_parallel` (`RunParams { workers: 254 через CoreConfig, mode, deadline, completed }`), `pipeline::check::run_check`, `network::dns::resolve_domain` (режим `doh`, как во встроенном режиме), `firewall::rules::prepare_chains`, `cmd::check_prerequisites`, `bypass::ipc::call`, `network::http_client::http_test_data` с `so_mark = 0` для `Verifier`.
- Produces: `SystemProbe`, `SystemSvc`, `SystemVerifier`; JSON ответов (все с `schema: 1`):
  - `search start` → `{"ok":true,"id":"20261104-194620"}`; отказ — `{"ok":false,"error":"поиск уже идёт"}` / `"нет сети"` / `"нет стратегии <имя>"`;
  - `search status` → `{"ok":true,"state":<State>|null,"recovered":<bool>}`;
  - `search stop` → `{"ok":true,"stopped":<bool>}`; `search runs` → `{"ok":true,"runs":[{id,time,network_title,outcome}]}`; `search report <id>` → `{"ok":true,"state":<State>}`.

- [ ] **Step 1: Падающие тесты** (в `cmd/search.rs`, временный каталог, подделка запуска процесса `trait Spawn { fn spawn(&self, args: &[String], log: &Path) -> io::Result<u32>; }` и проверки живости `fn alive(pid: u32) -> bool`):
  - `start_spawns_detached`: `start` пишет начальный `state.json`, вызывает `Spawn` с `["search","run","--id",<id>,"--base",<base>]`, удаляет прогоны сверх 10.
  - `start_refuses_running`: живое задание (`alive(pid) == true`) → `"поиск уже идёт"`, `undo.json` прежнего прогона не изменён (Review Focus 5).
  - `start_default_base`: без `--base` берётся стратегия сети из `networks.tsv` при `NET_STRATEGY=1`, иначе `DEFAULT_STRATEGY`.
  - `status_recovers`: последнее задание мертво, `undo.json` с `finished: false` → выполнен `rollback`, `recovered: true`, `outcome` — `RolledBack { reason: "поиск прервался посреди применения" }`.
  - `stop_signals_group`: `stop` шлёт `SIGTERM` группе `-pid` через подделку и ждёт `alive == false` до 30 с (подделка часов).
  - `webui_argv_parses` (существующий): новые строки `argv.json` разбираются clap; образцы `ctl-samples` сверяются (`UPDATE_SAMPLES=1` переписывает).
- [ ] **Step 2:** FAIL. **Step 3:** реализовать. `bcw search run`: `setsid` делает `ctl` (через `std::os::unix::process::CommandExt::process_group(0)` + `pre_exec(setsid)`), вывод — `runs/<id>/job.log`; в задании `SIGTERM` поднимает `stop` (а не выход через `spawn_cleanup_handler`), цепочки `bcw_*` снимаются по выходу и в panic-хуке, как в `main`. Замок `bcw.instance` берёт `search run` (`cmd::acquire_instance_lock`).
- [ ] **Step 4:** `cargo test` — PASS; `cargo build --release --target aarch64-unknown-linux-musl` через `cross` — как в `module.yml`.
- [ ] **Step 5:** коммит `feat(cmd): bcw search run и bcw ctl search`.

### Task 10: Ключи `FOUND_*` в редакторе стратегий

**Files:**
- Modify: `module/webroot/js/strategies.js:6-80`
- Test: `module/tests/webui/test_strategies.mjs`

**Interfaces:**
- Produces: `KEYS` дополнен `FOUND_YOUTUBE`, `FOUND_TLS`, `FOUND_HTTP` с подписями «Найдено: YouTube», «Найдено: TLS», «Найдено: HTTP»; поля `FOUND_*` показываются, только если в пресете хотя бы одно непустое.

- [ ] **Step 1: Падающие тесты:** `roundtrip_found` — разбор текста с `FOUND_TLS="--lua-desync=T"` и обратная сборка сохраняют значение; `found_hidden` — для `alt.conf` полей `FOUND_*` в разметке нет; существующий `editor-roundtrip.conf` проходит без изменений.
- [ ] **Step 2:** `node module/tests/webui/test_strategies.mjs` — FAIL. **Step 3:** реализовать. **Step 4:** все `test_*.mjs` — PASS.
- [ ] **Step 5:** коммит `feat(webui): FOUND_* в редакторе стратегий`.

### Task 11: Вкладка «Поиск»

**Files:**
- Create: `module/webroot/js/search.js`, `module/tests/webui/test_search.mjs`
- Modify: `module/webroot/js/commands.js`, `module/webroot/js/app.js` (регистрация вкладки после «Состояние»), `module/webroot/css/*` при необходимости, `module/tests/webui/test_commands.mjs`

**Interfaces:**
- Consumes: ответы задачи 9; `cmd.listGet/listSet`, `cmd.settingsGet`, `cmd.status`, `cmd.strategies`, загрузка через `upload begin|chunk|end` (как в `lists.js`).
- Produces: `cmd.searchStart(base, enableNet) => ['search','start', ...(enableNet?['--enable-net-strategy']:[]), '--', base]`; `cmd.searchStatus`, `cmd.searchStop`, `cmd.searchRuns`, `cmd.searchReport(id) => ['search','report','--',id]`; `export function renderState(state): string` и `export function outcomeText(outcome): string` (чистые функции для тестов).

- [ ] **Step 1: Падающие тесты** (`test_search.mjs` по образцам `ctl-samples/search*.json`):
  - `outcomeText` для каждого варианта `Outcome` даёт ровно: «Применено и проверено», «Применено частично: не подошло — <Общие|YouTube>», «Откат: <reason>», «Не найдено», «Остановлено», «Сеть сменилась — найденное не применено», «Сохранено, не применено: обход <state>».
  - `renderState` для `Phase::Narrow` показывает «сделано/всего», время `m:ss / 5:00`, по строке на домен с типом блокировки и остатком; для `Applied` — текст «Откройте видео в YouTube…» и найденные строки в `<pre>`.
  - при `NET_STRATEGY=0` нажатие «Найти» без согласия не вызывает `searchStart`; с согласием — вызывает с `--enable-net-strategy`.
  - `test_commands.mjs`: новые команды совпадают с `argv.json`.
- [ ] **Step 2:** FAIL. **Step 3:** реализовать по спеке §7.2; опрос `search status` раз в 1 с, пока `outcome == null`; остановка опроса при уходе с вкладки. **Step 4:** все `test_*.mjs` и `cargo test` (`webui_argv_parses`) — PASS.
- [ ] **Step 5:** коммит `feat(webui): вкладка «Поиск»`.

### Task 12: Приёмка, документация, сборка

**Files:**
- Modify: `module/README.md` (раздел «Приёмка этапа 3», шаги 1–6 спеки §8), `module/changelog.md`

- [ ] **Step 1:** описать шаги приёмки командами Termux (`su -c '…'`) и действиями в WebUI; шаг 5 (откат на телефоне): временно заменить список «Общие» на один домен, который поиск находит, но обход не открывает — **если такой домен не найдётся на приёмке, шаг пропускается с пометкой, откат покрыт тестами задачи 7**.
- [ ] **Step 2:** push ветки, CI `engine` и `module` зелёные (ссылки на запуски — в отчёт владельцу).
- [ ] **Step 3:** владелец ставит zip из артефакта CI и проходит приёмку по одному шагу; итоги — в README.
- [ ] **Step 4:** независимый обзор кода всей ветки, исправления (падающий тест → правка).
- [ ] **Step 5:** с согласия владельца — PR в `main`, версия `v0.2.0` (`module.prop` `version=v0.2.0`, `versionCode=200`, `update.json`), тег — способом, который выберет владелец.
