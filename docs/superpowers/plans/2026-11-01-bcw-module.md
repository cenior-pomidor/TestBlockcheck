# Этап 2. Модуль обхода `bcw` — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Модуль KernelSU `bcw`, который вместо nfqws2-android обходит DPI на Pixel 9 Pro, с логикой в Rust (`bcw svc`, `bcw ctl`) и WebUI.

**Architecture:** В крейт `engine` добавляется модуль `bypass` (пресеты, настройки, порты, командная строка nfqws2, правила `dpi_*`, сеть, данные, журналы, супервизор, IPC). Подкоманды `bcw svc` и `bcw ctl` строятся поверх него. Каталог `module/` — файлы модуля KernelSU и WebUI (HTML/JS без сборки, ES-модули). Веха 2а — задачи 1–16, приёмка из Termux. Веха 2б — задачи 17–21, WebUI и релиз.

**Tech Stack:** Rust (tokio, serde_json, clap — уже в `engine/Cargo.toml`), iptables-legacy через `iptables-restore`, POSIX sh (скрипты модуля), JavaScript в WebView (ES-модули), Node 22 (тесты WebUI), GitHub Actions (cross, Android NDK).

**Spec:** `docs/superpowers/specs/2026-11-01-bcw-module-design.md`

## Global Constraints

- Только KernelSU и arm64; `bcw` — `aarch64-unknown-linux-musl`, статический.
- id модуля `bcw`; `MODULE_DIR=/data/adb/modules/bcw`; `DATA_DIR=/data/adb/bcw`.
- Очередь обхода — `300`, всегда. Поиск — очередь `777` и цепочки `bcw_*`; их не трогать.
- Цепочки обхода: `dpi_post`, `dpi_pre` (mangle), `dpi_nat` (nat), `dpi_mquic` (filter). Только IPv4 (`iptables`).
- Метки: `0x40000000/0x40000000` — обработано nfqws2; connmark `0x80000000/0x80000000` — `NAT_FIX`. Изоляция от поиска: `-m mark ! --mark 0x0/0x3FE00000 -j RETURN` и `-m connmark ! --mark 0x0/0x00200000 -j RETURN`.
- Правила ставятся только транзакцией `iptables-restore --noflush -w` (`engine/src/firewall/ipt.rs`).
- Сокет службы — абстрактный unix `bcw.svc`. Замок поиска `bcw.instance` служба не берёт.
- Ответ `ctl`: JSON `{"schema":1,"ok":true,…}` / `{"schema":1,"ok":false,"error":"<по-русски>"}`.
- Эталон поведения — nfqws2-android v2.0.4, коммит `8e916c8`. Клон для эталонов: `/tmp/src_nfq/nfqws2-android`; скрипты сами клонируют его на этот коммит, если клона нет.
- nfqws2 и Lua — zapret2 коммит `f924d796b49da9e455c6bb09268298ef1471cd74` с патчами `001-tls-reasm-fastpath.patch` и `libnetfilter_queue-android.patch`.
- Интерфейс только на русском; без внешних загрузок; тема — `prefers-color-scheme`.
- Взятое из оригинала помечается в `module/NOTICE.md` (файл, автор, лицензия или её отсутствие).
- Окончание каждого коммита:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` и
  `Claude-Session: https://claude.ai/code/session_01Baqyxr5urRqCErFcq7qWA7`.

## Review Focus

1. **Необычный SSID** (кавычки, пробелы, кириллица, эмодзи, `<unknown ssid>`, пустой). Ключ сети — как у `current_network_key` оригинала, подпись — исходный текст; `<unknown ssid>` и пустой считаются «не Wi-Fi». Тест — задача 8.
2. **Дребезг сети** (Wi-Fi ↔ мобильная за секунды, нет маршрута наружу). Перезапуск только после двух одинаковых опросов подряд; без маршрута — ничего не делать. Тест — задача 11.
3. **Перезапуск обхода во время поиска.** Переходы `dpi_*` встают после переходов `bcw_*`, `ensure_order` поиска после этого изоляцию не нарушает. Тест — задачи 6 и 7.
4. **Испорченные данные** (мусорная строка в `settings.conf`, битая строка `networks.tsv`, перекрытие пресета с ошибкой синтаксиса). Служба не падает: строка → умолчание и запись в журнал; плохой пресет → ошибка в `ctl` и откат к `DEFAULT_STRATEGY`. Тест — задачи 3 и 9.
5. **Портов больше 15 на `multiport`** (`AUTO_PORTS` при многих фильтрах, `CALLS_BYPASS`). Список режется на правила по весу ≤ 15 (диапазон весит 2), транзакция проходит. Тест — задачи 4 и 6.

---

## Устройство файлов

```
engine/src/bypass/
  mod.rs         — pub mod …; константы MODULE_DIR, DATA_DIR, QNUM=300
  layout.rs      — Layout: пути модуля и данных
  preset.rs      — разбор .conf → Preset
  settings.rs    — Settings: умолчания, разбор, проверка set
  ports.rs       — PortList: add/without/auto, разбиение на multiport
  args.rs        — командная строка nfqws2 (порядок _startup_args)
  rules.rs       — батчи dpi_*, apply/remove, позиция переходов
  network.rs     — разбор cmd wifi / dumpsys / getprop, ключ сети, decide()
  store.rs       — данные: списки, перекрытия пресетов, сети, домашние Wi-Fi
  logs.rs        — журналы: запись, обрезка, чтение, статистика
  supervisor.rs  — состояния, сторож, откат, сеть (без ввода-вывода)
  ipc.rs         — запрос/ответ по bcw.svc
  system.rs      — боевые реализации трейтов супервизора
engine/src/cmd/svc.rs, engine/src/cmd/ctl.rs — подкоманды
engine/tests/bypass_e2e.rs                    — правила на реальном ядре
engine/tests/fixtures/bypass/                 — эталоны и их генератор
module/                                       — модуль (задачи 1, 15, 17–21)
.github/workflows/module.yml, .github/scripts/build-nfqws2.sh, .github/patches/
```

---

## Веха 2а — служба и `ctl`

### Task 1: Содержимое модуля из оригинала

**Files:**
- Create: `module/strategies/*.conf` (28 файлов: все из оригинала, кроме `smart.conf`), `module/strategies/meta.tsv` (без строки `smart`)
- Create: `module/defaults/lists/{user,auto,exclude,ipset,ipset_exclude}.list`, `module/defaults/calls-bypass.conf`
- Create: `module/lists/<имя>.list` — 15 тематических списков, на которые ссылаются пресеты: `geoblock`, `google`, `youtube`, `ipset_amazon`, `ipset_as_contabo`, `ipset_as_creanova`, `ipset_as_frantech`, `ipset_as_iomart`, `ipset_as_melbicom`, `ipset_cf_full`, `ipset_do`, `ipset_ovh` и прочие, найденные скриптом
- Create: `module/blobs/*.bin` — только те, на которые ссылаются пресеты (`@$BLOBS_DIR/…`) и обход звонков (`stun.bin`, `tls_clienthello.bin`)
- Create: `module/tools/import-upstream.sh`, `module/NOTICE.md`, `module/LICENSE.upstream` (MIT оригинала)
- Test: `module/tests/test_refs.sh`

- [ ] **Step 1:** Написать `module/tests/test_refs.sh`. Для каждой ссылки `$BLOBS_DIR/<f>`, `$LISTS_DIR/<f>` в `module/strategies/*.conf` проверить, что файл есть в `module/blobs/`, `module/lists/` или `module/defaults/lists/`. Также проверить, что пресетов ровно 28, `smart.conf` нет, у каждого пресета есть строка в `meta.tsv`.
- [ ] **Step 2:** `sh module/tests/test_refs.sh` → FAIL (файлов нет).
- [ ] **Step 3:** `module/tools/import-upstream.sh <путь к клону>`: копирует перечисленное из клона на коммите `8e916c8` (проверяет `git rev-parse HEAD`), вычисляя нужные блобы и списки grep-ом по пресетам. `NOTICE.md` — таблица «файлы → источник → автор → лицензия». Для пресетов nfqws-menu пишется «лицензия в источнике не указана».
- [ ] **Step 4:** `sh module/tools/import-upstream.sh /tmp/src_nfq/nfqws2-android && sh module/tests/test_refs.sh` → PASS.
- [ ] **Step 5:** Commit `feat(module): пресеты, списки и блобы из nfqws2-android v2.0.4`.

### Task 2: Раскладка путей и разбор пресетов

**Files:**
- Create: `engine/src/bypass/{mod.rs,layout.rs,preset.rs}`; Modify: `engine/src/lib.rs` (`pub mod bypass;`)
- Test: в `preset.rs` (`#[cfg(test)]`), данные — `../module/strategies` через `env!("CARGO_MANIFEST_DIR")`

**Interfaces:**
- Produces:
  - `pub struct Layout { pub module_dir: PathBuf, pub data_dir: PathBuf }`
  - `Layout::device() -> Layout` (`/data/adb/modules/bcw`, `/data/adb/bcw`)
  - методы `nfqws2()`, `lua_dir()`, `blobs_dir()`, `module_lists()`, `module_strategies()`, `defaults_dir()`, `data_lists()`, `data_strategies()`, `settings_file()`, `networks_file()`, `home_file()`, `logs_dir()`, `state_dir()`, `tmp_dir()` → `PathBuf`
  - `pub struct Preset { pub base, pub tcp, pub quic, pub udp, pub ipset, pub custom: String, pub limits: PktOverrides }` — значения **без раскрытия** переменных
  - `pub struct PktOverrides { pub tcp_out, pub tcp_in, pub udp_out, pub udp_in: Option<u16> }`
  - `pub struct PresetError { pub line: usize, pub message: String }` с `Display` по-русски
  - `pub fn parse_preset(text: &str) -> Result<Preset, PresetError>`
  - `pub const KNOWN_VARS: [&str; 7] = ["LUA_DIR","BLOBS_DIR","LISTS_DIR","LOG_DIR","MODE_LIST","MODE_ALL","MODE_AUTO"]`

- [ ] **Step 1:** Тесты:
  - `every_bundled_preset_parses` — все 28 файлов, у каждого непустой `tcp`;
  - `multiline_value_and_comments` — значение на 3 строках с комментарием `#` внутри (как в `alt.conf`);
  - `unknown_variable_is_an_error_with_line` — `NFQWS_ARGS="--x=$FOO"` на строке 4 → `line == 4`, сообщение содержит `FOO`;
  - `pkt_overrides_are_read_from_comment_lines` — `# NFQWS2_TCP_PKT_OUT=8` → `tcp_out == Some(8)`, как `get_strategy_packet_limits` оригинала;
  - `global_keys_are_ignored` — `AUTOSTART=0` не ошибка и не попадает в `Preset`.
- [ ] **Step 2:** `cargo test --lib bypass::preset` → FAIL (модуля нет).
- [ ] **Step 3:** Реализовать. Разбор построчный: `КЛЮЧ="` открывает значение, `"` закрывает. Неизвестный ключ пропускается, неизвестная переменная `$X` → `PresetError`.
- [ ] **Step 4:** `cargo test --lib bypass::preset` → PASS.
- [ ] **Step 5:** Commit `feat(bypass): раскладка путей и разбор пресетов`.

### Task 3: Настройки

**Files:** Create `engine/src/bypass/settings.rs`; Create `engine/src/bypass/ports.rs` пока только с `pub fn weight(list: &str) -> usize` (порт — 1, диапазон `a:b` или `a-b` — 2) и тестом `weight_counts_ranges_twice`; тесты настроек внутри `settings.rs`.

**Interfaces:**
- Produces:
  - `pub enum ListMode { List, All, Auto }`
  - `pub struct Settings { default_strategy: String, mode: ListMode, tcp_ports: String, udp_ports: String, auto_ports: bool, pkt_limit_out: u16, pkt_limit_in: u16, block_quic: bool, meta_quic_reject: bool, calls_bypass: bool, tcp_mss_clamp: u16, nat_fix: bool, autostart: bool, watchdog: bool, home_wifi: bool, net_strategy: bool, log_level: u8, log_max_kb: u32 }` — все поля `pub`
  - `impl Default` — значения таблицы §4.2 спецификации
  - `pub fn parse(text: &str) -> (Settings, Vec<String>)` — второе: предупреждения по-русски о строках, заменённых умолчанием
  - `pub fn render(&self) -> String`
  - `pub fn set(&mut self, key: &str, value: &str) -> Result<(), String>`
  - `pub const KEYS: [&str; 18]` — порядок как в таблице §4.2

- [ ] **Step 1:** Тесты:
  - `defaults_match_spec` — сравнить все 18 значений с §4.2;
  - `roundtrip` — `parse(render(s)) == s`;
  - `garbage_line_falls_back_with_warning` — `PKT_LIMIT_OUT=abc` → 15 и одно предупреждение (Review Focus 4);
  - `set_rejects_out_of_range` — `PKT_LIMIT_OUT=0`, `LOG_MAX_KB=10`, `TCP_MSS_CLAMP=50`, `MODE=x` → `Err`;
  - `set_rejects_more_than_15_multiport_weight` — `TCP_PORTS` из 16 одиночных портов → `Err` (Review Focus 5);
  - `mss_one_means_536` — `Settings::mss_value()` → `Some(536)` при 1, `None` при 0.
- [ ] **Step 2:** `cargo test --lib bypass::settings` → FAIL.
- [ ] **Step 3:** Реализовать `ports::weight` и настройки; проверка `TCP_PORTS`/`UDP_PORTS` — `ports::weight(..) <= 15`.
- [ ] **Step 4:** → PASS.
- [ ] **Step 5:** Commit `feat(bypass): настройки модуля`.

### Task 4: Порты

**Files:** Modify `engine/src/bypass/ports.rs` (дополнить; `weight` уже есть с задачи 3).

**Interfaces:**
- Produces:
  - `pub fn normalize(list: &str) -> String` — `-` → `:` (как `tr '-' ':'` оригинала)
  - `pub fn add(list: &str, extra: &[&str]) -> String` — семантика `port_list_add` (`lib/common.sh:509`)
  - `pub fn without(list: &str, port: &str) -> String` — `port_list_without`
  - `pub fn from_filters(args: &str, proto: Proto) -> String` — `collect_capture_ports` (`lib/common.sh:643`): `--filter-tcp=`/`--filter-udp=`, `-`→`:`, без повторов, по возрастанию первого порта
  - `pub fn chunks(list: &str) -> Vec<String>` — части с весом ≤ 15, порядок сохранён
  - `pub enum Proto { Tcp, Udp }`
  - `pub struct EffectivePorts { pub tcp: String, pub udp: String }`
  - `pub fn effective(s: &Settings, preset: &Preset) -> EffectivePorts` — `AUTO_PORTS` (TCP по умолчанию `80,443`, если пусто), `BLOCK_QUIC` убирает 443 из UDP, `CALLS_BYPASS` добавляет UDP `590:1400`, `3478:3482` и TCP `5222` — как в `_firewall_start` (`lib/common.sh:1442–1475`)

- [ ] **Step 1:** Тест `effective_ports_match_upstream` по эталону: `engine/tests/fixtures/bypass/ports.jsonl` — строки `{preset, auto_ports, block_quic, calls, tcp, udp}` для всех 28 пресетов × 2 × 2 × 2. Генератор `engine/tests/fixtures/bypass/gen-ports.sh <клон>` выполняет функции оригинала (`collect_capture_ports`, `port_list_add`, `port_list_without`) в его окружении (`MODDIR=<клон>`, `CONFDIR=$(mktemp -d)`). Сгенерировать и закоммитить. Плюс `chunks_never_exceed_15` (24 одиночных порта → 2 части, вес каждой ≤ 15).
- [ ] **Step 2:** `cargo test --lib bypass::ports` → FAIL.
- [ ] **Step 3:** Реализовать.
- [ ] **Step 4:** → PASS; `cargo test --lib bypass::settings` → PASS.
- [ ] **Step 5:** Commit `feat(bypass): порты перехвата как в nfqws2-android`.

### Task 5: Командная строка nfqws2

**Files:** Create `engine/src/bypass/args.rs`, `engine/tests/fixtures/bypass/gen-args.sh`, `engine/tests/fixtures/bypass/args.jsonl`.

**Interfaces:**
- Consumes: `Layout`, `Preset`, `Settings`.
- Produces:
  - `pub struct ArgsInput<'a> { pub preset: &'a Preset, pub settings: &'a Settings, pub layout: &'a Layout, pub ipset_nonempty: bool }`
  - `pub fn build(input: &ArgsInput) -> Result<Vec<String>, String>`
  - `pub fn expand(value: &str, layout: &Layout, settings: &Settings) -> String` — подстановка `$LUA_DIR`→`lua_dir()`, `$BLOBS_DIR`→`blobs_dir()`, `$LOG_DIR`→`logs_dir()`, `$LISTS_DIR/<f>`→`data_lists()/<f>`, если файл есть, иначе `module_lists()/<f>`; `$MODE_LIST`=`--hostlist=$LISTS_DIR/user.list`, `$MODE_ALL`=`--hostlist-exclude=$LISTS_DIR/exclude.list`, `$MODE_AUTO`=`$MODE_LIST --hostlist-auto=$LISTS_DIR/auto.list --hostlist-auto-debug=$LOG_DIR/auto.log $MODE_ALL`; затем `norm_args` (`lib/common.sh:371`): строки-комментарии удаляются, `\` удаляется, пробелы сжимаются
  - `pub const META_NET4: &str`, `pub const TG_NET4: &str`, `pub const META_NET6: &str`, `pub const TG_NET6: &str` — копии из `lib/common.sh:62–69`

  Порядок аргументов — `_startup_args` (`lib/common.sh:537–579`):
  1. `--debug=@<logs>/nfqws2.log` (`LOG_LEVEL=1` → `nfqws2-debug.log`), `--user=root`, `--qnum=300`;
  2. база;
  3. при `CALLS_BYPASS` — `--blob=calls_stun:@<blobs>/stun.bin --blob=calls_tls:@<blobs>/tls_clienthello.bin` + `calls-bypass.conf` с `@META@`/`@TG@` + `--new`;
  4. custom + `--new`;
  5. udp + `--new`;
  6. если quic и не `BLOCK_QUIC`: [quic + ipset + `--ipset-ip=0.0.0.0 --new`, если ipset] + quic + режим + `--new`;
  7. [tcp + ipset + `--ipset-ip=0.0.0.0 --new`, если ipset] + tcp + режим.

  Режим (`NFQWS_EXTRA_ARGS`) задаёт `Settings::mode`, а не текст пресета. В эталонах оригинал запускается с `NFQWS_EXTRA_ARGS="$MODE_LIST|$MODE_ALL|$MODE_AUTO"`.

- [ ] **Step 1:** Генератор `gen-args.sh <клон>`. Для каждого пресета × `MODE` (3) × `BLOCK_QUIC` (2) × `CALLS_BYPASS` (2) × ipset (пуст/одна строка `1.1.1.1`):
  - подготовить окружение, как в `tests/lib/harness.sh` оригинала;
  - выполнить `set_defaults; . <пресет>; <переопределения>; _startup_args`;
  - записать строку `{"preset","mode","block_quic","calls","ipset","args":[…]}` в `args.jsonl`, заменив `MODDIR` на `<MOD>`, `CONFDIR` на `<DATA>`.

  Сгенерировать, закоммитить. Тест `args_match_upstream_golden`: `Layout{module_dir:"<MOD>", data_dir:"<DATA>"}`; при сравнении `<DATA>/lists/` и `<MOD>/lists/` сводятся к `<LISTS>/`. Сравнивается каждая из 672 строк, при расхождении печатаются пресет, комбинация и первое различие.
- [ ] **Step 2:** `cargo test --lib bypass::args` → FAIL.
- [ ] **Step 3:** Реализовать `build` и `expand`.
- [ ] **Step 4:** → PASS (672/672).
- [ ] **Step 5:** Commit `feat(bypass): командная строка nfqws2 по эталону nfqws2-android`.

### Task 6: Правила `dpi_*`

**Files:** Modify `engine/src/firewall/ipt.rs` (в `Table` добавить `Nat`, `Filter`; `name()`); Create `engine/src/bypass/rules.rs`.

**Interfaces:**
- Consumes: `IptRun`, `IptBatch`, `RecordingIpt` (тесты), `ports::{chunks, EffectivePorts}`.
- Produces:
  - `pub struct Limits { pub tcp_out, pub tcp_in, pub udp_out, pub udp_in: u16 }`
  - `pub struct RuleParams { pub ports: EffectivePorts, pub limits: Limits, pub block_quic: bool, pub mss: Option<u16>, pub nat_fix: bool, pub meta_quic: bool }`
  - `pub fn params(s: &Settings, preset: &Preset) -> RuleParams` — лимиты пресета главнее `PKT_LIMIT_*`
  - `pub fn batches(p: &RuleParams) -> Vec<IptBatch>` — цепочки и их содержимое, без переходов
  - `pub fn jump_position(chain_listing: &str) -> usize` — 1 + число идущих подряд с начала `-A <CHAIN> -j bcw_*` в выводе `iptables -S <CHAIN>`
  - `pub async fn apply<R: IptRun>(r: &R, p: &RuleParams) -> Result<(), BlockcheckError>` — `remove`, батчи, переходы на `jump_position`
  - `pub async fn remove<R: IptRun>(r: &R)` — снимает все переходы на `dpi_*` (повторять `-D`, пока удаляется) и сами цепочки
  - `pub const CHAINS: [(Table, &str); 4]`

  Содержимое — §3.5 спецификации; правила с портами — по одному на каждую часть `ports::chunks`.

- [ ] **Step 1:** Тесты на `RecordingIpt`:
  - `isolation_rules_come_first` — первые две строки `dpi_post` и `dpi_pre`: глобальные константы изоляции;
  - `processed_mark_returns_second`;
  - `block_quic_drops_udp443_and_removes_it_from_queue`;
  - `mss_rule_only_when_set` — `--tcp-flags SYN,RST SYN -j TCPMSS --set-mss 536`;
  - `nat_fix_on_and_off` — при on: `dpi_nat` с MASQUERADE и две строки POSTROUTING после перехода, при off: одна (сброс бита 30);
  - `meta_quic_chain_in_filter_output`;
  - `queue_rules_use_connbytes_and_bypass` — `-m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 1:15 -j NFQUEUE --queue-num 300 --queue-bypass`;
  - `jump_lands_after_search_jumps` — листинг с двумя `-j bcw_post` → позиция 3 (Review Focus 3);
  - `apply_twice_leaves_one_copy` — после двух `apply` в записанных операциях каждая цепочка создана один раз после последнего `remove`, переходов по одному;
  - `ports_over_15_split_into_rules` (Review Focus 5).
- [ ] **Step 2:** `cargo test --lib bypass::rules` → FAIL.
- [ ] **Step 3:** Реализовать.
- [ ] **Step 4:** → PASS; `cargo test --lib firewall` → PASS.
- [ ] **Step 5:** Commit `feat(bypass): правила dpi_* транзакцией iptables-restore`.

### Task 7: Правила на реальном ядре

**Files:** Create `engine/tests/bypass_e2e.rs`; Modify `.github/workflows/engine.yml` (job `integration`: запуск `cargo test --test bypass_e2e`); Modify `engine/docker/integration.Dockerfile`, если нужен модуль `xt_TCPMSS`/`xt_MASQUERADE`.

- [ ] **Step 1:** Тесты (root, iptables-legacy; общий `KERNEL`-мьютекс, как в `e2e_infra.rs`):
  - `apply_and_remove_leave_no_trace` — после `remove` `iptables-save` (mangle, nat, filter) без `dpi_`;
  - `ten_restarts_no_duplicates` — 10× `apply`, у каждой строки `-A POSTROUTING … dpi_post` и `MARK --set-xmark 0x0/0x40000000` ровно одна копия;
  - `bypass_after_search_chains` — `rules::prepare_chains` поиска, затем `bypass::rules::apply`, затем `ensure_order` поиска не возвращает исправлений;
  - `search_control_probe_passes_beside_bypass` — по образцу `control_probe_skips_foreign_chain` из `e2e_infra.rs`: при стоящих `dpi_*` контрольная проба поиска не попадает в очередь 300 (счётчик пакетов правила NFQUEUE в `dpi_post` = 0).
- [ ] **Step 2:** `sudo -E cargo test --test bypass_e2e` → PASS. Если тест падает, это ошибка в задаче 6: чинить там.
- [ ] **Step 3:** Commit `test(bypass): правила обхода на реальном ядре`.

### Task 8: Сеть

**Files:** Create `engine/src/bypass/network.rs`.

**Interfaces:**
- Produces:
  - `pub enum Network { Wifi { ssid: String }, Mobile { operator: Option<String> }, Offline }`
  - `pub fn parse_cmd_wifi(out: &str) -> Option<Option<String>>` — `None`: вывод не от `cmd wifi`; `Some(None)`: не подключено; `Some(Some(ssid))` (как `current_ssid`, `lib/common.sh:2108`)
  - `pub fn parse_dumpsys_wifi(out: &str) -> Option<String>`
  - `pub fn operator_from_getprop(alpha: &str, sim_alpha: &str) -> Option<String>` — первый элемент до `,`
  - `impl Network { pub fn key(&self) -> String; pub fn title(&self) -> String }` — ключ по `current_network_key` (`lib/common.sh:2263`): `wifi_<safe>` или `wifi_<safe>_<hex>`, `cell_…`, `cellular`. Подпись: `Wi-Fi «…»`, `Мобильная (…)`, `Мобильная`
  - `pub enum Decision { Pause { ssid: String }, Resume, Restart { strategy: String }, Nothing }`
  - `pub fn decide(cur: &DecisionInput) -> Decision`, где `pub struct DecisionInput<'a> { pub settings: &'a Settings, pub network: &'a Network, pub running_strategy: Option<&'a str>, pub paused: bool, pub home: &'a [String], pub resumed_ssid: Option<&'a str>, pub saved: &'a [(String, String)] }` — `saved` = (ключ, пресет)

- [ ] **Step 1:** Тесты:
  - `cmd_wifi_connected_disconnected_foreign` — три образца вывода;
  - `unknown_ssid_is_not_wifi` (`<unknown ssid>`, пусто, `0x`);
  - `ssid_key_matches_upstream` — эталон: ключи для `Home`, `Мой дом`, `a"b c`, `Café ☕`, полученные `current_network_key` оригинала, в `engine/tests/fixtures/bypass/netkeys.jsonl` (генератор `gen-netkeys.sh`) (Review Focus 1);
  - `decide_table` — дома при `HOME_WIFI=1` → Pause; дома, но `resumed_ssid` = этот SSID → не Pause; ушёл из дома → Resume; `NET_STRATEGY=1` и сеть сохранена с другой стратегией → Restart{её}; `NET_STRATEGY=0` → стратегия `DEFAULT_STRATEGY`; `Offline` → Nothing.
- [ ] **Step 2:** `cargo test --lib bypass::network` → FAIL.
- [ ] **Step 3:** Реализовать.
- [ ] **Step 4:** → PASS.
- [ ] **Step 5:** Commit `feat(bypass): определение сети и решение по ней`.

### Task 9: Данные модуля

**Files:** Create `engine/src/bypass/store.rs`.

**Interfaces:**
- Consumes: `Layout`, `parse_preset`, `settings::parse`, `system::atomic::write_atomic`.
- Produces (`pub struct Store { layout: Layout }`, `Store::new(layout)`):
  - `init_data_dir(&self) -> io::Result<()>` — создать каталоги; скопировать `defaults/lists/*` в `data_lists()`, если файла нет; `settings.conf` с умолчаниями, если нет
  - `settings(&self) -> (Settings, Vec<String>)`, `save_settings(&self, &Settings) -> io::Result<()>`
  - `strategies(&self) -> Vec<StrategyInfo>` — `pub struct StrategyInfo { name, author, source: String, builtin: bool, modified: bool }`; авторы из `meta.tsv`
  - `load_preset(&self, name) -> Result<Preset, String>` — перекрытие главнее модульного; ошибка разбора → текст с номером строки
  - `save_preset(&self, name, text) -> Result<(), String>` — имя `[A-Za-z0-9_-]{1,64}`, текст обязан разбираться
  - `reset_preset(&self, name)`, `delete_preset(&self, name) -> Result<(), String>` — удалять встроенный нельзя
  - `list_names() -> [&str; 5]`, `read_list(&self, name) -> Result<String, String>`, `write_list(&self, name, text) -> Result<(), String>`, `list_count(&self, name) -> usize` — без пустых строк и `#`
  - `networks(&self) -> Vec<SavedNetwork>` — `pub struct SavedNetwork { key, title, strategy: String }`; битая строка пропускается с предупреждением
  - `set_network(&self, &Network, strategy) -> io::Result<()>`, `delete_network(&self, key)`
  - `home(&self) -> Vec<String>`, `add_home(&self, ssid)`, `remove_home(&self, ssid)`

- [ ] **Step 1:** Тесты во временном каталоге (модульная часть — копия `../module`):
  - `init_copies_default_lists_once` — повторный `init` не перезаписывает изменённый `user.list`;
  - `override_wins_and_reset_restores`;
  - `broken_override_reports_line` (Review Focus 4);
  - `cannot_delete_builtin`;
  - `bad_name_rejected` (`../x`, пусто, 65 символов);
  - `networks_skip_broken_line` (Review Focus 4);
  - `home_add_remove_dedup`;
  - `list_count_ignores_comments`.
- [ ] **Step 2:** `cargo test --lib bypass::store` → FAIL.
- [ ] **Step 3:** Реализовать; записи атомарные.
- [ ] **Step 4:** → PASS.
- [ ] **Step 5:** Commit `feat(bypass): хранилище данных модуля`.

### Task 10: Журналы

**Files:** Create `engine/src/bypass/logs.rs`.

**Interfaces:**
- Produces:
  - `pub enum Level { Info, Error }`
  - `pub enum EventKind { Start, Stop, Restart, Error, NetworkChange, Pause, Resume, Rollback }` — имена в журнале латиницей
  - `pub struct Journal { dir: PathBuf, max_kb: u32 }`
  - `Journal::event(&self, kind, level, text: &str) -> io::Result<()>` — строка `YYYY-MM-DD HH:MM:SS <level> <kind> <text>` в `service.log`; после записи `trim`
  - `pub fn trim(path: &Path, max_kb: u32) -> io::Result<()>` — сверх предела остаётся вторая половина с начала полной строки
  - `pub fn read(path: &Path, errors_only: bool, tail: Option<usize>) -> io::Result<String>`
  - `pub struct Stats { pub starts, pub restarts, pub errors, pub auto_added: usize }`, `pub fn stats(dir: &Path) -> Stats` — `auto_added` считается по строкам `auto.log`, которые оригинал считает добавлением (свериться с форматом `--hostlist-auto-debug` в zapret2 `f924d79` и записать образец в тест)
  - `pub const FILES: [&str; 3] = ["service.log", "nfqws2.log", "auto.log"]`

- [ ] **Step 1:** Тесты:
  - `trim_keeps_newest_half_on_line_boundary`;
  - `errors_filter`;
  - `tail_n`;
  - `stats_count_kinds` — по образцам строк;
  - `auto_added_counts_sample_lines` — образец строк из исходника zapret2.
- [ ] **Step 2:** `cargo test --lib bypass::logs` → FAIL.
- [ ] **Step 3:** Реализовать.
- [ ] **Step 4:** → PASS.
- [ ] **Step 5:** Commit `feat(bypass): журналы и статистика`.

### Task 11: Супервизор

**Files:** Create `engine/src/bypass/supervisor.rs`.

**Interfaces:**
- Consumes: `args::build`, `rules::params`, `network::decide`, `Store`, `Journal`.
- Produces:
  - трейты (async fn):
    - `pub trait Engine { async fn dry_run(&self, args: &[String]) -> Result<(), String>; async fn spawn(&mut self, args: &[String]) -> Result<(), String>; fn alive(&mut self) -> bool; async fn stop(&mut self); }`
    - `pub trait Firewall { async fn apply(&self, p: &RuleParams) -> Result<(), String>; async fn remove(&self); }`
    - `pub trait Probe { async fn network(&self) -> Network; fn neighbour_active(&self) -> bool; }` — сосед: `/data/adb/modules/nfqws2-android` есть, а `disable` и `remove` нет
  - `pub enum State { Running, Stopped, PausedHome { ssid: String }, BlockedNeighbour, Failed { reason: String, retry_at: Instant } }` с `as_str()`: `running`, `stopped`, `paused_home`, `blocked_neighbour`, `failed`
  - `pub enum Command { Start, Stop, Restart, Reload, HomeResume }`
  - `#[derive(Serialize, Deserialize)] pub struct Status { pub state: String, pub reason: Option<String>, pub network_key: Option<String>, pub network_title: Option<String>, pub strategy: Option<String> }`
  - `pub struct Supervisor<E, F, P> { … }`; `Supervisor::new(store, journal, engine, firewall, probe, boot: bool)` — `boot=true`: желаемое = `AUTOSTART`, записывается в `state/desired`; `boot=false` (перезапуск службы после падения): желаемое читается из `state/desired`
  - `async fn tick(&mut self, now: Instant)` — вызывается раз в 5 с
  - `async fn command(&mut self, c: Command, now: Instant) -> Result<Status, String>`
  - `fn status(&self) -> Status`
  - константы: `NET_POLL = 5 с`, `WATCHDOG_EVERY = 20 с`, `MAX_FAILS = 5`, `FAIL_PAUSE = 60 с`, `ROLLBACK_WINDOW = 10 с`, `STABLE_POLLS = 2`

  Поведение — §3.2–3.4 спецификации:
  - желаемое состояние хранится в `state/desired` (`on`/`off`);
  - последняя рабочая командная строка — в `state/last_good` (JSON-массив), туда пишется после 10 с жизни;
  - `HomeResume` действует, пока SSID не сменится;
  - `Reload` перечитывает настройки и данные и перезапускает, только если итоговая командная строка или `RuleParams` изменились.

- [ ] **Step 1:** Тесты с фейками и ручными часами:
  - `start_applies_rules_then_spawns`;
  - `stop_kills_and_removes_rules`;
  - `watchdog_restarts_dead_engine`;
  - `five_fails_enter_failed_then_retry_after_60s`;
  - `watchdog_off_goes_failed_at_once`;
  - `crash_within_10s_rolls_back_to_last_good` — `Rollback` в журнале;
  - `dry_run_error_keeps_previous_and_reports`;
  - `home_pause_and_resume`;
  - `network_change_needs_two_equal_polls` — Wi-Fi, мобильная, Wi-Fi за три опроса → ни одного перезапуска (Review Focus 2);
  - `offline_does_nothing` (Review Focus 2);
  - `neighbour_blocks_start`;
  - `broken_preset_falls_back_to_default_strategy` (Review Focus 4);
  - `reload_without_changes_does_not_restart`.
- [ ] **Step 2:** `cargo test --lib bypass::supervisor` → FAIL.
- [ ] **Step 3:** Реализовать. Время только из аргумента `now`, сна внутри нет.
- [ ] **Step 4:** → PASS.
- [ ] **Step 5:** Commit `feat(bypass): супервизор службы`.

### Task 12: IPC и `bcw svc`

**Files:** Create `engine/src/bypass/{ipc.rs,system.rs}`, `engine/src/cmd/svc.rs`; Modify `engine/src/cmd/mod.rs`, `engine/src/main.rs` (подкоманда `Svc { #[command(subcommand)] action: SvcAction }`, `SvcAction::{Run, Cleanup}`; вне `require_root`, root проверяется внутри).

**Interfaces:**
- Consumes: `Supervisor`, `rules::{apply, remove}`, `SystemIpt`, `system::process`, `network::parse_*`.
- Produces:
  - `pub const SOCKET_NAME: &str = "bcw.svc"`
  - `pub enum Request { Status, Start, Stop, Restart, Reload, HomeResume }`
  - `pub struct Response { pub ok: bool, pub error: Option<String>, pub status: Option<Status> }` (serde, `Status` — `Serialize`)
  - `pub async fn serve(…)` — одна строка JSON на запрос, ответ строкой
  - `pub async fn call(req: &Request, timeout: Duration) -> Result<Response, CallError>`, где `pub enum CallError { NotRunning, Timeout, Bad(String) }`
  - `system.rs`:
    - `SystemEngine: Engine` — nfqws2 как `BackgroundProcess`, `dry_run` через `nfqws2 --dry-run`;
    - `SystemFirewall: Firewall`;
    - `SystemProbe: Probe` — `cmd wifi status </dev/null`, запас `dumpsys wifi`, `getprop gsm.operator.alpha` / `gsm.sim.operator.alpha`; `Offline` — если `ip route get 1.1.1.1` без `dev`
  - `bcw svc run [--boot]` — `Store::init_data_dir`, `Supervisor::new(…, boot)`, цикл `tick` раз в 5 с, `serve`; при старте `rules::remove`; на SIGTERM — `stop` без записи `desired=off`
  - `bcw svc cleanup` — `rules::remove` и выход

- [ ] **Step 1:** Тесты:
  - `ipc_roundtrip` — `serve` с фейковым супервизором на уникальном имени сокета, `call(Status)`;
  - `call_without_server_is_not_running`;
  - `request_json_shape` — `{"cmd":"start"}`.
  - В `tests/cli.rs`: `svc_cleanup_requires_root` — без root код 1 и сообщение про `su -c`.
- [ ] **Step 2:** `cargo test --lib bypass::ipc && cargo test --test cli` → FAIL.
- [ ] **Step 3:** Реализовать.
- [ ] **Step 4:** → PASS; `cargo clippy --all-targets -- -D warnings` чисто.
- [ ] **Step 5:** Commit `feat(bypass): служба bcw svc и её сокет`.

### Task 13: `bcw ctl`

**Files:** Create `engine/src/cmd/ctl.rs`; Modify `engine/src/main.rs` (подкоманда `Ctl`).

**Interfaces:**
- Consumes: `Store`, `Journal`/`logs`, `ipc::call`, `args::build`, `SystemEngine::dry_run`.
- Produces: команды §5 спецификации, ровно с этими именами:
  - `status`, `start`, `stop`, `restart`;
  - `strategies`, `strategy get|save|reset|delete|apply`;
  - `settings get|set`;
  - `lists`, `list get|set`;
  - `networks`, `network set|delete`, `home add|remove|resume`;
  - `logs`, `logs clear`, `stats`;
  - `version`, `upload begin|chunk|end`.

  Каждая печатает одну строку JSON со `schema:1` и выходит с кодом 0, а при `ok:false` — с кодом 1.
  - `start`/`stop` пишут `state/desired` и вызывают `ipc::call`. `CallError::NotRunning` → `ok:false`, `"служба не запущена"`.
  - Изменяющие команды (`settings set`, `strategy save|apply|reset|delete`, `network …`, `home add|remove`, `list set`) пишут данные и шлют `Reload`. `NotRunning` здесь — не ошибка.
  - `status` без службы → `{"ok":true,"state":"not_running",…}` по файлам.
  - `strategy save` перед записью проверяет `dry_run` итоговой строки.
  - `upload begin` → `{"path":"<tmp_dir>/upload-<n>"}`; `upload chunk <path> <base64>` дописывает; `--from <path>` принимает только пути внутри `tmp_dir()` и удаляет файл после чтения.

- [ ] **Step 1:** Тесты в `ctl.rs` (временный `Layout`, фейковый IPC через параметр):
  - `every_command_prints_schema_1_json`;
  - `start_without_service_says_not_running`;
  - `settings_set_validates` — `PKT_LIMIT_OUT 0` → `ok:false` с текстом из `Settings::set`;
  - `upload_rejects_path_outside_tmp`;
  - `upload_roundtrip_200kb` — 4 куска по 64 КБ base64;
  - `strategy_save_rejects_dry_run_error`;
  - `ctl_samples_are_current` — пишет образцы ответов всех команд в `module/tests/ctl-samples/<команда>.json`, если задано `UPDATE_SAMPLES=1`, иначе сравнивает с ними.
- [ ] **Step 2:** `cargo test --bins ctl` → FAIL.
- [ ] **Step 3:** Реализовать.
- [ ] **Step 4:** `UPDATE_SAMPLES=1 cargo test --bins ctl_samples_are_current`, затем `cargo test --bins` → PASS.
- [ ] **Step 5:** Commit `feat(bypass): bcw ctl для интерфейса`.

### Task 14: Пути поиска внутри модуля

**Files:** Modify `engine/src/config.rs` (`DEFAULT_NFQWS2="/data/adb/modules/bcw/bin/nfqws2"`, `DEFAULT_LUA_DIR="/data/adb/modules/bcw/lua"`), `engine/src/cmd/doctor.rs` (проверка `neighbours` узнаёт `dpi_*` как свой обход: в `detail` пишется «обход bcw»), `engine/README.md` (пути), тесты, где зашиты старые пути.

- [ ] **Step 1:** Тест `default_paths_point_into_bcw_module` в `config.rs`; тест `doctor_names_bcw_bypass_neighbour` на `foreign_queue_chains` с `dpi_post`.
- [ ] **Step 2:** → FAIL.
- [ ] **Step 3:** Поправить константы и тексты.
- [ ] **Step 4:** `cargo test --lib --bins && cargo test --test cli` → PASS.
- [ ] **Step 5:** Commit `feat(engine): поиск берёт nfqws2 и Lua из модуля bcw`.

### Task 15: Скрипты модуля

**Files:** Create `module/module.prop` (`id=bcw`, `name=bcw — обход DPI`, `version=v0.1.0`, `versionCode=100`, `author=cenior-pomidor`, `description=Обход DPI на nfqws2 и поиск стратегий`, `updateJson=https://raw.githubusercontent.com/cenior-pomidor/TestBlockcheck/main/module/update.json`, `webuiIcon=webroot/icon.png`), `module/update.json`, `module/customize.sh`, `module/service.sh`, `module/uninstall.sh`; Test `module/tests/test_scripts.sh`.

- [ ] **Step 1:** `test_scripts.sh` с заглушками на `PATH`:
  - `sh -n` всех скриптов;
  - `customize.sh` при `ARCH=arm` или без `KSU=true` вызывает `abort`;
  - `service.sh` дожидается `sys.boot_completed=1` (заглушка `getprop`), первый раз запускает `bin/bcw svc run --boot`, после выхода — `bin/bcw svc run` (заглушка `bcw` пишет аргументы; 2 запуска за ≤ 12 с, `--boot` только у первого);
  - `uninstall.sh` вызывает `bin/bcw svc cleanup` и удаляет `$DATA_DIR`. Каталог данных подменяется переменной `BCW_DATA_DIR`, умолчание — `/data/adb/bcw`.
- [ ] **Step 2:** `sh module/tests/test_scripts.sh` → FAIL.
- [ ] **Step 3:** Написать скрипты. Права ставит `set_perm` из установщика KernelSU (`bin/*` 0755); на `webroot/` права не трогать — предупреждение документации KernelSU.
- [ ] **Step 4:** → PASS.
- [ ] **Step 5:** Commit `feat(module): установка, запуск и удаление`.

### Task 16: CI модуля и сборка nfqws2

**Files:**
- Create `.github/scripts/build-nfqws2.sh` — скрипт оригинала, урезанный до `android-arm64`, с шапкой об авторстве и MIT. Проверки архитектуры, выравнивания 16 КБ, `NEEDED`, патча сохраняются.
- Create `.github/patches/{001-tls-reasm-fastpath.patch,libnetfilter_queue-android.patch}`.
- Create `.github/workflows/module.yml`. Jobs:
  - `nfqws2` — NDK так же, как `build-binaries.yml` оригинала;
  - `bcw` — переиспользовать шаги `build-android` из `engine.yml`;
  - `package` — архив `bcw-module-<версия>.zip` из `module/` (без `tests/`, `tools/`, `webroot/js/package.json`) + `bin/bcw`, `bin/nfqws2`, `lua/{zapret-lib,zapret-antidpi,zapret-auto}.lua` из zapret2 `f924d79`;
  - проверки: `id=bcw`, `test_refs.sh`, `test_scripts.sh`, на теге — версия `module.prop` равна тегу;
  - `release` (по тегу `v*`) — GitHub Release с архивом.
- Create `module/README.md` — раздел «Проверка на телефоне, веха 2а» (сценарии §8.2 спецификации и команды для Termux).

- [ ] **Step 1:** Push ветки → все jobs зелёные, артефакт `bcw-module` есть. Внутри архива `unzip -l` показывает `bin/bcw`, `bin/nfqws2`, `lua/zapret-lib.lua`, `module.prop`, `webroot/` нет до задачи 17.
- [ ] **Step 2:** Commit `ci(module): сборка nfqws2, bcw и архива модуля`.
- [ ] **Step 3:** **Приёмка 2а на телефоне** по `module/README.md`. Сначала `su -c 'cmd wifi status'` (R1). Отчёт владельца разбирается до перехода к 2б.

## Веха 2б — WebUI и релиз

### Task 17: Основа WebUI и вкладка «Состояние»

**Files:** Create `module/webroot/{index.html,icon.png,css/app.css}`, `module/webroot/js/{bridge.js,app.js,status.js,package.json}` (`{"type":"module"}`, в архив не идёт); Test `module/tests/webui/{test_static.mjs,test_status.mjs}`.

**Interfaces:**
- Produces:
  - `bridge.js`:
    - `export async function ctl(args: string[], {timeoutMs=15000}={}): Promise<object>` — `window.ksu.exec(cmd, '{}', callbackName)` с запасным `window.ksu.spawn`, как в `core.js:264–325` оригинала. Аргументы экранируются одинарными кавычками; команда `/data/adb/modules/bcw/bin/bcw ctl …`;
    - `export async function uploadText(text): Promise<string>` — путь после `upload begin|chunk…|end` кусками по 48 КБ base64.
  - `app.js`: `export function registerTab(id, title, render)` и переключение вкладок.
  - `status.js`: `export function renderStatus(json): string` (HTML) и `export function bindStatus(root, json)`.

- [ ] **Step 1:** Тесты Node:
  - `test_static.mjs` — `node --check` каждого `js/*.js`; `index.html` подключает только локальные файлы; нет `http:`/`https:` в `src`/`href`;
  - `test_status.mjs` — `renderStatus` на образцах `module/tests/ctl-samples/status*.json` показывает «Работает», «Пауза: домашний Wi-Fi «Home»», «Не запущено: включён nfqws2-android», «Служба не запущена» и кнопку «Включить здесь сейчас» только в паузе.
- [ ] **Step 2:** `node module/tests/webui/test_static.mjs && node module/tests/webui/test_status.mjs` → FAIL.
- [ ] **Step 3:** Реализовать; стили — системная тема через `prefers-color-scheme`.
- [ ] **Step 4:** → PASS; добавить оба теста в job `package` из `module.yml`.
- [ ] **Step 5:** Commit `feat(webui): основа и вкладка «Состояние»`.

### Task 18: Вкладка «Стратегии»

**Files:** Create `module/webroot/js/strategies.js`; Test `module/tests/webui/test_strategies.mjs`.

**Interfaces:** `renderStrategies(listJson, statusJson): string`, `renderEditor(strategyJson): string`, `editorToText(fields): string` (6 ключей в формате пресета, значения в двойных кавычках, по ключу на строку).

- [ ] **Step 1:** Тесты:
  - список показывает автора, отметку «изменён» и текущую стратегию;
  - `editorToText` → текст, который `bcw` разбирает (проверка: образец `strategy-get.json` → `editorToText` → совпадает с полями образца);
  - кнопки «Для этой сети», «По умолчанию», «Вернуть к исходнику» (только у изменённых встроенных), «Удалить» (только у своих), «Новый» (пустой редактор с полем имени; имя проверяет `ctl`).
- [ ] **Step 2:** → FAIL.
- [ ] **Step 3:** Реализовать. Сохранение — `uploadText` → `strategy save <имя> --from <path>`; ошибка `dry_run` показывается под редактором.
- [ ] **Step 4:** → PASS.
- [ ] **Step 5:** Commit `feat(webui): стратегии и редактор`.

### Task 19: Вкладки «Сети» и «Списки»

**Files:** Create `module/webroot/js/{networks.js,lists.js}`; Test `module/tests/webui/{test_networks.mjs,test_lists.mjs}`.

**Interfaces:** `renderNetworks(networksJson, settingsJson, statusJson): string`, `renderLists(listsJson, settingsJson): string`.

- [ ] **Step 1:** Тесты:
  - сети: подписи из образца, «Добавить текущую» только на Wi-Fi, тумблеры `NET_STRATEGY`/`HOME_WIFI` отражают настройки, SSID с `<`, `"`, `&` экранируется в HTML (Review Focus 1);
  - списки: 5 списков с числом строк, режим `list`/`all`/`auto` выбран по настройке.
- [ ] **Step 2:** → FAIL.
- [ ] **Step 3:** Реализовать. Сохранение списка — `uploadText` → `list set <имя> --from <path>`.
- [ ] **Step 4:** → PASS.
- [ ] **Step 5:** Commit `feat(webui): сети и списки`.

### Task 20: Вкладки «Журналы» и «Настройки»

**Files:** Create `module/webroot/js/{logs.js,settings.js}`; Test `module/tests/webui/{test_logs.mjs,test_settings.mjs}`.

**Interfaces:** `renderLogs(logsJson, statsJson, {file, errorsOnly}): string`, `renderSettings(settingsJson, versionJson): string`, `settingControls: Array<{key, label, kind: 'bool'|'number'|'text'}>` — 16 ключей §4.2 (без `DEFAULT_STRATEGY`, `MODE`) с русскими подписями.

- [ ] **Step 1:** Тесты:
  - журналы: три файла, фильтр «Ошибки», статистика из `stats.json`;
  - настройки: все 16 ключей из `settings-get.json` имеют элемент; число вне диапазона показывает текст ошибки из ответа `ctl`, без собственной проверки на JS.
- [ ] **Step 2:** → FAIL.
- [ ] **Step 3:** Реализовать.
- [ ] **Step 4:** → PASS.
- [ ] **Step 5:** Commit `feat(webui): журналы и настройки`.

### Task 21: Релиз v0.1.0 и приёмка 2б

**Files:** Modify `module/README.md` (раздел «Проверка на телефоне, веха 2б»), `module/module.prop`, `module/update.json` (`version v0.1.0`, `versionCode 100`, `zipUrl` на релиз `v0.1.0`, `changelog`).

- [ ] **Step 1:** Полный набор: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --lib --bins`, `cargo test --test cli`, e2e (`e2e_infra`, `bypass_e2e`), `sh module/tests/*.sh`, `node module/tests/webui/*.mjs` — всё зелёное.
- [ ] **Step 2:** Commit `release(module): v0.1.0`; после согласия владельца — тег `v0.1.0` и push тега. Job `release` создаёт GitHub Release.
- [ ] **Step 3:** **Приёмка 2б на телефоне** по `module/README.md`: сценарии вехи 2а через WebUI; обновление видно в менеджере; удаление модуля стирает `/data/adb/bcw/`.
