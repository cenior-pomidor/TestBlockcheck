use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

mod cmd;
mod tracing_otel;

use blockcheckw::nfqws2::space as mark_space;

const fn help_styles() -> clap::builder::styling::Styles {
    use clap::builder::styling::{AnsiColor, Color, Style, Styles};

    Styles::styled()
        .header(
            Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::Yellow)))
                .bold()
                .underline(),
        )
        .usage(
            Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::Yellow)))
                .bold(),
        )
        .literal(
            Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::Green)))
                .bold(),
        )
        .placeholder(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Cyan))))
}

/// Верхнеуровневая справка перечисляет только команды: таймауты, DNS-режим и
/// число проходов задаются флагами конкретной команды (#66).
const AFTER_HELP: &str = "\
Examples:
  bcw scan -d rutracker.org                скан домена на работающие страты
  bcw scan -d example.com -p tls12         проверка только TLS 1.2
  bcw scan -d example.com -o report.json   сохранить отчёт в файл
  bcw check --from-file report.json        проверка найденных страт
  bcw universal --domain-list domains.txt  подбор пересекающихся страт для разных доменов
  bcw status --domain-list domains.txt     оценка эффективности работающего zapret2

Per-command flags (timeouts, DNS mode, passes, worker count):
  bcw <command> --help";

#[derive(Parser)]
#[command(
    name = "bcw",
    about = "Parallel DPI bypass strategy scanner (Android)",
    after_help = AFTER_HELP,
    styles = help_styles(),
)]
struct Cli {
    /// Print version
    #[arg(short = 'V', long)]
    version: bool,

    /// Number of parallel workers
    #[arg(short, long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..=254))]
    workers: u16,

    /// How many strategies to keep loaded in one nfqws2 process at a time (ceiling 254)
    #[arg(long, default_value_t = 254)]
    profiles_per_instance: usize,

    /// Путь к nfqws2 (умолчание /data/adb/modules/nfqws2-android/bin/nfqws2).
    #[arg(long, global = true, value_name = "PATH")]
    nfqws2: Option<std::path::PathBuf>,

    /// Каталог Lua-библиотек движка (умолчание /data/adb/modules/nfqws2-android/lua).
    #[arg(long, global = true, value_name = "PATH")]
    lua_dir: Option<std::path::PathBuf>,

    /// Рабочий каталог: замок и отчёты прогонов (умолчание /data/adb/bcw).
    #[arg(long, global = true, value_name = "PATH")]
    work_dir: Option<std::path::PathBuf>,

    /// Свой DoH-резолвер: `IP` или `IP:ИМЯ` (можно несколько; опрашиваются раньше встроенных
    /// 1.1.1.1, 8.8.8.8, 9.9.9.9).
    #[arg(long, global = true, value_name = "SPEC")]
    doh: Vec<String>,

    /// Номер боевой очереди NFQUEUE (умолчание 777).
    #[arg(long, value_name = "N")]
    qnum: Option<u16>,

    /// Префикс наших цепочек iptables (умолчание bcw).
    #[arg(long, value_name = "NAME")]
    chain_prefix: Option<String>,

    /// Метка пакетов nfqws2 поиска, 0xHEX или десятичное (умолчание 0x00200000, бит 21).
    #[arg(long, value_name = "MARK")]
    mark_desync: Option<String>,

    /// Сдвиг восьмибитного поля стратегии в метке (умолчание 22: биты 22–29).
    #[arg(long, value_name = "N")]
    mark_profile_shift: Option<u32>,

    /// Начало диапазона дымовых очередей преflight'а, 10 подряд (умолчание 65526).
    #[arg(long, value_name = "N")]
    smoke_qnum_base: Option<u16>,

    /// Отдавать подтверждённые стратегии ПОТОКОМ (ndjson в stdout), не дожидаясь конца
    /// прогона: пока идёт подбор, цель в карантине, и первая же годная стратегия лечит.
    #[arg(long, global = true)]
    stream: bool,

    /// Печатать ход работы машиночитаемо (ndjson в stderr): фаза, сделано, всего, секунды.
    /// Чтобы «встал» судилось сроком, а не гаданием по выводу для человека.
    #[arg(long, global = true)]
    progress: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run parallel scaling benchmark to find optimal worker count
    Benchmark {
        /// Seconds to run per worker-count level
        #[arg(short, long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(5..))]
        time: u64,

        /// Maximum number of workers to test
        #[arg(short = 'M', long, value_parser = clap::value_parser!(u16).range(1..=254))]
        max_workers: Option<u16>,

        /// Target domain
        #[arg(short, long, default_value = "rutracker.org")]
        domain: String,

        /// Protocol to benchmark (http, tls12, tls13)
        #[arg(short, long, default_value = "tls12")]
        protocol: String,

        /// Raw output: table only, no recommendation (for scripts)
        #[arg(long)]
        raw: bool,
    },

    /// Check strategies from a vanilla report with real data transfer.
    /// В JSON две оси: `working` — прошёл ли канал (главная), `observed`/`admits` —
    /// подлинность ресурса (побочная). Читать надо обе: «не наблюдали» и «наблюдали
    /// пустоту» оба дают `working: false`, но это разные вещи.
    Check {
        /// Path to report file (reads from stdin if omitted and pipe detected)
        #[arg(long)]
        from_file: Option<String>,

        /// Target domain to check
        #[arg(short, long, default_value = "rutracker.org")]
        domain: String,

        /// DNS resolution mode: auto, system, doh
        #[arg(long, default_value = "auto")]
        dns: String,

        /// Потолок одной пробы в секундах — `Expiry::Ceiling`: сколько всего мы готовы
        /// ждать, даже если цель ещё отдаёт байты. Утверждение о нас, не о цели.
        /// Замер 16.09 на стенде: медиана полной доставки 0,7–1,4 с, потолок не наступил
        /// ни разу — страница, идущая дольше трёх секунд, человеку уже не годится.
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u64).range(1..=60))]
        timeout: u64,

        /// Порог тишины в миллисекундах — `Expiry::Idle`: проба обрывается, когда цель
        /// молчит дольше этого после последнего шага (коннект, рукопожатие, заголовки,
        /// кадр тела). Мёртвая стратегия кончается здесь, а не на потолке. Замер 16.09 на
        /// стенде: здоровая тишина 180–370 мс, наибольшая 857; check 170 → 54–74 с при
        /// том же числе рабочих. Порог видно в отчёте рядом с `longest_silence_ms`.
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(100..=60_000))]
        idle_ms: u64,

        /// Общий срок прогона в секундах (0 — без срока).
        ///
        /// По истечении перебор прекращается, а отдаётся ТО, ЧТО УСПЕЛО подтвердиться:
        /// пустой отчёт по сроку наказывал бы человека за нашу медлительность. Исход при
        /// этом честно называется `censored`/`stopped_at: deadline` — замер не полон.
        #[arg(long, default_value_t = 0)]
        deadline: u64,

        /// Stop the SEARCH after N PASSING strategies, per protocol (0 = check all).
        /// Выдачу не урезает: в отчёт идёт всякая наблюдённая стратегия, ранжированная
        /// по судьбе.
        #[arg(long, default_value_t = 0)]
        take: usize,

        /// `M` — сколько раз мерить байтовую ось (спека §6-тер, «мера байтов»).
        ///
        /// Один прогон на маленьком файле рапортует 19-20 «рабочих» стратегий; два
        /// ОДИНАКОВЫХ прогона (тот же путь, тот же таймаут) дали 19 и 19, из которых
        /// общих — 11: разошлись 16 из 27. Третий прогон с таймаутом в 2,5 раза больше
        /// добавил ровно одну — флапает провод, а не нетерпение. Устойчивое ядро по
        /// трём прогонам — 9. Умолчание `M = 3` несёт этот замер рядом (спека §3):
        /// повторы возвращаются не голосованием, а числом измерений частоты.
        ///
        /// `M = 0` — честный исход «не наблюдали» (не паникует).
        #[arg(long, default_value_t = 3)]
        passes: usize,

        /// Чистый egress для ОБОИХ эталонов (снимается дважды для каждого из двух
        /// путей — `--probe-path` и `--identity-path`). Без него доли не существует, а
        /// круг судеб не сужается до `Mirage`/`Good`/`Grinding` (см. `Fate::Mirage`).
        #[arg(long, value_name = "ENDPOINT")]
        reference_via: Option<String>,

        /// Путь БАЙТОВОЙ оси (главная, спека §6-тер): сколько долей эталона вытянула
        /// стратегия, повторяется `--passes` раз. Умолчание — корень `/`: главный
        /// вердикт от пути не зависит (DPI решает по SNI в `ClientHello`, до HTTP), а
        /// байтовая ось требует ОБЪЁМА настоящего ресурса, а не статичного файла.
        #[arg(long, value_name = "PATH", default_value = "/")]
        probe_path: String,

        /// Путь ОСИ ПОДЛИННОСТИ (побочная, спека §6-тер): сверяется с эталоном ТОЧНО,
        /// один раз. Только она может дать круг `[Fate::Mirage]`. Умолчание —
        /// `/robots.txt`: детерминированный файл не редиректит и не гуляет в объёме
        /// между узлами CDN, значит сверка точна. Отката на `--probe-path` нет: если
        /// `robots.txt` у домена нет, сервер отдаст `404` — и это полноценная проба,
        /// эталон получит тот же `404` и сойдётся.
        #[arg(long, value_name = "PATH", default_value = "/robots.txt")]
        identity_path: String,

        /// Save JSON report to file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Scan domain for working DPI bypass strategies
    Scan {
        /// Target domain to check
        #[arg(short, long, default_value = "rutracker.org")]
        domain: String,

        /// Protocols to test (comma-separated: http,tls12,tls13)
        #[arg(short, long, default_value = "http,tls12,tls13")]
        protocols: String,

        /// DNS resolution mode: auto, system, doh
        #[arg(long, default_value = "auto")]
        dns: String,

        /// Overall scan timeout in seconds (0 = no limit)
        #[arg(long, default_value_t = 0)]
        timeout: u64,

        /// Show top N ranked strategies per protocol (0 = all)
        #[arg(long, default_value_t = 5)]
        top: usize,

        /// Save found strategies to file
        #[arg(short, long)]
        output: Option<String>,

        /// Load strategies from file instead of using built-in corpus
        #[arg(long)]
        from_file: Option<String>,
    },

    /// Проверить устройство перед первым прогоном: root, ядро, iptables, nfqws2, маршрут
    /// помеченных сокетов, DoH, соседи. JSON в stdout, таблица в stderr. Ничего не меняет.
    Doctor,

    /// Show zapret2 effectiveness: compare access with and without the service
    Status {
        /// Path to file with blocked domains (one per line)
        #[arg(long)]
        domain_list: String,

        /// DNS resolution mode: auto, system, doh
        #[arg(long, default_value = "auto")]
        dns: String,

        /// Request timeout per domain in seconds
        #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u64).range(1..=60))]
        timeout: u64,

        /// Save JSON report to file
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Find universal strategies that work across multiple blocked domains
    Universal {
        /// Path to file with blocked domains (one per line)
        #[arg(long)]
        domain_list: String,

        /// Protocols to test (comma-separated: http,tls12,tls13)
        #[arg(short, long, default_value = "tls12")]
        protocols: String,

        /// DNS resolution mode: auto, system, doh
        #[arg(long, default_value = "auto")]
        dns: String,

        /// Number of domains to sample from the list
        #[arg(long, default_value_t = 10)]
        sample: usize,

        /// Save report to file
        #[arg(short, long)]
        output: Option<String>,
    },
}

/// Разобрать режим DNS с оглядкой на встроенность.
///
/// ВО ВСТРОЕННОМ РЕЖИМЕ СИСТЕМНЫЙ РЕЗОЛВЕР ЗАПРЕЩЁН. Он работает внешними программами
/// (`getent`, `nslookup`), а чужому процессу не поставить `SO_MARK` — запрос имени уйдёт
/// немаркированным, то есть тем же путём, что трафик человека. Если вызывающий заворачивает
/// `udp dport 53` в свою очередь (а третий невод заворачивает), подбор окажется внутри мира,
/// который меряет, уже на уровне имени. Это не чинится ключом — это свойство чужого процесса,
/// и потому здесь отказ, а не предупреждение.
///
/// `auto` во встроенном режиме молча становится `doh`: он начинается с системного резолва, и
/// та же беда пришла бы через него.
fn dns_mode_of(raw: &str, embedded: bool) -> blockcheckw::config::DnsMode {
    let mode = match blockcheckw::config::parse_dns_mode(raw) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
    };
    if !embedded {
        return mode;
    }
    match mode {
        blockcheckw::config::DnsMode::System => {
            eprintln!(
                "ERROR: --dns system несовместим с --embedded: системный резолвер работает \
                 внешними программами, которым не поставить марку процесса, и запрос имени \
                 уйдёт тем же путём, что трафик человека. Используйте --dns doh."
            );
            std::process::exit(2);
        }
        blockcheckw::config::DnsMode::Auto => {
            eprintln!(
                "{}--embedded: режим DNS auto начинается с системного резолва внешней \
                 программой — беру doh, чтобы запрос имени нёс нашу марку",
                blockcheckw::ui::WARN,
            );
            blockcheckw::config::DnsMode::Doh
        }
        blockcheckw::config::DnsMode::Doh => mode,
    }
}

/// Return true if a named arg was explicitly provided on the command line.
fn is_explicit(matches: &clap::ArgMatches, id: &str) -> bool {
    matches.value_source(id) == Some(ValueSource::CommandLine)
}

/// Pick the effective value: CLI-explicit wins, then config, then clap default.
/// Returns owned String to avoid borrow conflicts with persisted config mutation.
fn resolve_str(
    matches: &clap::ArgMatches,
    id: &str,
    cli_val: &str,
    persisted: &Option<String>,
) -> String {
    if is_explicit(matches, id) {
        cli_val.to_string()
    } else {
        persisted.as_deref().unwrap_or(cli_val).to_string()
    }
}

/// For protocols: stored as Vec, CLI as comma-separated string.
fn resolve_protocols(
    matches: &clap::ArgMatches,
    cli_val: &str,
    persisted: &Option<Vec<String>>,
) -> String {
    if is_explicit(matches, "protocols") {
        cli_val.to_string()
    } else {
        persisted
            .as_ref()
            .map(|v| v.join(","))
            .unwrap_or_else(|| cli_val.to_string())
    }
}

fn resolve_u16(matches: &clap::ArgMatches, id: &str, cli_val: u16, persisted: Option<u16>) -> u16 {
    if is_explicit(matches, id) {
        cli_val
    } else {
        persisted.unwrap_or(cli_val)
    }
}

#[tokio::main]
async fn main() {
    // Panic hook: снять наши цепочки iptables (async-рантайм может быть мёртв — синхронно)
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        blockcheckw::network::via::Via::cleanup_sync();
        // Сносим ТОЛЬКО свои цепочки: метку выдаёт firewall-слой (#66). Таймаут внутри —
        // panic-хук без него уводил роутеры в перезагрузку.
        blockcheckw::firewall::rules::drop_chains_sync(
            &blockcheckw::firewall::ipt::SystemIptSync,
            &blockcheckw::firewall::rules::OwnedChainsMarker::planned(
                &blockcheckw::config::chain_prefix(),
            ),
        );
        default_hook(info);
    }));

    // Parse CLI: get both typed struct and raw matches (for value_source detection)
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    // --version: только версия. Обновления на Android приходят модулем через менеджер.
    if cli.version {
        println!("bcw v{}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // Без команды — печатаем справку и выходим. Это должно случиться до
    // require_root() и prereq-проверок: иначе голый `blockcheckw` поднимает
    // права через sudo и выдаёт диагностику окружения вместо help (#66).
    if cli.command.is_none() {
        let _ = Cli::command().print_help();
        println!();
        return;
    }

    // НА ANDROID ВСТРОЕННЫЙ РЕЖИМ ВСЕГДА: обходом владеет пользователь, чужие правила и
    // процессы не трогаются, контроль несёт собственную метку, вопросов нет, своя группа
    // процессов, свои остатки снимаются при входе, памяти прошлых запусков нет.
    let embedded = true;
    blockcheckw::nfqws2::mark::set_embedded(embedded);
    {
        let defaults = blockcheckw::config::Paths::default();
        blockcheckw::config::set_paths(blockcheckw::config::Paths {
            nfqws2: cli.nfqws2.clone().unwrap_or(defaults.nfqws2),
            lua_dir: cli.lua_dir.clone().unwrap_or(defaults.lua_dir),
            work_dir: cli.work_dir.clone().unwrap_or(defaults.work_dir),
        });
    }
    {
        let mut extra = Vec::with_capacity(cli.doh.len());
        for spec in &cli.doh {
            match blockcheckw::network::doh::parse_server(spec) {
                Ok(server) => extra.push(server),
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(2);
                }
            }
        }
        blockcheckw::network::doh::set_extra_servers(extra);
    }
    blockcheckw::machine::set_stream(cli.stream);
    blockcheckw::machine::set_progress(cli.progress);

    // Пространства имён ядра — от вызывающего, а не от умолчания: у него эти очереди, таблицы
    // и биты марки уже заняты, и заняты плотно.
    let mark_space = {
        let desync = match cli.mark_desync.as_deref().map(mark_space::parse_mark) {
            Some(Ok(value)) => value,
            Some(Err(e)) => {
                eprintln!("ERROR: --mark-desync: {e}");
                std::process::exit(2);
            }
            None => mark_space::DEFAULT_DESYNC_MARK,
        };
        let shift = cli
            .mark_profile_shift
            .unwrap_or(mark_space::DEFAULT_PROFILE_SHIFT);
        match mark_space::MarkSpace::new(desync, shift) {
            Ok(space) => space,
            Err(e) => {
                eprintln!("ERROR: раскладка марки непригодна: {e}");
                std::process::exit(2);
            }
        }
    };
    mark_space::set_space(mark_space);

    blockcheckw::config::set_kernel_keys(
        cli.qnum.unwrap_or(blockcheckw::config::DEFAULT_QNUM),
        cli.chain_prefix
            .as_deref()
            .unwrap_or(blockcheckw::config::DEFAULT_CHAIN_PREFIX),
        cli.smoke_qnum_base.unwrap_or(65_526),
    );
    // На Android маршрута «через шлюз» нет: netd решает маршрут по правилам fwmark,
    // и `ip route add` в основную таблицу ничего не меняет. Поэтому `--via` убран.

    // `doctor` сам проверяет root и отчитывается о нём — поднимать права до него незачем,
    // а замок, преflight и память прогона ему не нужны.
    if matches!(cli.command, Some(Command::Doctor)) {
        cmd::doctor::run_doctor_cmd().await;
    }

    blockcheckw::system::elevate::require_root();
    blockcheckw::system::elevate::raise_nofile_limit();
    let work_dir = blockcheckw::config::paths().work_dir;
    if let Err(e) = cmd::ensure_work_dir(&work_dir) {
        eprintln!(
            "ERROR: не удалось создать рабочий каталог {}: {e}",
            work_dir.display()
        );
        std::process::exit(2);
    }

    // `--workers` is global, but `check` verifies strategies sequentially by design —
    // warn (once, post-elevation) so users don't expect it to change `check` throughput (#33).
    if is_explicit(&matches, "workers") && matches!(cli.command, Some(Command::Check { .. })) {
        eprintln!(
            "{}--workers has no effect on `check` (it verifies strategies sequentially by design)",
            blockcheckw::ui::WARN,
        );
    }

    // Load persisted config
    let mut persisted = blockcheckw::persist::load();

    // Resolve effective workers (top-level arg)
    let eff_workers = resolve_u16(&matches, "workers", cli.workers, persisted.workers);
    if is_explicit(&matches, "workers") {
        persisted.workers = Some(cli.workers);
    }

    // #68: план не может обслужить больше проб в полёте, чем в нём загружено
    // профилей, а номер профиля не помещается в марку за потолком маски —
    // ловим здесь, на разборе аргументов, а не паникой в уже запущенном проце.
    //
    // Валидация аргументов обязана идти ДО любых побочных эффектов — в
    // частности, до `check_prerequisites` ниже, который живьём спавнит
    // nfqws2 (`smoke_sync`). Раньше проверка стояла после преflight'а: явно
    // мусорный `--profiles-per-instance` отвергался только после того, как
    // движок уже запускался и убивался вхолостую.
    if let Err(e) =
        blockcheckw::config::validate_parallelism(eff_workers as usize, cli.profiles_per_instance)
    {
        eprintln!("ERROR: {e}");
        std::process::exit(2);
    }

    // Pre-read stdin for check in pipe mode (before acquiring lock,
    // so the upstream pipe command can finish and release its lock first)
    let stdin_data = {
        use std::io::IsTerminal;
        if matches!(cli.command, Some(Command::Check { .. })) && !std::io::stdin().is_terminal() {
            Some(std::io::read_to_string(std::io::stdin()).unwrap_or_default())
        } else {
            None
        }
    };

    // Prevent parallel execution — keep _lock alive until process exits
    let _lock = cmd::acquire_instance_lock();

    // ВСТРОЕННЫЙ РЕЖИМ: своя группа процессов и снятие СВОИХ остатков.
    //
    // Оркестратор шлёт `SIGKILL`, по которому не отрабатывает ни один наш хук, — значит
    // прошлый прогон мог не убрать за собой ничего: на очереди остаётся движок, в ядре
    // таблица, и подбор слеп, а трафик человека стоит. Вход обязан быть идемпотентным, и
    // убирать он вправе только СВОЁ: чужое во встроенном режиме принадлежит вызывающему.
    //
    // Группа — чтобы `kill(-pgid)` снимал нас вместе с детьми одним вызовом. Отказ не
    // смертелен: детей всё равно снимет `PDEATHSIG`, и об отказе мы говорим вслух.
    if embedded {
        // На переднем плане терминала остаёмся в его группе: иначе `Ctrl+C` человека в
        // `su -c 'bcw scan | bcw check'` не дошёл бы до нас (review I6). Без терминала (экран
        // модуля) — своя группа для `kill(-pgid)`.
        let detach = blockcheckw::system::group::should_detach(
            blockcheckw::system::group::terminal_foreground_group(),
            blockcheckw::system::group::own_group(),
        );
        if detach {
            if let Err(e) = blockcheckw::system::group::detach_into_own_group() {
                eprintln!(
                    "{}не удалось уйти в свою группу процессов ({e}): оркестратору придётся бить \
                 по pid, дети снимутся PDEATHSIG",
                    blockcheckw::ui::WARN,
                );
            }
        }
        let defaults = blockcheckw::config::CoreConfig::default();
        let signature = blockcheckw::system::orphans::Signature {
            chain_prefix: defaults.chain_prefix.clone(),
            qnum: defaults.base_qnum,
            desync_mark: blockcheckw::nfqws2::mark::desync_mark(),
        };
        let swept = blockcheckw::system::orphans::sweep_own(
            &blockcheckw::firewall::ipt::SystemIpt,
            &signature,
        )
        .await;
        if !swept.is_empty() {
            eprintln!(
                "{}сняты остатки прошлого прогона: движков {}, цепочки {}",
                blockcheckw::ui::WARN,
                swept.killed.len(),
                if swept.chains_dropped {
                    "снесена"
                } else {
                    "чиста"
                },
            );
        }
    }

    // Status doesn't need nfqws2/nft — skip prereqs
    let prereq = if !matches!(cli.command, Some(Command::Status { .. })) {
        let console = blockcheckw::ui::Console::new();
        let prereq = cmd::check_prerequisites(&console);
        drop(console);
        Some(prereq)
    } else {
        None
    };

    // Init tracing: stderr-fmt всегда + OTLP-слой, если задан endpoint (feature otel).
    let otel_guard = tracing_otel::init();

    // Корневой span команды под родителем из TRACEPARENT (если демон прислал) —
    // так bcw.scan/bcw.check висят детьми selection-span'а демона.
    use tracing::Instrument;
    let cmd_name = match &cli.command {
        Some(Command::Scan { .. }) => "bcw.scan",
        Some(Command::Check { .. }) => "bcw.check",
        _ => "bcw.cmd",
    };
    let root = tracing::info_span!("bcw.root", cmd = cmd_name);
    tracing_otel::set_parent_from_env(&root);

    // Диспатч под bcw.root через .instrument, НЕ .enter(): держать enter-guard
    // через .await — анти-паттерн tracing. При поллинге фьючи на другом потоке
    // tokio thread-local «текущий span» теряется → bcw.scan/check рождаются
    // корнями, а потомки (baseline/protocol) разлетаются по отдельным trace_id.
    // .instrument перевходит в span на КАЖДЫЙ poll → потомки наследуют trace_id
    // bcw.root (единый trace и в standalone, без присланного родителя).
    async {
        match cli.command {
            Some(Command::Benchmark {
                time,
                max_workers,
                domain,
                protocol,
                raw,
            }) => {
                let sub = matches
                    .subcommand_matches("benchmark")
                    .expect("clap guarantees subcommand");
                let eff_domain = resolve_str(sub, "domain", &domain, &persisted.domain);

                if is_explicit(sub, "domain") {
                    persisted.domain = Some(domain.clone());
                }
                blockcheckw::persist::save(&persisted);

                cmd::benchmark::run_benchmark_cmd(
                    time,
                    max_workers,
                    &eff_domain,
                    &protocol,
                    raw,
                    cli.profiles_per_instance,
                    prereq
                        .as_ref()
                        .expect("benchmark requires prerequisites (skipped only for `status`)"),
                )
                .await;
            }
            Some(Command::Check {
                from_file,
                domain,
                dns,
                deadline,
                timeout,
                idle_ms,
                take,
                passes,
                reference_via,
                probe_path,
                identity_path,
                output,
            }) => {
                let sub = matches
                    .subcommand_matches("check")
                    .expect("clap guarantees subcommand");

                let eff_domain = resolve_str(sub, "domain", &domain, &persisted.domain);
                let eff_dns = resolve_str(sub, "dns", &dns, &persisted.dns);

                if is_explicit(sub, "domain") {
                    persisted.domain = Some(domain.clone());
                }
                if is_explicit(sub, "dns") {
                    persisted.dns = Some(dns.clone());
                }
                blockcheckw::persist::save(&persisted);

                // Determine input source: --from-file, pre-read stdin pipe, or error
                let (source, stdin_tmp) = if let Some(path) = from_file {
                    (path, None)
                } else if let Some(ref data) = stdin_data {
                    // Буфер — в каталоге прогона (рабочий каталог root, 0700): временного
                    // каталога на Android нет, а `/data/local/tmp` пишут все (review I3).
                    let tmp = cmd::stdin_buffer_path();
                    if let Err(e) = std::fs::write(&tmp, data) {
                        eprintln!("ERROR: cannot write temp file: {e}");
                        std::process::exit(1);
                    }
                    (tmp.to_string_lossy().into_owned(), Some(tmp))
                } else {
                    eprintln!("ERROR: no input — provide --from-file or pipe data to stdin");
                    std::process::exit(1);
                };

                let dns_mode = dns_mode_of(&eff_dns, embedded);

                let reference_via = reference_via.map(|raw| {
                    let v = blockcheckw::network::via::Via::parse(&raw).unwrap_or_else(|e| {
                        eprintln!("ERROR: --reference-via: {e}");
                        std::process::exit(1);
                    });
                    // Шлюз означал бы `ip route add`, а маршрутом на Android правит netd.
                    if !v.is_proxy() {
                        eprintln!(
                            "ERROR: --reference-via на Android — только прокси \
                             (socks5://host:port или host:port)"
                        );
                        std::process::exit(1);
                    }
                    v
                });

                cmd::check::run_check_cmd(cmd::check::CheckParams {
                    domain: &eff_domain,
                    from_file: &source,
                    dns_mode,
                    timeout,
                    idle_ms,
                    take,
                    deadline_secs: deadline,
                    passes,
                    output: output.as_deref(),
                    via: None,
                    reference_via: reference_via.as_ref(),
                    probe_path: &probe_path,
                    identity_path: &identity_path,
                    prereq: prereq
                        .as_ref()
                        .expect("check requires prerequisites (skipped only for `status`)"),
                })
                .await;

                // Clean up temp file from stdin pipe
                if let Some(tmp) = stdin_tmp {
                    let _ = std::fs::remove_file(tmp);
                }
            }
            Some(Command::Scan {
                domain,
                protocols,
                dns,
                timeout,
                top,
                output,
                from_file,
            }) => {
                let sub = matches
                    .subcommand_matches("scan")
                    .expect("clap guarantees subcommand");

                let eff_domain = resolve_str(sub, "domain", &domain, &persisted.domain);
                let eff_protocols = resolve_protocols(sub, &protocols, &persisted.protocols);
                let eff_dns = resolve_str(sub, "dns", &dns, &persisted.dns);

                if is_explicit(sub, "domain") {
                    persisted.domain = Some(domain.clone());
                }
                if is_explicit(sub, "protocols") {
                    persisted.protocols =
                        Some(protocols.split(',').map(|s| s.trim().to_string()).collect());
                }
                if is_explicit(sub, "dns") {
                    persisted.dns = Some(dns.clone());
                }
                blockcheckw::persist::save(&persisted);

                let protocols = match blockcheckw::config::parse_protocols(&eff_protocols) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("ERROR: {e}");
                        std::process::exit(1);
                    }
                };
                let dns_mode = dns_mode_of(&eff_dns, embedded);

                cmd::scan::run_scan(cmd::scan::ScanParams {
                    workers: eff_workers as usize,
                    profiles_per_instance: cli.profiles_per_instance,
                    domain: &eff_domain,
                    protocols: &protocols,
                    dns_mode,
                    timeout_secs: timeout,
                    top_n: top,
                    output: output.as_deref(),
                    from_file: from_file.as_deref(),
                    via: None,
                    alive_via: None,
                    prereq: prereq
                        .as_ref()
                        .expect("scan requires prerequisites (skipped only for `status`)"),
                })
                .await;
            }
            Some(Command::Universal {
                domain_list,
                protocols,
                dns,
                sample,
                output,
            }) => {
                let sub = matches
                    .subcommand_matches("universal")
                    .expect("clap guarantees subcommand");

                let eff_protocols = resolve_protocols(sub, &protocols, &persisted.protocols);
                let eff_dns = resolve_str(sub, "dns", &dns, &persisted.dns);

                if is_explicit(sub, "domain_list") {
                    persisted.domain_list = Some(domain_list.clone());
                }
                if is_explicit(sub, "protocols") {
                    persisted.protocols =
                        Some(protocols.split(',').map(|s| s.trim().to_string()).collect());
                }
                if is_explicit(sub, "dns") {
                    persisted.dns = Some(dns.clone());
                }
                blockcheckw::persist::save(&persisted);

                let protocols = match blockcheckw::config::parse_protocols(&eff_protocols) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("ERROR: {e}");
                        std::process::exit(1);
                    }
                };
                let dns_mode = dns_mode_of(&eff_dns, embedded);
                cmd::universal::run_universal(
                    eff_workers as usize,
                    cli.profiles_per_instance,
                    &domain_list,
                    &protocols,
                    dns_mode,
                    sample,
                    output.as_deref(),
                    None,
                    prereq
                        .as_ref()
                        .expect("universal requires prerequisites (skipped only for `status`)"),
                )
                .await;
            }
            Some(Command::Status {
                domain_list,
                dns,
                timeout,
                output,
            }) => {
                let sub = matches
                    .subcommand_matches("status")
                    .expect("clap guarantees subcommand");

                let eff_dns = resolve_str(sub, "dns", &dns, &persisted.dns);

                if is_explicit(sub, "dns") {
                    persisted.dns = Some(dns.clone());
                }
                blockcheckw::persist::save(&persisted);

                let dns_mode = dns_mode_of(&eff_dns, embedded);

                cmd::status::run_status_cmd(cmd::status::StatusParams {
                    domain_list: &domain_list,
                    dns_mode,
                    timeout,
                    output: output.as_deref(),
                    via: None,
                })
                .await;
            }
            Some(Command::Doctor) => unreachable!("doctor обрабатывается до elevation"),
            None => unreachable!("справка без команды печатается до elevation"),
        }
    }
    .instrument(root)
    .await;

    // bcw.root закрыт (.instrument уронил span по завершении фьючи). Принудительно
    // выгружаем OTLP-буфер до выхода (см. OtelGuard::shutdown). Без feature otel —
    // no-op. Пути std::process::exit (ошибки prereq) сюда не доходят — их span'ы не нужны.
    otel_guard.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--doh` повторяемый и глобальный: свои резолверы задаются там, где умолчания
    /// недоступны, и порядок их задания — порядок опроса.
    #[test]
    fn doh_flag_is_repeatable_and_global() {
        let cli = Cli::try_parse_from([
            "bcw",
            "scan",
            "--doh",
            "77.88.8.8",
            "--doh",
            "94.140.14.14:dns.adguard-dns.com",
        ])
        .expect("parse");
        assert_eq!(cli.doh, ["77.88.8.8", "94.140.14.14:dns.adguard-dns.com"]);
    }

    #[test]
    fn check_probe_path_defaults_to_root() {
        // Байтовая ось (главная, спека §6-тер) идёт по настоящему ресурсу: главный
        // вердикт от пути не зависит (DPI решает по SNI, до HTTP), а объём требует
        // реального содержимого, а не статичного файла.
        let cli =
            Cli::try_parse_from(["blockcheckw", "check", "--from-file", "v.json"]).expect("parse");
        match cli.command {
            Some(Command::Check { probe_path, .. }) => assert_eq!(probe_path, "/"),
            _ => panic!("expected Check command"),
        }
    }

    #[test]
    fn check_accepts_probe_path_flag() {
        let cli = Cli::try_parse_from([
            "blockcheckw",
            "check",
            "--from-file",
            "v.json",
            "--probe-path",
            "/forum/index.php",
        ])
        .expect("parse");
        match cli.command {
            Some(Command::Check { probe_path, .. }) => assert_eq!(probe_path, "/forum/index.php"),
            _ => panic!("expected Check command"),
        }
    }

    #[test]
    fn check_identity_path_defaults_to_robots_txt() {
        // Ось подлинности (побочная): детерминированный путь — умолчание, а не опция.
        // Только она может дать круг [Fate::Mirage] (спека §6-тер).
        let cli =
            Cli::try_parse_from(["blockcheckw", "check", "--from-file", "v.json"]).expect("parse");
        match cli.command {
            Some(Command::Check { identity_path, .. }) => assert_eq!(identity_path, "/robots.txt"),
            _ => panic!("expected Check command"),
        }
    }

    #[test]
    fn check_accepts_identity_path_flag() {
        let cli = Cli::try_parse_from([
            "blockcheckw",
            "check",
            "--from-file",
            "v.json",
            "--identity-path",
            "/static/manifest.json",
        ])
        .expect("parse");
        match cli.command {
            Some(Command::Check { identity_path, .. }) => {
                assert_eq!(identity_path, "/static/manifest.json")
            }
            _ => panic!("expected Check command"),
        }
    }

    #[test]
    fn check_passes_defaults_to_three() {
        // Умолчание несёт замер (спека §3): ядро устойчивости по трём одинаковым
        // прогонам на живой линии — 9 из 27, флап — 16 из 27.
        let cli =
            Cli::try_parse_from(["blockcheckw", "check", "--from-file", "v.json"]).expect("parse");
        match cli.command {
            Some(Command::Check { passes, .. }) => assert_eq!(passes, 3),
            _ => panic!("expected Check command"),
        }
    }

    #[test]
    fn check_accepts_passes_flag() {
        let cli = Cli::try_parse_from([
            "blockcheckw",
            "check",
            "--from-file",
            "v.json",
            "--passes",
            "5",
        ])
        .expect("parse");
        match cli.command {
            Some(Command::Check { passes, .. }) => assert_eq!(passes, 5),
            _ => panic!("expected Check command"),
        }
    }

    /// #68: `--profiles-per-instance` — глобальный флаг (как `--workers`), стоит
    /// ДО имени подкоманды. Ловит регресс, если кто-то случайно перенесёт его
    /// внутрь `Command::Scan` при рефакторинге — тогда этот же вызов перестал
    /// бы парситься.
    #[test]
    fn profiles_per_instance_parses_before_subcommand() {
        let cli = Cli::try_parse_from([
            "blockcheckw",
            "--profiles-per-instance",
            "256",
            "scan",
            "-d",
            "example.com",
        ])
        .expect("parse");
        assert_eq!(cli.profiles_per_instance, 256);
    }

    #[test]
    fn profiles_per_instance_defaults_to_254() {
        let cli = Cli::try_parse_from(["blockcheckw", "scan", "-d", "example.com"]).expect("parse");
        assert_eq!(cli.profiles_per_instance, 254);
    }

    #[test]
    fn workers_above_254_are_rejected() {
        assert!(Cli::try_parse_from(["blockcheckw", "-w", "255", "scan"]).is_err());
        assert!(Cli::try_parse_from(["blockcheckw", "-w", "254", "scan"]).is_ok());
    }

    #[test]
    fn mark_layout_keys_parse() {
        let cli = Cli::try_parse_from([
            "blockcheckw",
            "--mark-desync",
            "0x00200000",
            "--mark-profile-shift",
            "22",
            "scan",
        ])
        .expect("parse");
        assert_eq!(cli.mark_desync.as_deref(), Some("0x00200000"));
        assert_eq!(cli.mark_profile_shift, Some(22));
        assert!(Cli::try_parse_from(["blockcheckw", "--mark-base", "0x1", "scan"]).is_err());
    }
}
