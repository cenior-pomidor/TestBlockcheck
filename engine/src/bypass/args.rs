//! Командная строка nfqws2 обхода — как `_startup_args` nfqws2-android (`lib/common.sh:537–579`).
//! Эталон: `tests/fixtures/bypass/args.jsonl` (генератор `gen-args.sh`).

use super::layout::Layout;
use super::preset::Preset;
use super::settings::{ListMode, Settings};

// Сети Meta и Telegram для обхода звонков — копии из `lib/common.sh:64–69`.
pub const META_NET4: &str = "157.240.0.0/16 31.13.24.0/21 31.13.64.0/18 57.144.0.0/14 163.70.128.0/17 129.134.0.0/16 69.171.224.0/19 173.252.64.0/18 179.60.192.0/22 185.60.216.0/22 66.220.144.0/20 69.63.176.0/20 102.132.96.0/20 204.15.20.0/22 45.64.40.0/22";
pub const META_NET6: &str = "2a03:2880::/32";
pub const TG_NET4: &str = "91.105.192.0/23 91.108.4.0/22 91.108.8.0/22 91.108.12.0/22 91.108.16.0/22 91.108.20.0/22 91.108.56.0/22 95.161.64.0/20 149.154.160.0/20 185.76.151.0/24";
pub const TG_NET6: &str =
    "2001:67c:4e8::/48 2001:b28:f23c::/48 2001:b28:f23d::/48 2001:b28:f23f::/48 2a0a:f280::/32";

/// Что нужно для сборки командной строки.
pub struct ArgsInput<'a> {
    pub preset: &'a Preset,
    pub settings: &'a Settings,
    pub layout: &'a Layout,
    /// В `ipset.list` есть хоть одна строка (не пустая, не комментарий).
    pub ipset_nonempty: bool,
    /// Текст `defaults/calls-bypass.conf`; читает вызывающий.
    pub calls_conf: &'a str,
}

/// Раскрыть переменные пресета и нормализовать как `norm_args`.
pub fn expand(value: &str, layout: &Layout, settings: &Settings) -> String {
    let _ = settings;
    let v = value
        .replace("$MODE_AUTO", MODE_AUTO)
        .replace("$MODE_LIST", MODE_LIST)
        .replace("$MODE_ALL", MODE_ALL)
        .replace("$LUA_DIR", &layout.lua_dir().to_string_lossy())
        .replace("$BLOBS_DIR", &layout.blobs_dir().to_string_lossy())
        .replace("$LOG_DIR", &layout.logs_dir().to_string_lossy());
    norm_args(&resolve_lists(&v, layout))
}

const MODE_LIST: &str = "--hostlist=$LISTS_DIR/user.list";
const MODE_ALL: &str = "--hostlist-exclude=$LISTS_DIR/exclude.list";
const MODE_AUTO: &str = "--hostlist=$LISTS_DIR/user.list --hostlist-auto=$LISTS_DIR/auto.list \
                         --hostlist-auto-debug=$LOG_DIR/auto.log --hostlist-exclude=$LISTS_DIR/exclude.list";

/// `$LISTS_DIR/<файл>`: файл данных, если он есть, иначе файл модуля.
fn resolve_lists(v: &str, layout: &Layout) -> String {
    const TOKEN: &str = "$LISTS_DIR/";
    let mut out = String::with_capacity(v.len());
    let mut rest = v;
    while let Some(pos) = rest.find(TOKEN) {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + TOKEN.len()..];
        let end = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || "_.-".contains(c)))
            .unwrap_or(after.len());
        let name = &after[..end];
        let data = layout.data_lists().join(name);
        let path = if data.is_file() {
            data
        } else {
            layout.module_lists().join(name)
        };
        out.push_str(&path.to_string_lossy());
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// `norm_args` (`lib/common.sh:371`): строки-комментарии прочь, `\` прочь, пробелы сжать.
fn norm_args(v: &str) -> String {
    v.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| l.replace('\\', ""))
        .flat_map(|l| l.split_whitespace().map(str::to_string).collect::<Vec<_>>())
        .collect::<Vec<_>>()
        .join(" ")
}

fn calls_args(conf: &str) -> String {
    let meta = format!("{META_NET4} {META_NET6}").replace(' ', ",");
    let tg = format!("{TG_NET4} {TG_NET6}").replace(' ', ",");
    norm_args(&conf.replace("@META@", &meta).replace("@TG@", &tg))
}

/// Собрать аргументы nfqws2.
pub fn build(input: &ArgsInput) -> Result<Vec<String>, String> {
    let (s, l) = (input.settings, input.layout);
    let x = |v: &str| expand(v, l, s);
    let p = input.preset;
    let (base, tcp, quic, udp, custom) =
        (x(&p.base), x(&p.tcp), x(&p.quic), x(&p.udp), x(&p.custom));
    let ipset = if input.ipset_nonempty {
        x(&p.ipset)
    } else {
        String::new()
    };
    let extra = x(match s.mode {
        ListMode::List => "$MODE_LIST",
        ListMode::All => "$MODE_ALL",
        ListMode::Auto => "$MODE_AUTO",
    });
    let logs = l.logs_dir();
    let log = if s.log_level == 1 {
        "nfqws2-debug.log"
    } else {
        "nfqws2.log"
    };
    let mut a: Vec<String> = vec![
        format!("--debug=@{}", logs.join(log).display()),
        "--user=root".into(),
        format!("--qnum={}", super::QNUM),
    ];
    let mut push = |text: &str| a.extend(text.split_whitespace().map(str::to_string));
    push(&base);
    if s.calls_bypass && !input.calls_conf.trim().is_empty() {
        let blobs = l.blobs_dir();
        push(&format!(
            "--blob=calls_stun:@{}/stun.bin --blob=calls_tls:@{}/tls_clienthello.bin {} --new",
            blobs.display(),
            blobs.display(),
            calls_args(input.calls_conf)
        ));
    }
    if !custom.is_empty() {
        push(&format!("{custom} --new"));
    }
    if !udp.is_empty() {
        push(&format!("{udp} --new"));
    }
    if !quic.is_empty() && !s.block_quic {
        if !ipset.is_empty() {
            push(&format!("{quic} {ipset} --ipset-ip=0.0.0.0 --new"));
        }
        push(&format!("{quic} {extra} --new"));
    }
    if !ipset.is_empty() {
        push(&format!("{tcp} {ipset} --ipset-ip=0.0.0.0 --new"));
    }
    push(&format!("{tcp} {extra}"));
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bypass::preset::parse_preset;

    fn normalize(args: &[String]) -> Vec<String> {
        args.iter()
            .map(|a| {
                a.replace("<DATA>/lists/", "<LISTS>/")
                    .replace("<MOD>/lists/", "<LISTS>/")
            })
            .collect()
    }

    #[test]
    fn args_match_upstream_golden() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../module");
        let calls = std::fs::read_to_string(format!("{root}/defaults/calls-bypass.conf")).unwrap();
        let layout = Layout {
            module_dir: "<MOD>".into(),
            data_dir: "<DATA>".into(),
        };
        let golden = include_str!("../../tests/fixtures/bypass/args.jsonl");
        let mut n = 0;
        for line in golden.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let name = v["preset"].as_str().unwrap();
            let text = std::fs::read_to_string(format!("{root}/strategies/{name}.conf")).unwrap();
            let preset = parse_preset(&text).unwrap();
            let mut s = Settings::default();
            s.set("MODE", v["mode"].as_str().unwrap()).unwrap();
            s.block_quic = v["block_quic"] == 1;
            s.calls_bypass = v["calls"] == 1;
            let want: Vec<String> = v["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap().to_string())
                .collect();
            let got = build(&ArgsInput {
                preset: &preset,
                settings: &s,
                layout: &layout,
                ipset_nonempty: v["ipset"] == 1,
                calls_conf: &calls,
            })
            .unwrap();
            let (got, want) = (normalize(&got), normalize(&want));
            if got != want {
                let i = got
                    .iter()
                    .zip(&want)
                    .position(|(a, b)| a != b)
                    .unwrap_or(got.len().min(want.len()));
                panic!(
                    "{name} {}: расхождение в аргументе {i}: получено {:?}, ожидалось {:?} (длины {} / {})",
                    line.split("\"args\"").next().unwrap(),
                    got.get(i),
                    want.get(i),
                    got.len(),
                    want.len()
                );
            }
            n += 1;
        }
        assert_eq!(n, 672);
    }

    #[test]
    fn log_level_one_uses_debug_file() {
        let layout = Layout {
            module_dir: "/m".into(),
            data_dir: "/d".into(),
        };
        let preset = parse_preset("NFQWS_ARGS=\"--filter-tcp=443\"\n").unwrap();
        let mut s = Settings::default();
        s.log_level = 1;
        let a = build(&ArgsInput {
            preset: &preset,
            settings: &s,
            layout: &layout,
            ipset_nonempty: false,
            calls_conf: "",
        })
        .unwrap();
        assert_eq!(a[0], "--debug=@/d/logs/nfqws2-debug.log");
    }

    #[test]
    fn data_list_wins_over_module_list() {
        let dir = std::env::temp_dir().join(format!("bcw-args-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("data/lists")).unwrap();
        std::fs::write(dir.join("data/lists/youtube.list"), "x\n").unwrap();
        let layout = Layout {
            module_dir: dir.join("mod"),
            data_dir: dir.join("data"),
        };
        let s = Settings::default();
        let e = expand(
            "--hostlist=$LISTS_DIR/youtube.list --hostlist=$LISTS_DIR/google.list",
            &layout,
            &s,
        );
        assert!(
            e.contains(&format!("{}/data/lists/youtube.list", dir.display())),
            "{e}"
        );
        assert!(
            e.contains(&format!("{}/mod/lists/google.list", dir.display())),
            "{e}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
