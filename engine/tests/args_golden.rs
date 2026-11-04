//! Эталон аргументов nfqws2 для 28 пресетов `v0.1.0`: пресеты без `FOUND_*` обязаны собираться
//! байт-в-байт так же. `UPDATE_GOLDEN=1 cargo test --test args_golden` перезаписывает эталон.
//! Раскладка `/m`, `/d` не существует на диске — `$LISTS_DIR` раскрывается в путь модуля.

use std::path::PathBuf;

use blockcheckw::bypass::args::{build, ArgsInput};
use blockcheckw::bypass::layout::Layout;
use blockcheckw::bypass::preset::parse_preset;
use blockcheckw::bypass::settings::Settings;

#[test]
fn presets_without_found_match_v010() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let strategies = root.join("../module/strategies");
    let fixtures = root.join("tests/fixtures/args-v0.1.0");
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    if update {
        std::fs::create_dir_all(&fixtures).unwrap();
    }
    let layout = Layout {
        module_dir: "/m".into(),
        data_dir: "/d".into(),
    };
    let settings = Settings::default();
    let mut names: Vec<String> = std::fs::read_dir(&strategies)
        .unwrap()
        .filter_map(|e| {
            let n = e.unwrap().file_name().into_string().unwrap();
            n.strip_suffix(".conf").map(str::to_string)
        })
        .collect();
    names.sort();
    assert_eq!(names.len(), 28, "ожидалось 28 пресетов");
    for name in &names {
        let text = std::fs::read_to_string(strategies.join(format!("{name}.conf"))).unwrap();
        let preset = parse_preset(&text).unwrap();
        let mut out = String::new();
        for ipset in [true, false] {
            let args = build(&ArgsInput {
                preset: &preset,
                settings: &settings,
                layout: &layout,
                ipset_nonempty: ipset,
                calls_conf: "",
            })
            .unwrap();
            out.push_str(&format!("### ipset={ipset}\n{}\n", args.join("\n")));
        }
        let path = fixtures.join(format!("{name}.txt"));
        if update {
            std::fs::write(&path, &out).unwrap();
        } else {
            let want = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("нет эталона {}: {e}", path.display()));
            assert_eq!(out, want, "пресет {name} изменился относительно v0.1.0");
        }
    }
}
