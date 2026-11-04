//! Применение найденного пресета к текущей сети, проверка через обход и полный откат
//! по журналу `undo.json` (спека §6, п. 2–6).
#![allow(async_fn_in_trait)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::assemble::preset_text;
use super::runs::{read_undo, write_undo, Undo};
use super::{Found, Group, Outcome, Proto};
use crate::bypass::settings::{ListMode, Settings};
use crate::bypass::store::Store;
use crate::bypass::supervisor::Status;

/// Связь со службой обхода.
pub trait SvcLink {
    async fn status(&self) -> Option<Status>;
    async fn reload(&self) -> Result<(), String>;
}

/// Проверка домена через работающий обход (без метки, как F12).
pub trait Verifier {
    async fn through_bypass(&self, domain: &str, p: Proto) -> bool;
}

/// Что применять. Текст пресета собирается здесь из основы и `found`, чтобы при частичном
/// провале пересобрать его без строк провалившейся группы.
pub struct Plan {
    pub dir: PathBuf,
    pub network_key: String,
    pub network_title: String,
    pub preset: String,
    pub found: Found,
    pub base_text: String,
    pub header: String,
    pub general_blocked: Vec<String>,
    pub checks: Vec<(Group, String, Proto)>,
    pub enable_net_strategy: bool,
}

/// Опрос службы при ожидании новой стратегии.
const POLL: Duration = Duration::from_millis(500);

pub async fn apply<S: SvcLink, V: Verifier>(
    store: &Store,
    svc: &S,
    v: &V,
    plan: &Plan,
    wait: Duration,
) -> Outcome {
    // п. 2: журнал отмены — до любых изменений.
    let (settings, _) = store.settings();
    let (nets, _) = store.networks();
    let prev = nets.iter().find(|n| n.key == plan.network_key);
    let lists_used = settings.mode != ListMode::All;
    let user = if lists_used {
        match store.read_list("user") {
            Ok(t) => t,
            Err(e) => return nothing_changed(e),
        }
    } else {
        String::new()
    };
    let added = if lists_used {
        missing_lines(&user, &plan.general_blocked)
    } else {
        Vec::new()
    };
    let mut undo = Undo {
        network_key: plan.network_key.clone(),
        prev_strategy: prev.map(|n| n.strategy.clone()),
        network_title: prev
            .map(|n| n.title.clone())
            .unwrap_or_else(|| plan.network_title.clone()),
        prev_net_strategy: settings.net_strategy,
        preset: plan.preset.clone(),
        added_user_lines: added.clone(),
        user_list_no_eol: !added.is_empty() && !user.is_empty() && !user.ends_with('\n'),
        finished: false,
    };
    if let Err(e) = write_undo(&plan.dir, &undo) {
        return nothing_changed(format!("не записан журнал отмены: {e}"));
    }

    // п. 3: применение.
    let text = preset_text(&plan.base_text, &plan.found, &plan.header);
    if let Err(e) = change(store, plan, &settings, &user, &added, &text) {
        return fail(store, svc, &plan.dir, format!("не удалось применить: {e}")).await;
    }
    if let Err(e) = restart(svc, &plan.preset, wait).await {
        return fail(store, svc, &plan.dir, e).await;
    }

    // п. 4–5: проверка через обход.
    let mut groups: Vec<Group> = Vec::new();
    for (g, _, _) in &plan.checks {
        if !groups.contains(g) {
            groups.push(*g);
        }
    }
    let mut failed = Vec::new();
    for g in &groups {
        if !group_ok(v, plan, *g).await {
            failed.push(*g);
        }
    }
    match (groups.as_slice(), failed.as_slice()) {
        (_, []) => {
            finish(&plan.dir, &mut undo);
            Outcome::Applied
        }
        ([_, _], [f]) => {
            let f = *f;
            let passed = if f == Group::General {
                Group::Youtube
            } else {
                Group::General
            };
            let mut found = plan.found.clone();
            match f {
                Group::General => {
                    found.tls = None;
                    found.http = None;
                }
                Group::Youtube => found.youtube = None,
            }
            let text = preset_text(&plan.base_text, &found, &plan.header);
            if let Err(e) = store.save_preset(&plan.preset, &text) {
                return fail(
                    store,
                    svc,
                    &plan.dir,
                    format!("пресет не пересохранён: {e}"),
                )
                .await;
            }
            if let Err(e) = restart(svc, &plan.preset, wait).await {
                return fail(store, svc, &plan.dir, e).await;
            }
            if group_ok(v, plan, passed).await {
                finish(&plan.dir, &mut undo);
                Outcome::Partial { failed: f }
            } else {
                fail(
                    store,
                    svc,
                    &plan.dir,
                    format!(
                        "группа «{}» не прошла повторную проверку через обход",
                        group_title(passed)
                    ),
                )
                .await
            }
        }
        _ => {
            fail(
                store,
                svc,
                &plan.dir,
                "проверка через обход не прошла".to_string(),
            )
            .await
        }
    }
}

/// Полный откат по `undo.json` (п. 6). Повторный вызов ничего не меняет. При ошибке отметка
/// завершения не ставится — откат можно довести позже.
pub async fn rollback<S: SvcLink>(store: &Store, svc: &S, dir: &Path) -> Result<(), String> {
    let mut u = read_undo(dir).ok_or_else(|| "нет журнала отмены undo.json".to_string())?;
    let mut errs: Vec<String> = Vec::new();

    let (nets, _) = store.networks();
    let cur = nets.iter().find(|n| n.key == u.network_key);
    let r = match (&u.prev_strategy, cur) {
        (Some(p), Some(c)) if c.strategy == *p && c.title == u.network_title => Ok(()),
        (Some(p), _) => store.put_network_entry(&u.network_key, &u.network_title, p),
        (None, Some(_)) => store.delete_network(&u.network_key),
        (None, None) => Ok(()),
    };
    if let Err(e) = r {
        errs.push(format!("networks.tsv: {e}"));
    }

    if store.preset_text(&u.preset).is_ok() {
        if let Err(e) = store.delete_preset(&u.preset) {
            errs.push(e);
        }
    }

    if !u.added_user_lines.is_empty() {
        match store.read_list("user") {
            Ok(t) => {
                let back = remove_lines(&t, &u.added_user_lines, u.user_list_no_eol);
                if back != t {
                    if let Err(e) = store.write_list("user", &back) {
                        errs.push(format!("user.list: {e}"));
                    }
                }
            }
            Err(e) => errs.push(e),
        }
    }

    let (mut st, _) = store.settings();
    if st.net_strategy != u.prev_net_strategy {
        st.net_strategy = u.prev_net_strategy;
        if let Err(e) = store.save_settings(&st) {
            errs.push(format!("настройки: {e}"));
        }
    }

    if !errs.is_empty() {
        return Err(errs.join("; "));
    }
    u.finished = true;
    write_undo(dir, &u).map_err(|e| format!("undo.json: {e}"))?;
    svc.reload().await
}

fn nothing_changed(reason: String) -> Outcome {
    Outcome::RolledBack {
        reason: format!("{reason}; ничего не изменено"),
    }
}

/// Изменения п. 3, кроме уведомления службы.
fn change(
    store: &Store,
    plan: &Plan,
    settings: &Settings,
    user: &str,
    added: &[String],
    text: &str,
) -> Result<(), String> {
    store.save_preset(&plan.preset, text)?;
    if !added.is_empty() {
        store.write_list("user", &append_lines(user, added))?;
    }
    if plan.enable_net_strategy && !settings.net_strategy {
        let mut s = settings.clone();
        s.net_strategy = true;
        store.save_settings(&s).map_err(|e| e.to_string())?;
    }
    store
        .put_network_entry(&plan.network_key, &plan.network_title, &plan.preset)
        .map_err(|e| e.to_string())
}

/// Уведомить службу и дождаться `running` с пресетом. Запасная стратегия (`last_good`)
/// или срок — провал.
async fn restart<S: SvcLink>(svc: &S, preset: &str, wait: Duration) -> Result<(), String> {
    svc.reload()
        .await
        .map_err(|e| format!("служба не уведомлена: {e}"))?;
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        if let Some(st) = svc.status().await {
            if st.state == "running" && st.strategy.as_deref() == Some(preset) {
                return Ok(());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "служба не перешла на «{preset}» за {} с",
                wait.as_secs()
            ));
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Группа прошла, если прошли все её проверки.
async fn group_ok<V: Verifier>(v: &V, plan: &Plan, g: Group) -> bool {
    for (cg, domain, p) in &plan.checks {
        if *cg == g && !v.through_bypass(domain, *p).await {
            return false;
        }
    }
    true
}

fn group_title(g: Group) -> &'static str {
    match g {
        Group::General => "Общие",
        Group::Youtube => "YouTube",
    }
}

async fn fail<S: SvcLink>(store: &Store, svc: &S, dir: &Path, reason: String) -> Outcome {
    match rollback(store, svc, dir).await {
        Ok(()) => Outcome::RolledBack { reason },
        Err(e) => Outcome::RolledBack {
            reason: format!("{reason}; откат: {e}"),
        },
    }
}

fn finish(dir: &Path, undo: &mut Undo) {
    undo.finished = true;
    if let Err(e) = write_undo(dir, undo) {
        tracing::warn!("undo.json: отметка завершения не записана: {e}");
    }
}

/// Сравнение строк `user.list`: без регистра и окружающих пробелов.
fn norm(line: &str) -> String {
    line.trim().to_lowercase()
}

/// Домены, которых нет в списке, в нижнем регистре и без повторов.
fn missing_lines(list: &str, blocked: &[String]) -> Vec<String> {
    let have: Vec<String> = list.lines().map(norm).collect();
    let mut out: Vec<String> = Vec::new();
    for d in blocked {
        let d = norm(d);
        if !d.is_empty() && !have.contains(&d) && !out.contains(&d) {
            out.push(d);
        }
    }
    out
}

/// Дописать строки, не склеивая с последней строкой без перевода строки.
fn append_lines(list: &str, add: &[String]) -> String {
    let mut out = list.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for l in add {
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// Убрать добавленные строки; остальное, с окончаниями строк, — как было. Если до добавления
/// не было завершающего перевода строки и удалён хвост файла — убрать и вставленный `\n`.
fn remove_lines(list: &str, added: &[String], no_eol: bool) -> String {
    let mut out = String::new();
    let mut tail_removed = false;
    for seg in list.split_inclusive('\n') {
        tail_removed = added.contains(&norm(seg));
        if !tail_removed {
            out.push_str(seg);
        }
    }
    if no_eol && tail_removed && out.ends_with('\n') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bypass::layout::Layout;
    use std::collections::{HashMap, VecDeque};
    use std::fs;
    use std::sync::Mutex;

    const PRESET: &str = "found-alt-20261104-1946";
    const KEY: &str = "wifi:home";
    const WAIT: Duration = Duration::from_secs(20);

    fn copy_dir(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for e in fs::read_dir(from).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if p.is_dir() {
                copy_dir(&p, &to.join(e.file_name()));
            } else {
                fs::copy(&p, to.join(e.file_name())).unwrap();
            }
        }
    }

    /// Временный модуль и данные; каталог прогона — `root/run`.
    fn store(tag: &str) -> (Store, PathBuf) {
        let root = std::env::temp_dir().join(format!("bcw-apply-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let module = Path::new(env!("CARGO_MANIFEST_DIR")).join("../module");
        for d in ["strategies", "defaults"] {
            copy_dir(&module.join(d), &root.join("mod").join(d));
        }
        let s = Store::new(Layout {
            module_dir: root.join("mod"),
            data_dir: root.join("data"),
        });
        s.init_data_dir().unwrap();
        fs::create_dir_all(root.join("run")).unwrap();
        (s, root)
    }

    fn plan(root: &Path) -> Plan {
        Plan {
            dir: root.join("run"),
            network_key: KEY.into(),
            network_title: "Wi-Fi «Home»".into(),
            preset: PRESET.into(),
            found: Found {
                youtube: Some("--lua-desync=fake:blob=fake_default_tls".into()),
                tls: Some("--lua-desync=multisplit:pos=1".into()),
                http: Some("--lua-desync=fake:blob=fake_default_http".into()),
            },
            base_text: "NFQWS_ARGS=\"--filter-tcp=443 --x\"\n".into(),
            header: "Найдено поиском".into(),
            general_blocked: vec!["rutracker.org".into()],
            checks: vec![
                (Group::General, "rutracker.org".into(), Proto::Tls13),
                (Group::General, "rutracker.org".into(), Proto::Http),
                (Group::Youtube, "www.youtube.com".into(), Proto::Tls13),
            ],
            enable_net_strategy: false,
        }
    }

    fn st(state: &str, strategy: &str) -> Option<Status> {
        Some(Status {
            state: state.into(),
            reason: None,
            network_key: Some(KEY.into()),
            network_title: None,
            strategy: Some(strategy.into()),
        })
    }

    /// Что видно в момент `reload`: журнал и `networks.tsv`.
    type Seen = (Option<Undo>, String);

    struct FakeSvc {
        script: Mutex<VecDeque<Option<Status>>>,
        reloads: Mutex<u32>,
        dir: PathBuf,
        nets: PathBuf,
        seen: Mutex<Vec<Seen>>,
    }

    impl FakeSvc {
        fn new(store: &Store, root: &Path, script: Vec<Option<Status>>) -> FakeSvc {
            FakeSvc {
                script: Mutex::new(script.into()),
                reloads: Mutex::new(0),
                dir: root.join("run"),
                nets: store.layout.networks_file(),
                seen: Mutex::new(Vec::new()),
            }
        }
        fn reloads(&self) -> u32 {
            *self.reloads.lock().unwrap()
        }
    }

    impl SvcLink for FakeSvc {
        async fn status(&self) -> Option<Status> {
            let mut s = self.script.lock().unwrap();
            if s.len() > 1 {
                s.pop_front().unwrap()
            } else {
                s.front().cloned().flatten()
            }
        }
        async fn reload(&self) -> Result<(), String> {
            *self.reloads.lock().unwrap() += 1;
            self.seen.lock().unwrap().push((
                read_undo(&self.dir),
                fs::read_to_string(&self.nets).unwrap_or_default(),
            ));
            Ok(())
        }
    }

    /// Ответы по (домен, протокол): очередь, последний повторяется; по умолчанию `true`.
    #[derive(Default)]
    struct FakeVerifier {
        table: Mutex<HashMap<(String, Proto), VecDeque<bool>>>,
        calls: Mutex<HashMap<(String, Proto), u32>>,
    }

    impl FakeVerifier {
        fn with(rows: &[(&str, Proto, &[bool])]) -> FakeVerifier {
            let v = FakeVerifier::default();
            for (d, p, r) in rows {
                v.table
                    .lock()
                    .unwrap()
                    .insert((d.to_string(), *p), r.iter().copied().collect());
            }
            v
        }
        fn calls(&self, d: &str, p: Proto) -> u32 {
            *self
                .calls
                .lock()
                .unwrap()
                .get(&(d.to_string(), p))
                .unwrap_or(&0)
        }
    }

    impl Verifier for FakeVerifier {
        async fn through_bypass(&self, domain: &str, p: Proto) -> bool {
            let k = (domain.to_string(), p);
            *self.calls.lock().unwrap().entry(k.clone()).or_default() += 1;
            let mut t = self.table.lock().unwrap();
            match t.get_mut(&k) {
                Some(q) if q.len() > 1 => q.pop_front().unwrap(),
                Some(q) => *q.front().unwrap_or(&true),
                None => true,
            }
        }
    }

    fn nets_text(s: &Store) -> String {
        fs::read_to_string(s.layout.networks_file()).unwrap_or_default()
    }

    fn strategy_of(s: &Store, key: &str) -> Option<String> {
        s.networks()
            .0
            .into_iter()
            .find(|n| n.key == key)
            .map(|n| n.strategy)
    }

    #[tokio::test(start_paused = true)]
    async fn undo_written_first() {
        let (s, root) = store("undo-first");
        s.set_network_entry(KEY, "Home", "alt").unwrap();
        let svc = FakeSvc::new(&s, &root, vec![st("running", PRESET)]);
        let mut p = plan(&root);
        // rutracker.org уже есть в списке по умолчанию — добавится только второй.
        p.general_blocked = vec!["rutracker.org".into(), "Example-Blocked.test".into()];
        let out = apply(&s, &svc, &FakeVerifier::default(), &p, WAIT).await;
        assert_eq!(out, Outcome::Applied);
        let seen = svc.seen.lock().unwrap();
        let (u, nets) = &seen[0];
        let u = u.as_ref().expect("undo.json до уведомления службы");
        assert_eq!(u.prev_strategy.as_deref(), Some("alt"));
        assert_eq!(u.network_title, "Home");
        assert_eq!(u.network_key, KEY);
        assert_eq!(u.preset, PRESET);
        assert!(!u.prev_net_strategy && !u.finished);
        assert_eq!(u.added_user_lines, ["example-blocked.test"]);
        assert!(nets.contains(PRESET));
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn undo_fail_changes_nothing() {
        let (s, root) = store("undo-fail");
        s.set_network_entry(KEY, "Home", "alt").unwrap();
        let before = nets_text(&s);
        let user = s.read_list("user").unwrap();
        let svc = FakeSvc::new(&s, &root, vec![st("running", PRESET)]);
        let mut p = plan(&root);
        p.dir = root.join("no").join("such");
        let out = apply(&s, &svc, &FakeVerifier::default(), &p, WAIT).await;
        assert!(matches!(out, Outcome::RolledBack { .. }), "{out:?}");
        assert_eq!(nets_text(&s), before);
        assert_eq!(s.read_list("user").unwrap(), user);
        assert!(s.load_preset(PRESET).is_err());
        assert_eq!(svc.reloads(), 0);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn apply_ok() {
        let (s, root) = store("ok");
        s.set_network_entry(KEY, "Home", "alt").unwrap();
        let svc = FakeSvc::new(
            &s,
            &root,
            vec![None, st("starting", "alt"), st("running", PRESET)],
        );
        let p = plan(&root);
        let out = apply(&s, &svc, &FakeVerifier::default(), &p, WAIT).await;
        assert_eq!(out, Outcome::Applied);
        assert_eq!(strategy_of(&s, KEY).as_deref(), Some(PRESET));
        let pr = s.load_preset(PRESET).unwrap();
        assert_eq!(pr.found_tls, "--lua-desync=multisplit:pos=1");
        assert_eq!(pr.found_youtube, "--lua-desync=fake:blob=fake_default_tls");
        assert!(read_undo(&p.dir).unwrap().finished);
        assert_eq!(svc.reloads(), 1);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn user_list_add_exact() {
        let (s, root) = store("user-add");
        let mut st0 = s.settings().0;
        st0.mode = ListMode::Auto;
        s.save_settings(&st0).unwrap();
        s.write_list("user", "a.com").unwrap();
        let svc = FakeSvc::new(&s, &root, vec![st("running", PRESET)]);
        let mut p = plan(&root);
        p.general_blocked = vec![
            "A.com".into(),
            "rutracker.org".into(),
            " RuTracker.org ".into(),
        ];
        let out = apply(&s, &svc, &FakeVerifier::default(), &p, WAIT).await;
        assert_eq!(out, Outcome::Applied);
        assert_eq!(s.read_list("user").unwrap(), "a.com\nrutracker.org\n");
        assert_eq!(
            read_undo(&p.dir).unwrap().added_user_lines,
            ["rutracker.org"]
        );

        // MODE=all: списки не применяются, файл не трогаем.
        let (s, root2) = store("user-all");
        let mut st0 = s.settings().0;
        st0.mode = ListMode::All;
        s.save_settings(&st0).unwrap();
        s.write_list("user", "a.com").unwrap();
        let svc = FakeSvc::new(&s, &root2, vec![st("running", PRESET)]);
        let mut p = plan(&root2);
        p.general_blocked = vec!["A.com".into(), "rutracker.org".into()];
        let out = apply(&s, &svc, &FakeVerifier::default(), &p, WAIT).await;
        assert_eq!(out, Outcome::Applied);
        assert_eq!(s.read_list("user").unwrap(), "a.com");
        assert!(read_undo(&p.dir).unwrap().added_user_lines.is_empty());
        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(root2).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn net_strategy_on() {
        let (s, root) = store("net-on");
        let mut st0 = s.settings().0;
        st0.net_strategy = false;
        s.save_settings(&st0).unwrap();
        let svc = FakeSvc::new(&s, &root, vec![st("running", PRESET)]);
        let mut p = plan(&root);
        p.enable_net_strategy = true;
        let out = apply(&s, &svc, &FakeVerifier::default(), &p, WAIT).await;
        assert_eq!(out, Outcome::Applied);
        assert!(s.settings().0.net_strategy);
        rollback(&s, &svc, &p.dir).await.unwrap();
        assert!(!s.settings().0.net_strategy);
        assert_eq!(strategy_of(&s, KEY), None);
        assert!(read_undo(&p.dir).unwrap().finished);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn svc_fallback_is_failure() {
        let (s, root) = store("fallback");
        s.set_network_entry(KEY, "Home", "alt").unwrap();
        let svc = FakeSvc::new(&s, &root, vec![st("running", "default")]);
        let p = plan(&root);
        let t0 = tokio::time::Instant::now();
        let out = apply(&s, &svc, &FakeVerifier::default(), &p, WAIT).await;
        assert!(matches!(out, Outcome::RolledBack { .. }), "{out:?}");
        assert!(t0.elapsed() >= WAIT);
        assert_eq!(strategy_of(&s, KEY).as_deref(), Some("alt"));
        assert!(s.load_preset(PRESET).is_err());
        // Уведомление при применении и после отката.
        assert_eq!(svc.reloads(), 2);
        assert!(read_undo(&p.dir).unwrap().finished);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn partial() {
        let (s, root) = store("partial");
        s.set_network_entry(KEY, "Home", "alt").unwrap();
        let svc = FakeSvc::new(&s, &root, vec![st("running", PRESET)]);
        let v = FakeVerifier::with(&[
            ("rutracker.org", Proto::Tls13, &[false]),
            ("rutracker.org", Proto::Http, &[true]),
            ("www.youtube.com", Proto::Tls13, &[true]),
        ]);
        let p = plan(&root);
        let out = apply(&s, &svc, &v, &p, WAIT).await;
        assert_eq!(
            out,
            Outcome::Partial {
                failed: Group::General
            }
        );
        let pr = s.load_preset(PRESET).unwrap();
        assert_eq!(pr.found_tls, "");
        assert_eq!(pr.found_http, "");
        assert_eq!(pr.found_youtube, "--lua-desync=fake:blob=fake_default_tls");
        assert_eq!(svc.reloads(), 2);
        assert_eq!(v.calls("www.youtube.com", Proto::Tls13), 2);
        assert_eq!(strategy_of(&s, KEY).as_deref(), Some(PRESET));
        assert!(read_undo(&p.dir).unwrap().finished);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn partial_youtube_failed() {
        let (s, root) = store("partial-yt");
        let svc = FakeSvc::new(&s, &root, vec![st("running", PRESET)]);
        let v = FakeVerifier::with(&[("www.youtube.com", Proto::Tls13, &[false])]);
        let p = plan(&root);
        let out = apply(&s, &svc, &v, &p, WAIT).await;
        assert_eq!(
            out,
            Outcome::Partial {
                failed: Group::Youtube
            }
        );
        let pr = s.load_preset(PRESET).unwrap();
        assert_eq!(pr.found_youtube, "");
        assert_eq!(pr.found_tls, "--lua-desync=multisplit:pos=1");
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn partial_then_fail() {
        let (s, root) = store("partial-fail");
        s.set_network_entry(KEY, "Home", "alt").unwrap();
        let svc = FakeSvc::new(&s, &root, vec![st("running", PRESET)]);
        let v = FakeVerifier::with(&[
            ("rutracker.org", Proto::Tls13, &[false]),
            ("www.youtube.com", Proto::Tls13, &[true, false]),
        ]);
        let p = plan(&root);
        let out = apply(&s, &svc, &v, &p, WAIT).await;
        assert!(matches!(out, Outcome::RolledBack { .. }), "{out:?}");
        assert_eq!(strategy_of(&s, KEY).as_deref(), Some("alt"));
        assert!(s.load_preset(PRESET).is_err());
        assert_eq!(svc.reloads(), 3);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn single_group_failed_rolls_back() {
        let (s, root) = store("single");
        let svc = FakeSvc::new(&s, &root, vec![st("running", PRESET)]);
        let v = FakeVerifier::with(&[("rutracker.org", Proto::Tls13, &[false])]);
        let mut p = plan(&root);
        p.checks.retain(|c| c.0 == Group::General);
        let out = apply(&s, &svc, &v, &p, WAIT).await;
        assert!(matches!(out, Outcome::RolledBack { .. }), "{out:?}");
        assert_eq!(strategy_of(&s, KEY), None);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn rollback_restores() {
        // Запись сети была (в середине файла), user.list без завершающего \n и с \r\n.
        let (s, root) = store("restore");
        let nets0 = "x\tX\talt4\nwifi:home\tHome\talt\nz\tZ\tdefault\n";
        fs::write(s.layout.networks_file(), nets0).unwrap();
        let user0 = "# мой\r\nB.org\r\na.com";
        s.write_list("user", user0).unwrap();
        let settings0 = fs::read_to_string(s.layout.settings_file()).unwrap();
        let svc = FakeSvc::new(&s, &root, vec![st("running", PRESET)]);
        let mut p = plan(&root);
        p.enable_net_strategy = true;
        p.general_blocked = vec![
            "a.com".into(),
            "rutracker.org".into(),
            "b.ORG ".into(),
            "New.net".into(),
        ];
        let out = apply(&s, &svc, &FakeVerifier::default(), &p, WAIT).await;
        assert_eq!(out, Outcome::Applied);
        assert_eq!(
            s.read_list("user").unwrap(),
            "# мой\r\nB.org\r\na.com\nrutracker.org\nnew.net\n"
        );
        rollback(&s, &svc, &p.dir).await.unwrap();
        assert_eq!(nets_text(&s), nets0);
        assert_eq!(s.read_list("user").unwrap(), user0);
        assert_eq!(
            fs::read_to_string(s.layout.settings_file()).unwrap(),
            settings0
        );
        assert!(s.load_preset(PRESET).is_err());
        let undo1 = read_undo(&p.dir).unwrap();
        assert!(undo1.finished);
        // Повторный откат — без ошибок и изменений.
        rollback(&s, &svc, &p.dir).await.unwrap();
        assert_eq!(nets_text(&s), nets0);
        assert_eq!(s.read_list("user").unwrap(), user0);
        assert_eq!(read_undo(&p.dir).unwrap(), undo1);
        fs::remove_dir_all(root).ok();

        // Записи не было: после отката её нет, файл побайтно прежний.
        let (s, root) = store("restore-none");
        let nets0 = "x\tX\talt4\n";
        fs::write(s.layout.networks_file(), nets0).unwrap();
        s.write_list("user", "").unwrap();
        let svc = FakeSvc::new(&s, &root, vec![st("running", PRESET)]);
        let p = plan(&root);
        assert_eq!(
            apply(&s, &svc, &FakeVerifier::default(), &p, WAIT).await,
            Outcome::Applied
        );
        assert_eq!(s.read_list("user").unwrap(), "rutracker.org\n");
        rollback(&s, &svc, &p.dir).await.unwrap();
        assert_eq!(nets_text(&s), nets0);
        assert_eq!(strategy_of(&s, KEY), None);
        assert_eq!(s.read_list("user").unwrap(), "");
        rollback(&s, &svc, &p.dir).await.unwrap();
        assert_eq!(nets_text(&s), nets0);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn rollback_keeps_owner_edits() {
        // После применения владелец дописал свою строку — откат её не трогает.
        let (s, root) = store("owner-edit");
        s.write_list("user", "a.com\n").unwrap();
        let svc = FakeSvc::new(&s, &root, vec![st("running", PRESET)]);
        let p = plan(&root);
        apply(&s, &svc, &FakeVerifier::default(), &p, WAIT).await;
        let t = s.read_list("user").unwrap();
        s.write_list("user", &format!("{t}mine.org\n")).unwrap();
        rollback(&s, &svc, &p.dir).await.unwrap();
        assert_eq!(s.read_list("user").unwrap(), "a.com\nmine.org\n");
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn rollback_without_undo_is_error() {
        let (s, root) = store("no-undo");
        let svc = FakeSvc::new(&s, &root, vec![None]);
        assert!(rollback(&s, &svc, &root.join("run")).await.is_err());
        fs::remove_dir_all(root).ok();
    }
}
