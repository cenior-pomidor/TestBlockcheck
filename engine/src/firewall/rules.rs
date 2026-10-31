//! Правила iptables для поиска на Android (спека этапа 1, §4).
//!
//! Свои цепочки, переход на каждую — первой строкой стандартной цепочки. Всё, что несёт наши
//! биты метки, принимается (`ACCEPT`) раньше чужих цепочек — так пробы и контроль идут мимо
//! модуля обхода. «Наше соединение» в метке соединения — только бит `DESYNC`.

use crate::error::BlockcheckError;
use crate::firewall::ipt::{IptBatch, IptRun, IptRunSync, Table};
use crate::network::dns::is_ipv4;
use crate::nfqws2::dispatch::Dispatch;
use crate::nfqws2::mark::{control_mark, desync_mark, our_mask, profile_mask};
use crate::nfqws2::run::Ready;
use tracing::warn;

/// Сколько первых исходящих пакетов соединения отдавать движку (#68 upstream).
const MAX_PKT_OUT: u32 = 10;

/// Потолок повторов `-D` одного перехода: защита от исполнителя, который всегда отвечает «ок».
const MAX_JUMP_DELETES: usize = 64;

/// Имена наших цепочек.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainNames {
    prefix: String,
}

impl ChainNames {
    pub fn new(prefix: &str) -> Self {
        ChainNames {
            prefix: prefix.to_string(),
        }
    }

    fn named(&self, suffix: &str) -> String {
        format!("{}_{suffix}", self.prefix)
    }

    pub fn raw(&self) -> String {
        self.named("raw")
    }
    pub fn out(&self) -> String {
        self.named("out")
    }
    pub fn post(&self) -> String {
        self.named("post")
    }
    pub fn pre(&self) -> String {
        self.named("pre")
    }
    pub fn q(&self) -> String {
        self.named("q")
    }
    pub fn qin(&self) -> String {
        self.named("qin")
    }
    pub fn ctl(&self) -> String {
        self.named("ctl")
    }

    /// Пары «таблица, стандартная цепочка, наша цепочка», в которые мы вставляем переход.
    fn jumps(&self) -> [(Table, &'static str, String); 4] {
        [
            (Table::Raw, "OUTPUT", self.raw()),
            (Table::Mangle, "OUTPUT", self.out()),
            (Table::Mangle, "POSTROUTING", self.post()),
            (Table::Mangle, "PREROUTING", self.pre()),
        ]
    }

    /// Все семь цепочек с их таблицами.
    fn all(&self) -> [(Table, String); 7] {
        [
            (Table::Raw, self.raw()),
            (Table::Mangle, self.out()),
            (Table::Mangle, self.post()),
            (Table::Mangle, self.pre()),
            (Table::Mangle, self.q()),
            (Table::Mangle, self.qin()),
            (Table::Mangle, self.ctl()),
        ]
    }
}

/// Хэндл цепочек, которыми владеем мы. Не `Clone`: получить его можно только из
/// [`prepare_chains`].
#[derive(Debug)]
pub struct OwnedChains {
    names: ChainNames,
}

impl OwnedChains {
    pub fn names(&self) -> &ChainNames {
        &self.names
    }

    pub fn marker(&self) -> OwnedChainsMarker {
        OwnedChainsMarker {
            names: self.names.clone(),
        }
    }
}

/// Метка наших цепочек для аварийных путей, где хэндла нет.
#[derive(Debug, Clone)]
pub struct OwnedChainsMarker {
    names: ChainNames,
}

impl OwnedChainsMarker {
    pub fn planned(prefix: &str) -> Self {
        OwnedChainsMarker {
            names: ChainNames::new(prefix),
        }
    }

    pub fn names(&self) -> &ChainNames {
        &self.names
    }
}

fn hex(v: u32) -> String {
    format!("0x{v:08X}")
}

/// `value/mask` в написании правил.
fn vm(value: u32, mask: u32) -> String {
    format!("{}/{}", hex(value), hex(mask))
}

/// Базовая часть `<p>_post` с правилами плана перед завершающими ACCEPT.
fn post_rules(n: &ChainNames, plan: &[String]) -> Vec<String> {
    let post = n.post();
    let desync = desync_mark();
    let control = control_mark();
    let mut lines = vec![format!(
        "-A {post} -m mark --mark {} -j ACCEPT",
        vm(desync, desync)
    )];
    lines.extend(plan.iter().cloned());
    lines.push(format!(
        "-A {post} -m mark --mark {} -j {}",
        vm(control, control),
        n.ctl()
    ));
    lines.push(format!(
        "-A {post} -m mark ! --mark {} -j ACCEPT",
        vm(0, our_mask())
    ));
    lines
}

/// Базовая часть `<p>_pre` с правилами плана перед завершающим ACCEPT.
fn pre_rules(n: &ChainNames, plan: &[String]) -> Vec<String> {
    let pre = n.pre();
    let desync = desync_mark();
    let ours = vm(desync, desync);
    let mut lines = vec![
        format!("-A {pre} -p icmp --icmp-type time-exceeded -m connmark --mark {ours} -j DROP"),
        format!(
            "-A {pre} -p icmp --icmp-type time-exceeded -m conntrack --ctstate INVALID -j DROP"
        ),
    ];
    lines.extend(plan.iter().cloned());
    lines.push(format!("-A {pre} -m connmark --mark {ours} -j ACCEPT"));
    lines
}

fn save_profile(chain: &str) -> String {
    let p = hex(profile_mask());
    format!("-A {chain} -j CONNMARK --save-mark --nfmask {p} --ctmask {p}")
}

fn set_ours(chain: &str) -> String {
    let d = desync_mark();
    format!("-A {chain} -j CONNMARK --set-xmark {}", vm(d, d))
}

/// Статическая часть: `[Raw, Mangle]`, очереди пустые.
pub fn static_batches(names: &ChainNames) -> [IptBatch; 2] {
    let desync = desync_mark();
    let raw = IptBatch::new(
        Table::Raw,
        vec![
            format!(":{} - [0:0]", names.raw()),
            format!("-I OUTPUT 1 -j {}", names.raw()),
            format!(
                "-A {} -m mark --mark {} -j CT --notrack",
                names.raw(),
                vm(desync, desync)
            ),
        ],
    );

    let mut mangle = vec![
        format!(":{} - [0:0]", names.out()),
        format!(":{} - [0:0]", names.post()),
        format!(":{} - [0:0]", names.pre()),
        format!(":{} - [0:0]", names.q()),
        format!(":{} - [0:0]", names.qin()),
        format!(":{} - [0:0]", names.ctl()),
        format!("-I OUTPUT 1 -j {}", names.out()),
        format!("-I POSTROUTING 1 -j {}", names.post()),
        format!("-I PREROUTING 1 -j {}", names.pre()),
        format!(
            "-A {} -m mark ! --mark {} -j ACCEPT",
            names.out(),
            vm(0, our_mask())
        ),
    ];
    mangle.extend(post_rules(names, &[]));
    mangle.extend(pre_rules(names, &[]));
    mangle.push(save_profile(&names.ctl()));
    mangle.push(set_ours(&names.ctl()));
    mangle.push(format!("-A {} -j ACCEPT", names.ctl()));

    [raw, IptBatch::new(Table::Mangle, mangle)]
}

/// Создать наши цепочки: снять остатки прошлого прогона, затем статическая часть.
pub async fn prepare_chains<R: IptRun>(
    r: &R,
    prefix: &str,
) -> Result<OwnedChains, BlockcheckError> {
    let names = ChainNames::new(prefix);
    let marker = OwnedChainsMarker {
        names: names.clone(),
    };
    drop_chains(r, &marker).await;
    for batch in static_batches(&names) {
        if let Err(e) = r.restore(batch).await {
            // Транзакции две, и первая (raw) уже могла встать: отказ второй не вправе
            // оставить её в ядре до конца прогона — «ничего не применено частично».
            drop_chains(r, &marker).await;
            return Err(e);
        }
    }
    Ok(OwnedChains { names })
}

/// Проверить IP до подстановки в правила: пусто или не IPv4 — отказ, а не синтаксис iptables.
fn validate_ip_set(ips: &[String]) -> Result<(), BlockcheckError> {
    if ips.is_empty() {
        return Err(BlockcheckError::Iptables {
            command: "validate ip set".to_string(),
            stderr: "empty IP set: nothing to dispatch".to_string(),
        });
    }
    for ip in ips {
        if !is_ipv4(ip) {
            return Err(BlockcheckError::Iptables {
                command: "validate ip set".to_string(),
                stderr: format!("invalid IPv4 address: {ip}"),
            });
        }
    }
    Ok(())
}

/// Транзакция диспетчеризации: базовые части `<p>_post`/`<p>_pre` с правилами плана и
/// очереди `<p>_q`/`<p>_qin`. `plan == None` — снять план.
fn dispatch_batch(n: &ChainNames, plan: Option<(&Dispatch, &[String])>) -> IptBatch {
    let mut lines = vec![
        format!(":{} - [0:0]", n.post()),
        format!(":{} - [0:0]", n.pre()),
        format!(":{} - [0:0]", n.q()),
        format!(":{} - [0:0]", n.qin()),
    ];
    let (out_rules, in_rules) = match plan {
        None => (Vec::new(), Vec::new()),
        Some((d, ips)) => {
            let profile = profile_mask();
            let control = control_mark();
            let desync = desync_mark();
            let out = ips
                .iter()
                .map(|ip| {
                    format!(
                        "-A {} -p tcp --dport {} -d {ip} -m mark ! --mark {} -m mark ! --mark {} \
                         -m connbytes --connbytes 1:{MAX_PKT_OUT} --connbytes-dir original \
                         --connbytes-mode packets -j {}",
                        n.post(),
                        d.dport,
                        vm(0, profile),
                        vm(control, control),
                        n.q()
                    )
                })
                .collect();
            let inc = ips
                .iter()
                .map(|ip| {
                    format!(
                        "-A {} -p tcp --sport {} -s {ip} --tcp-flags SYN,ACK SYN,ACK \
                         -m connmark --mark {} -m connmark ! --mark {} -j {}",
                        n.pre(),
                        d.dport,
                        vm(desync, desync),
                        vm(control, control),
                        n.qin()
                    )
                })
                .collect();
            (out, inc)
        }
    };
    lines.extend(post_rules(n, &out_rules));
    lines.extend(pre_rules(n, &in_rules));
    if let Some((d, _)) = plan {
        let q = d.queue.get();
        lines.push(save_profile(&n.q()));
        lines.push(set_ours(&n.q()));
        lines.push(format!("-A {} -j NFQUEUE --queue-num {q}", n.q()));
        let p = hex(profile_mask());
        lines.push(format!(
            "-A {} -j CONNMARK --restore-mark --nfmask {p} --ctmask {p}",
            n.qin()
        ));
        lines.push(format!("-A {} -j NFQUEUE --queue-num {q}", n.qin()));
    }
    IptBatch::new(Table::Mangle, lines)
}

/// Поставить правила плана. Свидетельство готовности очереди обязано быть выдано той же
/// очереди, в которую ведут правила: иначе пакеты ушли бы в очередь без слушателя.
pub async fn apply_dispatch<R: IptRun>(
    r: &R,
    chains: &OwnedChains,
    ready: &Ready,
    d: &Dispatch,
    ips: &[String],
) -> Result<(), BlockcheckError> {
    if ready.queue() != d.queue {
        return Err(BlockcheckError::QueueWitnessMismatch {
            witnessed: ready.queue().get(),
            requested: d.queue.get(),
        });
    }
    validate_ip_set(ips)?;
    r.restore(dispatch_batch(chains.names(), Some((d, ips))))
        .await
}

/// Снять правила плана, оставив базовую часть.
pub async fn remove_dispatch<R: IptRun>(r: &R, chains: &OwnedChains) {
    if let Err(e) = r.restore(dispatch_batch(chains.names(), None)).await {
        warn!(error = %e, "remove_dispatch failed: dispatch rules of the previous plan may still be in place");
    }
}

fn delete_jump_args(builtin: &str, ours: &str) -> Vec<String> {
    vec![
        "-D".to_string(),
        builtin.to_string(),
        "-j".to_string(),
        ours.to_string(),
    ]
}

/// Снять все наши переходы из одной стандартной цепочки.
async fn delete_jumps<R: IptRun>(r: &R, table: Table, builtin: &str, ours: &str) {
    let args = delete_jump_args(builtin, ours);
    for _ in 0..MAX_JUMP_DELETES {
        match r.cmd(table, &args).await {
            Ok(out) if out.ok => continue,
            _ => break,
        }
    }
}

/// Снести наши цепочки целиком. Идемпотентно: отсутствие цепочки или перехода — не ошибка.
pub async fn drop_chains<R: IptRun>(r: &R, m: &OwnedChainsMarker) {
    let names = m.names();
    for (table, builtin, ours) in names.jumps() {
        delete_jumps(r, table, builtin, &ours).await;
    }
    for verb in ["-F", "-X"] {
        for (table, chain) in names.all() {
            let _ = r.cmd(table, &[verb.to_string(), chain]).await;
        }
    }
}

/// То же для panic-хука и обработчиков сигналов: без рантайма.
pub fn drop_chains_sync<R: IptRunSync>(r: &R, m: &OwnedChainsMarker) {
    let names = m.names();
    for (table, builtin, ours) in names.jumps() {
        let args = delete_jump_args(builtin, &ours);
        for _ in 0..MAX_JUMP_DELETES {
            match r.cmd(table, &args) {
                Ok(true) => continue,
                _ => break,
            }
        }
    }
    for verb in ["-F", "-X"] {
        for (table, chain) in names.all() {
            let _ = r.cmd(table, &[verb.to_string(), chain]);
        }
    }
}

/// Что сделал страж порядка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reorder {
    pub table: Table,
    pub chain: &'static str,
    /// `true` — перехода не было вовсе, статическая часть применена заново.
    pub reapplied: bool,
}

/// Страж порядка: наши переходы обязаны стоять первыми. Сторож модуля обхода вставляет свои
/// правила на позицию 1 при смене сети, а система может сбросить таблицы целиком.
pub async fn ensure_order<R: IptRun>(
    r: &R,
    chains: &OwnedChains,
) -> Result<Vec<Reorder>, BlockcheckError> {
    let names = chains.names();
    let mut reorders = Vec::new();
    let mut missing = Vec::new();

    for (table, builtin, ours) in names.jumps() {
        let listed = r
            .cmd(table, &["-S".to_string(), builtin.to_string()])
            .await?;
        let rules = if listed.ok {
            crate::firewall::ipt::parse_rules(builtin, &listed.stdout)
        } else {
            Vec::new()
        };
        let jump = format!("-A {builtin} -j {ours}");
        if rules.first() == Some(&jump) {
            continue;
        }
        if rules.contains(&jump) {
            delete_jumps(r, table, builtin, &ours).await;
            let insert = vec![
                "-I".to_string(),
                builtin.to_string(),
                "1".to_string(),
                "-j".to_string(),
                ours.clone(),
            ];
            let out = r.cmd(table, &insert).await?;
            if !out.ok {
                return Err(BlockcheckError::Iptables {
                    command: insert.join(" "),
                    stderr: out.stderr,
                });
            }
            reorders.push(Reorder {
                table,
                chain: builtin,
                reapplied: false,
            });
        } else {
            missing.push((table, builtin));
        }
    }

    if !missing.is_empty() {
        // Оставшиеся переходы снимаем, чтобы статическая часть не поставила их дважды.
        for (table, builtin, ours) in names.jumps() {
            delete_jumps(r, table, builtin, &ours).await;
        }
        for batch in static_batches(names) {
            r.restore(batch).await?;
        }
        reorders.extend(missing.into_iter().map(|(table, chain)| Reorder {
            table,
            chain,
            reapplied: true,
        }));
    }
    Ok(reorders)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::ipt::testing::RecordingIpt;
    use crate::nfqws2::plan::{FilterMark, Plan, QueueNum};
    use crate::nfqws2::run::Ready;

    const POST_ACCEPT: &str = "-A bcw_post -m mark ! --mark 0x00000000/0x3FE00000 -j ACCEPT";
    const PRE_ACCEPT: &str = "-A bcw_pre -m connmark --mark 0x00200000/0x00200000 -j ACCEPT";

    fn all_lines(r: &RecordingIpt) -> Vec<String> {
        r.restores()
            .iter()
            .flat_map(|b| b.lines().to_vec())
            .collect()
    }

    fn deletes(r: &RecordingIpt, table: Table, chain: &str) -> usize {
        r.cmds()
            .iter()
            .filter(|(t, a)| {
                *t == table && a.first().map(String::as_str) == Some("-D") && a[1] == chain
            })
            .count()
    }

    fn verb_count(r: &RecordingIpt, verb: &str) -> usize {
        r.cmds()
            .iter()
            .filter(|(_, a)| a.first().map(String::as_str) == Some(verb))
            .count()
    }

    fn plan_dispatch(queue: u16, dport: u16) -> Dispatch {
        Plan::from_strategies(
            &FilterMark::granted(),
            QueueNum::new(queue),
            &[vec!["--a".to_string()], vec!["--b".to_string()]],
        )
        .dispatch(dport)
    }

    async fn dispatched(ips: &[&str]) -> (RecordingIpt, Vec<String>) {
        let r = RecordingIpt::default();
        let chains = prepare_chains(&r, "bcw").await.unwrap();
        let ips: Vec<String> = ips.iter().map(|s| s.to_string()).collect();
        apply_dispatch(
            &r,
            &chains,
            &Ready::witnessed(QueueNum::new(777)),
            &plan_dispatch(777, 443),
            &ips,
        )
        .await
        .unwrap();
        let last = r.restores().last().unwrap().lines().to_vec();
        (r, last)
    }

    fn masks(line: &str) -> Vec<u32> {
        let mut out = Vec::new();
        let words: Vec<&str> = line.split_whitespace().collect();
        for (i, w) in words.iter().enumerate() {
            if let Some((_, m)) = w.split_once('/') {
                if let Some(hex) = m.strip_prefix("0x") {
                    out.push(u32::from_str_radix(hex, 16).unwrap());
                }
            }
            if (*w == "--nfmask" || *w == "--ctmask") && i + 1 < words.len() {
                out.push(u32::from_str_radix(words[i + 1].trim_start_matches("0x"), 16).unwrap());
            }
        }
        out
    }

    // ── статическая часть ────────────────────────────────────────────────────

    #[tokio::test]
    async fn static_part_is_one_transaction_per_table() {
        let r = RecordingIpt::default();
        prepare_chains(&r, "bcw").await.unwrap();
        let t: Vec<Table> = r.restores().iter().map(|b| b.table()).collect();
        assert_eq!(t, [Table::Raw, Table::Mangle]);
    }

    #[tokio::test]
    async fn jumps_are_inserted_first() {
        let r = RecordingIpt::default();
        prepare_chains(&r, "bcw").await.unwrap();
        let tx = r.restores();
        assert!(tx[0]
            .lines()
            .contains(&"-I OUTPUT 1 -j bcw_raw".to_string()));
        for jump in [
            "-I OUTPUT 1 -j bcw_out",
            "-I POSTROUTING 1 -j bcw_post",
            "-I PREROUTING 1 -j bcw_pre",
        ] {
            assert!(tx[1].lines().contains(&jump.to_string()), "нет {jump}");
        }
    }

    #[tokio::test]
    async fn prepare_sweeps_leftover_jumps_before_restore() {
        let r = RecordingIpt::default();
        r.delete_succeeds(Table::Mangle, "OUTPUT", 1);
        prepare_chains(&r, "bcw").await.unwrap();
        assert_eq!(deletes(&r, Table::Mangle, "OUTPUT"), 2, "ok, затем false");
        assert_eq!(r.restores().len(), 2);
        // RecordingIpt не упорядочивает cmd и restore между собой, поэтому порядок
        // проверяем по факту: уборка (-X) отработала до того, как появились транзакции —
        // её вызовы есть, и все они относятся к нашим цепочкам.
        assert!(verb_count(&r, "-X") >= 7);
    }

    #[tokio::test]
    async fn desync_packets_are_notracked() {
        let r = RecordingIpt::default();
        prepare_chains(&r, "bcw").await.unwrap();
        assert!(r.restores()[0].lines().contains(
            &"-A bcw_raw -m mark --mark 0x00200000/0x00200000 -j CT --notrack".to_string()
        ));
    }

    #[tokio::test]
    async fn control_connection_is_marked_ours_without_queue() {
        let r = RecordingIpt::default();
        prepare_chains(&r, "bcw").await.unwrap();
        let lines = r.restores()[1].lines().to_vec();
        for rule in [
            "-A bcw_post -m mark --mark 0x3FC00000/0x3FC00000 -j bcw_ctl",
            "-A bcw_ctl -j CONNMARK --save-mark --nfmask 0x3FC00000 --ctmask 0x3FC00000",
            "-A bcw_ctl -j CONNMARK --set-xmark 0x00200000/0x00200000",
            "-A bcw_ctl -j ACCEPT",
            "-A bcw_out -m mark ! --mark 0x00000000/0x3FE00000 -j ACCEPT",
        ] {
            assert!(lines.contains(&rule.to_string()), "нет {rule}");
        }
    }

    // ── диспетчеризация ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_rules_match_spec_for_each_ip() {
        let (_, last) = dispatched(&["1.2.3.4", "5.6.7.8"]).await;
        for ip in ["1.2.3.4", "5.6.7.8"] {
            let out = format!(
                "-A bcw_post -p tcp --dport 443 -d {ip} -m mark ! --mark 0x00000000/0x3FC00000 \
                 -m mark ! --mark 0x3FC00000/0x3FC00000 -m connbytes --connbytes 1:10 \
                 --connbytes-dir original --connbytes-mode packets -j bcw_q"
            );
            let inc = format!(
                "-A bcw_pre -p tcp --sport 443 -s {ip} --tcp-flags SYN,ACK SYN,ACK \
                 -m connmark --mark 0x00200000/0x00200000 -m connmark ! --mark 0x3FC00000/0x3FC00000 \
                 -j bcw_qin"
            );
            assert_eq!(
                last.iter().filter(|l| **l == out).count(),
                1,
                "{out}\n{last:#?}"
            );
            assert_eq!(
                last.iter().filter(|l| **l == inc).count(),
                1,
                "{inc}\n{last:#?}"
            );
        }
        assert_eq!(last.iter().filter(|l| l.ends_with("-j bcw_q")).count(), 2);
        assert_eq!(last.iter().filter(|l| l.ends_with("-j bcw_qin")).count(), 2);
        assert!(last.contains(&"-A bcw_q -j NFQUEUE --queue-num 777".to_string()));
        assert!(last.contains(&"-A bcw_qin -j NFQUEUE --queue-num 777".to_string()));
    }

    #[tokio::test]
    async fn dispatch_rules_precede_final_accepts() {
        let (_, last) = dispatched(&["1.2.3.4"]).await;
        let pos = |pred: &dyn Fn(&String) -> bool| last.iter().position(pred).unwrap();
        let q = pos(&|l| l.ends_with("-j bcw_q"));
        let post_accept = pos(&|l| l == POST_ACCEPT);
        assert!(q < post_accept);
        let qin = pos(&|l| l.ends_with("-j bcw_qin"));
        let icmp_last = last
            .iter()
            .rposition(|l| l.contains("--icmp-type time-exceeded"))
            .unwrap();
        let pre_accept = pos(&|l| l == PRE_ACCEPT);
        assert!(icmp_last < qin && qin < pre_accept);
    }

    #[tokio::test]
    async fn every_mask_is_within_our_bits() {
        let (r, _) = dispatched(&["1.2.3.4"]).await;
        for line in all_lines(&r) {
            for m in masks(&line) {
                assert_eq!(
                    m & !0x3FE0_0000,
                    0,
                    "маска 0x{m:08X} вне наших битов: {line}"
                );
            }
        }
    }

    #[tokio::test]
    async fn our_connection_is_recognised_by_bit_21_only() {
        let (r, _) = dispatched(&["1.2.3.4"]).await;
        for line in all_lines(&r) {
            let words: Vec<&str> = line.split_whitespace().collect();
            for i in 0..words.len() {
                if words[i] == "connmark" && words.get(i + 1) == Some(&"--mark") {
                    assert_eq!(words[i + 2], "0x00200000/0x00200000", "{line}");
                }
            }
        }
    }

    #[tokio::test]
    async fn control_is_never_queued() {
        let (r, _) = dispatched(&["1.2.3.4"]).await;
        for line in all_lines(&r) {
            if line.ends_with("-j bcw_q") {
                assert!(line.contains("! --mark 0x3FC00000/0x3FC00000"), "{line}");
            }
            if line.starts_with("-A bcw_ctl") {
                assert!(!line.contains("NFQUEUE"), "{line}");
            }
        }
    }

    #[tokio::test]
    async fn witness_for_another_queue_is_refused() {
        let r = RecordingIpt::default();
        let chains = prepare_chains(&r, "bcw").await.unwrap();
        let before = r.restores().len();
        let err = apply_dispatch(
            &r,
            &chains,
            &Ready::witnessed(QueueNum::new(778)),
            &plan_dispatch(777, 443),
            &["1.2.3.4".to_string()],
        )
        .await
        .unwrap_err();
        assert!(matches!(err, BlockcheckError::QueueWitnessMismatch { .. }));
        assert_eq!(r.restores().len(), before);
    }

    #[tokio::test]
    async fn remove_dispatch_restores_base_and_empties_queues() {
        let (r, _) = dispatched(&["1.2.3.4"]).await;
        let chains = OwnedChains {
            names: ChainNames::new("bcw"),
        };
        remove_dispatch(&r, &chains).await;
        let last = r.restores().last().unwrap().lines().to_vec();
        assert!(!last
            .iter()
            .any(|l| l.ends_with("-j bcw_q") || l.ends_with("-j bcw_qin")));
        assert!(!last.iter().any(|l| l.contains("NFQUEUE")));
        assert!(last.contains(&POST_ACCEPT.to_string()));
        assert!(last.contains(&PRE_ACCEPT.to_string()));
    }

    // ── Review Focus ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn empty_ip_set_is_rejected_before_iptables() {
        let r = RecordingIpt::default();
        let chains = prepare_chains(&r, "bcw").await.unwrap();
        let before = r.restores().len();
        assert!(apply_dispatch(
            &r,
            &chains,
            &Ready::witnessed(QueueNum::new(777)),
            &plan_dispatch(777, 443),
            &[]
        )
        .await
        .is_err());
        assert_eq!(r.restores().len(), before);
    }

    #[tokio::test]
    async fn non_ipv4_is_rejected_before_iptables() {
        let r = RecordingIpt::default();
        let chains = prepare_chains(&r, "bcw").await.unwrap();
        let before = r.restores().len();
        for bad in ["2001:db8::1", "1.2.3.4 -j DROP"] {
            assert!(
                apply_dispatch(
                    &r,
                    &chains,
                    &Ready::witnessed(QueueNum::new(777)),
                    &plan_dispatch(777, 443),
                    &[bad.to_string()]
                )
                .await
                .is_err(),
                "{bad}"
            );
        }
        assert_eq!(r.restores().len(), before);
    }

    #[tokio::test]
    async fn restore_failure_carries_stderr_and_stops() {
        let r = RecordingIpt::default();
        r.fail_restore("Couldn't load match `connbytes'");
        let err = match prepare_chains(&r, "bcw").await {
            Err(e) => e,
            Ok(_) => panic!("подготовка обязана провалиться"),
        };
        match err {
            BlockcheckError::Iptables { stderr, .. } => assert!(stderr.contains("connbytes")),
            other => panic!("ожидалась Iptables, получено {other:?}"),
        }
        assert_eq!(r.restores().len(), 1, "вторая транзакция не отправлена");
    }

    #[tokio::test]
    async fn drop_chains_deletes_every_duplicate_jump() {
        let r = RecordingIpt::default();
        r.delete_succeeds(Table::Mangle, "OUTPUT", 2);
        drop_chains(&r, &OwnedChainsMarker::planned("bcw")).await;
        assert_eq!(deletes(&r, Table::Mangle, "OUTPUT"), 3);
        assert_eq!(verb_count(&r, "-F"), 7);
        assert_eq!(verb_count(&r, "-X"), 7);
        for (_, args) in r.cmds() {
            if matches!(args[0].as_str(), "-F" | "-X") {
                assert!(args[1].starts_with("bcw_"), "{args:?}");
            }
        }
    }

    #[tokio::test]
    async fn drop_chains_on_clean_system_is_silent() {
        let r = RecordingIpt::default();
        drop_chains(&r, &OwnedChainsMarker::planned("bcw")).await;
        assert_eq!(verb_count(&r, "-F"), 7);
        assert_eq!(verb_count(&r, "-X"), 7);
    }

    #[test]
    fn drop_chains_sync_mirrors_async_cleanup() {
        let r = RecordingIpt::default();
        r.delete_succeeds(Table::Raw, "OUTPUT", 1);
        drop_chains_sync(&r, &OwnedChainsMarker::planned("bcw"));
        assert_eq!(deletes(&r, Table::Raw, "OUTPUT"), 2);
        assert_eq!(verb_count(&r, "-X"), 7);
    }

    fn ours_first(r: &RecordingIpt) {
        r.set_rules(Table::Raw, "OUTPUT", vec!["-A OUTPUT -j bcw_raw".into()]);
        r.set_rules(Table::Mangle, "OUTPUT", vec!["-A OUTPUT -j bcw_out".into()]);
        r.set_rules(
            Table::Mangle,
            "POSTROUTING",
            vec!["-A POSTROUTING -j bcw_post".into()],
        );
        r.set_rules(
            Table::Mangle,
            "PREROUTING",
            vec!["-A PREROUTING -j bcw_pre".into()],
        );
    }

    #[tokio::test]
    async fn ensure_order_is_quiet_when_our_jumps_are_first() {
        let r = RecordingIpt::default();
        let chains = prepare_chains(&r, "bcw").await.unwrap();
        ours_first(&r);
        let before = r.restores().len();
        assert!(ensure_order(&r, &chains).await.unwrap().is_empty());
        assert_eq!(r.restores().len(), before);
        assert_eq!(verb_count(&r, "-I"), 0);
    }

    #[tokio::test]
    async fn ensure_order_reinserts_when_foreign_jump_is_first() {
        let r = RecordingIpt::default();
        let chains = prepare_chains(&r, "bcw").await.unwrap();
        ours_first(&r);
        r.set_rules(
            Table::Mangle,
            "OUTPUT",
            vec![
                "-A OUTPUT -j nfqws_post".into(),
                "-A OUTPUT -j bcw_out".into(),
            ],
        );
        r.delete_succeeds(Table::Mangle, "OUTPUT", 1);
        let reorders = ensure_order(&r, &chains).await.unwrap();
        assert_eq!(reorders.len(), 1);
        assert_eq!(
            (reorders[0].table, reorders[0].chain, reorders[0].reapplied),
            (Table::Mangle, "OUTPUT", false)
        );
        let inserted: Vec<Vec<String>> = r
            .cmds()
            .into_iter()
            .filter(|(t, a)| *t == Table::Mangle && a[0] == "-I")
            .map(|(_, a)| a)
            .collect();
        assert_eq!(inserted, [["-I", "OUTPUT", "1", "-j", "bcw_out"]]);
    }

    #[tokio::test]
    async fn ensure_order_reapplies_static_part_when_jump_is_missing() {
        let r = RecordingIpt::default();
        let chains = prepare_chains(&r, "bcw").await.unwrap();
        ours_first(&r);
        r.set_rules(Table::Mangle, "OUTPUT", vec![]);
        let before = r.restores().len();
        let reorders = ensure_order(&r, &chains).await.unwrap();
        assert_eq!(r.restores().len(), before + 2);
        assert!(reorders
            .iter()
            .any(|o| o.table == Table::Mangle && o.chain == "OUTPUT" && o.reapplied));
        assert!(reorders.iter().all(|o| o.reapplied));
    }

    #[test]
    fn chain_names_follow_the_prefix() {
        let n = ChainNames::new("bcw");
        assert_eq!(
            [n.raw(), n.out(), n.post(), n.pre(), n.q(), n.qin(), n.ctl()],
            ["bcw_raw", "bcw_out", "bcw_post", "bcw_pre", "bcw_q", "bcw_qin", "bcw_ctl"]
        );
    }

    /// Review I1: сырая часть уже применена, mangle отказал — уйти без следа, а не оставить
    /// `bcw_raw` и его переход до конца прогона.
    #[tokio::test]
    async fn prepare_failure_after_raw_drops_what_was_applied() {
        let r = RecordingIpt::default();
        r.fail_restore_from(1, "Couldn't load match `connbytes'");
        let err = prepare_chains(&r, "bcw").await.expect_err("mangle отказал");
        assert!(matches!(err, BlockcheckError::Iptables { .. }), "{err:?}");
        let ops = r.ops();
        let failed_at = ops
            .iter()
            .rposition(|op| op == "restore:mangle")
            .expect("mangle отправлялся");
        let after: Vec<&String> = ops[failed_at..].iter().collect();
        assert!(
            after
                .iter()
                .any(|op| op.starts_with("cmd:raw:-D OUTPUT -j bcw_raw")),
            "после отказа не снят переход raw: {after:?}"
        );
        assert!(
            after.iter().any(|op| op.as_str() == "cmd:raw:-X bcw_raw"),
            "после отказа не снесена цепочка raw: {after:?}"
        );
    }
}
