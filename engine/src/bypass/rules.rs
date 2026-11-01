//! Правила обхода `dpi_*` — содержимое как `_fw_iface_rules`/`_firewall_start` nfqws2-android
//! (`lib/common.sh:1398–1575`), постановка транзакцией `iptables-restore`.
//!
//! Отличия от оригинала (спецификация §3.5):
//! - первыми идут правила изоляции от поиска (биты 21–29 метки и бит 21 connmark);
//! - `NAT_FIX` и сброс бита 30 стоят внутри `dpi_post`, а не в стандартном `POSTROUTING`:
//!   действие на пакет то же, а снятие трогает только свои цепочки;
//! - переходы встают после переходов поиска `bcw_*`, если поиск идёт.

use super::ports::{self, EffectivePorts};
use super::preset::Preset;
use super::settings::Settings;
use crate::error::BlockcheckError;
use crate::firewall::ipt::{IptBatch, IptRun, Table};

pub const POST: &str = "dpi_post";
pub const PRE: &str = "dpi_pre";
pub const NAT: &str = "dpi_nat";
pub const MQUIC: &str = "dpi_mquic";

/// Наши цепочки.
pub const CHAINS: [(Table, &str); 4] = [
    (Table::Mangle, POST),
    (Table::Mangle, PRE),
    (Table::Nat, NAT),
    (Table::Filter, MQUIC),
];

/// Переходы: таблица, стандартная цепочка, наша цепочка.
const JUMPS: [(Table, &str, &str); 4] = [
    (Table::Mangle, "POSTROUTING", POST),
    (Table::Mangle, "PREROUTING", PRE),
    (Table::Nat, "POSTROUTING", NAT),
    (Table::Filter, "OUTPUT", MQUIC),
];

const ISOLATE_MARK: &str = "-m mark ! --mark 0x0/0x3FE00000 -j RETURN";
const ISOLATE_CONNMARK: &str = "-m connmark ! --mark 0x0/0x00200000 -j RETURN";
const PROCESSED: &str = "-m mark --mark 0x40000000/0x40000000";
const RENAT: &str = "0x80000000/0x80000000";
const IFACE_EXCLUDE: [&str; 8] = [
    "lo", "tun+", "tap+", "wg+", "ppp+", "ipsec+", "ifb+", "dummy+",
];
/// Сколько раз пытаться снять повторяющийся переход.
const MAX_JUMP_DELETES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub tcp_out: u16,
    pub tcp_in: u16,
    pub udp_out: u16,
    pub udp_in: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleParams {
    pub ports: EffectivePorts,
    pub limits: Limits,
    pub block_quic: bool,
    pub mss: Option<u16>,
    pub nat_fix: bool,
    pub meta_quic: bool,
}

/// Параметры правил: лимиты пресета главнее `PKT_LIMIT_*`.
pub fn params(s: &Settings, preset: &Preset) -> RuleParams {
    let l = &preset.limits;
    RuleParams {
        ports: ports::effective(s, preset),
        limits: Limits {
            tcp_out: l.tcp_out.unwrap_or(s.pkt_limit_out),
            tcp_in: l.tcp_in.unwrap_or(s.pkt_limit_in),
            udp_out: l.udp_out.unwrap_or(s.pkt_limit_out),
            udp_in: l.udp_in.unwrap_or(s.pkt_limit_in),
        },
        block_quic: s.block_quic,
        mss: s.mss_value(),
        nat_fix: s.nat_fix,
        meta_quic: s.meta_quic_reject,
    }
}

fn queue() -> String {
    format!("-j NFQUEUE --queue-num {} --queue-bypass", super::QNUM)
}

fn connbytes(dir: &str, n: u16) -> String {
    format!(
        "-m connbytes --connbytes 1:{n} --connbytes-dir {dir} --connbytes-mode packets {}",
        queue()
    )
}

/// Правило на каждую часть списка портов (не больше 15 на `multiport`).
fn port_rules(out: &mut Vec<String>, chain: &str, proto: &str, dir: &str, list: &str, rest: &str) {
    for part in ports::chunks(list) {
        out.push(format!(
            "-A {chain} -p {proto} -m multiport --{dir} {part} {rest}"
        ));
    }
}

/// Цепочки и их содержимое, без переходов.
pub fn batches(p: &RuleParams) -> Vec<IptBatch> {
    let mut m = vec![format!(":{POST} - [0:0]"), format!(":{PRE} - [0:0]")];
    for c in [POST, PRE] {
        m.push(format!("-A {c} {ISOLATE_MARK}"));
        m.push(format!("-A {c} {ISOLATE_CONNMARK}"));
    }
    // Порядок строк важен: изоляция обеих цепочек первой, но `-A` к разным цепочкам
    // независимы, поэтому дальше пишем цепочки по очереди.
    if p.nat_fix {
        m.push(format!(
            "-A {POST} {PROCESSED} -j CONNMARK --set-xmark {RENAT}"
        ));
    }
    m.push(format!(
        "-A {POST} {PROCESSED} -j MARK --set-xmark 0x0/0x40000000"
    ));
    m.push(format!("-A {POST} {PROCESSED} -j RETURN"));
    m.push(format!("-A {PRE} {PROCESSED} -j RETURN"));
    for i in IFACE_EXCLUDE {
        m.push(format!("-A {POST} -o {i} -j RETURN"));
        m.push(format!("-A {PRE} -i {i} -j RETURN"));
    }
    if p.block_quic {
        m.push(format!("-A {POST} -p udp --dport 443 -j DROP"));
    }
    let (tp, up, l) = (&p.ports.tcp, &p.ports.udp, &p.limits);
    // Исходящие (`_fw_iface_rules`, POSTROUTING).
    port_rules(
        &mut m,
        POST,
        "udp",
        "dports",
        up,
        &connbytes("original", l.udp_out),
    );
    port_rules(
        &mut m,
        POST,
        "tcp",
        "dports",
        tp,
        &connbytes("original", l.tcp_out),
    );
    port_rules(
        &mut m,
        POST,
        "tcp",
        "dports",
        tp,
        &format!("--tcp-flags FIN FIN {}", queue()),
    );
    port_rules(
        &mut m,
        POST,
        "tcp",
        "dports",
        tp,
        &format!("--tcp-flags RST RST {}", queue()),
    );
    if let Some(mss) = p.mss {
        port_rules(
            &mut m,
            POST,
            "tcp",
            "dports",
            tp,
            &format!("--tcp-flags SYN,RST SYN -j TCPMSS --set-mss {mss}"),
        );
    }
    // Входящие (PREROUTING).
    port_rules(
        &mut m,
        PRE,
        "tcp",
        "sports",
        tp,
        &format!("--tcp-flags SYN,ACK SYN,ACK {}", queue()),
    );
    port_rules(
        &mut m,
        PRE,
        "tcp",
        "sports",
        tp,
        &format!("--tcp-flags FIN FIN {}", queue()),
    );
    port_rules(
        &mut m,
        PRE,
        "tcp",
        "sports",
        tp,
        &format!("--tcp-flags RST RST {}", queue()),
    );
    port_rules(
        &mut m,
        PRE,
        "udp",
        "sports",
        up,
        &connbytes("reply", l.udp_in),
    );
    port_rules(
        &mut m,
        PRE,
        "tcp",
        "sports",
        tp,
        &connbytes("reply", l.tcp_in),
    );

    // Изоляцию обеих цепочек ставим первой — упорядочим по цепочке, сохраняя порядок внутри.
    let mut post: Vec<String> = Vec::new();
    let mut pre: Vec<String> = Vec::new();
    let mut head: Vec<String> = Vec::new();
    for line in m {
        if line.starts_with(&format!("-A {POST} ")) {
            post.push(line);
        } else if line.starts_with(&format!("-A {PRE} ")) {
            pre.push(line);
        } else {
            head.push(line);
        }
    }
    head.extend(post);
    head.extend(pre);
    let mut out = vec![IptBatch::new(Table::Mangle, head)];
    if p.nat_fix {
        out.push(IptBatch::new(
            Table::Nat,
            vec![
                format!(":{NAT} - [0:0]"),
                format!("-A {NAT} -p udp -m connmark --mark {RENAT} -j MASQUERADE"),
            ],
        ));
    }
    if p.meta_quic {
        let nets = super::args::META_NET4.replace(' ', ",");
        out.push(IptBatch::new(
            Table::Filter,
            vec![
                format!(":{MQUIC} - [0:0]"),
                format!("-A {MQUIC} -p udp --dport 443 -d {nets} -j REJECT --reject-with icmp-port-unreachable"),
            ],
        ));
    }
    out
}

/// Куда вставить наш переход: сразу после идущих с начала переходов поиска `bcw_*`.
pub fn jump_position(chain_listing: &str) -> usize {
    let n = chain_listing
        .lines()
        .filter(|l| l.starts_with("-A "))
        .take_while(|l| {
            l.split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|w| w[0] == "-j" && w[1].starts_with("bcw_"))
        })
        .count();
    n + 1
}

/// Поставить правила: снять прежние, создать цепочки, вставить переходы.
pub async fn apply<R: IptRun>(r: &R, p: &RuleParams) -> Result<(), BlockcheckError> {
    remove(r).await;
    let chains = batches(p);
    let tables: Vec<Table> = chains.iter().map(|b| b.table()).collect();
    for b in chains {
        r.restore(b).await?;
    }
    for t in [Table::Mangle, Table::Nat, Table::Filter] {
        if !tables.contains(&t) {
            continue;
        }
        let mut lines = Vec::new();
        for (jt, builtin, ours) in JUMPS {
            if jt != t {
                continue;
            }
            let pos = if t == Table::Mangle {
                let listing = r.cmd(t, &["-S".to_string(), builtin.to_string()]).await?;
                jump_position(&listing.stdout)
            } else {
                1
            };
            lines.push(format!("-I {builtin} {pos} -j {ours}"));
        }
        r.restore(IptBatch::new(t, lines)).await?;
    }
    Ok(())
}

/// Снять все переходы на `dpi_*` и сами цепочки. Идемпотентно.
pub async fn remove<R: IptRun>(r: &R) {
    for (t, builtin, ours) in JUMPS {
        let args = vec![
            "-D".to_string(),
            builtin.to_string(),
            "-j".to_string(),
            ours.to_string(),
        ];
        for _ in 0..MAX_JUMP_DELETES {
            match r.cmd(t, &args).await {
                Ok(o) if o.ok => continue,
                _ => break,
            }
        }
    }
    for verb in ["-F", "-X"] {
        for (t, c) in CHAINS {
            let _ = r.cmd(t, &[verb.to_string(), c.to_string()]).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::ipt::testing::RecordingIpt;

    fn p() -> RuleParams {
        params(&Settings::default(), &Preset::default())
    }

    fn lines(p: &RuleParams, t: Table) -> Vec<String> {
        batches(p)
            .into_iter()
            .filter(|b| b.table() == t)
            .flat_map(|b| b.lines().to_vec())
            .collect()
    }

    fn chain(p: &RuleParams, t: Table, c: &str) -> Vec<String> {
        let prefix = format!("-A {c} ");
        lines(p, t)
            .into_iter()
            .filter_map(|l| l.strip_prefix(&prefix).map(str::to_string))
            .collect()
    }

    #[test]
    fn isolation_rules_come_first() {
        for c in [POST, PRE] {
            let r = chain(&p(), Table::Mangle, c);
            assert_eq!(r[0], ISOLATE_MARK, "{c}");
            assert_eq!(r[1], ISOLATE_CONNMARK, "{c}");
        }
    }

    #[test]
    fn processed_mark_handled_right_after_isolation() {
        let post = chain(&p(), Table::Mangle, POST);
        assert_eq!(
            post[2],
            format!("{PROCESSED} -j CONNMARK --set-xmark {RENAT}"),
            "NAT_FIX включён по умолчанию"
        );
        assert_eq!(
            post[3],
            format!("{PROCESSED} -j MARK --set-xmark 0x0/0x40000000")
        );
        assert_eq!(post[4], format!("{PROCESSED} -j RETURN"));
        let pre = chain(&p(), Table::Mangle, PRE);
        assert_eq!(pre[2], format!("{PROCESSED} -j RETURN"));
    }

    #[test]
    fn nat_fix_on_and_off() {
        let on = p();
        assert!(chain(&on, Table::Nat, NAT)
            .contains(&format!("-p udp -m connmark --mark {RENAT} -j MASQUERADE")));
        let mut off = on.clone();
        off.nat_fix = false;
        assert!(lines(&off, Table::Nat).is_empty());
        let post = chain(&off, Table::Mangle, POST);
        assert_eq!(
            post[2],
            format!("{PROCESSED} -j MARK --set-xmark 0x0/0x40000000")
        );
        assert_eq!(post[3], format!("{PROCESSED} -j RETURN"));
    }

    #[test]
    fn interfaces_are_excluded() {
        let post = chain(&p(), Table::Mangle, POST);
        let pre = chain(&p(), Table::Mangle, PRE);
        for i in IFACE_EXCLUDE {
            assert!(post.contains(&format!("-o {i} -j RETURN")), "{i}");
            assert!(pre.contains(&format!("-i {i} -j RETURN")), "{i}");
        }
    }

    #[test]
    fn block_quic_drops_udp443_and_removes_it_from_queue() {
        let mut s = Settings::default();
        s.block_quic = true;
        let bq = params(&s, &Preset::default());
        let post = chain(&bq, Table::Mangle, POST);
        assert!(post.contains(&"-p udp --dport 443 -j DROP".to_string()));
        assert!(!bq.ports.udp.split(',').any(|x| x == "443"));
        assert!(!chain(&p(), Table::Mangle, POST)
            .iter()
            .any(|l| l.contains("DROP")));
    }

    #[test]
    fn queue_rules_use_connbytes_and_bypass() {
        let post = chain(&p(), Table::Mangle, POST);
        let want = "-p tcp -m multiport --dports 80,443,1984,2053,2083,2087,2096,5222,8443 \
                    -m connbytes --connbytes 1:15 --connbytes-dir original --connbytes-mode packets \
                    -j NFQUEUE --queue-num 300 --queue-bypass";
        assert!(post.contains(&want.to_string()), "{post:#?}");
        let pre = chain(&p(), Table::Mangle, PRE);
        assert!(pre.iter().any(|l| l.contains("--sports 80,443")
            && l.contains("--connbytes-dir reply")
            && l.contains("--queue-num 300 --queue-bypass")));
        for f in ["FIN FIN", "RST RST"] {
            assert!(
                post.iter()
                    .any(|l| l.contains(&format!("--tcp-flags {f} -j NFQUEUE"))),
                "{f}"
            );
            assert!(
                pre.iter()
                    .any(|l| l.contains(&format!("--tcp-flags {f} -j NFQUEUE"))),
                "{f}"
            );
        }
        assert!(pre
            .iter()
            .any(|l| l.contains("--tcp-flags SYN,ACK SYN,ACK -j NFQUEUE")));
    }

    #[test]
    fn preset_limits_win() {
        let mut preset = Preset::default();
        preset.limits.tcp_out = Some(6);
        let pr = params(&Settings::default(), &preset);
        assert_eq!(
            pr.limits,
            Limits {
                tcp_out: 6,
                tcp_in: 15,
                udp_out: 15,
                udp_in: 15
            }
        );
        assert!(chain(&pr, Table::Mangle, POST)
            .iter()
            .any(|l| l.contains("-p tcp") && l.contains("--connbytes 1:6 ")));
    }

    #[test]
    fn mss_rule_only_when_set() {
        assert!(!chain(&p(), Table::Mangle, POST)
            .iter()
            .any(|l| l.contains("TCPMSS")));
        let mut s = Settings::default();
        s.tcp_mss_clamp = 1;
        let post = chain(&params(&s, &Preset::default()), Table::Mangle, POST);
        assert!(post
            .iter()
            .any(|l| l.ends_with("--tcp-flags SYN,RST SYN -j TCPMSS --set-mss 536")));
    }

    #[test]
    fn meta_quic_chain_in_filter_output() {
        let f = chain(&p(), Table::Filter, MQUIC);
        assert_eq!(f.len(), 1);
        assert!(f[0].starts_with("-p udp --dport 443 -d 157.240.0.0/16,"));
        assert!(f[0].ends_with("-j REJECT --reject-with icmp-port-unreachable"));
        let mut off = p();
        off.meta_quic = false;
        assert!(lines(&off, Table::Filter).is_empty());
    }

    #[test]
    fn ports_over_15_split_into_rules() {
        let mut pr = p();
        pr.ports.tcp = (1000..1020)
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let post = chain(&pr, Table::Mangle, POST);
        let queue: Vec<_> = post
            .iter()
            .filter(|l| l.starts_with("-p tcp -m multiport --dports") && l.contains("connbytes"))
            .collect();
        assert_eq!(queue.len(), 2, "{queue:#?}");
    }

    #[test]
    fn jump_lands_after_search_jumps() {
        assert_eq!(jump_position("-P POSTROUTING ACCEPT\n"), 1);
        let l = "-P POSTROUTING ACCEPT\n-A POSTROUTING -j bcw_post\n-A POSTROUTING -j bcw_post\n\
                 -A POSTROUTING -j fw_x\n-A POSTROUTING -j bcw_post\n";
        assert_eq!(jump_position(l), 3);
    }

    #[tokio::test]
    async fn apply_puts_jumps_after_search() {
        let r = RecordingIpt::default();
        r.set_rules(
            Table::Mangle,
            "POSTROUTING",
            vec![
                "-P POSTROUTING ACCEPT".into(),
                "-A POSTROUTING -j bcw_post".into(),
            ],
        );
        apply(&r, &p()).await.unwrap();
        let jumps: Vec<String> = r
            .restores()
            .iter()
            .flat_map(|b| b.lines().to_vec())
            .filter(|l| l.starts_with("-I "))
            .collect();
        assert!(
            jumps.contains(&format!("-I POSTROUTING 2 -j {POST}")),
            "{jumps:?}"
        );
        assert!(
            jumps.contains(&format!("-I PREROUTING 1 -j {PRE}")),
            "{jumps:?}"
        );
        assert!(
            jumps.contains(&format!("-I POSTROUTING 1 -j {NAT}")),
            "{jumps:?}"
        );
        assert!(
            jumps.contains(&format!("-I OUTPUT 1 -j {MQUIC}")),
            "{jumps:?}"
        );
    }

    #[tokio::test]
    async fn apply_twice_leaves_one_copy() {
        let r = RecordingIpt::default();
        apply(&r, &p()).await.unwrap();
        apply(&r, &p()).await.unwrap();
        let ops = r.ops();
        let last_x = ops
            .iter()
            .rposition(|o| o.contains(&format!("-X {MQUIC}")))
            .unwrap();
        let after = &ops[last_x + 1..];
        let restores = after.iter().filter(|o| o.starts_with("restore:")).count();
        // mangle и nat/filter цепочки + переходы: батчи цепочек (3) и батчи переходов (3).
        assert_eq!(restores, 6, "{after:#?}");
        let before = &ops[..last_x];
        assert!(before
            .iter()
            .any(|o| o.contains(&format!("-D POSTROUTING -j {POST}"))));
    }

    #[tokio::test]
    async fn remove_deletes_every_copy_of_a_jump_and_the_chains() {
        let r = RecordingIpt::default();
        r.delete_succeeds(Table::Mangle, "POSTROUTING", 3);
        remove(&r).await;
        let deletes = r
            .cmds()
            .iter()
            .filter(|(t, a)| {
                *t == Table::Mangle && a[..2] == ["-D".to_string(), "POSTROUTING".to_string()]
            })
            .count();
        assert_eq!(deletes, 4, "три успешных и одна неуспешная");
        for (t, c) in CHAINS {
            assert!(
                r.cmds()
                    .contains(&(t, vec!["-X".to_string(), c.to_string()])),
                "{c}"
            );
        }
    }
}
