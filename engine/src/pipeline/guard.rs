//! Постановка правил плана под стражем порядка.
//!
//! Перед каждым планом наши переходы проверяются: сторож модуля обхода вставляет свои правила
//! на позицию 1 при смене сети, а система может сбросить таблицы целиком. Каждая поправка
//! уходит в поток `--progress` и в журнал.

use crate::error::BlockcheckError;
use crate::firewall::ipt::{IptRun, SystemIpt};
use crate::firewall::rules::{self, OwnedChains};
use crate::nfqws2::dispatch::Dispatch;
use crate::nfqws2::run::Ready;

/// Поправки порядка — в журнал и в поток `--progress`.
fn report(fixes: &[rules::Reorder]) {
    for fix in fixes {
        tracing::warn!(
            table = fix.table.name(),
            chain = fix.chain,
            reapplied = fix.reapplied,
            "наш переход не был первым — поставлен заново"
        );
        crate::machine::emit_reorder(fix.table.name(), fix.chain, fix.reapplied);
    }
}

/// Устояла ли изоляция за время плана: проверяется ПОСЛЕ плана. Если сторож обхода успел
/// встать перед нами, пробы этого плана шли через его очередь — их «успехи» не наши.
/// Порядок при этом сразу восстанавливается для следующего плана.
pub async fn isolation_held<R: IptRun>(r: &R, chains: &OwnedChains) -> bool {
    match rules::ensure_order(r, chains).await {
        Ok(fixes) => {
            report(&fixes);
            fixes.is_empty()
        }
        Err(e) => {
            tracing::warn!(error = %e, "порядок наших переходов не прочитан — план не засчитан");
            false
        }
    }
}

/// Проверить порядок наших переходов и поставить правила плана.
pub async fn apply_guarded(
    chains: &OwnedChains,
    ready: &Ready,
    dispatch: &Dispatch,
    ips: &[String],
) -> Result<(), BlockcheckError> {
    report(&rules::ensure_order(&SystemIpt, chains).await?);
    rules::apply_dispatch(&SystemIpt, chains, ready, dispatch, ips).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::ipt::testing::RecordingIpt;
    use crate::firewall::ipt::Table;

    fn jumps_first(r: &RecordingIpt) {
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

    /// Review I5: план, во время которого сторож обхода встал перед нами, мерил ЕГО обход,
    /// а не наш, — изоляция названа нарушенной.
    #[tokio::test]
    async fn isolation_is_broken_when_a_foreign_jump_got_ahead() {
        let r = RecordingIpt::default();
        let chains = rules::prepare_chains(&r, "bcw").await.unwrap();
        jumps_first(&r);
        r.set_rules(
            Table::Mangle,
            "POSTROUTING",
            vec![
                "-A POSTROUTING -j nfqws_post".into(),
                "-A POSTROUTING -j bcw_post".into(),
            ],
        );
        assert!(!isolation_held(&r, &chains).await);
    }

    #[tokio::test]
    async fn isolation_holds_when_our_jumps_stayed_first() {
        let r = RecordingIpt::default();
        let chains = rules::prepare_chains(&r, "bcw").await.unwrap();
        jumps_first(&r);
        assert!(isolation_held(&r, &chains).await);
    }
}
