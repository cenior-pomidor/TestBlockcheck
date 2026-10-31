//! Постановка правил плана под стражем порядка.
//!
//! Перед каждым планом наши переходы проверяются: сторож модуля обхода вставляет свои правила
//! на позицию 1 при смене сети, а система может сбросить таблицы целиком. Каждая поправка
//! уходит в поток `--progress` и в журнал.

use crate::error::BlockcheckError;
use crate::firewall::ipt::SystemIpt;
use crate::firewall::rules::{self, OwnedChains};
use crate::nfqws2::dispatch::Dispatch;
use crate::nfqws2::run::Ready;

/// Проверить порядок наших переходов и поставить правила плана.
pub async fn apply_guarded(
    chains: &OwnedChains,
    ready: &Ready,
    dispatch: &Dispatch,
    ips: &[String],
) -> Result<(), BlockcheckError> {
    for fix in rules::ensure_order(&SystemIpt, chains).await? {
        tracing::warn!(
            table = fix.table.name(),
            chain = fix.chain,
            reapplied = fix.reapplied,
            "наш переход не был первым — поставлен заново"
        );
        crate::machine::emit_reorder(fix.table.name(), fix.chain, fix.reapplied);
    }
    rules::apply_dispatch(&SystemIpt, chains, ready, dispatch, ips).await
}
