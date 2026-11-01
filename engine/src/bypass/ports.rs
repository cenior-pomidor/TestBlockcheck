//! Порты перехвата: семантика функций портов nfqws2-android (`lib/common.sh`).

/// Вес списка портов для `-m multiport`: порт — 1, диапазон `a:b` / `a-b` — 2. Предел — 15.
pub fn weight(list: &str) -> usize {
    list.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            if p.contains(':') || p.contains('-') {
                2
            } else {
                1
            }
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weight_counts_ranges_twice() {
        assert_eq!(weight(""), 0);
        assert_eq!(weight("443"), 1);
        assert_eq!(weight("443,590:600,1400,3478-3481"), 6);
        assert_eq!(
            weight("443,590:600,1400,3478:3481,5349,19294:19344,49152:65535"),
            11
        );
    }
}
