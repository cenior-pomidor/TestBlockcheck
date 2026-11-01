use std::num::NonZeroU16;

use crate::nfqws2::space;

/// Метка пакетов nfqws2 поиска (`--fwmark`). Функция, а не константа: раскладку задаёт
/// командная строка (`--mark-desync`, `--mark-profile-shift`).
pub fn desync_mark() -> u32 {
    space::space().desync()
}

/// Маска поля стратегии.
pub fn profile_mask() -> u32 {
    space::space().profile_mask()
}

/// Метка контроля: проба без десинка и DoH.
pub fn control_mark() -> u32 {
    space::space().control_mark()
}

/// Все наши биты метки.
pub fn our_mask() -> u32 {
    space::space().our_mask()
}

/// Встроенный ли режим. Живёт в библиотеке, а не в бинаре: его читают отчёт и память запусков.
static EMBEDDED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Встроены ли мы.
pub fn is_embedded() -> bool {
    EMBEDDED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Объявить встроенный режим (ставится разбором командной строки).
pub fn set_embedded(embedded: bool) {
    EMBEDDED.store(embedded, std::sync::atomic::Ordering::Relaxed);
}

/// МЕТКА ПРОБЫ. Два исхода, и ни одного числа снаружи: литеральный ноль невыразим.
///
/// На Android контроль ВСЕГДА несёт собственную метку: без неё он уходил бы через цепочки
/// модуля обхода, «проходил» и объявлял режущийся домен чистым.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMark {
    /// БЕЗ десинка: контроль, эталон, DoH.
    Control,
    /// С десинком: метка стратегии выбирает профиль внутри движка.
    Desync(ProfileMark),
}

impl ProbeMark {
    pub fn so_mark(self) -> u32 {
        match self {
            ProbeMark::Control => control_mark(),
            ProbeMark::Desync(profile) => profile.so_mark(),
        }
    }
}

/// Номер стратегии `1…254` в поле стратегии метки.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileMark(NonZeroU16);

impl ProfileMark {
    /// Метка стратегии с индексом `index` (нумерация с единицы). `255` — метка контроля,
    /// поэтому стратегией быть не может.
    pub fn new(index: u16) -> Option<Self> {
        if index > space::MAX_PROFILE_INDEX {
            return None;
        }
        NonZeroU16::new(index).map(ProfileMark)
    }

    pub fn index(self) -> u16 {
        self.0.get()
    }

    /// Что кладётся в `SO_MARK` сокета пробы.
    pub fn so_mark(self) -> u32 {
        u32::from(self.0.get()) << space::space().profile_shift()
    }

    /// Что оказывается в метке соединения после правила очереди: номер стратегии и бит
    /// «наше соединение».
    pub fn ct_mark(self) -> u32 {
        self.so_mark() | desync_mark()
    }

    /// Объявление профиля в argv движка.
    pub fn filter_arg(self) -> String {
        format!(
            "--filter-mark=0x{:08X}/0x{:08X}",
            self.so_mark(),
            profile_mask()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfqws2::space::FOREIGN_BITS;

    #[test]
    fn every_profile_mark_stays_in_our_bits() {
        for i in 1..=254u16 {
            let m = ProfileMark::new(i).unwrap();
            assert_eq!(m.so_mark() & FOREIGN_BITS, 0, "индекс {i}");
            assert_eq!(m.so_mark() & desync_mark(), 0, "индекс {i}");
            assert_eq!(m.so_mark() >> 22, u32::from(i), "индекс {i}");
            assert_ne!(m.ct_mark() & desync_mark(), 0, "индекс {i}");
            assert_eq!(m.ct_mark() & profile_mask(), m.so_mark(), "индекс {i}");
            assert_ne!(m.so_mark(), control_mark(), "индекс {i}");
        }
    }

    #[test]
    fn zero_255_and_above_are_not_profile_marks() {
        assert!(
            ProfileMark::new(0).is_none()
                && ProfileMark::new(255).is_none()
                && ProfileMark::new(300).is_none()
        );
    }

    #[test]
    fn filter_arg_spells_shifted_index_and_mask() {
        assert_eq!(
            ProfileMark::new(7).unwrap().filter_arg(),
            "--filter-mark=0x01C00000/0x3FC00000"
        );
    }

    #[test]
    fn control_probe_carries_control_mark() {
        assert_eq!(ProbeMark::Control.so_mark(), 0x3FC0_0000);
    }

    #[test]
    fn a_desync_probe_carries_the_profile_mark() {
        let profile = ProfileMark::new(7).unwrap();
        assert_eq!(ProbeMark::Desync(profile).so_mark(), profile.so_mark());
    }
}
