//! РАСКЛАДКА МАРКИ ДЛЯ ANDROID — чьи биты какие.
//!
//! Марка пакета одна на всё ядро, и на Android живём мы в ней не одни:
//!
//! | биты  | владелец      | что там                                                      |
//! |-------|---------------|--------------------------------------------------------------|
//! | 0–20  | Android netd  | номер сети, VPN, права (`include/Fwmark.h`)                 |
//! | 21    | bcw           | `DESYNC` — пакеты, отправленные nfqws2 поиска (`--fwmark`)   |
//! | 22–29 | bcw           | номер стратегии 1…254; 255 — `CONTROL` (без десинка, DoH)    |
//! | 30    | модули обхода | пакеты nfqws2 обхода (zapret, nfqws2-android)               |
//! | 31    | Android netd  | `ingress_cpu_wakeup`                                         |
//!
//! Биты netd в наших пробах обязаны быть нулями: правило «сеть по умолчанию» на устройстве
//! (`fwmark 0x0/0xffff`) иначе не сработает, и сокет получит `ENETUNREACH`.

use std::sync::atomic::{AtomicU32, Ordering};

/// Ширина поля стратегии: восемь бит — 254 стратегии и метка контроля.
pub const PROFILE_WIDTH: u32 = 8;

/// Сдвиг поля стратегии по умолчанию (биты 22–29).
pub const DEFAULT_PROFILE_SHIFT: u32 = 22;

/// Метка пакетов nfqws2 поиска по умолчанию (бит 21).
pub const DEFAULT_DESYNC_MARK: u32 = 0x0020_0000;

/// Значение поля стратегии, означающее «контроль»: проба без десинка, DoH.
pub const CONTROL_INDEX: u32 = 255;

/// Наибольший номер стратегии.
pub const MAX_PROFILE_INDEX: u16 = 254;

/// Биты, которые не наши: 0–20 и 31 — Android netd, 30 — nfqws2 модулей обхода.
pub const FOREIGN_BITS: u32 = 0xC01F_FFFF;

/// Наибольший допустимый сдвиг: поле из восьми бит не должно доставать до бита 30.
const MAX_PROFILE_SHIFT: u32 = 23;

static DESYNC: AtomicU32 = AtomicU32::new(DEFAULT_DESYNC_MARK);
static PROFILE_SHIFT: AtomicU32 = AtomicU32::new(DEFAULT_PROFILE_SHIFT);

/// Проверенная раскладка. Получить её можно только через [`MarkSpace::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkSpace {
    desync: u32,
    profile_shift: u32,
}

impl MarkSpace {
    /// Собрать раскладку, проверив её: каждая причина отказа тихо ломает подбор.
    pub fn new(desync: u32, profile_shift: u32) -> Result<Self, String> {
        if desync == 0 {
            return Err("метка десинка не может быть нулевой: ноль значит «метки нет»".into());
        }
        if desync & FOREIGN_BITS != 0 {
            return Err(format!(
                "--mark-desync 0x{desync:08X} задевает чужие биты (0x{FOREIGN_BITS:08X}: \
                 0–20 и 31 — Android netd, 30 — nfqws2 обхода)"
            ));
        }
        if profile_shift > MAX_PROFILE_SHIFT {
            return Err(format!(
                "--mark-profile-shift {profile_shift}: поле стратегии дошло бы до бита 30 и выше"
            ));
        }
        let profile = profile_field(profile_shift);
        if profile & FOREIGN_BITS != 0 {
            return Err(format!(
                "--mark-profile-shift {profile_shift}: поле стратегии 0x{profile:08X} задевает \
                 чужие биты (0x{FOREIGN_BITS:08X})"
            ));
        }
        if desync & profile != 0 {
            return Err(format!(
                "--mark-desync 0x{desync:08X} лежит внутри поля стратегии 0x{profile:08X}: \
                 собственный реинжект станет неотличим от пробы"
            ));
        }
        Ok(MarkSpace {
            desync,
            profile_shift,
        })
    }

    pub fn desync(self) -> u32 {
        self.desync
    }

    pub fn profile_shift(self) -> u32 {
        self.profile_shift
    }

    /// Маска поля стратегии.
    pub fn profile_mask(self) -> u32 {
        profile_field(self.profile_shift)
    }

    /// Метка контроля: все биты поля стратегии.
    pub fn control_mark(self) -> u32 {
        CONTROL_INDEX << self.profile_shift
    }

    /// Все наши биты: поле стратегии и десинк.
    pub fn our_mask(self) -> u32 {
        self.profile_mask() | self.desync
    }
}

fn profile_field(shift: u32) -> u32 {
    ((1u32 << PROFILE_WIDTH) - 1) << shift
}

/// Текущая раскладка процесса.
pub fn space() -> MarkSpace {
    MarkSpace {
        desync: DESYNC.load(Ordering::Relaxed),
        profile_shift: PROFILE_SHIFT.load(Ordering::Relaxed),
    }
}

/// Объявить раскладку (ставится разбором командной строки, до всякой работы с ядром).
pub fn set_space(space: MarkSpace) {
    DESYNC.store(space.desync, Ordering::Relaxed);
    PROFILE_SHIFT.store(space.profile_shift, Ordering::Relaxed);
}

/// Разобрать марку из строки: `0x00200000` или десятичное число.
pub fn parse_mark(raw: &str) -> Result<u32, String> {
    let trimmed = raw.trim();
    let parsed = match trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => trimmed.parse::<u32>(),
    };
    parsed.map_err(|_| format!("не марка: '{raw}' (ожидается 0xHEX или десятичное число)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_layout_matches_spec() {
        let s = MarkSpace::new(DEFAULT_DESYNC_MARK, DEFAULT_PROFILE_SHIFT).unwrap();
        assert_eq!(
            (s.desync(), s.profile_mask(), s.our_mask(), s.control_mark()),
            (0x0020_0000, 0x3FC0_0000, 0x3FE0_0000, 0x3FC0_0000)
        );
    }

    #[test]
    fn rejects_zero_desync() {
        assert!(MarkSpace::new(0, 22).is_err());
    }

    #[test]
    fn rejects_desync_in_netd_bits() {
        assert!(MarkSpace::new(0x0000_0001, 22).is_err());
    }

    #[test]
    fn rejects_profile_reaching_bit_30() {
        assert!(MarkSpace::new(0x0020_0000, 23).is_err());
    }

    #[test]
    fn rejects_desync_inside_profile() {
        assert!(MarkSpace::new(0x0040_0000, 22).is_err());
    }

    #[test]
    fn parses_hex_and_decimal_marks() {
        assert_eq!(parse_mark("0x00200000"), Ok(0x0020_0000));
        assert_eq!(parse_mark("2097152"), Ok(0x0020_0000));
        assert!(parse_mark("bits").is_err());
    }
}
