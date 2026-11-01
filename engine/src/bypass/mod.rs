//! Модуль обхода `bcw` для KernelSU (этап 2): пресеты, настройки, правила `dpi_*`, служба.
//!
//! Поведение повторяет nfqws2-android v2.0.4 (коммит `8e916c8`, MIT) — эталон, против
//! которого сверяются тесты. Спецификация: `docs/superpowers/specs/2026-11-01-bcw-module-design.md`.

pub mod layout;
pub mod ports;
pub mod preset;
pub mod settings;

/// Каталог модуля на телефоне.
pub const MODULE_DIR: &str = "/data/adb/modules/bcw";
/// Каталог данных модуля (переживает обновления, стирается удалением модуля).
pub const DATA_DIR: &str = "/data/adb/bcw";
/// Очередь nfqws2 обхода. Поиск ходит через 777.
pub const QNUM: u16 = 300;
