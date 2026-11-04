//! Поиск стратегий: общие типы и сборка пресета `found-*`.

use serde::{Deserialize, Serialize};

use crate::config::Protocol;

pub mod apply;
pub mod assemble;
pub mod job;
pub mod narrow;
pub mod runs;

/// Местное время без пояса (считает вызывающий).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NaiveStamp {
    pub y: i32,
    pub mo: u32,
    pub d: u32,
    pub h: u32,
    pub mi: u32,
    pub s: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    General,
    Youtube,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Tls13,
    Tls12,
    Http,
}

impl Proto {
    pub fn to_protocol(self) -> Protocol {
        match self {
            Proto::Tls13 => Protocol::HttpsTls13,
            Proto::Tls12 => Protocol::HttpsTls12,
            Proto::Http => Protocol::Http,
        }
    }
}

/// Найденные строки стратегий по группам.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Found {
    pub youtube: Option<String>,
    pub tls: Option<String>,
    pub http: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Applied,
    Partial { failed: Group },
    RolledBack { reason: String },
    NotFound,
    Stopped,
    NetworkChanged,
    SavedNotApplied { state: String },
}
