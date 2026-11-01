//! Пути модуля и данных.

use std::path::PathBuf;

/// Где лежит модуль и где его данные.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub module_dir: PathBuf,
    pub data_dir: PathBuf,
}

impl Layout {
    /// Раскладка на телефоне.
    pub fn device() -> Layout {
        Layout {
            module_dir: super::MODULE_DIR.into(),
            data_dir: super::DATA_DIR.into(),
        }
    }

    /// Раскладка телефона с переопределением `BCW_MODULE_DIR` / `BCW_DATA_DIR` (стенд, тесты).
    pub fn from_env() -> Layout {
        let d = Layout::device();
        Layout {
            module_dir: std::env::var_os("BCW_MODULE_DIR")
                .map(PathBuf::from)
                .unwrap_or(d.module_dir),
            data_dir: std::env::var_os("BCW_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or(d.data_dir),
        }
    }

    pub fn nfqws2(&self) -> PathBuf {
        self.module_dir.join("bin/nfqws2")
    }
    pub fn lua_dir(&self) -> PathBuf {
        self.module_dir.join("lua")
    }
    pub fn blobs_dir(&self) -> PathBuf {
        self.module_dir.join("blobs")
    }
    pub fn module_lists(&self) -> PathBuf {
        self.module_dir.join("lists")
    }
    pub fn module_strategies(&self) -> PathBuf {
        self.module_dir.join("strategies")
    }
    pub fn defaults_dir(&self) -> PathBuf {
        self.module_dir.join("defaults")
    }
    pub fn data_lists(&self) -> PathBuf {
        self.data_dir.join("lists")
    }
    pub fn data_strategies(&self) -> PathBuf {
        self.data_dir.join("strategies")
    }
    pub fn settings_file(&self) -> PathBuf {
        self.data_dir.join("settings.conf")
    }
    pub fn networks_file(&self) -> PathBuf {
        self.data_dir.join("networks.tsv")
    }
    pub fn home_file(&self) -> PathBuf {
        self.data_dir.join("home_wifi.list")
    }
    pub fn logs_dir(&self) -> PathBuf {
        self.data_dir.join("logs")
    }
    pub fn state_dir(&self) -> PathBuf {
        self.data_dir.join("state")
    }
    pub fn tmp_dir(&self) -> PathBuf {
        self.data_dir.join("tmp")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_layout_matches_spec() {
        let l = Layout::device();
        assert_eq!(
            l.nfqws2(),
            PathBuf::from("/data/adb/modules/bcw/bin/nfqws2")
        );
        assert_eq!(
            l.settings_file(),
            PathBuf::from("/data/adb/bcw/settings.conf")
        );
        assert_eq!(l.data_lists(), PathBuf::from("/data/adb/bcw/lists"));
    }
}
