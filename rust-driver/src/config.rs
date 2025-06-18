use serde::{Deserialize, Serialize};

use crate::{ack_timeout::AckTimeoutConfig, net::config::NetworkConfig};

const DEFAULT_CONFIG_PATH: &str = "/etc/bluerdma/config.toml";

#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(#[from] toml::de::Error),
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct DeviceConfig {
    pub(crate) ack: AckTimeoutConfig,
}

impl DeviceConfig {
    pub(crate) fn ack(&self) -> AckTimeoutConfig {
        self.ack
    }
}

pub(crate) struct ConfigLoader;

impl ConfigLoader {
    /// Loads the configuration from the default path.
    pub(crate) fn load_default() -> Result<DeviceConfig, ConfigError> {
        Self::load_from_path(DEFAULT_CONFIG_PATH)
    }

    /// Loads the configuration from the specified path.
    pub(crate) fn load_from_path(path: &str) -> Result<DeviceConfig, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: DeviceConfig = toml::from_str(&content)?;
        Ok(config)
    }
}
