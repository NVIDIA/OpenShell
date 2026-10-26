// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-independent application listener configuration.

use serde::{Deserialize, Serialize};

/// Explicitly enabled application ingress. Deployment details such as TLS
/// Secret names belong to the driver, not to this common configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppListenerConfig {
    pub enabled: bool,
    pub port: u16,
    pub domain: String,
}

impl Default for AppListenerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 8443,
            domain: String::new(),
        }
    }
}

impl AppListenerConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.port < 1024 {
            return Err("supervisor.app_listener.port must be at least 1024".into());
        }
        if self.domain.len() > 253
            || !self.domain.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        {
            return Err("supervisor.app_listener.domain must be a lowercase DNS name".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_explicit_enablement_requires_a_valid_endpoint() {
        assert!(!AppListenerConfig::default().enabled);
        assert!(AppListenerConfig::default().validate().is_ok());
        let mut config = AppListenerConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        config.domain = "services.example.com".into();
        assert!(config.validate().is_ok());
        config.port = 0;
        assert!(config.validate().is_err());
    }
}

/// A synchronous view of installed ingress, evaluated on the sandbox instance
/// runtime. The requested lease must fit entirely within serving freshness.
pub type InstallationSource = std::sync::Arc<
    dyn Fn(std::time::Duration) -> crate::proto::SupervisorServiceAdvertisement + Send + Sync,
>;
