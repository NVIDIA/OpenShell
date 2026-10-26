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
    /// Public HTTPS origin, independently of the supervisor's listener port.
    pub public_url: Option<String>,
}

impl Default for AppListenerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 8443,
            domain: String::new(),
            public_url: None,
        }
    }
}

impl AppListenerConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            if self.public_url.is_some() {
                return Err("supervisor.app_listener.public_url requires enabled = true".into());
            }
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
        if let Some(origin) = &self.public_url {
            let parsed = url::Url::parse(origin)
                .map_err(|_| "supervisor.app_listener.public_url must be an HTTPS origin")?;
            if parsed.scheme() != "https"
                || parsed.host_str() != Some(self.domain.as_str())
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || parsed.port() == Some(0)
            {
                return Err("supervisor.app_listener.public_url must be an HTTPS origin matching domain, without credentials, path, query, or fragment".into());
            }
        }
        Ok(())
    }

    /// Configured address only; this does not imply installation or readiness.
    pub fn service_url(&self, workspace: &str, sandbox: &str, service: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let mut origin = url::Url::parse(self.public_url.as_deref()?).ok()?;
        let label = if service.is_empty() {
            format!("{workspace}--{sandbox}")
        } else {
            format!("{workspace}--{sandbox}--{service}")
        };
        origin
            .set_host(Some(&format!("{label}.{}", self.domain)))
            .ok()?;
        Some(origin.into())
    }
}

/// A synchronous view of installed ingress, evaluated on the sandbox instance
/// runtime. The requested lease must fit entirely within serving freshness.
pub type InstallationSource = std::sync::Arc<
    dyn Fn(std::time::Duration) -> crate::proto::SupervisorServiceAdvertisement + Send + Sync,
>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_origin_is_explicit_https_and_matches_listener_domain() {
        let mut config = AppListenerConfig {
            enabled: true,
            domain: "services.example.com".into(),
            public_url: Some("https://services.example.com:10443".into()),
            ..Default::default()
        };
        config.validate().unwrap();
        assert_eq!(
            config.service_url("default", "demo", "web").as_deref(),
            Some("https://default--demo--web.services.example.com:10443/")
        );
        config.public_url = Some("https://services.example.com:443/".into());
        assert_eq!(
            config.service_url("default", "demo", "").as_deref(),
            Some("https://default--demo.services.example.com/")
        );
        for bad in [
            "http://services.example.com",
            "https://other.example.com",
            "https://user:password@services.example.com",
            "https://services.example.com/path",
            "https://services.example.com/?query",
            "https://services.example.com/#fragment",
            "https://services.example.com:0",
            "not-a-url",
        ] {
            config.public_url = Some(bad.into());
            assert!(config.validate().is_err(), "{bad}");
        }
        config.public_url = Some("https://services.example.com".into());
        config.enabled = false;
        assert!(config.validate().is_err());
        assert!(config.service_url("default", "demo", "web").is_none());
    }

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
