// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-independent application listener configuration.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

    /// Canonical SNI/Host shared by URL publication, configuration and discovery.
    /// A discriminator selects the gateway's hashed mode; otherwise use readable names.
    pub fn service_hostname(
        &self,
        workspace: &str,
        sandbox: &str,
        service: &str,
        discriminator: Option<&str>,
    ) -> String {
        let label = service_route_label(discriminator, workspace, sandbox, service);
        format!("{label}.{}", self.domain)
    }

    /// Configured address only; this does not imply installation or readiness.
    pub fn service_url(
        &self,
        workspace: &str,
        sandbox: &str,
        service: &str,
        discriminator: Option<&str>,
    ) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let mut origin = url::Url::parse(self.public_url.as_deref()?).ok()?;
        origin
            .set_host(Some(&self.service_hostname(
                workspace,
                sandbox,
                service,
                discriminator,
            )))
            .ok()?;
        Some(origin.into())
    }
}

/// Shared naming policy for gateway-mediated and direct application URLs.
/// The ingress implementation does not participate in the public service identity.
pub fn service_route_label(
    discriminator: Option<&str>,
    workspace: &str,
    sandbox: &str,
    service: &str,
) -> String {
    discriminator.map_or_else(
        || {
            if service.is_empty() {
                format!("{workspace}--{sandbox}")
            } else {
                format!("{workspace}--{sandbox}--{service}")
            }
        },
        |gateway| service_route_hash_label(gateway, workspace, sandbox, Some(service)),
    )
}

/// Returns the stable, one-label DNS name for a service route.
///
/// This is a non-security naming digest, not authentication or proof of authority.
/// Preserve the existing SHA-256 input encoding and 80-bit base32 label from #4842.
pub fn service_route_hash_label(
    gateway_name: &str,
    workspace: &str,
    sandbox: &str,
    service: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(gateway_name.as_bytes());
    hasher.update([0]);
    hasher.update(workspace.as_bytes());
    hasher.update([0]);
    hasher.update(sandbox.as_bytes());
    hasher.update([0]);
    hasher.update(service.unwrap_or("").as_bytes());
    let digest = hasher.finalize();
    base32_lower_no_padding(&digest[..10])
}

fn base32_lower_no_padding(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut output = String::with_capacity(16);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(char::from(
                ALPHABET[((accumulator >> bits) & 0x1f) as usize],
            ));
        }
    }
    if bits > 0 {
        output.push(char::from(
            ALPHABET[((accumulator << (5 - bits)) & 0x1f) as usize],
        ));
    }
    output
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
    fn legacy_service_route_wire_payload_keeps_readable_routing_default() {
        use prost::Message as _;
        let legacy = b"\x0a\x08endpoint\x12\x03web\x18\x90\x3f\x20\x01\x28\x02";
        let route = crate::proto::SandboxServiceRoute::decode(legacy.as_slice()).unwrap();
        assert_eq!(route.endpoint_id, "endpoint");
        assert_eq!(route.name, "web");
        assert_eq!(route.target_port, 8080);
        assert!(route.application_hostname.is_empty());
    }

    #[test]
    fn application_urls_share_gateway_hash_labels_and_preserve_public_origin() {
        let config = AppListenerConfig {
            enabled: true,
            domain: "apps.example.com".into(),
            public_url: Some("https://apps.example.com:10443".into()),
            ..Default::default()
        };
        assert_eq!(
            config
                .service_url("default", "my-sandbox", "web", Some("gateway-a"))
                .unwrap(),
            "https://enh47uqyj7bpyttz.apps.example.com:10443/"
        );
        assert_eq!(
            config
                .service_url("default", "my-sandbox", "", Some("gateway-a"))
                .unwrap(),
            "https://eiud2z5apv3yeucg.apps.example.com:10443/"
        );
        assert_ne!(
            config.service_hostname("default", "my-sandbox", "web", Some("gateway-a")),
            config.service_hostname("default", "my-sandbox", "web", Some("gateway-b"))
        );
    }

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
            config
                .service_url("default", "demo", "web", None)
                .as_deref(),
            Some("https://default--demo--web.services.example.com:10443/")
        );
        config.public_url = Some("https://services.example.com:443/".into());
        assert_eq!(
            config.service_url("default", "demo", "", None).as_deref(),
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
        assert!(config.service_url("default", "demo", "web", None).is_none());
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
