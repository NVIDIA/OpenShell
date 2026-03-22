// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ergonomic builders for constructing OCSF events.
//!
//! Each event class has a builder that takes a `SandboxContext` reference
//! and provides chainable methods for setting event fields.

mod base;
mod config;
mod finding;
mod http;
mod lifecycle;
mod network;
mod process;
mod ssh;

pub use base::BaseEventBuilder;
pub use config::ConfigStateChangeBuilder;
pub use finding::DetectionFindingBuilder;
pub use http::HttpActivityBuilder;
pub use lifecycle::AppLifecycleBuilder;
pub use network::NetworkActivityBuilder;
pub use process::ProcessActivityBuilder;
pub use ssh::SshActivityBuilder;

use std::net::IpAddr;

use crate::OCSF_VERSION;
use crate::objects::{Container, Device, Endpoint, Image, Metadata, Product};

/// Immutable context created once at sandbox startup.
///
/// Passed to every event builder to populate shared OCSF fields
/// (metadata, container, device, proxy endpoint).
#[derive(Debug, Clone)]
pub struct SandboxContext {
    /// Sandbox unique identifier.
    pub sandbox_id: String,
    /// Sandbox display name.
    pub sandbox_name: String,
    /// Container image reference.
    pub container_image: String,
    /// Device hostname.
    pub hostname: String,
    /// Product version string.
    pub product_version: String,
    /// Proxy listen IP address.
    pub proxy_ip: IpAddr,
    /// Proxy listen port.
    pub proxy_port: u16,
}

impl SandboxContext {
    /// Build the OCSF `Metadata` object for any event.
    #[must_use]
    pub fn metadata(&self, profiles: &[&str]) -> Metadata {
        Metadata {
            version: OCSF_VERSION.to_string(),
            product: Product::openshell_sandbox(&self.product_version),
            profiles: profiles.iter().map(|s| (*s).to_string()).collect(),
            uid: Some(self.sandbox_id.clone()),
            log_source: None,
        }
    }

    /// Build the OCSF `Container` object.
    #[must_use]
    pub fn container(&self) -> Container {
        Container {
            name: self.sandbox_name.clone(),
            uid: Some(self.sandbox_id.clone()),
            image: Some(Image {
                name: self.container_image.clone(),
            }),
        }
    }

    /// Build the OCSF `Device` object.
    #[must_use]
    pub fn device(&self) -> Device {
        Device::linux(&self.hostname)
    }

    /// Build the `proxy_endpoint` object for the Network Proxy profile.
    #[must_use]
    pub fn proxy_endpoint(&self) -> Endpoint {
        Endpoint::from_ip(self.proxy_ip, self.proxy_port)
    }
}

#[cfg(test)]
pub(crate) fn test_sandbox_context() -> SandboxContext {
    SandboxContext {
        sandbox_id: "sandbox-abc123".to_string(),
        sandbox_name: "my-sandbox".to_string(),
        container_image: "ghcr.io/openshell/sandbox:latest".to_string(),
        hostname: "sandbox-abc123".to_string(),
        product_version: "0.1.0".to_string(),
        proxy_ip: "10.42.0.1".parse().unwrap(),
        proxy_port: 3128,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_context_metadata() {
        let ctx = test_sandbox_context();
        let meta = ctx.metadata(&["security_control", "container"]);
        assert_eq!(meta.version, "1.7.0");
        assert_eq!(meta.product.name, "OpenShell Sandbox Supervisor");
        assert_eq!(meta.profiles.len(), 2);
        assert_eq!(meta.uid.as_deref(), Some("sandbox-abc123"));
    }

    #[test]
    fn test_sandbox_context_container() {
        let ctx = test_sandbox_context();
        let container = ctx.container();
        assert_eq!(container.name, "my-sandbox");
        assert_eq!(container.uid.as_deref(), Some("sandbox-abc123"));
    }

    #[test]
    fn test_sandbox_context_device() {
        let ctx = test_sandbox_context();
        let device = ctx.device();
        assert_eq!(device.hostname, "sandbox-abc123");
    }

    #[test]
    fn test_sandbox_context_proxy_endpoint() {
        let ctx = test_sandbox_context();
        let ep = ctx.proxy_endpoint();
        assert_eq!(ep.ip.as_deref(), Some("10.42.0.1"));
        assert_eq!(ep.port, Some(3128));
    }
}
