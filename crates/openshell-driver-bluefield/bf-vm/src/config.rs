// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! BlueField VM-driver configuration and config-derived runtime options.

use std::path::PathBuf;

use bf_core::{BluefieldRole, ProxyPlacement};

use crate::guest_egress::GuestEgress;
use crate::kernel::BluefieldKernel;

/// VM-driver BlueField extension configuration.
///
/// The top-level driver keeps this disabled by default. When enabled, the
/// builder discovers host VFs under `host_pf`, rewrites their cross-host PF
/// coordinate to `pf_key` when supplied, and delegates datapath policy to the
/// remote DPU controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BluefieldDriverConfig {
    pub enabled: bool,
    pub role: BluefieldRole,
    pub openshell_endpoint: Option<String>,
    pub controller_endpoint: Option<String>,
    pub tls_dir: Option<PathBuf>,
    pub tls_domain: String,
    pub host_pf: Option<String>,
    pub reserved_vf_indexes: Vec<u32>,
    pub pf_key: Option<String>,
    pub snat_ip: Option<String>,
    pub uplink_port: Option<String>,
    pub kernel_image: Option<PathBuf>,
    pub kernel_version: Option<String>,
    pub kernel_image_sha256: Option<String>,
    pub kernel_modules: Vec<String>,
    pub egress_cidr: Option<String>,
    pub egress_cidr_pool: Vec<String>,
    pub egress_gateway: Option<String>,
    /// Retained for deployment compatibility. Lab/upstream DNS resolvers are
    /// applied by the DPU provider policy, not written into guest resolv.conf.
    pub egress_dns: Vec<String>,
    pub proxy_placement: ProxyPlacement,
    pub explicit_proxy_url: Option<String>,
}

impl Default for BluefieldDriverConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            role: BluefieldRole::AllInOne,
            openshell_endpoint: None,
            controller_endpoint: None,
            tls_dir: None,
            tls_domain: "bluefield-controller".to_string(),
            host_pf: None,
            reserved_vf_indexes: Vec::new(),
            pf_key: None,
            snat_ip: None,
            uplink_port: None,
            kernel_image: None,
            kernel_version: None,
            kernel_image_sha256: None,
            kernel_modules: Vec::new(),
            egress_cidr: None,
            egress_cidr_pool: Vec::new(),
            egress_gateway: None,
            egress_dns: Vec::new(),
            proxy_placement: ProxyPlacement::None,
            explicit_proxy_url: None,
        }
    }
}

/// PR1 defers the DPU proxy; reject any config that asks for it so a
/// misconfiguration fails loudly instead of silently ignoring the request.
pub(crate) fn reject_deferred_proxy(config: &BluefieldDriverConfig) -> Result<(), String> {
    if config.proxy_placement != ProxyPlacement::None {
        return Err("BlueField DPU proxy placement is deferred from PR1".to_string());
    }
    if config
        .explicit_proxy_url
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .is_some()
    {
        return Err("BlueField explicit proxy URL is deferred from PR1".to_string());
    }
    Ok(())
}

pub(crate) fn bluefield_kernel_from_config(
    config: &BluefieldDriverConfig,
) -> Option<BluefieldKernel> {
    let mut kernel = if let Some(image) = &config.kernel_image {
        BluefieldKernel::from_image(image.clone())
    } else if config.kernel_modules.is_empty()
        && config.kernel_version.is_none()
        && config.kernel_image_sha256.is_none()
    {
        return None;
    } else {
        BluefieldKernel::new()
    };

    if !config.kernel_modules.is_empty() {
        kernel = kernel.with_modules(config.kernel_modules.clone());
    }
    if let Some(version) = &config.kernel_version {
        kernel = kernel.with_version(version.clone());
    }
    if let Some(sha256) = &config.kernel_image_sha256 {
        kernel = kernel.with_image_sha256(sha256.clone());
    }
    Some(kernel)
}

pub(crate) fn guest_egress_from_config(
    config: &BluefieldDriverConfig,
) -> Result<Option<GuestEgress>, String> {
    let address_cidr = config
        .egress_cidr
        .clone()
        .or_else(|| config.egress_cidr_pool.first().cloned());
    match (address_cidr, &config.egress_gateway) {
        (Some(address_cidr), Some(gateway)) => Ok(Some(GuestEgress {
            address_cidr,
            gateway: gateway.clone(),
        })),
        (None, None) if !config.enabled => Ok(None),
        _ => Err(format!(
            "BlueField guest egress requires {} with {} or {}",
            bf_core::env::BLUEFIELD_EGRESS_GATEWAY,
            bf_core::env::BLUEFIELD_EGRESS_CIDR,
            bf_core::env::BLUEFIELD_EGRESS_CIDR_POOL
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{BluefieldDriverConfig, guest_egress_from_config, reject_deferred_proxy};
    use bf_core::ProxyPlacement;

    #[test]
    fn rejects_deferred_dpu_proxy_placement() {
        let config = BluefieldDriverConfig {
            enabled: true,
            proxy_placement: ProxyPlacement::Dpu,
            ..Default::default()
        };

        let err = reject_deferred_proxy(&config).unwrap_err();

        assert!(err.contains("DPU proxy placement is deferred"));
    }

    #[test]
    fn rejects_deferred_explicit_proxy_url() {
        let config = BluefieldDriverConfig {
            enabled: true,
            explicit_proxy_url: Some("http://100.64.4.1:3128".to_string()),
            ..Default::default()
        };

        let err = reject_deferred_proxy(&config).unwrap_err();

        assert!(err.contains("explicit proxy URL is deferred"));
    }

    #[test]
    fn guest_egress_from_config_accepts_cidr_and_gateway() {
        let config = BluefieldDriverConfig {
            enabled: true,
            egress_cidr: Some("10.0.120.10/22".to_string()),
            egress_gateway: Some("10.0.120.254".to_string()),
            ..Default::default()
        };

        let egress = guest_egress_from_config(&config)
            .unwrap()
            .expect("egress config");

        assert_eq!(egress.address_cidr, "10.0.120.10/22");
        assert_eq!(egress.gateway, "10.0.120.254");
    }

    #[test]
    fn guest_egress_requires_cidr_and_gateway_when_bluefield_enabled() {
        let config = BluefieldDriverConfig {
            enabled: true,
            ..Default::default()
        };

        let err = guest_egress_from_config(&config).unwrap_err();

        assert!(err.contains("BlueField guest egress requires"));
    }

    #[test]
    fn guest_egress_requires_gateway_with_cidr() {
        let config = BluefieldDriverConfig {
            enabled: true,
            egress_cidr: Some("10.0.120.10/22".to_string()),
            ..Default::default()
        };

        let err = guest_egress_from_config(&config).unwrap_err();

        assert!(err.contains("BlueField guest egress requires"));
    }

    #[test]
    fn guest_egress_requires_cidr_with_gateway() {
        let config = BluefieldDriverConfig {
            enabled: true,
            egress_gateway: Some("10.0.120.254".to_string()),
            ..Default::default()
        };

        let err = guest_egress_from_config(&config).unwrap_err();

        assert!(err.contains("BlueField guest egress requires"));
    }
}
