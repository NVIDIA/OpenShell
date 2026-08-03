// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! BlueField VM-driver CLI/env surface.
//!
//! The root driver binary exposes these flags, but the extension owns their
//! names, defaults, parsing, and conversion into [`BluefieldDriverConfig`].

use std::path::PathBuf;

use bf_core::BluefieldRole;
use clap::Args;

use super::{BluefieldDriverConfig, ProxyPlacement};

#[derive(Args, Debug, Clone, Default)]
pub struct BluefieldDriverArgs {
    #[arg(
        long = "bluefield",
        env = bf_core::env::BLUEFIELD,
        default_value_t = false
    )]
    pub enabled: bool,

    /// Deployment role: `all-in-one` (default), `control-plane`, or
    /// `compute-node`. Selects how this driver instance behaves in the split
    /// topology.
    #[arg(
        long = "bluefield-role",
        env = bf_core::env::BLUEFIELD_ROLE,
        default_value = "all-in-one"
    )]
    pub role: String,

    #[arg(
        long = "bluefield-controller-endpoint",
        env = bf_core::env::BLUEFIELD_CONTROLLER_ENDPOINT
    )]
    pub controller_endpoint: Option<String>,

    #[arg(long = "bluefield-tls-dir", env = bf_core::env::BLUEFIELD_TLS_DIR)]
    pub tls_dir: Option<PathBuf>,

    #[arg(
        long = "bluefield-tls-domain",
        env = bf_core::env::BLUEFIELD_TLS_DOMAIN,
        default_value = "bluefield-controller"
    )]
    pub tls_domain: String,

    #[arg(long = "bluefield-host-pf", env = bf_core::env::BLUEFIELD_HOST_PF)]
    pub host_pf: Option<String>,

    #[arg(
        long = "bluefield-reserved-vf-index",
        env = bf_core::env::BLUEFIELD_RESERVED_VF_INDEXES,
        value_delimiter = ','
    )]
    pub reserved_vf_indexes: Vec<u32>,

    #[arg(long = "bluefield-pf-key", env = bf_core::env::BLUEFIELD_PF_KEY)]
    pub pf_key: Option<String>,

    #[arg(long = "bluefield-snat-ip", env = bf_core::env::BLUEFIELD_SNAT_IP)]
    pub snat_ip: Option<String>,

    #[arg(
        long = "bluefield-uplink-port",
        env = bf_core::env::BLUEFIELD_UPLINK_PORT
    )]
    pub uplink_port: Option<String>,

    #[arg(
        long = "bluefield-kernel-image",
        env = bf_core::env::BLUEFIELD_KERNEL_IMAGE
    )]
    pub kernel_image: Option<PathBuf>,

    #[arg(
        long = "bluefield-kernel-version",
        env = bf_core::env::BLUEFIELD_KERNEL_VERSION
    )]
    pub kernel_version: Option<String>,

    #[arg(
        long = "bluefield-kernel-sha256",
        env = bf_core::env::BLUEFIELD_KERNEL_SHA256
    )]
    pub kernel_sha256: Option<String>,

    #[arg(
        long = "bluefield-kernel-modules",
        env = bf_core::env::BLUEFIELD_KERNEL_MODULES,
        value_delimiter = ','
    )]
    pub kernel_modules: Vec<String>,

    #[arg(
        long = "bluefield-egress-cidr",
        env = bf_core::env::BLUEFIELD_EGRESS_CIDR
    )]
    pub egress_cidr: Option<String>,

    #[arg(
        long = "bluefield-egress-cidr-pool",
        env = bf_core::env::BLUEFIELD_EGRESS_CIDR_POOL,
        value_delimiter = ','
    )]
    pub egress_cidr_pool: Vec<String>,

    #[arg(
        long = "bluefield-egress-gateway",
        env = bf_core::env::BLUEFIELD_EGRESS_GATEWAY
    )]
    pub egress_gateway: Option<String>,

    #[arg(
        long = "bluefield-egress-dns",
        env = bf_core::env::BLUEFIELD_EGRESS_DNS,
        value_delimiter = ','
    )]
    pub egress_dns: Vec<String>,

    #[arg(
        long = "bluefield-proxy-placement",
        env = bf_core::env::BLUEFIELD_PROXY_PLACEMENT,
        default_value = "none"
    )]
    pub proxy_placement: String,

    #[arg(
        long = "bluefield-explicit-proxy-url",
        env = bf_core::env::BLUEFIELD_EXPLICIT_PROXY_URL
    )]
    pub explicit_proxy_url: Option<String>,
}

impl BluefieldDriverArgs {
    pub fn to_driver_config(
        &self,
        openshell_endpoint: Option<String>,
    ) -> Result<BluefieldDriverConfig, String> {
        let role = if self.role.trim().is_empty() {
            BluefieldRole::AllInOne
        } else {
            self.role.parse::<BluefieldRole>()?
        };
        Ok(BluefieldDriverConfig {
            enabled: self.enabled,
            role,
            openshell_endpoint,
            controller_endpoint: self.controller_endpoint.clone(),
            tls_dir: self.tls_dir.clone(),
            tls_domain: self.tls_domain.clone(),
            host_pf: self.host_pf.clone(),
            reserved_vf_indexes: self.reserved_vf_indexes.clone(),
            pf_key: self.pf_key.clone(),
            snat_ip: self.snat_ip.clone(),
            uplink_port: self.uplink_port.clone(),
            kernel_image: self.kernel_image.clone(),
            kernel_version: self.kernel_version.clone(),
            kernel_image_sha256: self.kernel_sha256.clone(),
            kernel_modules: self.kernel_modules.clone(),
            egress_cidr: self.egress_cidr.clone(),
            egress_cidr_pool: self.egress_cidr_pool.clone(),
            egress_gateway: self.egress_gateway.clone(),
            egress_dns: self.egress_dns.clone(),
            proxy_placement: parse_proxy_placement(&self.proxy_placement)?,
            explicit_proxy_url: self.explicit_proxy_url.clone(),
        })
    }
}

fn parse_proxy_placement(value: &str) -> Result<ProxyPlacement, String> {
    match value {
        "none" => Ok(ProxyPlacement::None),
        "dpu" => Ok(ProxyPlacement::Dpu),
        other => Err(format!(
            "invalid BlueField proxy placement {other:?}; expected 'none' or 'dpu'"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_driver_config_parses_proxy_placement() {
        let args = BluefieldDriverArgs {
            enabled: true,
            proxy_placement: "dpu".to_string(),
            explicit_proxy_url: Some("http://10.0.0.2:3128".to_string()),
            ..BluefieldDriverArgs::default()
        };

        let config = args
            .to_driver_config(Some("https://gateway.example".to_string()))
            .unwrap();

        assert!(config.enabled);
        assert_eq!(
            config.openshell_endpoint,
            Some("https://gateway.example".to_string())
        );
        assert_eq!(config.proxy_placement, ProxyPlacement::Dpu);
        assert_eq!(
            config.explicit_proxy_url,
            Some("http://10.0.0.2:3128".to_string())
        );
    }

    #[test]
    fn to_driver_config_rejects_unknown_proxy_placement() {
        let args = BluefieldDriverArgs {
            proxy_placement: "host".to_string(),
            ..BluefieldDriverArgs::default()
        };

        let err = args.to_driver_config(None).unwrap_err();

        assert!(err.contains("invalid BlueField proxy placement"));
    }
}
