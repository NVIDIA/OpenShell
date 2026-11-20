// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The VM driver's configuration and its view of the gateway startup document.
//!
//! The document's `[gateway]` table is defined by `openshell-driver-sdk`. Its
//! `[driver_config]` table is the operator's `[openshell.drivers.vm]` table,
//! passed through unchanged; [`VmComputeConfig`] is what the driver accepts in
//! it, and the driver validates it at startup.

use std::path::PathBuf;

use openshell_core::{Error, Result, UpstreamProxyConfig};
use openshell_driver_sdk::StartupDocument;

/// The VM driver's own configuration: the operator's `[openshell.drivers.vm]`
/// table, which the gateway passes through as the startup document's
/// `driver_config`. The driver validates it at startup.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VmComputeConfig {
    pub allow_driver_config: bool,
    pub resource_admission: openshell_core::resource_admission::ResourceAdmissionConfig,
    /// Working directory for VM driver sandbox state.
    pub state_dir: PathBuf,

    /// Default sandbox image the driver should use when a request omits one.
    pub default_image: String,

    /// Gateway gRPC endpoint the sandbox guest connects back to.
    pub grpc_endpoint: String,

    /// Bootstrap image used to boot and prepare VM sandbox target images.
    pub bootstrap_image: String,

    /// libkrun log level used by the VM driver helper.
    pub krun_log_level: u32,

    /// Default vCPU count for VM sandboxes.
    pub vcpus: u8,

    /// Default memory allocation for VM sandboxes, in MiB.
    pub mem_mib: u32,

    /// Writable overlay disk size for each VM sandbox, in MiB.
    pub overlay_disk_mib: u64,

    /// Optional UID override for the VM guest sandbox account.
    pub sandbox_uid: Option<u32>,

    /// Optional GID override for the VM guest sandbox account.
    pub sandbox_gid: Option<u32>,

    /// Directory shared with the gateway for request-scoped rootfs tar staging.
    pub rootfs_tar_staging_dir: Option<PathBuf>,

    /// Maximum accepted rootfs tar size, in bytes, before and after decompression.
    pub rootfs_tar_max_bytes: Option<u64>,

    /// Corporate forward-proxy settings passed to the VM driver. Flattening
    /// preserves the shared local-driver TOML field names.
    #[serde(flatten)]
    pub upstream_proxy: UpstreamProxyConfig,

    /// Path on the gateway host to a PEM CA bundle trusted for the corporate
    /// proxy and for server certificates re-signed by a TLS-intercepting proxy.
    pub proxy_ca_bundle: Option<PathBuf>,

    /// Explicit guest-reachable SPIFFE Workload API TCP listener. VM guests
    /// cannot receive a host UNIX socket, so this requires acknowledgement.
    pub provider_spiffe_workload_api_tcp_endpoint: Option<String>,
    #[serde(default)]
    pub provider_spiffe_allow_guest_tcp: bool,

    /// Allow bind-mounting host directories into VM sandboxes.
    #[serde(default)]
    pub enable_bind_mounts: bool,
}

impl VmComputeConfig {
    /// Default working directory for VM driver state.
    #[must_use]
    pub fn default_state_dir() -> PathBuf {
        openshell_core::paths::openshell_state_dir().map_or_else(
            |_| PathBuf::from("target/openshell-vm-driver"),
            |dir| dir.join("vm-driver"),
        )
    }

    /// Default libkrun log level.
    #[must_use]
    pub const fn default_krun_log_level() -> u32 {
        1
    }

    /// Default vCPU count.
    #[must_use]
    pub const fn default_vcpus() -> u8 {
        2
    }

    /// Default memory allocation, in MiB.
    #[must_use]
    pub const fn default_mem_mib() -> u32 {
        2048
    }

    /// Default writable overlay disk size, in MiB.
    #[must_use]
    pub const fn default_overlay_disk_mib() -> u64 {
        4096
    }

    /// Validate startup configuration without resolving binaries, creating
    /// state directories, spawning a process, or connecting a socket.
    pub fn validate_configuration(&self) -> Result<()> {
        self.resource_admission.validate().map_err(Error::config)?;
        if self.grpc_endpoint.trim().is_empty() {
            return Err(Error::config(
                "grpc_endpoint is required when using the vm compute driver",
            ));
        }
        if self.bootstrap_image.trim().is_empty() && self.default_image.trim().is_empty() {
            return Err(Error::config(
                "bootstrap_image or default_image is required when using the vm compute driver; sandbox images cannot be used as VM bootstrap images",
            ));
        }
        validate_vm_sandbox_identity(self)?;
        if self
            .rootfs_tar_staging_dir
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(Error::config(
                "rootfs_tar_staging_dir must not be empty when set",
            ));
        }
        if self.rootfs_tar_max_bytes == Some(0) {
            return Err(Error::config(
                "rootfs_tar_max_bytes must be greater than zero when set",
            ));
        }
        self.validate_proxy_config()?;
        if let Some(endpoint) = self.provider_spiffe_workload_api_tcp_endpoint.as_deref() {
            openshell_core::driver_utils::validate_guest_spiffe_tcp_endpoint(
                endpoint,
                self.provider_spiffe_allow_guest_tcp,
            )
            .map_err(Error::config)?;
        } else if self.provider_spiffe_allow_guest_tcp {
            return Err(Error::config(
                "provider_spiffe_allow_guest_tcp is set but no provider_spiffe_workload_api_tcp_endpoint is configured",
            ));
        }
        Ok(())
    }

    fn validate_proxy_config(&self) -> Result<()> {
        self.upstream_proxy.validate().map_err(Error::config)?;
        if let Some(path) = self.proxy_ca_bundle.as_ref() {
            if path.as_os_str().is_empty() {
                return Err(Error::config("proxy_ca_bundle must not be empty when set"));
            }
            if self.upstream_proxy.https_proxy.is_none() {
                return Err(Error::config(
                    "proxy_ca_bundle is set but no https_proxy is configured",
                ));
            }
        }
        Ok(())
    }
}

impl Default for VmComputeConfig {
    fn default() -> Self {
        Self {
            state_dir: Self::default_state_dir(),
            allow_driver_config: false,
            resource_admission:
                openshell_core::resource_admission::ResourceAdmissionConfig::default(),
            default_image: openshell_core::image::default_sandbox_image(),
            grpc_endpoint: String::new(),
            bootstrap_image: String::new(),
            krun_log_level: Self::default_krun_log_level(),
            vcpus: Self::default_vcpus(),
            mem_mib: Self::default_mem_mib(),
            overlay_disk_mib: Self::default_overlay_disk_mib(),
            sandbox_uid: None,
            sandbox_gid: None,
            rootfs_tar_staging_dir: None,
            rootfs_tar_max_bytes: None,
            upstream_proxy: UpstreamProxyConfig::default(),
            proxy_ca_bundle: None,
            provider_spiffe_workload_api_tcp_endpoint: None,
            provider_spiffe_allow_guest_tcp: false,
            enable_bind_mounts: false,
        }
    }
}

impl VmComputeConfig {
    /// Decode the document's `driver_config` table.
    ///
    /// # Errors
    ///
    /// Returns a message naming the unknown or invalid key.
    pub fn from_document(document: &StartupDocument) -> std::result::Result<Self, String> {
        toml::Value::Table(document.driver_config.clone())
            .try_into()
            .map_err(|error: toml::de::Error| {
                format!("invalid [driver_config] in startup document: {error}")
            })
    }
}

pub fn validate_vm_sandbox_identity(config: &VmComputeConfig) -> Result<()> {
    let range = openshell_policy::MIN_SANDBOX_UID..=openshell_policy::MAX_SANDBOX_UID;
    for (field, value) in [
        ("sandbox_uid", config.sandbox_uid),
        ("sandbox_gid", config.sandbox_gid),
    ] {
        if let Some(value) = value
            && !range.contains(&value)
        {
            return Err(Error::config(format!(
                "{field} {value} is outside the allowed range [{}, {}]",
                openshell_policy::MIN_SANDBOX_UID,
                openshell_policy::MAX_SANDBOX_UID
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/startup-vm.toml");

    #[test]
    fn the_fixture_driver_config_deserializes_and_validates() {
        let document = StartupDocument::parse(FIXTURE).unwrap();
        let config = VmComputeConfig::from_document(&document).unwrap();
        config.validate_configuration().unwrap();
        assert_eq!(config.vcpus, 4);
        assert!(config.allow_driver_config);
        assert_eq!(config.grpc_endpoint, "https://127.0.0.1:8080");
    }

    #[test]
    fn unknown_driver_config_keys_are_rejected() {
        let mut document = StartupDocument::parse(FIXTURE).unwrap();
        document.driver_config = toml::from_str("surprise = 1").unwrap();
        let error = VmComputeConfig::from_document(&document).unwrap_err();
        assert!(error.contains("surprise"), "{error}");
    }

    #[test]
    fn keys_the_gateway_owns_are_rejected_in_driver_config() {
        for key in ["guest_tls_ca", "driver_dir"] {
            let mut document = StartupDocument::parse(FIXTURE).unwrap();
            document.driver_config = toml::from_str(&format!("{key} = '/x'")).unwrap();
            assert!(VmComputeConfig::from_document(&document).is_err(), "{key}");
        }
    }

    #[test]
    fn vm_uses_nvidia_ubuntu_default_image() {
        assert_eq!(
            VmComputeConfig::default().default_image,
            openshell_core::image::DEFAULT_SANDBOX_BASE_IMAGE
        );
    }

    #[test]
    fn vm_gateway_requires_a_trusted_bootstrap_image_source() {
        let config = VmComputeConfig {
            grpc_endpoint: "http://127.0.0.1:50051".to_string(),
            default_image: String::new(),
            bootstrap_image: String::new(),
            ..Default::default()
        };
        let error = config
            .validate_configuration()
            .expect_err("the gateway must reject an empty bootstrap configuration");
        assert!(error.to_string().contains("sandbox images cannot be used"));

        VmComputeConfig {
            default_image: "openshell/sandbox:default".to_string(),
            ..config.clone()
        }
        .validate_configuration()
        .expect("the operator-controlled default image is a valid fallback");

        VmComputeConfig {
            bootstrap_image: "openshell/sandbox-bootstrap:latest".to_string(),
            ..config
        }
        .validate_configuration()
        .expect("an explicit bootstrap image is valid");
    }

    #[test]
    fn invalid_corporate_proxy_config_is_rejected_before_the_driver_starts() {
        let err = UpstreamProxyConfig {
            https_proxy: Some("socks5://proxy.corp.com:1080".to_string()),
            ..Default::default()
        }
        .validate()
        .expect_err("only http:// and https:// proxies are supported");
        assert!(err.contains("https_proxy"), "{err}");

        VmComputeConfig {
            proxy_ca_bundle: Some(PathBuf::from("/etc/openshell/tls/proxy-ca.pem")),
            ..Default::default()
        }
        .validate_proxy_config()
        .expect_err("a CA bundle without a proxy URL must fail closed");

        VmComputeConfig {
            upstream_proxy: UpstreamProxyConfig {
                https_proxy: Some("http://proxy.corp.com:8080".to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
        .validate_proxy_config()
        .expect("a lone proxy URL is a complete configuration");
    }

    #[test]
    fn vm_gateway_toml_accepts_rootfs_tar_settings() {
        let config: VmComputeConfig = toml::from_str(
            r#"
                grpc_endpoint = "http://127.0.0.1:50051"
                rootfs_tar_staging_dir = "/var/lib/openshell/rootfs-tar-staging"
                rootfs_tar_max_bytes = 1073741824
            "#,
        )
        .expect("schema-v2 VM rootfs tar settings must deserialize");
        config
            .validate_configuration()
            .expect("rootfs tar settings must pass static validation");
    }

    #[test]
    fn vm_gateway_rejects_zero_rootfs_tar_limit() {
        let config = VmComputeConfig {
            grpc_endpoint: "http://127.0.0.1:50051".to_string(),
            rootfs_tar_max_bytes: Some(0),
            ..Default::default()
        };

        let error = config
            .validate_configuration()
            .expect_err("a zero rootfs tar limit must fail before driver startup");
        assert!(error.to_string().contains("rootfs_tar_max_bytes"));
    }

    #[test]
    fn vm_gateway_config_rejects_root_identity() {
        let config = VmComputeConfig {
            sandbox_uid: Some(0),
            ..Default::default()
        };
        let error = validate_vm_sandbox_identity(&config).expect_err("root UID must fail");
        assert!(error.to_string().contains("sandbox_uid 0"));
    }
}
