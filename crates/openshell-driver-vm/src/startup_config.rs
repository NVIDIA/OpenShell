// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The VM driver's view of the gateway startup document.
//!
//! The document's `[gateway]` table is defined by `openshell-driver-sdk`. Its
//! `[driver_config]` table is opaque there; [`VmDriverFileConfig`] is what the
//! VM driver accepts in it.

use std::io::Read;
use std::path::{Path, PathBuf};

use openshell_core::resource_admission::ResourceAdmissionConfig;
use openshell_driver_sdk::{MAX_DOCUMENT_BYTES, StartupDocument};
use serde::Deserialize;

/// The operator's settings in the document's `[driver_config]` table. A key left
/// out keeps the driver's own default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VmDriverFileConfig {
    pub allow_driver_config: Option<bool>,
    pub resource_admission: Option<ResourceAdmissionConfig>,
    /// Endpoint sandboxes use to reach the gateway.
    pub grpc_endpoint: Option<String>,
    pub https_proxy: Option<String>,
    pub no_proxy: Option<String>,
    pub proxy_auth_file: Option<PathBuf>,
    pub proxy_auth_allow_insecure: Option<bool>,
    pub proxy_connect_by_hostname: Option<bool>,
    pub proxy_ca_bundle: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub default_image: Option<String>,
    pub bootstrap_image: Option<String>,
    pub krun_log_level: Option<u32>,
    pub vcpus: Option<u8>,
    pub mem_mib: Option<u32>,
    pub overlay_disk_mib: Option<u64>,
    pub sandbox_uid: Option<u32>,
    pub sandbox_gid: Option<u32>,
    pub rootfs_tar_staging_dir: Option<PathBuf>,
    pub rootfs_tar_max_bytes: Option<u64>,
    pub enable_bind_mounts: Option<bool>,
    pub provider_spiffe_workload_api_tcp_endpoint: Option<String>,
    pub provider_spiffe_allow_guest_tcp: Option<bool>,
}

impl VmDriverFileConfig {
    /// Decode the document's `driver_config` table.
    ///
    /// # Errors
    ///
    /// Returns a message naming the unknown or invalid key.
    pub fn from_document(document: &StartupDocument) -> Result<Self, String> {
        toml::Value::Table(document.driver_config.clone())
            .try_into()
            .map_err(|error: toml::de::Error| {
                format!("invalid [driver_config] in startup document: {error}")
            })
    }
}

/// Read and parse a startup document, reading no more than the size limit.
///
/// # Errors
///
/// Returns a message that names the file for read failures, an oversized
/// document, a schema version this driver does not accept, or invalid content.
pub fn read_startup_document(path: &Path) -> Result<StartupDocument, String> {
    let mut text = String::new();
    std::fs::File::open(path)
        .and_then(|file| {
            file.take(MAX_DOCUMENT_BYTES as u64 + 1)
                .read_to_string(&mut text)
        })
        .map_err(|error| format!("read startup document {}: {error}", path.display()))?;
    StartupDocument::parse(&text)
        .map_err(|error| format!("startup document {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_driver_config_keys_are_rejected() {
        let mut document: StartupDocument = StartupDocument::parse(include_str!(
            "../../openshell-driver-sdk/tests/fixtures/startup-v1.toml"
        ))
        .unwrap();
        document.driver_config = toml::from_str("surprise = 1").unwrap();
        let error = VmDriverFileConfig::from_document(&document).unwrap_err();
        assert!(error.contains("surprise"), "{error}");
    }

    #[test]
    fn a_missing_file_names_the_path() {
        let error = read_startup_document(Path::new("/nonexistent/startup.toml")).unwrap_err();
        assert!(error.contains("/nonexistent/startup.toml"), "{error}");
    }
}
