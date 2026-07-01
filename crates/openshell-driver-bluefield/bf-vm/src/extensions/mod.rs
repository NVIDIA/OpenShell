// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Concrete VM lifecycle extensions used by the BlueField VM driver.

use bf_core::BluefieldRole;

use crate::lifecycle::LifecycleExtensionRegistry;

pub use crate::cli::BluefieldDriverArgs;
pub use crate::extension::{BluefieldDriverConfig, BluefieldExtension};

#[derive(Debug, Clone, Default)]
pub struct ExtensionRuntimeConfig {
    pub bluefield: BluefieldDriverConfig,
}

/// Build the workload-side lifecycle extensions. Only the workload-running
/// roles (`all-in-one`, `compute-node`) install a BlueField extension; the
/// `control-plane` role runs no workload and serves the leader directly, so it
/// installs nothing here.
pub fn build_lifecycle_extensions(
    config: &ExtensionRuntimeConfig,
) -> Result<LifecycleExtensionRegistry, String> {
    let mut registry = LifecycleExtensionRegistry::new();
    let extension = match config.bluefield.role {
        BluefieldRole::ComputeNode => {
            BluefieldExtension::from_compute_node_config(&config.bluefield)?
        }
        BluefieldRole::AllInOne => BluefieldExtension::from_driver_config(&config.bluefield)?,
        BluefieldRole::ControlPlane => None,
    };
    if let Some(extension) = extension {
        registry.push(std::sync::Arc::new(extension));
    }
    Ok(registry)
}
