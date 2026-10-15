// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared CDI context schema.

use serde::{Deserialize, Serialize};

pub const CDI_CONTEXT_VERSION: u32 = 1;

/// Base workload-runtime path under which compute drivers mount CDI specification directories.
pub const CDI_SPEC_DIR_BASE: &str = "/.openshell/cdi-specs";

/// Return the workload-runtime path used for a CDI specification directory.
#[must_use]
pub fn cdi_spec_mount_path(index: usize) -> String {
    format!("{CDI_SPEC_DIR_BASE}/{index}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CdiContext {
    pub version: u32,
    pub selected_devices: Vec<String>,
    pub spec_dirs: Vec<CdiSpecDirectory>,
}

impl CdiContext {
    #[must_use]
    pub fn new(selected_devices: Vec<String>, spec_dirs: Vec<CdiSpecDirectory>) -> Self {
        Self {
            version: CDI_CONTEXT_VERSION,
            selected_devices,
            spec_dirs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CdiSpecDirectory {
    pub path: String,
    pub source: String,
}

impl CdiSpecDirectory {
    #[must_use]
    pub fn new(path: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            source: source.into(),
        }
    }
}
