// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared CDI context schema and resolver helpers.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const CDI_CONTEXT_VERSION: u32 = 1;

/// File name used for the serialized CDI context.
pub const CDI_CONTEXT_FILE_NAME: &str = "cdi-context.json";

/// Absolute supervisor path for the CDI context file mounted by a compute driver.
pub const CDI_CONTEXT_PATH: &str = "/run/openshell/supervisor/cdi-context.json";

/// Base supervisor path under which compute drivers mount CDI specification directories.
pub const CDI_SPEC_DIR_BASE: &str = "/run/openshell/supervisor/cdi-specs";

/// Return the supervisor path used for a CDI specification directory.
#[must_use]
pub fn cdi_spec_mount_path(index: usize) -> String {
    format!("{CDI_SPEC_DIR_BASE}/{index}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CdiDerivedRequirements {
    pub device_node_paths: Vec<String>,
    pub read_only_mount_paths: Vec<String>,
    pub read_write_mount_paths: Vec<String>,
    pub additional_gids: Vec<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum CdiError {
    #[error("CDI policy resolution is unavailable on this platform")]
    UnsupportedPlatform,
    #[error("failed to read CDI context '{}': {source}", path.display())]
    ContextRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse CDI context '{}': {source}", path.display())]
    ContextParse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("unsupported CDI context version {0}")]
    UnsupportedContextVersion(u32),
    #[error("CDI spec dir '{path}' from source '{diagnostic_source}' is unsafe: {reason}")]
    UnsafeSpecDir {
        path: String,
        diagnostic_source: String,
        reason: &'static str,
    },
    #[error("selected CDI device '{0}' was not found in mounted CDI specs")]
    MissingDevice(String),
    #[error(
        "selected CDI device '{device}' was not found in mounted CDI specs after CDI spec refresh reported: {refresh_error}"
    )]
    MissingDeviceAfterRefresh {
        device: String,
        refresh_error: String,
    },
    #[error("failed to merge CDI edits for '{device}': {error}")]
    EditMerge { device: String, error: String },
    #[error("failed to encode resolved CDI edits: {source}")]
    EditEncode { source: serde_json::Error },
    #[error("failed to decode resolved CDI edits: {source}")]
    EditDecode { source: serde_json::Error },
    #[error("CDI-derived path '{path}' is unsafe: {reason}")]
    UnsafePolicyPath { path: String, reason: &'static str },
    #[error("CDI path '{path}' requested conflicting access modes")]
    ConflictingAccess { path: String },
    #[error(
        "CDI writable mount '{path}' is not explicitly listed in the sandbox policy read_write paths"
    )]
    WritableMountNotAllowed { path: String },
    #[error("CDI writable mount '{path}' must target a single file, found {kind}")]
    WritableMountNotFile { path: String, kind: String },
    #[error("CDI device node '{path}' must target a character or block device, found {kind}")]
    DeviceNodeNotDevice { path: String, kind: String },
    #[error("CDI additionalGids must not contain root GID 0")]
    RootAdditionalGid,
    #[error("CDI mount '{path}' has conflicting ro/rw options")]
    ConflictingMountOptions { path: String },
}

pub fn read_context(path: impl AsRef<Path>) -> Result<CdiContext, CdiError> {
    let path = path.as_ref();
    let json = std::fs::read_to_string(path).map_err(|source| CdiError::ContextRead {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&json).map_err(|source| CdiError::ContextParse {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(target_os = "linux")]
#[path = "cdi_linux.rs"]
mod cdi_linux;
#[cfg(target_os = "linux")]
pub use cdi_linux::resolve_cdi_context;

#[cfg(not(target_os = "linux"))]
#[path = "cdi_stub.rs"]
mod cdi_stub;
#[cfg(not(target_os = "linux"))]
pub use cdi_stub::resolve_cdi_context;
