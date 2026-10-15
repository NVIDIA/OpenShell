// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workload-local CDI resolution and resource validation.

use std::path::Path;

use openshell_core::cdi::{CDI_CONTEXT_VERSION, CdiContext, CdiSpecDirectory};

use crate::launch::{CdiDerivedRequirements, CdiMountRequirement};

/// Roots that CDI destinations and expanded library parents must not grant.
pub const FORBIDDEN_CDI_ROOTS: &[&str] = &["/", "/dev", "/proc", "/sys", "/run", "/usr"];

/// Writable IPC directories that CDI may mount for GPU daemons. Clients must
/// open the named pipes inside for writing, so these are the only writable
/// directory mounts granted. The NVIDIA MPS pipe directory is the only entry.
pub const CDI_IPC_DIRECTORIES: &[&str] = &["/tmp/nvidia-mps"];

/// Mount options a CDI IPC directory must carry, in the spec and in effect.
pub const CDI_IPC_DIRECTORY_MOUNT_OPTIONS: &[&str] = &["nosuid", "nodev", "noexec"];

#[derive(Debug, thiserror::Error)]
pub enum CdiError {
    #[error("failed to inspect effective CDI mount '{path}': {error}")]
    MountInspection { path: String, error: String },
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
        "CDI writable mount '{path}' is unsupported: ordinary host-backed file and directory mounts must be read-only; filesystem read_write grants do not authorize CDI host writes"
    )]
    WritableMountNotAllowed { path: String },
    #[error("CDI additionalGids must not contain root GID 0")]
    RootAdditionalGid,
    #[error("CDI mount '{path}' has conflicting ro/rw options")]
    ConflictingMountOptions { path: String },
    #[error("CDI IPC directory '{path}' must be mounted with nosuid, nodev and noexec")]
    UnsafeIpcDirectory { path: String },
}

#[cfg(any(target_os = "linux", test))]
fn shared_library_parent(path: &str) -> Option<String> {
    let path = Path::new(path);
    let name = path.file_name()?.to_str()?;
    let versioned_library = name.rsplit_once(".so.").is_some_and(|(_, version)| {
        version.split('.').all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
    });
    let unversioned_library = name
        .rsplit_once('.')
        .is_some_and(|(_, extension)| extension == "so");
    if !unversioned_library && !versioned_library {
        return None;
    }
    path.parent()?.to_str().map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::shared_library_parent;

    #[test]
    fn identifies_shared_library_parent_directories() {
        for path in [
            "/opt/nvidia/lib/libcuda.so",
            "/opt/nvidia/lib/libnvidia-ml.so.1",
            "/opt/nvidia/lib/libnvidia-eglcore.so.540.5.0",
        ] {
            assert_eq!(
                shared_library_parent(path).as_deref(),
                Some("/opt/nvidia/lib")
            );
        }
        for path in [
            "/etc/ld.so.conf",
            "/opt/nvidia/lib/libcuda.so.debug",
            "/opt/nvidia/lib/libcuda.so.1beta",
            "/usr/bin/nvidia-smi",
        ] {
            assert_eq!(shared_library_parent(path), None);
        }
    }
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{CdiMountTable, resolve_cdi_context, validate_cdi_requirements};
