// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workload-local requirements derived for launch-time enforcement.

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CdiDerivedRequirements {
    pub device_node_paths: Vec<String>,
    /// Exact Unix socket destinations. Never expanded into filesystem grants.
    pub socket_paths: Vec<String>,
    /// Derived read-only policy paths. Shared-library mounts contribute their
    /// parent directory; other read-only mounts contribute their exact path.
    pub read_only_paths: Vec<String>,
    pub read_write_mount_paths: Vec<String>,
    /// Known writable IPC directories, such as the NVIDIA MPS pipe directory.
    /// Granted read-write on the exact directory and revalidated at each launch.
    pub ipc_directory_paths: Vec<String>,
    pub additional_gids: Vec<u32>,
    /// Original ordinary mount destinations, separate from sockets and library parents.
    /// Access is confirmed in the workload namespace before enrichment.
    pub mounts: Vec<CdiMountRequirement>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CdiMountRequirement {
    pub path: String,
    pub read_only: bool,
}
