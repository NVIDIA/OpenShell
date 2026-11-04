// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Trusted backend prerequisites composed before effective policy admission.

use std::collections::BTreeSet;

use crate::proto::SandboxPolicy;
use crate::proto::compute::v1::ProxyFilesystemBaseline;

/// Proxy runtime paths selected by trusted backend composition.
/// An explicit empty baseline suppresses legacy defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilesystemBaseline {
    pub read_only: Vec<String>,
    pub read_write: Vec<String>,
}

impl From<ProxyFilesystemBaseline> for FilesystemBaseline {
    fn from(value: ProxyFilesystemBaseline) -> Self {
        Self {
            read_only: value.read_only,
            read_write: value.read_write,
        }
    }
}

impl From<FilesystemBaseline> for ProxyFilesystemBaseline {
    fn from(value: FilesystemBaseline) -> Self {
        Self {
            read_only: value.read_only,
            read_write: value.read_write,
        }
    }
}

impl FilesystemBaseline {
    /// Validate bounded, canonical POSIX path syntax without inspecting the
    /// gateway host filesystem, which need not be the workload's platform.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.read_only.len() + self.read_write.len() > 64 {
            return Err("proxy filesystem baseline has too many paths");
        }
        let mut seen = BTreeSet::new();
        for path in self.read_only.iter().chain(&self.read_write) {
            if path.len() > 4096
                || !path.starts_with('/')
                || path.chars().any(char::is_control)
                || (path != "/"
                    && path[1..]
                        .split('/')
                        .any(|part| matches!(part, "" | "." | "..")))
                || !seen.insert(path)
            {
                return Err(
                    "proxy filesystem baseline requires unique canonical POSIX absolute paths",
                );
            }
        }
        Ok(())
    }

    /// Add prerequisites to a proxy-mode policy without replacing explicit
    /// grants. An explicit read-only path stays read-only. `path_exists` is
    /// used only by legacy image-local Linux defaults; advertised prerequisites
    /// are unconditional and callers pass a predicate that always returns true.
    /// Validate the descriptor at the trusted admission boundary before use.
    pub fn enrich(&self, policy: &mut SandboxPolicy, path_exists: impl Fn(&str) -> bool) -> bool {
        if policy.network_policies.is_empty()
            || (self.read_only.is_empty() && self.read_write.is_empty())
        {
            return false;
        }
        let filesystem = policy
            .filesystem
            .get_or_insert_with(|| crate::proto::FilesystemPolicy {
                include_workdir: true,
                ..Default::default()
            });
        let mut modified = false;
        for path in &self.read_only {
            if !filesystem.read_only.contains(path)
                && !filesystem.read_write.contains(path)
                && path_exists(path)
            {
                filesystem.read_only.push(path.clone());
                modified = true;
            }
        }
        for path in &self.read_write {
            if !filesystem.read_only.contains(path)
                && !filesystem.read_write.contains(path)
                && path_exists(path)
            {
                filesystem.read_write.push(path.clone());
                modified = true;
            }
        }
        modified
    }
}
