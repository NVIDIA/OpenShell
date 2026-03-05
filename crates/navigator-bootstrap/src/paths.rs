// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{IntoDiagnostic, Result, WrapErr};
use std::path::PathBuf;

pub fn xdg_config_dir() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME")
        .into_diagnostic()
        .wrap_err("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config"))
}

/// Path to the file that stores the active cluster name.
///
/// Location: `$XDG_CONFIG_HOME/nemoclaw/active_cluster`
pub fn active_cluster_path() -> Result<PathBuf> {
    Ok(xdg_config_dir()?.join("nemoclaw").join("active_cluster"))
}

/// Base directory for all cluster metadata files.
///
/// Location: `$XDG_CONFIG_HOME/nemoclaw/clusters/`
pub fn clusters_dir() -> Result<PathBuf> {
    Ok(xdg_config_dir()?.join("nemoclaw").join("clusters"))
}

/// Path to the file that stores the last-used sandbox name for a cluster.
///
/// Location: `$XDG_CONFIG_HOME/nemoclaw/clusters/<cluster>/last_sandbox`
pub fn last_sandbox_path(cluster: &str) -> Result<PathBuf> {
    Ok(clusters_dir()?.join(cluster).join("last_sandbox"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code)]
    fn last_sandbox_path_layout() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let orig = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }
        let path = last_sandbox_path("my-cluster").unwrap();
        assert!(
            path.ends_with("nemoclaw/clusters/my-cluster/last_sandbox"),
            "unexpected path: {path:?}"
        );
        unsafe {
            match orig {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }
}
