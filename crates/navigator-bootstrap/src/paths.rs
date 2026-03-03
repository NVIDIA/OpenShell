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
/// Location: `$XDG_CONFIG_HOME/navigator/active_cluster`
pub fn active_cluster_path() -> Result<PathBuf> {
    Ok(xdg_config_dir()?.join("navigator").join("active_cluster"))
}

/// Base directory for all cluster metadata files.
///
/// Location: `$XDG_CONFIG_HOME/navigator/clusters/`
pub fn clusters_dir() -> Result<PathBuf> {
    Ok(xdg_config_dir()?.join("navigator").join("clusters"))
}
