// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::process::Command;

pub fn requirements_path() -> PathBuf {
    PathBuf::from(std::env::var("ANSIBLE_CONFIG").unwrap()).with_file_name("requirements.yaml")
}

pub async fn install_roles() {
    let status = Command::new("ansible-galaxy")
        .arg("role")
        .arg("install")
        .arg("--role-file")
        .arg(requirements_path())
        .status()
        .await
        .unwrap();

    assert!(status.success());
}

pub async fn run(playbook: &Path, inputs: &BTreeMap<String, PathBuf>) -> Result<()> {
    let mut command = Command::new("ansible-playbook");
    for (name, path) in inputs {
        let path = std::fs::canonicalize(path)
            .with_context(|| format!("failed to resolve input {name:?} from {}", path.display()))?;
        command
            .arg("--extra-vars")
            .arg(format!("{name}={}", path.display()));
    }

    let status = command.arg(playbook).status().await.unwrap();

    assert!(status.success());
    Ok(())
}
