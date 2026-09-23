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
        .arg("--force-with-deps")
        .arg("--role-file")
        .arg(requirements_path())
        .status()
        .await
        .unwrap();

    assert!(status.success());
}

pub async fn run(
    playbook: &Path,
    inputs: &BTreeMap<String, PathBuf>,
    variables: &BTreeMap<String, String>,
) -> Result<()> {
    let mut command = command(playbook, inputs, variables)?;
    let status = command.status().await.context("run ansible-playbook")?;

    anyhow::ensure!(status.success(), "ansible-playbook exited with {status}");
    Ok(())
}

pub async fn collect_diagnostics(
    playbook: &Path,
    variables: &BTreeMap<String, String>,
) -> Result<()> {
    let mut command = command(playbook, &BTreeMap::new(), variables)?;
    let output = command.output().await.context("run diagnostics playbook")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    print!("{stdout}");
    eprint!("{stderr}");
    if let Some(dir) = std::env::var_os("TMACHINE_ARTIFACTS_DIR") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).context("create tmachine artifacts directory")?;
        std::fs::write(dir.join("k3s-diagnostics.txt"), stdout.as_bytes())
        .context("write k3s diagnostics artifact")?;
    }
    anyhow::ensure!(
        output.status.success(),
        "diagnostics playbook exited with {}",
        output.status
    );
    Ok(())
}

fn command(
    playbook: &Path,
    inputs: &BTreeMap<String, PathBuf>,
    variables: &BTreeMap<String, String>,
) -> Result<Command> {
    let mut command = Command::new("ansible-playbook");
    for (name, value) in variables {
        command.arg("--extra-vars").arg(format!("{name}={value}"));
    }
    for (name, path) in inputs {
        let value = match std::fs::canonicalize(path) {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => path.clone(),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to resolve input {name:?} from {}", path.display())
                });
            }
        };
        command
            .arg("--extra-vars")
            .arg(format!("{name}={}", value.display()));
    }

    command.arg(playbook);
    command.kill_on_drop(true);
    Ok(command)
}
