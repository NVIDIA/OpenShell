// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::io::AsyncReadExt;
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
    let command = command(playbook, &BTreeMap::new(), variables)?;
    let artifact = std::env::var_os("TMACHINE_ARTIFACTS_DIR")
        .map(|dir| PathBuf::from(dir).join("k3s-diagnostics.txt"));
    if let Some(path) = &artifact {
        std::fs::create_dir_all(path.parent().unwrap())
            .context("create tmachine artifacts directory")?;
    }
    capture_diagnostics(command, artifact.as_deref()).await
}

async fn capture_diagnostics(mut command: Command, artifact: Option<&Path>) -> Result<()> {
    let mut artifact = artifact
        .map(std::fs::File::create)
        .transpose()
        .context("create k3s diagnostics artifact")?;
    let mut child = command
        .env("PYTHONUNBUFFERED", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("run diagnostics playbook")?;
    let mut stdout = child.stdout.take().context("capture diagnostics stdout")?;
    let mut buffer = [0; 8192];
    loop {
        let count = stdout
            .read(&mut buffer)
            .await
            .context("read diagnostics output")?;
        if count == 0 {
            break;
        }
        // Write each chunk immediately so cancellation retains completed sections.
        if let Some(file) = &mut artifact {
            file.write_all(&buffer[..count])
                .context("write k3s diagnostics artifact")?;
        }
        std::io::stdout()
            .write_all(&buffer[..count])
            .context("print diagnostics output")?;
    }
    let status = child
        .wait()
        .await
        .context("wait for diagnostics playbook")?;
    anyhow::ensure!(
        status.success(),
        "diagnostics playbook exited with {status}"
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tempfile::tempdir;
    use tokio::process::Command;

    use super::capture_diagnostics;

    #[tokio::test]
    async fn diagnostics_timeout_preserves_output_already_collected() {
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("k3s-diagnostics.txt");
        let mut command = Command::new("sh");
        command.args(["-c", "printf 'guest and systemd state\\n'; exec sleep 30"]);
        command.kill_on_drop(true);

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            capture_diagnostics(command, Some(&artifact)),
        )
        .await;

        assert!(result.is_err(), "the stalled collector must time out");
        assert_eq!(
            std::fs::read_to_string(&artifact).unwrap(),
            "guest and systemd state\n",
            "cancellation must preserve diagnostic output already received"
        );
    }

    #[tokio::test]
    async fn diagnostics_preserve_output_and_exit_status() {
        for status in [0, 42] {
            let dir = tempdir().unwrap();
            let artifact = dir.path().join("k3s-diagnostics.txt");
            let mut command = Command::new("sh");
            command.args(["-c", "printf 'diagnostic section\\n'; exit \"$1\"", "sh"]);
            command.arg(status.to_string());

            let result = capture_diagnostics(command, Some(&artifact)).await;

            assert_eq!(result.is_ok(), status == 0);
            assert_eq!(
                std::fs::read_to_string(artifact).unwrap(),
                "diagnostic section\n"
            );
        }
    }
}
