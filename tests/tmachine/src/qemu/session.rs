// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A running machine that callers act on over SSH.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use tempfile::{TempDir, tempdir};
use tokio::process::Command;

use crate::config::{Environment, Installer, Machine};

use super::img::QemuImage;
use super::install::install;
use super::layer::run_playbooks;
use super::vm::QemuVm;

// Must match the QEMU port forward in `vm.rs` and `ansible/inventory.ini`.
const SSH_HOST: &str = "127.0.0.1";
const SSH_PORT: &str = "2222";
const SSH_USER: &str = "tmachine";
const SSH_PASSWORD: &str = "tmachine";
// Password authentication only: keys from the caller's agent or ~/.ssh would
// otherwise use up the guest's authentication attempts first.
const SSH_OPTIONS: [&str; 14] = [
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "LogLevel=ERROR",
    "-o",
    "ConnectTimeout=5",
    "-o",
    "PreferredAuthentications=password",
    "-o",
    "PubkeyAuthentication=no",
    "-o",
    "IdentityAgent=none",
];
const SSH_READY_TIMEOUT: Duration = Duration::from_secs(300);
const SSH_READY_INTERVAL: Duration = Duration::from_secs(2);

/// A machine booted from a throwaway overlay of the installed disk.
///
/// The VM stops when the session is dropped, so a caller that fails or
/// panics cannot leak it. Call [`Session::down`] for a clean shutdown.
pub struct Session {
    // Declared before `_dir` so the VM stops before its disk is removed.
    vm: Option<QemuVm>,
    _image: QemuImage,
    _dir: TempDir,
}

impl Session {
    /// Set up and install the environment (reusing cached disks), boot a VM
    /// from a throwaway overlay, and wait until it accepts SSH.
    pub async fn up(
        machine: &Machine,
        environment: &Environment,
        installer: &Installer,
    ) -> Result<Self> {
        let install_disk = install(machine, environment, installer).await?;
        let dir = tempdir().context("create session directory")?;
        let image = QemuImage::create(&install_disk, dir.path().join("session.qcow2")).await;
        let vm = QemuVm::start(&image).await;
        let mut session = Self {
            vm: Some(vm),
            _image: image,
            _dir: dir,
        };
        session.wait_for_ssh().await?;
        Ok(session)
    }

    async fn wait_for_ssh(&mut self) -> Result<()> {
        let started = Instant::now();
        loop {
            if let Some(status) = self.vm.as_mut().and_then(QemuVm::try_wait) {
                bail!(
                    "QEMU exited with {status} before SSH was ready; is another tmachine VM using port {SSH_PORT}?"
                );
            }
            match self.exec(&["true"]).await {
                Ok(output) if output.status.success() => return Ok(()),
                Ok(_) | Err(_) if started.elapsed() < SSH_READY_TIMEOUT => {
                    tokio::time::sleep(SSH_READY_INTERVAL).await;
                }
                Ok(output) => bail!(
                    "SSH was not ready after {SSH_READY_TIMEOUT:?}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
                Err(error) => {
                    return Err(
                        error.context(format!("SSH was not ready after {SSH_READY_TIMEOUT:?}"))
                    );
                }
            }
        }
    }

    /// Run Ansible playbooks against the machine.
    pub async fn run_playbooks(
        &self,
        playbooks: &[PathBuf],
        inputs: &BTreeMap<String, PathBuf>,
    ) -> Result<()> {
        run_playbooks(playbooks, inputs).await
    }

    /// Run a command in the machine as the `tmachine` user and capture its
    /// output. A non-zero exit is returned in the output, not as an error.
    pub async fn exec(&self, argv: &[&str]) -> Result<Output> {
        ensure!(!argv.is_empty(), "exec needs a command");
        let remote = argv
            .iter()
            .map(|arg| shell_quote(arg))
            .collect::<Vec<_>>()
            .join(" ");
        ssh_command("ssh", &["-p", SSH_PORT])
            .arg(format!("{SSH_USER}@{SSH_HOST}"))
            .arg("--")
            .arg(remote)
            .stdin(Stdio::null())
            .output()
            .await
            .with_context(|| format!("run {argv:?} in tmachine VM"))
    }

    /// Copy a local file or directory into the machine.
    pub async fn copy_in(&self, src: &Path, dst: &str) -> Result<()> {
        let remote = format!("{SSH_USER}@{SSH_HOST}:{dst}");
        scp(src.as_os_str().to_string_lossy().as_ref(), &remote)
            .await
            .with_context(|| format!("copy {} to {dst} in tmachine VM", src.display()))
    }

    /// Copy a file or directory out of the machine.
    pub async fn copy_out(&self, src: &str, dst: &Path) -> Result<()> {
        let remote = format!("{SSH_USER}@{SSH_HOST}:{src}");
        scp(&remote, dst.as_os_str().to_string_lossy().as_ref())
            .await
            .with_context(|| format!("copy {src} from tmachine VM to {}", dst.display()))
    }

    /// Write the OpenShell gateway's journal to `dir/gateway.log`.
    pub async fn collect_diagnostics(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create diagnostics directory {}", dir.display()))?;
        let output = self
            .exec(&[
                "sudo",
                "-n",
                "journalctl",
                "--no-pager",
                "--lines",
                "2000",
                "_SYSTEMD_UNIT=openshell-gateway.service",
                "+",
                "_SYSTEMD_USER_UNIT=openshell-gateway.service",
            ])
            .await?;
        let log = dir.join("gateway.log");
        let mut contents = output.stdout;
        contents.extend_from_slice(&output.stderr);
        std::fs::write(&log, contents).with_context(|| format!("write {}", log.display()))
    }

    /// Open an interactive SSH shell in the machine.
    pub async fn shell(&self) -> Result<ExitStatus> {
        ssh_command("ssh", &["-tt", "-p", SSH_PORT])
            .arg(format!("{SSH_USER}@{SSH_HOST}"))
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("open SSH shell in tmachine VM")
    }

    /// Power the machine off and wait for QEMU to exit.
    pub async fn down(mut self) {
        if let Some(vm) = self.vm.take() {
            vm.shutdown().await;
            vm.wait().await;
        }
    }
}

fn ssh_command(program: &str, args: &[&str]) -> Command {
    let mut command = Command::new("sshpass");
    command
        .env("SSHPASS", SSH_PASSWORD)
        .arg("-e")
        .arg(program)
        .args(args)
        .args(SSH_OPTIONS);
    command
}

async fn scp(src: &str, dst: &str) -> Result<()> {
    let output = ssh_command("scp", &["-r", "-P", SSH_PORT])
        .arg(src)
        .arg(dst)
        .stdin(Stdio::null())
        .output()
        .await
        .context("run scp")?;
    ensure!(
        output.status.success(),
        "scp exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

/// Quote an argument for the remote POSIX shell that SSH runs commands in.
fn shell_quote(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./=:@,+%".contains(&b));
    if safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::shell_quote;

    #[test]
    fn leaves_plain_arguments_unquoted() {
        assert_eq!(shell_quote("cargo-nextest"), "cargo-nextest");
        assert_eq!(shell_quote("/var/lib/x.tar.zst"), "/var/lib/x.tar.zst");
        assert_eq!(shell_quote("KEY=value"), "KEY=value");
    }

    #[test]
    fn quotes_shell_metacharacters() {
        assert_eq!(
            shell_quote("binary(a) | binary(b)"),
            "'binary(a) | binary(b)'"
        );
        assert_eq!(shell_quote("$HOME"), "'$HOME'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn escapes_single_quotes() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
