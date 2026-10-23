// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "aarch64")]
use std::fs;
use std::net::{Ipv4Addr, TcpListener};
#[cfg(target_arch = "aarch64")]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};

use super::cleanup;
use super::img::QemuImage;

/// The host port forwarded to the guest's SSH server unless
/// `TMACHINE_SSH_PORT` says otherwise.
pub const DEFAULT_SSH_PORT: u16 = 2222;

/// How long the QMP power-off request has to be acknowledged. A guest or QEMU
/// that stops answering must not hang teardown.
const QMP_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a powered-off guest has to exit at teardown before QEMU is
/// killed.
const POWER_OFF_TIMEOUT: Duration = Duration::from_secs(120);

/// How long a guest being saved as a cached layer has to power off. A heavily
/// provisioned guest (Docker, k3s) can take minutes to stop its services, and
/// a layer that is killed instead is not cached, so this is much longer than
/// [`POWER_OFF_TIMEOUT`]. It still bounds a guest that never stops.
pub(super) const LAYER_POWER_OFF_TIMEOUT: Duration = Duration::from_secs(600);

/// The host port forwarded to the guest's SSH server.
///
/// Concurrent tmachine runs on one host need different ports; set
/// `TMACHINE_SSH_PORT` to run them side by side.
pub fn ssh_port() -> u16 {
    let value = std::env::var("TMACHINE_SSH_PORT").ok();
    let port = parse_ssh_port(value.as_deref());
    if let Some(value) = value.as_deref().filter(|_| port == DEFAULT_SSH_PORT)
        && value.trim() != DEFAULT_SSH_PORT.to_string()
    {
        eprintln!(
            "tmachine: ignoring TMACHINE_SSH_PORT={value:?}, which is not a port from 1 to 65535; using {DEFAULT_SSH_PORT}"
        );
    }
    port
}

fn parse_ssh_port(value: Option<&str>) -> u16 {
    value
        .and_then(|value| value.trim().parse().ok())
        .filter(|port| *port != 0)
        .unwrap_or(DEFAULT_SSH_PORT)
}

pub(super) struct QemuVm {
    child: Child,
    runtime_dir: TempDir,
    pid: Option<u32>,
}

impl Drop for QemuVm {
    fn drop(&mut self) {
        // `kill_on_drop` stops QEMU; stop tracking it for signal cleanup.
        if let Some(pid) = self.pid.take() {
            cleanup::forget(pid);
        }
    }
}

impl QemuVm {
    pub(super) async fn start(image: &QemuImage) -> Result<Self> {
        let port = ssh_port();
        // QEMU reports a taken port only by exiting, which is slow to notice
        // and hard to diagnose.
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).with_context(|| {
            format!(
                "host port {port} is not available for the VM's SSH forward; is another tmachine VM running? Set TMACHINE_SSH_PORT to use another port"
            )
        })?;

        let runtime_dir = tempdir().context("create VM runtime directory")?;
        let qmp_socket = runtime_dir.path().join("qmp.sock");
        ensure!(
            qmp_socket.as_os_str().as_encoded_bytes().len() < 108,
            "QMP socket path is too long: {} (set TMPDIR to a shorter path)",
            qmp_socket.display()
        );
        let firmware_vars = prepare_firmware(runtime_dir.path());
        let child = command(image, &qmp_socket, firmware_vars.as_deref(), port)
            .spawn()
            .context("start QEMU")?;
        let pid = child.id();
        if let Some(pid) = pid {
            cleanup::track(pid);
        }

        Ok(Self {
            child,
            runtime_dir,
            pid,
        })
    }

    /// The exit status, if QEMU has already exited.
    pub(super) fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    /// Wait for QEMU to exit after a power-off request, and check it exited
    /// cleanly. QEMU is killed if it does not exit within `timeout`.
    pub(super) async fn wait(mut self, timeout: Duration) -> Result<()> {
        match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(status) => {
                let status = status.context("wait for QEMU")?;
                ensure!(status.success(), "QEMU exited with {status}");
                Ok(())
            }
            Err(_) => {
                self.kill().await;
                bail!("QEMU did not exit within {timeout:?} of the power-off request; killed it")
            }
        }
    }

    /// Stop QEMU immediately and reap it.
    pub(super) async fn kill(&mut self) {
        let _ = self.child.kill().await;
    }

    /// Ask the guest to power off over QMP.
    pub(super) async fn shutdown(&self) -> Result<()> {
        let stream = UnixStream::connect(self.runtime_dir.path().join("qmp.sock"))
            .await
            .context("connect to QMP")?;
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut response = String::new();

        reader
            .read_line(&mut response)
            .await
            .context("read QMP greeting")?;

        writer
            .write_all(b"{\"execute\":\"qmp_capabilities\"}\r\n")
            .await
            .context("negotiate QMP capabilities")?;
        response.clear();
        reader
            .read_line(&mut response)
            .await
            .context("read QMP capabilities response")?;
        ensure!(
            response.contains("\"return\""),
            "unexpected QMP response: {response}"
        );

        writer
            .write_all(b"{\"execute\":\"system_powerdown\"}\r\n")
            .await
            .context("send system_powerdown")?;

        loop {
            response.clear();
            let bytes_read = reader
                .read_line(&mut response)
                .await
                .context("read system_powerdown response")?;
            ensure!(
                bytes_read != 0,
                "QMP closed before system_powerdown returned"
            );

            if response.contains("\"return\"") {
                return Ok(());
            }
        }
    }

    /// Power the guest off and wait for QEMU to exit. Never panics: a guest
    /// that can't be powered off cleanly is killed, and the problem is
    /// logged. Use this when tearing down, where there is nothing left to do
    /// about a failure.
    pub(super) async fn power_off_or_kill(mut self) {
        let shutdown = match tokio::time::timeout(QMP_TIMEOUT, self.shutdown()).await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("QMP did not answer within {QMP_TIMEOUT:?}")),
        };
        match shutdown {
            Ok(()) => {
                if let Err(error) = self.wait(POWER_OFF_TIMEOUT).await {
                    eprintln!("tmachine: {error:#}");
                }
            }
            Err(error) => {
                eprintln!("tmachine: could not power off the VM cleanly, killing it: {error:#}");
                self.kill().await;
            }
        }
    }
}

fn command(
    image: &QemuImage,
    qmp_socket: &Path,
    firmware_vars: Option<&Path>,
    ssh_port: u16,
) -> Command {
    let qemu = if cfg!(target_arch = "aarch64") {
        "qemu-system-aarch64"
    } else {
        "qemu-system-x86_64"
    };
    let machine = if cfg!(target_arch = "aarch64") {
        "virt"
    } else {
        "q35"
    };
    let accelerator = if cfg!(target_os = "macos") {
        "hvf"
    } else {
        "kvm"
    };
    let mut command = Command::new(qemu);

    command
        .arg("-machine")
        .arg(format!("{machine},accel={accelerator}"))
        .arg("-cpu")
        .arg("host")
        .arg("-m")
        .arg("4G")
        .arg("-smp")
        .arg("4")
        .arg("-nodefaults")
        .arg("-no-user-config")
        .arg("-display")
        .arg("none")
        .arg("-serial")
        .arg("stdio")
        .arg("-monitor")
        .arg("none")
        .arg("-qmp")
        .arg(format!("unix:{},server=on,wait=off", qmp_socket.display()));

    if let Some(firmware_vars) = firmware_vars {
        let firmware_code = firmware_path(
            "TMACHINE_FIRMWARE_CODE",
            option_env!("TMACHINE_FIRMWARE_CODE"),
        );
        command
            .arg("-drive")
            .arg(format!(
                "if=pflash,format=raw,readonly=on,file={firmware_code}"
            ))
            .arg("-drive")
            .arg(format!(
                "if=pflash,format=raw,file={}",
                firmware_vars.display()
            ));
    }

    command
        .arg("-drive")
        .arg(format!(
            "id=rootfs,file={},format=qcow2,if=none",
            image.path().display()
        ))
        .arg("-device")
        .arg("virtio-blk-pci,drive=rootfs,bootindex=1")
        .arg("-device")
        .arg("virtio-rng-pci")
        .arg("-netdev")
        .arg(format!("user,id=net0,hostfwd=tcp:127.0.0.1:{ssh_port}-:22"))
        .arg("-device")
        .arg("virtio-net-pci,netdev=net0");

    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Dropping the handle stops QEMU; the parent-death signal covers the
    // cases where no destructor runs.
    command.kill_on_drop(true);
    cleanup::die_with_parent(&mut command);
    command
}

/// A firmware path from the runtime environment, falling back to the value
/// compiled in. The fallback lets library users built outside Nix (such as
/// the test runner) supply firmware at runtime.
fn firmware_path(name: &str, compiled: Option<&'static str>) -> String {
    std::env::var(name)
        .ok()
        .or_else(|| compiled.map(str::to_string))
        .unwrap_or_else(|| panic!("{name} must be set for ARM builds"))
}

fn prepare_firmware(runtime_dir: &Path) -> Option<PathBuf> {
    #[cfg(target_arch = "aarch64")]
    {
        let template = firmware_path(
            "TMACHINE_FIRMWARE_VARS",
            option_env!("TMACHINE_FIRMWARE_VARS"),
        );
        let firmware_vars = runtime_dir.join("firmware-vars.fd");
        fs::copy(template, &firmware_vars).unwrap();
        fs::set_permissions(&firmware_vars, fs::Permissions::from_mode(0o600)).unwrap();
        Some(firmware_vars)
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = runtime_dir;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_port_defaults_and_overrides() {
        assert_eq!(parse_ssh_port(None), DEFAULT_SSH_PORT);
        assert_eq!(parse_ssh_port(Some("2300")), 2300);
        assert_eq!(parse_ssh_port(Some(" 2301 ")), 2301);
        assert_eq!(parse_ssh_port(Some("0")), DEFAULT_SSH_PORT);
        assert_eq!(parse_ssh_port(Some("not-a-port")), DEFAULT_SSH_PORT);
        assert_eq!(parse_ssh_port(Some("70000")), DEFAULT_SSH_PORT);
    }
}
