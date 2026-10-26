// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "aarch64")]
use std::fs;
#[cfg(target_arch = "aarch64")]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::OnceLock;
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
const DEFAULT_SSH_PORT: u16 = 2222;

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
///
/// # Panics
///
/// If `TMACHINE_SSH_PORT` is set but is not a port from 1 to 65535.
pub fn ssh_port() -> u16 {
    static PORT: OnceLock<u16> = OnceLock::new();
    *PORT.get_or_init(|| {
        let value = std::env::var("TMACHINE_SSH_PORT").ok();
        parse_ssh_port(value.as_deref())
            .unwrap_or_else(|| panic!("TMACHINE_SSH_PORT={value:?} is not a port from 1 to 65535"))
    })
}

fn parse_ssh_port(value: Option<&str>) -> Option<u16> {
    match value {
        None => Some(DEFAULT_SSH_PORT),
        Some(value) => value.trim().parse().ok().filter(|port| *port != 0),
    }
}

pub(super) struct QemuVm {
    child: Child,
    runtime_dir: TempDir,
}

impl QemuVm {
    pub(super) async fn start(image: &QemuImage) -> Result<Self> {
        let runtime_dir = tempdir().context("create VM runtime directory")?;
        let qmp_socket = runtime_dir.path().join("qmp.sock");
        ensure!(
            qmp_socket.as_os_str().as_encoded_bytes().len() < 108,
            "QMP socket path is too long: {} (set TMPDIR to a shorter path)",
            qmp_socket.display()
        );
        let firmware = prepare_firmware(runtime_dir.path())?;
        let child = command(image, &qmp_socket, firmware.as_ref(), ssh_port())
            .spawn()
            .context("start QEMU")?;

        Ok(Self { child, runtime_dir })
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
    firmware: Option<&Firmware>,
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

    if let Some(Firmware { code, vars }) = firmware {
        command
            .arg("-drive")
            .arg(format!("if=pflash,format=raw,readonly=on,file={code}"))
            .arg("-drive")
            .arg(format!("if=pflash,format=raw,file={}", vars.display()));
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

/// UEFI firmware for ARM guests: the read-only code and a writable copy of
/// the variable store.
struct Firmware {
    code: &'static str,
    vars: PathBuf,
}

/// The firmware paths are compiled in by the Nix build.
fn prepare_firmware(runtime_dir: &Path) -> Result<Option<Firmware>> {
    #[cfg(target_arch = "aarch64")]
    {
        let missing =
            |name: &str| format!("{name} was not set when tmachine was built; build it with Nix");
        let code = option_env!("TMACHINE_FIRMWARE_CODE")
            .with_context(|| missing("TMACHINE_FIRMWARE_CODE"))?;
        let template = option_env!("TMACHINE_FIRMWARE_VARS")
            .with_context(|| missing("TMACHINE_FIRMWARE_VARS"))?;
        let vars = runtime_dir.join("firmware-vars.fd");
        fs::copy(template, &vars).context("copy the firmware variable store")?;
        fs::set_permissions(&vars, fs::Permissions::from_mode(0o600))?;
        Ok(Some(Firmware { code, vars }))
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = runtime_dir;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_port_defaults_and_overrides() {
        assert_eq!(parse_ssh_port(None), Some(DEFAULT_SSH_PORT));
        assert_eq!(parse_ssh_port(Some(" 2301 ")), Some(2301));
        assert_eq!(parse_ssh_port(Some("0")), None);
        assert_eq!(parse_ssh_port(Some("70000")), None);
    }
}
