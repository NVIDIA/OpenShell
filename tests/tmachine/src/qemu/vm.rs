// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "aarch64")]
use std::fs;
#[cfg(target_arch = "aarch64")]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;

use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};

use super::img::QemuImage;

pub(super) struct QemuVm {
    child: Child,
    runtime_dir: TempDir,
}

impl QemuVm {
    pub(super) async fn start(image: &QemuImage) -> Self {
        let runtime_dir = tempdir().unwrap();
        let qmp_socket = runtime_dir.path().join("qmp.sock");
        assert!(
            qmp_socket.as_os_str().as_encoded_bytes().len() < 108,
            "QMP socket path is too long: {} (set TMPDIR to a shorter path)",
            qmp_socket.display()
        );
        let firmware_vars = prepare_firmware(runtime_dir.path());
        let child = command(image, &qmp_socket, firmware_vars.as_deref())
            .spawn()
            .unwrap();

        Self { child, runtime_dir }
    }

    pub(super) async fn wait(mut self) {
        let status = self.child.wait().await.unwrap();
        assert!(status.success());
    }

    pub(super) async fn shutdown(&self) {
        let stream = UnixStream::connect(self.runtime_dir.path().join("qmp.sock"))
            .await
            .unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut response = String::new();

        reader.read_line(&mut response).await.unwrap();

        writer
            .write_all(b"{\"execute\":\"qmp_capabilities\"}\r\n")
            .await
            .unwrap();
        response.clear();
        reader.read_line(&mut response).await.unwrap();
        assert!(response.contains("\"return\""));

        writer
            .write_all(b"{\"execute\":\"system_powerdown\"}\r\n")
            .await
            .unwrap();

        loop {
            response.clear();
            let bytes_read = reader.read_line(&mut response).await.unwrap();
            assert_ne!(bytes_read, 0);

            if response.contains("\"return\"") {
                break;
            }
        }
    }
}

fn command(image: &QemuImage, qmp_socket: &Path, firmware_vars: Option<&Path>) -> Command {
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
        let firmware_code = option_env!("TMACHINE_FIRMWARE_CODE")
            .expect("TMACHINE_FIRMWARE_CODE must be set for ARM builds");
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
        .arg("user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22")
        .arg("-device")
        .arg("virtio-net-pci,netdev=net0");

    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.kill_on_drop(true);
    command
}

fn prepare_firmware(runtime_dir: &Path) -> Option<PathBuf> {
    #[cfg(target_arch = "aarch64")]
    {
        let template = option_env!("TMACHINE_FIRMWARE_VARS")
            .expect("TMACHINE_FIRMWARE_VARS must be set for ARM builds");
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
