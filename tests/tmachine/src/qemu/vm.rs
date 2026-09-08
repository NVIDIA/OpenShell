// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
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
        let child = command(image, &qmp_socket).spawn().unwrap();

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

fn command(image: &QemuImage, qmp_socket: &Path) -> Command {
    let mut command = Command::new("qemu-system-x86_64");

    command
        .arg("-machine")
        .arg("q35,accel=kvm")
        .arg("-cpu")
        .arg("host")
        .arg("-m")
        .arg("1G")
        .arg("-smp")
        .arg("2")
        .arg("-nodefaults")
        .arg("-no-user-config")
        .arg("-display")
        .arg("none")
        .arg("-serial")
        .arg("stdio")
        .arg("-monitor")
        .arg("none")
        .arg("-qmp")
        .arg(format!("unix:{},server=on,wait=off", qmp_socket.display()))
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
