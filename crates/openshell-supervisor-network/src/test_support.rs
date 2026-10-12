// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Socket-owner subprocess fixtures.

use std::net::TcpStream;
use std::os::fd::OwnedFd;
use std::process::{Child, Command, Stdio};

pub struct SocketHolder(pub Child);

impl Drop for SocketHolder {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Keep a duplicate of the parent's connected socket in a descendant process.
/// Stdin transfers descriptor ownership through the standard process API.
pub fn spawn_socket_holder(stream: &TcpStream, exec_sleep: bool) -> SocketHolder {
    let mut command = if exec_sleep {
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        command
    } else {
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args([
                "--exact",
                "test_support::socket_holder_child",
                "--nocapture",
            ])
            .env("OPENSHELL_SOCKET_HOLDER_CHILD", "1");
        command
    };
    let fd = OwnedFd::from(stream.try_clone().expect("duplicate socket"));
    SocketHolder(
        command
            .stdin(Stdio::from(fd))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn socket holder"),
    )
}

#[test]
fn socket_holder_child() {
    if std::env::var_os("OPENSHELL_SOCKET_HOLDER_CHILD").is_some() {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}
