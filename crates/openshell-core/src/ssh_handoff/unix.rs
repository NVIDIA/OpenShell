// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

pub struct Listener {
    socket: UnixListener,
    #[cfg(not(target_os = "linux"))]
    _cleanup: crate::external_driver_socket::SocketCleanup,
}

fn address(id: Uuid) -> String {
    #[cfg(target_os = "linux")]
    return format!("\0openshell-ssh-{id}");
    #[cfg(not(target_os = "linux"))]
    return format!("/tmp/openshell-ssh-{id}.sock");
}

fn same_user(stream: &UnixStream) -> io::Result<bool> {
    Ok(stream.peer_cred()?.uid() == rustix::process::geteuid().as_raw())
}

impl Listener {
    pub fn bind(id: Uuid) -> io::Result<Self> {
        let path = address(id);
        let socket = UnixListener::bind(&path)?;
        Ok(Self {
            socket,
            #[cfg(not(target_os = "linux"))]
            _cleanup: crate::external_driver_socket::SocketCleanup::new(path.into()),
        })
    }

    pub async fn accept(self) -> io::Result<UnixStream> {
        loop {
            let (stream, _) = self.socket.accept().await?;
            if same_user(&stream)? {
                return Ok(stream);
            }
        }
    }
}

pub async fn connect(id: Uuid, expected_pid: u32) -> io::Result<UnixStream> {
    let stream = UnixStream::connect(address(id)).await?;
    let peer = stream.peer_cred()?;
    if peer.uid() != rustix::process::geteuid().as_raw()
        || peer.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(expected_pid)
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(stream)
}
