// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::{Error, Result};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;

pub struct BoundGatewayListener {
    pub listener: TcpListener,
    pub address: SocketAddr,
}

/// Bind the operator-configured gateway endpoint.
pub async fn bind_gateway_listener(address: SocketAddr) -> Result<BoundGatewayListener> {
    let listener = TcpListener::bind(address)
        .await
        .map_err(|error| Error::transport(format!("failed to bind to {address}: {error}")))?;
    let local_addr = listener.local_addr().unwrap_or(address);
    info!(address = %local_addr, "Gateway listener bound");
    Ok(BoundGatewayListener {
        listener,
        address: local_addr,
    })
}

/// Windows only: `mio` 1.2.1 and later create sockets with
/// `WSA_FLAG_NO_HANDLE_INHERIT`, so a sandbox process the gateway spawns cannot
/// keep a copy of the listening socket and hold its port after a gateway crash.
/// Older `mio` versions (1.2.0 and earlier) used plain `socket()`, which is
/// inheritable. These tests fail if the dependency ever regresses to that.
#[cfg(all(test, windows))]
#[allow(unsafe_code)] // Win32 handle flags, test-only.
mod tests {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawSocket;

    use windows::Win32::Foundation::{GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};

    use super::*;

    fn is_inheritable(listener: &TcpListener) -> bool {
        let handle = HANDLE(listener.as_raw_socket() as *mut c_void);
        let mut flags = 0u32;
        // SAFETY: `listener` owns a live socket handle and `flags` outlives the call.
        unsafe { GetHandleInformation(handle, &raw mut flags) }.expect("GetHandleInformation");
        flags & HANDLE_FLAG_INHERIT.0 != 0
    }

    #[tokio::test]
    async fn bound_gateway_listener_is_not_inheritable() {
        let bound = bind_gateway_listener("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        assert!(
            !is_inheritable(&bound.listener),
            "child processes would inherit the gateway's listening socket"
        );
    }

    #[tokio::test]
    async fn listener_accepts_connections() {
        let bound = bind_gateway_listener("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let client = tokio::net::TcpStream::connect(bound.address);
        let (accepted, connected) = tokio::join!(bound.listener.accept(), client);
        accepted.expect("accept");
        connected.expect("connect");
    }
}
