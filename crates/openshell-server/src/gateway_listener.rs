// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::{Error, Result};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;
#[cfg(windows)]
use tracing::warn;

pub struct BoundGatewayListener {
    pub listener: TcpListener,
    pub address: SocketAddr,
}

/// Bind the operator-configured gateway endpoint.
pub async fn bind_gateway_listener(address: SocketAddr) -> Result<BoundGatewayListener> {
    let listener = TcpListener::bind(address)
        .await
        .map_err(|error| Error::transport(format!("failed to bind to {address}: {error}")))?;
    disable_handle_inheritance(&listener, "gateway");
    let local_addr = listener.local_addr().unwrap_or(address);
    info!(address = %local_addr, "Gateway listener bound");
    Ok(BoundGatewayListener {
        listener,
        address: local_addr,
    })
}

/// Keep a listening socket private to the gateway process.
///
/// On Windows, `mio` (underneath tokio) creates sockets with plain `socket()`,
/// which leaves the handle inheritable, and `std::process::Command` starts
/// children with handle inheritance enabled. Every sandbox process the gateway
/// spawns therefore keeps its own copy of the listening socket. If the gateway
/// is killed while a sandbox is still running, that copy keeps the port bound
/// ("Only one usage of each socket address") and a new gateway cannot start.
/// Clearing the inherit flag right after `bind` prevents the leak.
///
/// A failure is logged and otherwise ignored: the listener still works, it just
/// keeps the old behaviour. This is a no-op on other platforms.
pub fn disable_handle_inheritance(listener: &TcpListener, name: &str) {
    #[cfg(windows)]
    if let Err(error) = windows_impl::disable_handle_inheritance(listener) {
        warn!(
            listener = name,
            %error,
            "could not make the listening socket non-inheritable; child processes may keep the port bound after a gateway crash"
        );
    }
    #[cfg(not(windows))]
    let _ = (listener, name);
}

#[cfg(windows)]
#[allow(unsafe_code)] // Win32 handle flags.
mod windows_impl {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawSocket;

    use tokio::net::TcpListener;
    use windows::Win32::Foundation::{
        HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation,
    };

    fn handle_of(listener: &TcpListener) -> HANDLE {
        // A SOCKET is a pointer-sized handle value; this is an integer-to-pointer cast.
        HANDLE(listener.as_raw_socket() as *mut c_void)
    }

    pub(super) fn disable_handle_inheritance(listener: &TcpListener) -> windows::core::Result<()> {
        // SAFETY: `listener` owns a live socket handle for the whole call.
        unsafe { SetHandleInformation(handle_of(listener), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }
    }

    #[cfg(test)]
    pub(super) fn is_inheritable(listener: &TcpListener) -> bool {
        use windows::Win32::Foundation::GetHandleInformation;

        let mut flags = 0u32;
        // SAFETY: `listener` owns a live socket handle and `flags` outlives the call.
        unsafe { GetHandleInformation(handle_of(listener), &raw mut flags) }
            .expect("GetHandleInformation");
        flags & HANDLE_FLAG_INHERIT.0 != 0
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bound_gateway_listener_is_not_inheritable() {
        let bound = bind_gateway_listener("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        assert!(
            !windows_impl::is_inheritable(&bound.listener),
            "child processes would inherit the gateway's listening socket"
        );
    }

    #[tokio::test]
    async fn listener_still_accepts_connections_after_disabling_inheritance() {
        let bound = bind_gateway_listener("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let client = tokio::net::TcpStream::connect(bound.address);
        let (accepted, connected) = tokio::join!(bound.listener.accept(), client);
        accepted.expect("accept");
        connected.expect("connect");
    }
}
