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
