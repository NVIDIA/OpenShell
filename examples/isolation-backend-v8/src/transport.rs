// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS connections carry backend-owned IDs, never request-supplied IDs.
use openshell_sandbox_backend::sandbox_auth::{SandboxConnectionId, SandboxConnectionRegistry};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;

pub struct Connection {
    pub stream: TlsStream<tokio::net::UnixStream>,
    pub id: SandboxConnectionId,
    pub registry: Arc<SandboxConnectionRegistry>,
}
impl tonic::transport::server::Connected for Connection {
    type ConnectInfo = SandboxConnectionId;
    fn connect_info(&self) -> Self::ConnectInfo {
        self.id
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.registry.disconnect(self.id);
    }
}
impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
