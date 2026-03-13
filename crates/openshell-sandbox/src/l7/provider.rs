// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! L7 protocol provider trait.
//!
//! Each application protocol (REST, SQL) implements this trait to provide
//! request parsing, relay, and deny response generation.
//!
//! Uses generic `AsyncRead + AsyncWrite` stream bounds so the same provider
//! works for both plaintext TCP and TLS-terminated connections.

use miette::Result;
use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};

/// Body framing for HTTP requests/responses.
#[derive(Debug, Clone, Copy)]
pub enum BodyLength {
    /// Fixed-length body via Content-Length header.
    ContentLength(u64),
    /// Chunked transfer encoding.
    Chunked,
    /// No body (e.g. GET, HEAD, DELETE, or responses to HEAD).
    None,
}

/// A parsed L7 request ready for policy evaluation and forwarding.
#[derive(Debug)]
pub struct L7Request {
    /// Protocol action: HTTP method or SQL command.
    pub action: String,
    /// Target: URL path for REST, empty for SQL.
    pub target: String,
    /// Raw request header bytes (request line + headers for HTTP, message for SQL).
    /// May include overflow body bytes read during header parsing.
    pub raw_header: Vec<u8>,
    /// How to relay the request body.
    pub body_length: BodyLength,
}

/// Protocol-specific request parsing, relay, and deny logic.
///
/// Generic over the stream type to support both plaintext and TLS connections.
pub trait L7Provider: Send + Sync {
    /// Parse one request from the client stream.
    ///
    /// Returns `Ok(Some(request))` if a request was parsed,
    /// `Ok(None)` if the client closed the connection cleanly,
    /// `Err` on parse error or protocol violation.
    fn parse_request<C: AsyncRead + AsyncWrite + Unpin + Send>(
        &self,
        client: &mut C,
    ) -> impl Future<Output = Result<Option<L7Request>>> + Send;

    /// Forward an allowed request to upstream and relay the response back.
    ///
    /// Returns `true` if the upstream connection is reusable (keep-alive),
    /// `false` if it was consumed (e.g. read-until-EOF or `Connection: close`).
    fn relay<C, U>(
        &self,
        req: &L7Request,
        client: &mut C,
        upstream: &mut U,
    ) -> impl Future<Output = Result<bool>> + Send
    where
        C: AsyncRead + AsyncWrite + Unpin + Send,
        U: AsyncRead + AsyncWrite + Unpin + Send;

    /// Send a protocol-appropriate deny response to the client.
    fn deny<C: AsyncRead + AsyncWrite + Unpin + Send>(
        &self,
        req: &L7Request,
        policy_name: &str,
        reason: &str,
        client: &mut C,
    ) -> impl Future<Output = Result<()>> + Send;
}
