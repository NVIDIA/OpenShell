// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A deliberately small HTTP host call. Only the supervisor opens upstream sockets.
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use openshell_isolation_interface::contract::{TcpOpenDecision, TcpOpenDenial};
use tokio::sync::{mpsc, oneshot, watch};
use tonic::{Status, Streaming};

use crate::protocol::boundary::{BoundaryChunk, boundary_chunk};

pub const POLICY_DENIED: i32 = -1;
pub const UNAVAILABLE: i32 = -2;
pub const OTHER_DENIAL: i32 = -3;
pub const INVALID_REQUEST: i32 = -4;
pub const MAX_URL: usize = 512;
const TIMEOUT: Duration = Duration::from_secs(10);

pub struct HttpOpen {
    pub destination: SocketAddr,
    pub request: Vec<u8>,
    pub queued_at: Instant,
    pub result: oneshot::Sender<i32>,
}

#[derive(Clone)]
pub struct Network {
    sender: mpsc::Sender<HttpOpen>,
    runtime: tokio::runtime::Handle,
}

impl Network {
    pub fn channel() -> (Self, mpsc::Receiver<HttpOpen>) {
        let (sender, receiver) = mpsc::channel(8);
        (
            Self {
                sender,
                runtime: tokio::runtime::Handle::current(),
            },
            receiver,
        )
    }

    /// Called only from the guest's blocking execution thread. A lost supervisor,
    /// full queue, timeout, or cancellation can never become a policy denial.
    pub fn http_get(&self, url: &str, mut stopped: watch::Receiver<bool>) -> i32 {
        let Some((destination, request)) = parse_request(url) else {
            return INVALID_REQUEST;
        };
        let (result, response) = oneshot::channel();
        let outcome = self.runtime.block_on(async {
            tokio::select! {
                biased;
                _ = stopped.wait_for(|value| *value) => UNAVAILABLE,
                result = tokio::time::timeout(TIMEOUT, async {
                    self.sender.send(HttpOpen { destination, request, queued_at: Instant::now(), result }).await.ok()?;
                    response.await.ok()
                }) => result.ok().flatten().unwrap_or(UNAVAILABLE),
            }
        });
        println!(
            "HTTP GET {url}: {}",
            match outcome {
                POLICY_DENIED => "denied by supervisor policy".to_string(),
                UNAVAILABLE => "supervisor mediation unavailable".to_string(),
                OTHER_DENIAL => "denied by supervisor (not a policy denial)".to_string(),
                status => format!("HTTP {status}"),
            }
        );
        outcome
    }
}

// Numeric destinations keep DNS out of this example. No host resolver or socket
// API is exposed to the guest, and CR/LF cannot inject extra HTTP requests.
fn parse_request(url: &str) -> Option<(SocketAddr, Vec<u8>)> {
    if url.len() > MAX_URL
        || !url.is_ascii()
        || url
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return None;
    }
    let url = url.strip_prefix("http://")?;
    let (authority, path) = url
        .split_once('/')
        .map_or((url, "/".to_string()), |(host, path)| {
            (host, format!("/{path}"))
        });
    let destination = authority
        .parse()
        .or_else(|_| authority.parse().map(|ip| SocketAddr::new(ip, 80)))
        .ok()?;
    Some((
        destination,
        format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
            .into_bytes(),
    ))
}

async fn data(input: &mut Streaming<BoundaryChunk>) -> Result<Vec<u8>, Status> {
    match input.message().await?.and_then(|chunk| chunk.payload) {
        Some(boundary_chunk::Payload::RelayData(bytes))
            if !bytes.is_empty()
                && bytes.len()
                    <= openshell_sandbox_backend::boundary_protocol::MAX_STREAM_FRAME_BYTES =>
        {
            Ok(bytes)
        }
        _ => Err(Status::unavailable("network stream closed or invalid")),
    }
}

pub async fn decision(input: &mut Streaming<BoundaryChunk>) -> Result<TcpOpenDecision, Status> {
    match input.message().await?.and_then(|chunk| chunk.payload) {
        Some(boundary_chunk::Payload::NetworkDecision(value)) => {
            crate::protocol::network_decision(value)
        }
        _ => Err(Status::invalid_argument("network decision required")),
    }
}

pub async fn http_status(input: &mut Streaming<BoundaryChunk>) -> Result<i32, Status> {
    let mut bytes = Vec::new();
    loop {
        let data = data(input).await?;
        let remaining = 4096 - bytes.len();
        bytes.extend_from_slice(&data[..data.len().min(remaining)]);
        if let Some(end) = bytes.windows(2).position(|pair| pair == b"\r\n") {
            let line = std::str::from_utf8(&bytes[..end])
                .map_err(|_| Status::invalid_argument("invalid HTTP status"))?;
            let mut fields = line.split(' ');
            if !matches!(fields.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
                return Err(Status::invalid_argument("invalid HTTP response"));
            }
            return fields
                .next()
                .and_then(|s| s.parse::<i32>().ok())
                .filter(|s| (100..=599).contains(s))
                .ok_or_else(|| Status::invalid_argument("invalid HTTP status"));
        }
        if bytes.len() == 4096 {
            return Err(Status::resource_exhausted("HTTP status line too long"));
        }
    }
}

pub fn denied(reason: TcpOpenDenial) -> i32 {
    match reason {
        TcpOpenDenial::PolicyDenied => POLICY_DENIED,
        TcpOpenDenial::MediationUnavailable => UNAVAILABLE,
        _ => OTHER_DENIAL,
    }
}
