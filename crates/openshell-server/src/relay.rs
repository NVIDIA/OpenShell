// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP CONNECT relay endpoint for supervisor-initiated reverse tunnels.
//!
//! When the gateway sends a `RelayOpen` message over the supervisor's gRPC
//! session, the supervisor opens `CONNECT /relay/{channel_id}` back to this
//! endpoint. The gateway then bridges the supervisor's upgraded stream with
//! the client's SSH tunnel or exec proxy.

use axum::{
    Router, extract::Path, extract::State, http::Method, response::IntoResponse, routing::any,
};
use http::StatusCode;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use crate::ServerState;

pub fn router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/relay/{channel_id}", any(relay_connect))
        .with_state(state)
}

async fn relay_connect(
    State(state): State<Arc<ServerState>>,
    Path(channel_id): Path<String>,
    req: hyper::Request<axum::body::Body>,
) -> impl IntoResponse {
    if req.method() != Method::CONNECT {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    // Claim the pending relay. This consumes the entry — it cannot be reused.
    let supervisor_stream = match state.supervisor_sessions.claim_relay(&channel_id) {
        Ok(stream) => stream,
        Err(_) => {
            warn!(channel_id = %channel_id, "relay: unknown or expired channel");
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    info!(channel_id = %channel_id, "relay: supervisor connected, upgrading");

    // Upgrade the HTTP connection to a raw byte stream and bridge it to
    // the DuplexStream that connects to the gateway-side waiter.
    let on_upgrade: OnUpgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let mut upgraded = TokioIo::new(upgraded);
                let mut supervisor = supervisor_stream;
                let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut supervisor).await;
                let _ = AsyncWriteExt::shutdown(&mut upgraded).await;
            }
            Err(e) => {
                warn!(channel_id = %channel_id, error = %e, "relay: upgrade failed");
            }
        }
    });

    StatusCode::SWITCHING_PROTOCOLS.into_response()
}
