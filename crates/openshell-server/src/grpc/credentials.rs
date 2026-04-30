// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Deferred credential relay between sandbox supervisors and CLI credential authorities.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use openshell_core::proto::{
    CredentialRequest, CredentialResponse, ResolveCredentialRequest, ResolveCredentialResponse,
};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::ServerState;

/// Registry of connected CLI credential authorities and pending resolution requests.
#[derive(Debug, Default)]
pub struct CredentialAuthorityRegistry {
    /// CLI authority streams, keyed by a session identifier (typically user/sandbox scope).
    /// Each entry includes a generation ID to prevent stale reader tasks from
    /// removing newer registrations.
    authorities: Mutex<HashMap<String, (u64, mpsc::Sender<CredentialRequest>)>>,
    /// Monotonically increasing generation counter for authority registrations.
    generation: AtomicU64,
    /// Pending credential resolutions waiting for a CLI response.
    /// Keyed by request_id, completed when the CLI sends back a CredentialResponse.
    pending: Mutex<HashMap<String, oneshot::Sender<CredentialResponse>>>,
}

impl CredentialAuthorityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve a deferred credential by forwarding to the registered CLI authority.
    ///
    /// Returns the CLI's response or an error if no authority is registered or the
    /// authority disconnected/timed out.
    pub async fn resolve(
        &self,
        req: ResolveCredentialRequest,
        sandbox_name: Option<String>,
    ) -> Result<ResolveCredentialResponse, Status> {
        let request_id = Uuid::new_v4().to_string();
        let sandbox_id = req.sandbox_id.clone();

        debug!(
            request_id = %request_id,
            sandbox_id = %sandbox_id,
            env_key = %req.env_key,
            "resolve: looking up authority"
        );

        // Find a registered authority for this sandbox (or a global authority).
        let (authority_tx, registered_keys) = {
            let authorities = self.authorities.lock().await;
            let keys: Vec<_> = authorities.keys().cloned().collect();
            debug!(registered_authorities = ?keys, "resolve: registered authorities");
            let tx = authorities
                .get(&sandbox_id)
                .or_else(|| authorities.get("global"))
                .map(|(_, sender)| sender.clone());
            (tx, keys)
        };

        let Some(authority_tx) = authority_tx else {
            warn!("resolve: no authority found (sandbox_id={sandbox_id}, registered={registered_keys:?})");
            return Err(Status::unavailable(
                "no credential authority registered — is the CLI connected?",
            ));
        };

        debug!(request_id = %request_id, "resolve: authority found, creating oneshot");

        // Create a oneshot channel for the response
        let (resp_tx, resp_rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            pending.insert(request_id.clone(), resp_tx);
        }

        // Send the request to the CLI
        let cred_request = CredentialRequest {
            request_id: request_id.clone(),
            sandbox_id: sandbox_id.clone(),
            sandbox_name: sandbox_name.unwrap_or_else(|| sandbox_id.clone()),
            env_key: req.env_key.clone(),
            destination_host: req.destination_host.clone(),
        };

        if authority_tx.send(cred_request).await.is_err() {
            warn!(request_id = %request_id, "resolve: authority_tx.send failed — CLI disconnected");
            self.pending.lock().await.remove(&request_id);
            return Err(Status::unavailable("credential authority disconnected"));
        }

        debug!(request_id = %request_id, "resolve: request sent to CLI, waiting for response");

        // Wait for the CLI response (with timeout)
        let timeout_result =
            tokio::time::timeout(std::time::Duration::from_secs(60), resp_rx).await;

        let response = match timeout_result {
            Ok(Ok(resp)) => {
                debug!(request_id = %request_id, approved = resp.approved, "resolve: got CLI response");
                resp
            }
            Ok(Err(_)) => {
                warn!(request_id = %request_id, "resolve: oneshot channel dropped");
                self.pending.lock().await.remove(&request_id);
                return Err(Status::internal("credential authority channel dropped"));
            }
            Err(_) => {
                warn!(request_id = %request_id, "resolve: 60s timeout");
                self.pending.lock().await.remove(&request_id);
                return Err(Status::deadline_exceeded(
                    "credential request timed out (60s)",
                ));
            }
        };

        Ok(ResolveCredentialResponse {
            approved: response.approved,
            value: response.value,
        })
    }

    /// Register a CLI as credential authority and relay requests/responses.
    /// Returns a generation ID that must be passed to `unregister_authority`.
    pub async fn register_authority(
        &self,
        scope: String,
        request_tx: mpsc::Sender<CredentialRequest>,
    ) -> u64 {
        let reg_id = self.generation.fetch_add(1, Ordering::Relaxed);
        let mut authorities = self.authorities.lock().await;
        authorities.insert(scope.clone(), (reg_id, request_tx));
        let keys: Vec<_> = authorities.keys().cloned().collect();
        info!("register_authority: scope={scope} reg_id={reg_id} total={keys:?}");
        reg_id
    }

    /// Remove a registered authority, but only if the generation matches.
    /// Prevents stale reader tasks from removing a newer registration.
    pub async fn unregister_authority(&self, scope: &str, reg_id: u64) {
        let mut authorities = self.authorities.lock().await;
        if let Some((stored_reg_id, _)) = authorities.get(scope) {
            if *stored_reg_id == reg_id {
                authorities.remove(scope);
                let keys: Vec<_> = authorities.keys().cloned().collect();
                info!("unregister_authority: scope={scope} reg_id={reg_id} remaining={keys:?}");
            } else {
                debug!("unregister_authority: scope={scope} reg_id={reg_id} skipped (current reg_id={})", stored_reg_id);
            }
        }
    }

    /// Complete a pending credential resolution with the CLI's response.
    pub async fn complete_resolution(&self, response: CredentialResponse) {
        let mut pending = self.pending.lock().await;
        if let Some(tx) = pending.remove(&response.request_id) {
            let _ = tx.send(response);
        } else {
            warn!(
                request_id = %response.request_id,
                "Received credential response for unknown request"
            );
        }
    }
}

/// Handle `ResolveCredential` RPC (called by sandbox supervisor).
pub async fn handle_resolve_credential(
    state: &ServerState,
    request: Request<ResolveCredentialRequest>,
) -> Result<Response<ResolveCredentialResponse>, Status> {
    let req = request.into_inner();
    debug!(
        sandbox_id = %req.sandbox_id,
        env_key = %req.env_key,
        destination_host = %req.destination_host,
        "Received deferred credential resolution request"
    );

    let sandbox_name = state.sandbox_index.sandbox_name_for_id(&req.sandbox_id);
    let response = state.credential_authority_registry.resolve(req, sandbox_name).await?;
    Ok(Response::new(response))
}

/// Handle `RegisterCredentialAuthority` bidirectional streaming RPC (called by CLI).
///
/// The CLI sends `CredentialResponse` messages on its stream; the gateway pushes
/// `CredentialRequest` messages back. The stream stays open for the sandbox lifetime.
pub async fn handle_register_credential_authority(
    state: &Arc<ServerState>,
    request: Request<tonic::Streaming<CredentialResponse>>,
) -> Result<
    Response<std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<CredentialRequest, Status>> + Send>>>,
    Status,
> {
    let mut inbound = request.into_inner();

    // Create a channel for sending requests to the CLI
    let (request_tx, request_rx) = mpsc::channel::<CredentialRequest>(16);

    // Register as authority (use "global" scope for now — PoC simplification)
    let scope = "global".to_string();
    let reg_id = state
        .credential_authority_registry
        .register_authority(scope.clone(), request_tx)
        .await;

    debug!("CLI registered as credential authority (scope: {scope}, reg_id: {reg_id})");

    // Spawn a task to read responses from the CLI and complete pending resolutions
    let state_clone = state.clone();
    let scope_clone = scope.clone();
    tokio::spawn(async move {
        debug!("credential authority reader task started (scope: {scope_clone}, reg_id: {reg_id})");
        loop {
            match inbound.message().await {
                Ok(Some(response)) => {
                    if response.request_id.is_empty() {
                        debug!("credential authority: seed frame received (scope: {scope_clone}, reg_id: {reg_id})");
                        continue;
                    }
                    debug!(request_id = %response.request_id, approved = response.approved, "credential authority: received CLI response");
                    state_clone
                        .credential_authority_registry
                        .complete_resolution(response)
                        .await;
                }
                Ok(None) => {
                    info!("credential authority: CLI stream ended (scope: {scope_clone}, reg_id: {reg_id})");
                    break;
                }
                Err(e) => {
                    warn!("credential authority: CLI stream error: {e} (scope: {scope_clone}, reg_id: {reg_id})");
                    break;
                }
            }
        }
        state_clone
            .credential_authority_registry
            .unregister_authority(&scope_clone, reg_id)
            .await;
    });

    // Convert the request receiver into a stream for the response
    let stream = tokio_stream::wrappers::ReceiverStream::new(request_rx)
        .map(Ok);

    Ok(Response::new(Box::pin(stream)))
}
