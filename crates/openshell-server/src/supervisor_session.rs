// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use uuid::Uuid;

use openshell_core::proto::{
    GatewayMessage, RelayOpen, SessionAccepted, SupervisorMessage, gateway_message,
    supervisor_message,
};

use crate::ServerState;

const HEARTBEAT_INTERVAL_SECS: u32 = 15;
const RELAY_PENDING_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Session registry
// ---------------------------------------------------------------------------

/// A live supervisor session handle.
struct LiveSession {
    #[allow(dead_code)]
    sandbox_id: String,
    tx: mpsc::Sender<GatewayMessage>,
    #[allow(dead_code)]
    connected_at: Instant,
}

/// Holds a oneshot sender that will deliver the upgraded relay stream.
type RelayStreamSender = oneshot::Sender<tokio::io::DuplexStream>;

/// Registry of active supervisor sessions and pending relay channels.
#[derive(Default)]
pub struct SupervisorSessionRegistry {
    /// sandbox_id -> live session handle.
    sessions: Mutex<HashMap<String, LiveSession>>,
    /// channel_id -> oneshot sender for the reverse CONNECT stream.
    pending_relays: Mutex<HashMap<String, PendingRelay>>,
}

struct PendingRelay {
    sender: RelayStreamSender,
    created_at: Instant,
}

impl std::fmt::Debug for SupervisorSessionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let session_count = self.sessions.lock().unwrap().len();
        let pending_count = self.pending_relays.lock().unwrap().len();
        f.debug_struct("SupervisorSessionRegistry")
            .field("sessions", &session_count)
            .field("pending_relays", &pending_count)
            .finish()
    }
}

impl SupervisorSessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a live supervisor session for the given sandbox.
    ///
    /// Returns the previous session's sender (if any) so the caller can close it.
    fn register(
        &self,
        sandbox_id: String,
        tx: mpsc::Sender<GatewayMessage>,
    ) -> Option<mpsc::Sender<GatewayMessage>> {
        let mut sessions = self.sessions.lock().unwrap();
        let previous = sessions.remove(&sandbox_id).map(|s| s.tx);
        sessions.insert(
            sandbox_id.clone(),
            LiveSession {
                sandbox_id,
                tx,
                connected_at: Instant::now(),
            },
        );
        previous
    }

    /// Remove the session for a sandbox.
    fn remove(&self, sandbox_id: &str) {
        self.sessions.lock().unwrap().remove(sandbox_id);
    }

    /// Open a relay channel, waiting for the supervisor session to appear.
    ///
    /// The supervisor session may not be established yet when the sandbox first
    /// reports Ready (race between K8s readiness and gRPC session handshake).
    /// This method retries the session lookup with short backoff before failing.
    pub async fn open_relay_with_wait(
        &self,
        sandbox_id: &str,
        timeout: Duration,
    ) -> Result<(String, oneshot::Receiver<tokio::io::DuplexStream>), Status> {
        let deadline = Instant::now() + timeout;
        let mut backoff = Duration::from_millis(100);

        loop {
            match self.open_relay(sandbox_id).await {
                Ok(result) => return Ok(result),
                Err(status) if status.code() == tonic::Code::Unavailable => {
                    if Instant::now() + backoff > deadline {
                        return Err(status);
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(2));
                }
                Err(status) => return Err(status),
            }
        }
    }

    /// Open a relay channel: sends RelayOpen to the supervisor and returns a
    /// stream that will be connected once the supervisor's reverse HTTP CONNECT
    /// arrives.
    ///
    /// Returns `(channel_id, receiver_for_relay_stream)`.
    pub async fn open_relay(
        &self,
        sandbox_id: &str,
    ) -> Result<(String, oneshot::Receiver<tokio::io::DuplexStream>), Status> {
        let channel_id = Uuid::new_v4().to_string();

        // Look up the session and send RelayOpen.
        let tx = {
            let sessions = self.sessions.lock().unwrap();
            let session = sessions
                .get(sandbox_id)
                .ok_or_else(|| Status::unavailable("supervisor session not connected"))?;
            session.tx.clone()
        };

        // Register the pending relay before sending RelayOpen to avoid a race.
        let (relay_tx, relay_rx) = oneshot::channel();
        {
            let mut pending = self.pending_relays.lock().unwrap();
            pending.insert(
                channel_id.clone(),
                PendingRelay {
                    sender: relay_tx,
                    created_at: Instant::now(),
                },
            );
        }

        let msg = GatewayMessage {
            payload: Some(gateway_message::Payload::RelayOpen(RelayOpen {
                channel_id: channel_id.clone(),
            })),
        };

        if tx.send(msg).await.is_err() {
            // Session dropped between our lookup and send.
            self.pending_relays.lock().unwrap().remove(&channel_id);
            return Err(Status::unavailable("supervisor session disconnected"));
        }

        Ok((channel_id, relay_rx))
    }

    /// Claim a pending relay channel. Called by the /relay/{channel_id} HTTP handler
    /// when the supervisor's reverse CONNECT arrives.
    ///
    /// Returns the DuplexStream half that the supervisor side should read/write.
    pub fn claim_relay(&self, channel_id: &str) -> Result<tokio::io::DuplexStream, Status> {
        let pending = {
            let mut map = self.pending_relays.lock().unwrap();
            map.remove(channel_id)
                .ok_or_else(|| Status::not_found("unknown or expired relay channel"))?
        };

        if pending.created_at.elapsed() > RELAY_PENDING_TIMEOUT {
            return Err(Status::deadline_exceeded("relay channel timed out"));
        }

        // Create a duplex stream pair: one end for the gateway bridge, one for
        // the supervisor HTTP CONNECT handler.
        let (gateway_stream, supervisor_stream) = tokio::io::duplex(64 * 1024);

        // Send the gateway-side stream to the waiter (ssh_tunnel or exec handler).
        if pending.sender.send(gateway_stream).is_err() {
            return Err(Status::internal("relay requester dropped"));
        }

        Ok(supervisor_stream)
    }

    /// Remove all pending relays that have exceeded the timeout.
    pub fn reap_expired_relays(&self) {
        let mut map = self.pending_relays.lock().unwrap();
        map.retain(|_, pending| pending.created_at.elapsed() <= RELAY_PENDING_TIMEOUT);
    }

    /// Clean up all state for a sandbox (session + pending relays).
    pub fn cleanup_sandbox(&self, sandbox_id: &str) {
        self.remove(sandbox_id);
    }
}

// ---------------------------------------------------------------------------
// ConnectSupervisor gRPC handler
// ---------------------------------------------------------------------------

pub async fn handle_connect_supervisor(
    state: &Arc<ServerState>,
    request: Request<tonic::Streaming<SupervisorMessage>>,
) -> Result<
    Response<
        Pin<Box<dyn tokio_stream::Stream<Item = Result<GatewayMessage, Status>> + Send + 'static>>,
    >,
    Status,
> {
    let mut inbound = request.into_inner();

    // Step 1: Wait for SupervisorHello.
    let hello = match inbound.message().await? {
        Some(msg) => match msg.payload {
            Some(supervisor_message::Payload::Hello(hello)) => hello,
            _ => return Err(Status::invalid_argument("expected SupervisorHello")),
        },
        None => return Err(Status::invalid_argument("stream closed before hello")),
    };

    let sandbox_id = hello.sandbox_id.clone();
    if sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }

    let session_id = Uuid::new_v4().to_string();
    info!(
        sandbox_id = %sandbox_id,
        session_id = %session_id,
        instance_id = %hello.instance_id,
        "supervisor session: accepted"
    );

    // Step 2: Create the outbound channel and register the session.
    let (tx, rx) = mpsc::channel::<GatewayMessage>(64);
    if let Some(_previous_tx) = state
        .supervisor_sessions
        .register(sandbox_id.clone(), tx.clone())
    {
        info!(sandbox_id = %sandbox_id, "supervisor session: superseded previous session");
    }

    // Step 3: Send SessionAccepted.
    let accepted = GatewayMessage {
        payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
            session_id: session_id.clone(),
            heartbeat_interval_secs: HEARTBEAT_INTERVAL_SECS,
        })),
    };
    if tx.send(accepted).await.is_err() {
        state.supervisor_sessions.remove(&sandbox_id);
        return Err(Status::internal("failed to send session accepted"));
    }

    // Step 4: Spawn the session loop that reads inbound messages.
    let state_clone = Arc::clone(state);
    let sandbox_id_clone = sandbox_id.clone();
    tokio::spawn(async move {
        run_session_loop(
            &state_clone,
            &sandbox_id_clone,
            &session_id,
            &tx,
            &mut inbound,
        )
        .await;
        state_clone.supervisor_sessions.remove(&sandbox_id_clone);
        info!(sandbox_id = %sandbox_id_clone, session_id = %session_id, "supervisor session: ended");
    });

    // Return the outbound stream.
    let stream = ReceiverStream::new(rx);
    let stream: Pin<
        Box<dyn tokio_stream::Stream<Item = Result<GatewayMessage, Status>> + Send + 'static>,
    > = Box::pin(tokio_stream::StreamExt::map(stream, Ok));

    Ok(Response::new(stream))
}

async fn run_session_loop(
    _state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    tx: &mpsc::Sender<GatewayMessage>,
    inbound: &mut tonic::Streaming<SupervisorMessage>,
) {
    let heartbeat_interval = Duration::from_secs(u64::from(HEARTBEAT_INTERVAL_SECS));
    let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
    // Skip the first immediate tick.
    heartbeat_timer.tick().await;

    loop {
        tokio::select! {
            msg = inbound.message() => {
                match msg {
                    Ok(Some(msg)) => {
                        handle_supervisor_message(sandbox_id, session_id, msg);
                    }
                    Ok(None) => {
                        info!(sandbox_id = %sandbox_id, session_id = %session_id, "supervisor session: stream closed by supervisor");
                        break;
                    }
                    Err(e) => {
                        warn!(sandbox_id = %sandbox_id, session_id = %session_id, error = %e, "supervisor session: stream error");
                        break;
                    }
                }
            }
            _ = heartbeat_timer.tick() => {
                let hb = GatewayMessage {
                    payload: Some(gateway_message::Payload::Heartbeat(
                        openshell_core::proto::GatewayHeartbeat {},
                    )),
                };
                if tx.send(hb).await.is_err() {
                    info!(sandbox_id = %sandbox_id, session_id = %session_id, "supervisor session: outbound channel closed");
                    break;
                }
            }
        }
    }
}

fn handle_supervisor_message(sandbox_id: &str, session_id: &str, msg: SupervisorMessage) {
    match msg.payload {
        Some(supervisor_message::Payload::Heartbeat(_)) => {
            // Heartbeat received — nothing to do for now.
        }
        Some(supervisor_message::Payload::RelayOpenResult(result)) => {
            if result.success {
                info!(
                    sandbox_id = %sandbox_id,
                    session_id = %session_id,
                    channel_id = %result.channel_id,
                    "supervisor session: relay opened successfully"
                );
            } else {
                warn!(
                    sandbox_id = %sandbox_id,
                    session_id = %session_id,
                    channel_id = %result.channel_id,
                    error = %result.error,
                    "supervisor session: relay open failed"
                );
            }
        }
        Some(supervisor_message::Payload::RelayClose(close)) => {
            info!(
                sandbox_id = %sandbox_id,
                session_id = %session_id,
                channel_id = %close.channel_id,
                reason = %close.reason,
                "supervisor session: relay closed by supervisor"
            );
        }
        _ => {
            warn!(
                sandbox_id = %sandbox_id,
                session_id = %session_id,
                "supervisor session: unexpected message type"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_register_and_lookup() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);

        assert!(registry.register("sandbox-1".to_string(), tx).is_none());

        // Should find the session.
        let sessions = registry.sessions.lock().unwrap();
        assert!(sessions.contains_key("sandbox-1"));
    }

    #[test]
    fn registry_supersedes_previous_session() {
        let registry = SupervisorSessionRegistry::new();
        let (tx1, _rx1) = mpsc::channel(1);
        let (tx2, _rx2) = mpsc::channel(1);

        assert!(registry.register("sandbox-1".to_string(), tx1).is_none());
        assert!(registry.register("sandbox-1".to_string(), tx2).is_some());
    }

    #[test]
    fn registry_remove() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);
        registry.register("sandbox-1".to_string(), tx);

        registry.remove("sandbox-1");
        let sessions = registry.sessions.lock().unwrap();
        assert!(!sessions.contains_key("sandbox-1"));
    }

    #[test]
    fn claim_relay_unknown_channel() {
        let registry = SupervisorSessionRegistry::new();
        let result = registry.claim_relay("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn claim_relay_success() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, _relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-1".to_string(),
            PendingRelay {
                sender: relay_tx,
                created_at: Instant::now(),
            },
        );

        let result = registry.claim_relay("ch-1");
        assert!(result.is_ok());
        // Should be consumed.
        assert!(!registry.pending_relays.lock().unwrap().contains_key("ch-1"));
    }

    #[test]
    fn reap_expired_relays() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, _relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-old".to_string(),
            PendingRelay {
                sender: relay_tx,
                created_at: Instant::now() - Duration::from_secs(60),
            },
        );

        registry.reap_expired_relays();
        assert!(
            !registry
                .pending_relays
                .lock()
                .unwrap()
                .contains_key("ch-old")
        );
    }
}
