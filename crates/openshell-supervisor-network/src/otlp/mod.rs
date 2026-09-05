// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP telemetry relay for the sandbox supervisor.
//!
//! Receives OTLP trace data from agent processes over HTTP, enriches spans
//! with sandbox resource attributes, buffers them in a bounded channel, and
//! forwards them to the gateway over the session protocol.

pub mod buffer;
pub mod enrichment;
pub mod receiver;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;
use tracing::info;

use openshell_core::proto::SupervisorMessage;
use openshell_core::proto::TelemetryData;
use openshell_core::proto::supervisor_message;

use buffer::{TelemetryReceiver, TelemetrySender};

/// Rate-limited OCSF relay sink that implements token bucket rate limiting
/// and sends accepted events through the telemetry buffer as OCSF bytes.
pub struct RateLimitedOcsfSink {
    buf_tx: TelemetrySender,
    tokens: std::sync::atomic::AtomicU32,
    max_tokens: u32,
    drop_count: AtomicU64,
    last_refill: std::sync::Mutex<std::time::Instant>,
}

impl RateLimitedOcsfSink {
    pub fn new(buf_tx: TelemetrySender, rate_per_sec: u32) -> Self {
        Self {
            buf_tx,
            tokens: std::sync::atomic::AtomicU32::new(rate_per_sec),
            max_tokens: rate_per_sec,
            drop_count: AtomicU64::new(0),
            last_refill: std::sync::Mutex::new(std::time::Instant::now()),
        }
    }

    fn try_acquire(&self) -> bool {
        self.refill();
        let mut current = self.tokens.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return false;
            }
            match self.tokens.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(updated) => current = updated,
            }
        }
    }

    fn refill(&self) {
        let Ok(mut last) = self.last_refill.lock() else {
            return;
        };
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(*last);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let new_tokens = (elapsed.as_secs_f64() * f64::from(self.max_tokens)) as u32;
        if new_tokens > 0 {
            *last = now;
            let current = self.tokens.load(Ordering::Relaxed);
            let capped = (current + new_tokens).min(self.max_tokens);
            self.tokens.store(capped, Ordering::Relaxed);
        }
    }

    pub fn drops(&self) -> u64 {
        self.drop_count.load(Ordering::Relaxed)
    }
}

impl openshell_ocsf::OcsfRelaySink for RateLimitedOcsfSink {
    fn send(&self, json_bytes: Vec<u8>) {
        if self.try_acquire() {
            self.buf_tx.send_ocsf(json_bytes);
        } else {
            self.drop_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Configuration for the telemetry relay.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub enabled: bool,
    pub buffer_capacity: usize,
    pub enrichment_enabled: bool,
    pub ocsf_rate_limit: u32,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            buffer_capacity: 4096,
            enrichment_enabled: true,
            ocsf_rate_limit: 100,
        }
    }
}

/// Sandbox identity used for span enrichment.
#[derive(Debug, Clone)]
pub struct SandboxMetadata {
    pub sandbox_id: String,
    pub workspace_id: String,
    pub policy: String,
    pub user: String,
    pub image: String,
    pub driver: String,
}

/// Handle returned by [`TelemetryRelay::start`] for lifecycle management.
pub struct RelayHandle {
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    forwarder_handle: tokio::task::JoinHandle<()>,
    receiver_handle: tokio::task::JoinHandle<()>,
    pub telemetry_tx: TelemetrySender,
}

impl RelayHandle {
    /// Gracefully shut down the relay: stop the HTTP receiver, then drain
    /// remaining buffered telemetry through the forwarder.
    pub async fn shutdown(self) {
        let metrics = self.telemetry_tx.metrics().clone();
        let _ = self.shutdown_tx.send(());
        let _ = self.receiver_handle.await;
        let _ = self.forwarder_handle.await;
        info!(
            spans_dropped = metrics.drops(),
            queue_depth = metrics.depth(),
            "telemetry relay shut down"
        );
    }
}

/// The telemetry relay manages receive, enrich, buffer, and forward.
pub struct TelemetryRelay {
    config: RelayConfig,
    metadata: SandboxMetadata,
    session_tx: mpsc::Sender<SupervisorMessage>,
    sandbox_id: String,
}

impl TelemetryRelay {
    pub fn new(
        config: RelayConfig,
        metadata: SandboxMetadata,
        session_tx: mpsc::Sender<SupervisorMessage>,
    ) -> Self {
        let sandbox_id = metadata.sandbox_id.clone();
        Self {
            config,
            metadata,
            session_tx,
            sandbox_id,
        }
    }

    /// Start the relay with a pre-bound listener (for netns topologies).
    pub fn start_with_listener(self, listener: tokio::net::TcpListener) -> RelayHandle {
        let (buf_tx, buf_rx) = buffer::new_telemetry_buffer(self.config.buffer_capacity);
        let session_drop_counter = Arc::new(AtomicU64::new(0));
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let receiver_handle = receiver::spawn_receiver_with_listener(
            listener,
            buf_tx.clone(),
            self.metadata.clone(),
            self.config.enrichment_enabled,
            shutdown_rx,
        );

        let forwarder_handle = spawn_forwarder(
            buf_rx,
            self.session_tx,
            self.sandbox_id.clone(),
            session_drop_counter,
        );

        info!(
            buffer_capacity = self.config.buffer_capacity,
            enrichment = self.config.enrichment_enabled,
            "telemetry relay started (pre-bound listener)"
        );

        RelayHandle {
            shutdown_tx,
            forwarder_handle,
            receiver_handle,
            telemetry_tx: buf_tx,
        }
    }

    /// Start the relay: bind the OTLP HTTP receiver and spawn the forwarder.
    pub async fn start(self, bind_addr: SocketAddr) -> Result<RelayHandle, StartError> {
        let (buf_tx, buf_rx) = buffer::new_telemetry_buffer(self.config.buffer_capacity);

        let session_drop_counter = Arc::new(AtomicU64::new(0));

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let receiver_handle = receiver::spawn_receiver(
            bind_addr,
            buf_tx.clone(),
            self.metadata.clone(),
            self.config.enrichment_enabled,
            shutdown_rx,
        )
        .await
        .map_err(StartError::Bind)?;

        let forwarder_handle = spawn_forwarder(
            buf_rx,
            self.session_tx,
            self.sandbox_id.clone(),
            session_drop_counter,
        );

        info!(
            bind = %bind_addr,
            buffer_capacity = self.config.buffer_capacity,
            enrichment = self.config.enrichment_enabled,
            "telemetry relay started"
        );

        Ok(RelayHandle {
            shutdown_tx,
            forwarder_handle,
            receiver_handle,
            telemetry_tx: buf_tx,
        })
    }
}

/// Errors that can occur when starting the relay.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("failed to bind OTLP receiver: {0}")]
    Bind(std::io::Error),
}

/// Spawn the forwarder task that drains the buffer and sends `TelemetryData`
/// via the session channel using `try_send` (non-blocking).
fn spawn_forwarder(
    mut buf_rx: TelemetryReceiver,
    session_tx: mpsc::Sender<SupervisorMessage>,
    sandbox_id: String,
    session_drop_counter: Arc<AtomicU64>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(item) = buf_rx.recv().await {
            let msg = match item {
                buffer::TelemetryItem::Trace(data) => SupervisorMessage {
                    payload: Some(supervisor_message::Payload::Telemetry(TelemetryData {
                        sandbox_id: sandbox_id.clone(),
                        trace_data: data,
                        ocsf_events: Vec::new(),
                    })),
                },
                buffer::TelemetryItem::Ocsf(data) => SupervisorMessage {
                    payload: Some(supervisor_message::Payload::Telemetry(TelemetryData {
                        sandbox_id: sandbox_id.clone(),
                        trace_data: Vec::new(),
                        ocsf_events: vec![data],
                    })),
                },
            };

            if session_tx.try_send(msg).is_err() {
                session_drop_counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    })
}
