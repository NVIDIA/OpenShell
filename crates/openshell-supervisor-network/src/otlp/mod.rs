// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP relay for the sandbox supervisor.
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
use openshell_core::proto::{OtelExportData, otel_export_data};
use openshell_core::proto::supervisor_message;

use buffer::{TelemetryReceiver, TelemetrySender};

/// Rate-limited OCSF relay sink that implements token bucket rate limiting
/// and sends accepted events through the OTEL buffer as OCSF bytes.
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
            let max = self.max_tokens;
            self.tokens
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_add(new_tokens).min(max))
                })
                .ok();
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

/// Configuration for the OTEL relay.
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

/// Handle returned by [`OtelRelay::start`] for lifecycle management.
pub struct RelayHandle {
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    forwarder_handle: tokio::task::JoinHandle<()>,
    receiver_handle: tokio::task::JoinHandle<()>,
    session_drop_counter: Arc<AtomicU64>,
    pub otel_tx: TelemetrySender,
}

impl RelayHandle {
    /// Gracefully shut down the relay: stop the HTTP receiver, then drain
    /// remaining buffered data through the forwarder.
    pub async fn shutdown(self) {
        let metrics = self.otel_tx.metrics().clone();
        let _ = self.shutdown_tx.send(());
        let _ = self.receiver_handle.await;
        drop(self.otel_tx);
        let _ = self.forwarder_handle.await;
        info!(
            buffer_drops = metrics.drops(),
            queue_depth = metrics.depth(),
            session_drops = self.session_drop_counter.load(Ordering::Relaxed),
            "OTEL relay shut down"
        );
    }
}

/// The OTEL relay manages receive, enrich, buffer, and forward.
pub struct OtelRelay {
    config: RelayConfig,
    metadata: SandboxMetadata,
    session_tx: mpsc::Sender<SupervisorMessage>,
    sandbox_id: String,
}

impl OtelRelay {
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
            session_drop_counter.clone(),
        );

        info!(
            buffer_capacity = self.config.buffer_capacity,
            enrichment = self.config.enrichment_enabled,
            "OTEL relay started (pre-bound listener)"
        );

        RelayHandle {
            shutdown_tx,
            forwarder_handle,
            receiver_handle,
            session_drop_counter,
            otel_tx: buf_tx,
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
            session_drop_counter.clone(),
        );

        info!(
            bind = %bind_addr,
            buffer_capacity = self.config.buffer_capacity,
            enrichment = self.config.enrichment_enabled,
            "OTEL relay started"
        );

        Ok(RelayHandle {
            shutdown_tx,
            forwarder_handle,
            receiver_handle,
            session_drop_counter,
            otel_tx: buf_tx,
        })
    }
}

/// Errors that can occur when starting the relay.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("failed to bind OTLP receiver: {0}")]
    Bind(std::io::Error),
}

/// Spawn the forwarder task that drains the buffer and sends `OtelExportData`
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
                    payload: Some(supervisor_message::Payload::OtelExport(OtelExportData {
                        sandbox_id: sandbox_id.clone(),
                        signal: Some(otel_export_data::Signal::TraceData(data)),
                        ocsf_events: Vec::new(),
                    })),
                },
                buffer::TelemetryItem::Ocsf(data) => SupervisorMessage {
                    payload: Some(supervisor_message::Payload::OtelExport(OtelExportData {
                        sandbox_id: sandbox_id.clone(),
                        signal: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_ocsf::OcsfRelaySink;

    #[test]
    fn rate_limiter_acquires_initial_tokens() {
        let (buf_tx, _rx) = buffer::new_telemetry_buffer(64);
        let sink = RateLimitedOcsfSink::new(buf_tx, 10);

        for i in 0..10 {
            assert!(sink.try_acquire(), "token {i} should be available");
        }
        assert!(!sink.try_acquire(), "11th token should fail");
    }

    #[test]
    fn rate_limiter_drops_when_exhausted() {
        let (buf_tx, mut rx) = buffer::new_telemetry_buffer(64);
        let sink = RateLimitedOcsfSink::new(buf_tx, 2);

        sink.send(vec![1]);
        sink.send(vec![2]);
        sink.send(vec![3]);

        assert_eq!(sink.drops(), 1);
        let items = rx.drain();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn rate_limiter_refills_after_time() {
        let (buf_tx, _rx) = buffer::new_telemetry_buffer(64);
        let sink = RateLimitedOcsfSink::new(buf_tx, 100);

        for _ in 0..100 {
            sink.try_acquire();
        }
        assert!(!sink.try_acquire(), "should be exhausted");

        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(sink.try_acquire(), "should have refilled after 50ms");
    }

    #[tokio::test]
    async fn forwarder_constructs_otel_export_messages() {
        let (buf_tx, buf_rx) = buffer::new_telemetry_buffer(64);
        let (session_tx, mut session_rx) = mpsc::channel::<SupervisorMessage>(64);
        let drop_counter = Arc::new(AtomicU64::new(0));

        buf_tx.send_trace(vec![1, 2, 3]);
        buf_tx.send_ocsf(vec![4, 5, 6]);
        drop(buf_tx);

        let handle = spawn_forwarder(buf_rx, session_tx, "sb-test".into(), drop_counter);

        let msg1 = session_rx.recv().await.unwrap();
        if let Some(supervisor_message::Payload::OtelExport(otel)) = msg1.payload {
            assert_eq!(otel.sandbox_id, "sb-test");
            assert_eq!(
                otel.signal,
                Some(otel_export_data::Signal::TraceData(vec![1, 2, 3]))
            );
            assert!(otel.ocsf_events.is_empty());
        } else {
            panic!("expected OtelExport payload for trace");
        }

        let msg2 = session_rx.recv().await.unwrap();
        if let Some(supervisor_message::Payload::OtelExport(otel)) = msg2.payload {
            assert_eq!(otel.sandbox_id, "sb-test");
            assert_eq!(otel.signal, None);
            assert_eq!(otel.ocsf_events, vec![vec![4, 5, 6]]);
        } else {
            panic!("expected OtelExport payload for OCSF");
        }

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn forwarder_increments_session_drop_counter() {
        let (buf_tx, buf_rx) = buffer::new_telemetry_buffer(64);
        let (session_tx, _session_rx) = mpsc::channel::<SupervisorMessage>(1);
        let drop_counter = Arc::new(AtomicU64::new(0));

        // Fill the session channel
        session_tx
            .send(SupervisorMessage { payload: None })
            .await
            .unwrap();

        buf_tx.send_trace(vec![1]);
        buf_tx.send_trace(vec![2]);
        buf_tx.send_trace(vec![3]);
        drop(buf_tx);

        let handle = spawn_forwarder(buf_rx, session_tx, "sb-test".into(), drop_counter.clone());
        handle.await.unwrap();

        assert!(
            drop_counter.load(Ordering::Relaxed) >= 2,
            "should have dropped at least 2 messages (channel capacity 1, pre-filled)"
        );
    }
}
