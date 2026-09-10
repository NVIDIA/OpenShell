// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP relay for the sandbox supervisor.
//!
//! Receives OTLP trace data from agent processes over HTTP, enriches spans
//! with sandbox resource attributes, and buffers them in a bounded channel.
//! The supervisor session owns the relay: it binds the receiver only once the
//! gateway confirms the `otel_export` capability, drains the buffer into the
//! session stream, and stops the receiver before the main-process exit is
//! reported so final spans still reach the gateway.

pub mod buffer;
pub mod enrichment;
pub mod receiver;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{info, warn};

use openshell_core::proto::supervisor_message;
use openshell_core::proto::{OtelExportData, SupervisorMessage, otel_export_data};

use buffer::{BufferMetrics, TelemetryItem, TelemetryReceiver, TelemetrySender};
use receiver::ReceiverHandle;

/// Bounded time the receiver gets to finish in-flight requests on shutdown.
pub const RECEIVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

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
    pub buffer_capacity: usize,
    pub enrichment_enabled: bool,
    pub ocsf_rate_limit: u32,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
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

/// Everything needed to start the relay once the gateway confirms
/// `otel_export`. Built by the sandbox supervisor, consumed by the session.
#[derive(Debug, Clone)]
pub struct RelaySetup {
    pub config: RelayConfig,
    pub metadata: SandboxMetadata,
    pub bind_addr: SocketAddr,
}

/// Wrap a buffered telemetry item in the session message the gateway expects.
pub fn export_message(sandbox_id: &str, item: TelemetryItem) -> SupervisorMessage {
    let export = match item {
        TelemetryItem::Trace(data) => OtelExportData {
            sandbox_id: sandbox_id.to_string(),
            signal: Some(otel_export_data::Signal::TraceData(data)),
            ocsf_events: Vec::new(),
        },
        TelemetryItem::Ocsf(data) => OtelExportData {
            sandbox_id: sandbox_id.to_string(),
            signal: None,
            ocsf_events: vec![data],
        },
    };
    SupervisorMessage {
        payload: Some(supervisor_message::Payload::OtelExport(export)),
    }
}

/// Lazily started relay owned by the supervisor session loop.
///
/// Lives in the session's reconnect loop frame so the bound receiver and the
/// buffer survive gateway reconnects.
pub enum RelayLifecycle {
    /// Setup is known; the receiver is bound on the first confirming session.
    Pending(RelaySetup),
    /// Receiver bound and accepting.
    Running {
        receiver: ReceiverHandle,
        buffer: TelemetryReceiver,
        bind_addr: SocketAddr,
    },
    /// Relay disabled, failed to bind, or already drained.
    Stopped,
}

impl RelayLifecycle {
    /// `None` means the relay is unavailable on this platform or disabled.
    pub fn new(setup: Option<RelaySetup>) -> Self {
        setup.map_or(Self::Stopped, Self::Pending)
    }

    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    /// Address the receiver is bound to while running.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Running { bind_addr, .. } => Some(*bind_addr),
            _ => None,
        }
    }

    /// Buffer counters while running.
    pub fn buffer_metrics(&self) -> Option<BufferMetrics> {
        match self {
            Self::Running { buffer, .. } => Some(buffer.metrics().clone()),
            _ => None,
        }
    }

    /// Called once per session after `SessionAccepted`. Binds the receiver on
    /// the first session that confirms `otel_export`. A bind failure logs and
    /// disables the relay for the rest of the sandbox lifetime. Once running,
    /// the receiver stays bound even if a later session declines the
    /// capability; the caller gates forwarding per session.
    ///
    /// Returns `true` iff the relay is running after the call.
    pub async fn ensure_started(&mut self, confirmed: bool, netns_fd: Option<i32>) -> bool {
        match self {
            Self::Running { .. } => return true,
            Self::Stopped => return false,
            Self::Pending(_) if !confirmed => return false,
            Self::Pending(_) => {}
        }
        let Self::Pending(setup) = std::mem::replace(self, Self::Stopped) else {
            return false;
        };

        match bind_listener(setup.bind_addr, netns_fd).await {
            Ok(listener) => {
                let bind_addr = listener.local_addr().unwrap_or(setup.bind_addr);
                let (buf_tx, buffer) = buffer::new_telemetry_buffer(setup.config.buffer_capacity);
                let receiver = receiver::spawn_receiver(
                    listener,
                    buf_tx,
                    setup.metadata,
                    setup.config.enrichment_enabled,
                );
                info!(
                    bind = %bind_addr,
                    buffer_capacity = setup.config.buffer_capacity,
                    enrichment = setup.config.enrichment_enabled,
                    "OTEL relay started"
                );
                *self = Self::Running {
                    receiver,
                    buffer,
                    bind_addr,
                };
                true
            }
            Err(e) => {
                warn!(
                    error = %e,
                    bind = %setup.bind_addr,
                    "OTEL relay failed to bind; continuing without relay"
                );
                false
            }
        }
    }

    /// Next buffered item. Pends forever unless running, so it is safe to use
    /// as a `select!` arm. Yields `None` once the receiver and all its
    /// connections are gone.
    pub async fn next_item(&mut self) -> Option<TelemetryItem> {
        match self {
            Self::Running { buffer, .. } => buffer.recv().await,
            _ => std::future::pending().await,
        }
    }

    /// Stop accepting, close connections (bounded by
    /// [`RECEIVER_SHUTDOWN_TIMEOUT`]), then push everything still buffered into
    /// `tx`. Ends in [`RelayLifecycle::Stopped`]. Uses the non-blocking
    /// `drain()` so a straggling connection task cannot stall the flush.
    pub async fn stop_and_drain(&mut self, sandbox_id: &str, tx: &mpsc::Sender<SupervisorMessage>) {
        let Self::Running {
            receiver,
            mut buffer,
            bind_addr,
        } = std::mem::replace(self, Self::Stopped)
        else {
            return;
        };

        receiver.shutdown().await;

        let items = buffer.drain();
        let buffered = items.len();
        let mut forwarded = 0usize;
        for item in items {
            if tx.send(export_message(sandbox_id, item)).await.is_err() {
                break;
            }
            forwarded += 1;
        }
        info!(
            bind = %bind_addr,
            buffered,
            forwarded,
            buffer_drops = buffer.metrics().drops(),
            "OTEL relay stopped"
        );
    }
}

async fn bind_listener(
    addr: SocketAddr,
    netns_fd: Option<i32>,
) -> std::io::Result<tokio::net::TcpListener> {
    #[cfg(target_os = "linux")]
    if let Some(fd) = netns_fd {
        return crate::netns::bind_tcp_in_netns_fd(fd, addr).await;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = netns_fd;
    tokio::net::TcpListener::bind(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_ocsf::OcsfRelaySink;
    use receiver::test_util::{metadata, request, sample_trace_body, send};

    fn setup(bind_addr: SocketAddr) -> RelaySetup {
        RelaySetup {
            config: RelayConfig {
                buffer_capacity: 16,
                ..RelayConfig::default()
            },
            metadata: metadata(),
            bind_addr,
        }
    }

    fn ephemeral() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

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

        std::thread::sleep(Duration::from_millis(50));
        assert!(sink.try_acquire(), "should have refilled after 50ms");
    }

    #[test]
    fn export_message_wraps_trace_and_ocsf() {
        let msg = export_message("sb-1", TelemetryItem::Trace(vec![1, 2, 3]));
        let Some(supervisor_message::Payload::OtelExport(export)) = msg.payload else {
            panic!("expected OtelExport payload");
        };
        assert_eq!(export.sandbox_id, "sb-1");
        assert_eq!(
            export.signal,
            Some(otel_export_data::Signal::TraceData(vec![1, 2, 3]))
        );
        assert!(export.ocsf_events.is_empty());

        let msg = export_message("sb-1", TelemetryItem::Ocsf(vec![9]));
        let Some(supervisor_message::Payload::OtelExport(export)) = msg.payload else {
            panic!("expected OtelExport payload");
        };
        assert_eq!(export.signal, None);
        assert_eq!(export.ocsf_events, vec![vec![9]]);
    }

    #[tokio::test]
    async fn lifecycle_none_is_stopped() {
        let mut relay = RelayLifecycle::new(None);
        assert!(matches!(relay, RelayLifecycle::Stopped));
        assert!(!relay.ensure_started(true, None).await);
        assert!(matches!(relay, RelayLifecycle::Stopped));
    }

    #[tokio::test]
    async fn lifecycle_stays_pending_until_confirmed() {
        let mut relay = RelayLifecycle::new(Some(setup(ephemeral())));
        let (tx, _rx) = mpsc::channel(8);

        assert!(!relay.ensure_started(false, None).await);
        assert!(matches!(relay, RelayLifecycle::Pending(_)));
        assert!(relay.local_addr().is_none());

        assert!(relay.ensure_started(true, None).await);
        assert!(relay.is_running());
        let addr = relay.local_addr().expect("bound address");
        assert_ne!(addr.port(), 0);

        // A later session declining the capability does not unbind.
        assert!(relay.ensure_started(false, None).await);
        assert!(relay.is_running());

        relay.stop_and_drain("sb-test", &tx).await;
        assert!(matches!(relay, RelayLifecycle::Stopped));
        assert!(!relay.ensure_started(true, None).await);
    }

    #[tokio::test]
    async fn lifecycle_bind_failure_becomes_stopped() {
        let occupied = tokio::net::TcpListener::bind(ephemeral()).await.unwrap();
        let mut relay = RelayLifecycle::new(Some(setup(occupied.local_addr().unwrap())));

        assert!(!relay.ensure_started(true, None).await);
        assert!(matches!(relay, RelayLifecycle::Stopped));
    }

    #[tokio::test]
    async fn stop_and_drain_flushes_buffered_items_into_tx() {
        let mut relay = RelayLifecycle::new(Some(setup(ephemeral())));
        let (tx, mut rx) = mpsc::channel(8);
        assert!(relay.ensure_started(true, None).await);
        let addr = relay.local_addr().unwrap();

        let (_stream, status) = send(
            addr,
            &request(
                "POST",
                "/v1/traces",
                "application/x-protobuf",
                &sample_trace_body(),
            ),
        )
        .await;
        assert!(status.contains("200"), "unexpected status: {status}");
        assert_eq!(relay.buffer_metrics().unwrap().depth(), 1);

        relay.stop_and_drain("sb-test", &tx).await;
        assert!(matches!(relay, RelayLifecycle::Stopped));

        let msg = rx.try_recv().expect("one drained export message");
        let Some(supervisor_message::Payload::OtelExport(export)) = msg.payload else {
            panic!("expected OtelExport payload");
        };
        assert_eq!(export.sandbox_id, "sb-test");
        assert!(matches!(
            export.signal,
            Some(otel_export_data::Signal::TraceData(_))
        ));
        assert!(rx.try_recv().is_err(), "no further messages expected");
    }
}
