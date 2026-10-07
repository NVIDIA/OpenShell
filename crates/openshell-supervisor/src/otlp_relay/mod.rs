// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-direct OTLP trace relay.
//!
//! A sandboxed agent exports OTLP/HTTP protobuf traces to the reserved
//! address [`openshell_core::sandbox_env::OTLP_RELAY_ADDR`]. The sandbox
//! broker stages that connection to the supervisor, the network proxy hands
//! the stream to [`receiver::OtlpConnectionServer`], and the accepted batch
//! is enriched with the sandbox id, buffered, and forwarded over OTLP/gRPC to
//! the collector the supervisor already uses for its own spans.

pub mod buffer;
pub mod enrichment;
pub mod exporter;
pub mod receiver;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use openshell_isolation_interface::contract::BoundaryDuplexStream;
use openshell_ocsf::{ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ocsf_emit};
use openshell_supervisor_network::proxy::{
    ReservedDestination, ReservedStreamFuture, ReservedStreamHandler,
};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use self::buffer::new_buffer;
use self::exporter::Exporter;
use self::receiver::{OtlpConnectionServer, ReceiverHandle};

/// Maximum accepted request body, in wire bytes.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Maximum size of a batch after attribution, derived from the per-entry
/// growth bound and the entry cap.
///
/// Relay memory attributable to the agent is bounded by three parts: the
/// export buffer, [`BUFFER_CAPACITY`] batches of this size (about 67 MiB);
/// bodies read but not yet enriched, [`MAX_CONCURRENT_CONNECTIONS`] times
/// [`MAX_BODY_BYTES`] (32 MiB); and the working set of the
/// [`ENRICHMENT_CONCURRENCY`] enrichments in progress, each about twice the
/// body plus at most about 1 MiB of decoded resource elements (about
/// 12 MiB). Every allocation is sized to its content before it is held.
pub const MAX_ENRICHED_BYTES: usize =
    MAX_BODY_BYTES + enrichment::MAX_RESOURCE_SPANS * enrichment::ATTRIBUTION_BYTES_PER_ENTRY;
/// How long a connection may idle before a complete request header arrives.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a request may take to deliver its body once the headers are in,
/// so a stalled sender cannot hold a connection slot indefinitely.
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum number of receiver connections served at once.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 16;
/// Requests enriched at the same time.
///
/// Enrichment is a short CPU-bound copy whose working set is about twice the
/// body plus the decoded resources, so two slots bound that transient
/// regardless of how many connections hold a body.
pub const ENRICHMENT_CONCURRENCY: usize = 2;
/// Number of enriched batches held between receipt and export.
pub const BUFFER_CAPACITY: usize = 32;
/// Deadline for one export attempt to the collector.
pub const EXPORT_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on the graceful shutdown of in-flight receiver connections.
pub const RECEIVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
/// Overall bound on flushing buffered batches before the exit report.
pub const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);
/// Interval of the cumulative-count summary log line.
pub const SUMMARY_INTERVAL: Duration = Duration::from_secs(30);
/// `Retry-After` value sent with a 503 back-pressure response.
pub const RETRY_AFTER_SECS: u64 = 1;

/// Point-in-time copy of the relay counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterSnapshot {
    /// Batches delivered to the collector.
    pub exported: u64,
    /// Export requests refused with 503 because the buffer was full.
    pub rejected: u64,
    /// Export attempts that failed, timed out, or were discarded at exit.
    pub export_failures: u64,
}

/// Cumulative relay counters shared by the receiver, exporter, and summary
/// task. Counts are monotonic for the supervisor's lifetime.
#[derive(Debug, Default)]
pub struct RelayCounters {
    accepted: AtomicU64,
    exported: AtomicU64,
    rejected: AtomicU64,
    export_failures: AtomicU64,
    first_rejection_logged: AtomicBool,
    first_failure_logged: AtomicBool,
    final_summary_logged: AtomicBool,
}

impl RelayCounters {
    /// Records one batch accepted into the buffer.
    pub fn record_accepted(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one export request refused with 503 because the buffer was
    /// full. Warns on the first occurrence only.
    pub fn record_rejection(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
        if !self.first_rejection_logged.swap(true, Ordering::Relaxed) {
            warn!(
                buffer_capacity = BUFFER_CAPACITY,
                "OTLP relay rejected an agent export: buffer full"
            );
        }
    }

    /// Records one export attempt that failed or timed out. Warns on the
    /// first occurrence only.
    pub fn record_export_failure(&self, endpoint: &str, error: &dyn std::fmt::Display) {
        self.export_failures.fetch_add(1, Ordering::Relaxed);
        if !self.first_failure_logged.swap(true, Ordering::Relaxed) {
            warn!(endpoint, %error, "OTLP relay export to collector failed");
        }
    }

    /// Records one batch delivered to the collector.
    pub fn record_export_success(&self) {
        self.exported.fetch_add(1, Ordering::Relaxed);
    }

    /// Current counts.
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            exported: self.exported.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            export_failures: self.export_failures.load(Ordering::Relaxed),
        }
    }

    /// Accepted batches not yet exported or failed: buffered plus in flight.
    fn pending(&self) -> u64 {
        let CounterSnapshot {
            exported,
            export_failures,
            ..
        } = self.snapshot();
        self.accepted
            .load(Ordering::Relaxed)
            .saturating_sub(exported)
            .saturating_sub(export_failures)
    }

    fn log_summary(&self) {
        let CounterSnapshot {
            exported,
            rejected,
            export_failures,
        } = self.snapshot();
        info!(exported, rejected, export_failures, "OTLP relay summary");
    }

    /// Logs the final summary once, and only when something was rejected or
    /// failed (FR-009). Called from `shutdown` and, for lifecycle paths that
    /// drop the relay without shutting it down, from `Drop`.
    fn log_final_summary(&self) {
        let CounterSnapshot {
            rejected,
            export_failures,
            ..
        } = self.snapshot();
        if (rejected > 0 || export_failures > 0)
            && !self.final_summary_logged.swap(true, Ordering::Relaxed)
        {
            self.log_summary();
        }
    }
}

/// Input to [`start`].
#[derive(Debug, Clone)]
pub struct OtlpRelayConfig {
    /// OTLP/gRPC collector URI (`OPENSHELL_OTLP_ENDPOINT`).
    pub endpoint: String,
    /// Sandbox identifier attached to every forwarded resource.
    pub sandbox_id: String,
}

/// The relay could not be started; it stays inactive.
#[derive(Debug)]
pub enum StartError {
    /// The collector endpoint is not a URI tonic accepts.
    InvalidEndpoint(tonic::transport::Error),
    /// The collector endpoint uses a scheme the relay does not speak. TLS to
    /// the collector is a tracked follow-up; the supervisor's own exporter
    /// rejects `https` the same way.
    UnsupportedScheme(String),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEndpoint(error) => write!(f, "invalid collector endpoint: {error}"),
            Self::UnsupportedScheme(scheme) => write!(
                f,
                "unsupported collector endpoint scheme {scheme:?}: the relay speaks plaintext OTLP/gRPC (http) only"
            ),
        }
    }
}

impl std::error::Error for StartError {}

/// A running relay. Owned by the supervisor lifecycle; dropping it aborts
/// the background tasks and logs the final summary, [`OtlpRelay::shutdown`]
/// flushes first.
pub struct OtlpRelay {
    server: Arc<OtlpConnectionServer>,
    receiver: Option<ReceiverHandle>,
    export_task: JoinHandle<()>,
    summary_task: JoinHandle<()>,
    counters: Arc<RelayCounters>,
}

impl Drop for OtlpRelay {
    fn drop(&mut self) {
        self.export_task.abort();
        self.summary_task.abort();
        self.counters.log_final_summary();
    }
}

/// Serves staged workload connections to the relay address with the OTLP
/// connection server.
struct RelayHandler(Arc<OtlpConnectionServer>);

impl ReservedStreamHandler for RelayHandler {
    fn serve(&self, stream: BoundaryDuplexStream) -> Option<ReservedStreamFuture> {
        // Reserve before the proxy answers `RelayReady`, so an exhausted or
        // stopped server refuses the open instead of resetting it later.
        let permit = self.0.try_reserve()?;
        let server = Arc::clone(&self.0);
        Some(Box::pin(async move { server.serve(permit, stream).await }))
    }
}

fn relay_addr() -> SocketAddr {
    openshell_core::sandbox_env::OTLP_RELAY_ADDR
        .parse()
        .expect("OTLP_RELAY_ADDR is a valid socket address")
}

/// Starts the relay for `config`. Must be called inside a tokio runtime.
///
/// Returns the relay handle and the reserved destination to install in the
/// network proxy. Fails only when the endpoint is not a valid plaintext URI;
/// an unreachable collector is handled lazily by the exporter.
pub fn start(config: OtlpRelayConfig) -> Result<(OtlpRelay, ReservedDestination), StartError> {
    if let Ok(uri) = config.endpoint.parse::<http::Uri>()
        && let Some(scheme) = uri.scheme_str()
        && !scheme.eq_ignore_ascii_case("http")
    {
        return Err(StartError::UnsupportedScheme(scheme.to_string()));
    }
    let exporter = Exporter::new(&config.endpoint).map_err(StartError::InvalidEndpoint)?;
    if config.sandbox_id.len() > enrichment::MAX_SANDBOX_ID_BYTES {
        // The attribution growth bound assumes a shorter id; batches near
        // the wire limit with many entries will be refused with 413.
        warn!(
            sandbox_id_bytes = config.sandbox_id.len(),
            max = enrichment::MAX_SANDBOX_ID_BYTES,
            "OTLP relay: sandbox id exceeds the attribution budget; large multi-resource batches will be refused"
        );
    }
    let (relay, reserved) = assemble(exporter, config.sandbox_id, None);
    ocsf_emit!(
        ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .state(StateId::Enabled, "enabled")
            .unmapped("endpoint", config.endpoint)
            .message("OTLP agent trace relay enabled")
            .build()
    );
    Ok((relay, reserved))
}

/// Decides whether the relay runs for this sandbox and records the outcome
/// as a configuration state change.
///
/// `None` endpoint: nothing is started and the proxy refuses the relay
/// address. `None` sandbox id: the same, because attribution is the point of
/// the relay and the supervisor's own spans carry no sandbox id either. An
/// endpoint that does not parse or uses an unsupported scheme leaves the
/// relay inactive the same way.
pub fn activate(
    endpoint: Option<String>,
    sandbox_id: Option<String>,
) -> (Option<OtlpRelay>, Option<ReservedDestination>) {
    let Some(endpoint) = endpoint else {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Disabled, "disabled")
                .message("OTLP agent trace relay inactive: no collector endpoint configured")
                .build()
        );
        return (None, None);
    };
    let Some(sandbox_id) = sandbox_id else {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(SeverityId::Low)
                .status(StatusId::Success)
                .state(StateId::Disabled, "disabled")
                .unmapped("endpoint", endpoint)
                .message("OTLP agent trace relay inactive: no sandbox id to attribute traces to")
                .build()
        );
        return (None, None);
    };
    match start(OtlpRelayConfig {
        endpoint: endpoint.clone(),
        sandbox_id,
    }) {
        Ok((relay, reserved)) => (Some(relay), Some(reserved)),
        Err(error) => {
            ocsf_emit!(
                ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(SeverityId::Medium)
                    .status(StatusId::Failure)
                    .state(StateId::Disabled, "disabled")
                    .unmapped("endpoint", endpoint)
                    .unmapped("error", error.to_string())
                    .message("OTLP agent trace relay inactive: collector endpoint rejected")
                    .build()
            );
            (None, None)
        }
    }
}

/// Builds the relay around a prepared exporter. `export_gate`, when given,
/// holds the export task until it reads `true`; tests use it to keep batches
/// buffered.
fn assemble(
    exporter: Exporter,
    sandbox_id: String,
    export_gate: Option<watch::Receiver<bool>>,
) -> (OtlpRelay, ReservedDestination) {
    let counters = Arc::new(RelayCounters::default());
    let (buffer_tx, mut buffer_rx) = new_buffer(BUFFER_CAPACITY);
    let (server, receiver) =
        OtlpConnectionServer::new(buffer_tx, sandbox_id, Arc::clone(&counters));

    let export_task = tokio::spawn({
        let counters = Arc::clone(&counters);
        async move {
            if let Some(mut gate) = export_gate {
                let _ = gate.wait_for(|open| *open).await;
            }
            while let Some(batch) = buffer_rx.recv().await {
                match exporter.export(batch).await {
                    Ok(()) => counters.record_export_success(),
                    Err(error) => counters.record_export_failure(exporter.endpoint(), &error),
                }
            }
        }
    });
    let summary_task = tokio::spawn(summary_loop(Arc::clone(&counters)));

    let reserved = ReservedDestination {
        addr: relay_addr(),
        handler: Arc::new(RelayHandler(Arc::clone(&server))),
    };
    let relay = OtlpRelay {
        server,
        receiver: Some(receiver),
        export_task,
        summary_task,
        counters,
    };
    (relay, reserved)
}

/// Logs the cumulative counts every [`SUMMARY_INTERVAL`], but only while the
/// rejected or failed counts keep changing.
async fn summary_loop(counters: Arc<RelayCounters>) {
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + SUMMARY_INTERVAL,
        SUMMARY_INTERVAL,
    );
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_reported = (0, 0);
    loop {
        interval.tick().await;
        let CounterSnapshot {
            rejected,
            export_failures,
            ..
        } = counters.snapshot();
        if (rejected, export_failures) != last_reported {
            last_reported = (rejected, export_failures);
            counters.log_summary();
        }
    }
}

fn elapsed_ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

impl OtlpRelay {
    /// Waits up to `bound` for every buffered batch to reach the collector
    /// while the relay keeps serving. Used before the exit report when the
    /// supervisor stays up for exec sessions afterwards, so their traces
    /// are still relayed; [`Self::shutdown`] runs at final teardown.
    pub async fn flush(&self, bound: Duration) {
        let started = Instant::now();
        let exported_before = self.counters.snapshot().exported;
        while self.counters.pending() > 0 && started.elapsed() < bound {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let pending = self.counters.pending();
        if pending == 0 {
            info!(
                flushed = self.counters.snapshot().exported - exported_before,
                elapsed_ms = elapsed_ms(started),
                "OTLP relay flushed before exit"
            );
        } else {
            warn!(
                pending,
                "OTLP relay flush deadline exceeded; batches stay buffered while the access plane is retained"
            );
        }
    }

    /// Stops accepting agent connections, flushes buffered batches to the
    /// collector for at most `flush_bound`, and logs the final summary.
    /// Never fails; batches still pending at the deadline are discarded and
    /// counted as export failures.
    pub async fn shutdown(mut self, flush_bound: Duration) {
        let started = Instant::now();
        let exported_before = self.counters.snapshot().exported;

        self.server.stop_accepting();
        if let Some(receiver) = self.receiver.take() {
            receiver.shutdown().await;
        }
        self.server.close_buffer();

        let remaining = flush_bound.saturating_sub(started.elapsed());
        match tokio::time::timeout(remaining, &mut self.export_task).await {
            Ok(Ok(())) => {
                info!(
                    flushed = self.counters.snapshot().exported - exported_before,
                    elapsed_ms = elapsed_ms(started),
                    "OTLP relay flushed before exit"
                );
            }
            Ok(Err(join_error)) => {
                let discarded = self.counters.pending();
                self.counters
                    .export_failures
                    .fetch_add(discarded, Ordering::Relaxed);
                warn!(
                    %join_error,
                    discarded,
                    "OTLP relay export task ended abnormally; buffered batches were not flushed"
                );
            }
            Err(_) => {
                // Let the cancellation land before reading the counters, so
                // an export that completed in the meantime is not counted as
                // discarded.
                self.export_task.abort();
                let _ = (&mut self.export_task).await;
                let discarded = self.counters.pending();
                self.counters
                    .export_failures
                    .fetch_add(discarded, Ordering::Relaxed);
                warn!(
                    discarded,
                    "OTLP relay flush deadline exceeded; discarding buffered batches"
                );
            }
        }
        self.summary_task.abort();
        self.counters.log_final_summary();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard};
    use std::time::Duration;

    use openshell_otel_test_support::OtlpTestServer;
    use tokio::io::AsyncWriteExt as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::enrichment::test_util::{encoded_request, encoded_request_with_large_span};
    use super::enrichment::{SANDBOX_ID_KEY, SOURCE_KEY, SOURCE_VALUE};
    use super::exporter::test_util::SilentCollector;
    use super::receiver::test_util::{connect, read_head, request, send};
    use super::*;

    const PROTOBUF: &str = "application/x-protobuf";

    /// Serialises the tests that install a log capture, so concurrent
    /// dispatcher registration on other test threads cannot race the
    /// callsite interest of the events under test.
    static LOG_CAPTURE_LOCK: Mutex<()> = Mutex::new(());

    /// One captured event: level, message, and its integer fields.
    #[derive(Clone, Debug)]
    struct CapturedEvent {
        level: tracing::Level,
        message: String,
        fields: Vec<(String, u64)>,
    }

    /// Captures events for the duration of a test. Works for events emitted
    /// on the test thread, which on a current-thread runtime includes every
    /// spawned task.
    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<CapturedEvent>>>);

    /// Keeps the capture installed and the serialisation lock held.
    struct CaptureGuard {
        _lock: MutexGuard<'static, ()>,
        _default: tracing::subscriber::DefaultGuard,
    }

    impl LogCapture {
        fn install(&self) -> CaptureGuard {
            let lock = LOG_CAPTURE_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let default =
                tracing::subscriber::set_default(tracing_subscriber::registry().with(self.clone()));
            CaptureGuard {
                _lock: lock,
                _default: default,
            }
        }

        fn count(&self, level: tracing::Level, message: &str) -> usize {
            self.events(level, message).len()
        }

        fn events(&self, level: tracing::Level, message: &str) -> Vec<CapturedEvent> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|event| event.level == level && event.message == message)
                .cloned()
                .collect()
        }

        /// Events at INFO or above, regardless of message.
        fn info_and_above(&self) -> usize {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|event| event.level <= tracing::Level::INFO)
                .count()
        }
    }

    impl CapturedEvent {
        fn field(&self, name: &str) -> Option<u64> {
            self.fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| *value)
        }
    }

    #[derive(Default)]
    struct EventVisitor {
        message: Option<String>,
        fields: Vec<(String, u64)>,
    }

    impl tracing::field::Visit for EventVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.message = Some(format!("{value:?}"));
            }
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.fields.push((field.name().to_string(), value));
        }

        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            if let Ok(value) = u64::try_from(value) {
                self.fields.push((field.name().to_string(), value));
            }
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = EventVisitor::default();
            event.record(&mut visitor);
            if let Some(message) = visitor.message {
                self.0.lock().unwrap().push(CapturedEvent {
                    level: *event.metadata().level(),
                    message,
                    fields: visitor.fields,
                });
            }
        }
    }

    fn gated(endpoint: &str) -> (OtlpRelay, ReservedDestination, watch::Sender<bool>) {
        let (gate_tx, gate_rx) = watch::channel(false);
        let exporter = Exporter::new(endpoint).unwrap();
        let (relay, reserved) = assemble(exporter, "sb-test".into(), Some(gate_rx));
        (relay, reserved, gate_tx)
    }

    async fn post(relay: &OtlpRelay, span: &str) -> u16 {
        let mut client = connect(&relay.server);
        let body = encoded_request(span, &[("service.name", "unit-agent")]);
        send(&mut client, &request("POST", "/v1/traces", PROTOBUF, &body))
            .await
            .status
    }

    async fn wait_until(deadline: Duration, mut condition: impl FnMut() -> bool) {
        let started = Instant::now();
        while !condition() {
            assert!(started.elapsed() < deadline, "condition not met in time");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn http_post_over_duplex_reaches_collector() {
        let collector = OtlpTestServer::start().await;
        let (relay, reserved) = start(OtlpRelayConfig {
            endpoint: collector.endpoint().to_string(),
            sandbox_id: "sb-test".into(),
        })
        .unwrap();
        assert_eq!(
            reserved.addr.to_string(),
            openshell_core::sandbox_env::OTLP_RELAY_ADDR
        );

        let (mut client, boundary) = tokio::io::duplex(64 * 1024);
        let served = reserved
            .handler
            .serve(Box::new(boundary))
            .expect("a fresh relay accepts a stream");
        tokio::spawn(served);

        let body = encoded_request(
            "unit-span",
            &[
                ("service.name", "unit-agent"),
                (SANDBOX_ID_KEY, "evil"),
                (SOURCE_KEY, "infrastructure"),
            ],
        );
        client
            .write_all(&request("POST", "/v1/traces", PROTOBUF, &body))
            .await
            .unwrap();
        assert_eq!(read_head(&mut client).await.status, 200);

        collector.wait_for_export().await;
        let received = collector.shutdown().await;
        assert!(received.spans.iter().any(|span| span.name == "unit-span"));
        // The collector keeps the last value per key, so a retained spoofed
        // attribute would only show up as a duplicate: assert both.
        assert!(
            received.duplicate_resource_keys.is_empty(),
            "spoofed attribution keys were appended to, not replaced: {:?}",
            received.duplicate_resource_keys
        );
        let attributes = &received.resource_attributes[0];
        assert_eq!(attributes.len(), 3);
        assert_eq!(
            attributes.get("service.name").map(String::as_str),
            Some("unit-agent")
        );
        assert_eq!(
            attributes.get(SOURCE_KEY).map(String::as_str),
            Some(SOURCE_VALUE)
        );
        assert_eq!(
            attributes.get(SANDBOX_ID_KEY).map(String::as_str),
            Some("sb-test")
        );
        assert!(
            !attributes
                .values()
                .any(|value| value == "evil" || value == "infrastructure")
        );
        drop(relay);
    }

    #[tokio::test]
    async fn invalid_endpoint_leaves_relay_inactive() {
        let before = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        let error = start(OtlpRelayConfig {
            endpoint: "not a uri".into(),
            sandbox_id: "sb-test".into(),
        })
        .err()
        .expect("unparsable endpoint fails");
        assert!(matches!(error, StartError::InvalidEndpoint(_)), "{error}");
        let after = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        assert_eq!(before, after, "nothing is spawned for an inactive relay");
    }

    #[tokio::test]
    async fn activate_without_endpoint_starts_nothing() {
        let before = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        let (relay, reserved) = activate(None, Some("sb-test".into()));
        assert!(relay.is_none());
        assert!(reserved.is_none());
        let after = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        assert_eq!(before, after);
    }

    #[tokio::test]
    async fn activate_without_sandbox_id_starts_nothing() {
        // Attribution is the point of the relay; without an id the supervisor's
        // own spans carry none either, so the relay stays inactive instead of
        // stamping every batch with an empty id.
        let collector = OtlpTestServer::start().await;
        let before = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        let (relay, reserved) = activate(Some(collector.endpoint().to_string()), None);
        assert!(relay.is_none());
        assert!(reserved.is_none());
        let after = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        assert_eq!(before, after);
        drop(collector.shutdown().await);
    }

    #[test]
    fn https_endpoint_is_refused_at_start() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _enter = runtime.enter();
        let error = start(OtlpRelayConfig {
            endpoint: "https://collector.example:4317".into(),
            sandbox_id: "sb-test".into(),
        })
        .err()
        .expect("https is not supported on the relay hop");
        assert!(
            matches!(error, StartError::UnsupportedScheme(ref scheme) if scheme == "https"),
            "{error}"
        );
        // Lower-case comparison, and plain http still starts.
        assert!(
            start(OtlpRelayConfig {
                endpoint: "HTTP://collector.example:4317".into(),
                sandbox_id: "sb-test".into(),
            })
            .is_ok()
        );
    }

    #[tokio::test]
    async fn flush_waits_for_pending_batches_and_keeps_the_relay_serving() {
        let collector = OtlpTestServer::start().await;
        let (relay, _reserved, gate) = gated(collector.endpoint());
        for span in ["one", "two"] {
            assert_eq!(post(&relay, span).await, 200);
        }
        assert_eq!(relay.counters.pending(), 2);

        gate.send_replace(true);
        let started = Instant::now();
        relay.flush(FLUSH_TIMEOUT).await;
        assert!(started.elapsed() < FLUSH_TIMEOUT);
        assert_eq!(relay.counters.pending(), 0);

        // Unlike shutdown, the relay still serves exec sessions afterwards.
        assert_eq!(post(&relay, "after-flush").await, 200);
        collector.wait_for_export().await;
        relay.shutdown(FLUSH_TIMEOUT).await;
        let received = collector.shutdown().await;
        assert!(received.spans.iter().any(|span| span.name == "after-flush"));
    }

    #[tokio::test]
    async fn dropping_the_relay_without_shutdown_logs_the_final_summary_once() {
        let logs = LogCapture::default();
        let _guard = logs.install();
        let collector = OtlpTestServer::start().await;
        let (relay, _reserved, _gate) = gated(collector.endpoint());
        relay.counters.record_rejection();
        // An early-exit lifecycle path drops the relay without `shutdown`.
        drop(relay);
        assert_eq!(logs.count(tracing::Level::INFO, "OTLP relay summary"), 1);
        drop(collector.shutdown().await);
    }

    #[tokio::test]
    async fn first_rejection_warns_once() {
        let logs = LogCapture::default();
        let _guard = logs.install();
        let counters = RelayCounters::default();
        for _ in 0..10 {
            counters.record_rejection();
        }
        assert_eq!(
            logs.count(
                tracing::Level::WARN,
                "OTLP relay rejected an agent export: buffer full"
            ),
            1
        );
        assert_eq!(counters.snapshot().rejected, 10);
    }

    #[tokio::test]
    async fn first_export_failure_warns_once() {
        let logs = LogCapture::default();
        let _guard = logs.install();
        let counters = RelayCounters::default();
        for _ in 0..3 {
            counters.record_export_failure("http://collector:4317", &"boom");
        }
        assert_eq!(
            logs.count(
                tracing::Level::WARN,
                "OTLP relay export to collector failed"
            ),
            1
        );
        assert_eq!(counters.snapshot().export_failures, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn summary_is_logged_only_while_counts_change() {
        let logs = LogCapture::default();
        let _guard = logs.install();
        let counters = Arc::new(RelayCounters::default());
        let summary = tokio::spawn(summary_loop(Arc::clone(&counters)));

        let summaries = || logs.count(tracing::Level::INFO, "OTLP relay summary");
        tokio::time::advance(SUMMARY_INTERVAL + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(summaries(), 0, "no summary while nothing was rejected");

        counters.record_rejection();
        tokio::time::advance(SUMMARY_INTERVAL).await;
        tokio::task::yield_now().await;
        assert_eq!(summaries(), 1);
        let first = &logs.events(tracing::Level::INFO, "OTLP relay summary")[0];
        assert_eq!(first.field("rejected"), Some(1));
        assert_eq!(first.field("export_failures"), Some(0));

        tokio::time::advance(SUMMARY_INTERVAL).await;
        tokio::task::yield_now().await;
        assert_eq!(summaries(), 1, "unchanged counts emit no summary");

        counters.record_export_failure("http://collector:4317", &"boom");
        tokio::time::advance(SUMMARY_INTERVAL).await;
        tokio::task::yield_now().await;
        assert_eq!(summaries(), 2);
        // Counts are cumulative, not per interval.
        let second = &logs.events(tracing::Level::INFO, "OTLP relay summary")[1];
        assert_eq!(second.field("rejected"), Some(1));
        assert_eq!(second.field("export_failures"), Some(1));
        summary.abort();
    }

    #[tokio::test]
    async fn failed_export_does_not_stop_the_relay() {
        // A freed ephemeral port can be taken by a parallel test before the
        // collector binds it, so try a few candidates.
        for attempt in 0..5 {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            drop(listener);
            let (relay, reserved, gate) = gated(&format!("http://{addr}"));
            gate.send_replace(true);

            assert_eq!(post(&relay, "lost").await, 200);
            wait_until(Duration::from_secs(10), || {
                relay.counters.snapshot().export_failures == 1
            })
            .await;

            let Ok(collector) = OtlpTestServer::try_start_on(addr).await else {
                eprintln!("port {addr} was taken meanwhile, retrying ({attempt})");
                drop(reserved);
                continue;
            };
            assert_eq!(post(&relay, "delivered").await, 200);
            collector.wait_for_export().await;
            let received = collector.shutdown().await;
            assert!(received.spans.iter().any(|span| span.name == "delivered"));
            assert_eq!(relay.counters.snapshot().exported, 1);
            drop(reserved);
            return;
        }
        panic!("could not rebind a freed port in five attempts");
    }

    #[tokio::test]
    async fn buffer_never_exceeds_capacity_under_flood() {
        // The gate stays closed: nothing drains the buffer, which is the
        // worst case of a collector that never answers.
        let logs = LogCapture::default();
        let _guard = logs.install();
        let collector = SilentCollector::start().await;
        let (relay, _reserved, _gate) = gated(&collector.endpoint);

        // A 1 MiB span attribute: large on the wire, small resource.
        let body = encoded_request_with_large_span("flood", 1024 * 1024);
        let req = Arc::new(request("POST", "/v1/traces", PROTOBUF, &body));
        let mut clients = Vec::new();
        for _ in 0..MAX_CONCURRENT_CONNECTIONS {
            clients.push(connect(&relay.server));
        }
        assert!(relay.server.try_reserve().is_none(), "cap reached");

        let mut accepted = 0;
        let mut rejected = 0;
        for i in 0..200 {
            let client = &mut clients[i % MAX_CONCURRENT_CONNECTIONS];
            let head = send(client, &req).await;
            match head.status {
                200 => accepted += 1,
                503 => rejected += 1,
                other => panic!("unexpected status {other}"),
            }
        }
        assert_eq!(
            accepted, BUFFER_CAPACITY,
            "accepted {accepted}: exactly the buffer capacity"
        );
        assert_eq!(accepted + rejected, 200);
        assert_eq!(relay.counters.snapshot().rejected, rejected as u64);
        // FR-009: one warning for the first rejection, nothing per request.
        assert_eq!(
            logs.count(
                tracing::Level::WARN,
                "OTLP relay rejected an agent export: buffer full"
            ),
            1
        );
        assert!(
            logs.info_and_above() < 5,
            "relay log lines must not scale with rejections: {}",
            logs.info_and_above()
        );
        drop(relay);
    }

    #[tokio::test]
    async fn shutdown_flushes_buffered_batches() {
        let logs = LogCapture::default();
        let _guard = logs.install();
        let collector = OtlpTestServer::start().await;
        let (relay, _reserved, gate) = gated(collector.endpoint());

        for span in ["one", "two", "three"] {
            assert_eq!(post(&relay, span).await, 200);
        }
        assert_eq!(relay.counters.pending(), 3);

        gate.send_replace(true);
        let started = Instant::now();
        relay.shutdown(FLUSH_TIMEOUT).await;
        assert!(started.elapsed() < FLUSH_TIMEOUT);

        let received = collector.shutdown().await;
        let names: Vec<&str> = received
            .spans
            .iter()
            .map(|span| span.name.as_str())
            .collect();
        for span in ["one", "two", "three"] {
            assert!(names.contains(&span), "missing {span} in {names:?}");
        }
        assert_eq!(
            logs.count(tracing::Level::INFO, "OTLP relay flushed before exit"),
            1
        );
        assert_eq!(
            logs.count(tracing::Level::INFO, "OTLP relay summary"),
            0,
            "no final summary when nothing was rejected or failed"
        );
    }

    #[tokio::test]
    async fn shutdown_with_unreachable_collector_returns_within_bound() {
        let logs = LogCapture::default();
        let _guard = logs.install();
        let collector = SilentCollector::start().await;
        let (relay, _reserved, gate) = gated(&collector.endpoint);
        for span in ["one", "two"] {
            assert_eq!(post(&relay, span).await, 200);
        }
        let counters = Arc::clone(&relay.counters);

        gate.send_replace(true);
        let started = Instant::now();
        relay.shutdown(FLUSH_TIMEOUT).await;
        assert!(
            started.elapsed() < FLUSH_TIMEOUT + Duration::from_secs(1),
            "shutdown took {:?}",
            started.elapsed()
        );
        assert_eq!(
            logs.count(
                tracing::Level::WARN,
                "OTLP relay flush deadline exceeded; discarding buffered batches"
            ),
            1
        );
        assert_eq!(
            counters.snapshot().export_failures,
            2,
            "both batches count as failures"
        );
        let summaries = logs.events(tracing::Level::INFO, "OTLP relay summary");
        assert_eq!(
            summaries.len(),
            1,
            "final summary when failures are non-zero"
        );
        assert_eq!(summaries[0].field("export_failures"), Some(2));
        assert_eq!(summaries[0].field("rejected"), Some(0));
    }

    #[tokio::test]
    async fn shutdown_logs_final_summary_when_counters_nonzero() {
        let logs = LogCapture::default();
        let _guard = logs.install();
        let collector = OtlpTestServer::start().await;
        let (relay, _reserved, gate) = gated(collector.endpoint());
        relay.counters.record_rejection();
        gate.send_replace(true);
        relay.shutdown(FLUSH_TIMEOUT).await;
        assert_eq!(logs.count(tracing::Level::INFO, "OTLP relay summary"), 1);
        drop(collector.shutdown().await);
    }

    #[tokio::test]
    async fn handler_refuses_streams_once_shutdown_started() {
        let collector = OtlpTestServer::start().await;
        let (relay, reserved, gate) = gated(collector.endpoint());
        gate.send_replace(true);
        relay.shutdown(FLUSH_TIMEOUT).await;
        let (_client, boundary) = tokio::io::duplex(1024);
        assert!(
            reserved.handler.serve(Box::new(boundary)).is_none(),
            "the proxy must refuse the open rather than reset it after RelayReady"
        );
        drop(collector.shutdown().await);
    }
}
