// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway capacity and HA metrics.
//!
//! The metric names are an operator-facing contract, documented in
//! docs/observability/gateway-metrics.mdx. Labels are bounded enums only: never a sandbox,
//! channel, endpoint, token, or replica id. The scrape target already identifies the replica.
//!
//! Metric handles bind to whichever recorder is current when a macro runs. `run_server`
//! installs the Prometheus recorder after it builds `ServerState`, so never cache a handle in a
//! static or in state built before [`install_global_recorder`]. [`GaugeSlot`] acquires its
//! handle when the tracked object is created and releases it through the same handle, so a
//! slot can never drive a series negative.

use std::time::{Duration, Instant};

use metrics::{
    Gauge, Unit, counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram,
};
use metrics_exporter_prometheus::{BuildError, Matcher, PrometheusBuilder, PrometheusHandle};
use tonic::{Code, Status};

// Gauges
pub const SUPERVISOR_SESSIONS: &str = "openshell_server_supervisor_sessions";
pub const DRAINING: &str = "openshell_server_draining";
pub const RELAY_PENDING: &str = "openshell_server_relay_pending";
pub const RELAY_PENDING_CAPACITY: &str = "openshell_server_relay_pending_capacity";
pub const RELAY_PENDING_PER_SANDBOX_CAPACITY: &str =
    "openshell_server_relay_pending_per_sandbox_capacity";
pub const SANDBOX_WATCH_POLLED_SANDBOXES: &str = "openshell_server_sandbox_watch_polled_sandboxes";
// Counters
pub const RELAY_REJECTED_TOTAL: &str = "openshell_server_relay_rejected_total";
pub const RELAY_EXPIRED_TOTAL: &str = "openshell_server_relay_expired_total";
pub const PEER_REQUESTS_TOTAL: &str = "openshell_server_peer_requests_total";
pub const MUTATION_LOCK_TIMEOUTS_TOTAL: &str = "openshell_server_mutation_lock_timeouts_total";
pub const SANDBOX_WATCH_POLL_ERRORS_TOTAL: &str =
    "openshell_server_sandbox_watch_poll_errors_total";
// Histograms (explicit buckets, see BUCKETED_HISTOGRAMS)
pub const RELAY_CLAIM_DURATION_SECONDS: &str = "openshell_server_relay_claim_duration_seconds";
pub const PEER_REQUEST_DURATION_SECONDS: &str = "openshell_server_peer_request_duration_seconds";
pub const MUTATION_LOCK_WAIT_SECONDS: &str = "openshell_server_mutation_lock_wait_seconds";
pub const SANDBOX_WATCH_POLL_DURATION_SECONDS: &str =
    "openshell_server_sandbox_watch_poll_duration_seconds";

const LABEL_REASON: &str = "reason";
const LABEL_RPC: &str = "rpc";
const LABEL_OUTCOME: &str = "outcome";
const LABEL_CODE: &str = "code";
const LABEL_SCOPE: &str = "scope";

/// Buckets for the new latency histograms, 1 ms to 15 s. The top buckets cover the 10 s relay
/// claim and lock timeouts and the 15 s routed-relay wait.
const LATENCY_BUCKETS_SECONDS: [f64; 14] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0,
];

/// Only these names render as Prometheus histograms. Every existing `*_duration_seconds` metric
/// keeps its summary format, so current dashboards are unaffected.
const BUCKETED_HISTOGRAMS: [&str; 4] = [
    RELAY_CLAIM_DURATION_SECONDS,
    PEER_REQUEST_DURATION_SECONDS,
    MUTATION_LOCK_WAIT_SECONDS,
    SANDBOX_WATCH_POLL_DURATION_SECONDS,
];

/// Which pending-relay cap rejected an open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayRejection {
    GlobalCapacity,
    SandboxCapacity,
}

impl RelayRejection {
    pub const ALL: [Self; 2] = [Self::GlobalCapacity, Self::SandboxCapacity];

    pub const fn label(self) -> &'static str {
        match self {
            Self::GlobalCapacity => "global_capacity",
            Self::SandboxCapacity => "sandbox_capacity",
        }
    }
}

/// Outbound peer RPC. Labels match the existing `method` label of
/// `openshell_server_grpc_requests_total` on the owning replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRpc {
    Relay,
    ReportProviderReadiness,
    ReportEndpointStatus,
    GetSandboxProviderStatus,
}

impl PeerRpc {
    pub const ALL: [Self; 4] = [
        Self::Relay,
        Self::ReportProviderReadiness,
        Self::ReportEndpointStatus,
        Self::GetSandboxProviderStatus,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Relay => "PeerRelay",
            Self::ReportProviderReadiness => "PeerReportProviderReadiness",
            Self::ReportEndpointStatus => "PeerReportEndpointStatus",
            Self::GetSandboxProviderStatus => "PeerGetSandboxProviderStatus",
        }
    }
}

/// Mutation lock scope kind. The platform scope ("" workspace) maps to `Global`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockScope {
    Global,
    Workspace,
    Sandbox,
}

impl LockScope {
    pub const ALL: [Self; 3] = [Self::Global, Self::Workspace, Self::Sandbox];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Workspace => "workspace",
            Self::Sandbox => "sandbox",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerOutcome {
    Ok,
    ClientError,
    RpcError,
}

impl PeerOutcome {
    const fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::ClientError => "client_error",
            Self::RpcError => "rpc_error",
        }
    }
}

/// Snake-case gRPC status name for the `code` label. Exhaustive on purpose, so a new tonic
/// variant fails to compile instead of producing an unbounded label.
const fn grpc_code_label(code: Code) -> &'static str {
    match code {
        Code::Ok => "ok",
        Code::Cancelled => "cancelled",
        Code::Unknown => "unknown",
        Code::InvalidArgument => "invalid_argument",
        Code::DeadlineExceeded => "deadline_exceeded",
        Code::NotFound => "not_found",
        Code::AlreadyExists => "already_exists",
        Code::PermissionDenied => "permission_denied",
        Code::ResourceExhausted => "resource_exhausted",
        Code::FailedPrecondition => "failed_precondition",
        Code::Aborted => "aborted",
        Code::OutOfRange => "out_of_range",
        Code::Unimplemented => "unimplemented",
        Code::Internal => "internal",
        Code::Unavailable => "unavailable",
        Code::DataLoss => "data_loss",
        Code::Unauthenticated => "unauthenticated",
    }
}

/// Relay caps published as `openshell_server_relay_pending_capacity` and
/// `openshell_server_relay_pending_per_sandbox_capacity`. The caller passes the values that
/// enforce the caps, so this module does not depend on the relay registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayCapacity {
    /// Pending relays allowed on one replica.
    pub global: usize,
    /// Pending relays allowed for one sandbox on one replica.
    pub per_sandbox: usize,
}

/// Apply the bucket overrides. Tests build local recorders from the same builder.
pub fn configure_exporter(builder: PrometheusBuilder) -> Result<PrometheusBuilder, BuildError> {
    BUCKETED_HISTOGRAMS
        .iter()
        .try_fold(builder, |builder, name| {
            builder.set_buckets_for_metric(
                Matcher::Full((*name).to_string()),
                &LATENCY_BUCKETS_SECONDS,
            )
        })
}

/// Install the process-wide recorder, then describe and zero-initialize the catalog. Call
/// once, from `run_server`.
pub fn install_global_recorder(relay: RelayCapacity) -> Result<PrometheusHandle, BuildError> {
    let handle = configure_exporter(PrometheusBuilder::new())?.install_recorder()?;
    describe_and_initialize(relay);
    Ok(handle)
}

/// Emit HELP metadata, create every fixed-label series at 0, and publish the relay caps. An
/// idle replica then exports 0 instead of "no data", which HPA and `rate()` need.
pub fn describe_and_initialize(relay: RelayCapacity) {
    describe_gauge!(
        SUPERVISOR_SESSIONS,
        Unit::Count,
        "Supervisor control sessions registered on this gateway replica."
    );
    describe_gauge!(
        DRAINING,
        "1 while this gateway replica is draining supervisor sessions before shutdown, otherwise 0."
    );
    describe_gauge!(
        RELAY_PENDING,
        Unit::Count,
        "Relay channels on this replica waiting for the supervisor to connect back, including channels opened for peer replicas."
    );
    describe_gauge!(
        RELAY_PENDING_CAPACITY,
        Unit::Count,
        "Maximum pending relay channels on one gateway replica."
    );
    describe_gauge!(
        RELAY_PENDING_PER_SANDBOX_CAPACITY,
        Unit::Count,
        "Maximum pending relay channels for one sandbox on one gateway replica."
    );
    describe_gauge!(
        SANDBOX_WATCH_POLLED_SANDBOXES,
        Unit::Count,
        "Sandboxes with a local WatchSandbox follower checked on the last watch-poller tick."
    );
    describe_counter!(
        RELAY_REJECTED_TOTAL,
        Unit::Count,
        "Relay opens rejected because a pending relay cap was reached."
    );
    describe_counter!(
        RELAY_EXPIRED_TOTAL,
        Unit::Count,
        "Pending relay channels dropped because the supervisor did not connect back in time."
    );
    describe_counter!(
        PEER_REQUESTS_TOTAL,
        Unit::Count,
        "Requests this replica sent to the replica that owns a sandbox's supervisor session."
    );
    describe_counter!(
        MUTATION_LOCK_TIMEOUTS_TOTAL,
        Unit::Count,
        "Mutation lock acquisitions that timed out."
    );
    describe_counter!(
        SANDBOX_WATCH_POLL_ERRORS_TOTAL,
        Unit::Count,
        "Watch-poller ticks whose version lookup failed."
    );
    describe_histogram!(
        RELAY_CLAIM_DURATION_SECONDS,
        Unit::Seconds,
        "Time from opening a relay channel to the supervisor claiming it."
    );
    describe_histogram!(
        PEER_REQUEST_DURATION_SECONDS,
        Unit::Seconds,
        "Latency of requests to the owning replica. For PeerRelay, until the owner's supervisor claimed the relay."
    );
    describe_histogram!(
        MUTATION_LOCK_WAIT_SECONDS,
        Unit::Seconds,
        "Time spent acquiring the mutation lock for a scope."
    );
    describe_histogram!(
        SANDBOX_WATCH_POLL_DURATION_SECONDS,
        Unit::Seconds,
        "Duration of the batched version lookup for one watch-poller tick."
    );

    // `increment(0)` registers a series without overwriting a value recorded earlier.
    gauge!(SUPERVISOR_SESSIONS).increment(0.0);
    gauge!(RELAY_PENDING).increment(0.0);
    gauge!(DRAINING).increment(0.0);
    gauge!(SANDBOX_WATCH_POLLED_SANDBOXES).increment(0.0);
    gauge!(RELAY_PENDING_CAPACITY).set(count_as_f64(relay.global));
    gauge!(RELAY_PENDING_PER_SANDBOX_CAPACITY).set(count_as_f64(relay.per_sandbox));
    for reason in RelayRejection::ALL {
        counter!(RELAY_REJECTED_TOTAL, LABEL_REASON => reason.label()).increment(0);
    }
    counter!(RELAY_EXPIRED_TOTAL).increment(0);
    for scope in LockScope::ALL {
        counter!(MUTATION_LOCK_TIMEOUTS_TOTAL, LABEL_SCOPE => scope.label()).increment(0);
    }
    counter!(SANDBOX_WATCH_POLL_ERRORS_TOTAL).increment(0);
    for rpc in PeerRpc::ALL {
        counter!(
            PEER_REQUESTS_TOTAL,
            LABEL_RPC => rpc.label(),
            LABEL_OUTCOME => PeerOutcome::Ok.label(),
            LABEL_CODE => grpc_code_label(Code::Ok)
        )
        .increment(0);
    }
}

/// Counts in this module stay far below 2^53, so the conversion is exact.
#[allow(clippy::cast_precision_loss)]
pub fn count_as_f64(count: usize) -> f64 {
    count as f64
}

/// One unit of an exact gauge, held for as long as the tracked object lives. Dropping it
/// decrements through the same handle it incremented, so every removal path is counted exactly
/// once, including paths added in the future.
#[must_use = "dropping a GaugeSlot immediately releases it"]
pub struct GaugeSlot(Gauge);

impl GaugeSlot {
    /// Share of `openshell_server_supervisor_sessions`.
    pub fn supervisor_session() -> Self {
        Self::acquire(SUPERVISOR_SESSIONS)
    }

    /// Share of `openshell_server_relay_pending`.
    pub fn relay_pending() -> Self {
        Self::acquire(RELAY_PENDING)
    }

    fn acquire(name: &'static str) -> Self {
        let gauge = gauge!(name);
        gauge.increment(1.0);
        Self(gauge)
    }
}

impl Drop for GaugeSlot {
    fn drop(&mut self) {
        self.0.decrement(1.0);
    }
}

/// Mark this replica as draining (`true`) for the rest of the process lifetime.
pub fn set_draining(draining: bool) {
    gauge!(DRAINING).set(if draining { 1.0 } else { 0.0 });
}

pub fn record_relay_rejected(reason: RelayRejection) {
    counter!(RELAY_REJECTED_TOTAL, LABEL_REASON => reason.label()).increment(1);
}

/// `count` pending relays were dropped unclaimed (late claim or reaper).
pub fn record_relay_expired(count: usize) {
    if count > 0 {
        counter!(RELAY_EXPIRED_TOTAL).increment(count as u64);
    }
}

pub fn record_relay_claimed(waited: Duration) {
    histogram!(RELAY_CLAIM_DURATION_SECONDS).record(waited);
}

/// Time to acquire every key of one mutation guard (local registry plus Postgres), recorded
/// on success only.
pub fn record_lock_wait(scope: LockScope, waited: Duration) {
    histogram!(MUTATION_LOCK_WAIT_SECONDS, LABEL_SCOPE => scope.label()).record(waited);
}

/// A guard acquisition that timed out (local wait or Postgres `lock_timeout` / SQLSTATE 55P03).
/// The caller maps it to `Status::unavailable`.
pub fn record_lock_timeout(scope: LockScope) {
    counter!(MUTATION_LOCK_TIMEOUTS_TOTAL, LABEL_SCOPE => scope.label()).increment(1);
}

/// Times one outbound peer request and records it exactly once. Dropping an unfinished timer
/// (the caller's future was cancelled) records `client_error` / `cancelled`.
#[must_use = "finish the timer with client_error() or finish()"]
pub struct PeerRequestTimer {
    rpc: PeerRpc,
    started: Instant,
    recorded: bool,
}

impl PeerRequestTimer {
    pub fn start(rpc: PeerRpc) -> Self {
        Self {
            rpc,
            started: Instant::now(),
            recorded: false,
        }
    }

    /// The request failed before it reached the peer: token, channel, headers, or stream setup.
    pub fn client_error(&mut self, status: &Status) {
        self.record(PeerOutcome::ClientError, status.code());
    }

    /// Record the raw tonic result of the RPC itself. Call this BEFORE any remap to
    /// `Unavailable`, so the owner's code (for example `resource_exhausted`) is kept.
    pub fn finish<T>(&mut self, result: &Result<T, Status>) {
        match result {
            Ok(_) => self.record(PeerOutcome::Ok, Code::Ok),
            Err(status) => self.record(PeerOutcome::RpcError, status.code()),
        }
    }

    fn record(&mut self, outcome: PeerOutcome, code: Code) {
        if self.recorded {
            return;
        }
        self.recorded = true;
        counter!(
            PEER_REQUESTS_TOTAL,
            LABEL_RPC => self.rpc.label(),
            LABEL_OUTCOME => outcome.label(),
            LABEL_CODE => grpc_code_label(code)
        )
        .increment(1);
        histogram!(
            PEER_REQUEST_DURATION_SECONDS,
            LABEL_RPC => self.rpc.label(),
            LABEL_OUTCOME => outcome.label()
        )
        .record(self.started.elapsed());
    }
}

impl Drop for PeerRequestTimer {
    fn drop(&mut self) {
        self.record(PeerOutcome::ClientError, Code::Cancelled);
    }
}

/// Captures metrics recorded on the current thread through a configured Prometheus recorder.
///
/// Works in `#[test]` and in the default current-thread `#[tokio::test]`, where tasks spawned on
/// the runtime share the thread. It does not work in `multi_thread` tests or inside
/// `spawn_blocking`. Never pass it into an `async fn` helper: it is `!Send`, and clippy
/// `future_not_send` (nursery) would fire.
#[cfg(test)]
pub struct MetricsCapture {
    handle: PrometheusHandle,
    _guard: metrics::LocalRecorderGuard<'static>,
}

#[cfg(test)]
impl MetricsCapture {
    pub fn install() -> Self {
        // Leaked (test only, one small allocation per test) so the guard can borrow it for 'static.
        let recorder: &'static metrics_exporter_prometheus::PrometheusRecorder =
            Box::leak(Box::new(
                configure_exporter(PrometheusBuilder::new())
                    .expect("valid exporter config")
                    .build_recorder(),
            ));
        let handle = recorder.handle();
        let guard = metrics::set_default_local_recorder(recorder);
        Self {
            handle,
            _guard: guard,
        }
    }

    pub fn render(&self) -> String {
        self.handle.render()
    }

    /// Integer value of one exact series, such as `name` or `name{a="b"}`. Parses as i64 to
    /// avoid clippy `float_cmp` and so a negative gauge is visible. `None` if the series is absent.
    pub fn value(&self, series: &str) -> Option<i64> {
        series_value(&self.handle, series)
    }

    /// Reads one series like [`Self::value`], from code that cannot hold `self`, such as a
    /// waker that runs while the value is being produced.
    pub fn value_reader(&self, series: &'static str) -> Box<dyn Fn() -> Option<i64> + Send + Sync> {
        let handle = self.handle.clone();
        Box::new(move || series_value(&handle, series))
    }
}

#[cfg(test)]
fn series_value(handle: &PrometheusHandle, series: &str) -> Option<i64> {
    handle
        .render()
        .lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn describe_and_initialize_exports_capacity_and_zero_series() {
        let metrics = MetricsCapture::install();
        describe_and_initialize(RelayCapacity {
            global: 256,
            per_sandbox: 32,
        });

        for (series, expected) in [
            ("openshell_server_relay_pending_capacity", 256),
            ("openshell_server_relay_pending_per_sandbox_capacity", 32),
            ("openshell_server_supervisor_sessions", 0),
            ("openshell_server_relay_pending", 0),
            ("openshell_server_draining", 0),
            ("openshell_server_sandbox_watch_polled_sandboxes", 0),
            (
                "openshell_server_relay_rejected_total{reason=\"global_capacity\"}",
                0,
            ),
            (
                "openshell_server_relay_rejected_total{reason=\"sandbox_capacity\"}",
                0,
            ),
            ("openshell_server_relay_expired_total", 0),
            (
                "openshell_server_mutation_lock_timeouts_total{scope=\"global\"}",
                0,
            ),
            (
                "openshell_server_mutation_lock_timeouts_total{scope=\"workspace\"}",
                0,
            ),
            (
                "openshell_server_mutation_lock_timeouts_total{scope=\"sandbox\"}",
                0,
            ),
            ("openshell_server_sandbox_watch_poll_errors_total", 0),
        ] {
            assert_eq!(metrics.value(series), Some(expected), "{series}");
        }
        for rpc in [
            "PeerRelay",
            "PeerReportProviderReadiness",
            "PeerReportEndpointStatus",
            "PeerGetSandboxProviderStatus",
        ] {
            let series = format!(
                "openshell_server_peer_requests_total{{rpc=\"{rpc}\",outcome=\"ok\",code=\"ok\"}}"
            );
            assert_eq!(metrics.value(&series), Some(0), "{series}");
        }
        assert!(
            metrics
                .render()
                .contains("# HELP openshell_server_supervisor_sessions ")
        );
    }

    #[test]
    fn configured_exporter_buckets_only_new_latency_histograms() {
        let metrics = MetricsCapture::install();
        let sample = Duration::from_millis(3);
        histogram!(RELAY_CLAIM_DURATION_SECONDS).record(sample);
        histogram!(PEER_REQUEST_DURATION_SECONDS, LABEL_RPC => "PeerRelay", LABEL_OUTCOME => "ok")
            .record(sample);
        histogram!(MUTATION_LOCK_WAIT_SECONDS, LABEL_SCOPE => "sandbox").record(sample);
        histogram!(SANDBOX_WATCH_POLL_DURATION_SECONDS).record(sample);
        histogram!(
            "openshell_server_grpc_request_duration_seconds",
            "method" => "ListSandboxes",
            "code" => "0"
        )
        .record(sample);
        histogram!(
            "openshell_server_http_request_duration_seconds",
            "path" => "/healthz",
            "status" => "200"
        )
        .record(sample);
        histogram!(
            "openshell_server_readiness_database_probe_duration_seconds",
            "outcome" => "success"
        )
        .record(sample);
        histogram!("openshell_gateway_interceptor_latency_seconds").record(sample);

        let rendered = metrics.render();
        for name in BUCKETED_HISTOGRAMS {
            assert!(
                rendered.contains(&format!("# TYPE {name} histogram")),
                "{name} should render as a histogram"
            );
        }
        for name in [
            "openshell_server_grpc_request_duration_seconds",
            "openshell_server_http_request_duration_seconds",
            "openshell_server_readiness_database_probe_duration_seconds",
            "openshell_gateway_interceptor_latency_seconds",
        ] {
            assert!(
                rendered.contains(&format!("# TYPE {name} summary")),
                "{name} should keep its summary format"
            );
        }
        assert!(
            rendered.contains("openshell_server_relay_claim_duration_seconds_bucket{le=\"0.001\"}")
        );
        assert!(
            rendered.contains("openshell_server_relay_claim_duration_seconds_bucket{le=\"15\"}")
        );
    }

    #[test]
    fn gauge_slot_counts_until_dropped() {
        let metrics = MetricsCapture::install();
        let first = GaugeSlot::relay_pending();
        let second = GaugeSlot::relay_pending();
        assert_eq!(metrics.value(RELAY_PENDING), Some(2));
        drop(first);
        assert_eq!(metrics.value(RELAY_PENDING), Some(1));
        drop(second);
        assert_eq!(metrics.value(RELAY_PENDING), Some(0));

        let session = GaugeSlot::supervisor_session();
        assert_eq!(metrics.value(SUPERVISOR_SESSIONS), Some(1));
        drop(session);
        assert_eq!(metrics.value(SUPERVISOR_SESSIONS), Some(0));
    }

    #[test]
    fn gauge_slot_acquired_before_recorder_never_goes_negative() {
        // No capture is installed yet, so this slot binds to the no-op recorder.
        let slot = GaugeSlot::relay_pending();
        let metrics = MetricsCapture::install();
        drop(slot);
        assert_eq!(metrics.value(RELAY_PENDING), None);
    }

    #[test]
    fn peer_request_timer_records_outcome_code_and_latency() {
        let metrics = MetricsCapture::install();

        let mut relay = PeerRequestTimer::start(PeerRpc::Relay);
        relay.finish(&Err::<(), _>(Status::resource_exhausted("x")));
        drop(relay);
        assert_eq!(
            metrics.value(
                "openshell_server_peer_requests_total{rpc=\"PeerRelay\",outcome=\"rpc_error\",code=\"resource_exhausted\"}"
            ),
            Some(1)
        );
        assert_eq!(
            metrics.value(
                "openshell_server_peer_request_duration_seconds_count{rpc=\"PeerRelay\",outcome=\"rpc_error\"}"
            ),
            Some(1)
        );

        let mut endpoint = PeerRequestTimer::start(PeerRpc::ReportEndpointStatus);
        endpoint.client_error(&Status::unavailable("x"));
        drop(endpoint);
        assert_eq!(
            metrics.value(
                "openshell_server_peer_requests_total{rpc=\"PeerReportEndpointStatus\",outcome=\"client_error\",code=\"unavailable\"}"
            ),
            Some(1)
        );

        let mut provider_status = PeerRequestTimer::start(PeerRpc::GetSandboxProviderStatus);
        provider_status.finish(&Ok::<(), Status>(()));
        drop(provider_status);
        assert_eq!(
            metrics.value(
                "openshell_server_peer_requests_total{rpc=\"PeerGetSandboxProviderStatus\",outcome=\"ok\",code=\"ok\"}"
            ),
            Some(1)
        );
    }

    #[test]
    fn peer_request_timer_records_cancelled_when_dropped_unfinished() {
        let metrics = MetricsCapture::install();
        drop(PeerRequestTimer::start(PeerRpc::ReportProviderReadiness));
        assert_eq!(
            metrics.value(
                "openshell_server_peer_requests_total{rpc=\"PeerReportProviderReadiness\",outcome=\"client_error\",code=\"cancelled\"}"
            ),
            Some(1)
        );
    }

    #[test]
    fn peer_request_timer_records_once() {
        let metrics = MetricsCapture::install();
        let mut timer = PeerRequestTimer::start(PeerRpc::Relay);
        timer.finish(&Ok::<(), Status>(()));
        timer.client_error(&Status::unavailable("x"));
        drop(timer);
        assert_eq!(
            metrics.value(
                "openshell_server_peer_requests_total{rpc=\"PeerRelay\",outcome=\"ok\",code=\"ok\"}"
            ),
            Some(1)
        );
        assert!(!metrics.render().contains("outcome=\"client_error\""));
    }

    #[test]
    fn grpc_code_labels_are_distinct_snake_case() {
        let labels: HashSet<&str> = (0..=16)
            .map(|code| grpc_code_label(Code::from(code)))
            .collect();
        for label in &labels {
            assert!(
                label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{label} is not snake_case"
            );
        }
        assert_eq!(labels.len(), 17);
        assert_eq!(grpc_code_label(Code::DeadlineExceeded), "deadline_exceeded");
        assert_eq!(
            grpc_code_label(Code::ResourceExhausted),
            "resource_exhausted"
        );
        assert_eq!(grpc_code_label(Code::Ok), "ok");
    }
}
