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
pub const RELAY_PENDING: &str = "openshell_server_relay_pending";
pub const RELAY_PENDING_CAPACITY: &str = "openshell_server_relay_pending_capacity";
pub const MUTATION_LOCK_CONNECTIONS_IN_USE: &str =
    "openshell_server_mutation_lock_connections_in_use";
pub const MUTATION_LOCK_CONNECTIONS_CAPACITY: &str =
    "openshell_server_mutation_lock_connections_capacity";
// Counters
pub const RELAY_REJECTED_TOTAL: &str = "openshell_server_relay_rejected_total";
pub const RELAY_EXPIRED_TOTAL: &str = "openshell_server_relay_expired_total";
pub const ROUTED_REQUEST_ATTEMPTS_TOTAL: &str = "openshell_server_routed_request_attempts_total";
pub const MUTATION_LOCK_TIMEOUTS_TOTAL: &str = "openshell_server_mutation_lock_timeouts_total";
pub const MUTATION_LOCK_ERRORS_TOTAL: &str = "openshell_server_mutation_lock_errors_total";
// Histograms (explicit buckets, see BUCKETED_HISTOGRAMS)
pub const RELAY_CLAIM_DURATION_SECONDS: &str = "openshell_server_relay_claim_duration_seconds";
pub const PEER_REQUEST_DURATION_SECONDS: &str = "openshell_server_peer_request_duration_seconds";
pub const MUTATION_LOCK_WAIT_SECONDS: &str = "openshell_server_mutation_lock_wait_seconds";
pub const MUTATION_LOCK_HOLD_SECONDS: &str = "openshell_server_mutation_lock_hold_seconds";

const LABEL_REASON: &str = "reason";
const LABEL_OPERATION: &str = "operation";
const LABEL_OUTCOME: &str = "outcome";
const LABEL_GRPC_CODE: &str = "grpc_code";
const LABEL_RELAY_KIND: &str = "relay_kind";
const LABEL_ROUTE: &str = "route";
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
    MUTATION_LOCK_HOLD_SECONDS,
];

/// Protocol the supervisor is asked to relay. Never label metrics with the target address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayKind {
    Ssh,
    Tcp,
}

impl RelayKind {
    pub const ALL: [Self; 2] = [Self::Ssh, Self::Tcp];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Tcp => "tcp",
        }
    }
}

/// Where the requesting replica tries to open a relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayRoute {
    Local,
    Peer,
}

impl RelayRoute {
    pub const ALL: [Self; 2] = [Self::Local, Self::Peer];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Peer => "peer",
        }
    }
}

/// Which pending-relay cap rejected an open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayRejection {
    ReplicaCapacity,
    SandboxCapacity,
}

impl RelayRejection {
    pub const ALL: [Self; 2] = [Self::ReplicaCapacity, Self::SandboxCapacity];

    pub const fn label(self) -> &'static str {
        match self {
            Self::ReplicaCapacity => "replica_capacity",
            Self::SandboxCapacity => "sandbox_capacity",
        }
    }
}

/// Routed operation. For a peer request, the owning replica records the matching gRPC method in
/// `openshell_server_grpc_requests_total`, for example `PeerRelay` for `relay`.
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

    const fn operation(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::ReportProviderReadiness => "report_provider_readiness",
            Self::ReportEndpointStatus => "report_endpoint_status",
            Self::GetSandboxProviderStatus => "get_sandbox_provider_status",
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

/// Where a routed attempt ended. A relay succeeds only when the supervisor claims it, on either
/// route, so the values mean the same thing for local and peer attempts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttemptOutcome {
    Success,
    /// Failed on this replica, including cancellation by the caller.
    LocalError,
    /// The owning replica returned an error, or the open peer connection failed.
    RemoteError,
}

impl AttemptOutcome {
    const fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::LocalError => "local_error",
            Self::RemoteError => "remote_error",
        }
    }
}

/// Snake-case gRPC status name for the `grpc_code` label. It is not named `code` because
/// `openshell_server_grpc_requests_total` uses that name for the numeric status. Exhaustive on
/// purpose, so a new tonic variant fails to compile instead of producing an unbounded label.
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

/// Relay cap published as `openshell_server_relay_pending_capacity`. The caller passes the value
/// that enforces the cap, so this module does not depend on the relay registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayCapacity {
    /// Pending relays allowed on one replica.
    pub per_replica: usize,
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
/// once, from `run_server`. `mutation_lock_connections` is the `PostgreSQL` lock pool size,
/// `None` on a backend without a lock pool.
pub fn install_global_recorder(
    relay: RelayCapacity,
    mutation_lock_connections: Option<u32>,
) -> Result<PrometheusHandle, BuildError> {
    let handle = configure_exporter(PrometheusBuilder::new())?.install_recorder()?;
    describe_and_initialize(relay, mutation_lock_connections);
    Ok(handle)
}

/// Emit HELP metadata, create every fixed-label series at 0, and publish the relay caps and,
/// with a lock pool, its size. An idle replica then exports 0 instead of "no data", which HPA
/// and `rate()` need.
pub fn describe_and_initialize(relay: RelayCapacity, mutation_lock_connections: Option<u32>) {
    describe_gauge!(
        SUPERVISOR_SESSIONS,
        Unit::Count,
        "Supervisor control sessions registered on this gateway replica."
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
    describe_counter!(
        ROUTED_REQUEST_ATTEMPTS_TOTAL,
        Unit::Count,
        "Local relay setup and outbound peer attempts completed or cancelled by this replica. Each retry counts separately."
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
        MUTATION_LOCK_TIMEOUTS_TOTAL,
        Unit::Count,
        "Mutation lock acquisitions that timed out."
    );
    describe_counter!(
        MUTATION_LOCK_ERRORS_TOTAL,
        Unit::Count,
        "Mutation lock acquisitions that failed without timing out, such as a lock connection PostgreSQL did not open."
    );
    describe_histogram!(
        RELAY_CLAIM_DURATION_SECONDS,
        Unit::Seconds,
        "Time from opening a relay channel to the supervisor claiming it."
    );
    describe_histogram!(
        PEER_REQUEST_DURATION_SECONDS,
        Unit::Seconds,
        "Latency of outbound requests to the owning replica. For relays, until the owner's supervisor claimed the relay."
    );
    describe_histogram!(
        MUTATION_LOCK_WAIT_SECONDS,
        Unit::Seconds,
        "Time spent acquiring the mutation lock for a scope."
    );
    describe_histogram!(
        MUTATION_LOCK_HOLD_SECONDS,
        Unit::Seconds,
        "Time a mutation lock was held, from acquisition to release, including requests cancelled while holding it."
    );

    // `increment(0)` registers a series without overwriting a value recorded earlier.
    gauge!(SUPERVISOR_SESSIONS).increment(0.0);
    gauge!(RELAY_PENDING).increment(0.0);
    gauge!(RELAY_PENDING_CAPACITY).set(count_as_f64(relay.per_replica));
    for kind in RelayKind::ALL {
        for route in RelayRoute::ALL {
            counter!(
                ROUTED_REQUEST_ATTEMPTS_TOTAL,
                LABEL_OPERATION => PeerRpc::Relay.operation(),
                LABEL_ROUTE => route.label(),
                LABEL_RELAY_KIND => kind.label(),
                LABEL_OUTCOME => AttemptOutcome::Success.label(),
                LABEL_GRPC_CODE => grpc_code_label(Code::Ok)
            )
            .increment(0);
        }
    }
    for reason in RelayRejection::ALL {
        counter!(RELAY_REJECTED_TOTAL, LABEL_REASON => reason.label()).increment(0);
    }
    counter!(RELAY_EXPIRED_TOTAL).increment(0);
    for scope in LockScope::ALL {
        counter!(MUTATION_LOCK_TIMEOUTS_TOTAL, LABEL_SCOPE => scope.label()).increment(0);
        counter!(MUTATION_LOCK_ERRORS_TOTAL, LABEL_SCOPE => scope.label()).increment(0);
    }
    if let Some(capacity) = mutation_lock_connections {
        describe_gauge!(
            MUTATION_LOCK_CONNECTIONS_IN_USE,
            Unit::Count,
            "PostgreSQL lock-pool connections checked out on this replica: held by mutation guards, by acquisitions waiting for an advisory lock, or being returned to the pool."
        );
        describe_gauge!(
            MUTATION_LOCK_CONNECTIONS_CAPACITY,
            Unit::Count,
            "Maximum PostgreSQL lock-pool connections on one gateway replica."
        );
        gauge!(MUTATION_LOCK_CONNECTIONS_IN_USE).increment(0.0);
        gauge!(MUTATION_LOCK_CONNECTIONS_CAPACITY).set(f64::from(capacity));
    }
    for rpc in PeerRpc::ALL {
        if rpc == PeerRpc::Relay {
            continue;
        }
        counter!(
            ROUTED_REQUEST_ATTEMPTS_TOTAL,
            LABEL_OPERATION => rpc.operation(),
            LABEL_ROUTE => RelayRoute::Peer.label(),
            LABEL_RELAY_KIND => "none",
            LABEL_OUTCOME => AttemptOutcome::Success.label(),
            LABEL_GRPC_CODE => grpc_code_label(Code::Ok)
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

    /// Share of `openshell_server_mutation_lock_connections_in_use`.
    pub fn mutation_lock_connection() -> Self {
        Self::acquire(MUTATION_LOCK_CONNECTIONS_IN_USE)
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

/// How long one mutation guard was held, recorded when it is released. Holds longer than the
/// top bucket count only in `+Inf`; the hold warning logs their duration.
pub fn record_lock_hold(scope: LockScope, held: Duration) {
    histogram!(MUTATION_LOCK_HOLD_SECONDS, LABEL_SCOPE => scope.label()).record(held);
}

/// A guard acquisition that timed out: a local wait, a full lock pool, too little time left to
/// open a lock connection, or Postgres `lock_timeout` (SQLSTATE 55P03). A lock connection that
/// Postgres does not open with at least `LOCK_CONNECTION_MIN_BUDGET` left counts in
/// [`record_lock_error`] instead. RPC callers return the timeout as `Status::unavailable`.
pub fn record_lock_timeout(scope: LockScope) {
    counter!(MUTATION_LOCK_TIMEOUTS_TOTAL, LABEL_SCOPE => scope.label()).increment(1);
}

/// A guard acquisition that failed without timing out: Postgres did not open a lock connection,
/// or a lock statement failed. RPC callers return it as `Status::internal`. A cancelled
/// acquisition is not counted.
pub fn record_lock_error(scope: LockScope) {
    counter!(MUTATION_LOCK_ERRORS_TOTAL, LABEL_SCOPE => scope.label()).increment(1);
}

/// Counts one local relay setup or outbound peer attempt exactly once, and times peer requests.
/// A relay succeeds when the supervisor claims it, on either route. Dropping an unfinished
/// timer (the caller gave up) records `local_error` / `cancelled`.
#[must_use = "finish the timer with local_error() or finish()"]
pub struct RoutedRequestTimer {
    rpc: PeerRpc,
    route: RelayRoute,
    relay_kind: Option<RelayKind>,
    started: Instant,
    recorded: bool,
}

impl RoutedRequestTimer {
    pub fn start(rpc: PeerRpc) -> Self {
        Self {
            rpc,
            route: RelayRoute::Peer,
            relay_kind: if rpc == PeerRpc::Relay {
                Some(RelayKind::Ssh)
            } else {
                None
            },
            started: Instant::now(),
            recorded: false,
        }
    }

    pub fn relay(kind: RelayKind, route: RelayRoute) -> Self {
        Self {
            rpc: PeerRpc::Relay,
            route,
            relay_kind: Some(kind),
            started: Instant::now(),
            recorded: false,
        }
    }

    /// The attempt failed on this replica: local relay setup or claim (including the claim
    /// window closing), or a peer request that failed before it reached the owner (token,
    /// channel, headers, or stream setup).
    pub fn local_error(&mut self, status: &Status) {
        self.record(AttemptOutcome::LocalError, status.code());
    }

    /// Record the raw tonic result of the RPC itself. Call this BEFORE any remap to
    /// `Unavailable`, so the owner's code (for example `resource_exhausted`) is kept.
    pub fn finish<T>(&mut self, result: &Result<T, Status>) {
        match result {
            Ok(_) => self.record(AttemptOutcome::Success, Code::Ok),
            Err(status) if self.route == RelayRoute::Local => self.local_error(status),
            Err(status) => self.record(AttemptOutcome::RemoteError, status.code()),
        }
    }

    fn record(&mut self, outcome: AttemptOutcome, code: Code) {
        if self.recorded {
            return;
        }
        self.recorded = true;
        counter!(
            ROUTED_REQUEST_ATTEMPTS_TOTAL,
            LABEL_OPERATION => self.rpc.operation(),
            LABEL_ROUTE => self.route.label(),
            LABEL_RELAY_KIND => self.relay_kind.map_or("none", RelayKind::label),
            LABEL_OUTCOME => outcome.label(),
            LABEL_GRPC_CODE => grpc_code_label(code)
        )
        .increment(1);
        if self.route == RelayRoute::Peer {
            histogram!(
                PEER_REQUEST_DURATION_SECONDS,
                LABEL_OPERATION => self.rpc.operation(),
                LABEL_OUTCOME => outcome.label()
            )
            .record(self.started.elapsed());
        }
    }
}

impl Drop for RoutedRequestTimer {
    fn drop(&mut self) {
        self.record(AttemptOutcome::LocalError, Code::Cancelled);
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
        describe_and_initialize(RelayCapacity { per_replica: 256 }, Some(4));

        for (series, expected) in [
            ("openshell_server_relay_pending_capacity", 256),
            ("openshell_server_mutation_lock_connections_capacity", 4),
            ("openshell_server_mutation_lock_connections_in_use", 0),
            ("openshell_server_supervisor_sessions", 0),
            ("openshell_server_relay_pending", 0),
            (
                "openshell_server_relay_rejected_total{reason=\"replica_capacity\"}",
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
            (
                "openshell_server_mutation_lock_errors_total{scope=\"global\"}",
                0,
            ),
            (
                "openshell_server_mutation_lock_errors_total{scope=\"workspace\"}",
                0,
            ),
            (
                "openshell_server_mutation_lock_errors_total{scope=\"sandbox\"}",
                0,
            ),
        ] {
            assert_eq!(metrics.value(series), Some(expected), "{series}");
        }
        for kind in ["ssh", "tcp"] {
            for route in ["local", "peer"] {
                let series = format!(
                    "openshell_server_routed_request_attempts_total{{operation=\"relay\",route=\"{route}\",relay_kind=\"{kind}\",outcome=\"success\",grpc_code=\"ok\"}}"
                );
                assert_eq!(metrics.value(&series), Some(0), "{series}");
            }
        }
        for operation in [
            "report_provider_readiness",
            "report_endpoint_status",
            "get_sandbox_provider_status",
        ] {
            let series = format!(
                "openshell_server_routed_request_attempts_total{{operation=\"{operation}\",route=\"peer\",relay_kind=\"none\",outcome=\"success\",grpc_code=\"ok\"}}"
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
    fn describe_and_initialize_without_a_lock_pool_omits_lock_connection_gauges() {
        let metrics = MetricsCapture::install();
        describe_and_initialize(RelayCapacity { per_replica: 256 }, None);

        assert_eq!(metrics.value(MUTATION_LOCK_CONNECTIONS_IN_USE), None);
        assert_eq!(metrics.value(MUTATION_LOCK_CONNECTIONS_CAPACITY), None);
        assert!(
            !metrics
                .render()
                .contains("openshell_server_mutation_lock_connections")
        );
        assert_eq!(
            metrics.value("openshell_server_mutation_lock_errors_total{scope=\"sandbox\"}"),
            Some(0)
        );
    }

    #[test]
    fn routed_attempts_have_seven_bounded_success_series_and_keep_counts_on_initialize() {
        let metrics = MetricsCapture::install();
        for kind in RelayKind::ALL {
            for route in RelayRoute::ALL {
                RoutedRequestTimer::relay(kind, route).finish(&Ok::<(), Status>(()));
            }
        }
        RoutedRequestTimer::relay(RelayKind::Tcp, RelayRoute::Peer).finish(&Ok::<(), Status>(()));
        describe_and_initialize(RelayCapacity { per_replica: 256 }, None);

        for kind in ["ssh", "tcp"] {
            for route in ["local", "peer"] {
                let series = format!(
                    "openshell_server_routed_request_attempts_total{{operation=\"relay\",route=\"{route}\",relay_kind=\"{kind}\",outcome=\"success\",grpc_code=\"ok\"}}"
                );
                let expected = if kind == "tcp" && route == "peer" {
                    2
                } else {
                    1
                };
                assert_eq!(metrics.value(&series), Some(expected), "{series}");
            }
        }
        let rendered = metrics.render();
        assert!(rendered.contains("# TYPE openshell_server_routed_request_attempts_total counter"));
        assert!(!rendered.contains("openshell_server_relay_setup_attempts_total"));
        assert!(!rendered.contains("openshell_server_peer_requests_total"));
        assert_eq!(
            rendered
                .lines()
                .filter(|line| line.starts_with("openshell_server_routed_request_attempts_total{"))
                .count(),
            7
        );
    }

    #[test]
    fn configured_exporter_buckets_only_new_latency_histograms() {
        let metrics = MetricsCapture::install();
        let sample = Duration::from_millis(3);
        histogram!(RELAY_CLAIM_DURATION_SECONDS).record(sample);
        histogram!(
            PEER_REQUEST_DURATION_SECONDS,
            LABEL_OPERATION => "relay",
            LABEL_OUTCOME => "success"
        )
        .record(sample);
        histogram!(MUTATION_LOCK_WAIT_SECONDS, LABEL_SCOPE => "sandbox").record(sample);
        histogram!(MUTATION_LOCK_HOLD_SECONDS, LABEL_SCOPE => "sandbox").record(sample);
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

        let first = GaugeSlot::mutation_lock_connection();
        let second = GaugeSlot::mutation_lock_connection();
        assert_eq!(metrics.value(MUTATION_LOCK_CONNECTIONS_IN_USE), Some(2));
        drop(first);
        assert_eq!(metrics.value(MUTATION_LOCK_CONNECTIONS_IN_USE), Some(1));
        drop(second);
        assert_eq!(metrics.value(MUTATION_LOCK_CONNECTIONS_IN_USE), Some(0));
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

        let mut relay = RoutedRequestTimer::start(PeerRpc::Relay);
        relay.finish(&Err::<(), _>(Status::resource_exhausted("x")));
        drop(relay);
        assert_eq!(
            metrics.value(
                "openshell_server_routed_request_attempts_total{operation=\"relay\",route=\"peer\",relay_kind=\"ssh\",outcome=\"remote_error\",grpc_code=\"resource_exhausted\"}"
            ),
            Some(1)
        );
        assert_eq!(
            metrics.value(
                "openshell_server_peer_request_duration_seconds_count{operation=\"relay\",outcome=\"remote_error\"}"
            ),
            Some(1)
        );

        let mut endpoint = RoutedRequestTimer::start(PeerRpc::ReportEndpointStatus);
        endpoint.local_error(&Status::unavailable("x"));
        drop(endpoint);
        assert_eq!(
            metrics.value(
                "openshell_server_routed_request_attempts_total{operation=\"report_endpoint_status\",route=\"peer\",relay_kind=\"none\",outcome=\"local_error\",grpc_code=\"unavailable\"}"
            ),
            Some(1)
        );

        let mut provider_status = RoutedRequestTimer::start(PeerRpc::GetSandboxProviderStatus);
        provider_status.finish(&Ok::<(), Status>(()));
        drop(provider_status);
        assert_eq!(
            metrics.value(
                "openshell_server_routed_request_attempts_total{operation=\"get_sandbox_provider_status\",route=\"peer\",relay_kind=\"none\",outcome=\"success\",grpc_code=\"ok\"}"
            ),
            Some(1)
        );
    }

    #[test]
    fn peer_request_timer_records_cancelled_when_dropped_unfinished() {
        let metrics = MetricsCapture::install();
        drop(RoutedRequestTimer::start(PeerRpc::ReportProviderReadiness));
        assert_eq!(
            metrics.value(
                "openshell_server_routed_request_attempts_total{operation=\"report_provider_readiness\",route=\"peer\",relay_kind=\"none\",outcome=\"local_error\",grpc_code=\"cancelled\"}"
            ),
            Some(1)
        );
    }

    #[test]
    fn peer_request_timer_records_once() {
        let metrics = MetricsCapture::install();
        let mut timer = RoutedRequestTimer::start(PeerRpc::Relay);
        timer.finish(&Ok::<(), Status>(()));
        timer.local_error(&Status::unavailable("x"));
        drop(timer);
        assert_eq!(
            metrics.value(
                "openshell_server_routed_request_attempts_total{operation=\"relay\",route=\"peer\",relay_kind=\"ssh\",outcome=\"success\",grpc_code=\"ok\"}"
            ),
            Some(1)
        );
        assert!(!metrics.render().contains("outcome=\"local_error\""));
    }

    #[test]
    fn local_relay_failure_records_status_without_peer_latency() {
        let metrics = MetricsCapture::install();
        let mut timer = RoutedRequestTimer::relay(RelayKind::Tcp, RelayRoute::Local);
        timer.finish(&Err::<(), _>(Status::resource_exhausted("capacity")));
        drop(timer);
        assert_eq!(
            metrics.value("openshell_server_routed_request_attempts_total{operation=\"relay\",route=\"local\",relay_kind=\"tcp\",outcome=\"local_error\",grpc_code=\"resource_exhausted\"}"),
            Some(1)
        );
        assert!(!metrics.render().contains(PEER_REQUEST_DURATION_SECONDS));
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
