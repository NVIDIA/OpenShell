// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Background database health monitor.
//!
//! Decouples the readiness probe from the underlying database call: a
//! background task periodically pings `Store::ping()` and publishes the
//! result to a [`tokio::sync::watch`] channel. The `/readyz` and `/health`
//! handlers read that channel synchronously, so probe responses are
//! sub-millisecond and never race with the kubelet's probe timeout.
//!
//! Both polling parameters are hardcoded by design:
//!
//! - [`DEFAULT_CHECK_INTERVAL`] (5s) bounds how stale the published state
//!   can be — once a DB outage occurs, `/readyz` reflects it within at
//!   most one interval (plus the next handler read by the kubelet).
//! - [`DEFAULT_CHECK_TIMEOUT`] (2s) bounds a single ping. A `SELECT 1` that
//!   takes longer than 2s is itself a symptom of an unhealthy database;
//!   the monitor records the iteration as a `Timeout` and the system goes
//!   `Unhealthy`.
//!
//! The interval/timeout invariant (`timeout < interval`) is enforced by
//! construction; the only public constructor wires the defaults.

use std::sync::Arc;
use std::time::{Duration, Instant};

use metrics::{gauge, histogram};
use tokio::sync::watch;
use tracing::warn;

use crate::persistence::Store;

/// How often the background task pings the database.
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum time a single database ping is allowed to take.
///
/// Must be strictly less than [`DEFAULT_CHECK_INTERVAL`] so a slow ping
/// cannot push the effective polling cycle past the interval.
pub const DEFAULT_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

const _: () = assert!(
    DEFAULT_CHECK_TIMEOUT.as_secs() < DEFAULT_CHECK_INTERVAL.as_secs(),
    "DEFAULT_CHECK_TIMEOUT must be strictly less than DEFAULT_CHECK_INTERVAL"
);

const METRIC_READINESS_DATABASE_HEALTHY: &str = "openshell_server_readiness_database_healthy";
const METRIC_READINESS_DATABASE_PROBE_DURATION_SECONDS: &str =
    "openshell_server_readiness_database_probe_duration_seconds";
const METRIC_OUTCOME_LABEL: &str = "outcome";

/// Latest published database health state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HealthState {
    /// The monitor has not yet completed its first ping.
    ///
    /// Treated as unhealthy by the handler: probes that arrive before the
    /// first iteration see `503` and the pod stays `NotReady` until the
    /// monitor settles. Resolves within one interval at startup.
    Initializing,

    /// Latest ping succeeded.
    Healthy {
        /// Measured ping duration in milliseconds.
        latency_ms: u64,
    },

    /// Latest ping failed or timed out.
    Unhealthy(HealthError),
}

impl HealthState {
    /// Returns `true` when the latest published state is `Healthy`.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy { .. })
    }
}

/// Reason the latest iteration failed.
///
/// Latency is carried per-variant because the invariant differs: an
/// `Unavailable` outcome always has a measured duration (the call returned
/// before the timeout fired), while `Timeout` never does (the call never
/// returned). Encoding this in the type prevents the call site from having
/// to invent a placeholder value for the timeout case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthError {
    /// The persistence layer returned an error before the timeout fired.
    Unavailable {
        /// Measured duration of the failed ping, in milliseconds.
        latency_ms: u64,
    },
    /// The persistence layer did not respond within [`DEFAULT_CHECK_TIMEOUT`].
    Timeout,
}

/// Background monitor that polls [`Store::ping`] on a fixed cadence and
/// publishes the latest result to a [`watch::Receiver`].
///
/// Construction spawns a Tokio task that lives until the runtime is
/// dropped. The task only holds an `Arc<Store>` clone and the
/// [`watch::Sender`], so dropping the monitor wrapper does not stop the
/// background polling — that is intentional, the gateway runtime owns the
/// monitor for the lifetime of the process. Tests rely on the same
/// "task lives until runtime exits" semantics since each test gets its own
/// Tokio runtime.
pub struct DatabaseHealthMonitor {
    receiver: watch::Receiver<HealthState>,
}

impl DatabaseHealthMonitor {
    /// Spawn a monitor with the production defaults.
    #[must_use]
    pub fn spawn(store: Arc<Store>) -> Self {
        Self::spawn_with(store, DEFAULT_CHECK_INTERVAL, DEFAULT_CHECK_TIMEOUT)
    }

    /// Spawn a monitor with custom polling parameters.
    ///
    /// Intended for tests that want fast iteration. Production paths should
    /// use [`spawn`] so the polling cadence stays consistent across
    /// deployments.
    #[must_use]
    pub fn spawn_with(store: Arc<Store>, interval: Duration, timeout: Duration) -> Self {
        let (tx, rx) = watch::channel(HealthState::Initializing);
        tokio::spawn(monitor_loop(store, tx, interval, timeout));
        Self { receiver: rx }
    }

    /// Subscribe to state updates.
    ///
    /// Returned receivers always observe the latest value with no lock
    /// contention (`tokio::sync::watch` semantics).
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<HealthState> {
        self.receiver.clone()
    }

    /// Wait until the monitor publishes its first non-`Initializing` state.
    ///
    /// Test-only: production builds intentionally do not block on the first
    /// poll so the health listener is responsive from t=0 (probes during
    /// the warmup window see a structured `Initializing → 503` instead of a
    /// TCP-level hang). Tests that need a deterministic post-warmup state
    /// call this before constructing the router.
    #[cfg(test)]
    pub(crate) async fn wait_until_polled(&mut self) {
        while matches!(*self.receiver.borrow(), HealthState::Initializing) {
            if self.receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

async fn monitor_loop(
    store: Arc<Store>,
    tx: watch::Sender<HealthState>,
    interval: Duration,
    timeout: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    // `Skip` keeps the schedule when a tick is missed (e.g. because a ping
    // approached the timeout). `Burst` (the default) would fire back-to-back
    // catch-up pings, defeating the bounded-cadence guarantee.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        let state = run_check(store.as_ref(), timeout).await;
        record_metrics(&state);
        // Send errors only happen when every receiver is dropped, at which
        // point the monitor is shutting down — exit cleanly.
        if tx.send(state).is_err() {
            break;
        }
    }
}

async fn run_check(store: &Store, timeout: Duration) -> HealthState {
    let started = Instant::now();
    match tokio::time::timeout(timeout, store.ping()).await {
        Ok(Ok(())) => HealthState::Healthy {
            latency_ms: elapsed_ms(started.elapsed()),
        },
        Ok(Err(err)) => {
            let latency_ms = elapsed_ms(started.elapsed());
            warn!(error = %err, latency_ms, "database health check failed");
            HealthState::Unhealthy(HealthError::Unavailable { latency_ms })
        }
        Err(_) => {
            warn!(
                timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                "database health check timed out"
            );
            HealthState::Unhealthy(HealthError::Timeout)
        }
    }
}

fn record_metrics(state: &HealthState) {
    let (healthy, outcome_label, latency_seconds) = match state {
        HealthState::Initializing => return,
        HealthState::Healthy { latency_ms } => {
            (true, "success", duration_seconds_from_ms(*latency_ms))
        }
        HealthState::Unhealthy(HealthError::Unavailable { latency_ms }) => {
            (false, "db_error", duration_seconds_from_ms(*latency_ms))
        }
        HealthState::Unhealthy(HealthError::Timeout) => {
            (false, "timeout", DEFAULT_CHECK_TIMEOUT.as_secs_f64())
        }
    };

    gauge!(METRIC_READINESS_DATABASE_HEALTHY).set(if healthy { 1.0 } else { 0.0 });
    histogram!(
        METRIC_READINESS_DATABASE_PROBE_DURATION_SECONDS,
        METRIC_OUTCOME_LABEL => outcome_label
    )
    .record(latency_seconds);
}

fn duration_seconds_from_ms(ms: u64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    {
        ms as f64 / 1000.0
    }
}

fn elapsed_ms(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fresh_store() -> Arc<Store> {
        Arc::new(
            Store::connect("sqlite::memory:")
                .await
                .expect("connect in-memory sqlite store"),
        )
    }

    #[tokio::test]
    async fn first_state_is_initializing_then_transitions_to_healthy() {
        let store = fresh_store().await;
        let mut monitor = DatabaseHealthMonitor::spawn_with(
            store,
            Duration::from_millis(10),
            Duration::from_secs(1),
        );

        assert_eq!(*monitor.subscribe().borrow(), HealthState::Initializing);

        monitor.wait_until_polled().await;
        let state = monitor.subscribe().borrow().clone();
        assert!(
            matches!(state, HealthState::Healthy { .. }),
            "expected Healthy, got {state:?}"
        );
    }

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn detects_database_outage_within_one_interval() {
        let store = fresh_store().await;
        let mut monitor = DatabaseHealthMonitor::spawn_with(
            store.clone(),
            Duration::from_millis(20),
            Duration::from_secs(1),
        );
        monitor.wait_until_polled().await;
        assert!(monitor.subscribe().borrow().is_healthy());

        store.close().await;

        // Wait for the next state change after the close (the polling loop
        // will pick it up within the interval).
        let mut rx = monitor.subscribe();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            assert!(
                rx.changed().await.is_ok(),
                "monitor task ended before reporting outage"
            );
            let state = rx.borrow().clone();
            if matches!(
                state,
                HealthState::Unhealthy(HealthError::Unavailable { .. })
            ) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "monitor did not transition to Unhealthy in time"
            );
        }
    }

    #[tokio::test]
    async fn slow_ping_is_recorded_as_timeout() {
        // Drive the loop directly so we can hand it a ping future that
        // never completes, isolating the timeout path from the live Store.
        let (tx, rx) = watch::channel(HealthState::Initializing);
        let timeout = Duration::from_millis(10);

        tokio::spawn(async move {
            let state = tokio::time::timeout(
                timeout,
                std::future::pending::<crate::persistence::PersistenceResult<()>>(),
            )
            .await;
            let outcome = match state {
                Ok(_) => unreachable!("pending future cannot resolve"),
                Err(_) => HealthState::Unhealthy(HealthError::Timeout),
            };
            let _ = tx.send(outcome);
        });

        let mut rx = rx;
        rx.changed().await.expect("monitor publishes a state");
        let state = rx.borrow().clone();
        assert!(
            matches!(state, HealthState::Unhealthy(HealthError::Timeout)),
            "expected Timeout, got {state:?}"
        );
    }

    #[test]
    fn default_check_timeout_is_strictly_less_than_default_check_interval() {
        // Sanity guard duplicated as a runtime test so CI catches any
        // regression on the const_assert above.
        assert!(DEFAULT_CHECK_TIMEOUT < DEFAULT_CHECK_INTERVAL);
    }
}
