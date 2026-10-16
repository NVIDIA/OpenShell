// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! One delivery task per push session.
//!
//! A publication only marks a session for a rebuild, so repeated
//! publications coalesce into one build. The session's task takes the mark
//! after it holds a build permit, so every build reads state at least as new
//! as every publication it covers.
//!
//! Build permits come from one FIFO semaphore sized from the database pool.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use metrics::{Gauge, gauge, histogram};
use openshell_core::proto::ProviderEnvironmentSnapshot;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// How often a session rebuilds its configuration, to repair a missed
/// publication or retry an update its supervisor failed to apply. Unchanged
/// configuration the supervisor already acknowledged is not sent again. A
/// session first reconciles one to two intervals after it registers, at a
/// random offset, so reconciliation is a steady trickle rather than a burst
/// and never repeats the bootstrap it just applied.
pub(super) const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const MIN_FAILURE_BACKOFF: Duration = Duration::from_secs(1);
const MAX_FAILURE_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FanoutScope {
    AllConnected,
    Workspace(String),
    /// Sandboxes in `workspace` that attach the named provider.
    Provider {
        workspace: String,
        name: String,
    },
}

/// A push session as the delivery task sees it.
#[derive(Debug, Clone)]
pub struct Registration {
    pub sandbox_id: String,
    pub session_id: String,
    pub workspace: String,
    pub providers: HashSet<String>,
    /// The provider environment the bootstrap delivered.
    pub provider_environment: Option<ProviderEnvironmentSnapshot>,
    /// [`super::ConfigDelivery::publications`] observed before the bootstrap
    /// inputs were read.
    pub captured_seq: u64,
    /// The bootstrap could not resolve part of the configuration, so the
    /// session rebuilds it at once rather than at its first reconciliation.
    pub rebuild: bool,
}

#[derive(Debug)]
pub(super) struct SessionRecord {
    pub(super) sandbox_id: String,
    pub(super) session_id: String,
    workspace: String,
    marks: Mutex<Marks>,
    wake: Notify,
    /// The last provider environment this session resolved, reused while the
    /// sandbox configuration names it.
    provider_environment: Mutex<Option<ProviderEnvironmentSnapshot>>,
}

#[derive(Debug, Default)]
struct Marks {
    dirty: bool,
    dirty_since: Option<Instant>,
    dirty_gauge: Option<GaugeGuard>,
    /// Attachments read by the last build, for provider-scoped fanouts.
    providers: HashSet<String>,
    /// A running build may install a new attachment, so provider fanouts
    /// include the session until it finishes.
    building: bool,
    closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Closed,
    Clean,
    Dirty,
}

impl SessionRecord {
    pub(super) fn new(registration: Registration) -> Self {
        Self {
            sandbox_id: registration.sandbox_id,
            session_id: registration.session_id,
            workspace: registration.workspace,
            marks: Mutex::new(Marks {
                providers: registration.providers,
                ..Marks::default()
            }),
            wake: Notify::new(),
            provider_environment: Mutex::new(registration.provider_environment),
        }
    }

    pub(super) fn provider_environment(&self) -> Option<ProviderEnvironmentSnapshot> {
        self.provider_environment
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(super) fn cache_provider_environment(&self, snapshot: ProviderEnvironmentSnapshot) {
        *self
            .provider_environment
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(snapshot);
    }

    /// Delivery is best effort beside the session lifecycle, so a poisoned
    /// lock must not turn session teardown into a panic.
    fn marks(&self) -> MutexGuard<'_, Marks> {
        self.marks.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wakes the task only when the session becomes dirty, so a waiter keeps
    /// its place in the permit queue.
    pub(super) fn mark(&self) {
        if self.add_mark() {
            self.wake.notify_one();
        }
    }

    /// Returns whether the session became dirty.
    fn add_mark(&self) -> bool {
        let mut marks = self.marks();
        if marks.closed || marks.dirty {
            return false;
        }
        marks.dirty = true;
        marks.dirty_since = Some(Instant::now());
        marks.dirty_gauge = Some(GaugeGuard::acquire(gauge!(DIRTY_SESSIONS)));
        true
    }

    pub(super) fn close(&self) {
        let mut marks = self.marks();
        marks.closed = true;
        marks.dirty = false;
        marks.dirty_gauge = None;
        drop(marks);
        self.wake.notify_one();
    }

    pub(super) fn in_scope(&self, scope: &FanoutScope) -> bool {
        match scope {
            FanoutScope::AllConnected => true,
            FanoutScope::Workspace(workspace) => self.workspace == *workspace,
            FanoutScope::Provider { workspace, name } => {
                self.workspace == *workspace && {
                    let marks = self.marks();
                    marks.building || marks.providers.contains(name)
                }
            }
        }
    }

    fn status(&self) -> Status {
        let marks = self.marks();
        if marks.closed {
            Status::Closed
        } else if marks.dirty {
            Status::Dirty
        } else {
            Status::Clean
        }
    }

    /// Take the mark once a build permit is held. Returns false when there
    /// was none.
    fn take(&self) -> bool {
        let mut marks = self.marks();
        if !std::mem::take(&mut marks.dirty) {
            return false;
        }
        marks.dirty_gauge = None;
        marks.building = true;
        if let Some(since) = marks.dirty_since.take() {
            histogram!("openshell_supervisor_config_queue_wait_seconds")
                .record(since.elapsed().as_secs_f64());
        }
        true
    }

    fn finish(&self, providers: Option<HashSet<String>>) {
        let mut marks = self.marks();
        marks.building = false;
        if let Some(providers) = providers {
            marks.providers = providers;
        }
    }
}

/// Wait for a build permit while the session is dirty, or return `None` once
/// the session closed.
pub(super) async fn acquire_permit(
    builds: &Arc<Semaphore>,
    record: &SessionRecord,
) -> Option<OwnedSemaphorePermit> {
    loop {
        match record.status() {
            Status::Closed => return None,
            Status::Dirty => tokio::select! {
                permit = Arc::clone(builds).acquire_owned() => {
                    return Some(permit.expect("the build semaphore is never closed"));
                }
                () = record.wake.notified() => {}
            },
            Status::Clean => record.wake.notified().await,
        }
    }
}

/// Build and deliver a session's configuration. Returns whether the build
/// failed and the attachments it read.
pub(super) trait Deliver: Sync {
    fn deliver(
        &self,
        record: &SessionRecord,
    ) -> impl Future<Output = (bool, Option<HashSet<String>>)> + Send;
}

/// Run a session's deliveries until it closes, rebuilding its configuration
/// every `reconcile_interval`.
pub(super) async fn run(
    record: Arc<SessionRecord>,
    builds: &Arc<Semaphore>,
    deliver: &impl Deliver,
    reconcile_interval: Duration,
) {
    let mut failures = 0u32;
    let mut next_reconcile = Instant::now() + reconcile_interval + jitter(reconcile_interval);
    loop {
        loop {
            match record.status() {
                Status::Closed => return,
                Status::Dirty => break,
                Status::Clean => {}
            }
            tokio::select! {
                () = record.wake.notified() => {}
                () = tokio::time::sleep_until(next_reconcile) => {
                    next_reconcile = Instant::now() + reconcile_interval;
                    record.mark();
                }
            }
        }
        let Some(permit) = acquire_permit(builds, &record).await else {
            return;
        };
        if !record.take() {
            continue;
        }
        let (failed, providers) = deliver.deliver(&record).await;
        drop(permit);
        record.finish(providers);
        if !failed {
            failures = 0;
            continue;
        }
        // A new publication or session close ends the backoff early.
        let retry_at = Instant::now() + failure_backoff(failures);
        loop {
            tokio::select! {
                () = tokio::time::sleep_until(retry_at) => break,
                () = record.wake.notified() => {
                    if record.status() != Status::Clean {
                        break;
                    }
                }
            }
        }
        failures = failures.saturating_add(1);
        // The task is awake, so the retry needs no wakeup.
        record.add_mark();
    }
}

fn failure_backoff(failures: u32) -> Duration {
    MIN_FAILURE_BACKOFF
        .saturating_mul(1 << failures.min(5))
        .min(MAX_FAILURE_BACKOFF)
}

fn jitter(interval: Duration) -> Duration {
    let millis = u64::try_from(interval.as_millis())
        .unwrap_or(u64::MAX)
        .max(1);
    Duration::from_millis(rand::random_range(0..millis))
}

const DIRTY_SESSIONS: &str = "openshell_supervisor_config_dirty_sessions";

/// One unit of a gauge, released through the same handle when dropped.
#[derive(Debug)]
struct GaugeGuard(Gauge);

impl GaugeGuard {
    fn acquire(gauge: Gauge) -> Self {
        gauge.increment(1.0);
        Self(gauge)
    }
}

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.0.decrement(1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Long enough that the reconcile timer never fires in a test that does
    /// not ask for it.
    const NO_RECONCILE: Duration = Duration::from_hours(24);

    fn record(sandbox_id: &str, workspace: &str, providers: &[&str]) -> Arc<SessionRecord> {
        Arc::new(SessionRecord::new(Registration {
            sandbox_id: sandbox_id.to_string(),
            session_id: format!("{sandbox_id}-session"),
            workspace: workspace.to_string(),
            providers: providers.iter().map(ToString::to_string).collect(),
            provider_environment: None,
            captured_seq: 0,
            rebuild: false,
        }))
    }

    fn builds(permits: usize) -> Arc<Semaphore> {
        Arc::new(Semaphore::new(permits))
    }

    /// Counts deliveries and fails them while `fail` is set.
    #[derive(Default)]
    struct Recorder {
        fail: AtomicBool,
        gate: Option<Arc<Semaphore>>,
        calls: AtomicUsize,
        delivered: AtomicUsize,
    }

    impl Deliver for Recorder {
        async fn deliver(&self, _record: &SessionRecord) -> (bool, Option<HashSet<String>>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = &self.gate {
                gate.acquire().await.unwrap().forget();
            }
            self.delivered.fetch_add(1, Ordering::SeqCst);
            (self.fail.load(Ordering::SeqCst), None)
        }
    }

    impl Recorder {
        fn delivered(&self) -> usize {
            self.delivered.load(Ordering::SeqCst)
        }
    }

    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    #[test]
    fn marks_coalesce_until_taken() {
        let record = record("sb", "ws", &[]);
        assert!(record.add_mark());
        assert!(!record.add_mark());
        assert!(record.take());
        assert!(!record.take());
    }

    #[test]
    fn provider_scope_includes_attached_or_building_sessions() {
        let attached = record("a", "ws", &["github"]);
        let other = record("b", "ws", &[]);
        let scope = FanoutScope::Provider {
            workspace: "ws".into(),
            name: "github".into(),
        };
        assert!(attached.in_scope(&scope));
        assert!(!other.in_scope(&scope));
        assert!(!record("c", "other", &["github"]).in_scope(&scope));

        other.mark();
        assert!(other.take());
        assert!(other.in_scope(&scope), "a running build may attach it");
        other.finish(Some(HashSet::from(["github".to_string()])));
        assert!(other.in_scope(&scope));
        attached.finish(Some(HashSet::new()));
        assert!(!attached.in_scope(&scope));
    }

    #[tokio::test(start_paused = true)]
    async fn publications_during_a_build_coalesce_into_one_rebuild() {
        let builds = builds(4);
        let gate = Arc::new(Semaphore::new(0));
        let recorder = Arc::new(Recorder {
            gate: Some(Arc::clone(&gate)),
            ..Recorder::default()
        });
        let session = record("sb", "ws", &[]);
        session.mark();
        let task = tokio::spawn({
            let session = Arc::clone(&session);
            let recorder = Arc::clone(&recorder);
            async move { run(session, &builds, recorder.as_ref(), NO_RECONCILE).await }
        });
        settle().await;
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 1);

        for _ in 0..5 {
            session.mark();
        }
        gate.add_permits(3);
        settle().await;
        assert_eq!(recorder.delivered(), 2);

        session.close();
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn failed_builds_retry_with_backoff_until_they_succeed() {
        let builds = builds(4);
        let recorder = Arc::new(Recorder::default());
        recorder.fail.store(true, Ordering::SeqCst);
        let session = record("sb", "ws", &[]);
        session.mark();
        let task = tokio::spawn({
            let session = Arc::clone(&session);
            let recorder = Arc::clone(&recorder);
            async move { run(session, &builds, recorder.as_ref(), NO_RECONCILE).await }
        });
        settle().await;
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_millis(999)).await;
        settle().await;
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 1, "backs off 1 s");
        tokio::time::advance(Duration::from_millis(1)).await;
        settle().await;
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 2);

        recorder.fail.store(false, Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(2)).await;
        settle().await;
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 3, "then 2 s");
        tokio::time::advance(Duration::from_mins(1)).await;
        settle().await;
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 3, "then stops");

        session.close();
        task.await.unwrap();
    }

    #[test]
    fn failure_backoff_doubles_up_to_thirty_seconds() {
        let backoff: Vec<_> = (0..7).map(|n| failure_backoff(n).as_secs()).collect();
        assert_eq!(backoff, [1, 2, 4, 8, 16, 30, 30]);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_sessions_reconcile_their_configuration() {
        let builds = builds(4);
        let recorder = Arc::new(Recorder::default());
        let session = record("sb", "ws", &[]);
        let task = tokio::spawn({
            let session = Arc::clone(&session);
            let recorder = Arc::clone(&recorder);
            async move { run(session, &builds, recorder.as_ref(), RECONCILE_INTERVAL).await }
        });
        settle().await;

        tokio::time::advance(RECONCILE_INTERVAL).await;
        settle().await;
        assert_eq!(recorder.delivered(), 0, "not right after bootstrap");
        tokio::time::advance(RECONCILE_INTERVAL).await;
        settle().await;
        assert_eq!(recorder.delivered(), 1);
        tokio::time::advance(RECONCILE_INTERVAL).await;
        settle().await;
        assert_eq!(recorder.delivered(), 2);

        session.close();
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn closing_a_session_ends_its_task_and_drops_its_marks() {
        let builds = builds(1);
        let _held = Arc::clone(&builds).acquire_owned().await.unwrap();
        let recorder = Arc::new(Recorder::default());
        let session = record("sb", "ws", &[]);
        session.mark();
        let task = tokio::spawn({
            let session = Arc::clone(&session);
            let builds = Arc::clone(&builds);
            let recorder = Arc::clone(&recorder);
            async move { run(session, &builds, recorder.as_ref(), NO_RECONCILE).await }
        });
        settle().await;

        session.close();
        task.await.unwrap();
        assert_eq!(recorder.delivered(), 0);
        session.mark();
        assert!(!session.take());
    }
}
