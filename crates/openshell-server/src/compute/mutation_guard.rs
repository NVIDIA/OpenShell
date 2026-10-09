// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hierarchical mutation guards: a process-local keyed lock table plus, on
//! `PostgreSQL`, the matching advisory locks on the dedicated lock pool.
//!
//! See [`crate::persistence::mutation_lock`] for the key hierarchy and the
//! ordering rules. In short: lifecycle gate first, then local keys in
//! ascending order, then `PostgreSQL` keys in ascending order on one
//! connection. A task never acquires a guard while it holds one, which debug
//! builds check.

use super::{ComputeRuntime, SandboxLifecycleGuard};
use crate::gateway_metrics::{self, LockScope};
use crate::grpc::workspace::DEFAULT_WORKSPACE_NAME;
use crate::persistence::lock_order;
use crate::persistence::mutation_lock::MUTATION_LOCK_TIMEOUT;
use crate::persistence::{
    DistributedMutationGuard, LockMode, MutationLockKey, MutationLockSet, PersistenceError,
    PersistenceResult,
};
use openshell_core::ObjectWorkspace;
use openshell_core::proto::Sandbox;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};
use tracing::warn;

/// What a guarded mutation reads and writes, which selects its lock set.
///
/// Every mutation whose invariant spans several persisted objects must take
/// the narrowest scope that still conflicts with every writer of the objects
/// it validates against. Global settings and policy writers and
/// platform-scope profile writers hold the global key exclusively; provider
/// and workspace-scoped profile writers hold their workspace key exclusively;
/// sandbox-scoped settings and policy writers hold only their sandbox key
/// exclusively. A new cross-object writer needs a scope from the same table.
/// Profile writers pick theirs with [`MutationScope::profiles`].
#[derive(Clone, Copy, Debug)]
pub enum MutationScope<'a> {
    /// Global policy/settings and platform-scope profiles. Excludes every
    /// other scope fleet-wide.
    Global,
    /// Provider and workspace-scoped profile mutations in a named workspace.
    /// The platform scope is `Global`: an empty name trips a debug assertion
    /// and locks as `Global` in release builds.
    Workspace(&'a str),
    /// Any mutation of one sandbox's records, admin or supervisor.
    Sandbox {
        workspace: &'a str,
        sandbox_id: &'a str,
    },
}

impl<'a> MutationScope<'a> {
    pub(crate) const fn sandbox(workspace: &'a str, sandbox_id: &'a str) -> Self {
        Self::Sandbox {
            workspace,
            sandbox_id,
        }
    }

    /// Scope of a provider profile write. Platform-scope profiles (`""`)
    /// feed every workspace's catalog and are validated against sandboxes in
    /// all workspaces, so they take `Global`; a named workspace takes
    /// `Workspace(name)`.
    pub(crate) const fn profiles(workspace: &'a str) -> Self {
        if workspace.is_empty() {
            Self::Global
        } else {
            Self::Workspace(workspace)
        }
    }

    /// Keys and modes of this scope:
    ///
    /// - `Global`: X(global).
    /// - `Workspace(ws)`: S(global) X(workspace). An empty name is a caller
    ///   bug that debug builds catch; release builds take X(global), which
    ///   over-locks rather than under-locks.
    /// - `Sandbox`: S(global) S(workspace) X(sandbox). A legacy sandbox with
    ///   an empty workspace locks the default workspace, where its providers
    ///   resolve.
    pub(crate) fn lock_set(&self) -> MutationLockSet {
        let mut set = MutationLockSet::default();
        match *self {
            Self::Global => set.insert(MutationLockKey::Global, LockMode::Exclusive),
            Self::Workspace(workspace) => {
                debug_assert!(
                    !workspace.is_empty(),
                    "the platform scope is MutationScope::Global; use MutationScope::profiles"
                );
                if workspace.is_empty() {
                    set.insert(MutationLockKey::Global, LockMode::Exclusive);
                } else {
                    set.insert(MutationLockKey::Global, LockMode::Shared);
                    set.insert(MutationLockKey::Workspace(workspace), LockMode::Exclusive);
                }
            }
            Self::Sandbox {
                workspace,
                sandbox_id,
            } => {
                set.insert(MutationLockKey::Global, LockMode::Shared);
                set.insert(
                    MutationLockKey::Workspace(sandbox_workspace_key(workspace)),
                    LockMode::Shared,
                );
                set.insert(MutationLockKey::Sandbox(sandbox_id), LockMode::Exclusive);
            }
        }
        set
    }

    /// The metric label of this scope.
    pub(crate) const fn lock_scope(&self) -> LockScope {
        match self {
            Self::Global => LockScope::Global,
            Self::Workspace(workspace) if workspace.is_empty() => LockScope::Global,
            Self::Workspace(_) => LockScope::Workspace,
            Self::Sandbox { .. } => LockScope::Sandbox,
        }
    }
}

/// Workspace key of a sandbox scope. Legacy sandboxes may carry an empty
/// workspace; their providers resolve in the default workspace.
fn sandbox_workspace_key(workspace: &str) -> &str {
    if workspace.is_empty() {
        DEFAULT_WORKSPACE_NAME
    } else {
        workspace
    }
}

/// Table length up to which [`LocalMutationLocks`] never sweeps.
const LOCK_TABLE_MIN_SWEEP_LEN: usize = 64;

/// Process-local table of mutation lock keys.
///
/// Entries are weak, so a key's lock is freed once no guard holds it and no
/// acquisition waits on it, including an acquisition that was cancelled. Its
/// entry stays until the next sweep, which runs only when a new key grows the
/// table past the larger of `LOCK_TABLE_MIN_SWEEP_LEN` and twice the live
/// entries the last sweep left. Acquisition is amortized O(1), and the table
/// stays within about twice its peak live set. Tokio's `RwLock` is fair and
/// write-preferring: a queued exclusive request blocks later shared requests
/// on the same key.
#[derive(Debug)]
pub struct LocalMutationLocks {
    table: StdMutex<LockTable>,
    timeout_ms: AtomicU64,
}

#[derive(Debug)]
struct LockTable {
    entries: HashMap<i64, Weak<RwLock<()>>>,
    /// Length past which the next new key sweeps released entries.
    sweep_above: usize,
}

impl LocalMutationLocks {
    pub(crate) fn new() -> Self {
        Self {
            table: StdMutex::new(LockTable {
                entries: HashMap::new(),
                sweep_above: LOCK_TABLE_MIN_SWEEP_LEN,
            }),
            timeout_ms: AtomicU64::new(duration_millis(MUTATION_LOCK_TIMEOUT)),
        }
    }

    fn lock_for(&self, key: i64) -> Arc<RwLock<()>> {
        let mut table = self
            .table
            .lock()
            .expect("mutation lock registry lock poisoned");
        if let Some(lock) = table.entries.get(&key).and_then(Weak::upgrade) {
            return lock;
        }

        let lock = Arc::new(RwLock::new(()));
        // Replacing a released entry for the same key does not grow the table.
        let replaced = table.entries.insert(key, Arc::downgrade(&lock));
        if replaced.is_none() && table.entries.len() > table.sweep_above {
            table.entries.retain(|_, lock| lock.strong_count() > 0);
            table.sweep_above = (2 * table.entries.len()).max(LOCK_TABLE_MIN_SWEEP_LEN);
        }
        lock
    }

    /// Acquire `set` in ascending key order. Dropping the future releases the
    /// keys already taken and leaves no queue entry behind.
    async fn acquire(&self, set: &MutationLockSet) -> LocalMutationGuard {
        lock_order::check(lock_order::Lock::Mutation);
        let mut guards = Vec::new();
        for (key, mode) in set.iter() {
            let lock = self.lock_for(key);
            guards.push(match mode {
                LockMode::Shared => LocalKeyGuard::Shared {
                    _guard: lock.read_owned().await,
                },
                LockMode::Exclusive => LocalKeyGuard::Exclusive {
                    _guard: lock.write_owned().await,
                },
            });
        }
        LocalMutationGuard {
            _guards: guards,
            _order: lock_order::hold(lock_order::Lock::Mutation),
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.load(Ordering::Relaxed))
    }

    #[cfg(test)]
    pub(crate) fn set_timeout_for_tests(&self, timeout: Duration) {
        self.timeout_ms
            .store(duration_millis(timeout), Ordering::Relaxed);
    }

    /// Entries in the table, including released keys that no sweep has
    /// removed yet.
    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.table
            .lock()
            .expect("mutation lock registry lock poisoned")
            .entries
            .len()
    }

    /// Keys still held by a guard or awaited by an acquisition. Does not
    /// prune, so it cannot hide a leak in `lock_for`.
    #[cfg(test)]
    pub(crate) fn live_entry_count(&self) -> usize {
        self.table
            .lock()
            .expect("mutation lock registry lock poisoned")
            .entries
            .values()
            .filter(|lock| lock.strong_count() > 0)
            .count()
    }

    /// References to `key`'s lock: one per guard holding it and one per
    /// acquisition waiting for it.
    #[cfg(test)]
    pub(crate) fn key_references(&self, key: i64) -> usize {
        self.table
            .lock()
            .expect("mutation lock registry lock poisoned")
            .entries
            .get(&key)
            .map_or(0, Weak::strong_count)
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

enum LocalKeyGuard {
    Shared { _guard: OwnedRwLockReadGuard<()> },
    Exclusive { _guard: OwnedRwLockWriteGuard<()> },
}

/// Process-local keys of one mutation or lifecycle operation.
#[must_use = "dropping the guard releases the local mutation locks"]
pub struct LocalMutationGuard {
    _guards: Vec<LocalKeyGuard>,
    _order: lock_order::Held,
}

/// Local and, on `PostgreSQL`, distributed keys of one guarded mutation.
#[must_use = "dropping the guard releases the mutation locks"]
pub struct MutationGuard {
    // Field order is drop order: the hold is recorded while the keys are
    // still held, then the database guard goes so its connection returns to
    // the lock pool (and is unlocked) as early as possible.
    _hold: HoldTimer,
    _distributed: DistributedMutationGuard,
    _local: LocalMutationGuard,
}

/// Times one [`MutationGuard`] from acquisition to release. Guarded work has
/// no time limit of its own, so a hold longer than the wait timeout means
/// conflicting acquisitions may have timed out behind it.
struct HoldTimer {
    scope: LockScope,
    acquired: tokio::time::Instant,
    warn_after: Duration,
}

impl Drop for HoldTimer {
    fn drop(&mut self) {
        let held = self.acquired.elapsed();
        gateway_metrics::record_lock_hold(self.scope, held);
        if held > self.warn_after {
            warn!(
                scope = self.scope.label(),
                held_ms = duration_millis(held),
                "mutation lock held longer than the lock wait timeout"
            );
        }
    }
}

impl ComputeRuntime {
    /// Serialize a cross-object mutation against every conflicting mutation
    /// on this and, on `PostgreSQL`, every other replica.
    ///
    /// One `MUTATION_LOCK_TIMEOUT` deadline covers the local keys, the
    /// lock-pool connection, and the advisory locks. Missing it fails with
    /// [`PersistenceError::LockTimeout`]: the mutation lock was not acquired,
    /// so the caller's guarded writes did not run. A lock connection that
    /// `PostgreSQL` does not open with at least `LOCK_CONNECTION_MIN_BUDGET`
    /// left fails with [`PersistenceError::Database`]. Timeouts count in
    /// `openshell_server_mutation_lock_timeouts_total` and other failures in
    /// `openshell_server_mutation_lock_errors_total`.
    ///
    /// Nothing bounds how long the guard is held. Dropping it records the
    /// hold in `openshell_server_mutation_lock_hold_seconds`, and logs a
    /// warning when the hold outlasted the wait timeout.
    pub(crate) async fn mutation_guard(
        &self,
        scope: MutationScope<'_>,
    ) -> PersistenceResult<MutationGuard> {
        let started = tokio::time::Instant::now();
        let timeout = self.mutation_locks.timeout();
        let result = self
            .acquire_mutation_guard(
                &scope.lock_set(),
                started + timeout,
                scope.lock_scope(),
                timeout,
            )
            .await;
        match &result {
            Ok(_) => gateway_metrics::record_lock_wait(scope.lock_scope(), started.elapsed()),
            Err(PersistenceError::LockTimeout(detail)) => {
                gateway_metrics::record_lock_timeout(scope.lock_scope());
                warn!(
                    scope = scope.lock_scope().label(),
                    waited_ms = duration_millis(started.elapsed()),
                    detail = %detail,
                    "mutation lock acquisition timed out"
                );
            }
            Err(error) => {
                gateway_metrics::record_lock_error(scope.lock_scope());
                warn!(
                    scope = scope.lock_scope().label(),
                    waited_ms = duration_millis(started.elapsed()),
                    error = %error,
                    "mutation lock acquisition failed"
                );
            }
        }
        result
    }

    /// Acquire `set` by `deadline`. The guard's hold is labeled `scope` and
    /// warns past `warn_after`.
    async fn acquire_mutation_guard(
        &self,
        set: &MutationLockSet,
        deadline: tokio::time::Instant,
        scope: LockScope,
        warn_after: Duration,
    ) -> PersistenceResult<MutationGuard> {
        let local = tokio::time::timeout_at(deadline, self.mutation_locks.acquire(set))
            .await
            .map_err(|_| {
                PersistenceError::LockTimeout("waiting for a local mutation lock".into())
            })?;
        let distributed = self
            .store
            .acquire_distributed_mutation_guard(set, deadline)
            .await?;
        Ok(MutationGuard {
            _hold: HoldTimer {
                scope,
                acquired: tokio::time::Instant::now(),
                warn_after,
            },
            _distributed: distributed,
            _local: local,
        })
    }

    /// Sandbox-scoped guard for paths that know only the sandbox id, such as
    /// supervisor reports.
    ///
    /// A sandbox's workspace never changes, so one read before locking
    /// derives the key set. Callers must re-read the sandbox after locking and
    /// never validate against this read. Returns `Ok(None)` when the sandbox
    /// does not exist.
    pub(crate) async fn sandbox_mutation_guard_by_id(
        &self,
        sandbox_id: &str,
    ) -> PersistenceResult<Option<MutationGuard>> {
        let Some(sandbox) = self.store.get_message::<Sandbox>(sandbox_id).await? else {
            return Ok(None);
        };
        self.mutation_guard(MutationScope::sandbox(
            sandbox.object_workspace(),
            sandbox_id,
        ))
        .await
        .map(Some)
    }

    /// Lifecycle gate, then the sandbox-scoped mutation guard, for a new
    /// sandbox.
    pub(crate) async fn sandbox_create_guards(
        &self,
        workspace: &str,
        sandbox_id: &str,
    ) -> PersistenceResult<(SandboxLifecycleGuard, MutationGuard)> {
        let lifecycle_guard = self.lifecycle_gates.lock_for(sandbox_id).await;
        let mutation_guard = self
            .mutation_guard(MutationScope::sandbox(workspace, sandbox_id))
            .await?;
        Ok((lifecycle_guard, mutation_guard))
    }

    /// Local S(global) X(sandbox) for code that already holds the sandbox's
    /// lifecycle gate. The guard parameter documents and enforces the
    /// lifecycle-gate -> mutation-lock order.
    pub(super) async fn lock_sandbox_for_lifecycle(
        &self,
        lifecycle_guard: &SandboxLifecycleGuard,
    ) -> LocalMutationGuard {
        self.lock_sandbox_local(&lifecycle_guard.sandbox_id).await
    }

    /// Local S(global) X(sandbox) for lifecycle, driver-watch, and reconcile
    /// paths. They write only this sandbox and its owned records and rely on
    /// compare-and-swap across replicas, so they take no database lock and
    /// never exclude another sandbox or a provider writer.
    pub(super) async fn lock_sandbox_local(&self, sandbox_id: &str) -> LocalMutationGuard {
        self.mutation_locks
            .acquire(&MutationLockSet::sandbox_lifecycle(sandbox_id))
            .await
    }

    /// Local S(global) S(workspace) X(sandbox), for provisioning-deadline
    /// reconciliation, which re-derives configuration from provider and
    /// profile records and must not interleave with their local writers.
    pub(super) async fn lock_sandbox_local_in_workspace(
        &self,
        workspace: &str,
        sandbox_id: &str,
    ) -> LocalMutationGuard {
        self.mutation_locks
            .acquire(&MutationScope::sandbox(workspace, sandbox_id).lock_set())
            .await
    }

    /// Shorten the mutation lock deadline of this runtime and its clones.
    #[cfg(test)]
    pub(crate) fn set_mutation_lock_timeout_for_tests(&self, timeout: Duration) {
        self.mutation_locks.set_timeout_for_tests(timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_metrics::MetricsCapture;
    use crate::persistence::Store;
    use crate::persistence::mutation_lock::GLOBAL_MUTATION_LOCK_KEY;
    use crate::persistence::test_postgres::TestSchema;
    use openshell_core::GetResourceVersion;
    use openshell_core::proto::SandboxPhase;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::sync::atomic::{AtomicBool, AtomicIsize};
    use tokio::task::JoinHandle;
    use uuid::Uuid;

    const BLOCKED_FOR: Duration = Duration::from_millis(100);
    const PROCEEDS_WITHIN: Duration = Duration::from_secs(5);

    async fn test_runtime() -> ComputeRuntime {
        let store = Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .expect("in-memory store"),
        );
        super::super::new_test_runtime_for_driver(store, "test").await
    }

    fn spawn_guard(
        runtime: &ComputeRuntime,
        scope: MutationScope<'static>,
    ) -> JoinHandle<MutationGuard> {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            runtime
                .mutation_guard(scope)
                .await
                .expect("mutation guard acquired")
        })
    }

    fn spawn_local(runtime: &ComputeRuntime, sandbox_id: &'static str) -> JoinHandle<()> {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            drop(runtime.lock_sandbox_local(sandbox_id).await);
        })
    }

    async fn assert_blocked<T>(handle: &mut JoinHandle<T>, what: &str) {
        assert!(
            tokio::time::timeout(BLOCKED_FOR, handle).await.is_err(),
            "{what} should wait"
        );
    }

    async fn assert_proceeds<T>(handle: JoinHandle<T>, what: &str) -> T {
        tokio::time::timeout(PROCEEDS_WITHIN, handle)
            .await
            .unwrap_or_else(|_| panic!("{what} should proceed"))
            .expect("guard task")
    }

    fn keys(entries: &[(MutationLockKey<'_>, LockMode)]) -> Vec<(i64, LockMode)> {
        let mut keys: Vec<_> = entries
            .iter()
            .map(|(key, mode)| (key.advisory_key(), *mode))
            .collect();
        keys.sort_unstable();
        keys
    }

    #[test]
    fn scope_lock_sets_follow_the_hierarchy() {
        use LockMode::{Exclusive, Shared};
        use MutationLockKey::{Global, Sandbox as SandboxKey, Workspace};

        let cases = [
            (MutationScope::Global, keys(&[(Global, Exclusive)])),
            (MutationScope::profiles(""), keys(&[(Global, Exclusive)])),
            (
                MutationScope::profiles("team-a"),
                keys(&[(Global, Shared), (Workspace("team-a"), Exclusive)]),
            ),
            (
                MutationScope::Workspace("team-a"),
                keys(&[(Global, Shared), (Workspace("team-a"), Exclusive)]),
            ),
            (
                MutationScope::sandbox("team-a", "sb-1"),
                keys(&[
                    (Global, Shared),
                    (Workspace("team-a"), Shared),
                    (SandboxKey("sb-1"), Exclusive),
                ]),
            ),
            (
                MutationScope::sandbox("", "sb-1"),
                keys(&[
                    (Global, Shared),
                    (Workspace("default"), Shared),
                    (SandboxKey("sb-1"), Exclusive),
                ]),
            ),
        ];
        for (scope, expected) in cases {
            assert_eq!(
                scope.lock_set().iter().collect::<Vec<_>>(),
                expected,
                "{scope:?}"
            );
        }
        assert_eq!(
            MutationLockSet::sandbox_lifecycle("sb-1")
                .iter()
                .collect::<Vec<_>>(),
            keys(&[(Global, Shared), (SandboxKey("sb-1"), Exclusive)])
        );
        assert!(
            MutationScope::Global
                .lock_set()
                .iter()
                .eq([(GLOBAL_MUTATION_LOCK_KEY, Exclusive)])
        );
    }

    #[test]
    fn scope_labels_map_platform_profiles_to_global() {
        assert_eq!(MutationScope::Global.lock_scope(), LockScope::Global);
        assert_eq!(MutationScope::profiles("").lock_scope(), LockScope::Global);
        assert_eq!(
            MutationScope::profiles("team-a").lock_scope(),
            LockScope::Workspace
        );
        assert_eq!(
            MutationScope::Workspace("team-a").lock_scope(),
            LockScope::Workspace
        );
        assert_eq!(
            MutationScope::sandbox("", "sb-1").lock_scope(),
            LockScope::Sandbox
        );
    }

    #[tokio::test]
    async fn sandbox_guards_for_different_sandboxes_proceed_concurrently() {
        let runtime = test_runtime().await;
        let held = runtime
            .mutation_guard(MutationScope::sandbox("w1", "a"))
            .await
            .unwrap();

        let other = spawn_guard(&runtime, MutationScope::sandbox("w1", "b"));
        drop(assert_proceeds(other, "a different sandbox in the same workspace").await);
        drop(held);
    }

    #[tokio::test]
    async fn same_sandbox_guard_waits_until_release() {
        let runtime = test_runtime().await;
        let held = runtime
            .mutation_guard(MutationScope::sandbox("w1", "a"))
            .await
            .unwrap();

        let mut same = spawn_guard(&runtime, MutationScope::sandbox("w1", "a"));
        assert_blocked(&mut same, "the same sandbox").await;
        drop(held);
        drop(assert_proceeds(same, "the same sandbox after release").await);
    }

    #[tokio::test]
    async fn workspace_guard_blocks_sandbox_scope_in_that_workspace_only() {
        let runtime = test_runtime().await;
        let held = runtime
            .mutation_guard(MutationScope::Workspace("w1"))
            .await
            .unwrap();

        let mut same_workspace = spawn_guard(&runtime, MutationScope::sandbox("w1", "a"));
        assert_blocked(&mut same_workspace, "a sandbox in the held workspace").await;
        let other_sandbox = spawn_guard(&runtime, MutationScope::sandbox("w2", "b"));
        drop(assert_proceeds(other_sandbox, "a sandbox in another workspace").await);
        let other_workspace = spawn_guard(&runtime, MutationScope::Workspace("w2"));
        drop(assert_proceeds(other_workspace, "another workspace").await);

        drop(held);
        drop(assert_proceeds(same_workspace, "the sandbox after release").await);
    }

    #[tokio::test]
    async fn global_guard_blocks_every_scope_and_lifecycle_lock() {
        let runtime = test_runtime().await;
        let held = runtime.mutation_guard(MutationScope::Global).await.unwrap();

        let mut waiting_guards = vec![
            spawn_guard(&runtime, MutationScope::Global),
            spawn_guard(&runtime, MutationScope::profiles("")),
            spawn_guard(&runtime, MutationScope::Workspace("w1")),
            spawn_guard(&runtime, MutationScope::sandbox("w1", "a")),
        ];
        for waiting in &mut waiting_guards {
            assert_blocked(waiting, "a guard behind the global guard").await;
        }
        let mut lifecycle = spawn_local(&runtime, "b");
        assert_blocked(&mut lifecycle, "a lifecycle lock behind the global guard").await;
        let reconcile_runtime = runtime.clone();
        let mut reconcile = tokio::spawn(async move {
            drop(
                reconcile_runtime
                    .lock_sandbox_local_in_workspace("w1", "c")
                    .await,
            );
        });
        assert_blocked(&mut reconcile, "a reconcile lock behind the global guard").await;

        drop(held);
        for waiting in waiting_guards {
            drop(assert_proceeds(waiting, "a guard after release").await);
        }
        assert_proceeds(lifecycle, "the lifecycle lock after release").await;
        assert_proceeds(reconcile, "the reconcile lock after release").await;
    }

    #[tokio::test]
    async fn queued_global_guard_is_not_starved() {
        let runtime = test_runtime().await;
        let held = runtime
            .mutation_guard(MutationScope::sandbox("w", "a"))
            .await
            .unwrap();

        let mut global = spawn_guard(&runtime, MutationScope::Global);
        assert_blocked(&mut global, "the global guard behind a sandbox guard").await;
        let mut later = spawn_guard(&runtime, MutationScope::sandbox("w", "b"));
        assert_blocked(&mut later, "a sandbox guard queued behind the global guard").await;

        drop(held);
        let global = assert_proceeds(global, "the queued global guard").await;
        assert_blocked(&mut later, "a sandbox guard while the global guard holds").await;
        drop(global);
        drop(assert_proceeds(later, "the later sandbox guard").await);
    }

    #[tokio::test]
    async fn lifecycle_lock_excludes_same_sandbox_only() {
        let runtime = test_runtime().await;
        let held = runtime.lock_sandbox_local("a").await;

        let mut same = spawn_guard(&runtime, MutationScope::sandbox("w", "a"));
        assert_blocked(&mut same, "the sandbox held by a lifecycle lock").await;
        let other = spawn_guard(&runtime, MutationScope::sandbox("w", "b"));
        drop(assert_proceeds(other, "another sandbox").await);
        let provider = spawn_guard(&runtime, MutationScope::Workspace("w"));
        drop(assert_proceeds(provider, "a provider writer").await);

        drop(held);
        drop(assert_proceeds(same, "the sandbox after release").await);
    }

    #[tokio::test]
    async fn legacy_empty_workspace_sandbox_conflicts_with_default_workspace_writer() {
        let runtime = test_runtime().await;
        let held = runtime
            .mutation_guard(MutationScope::Workspace("default"))
            .await
            .unwrap();

        let mut legacy = spawn_guard(&runtime, MutationScope::sandbox("", "a"));
        assert_blocked(
            &mut legacy,
            "a legacy sandbox behind a default-workspace writer",
        )
        .await;
        drop(held);
        drop(assert_proceeds(legacy, "the legacy sandbox after release").await);
    }

    #[tokio::test]
    async fn local_registry_stays_bounded() {
        let runtime = test_runtime().await;
        let held = lock_order::branch(runtime.mutation_guard(MutationScope::sandbox("w", "held")))
            .await
            .unwrap();

        // Few live keys: released keys pile up to the minimum, never past it.
        let mut peak = 0;
        for i in 0..4 * LOCK_TABLE_MIN_SWEEP_LEN {
            drop(runtime.lock_sandbox_local(&format!("sb-{i}")).await);
            let entries = runtime.mutation_locks.entry_count();
            assert!(entries <= LOCK_TABLE_MIN_SWEEP_LEN, "{entries} entries");
            peak = peak.max(entries);
        }
        assert_eq!(peak, LOCK_TABLE_MIN_SWEEP_LEN, "sweeps are not per call");

        // Sweeps keep the held global, workspace, and sandbox keys.
        assert_eq!(runtime.mutation_locks.live_entry_count(), 3);
        let held_key = MutationLockKey::Sandbox("held").advisory_key();
        assert_eq!(runtime.mutation_locks.key_references(held_key), 1);
        drop(held);
        assert_eq!(runtime.mutation_locks.live_entry_count(), 0);
    }

    #[tokio::test]
    async fn local_registry_bound_scales_with_live_keys() {
        const HELD: usize = 50;
        let runtime = test_runtime().await;
        let mut held = Vec::new();
        for i in 0..HELD {
            held.push(lock_order::branch(runtime.lock_sandbox_local(&format!("held-{i}"))).await);
        }

        // A sweep keeps the held sandbox keys, the global key, and the key
        // being inserted, then lets the table grow to twice that.
        let bound = 2 * (HELD + 2);
        let mut peak = 0;
        for i in 0..4 * HELD {
            drop(runtime.lock_sandbox_local(&format!("sb-{i}")).await);
            let entries = runtime.mutation_locks.entry_count();
            assert!(entries <= bound, "{entries} entries");
            peak = peak.max(entries);
        }
        assert_eq!(peak, bound, "sweeps wait until the table doubles");
        assert_eq!(runtime.mutation_locks.live_entry_count(), HELD + 1);

        drop(held);
        assert_eq!(runtime.mutation_locks.live_entry_count(), 0);
    }

    #[tokio::test]
    async fn cancelled_acquisition_leaves_no_queue_entry() {
        let runtime = test_runtime().await;
        let held = runtime
            .mutation_guard(MutationScope::sandbox("w", "a"))
            .await
            .unwrap();
        let mut waiter = spawn_guard(&runtime, MutationScope::sandbox("w", "a"));
        assert_blocked(&mut waiter, "the waiter").await;
        waiter.abort();
        let Err(error) = waiter.await else {
            panic!("the aborted waiter should not acquire the guard");
        };
        assert!(error.is_cancelled());
        drop(held);

        let next = spawn_guard(&runtime, MutationScope::sandbox("w", "a"));
        drop(assert_proceeds(next, "a new acquisition after the cancelled one").await);
        assert_eq!(runtime.mutation_locks.live_entry_count(), 0);
    }

    #[tokio::test]
    async fn local_timeout_returns_lock_timeout_and_unavailable() {
        let runtime = test_runtime().await;
        runtime.set_mutation_lock_timeout_for_tests(Duration::from_millis(50));
        let held = lock_order::branch(runtime.mutation_guard(MutationScope::sandbox("w", "a")))
            .await
            .unwrap();

        let Err(error) = runtime
            .mutation_guard(MutationScope::sandbox("w", "a"))
            .await
        else {
            panic!("the second acquisition should time out");
        };
        assert!(
            matches!(error, PersistenceError::LockTimeout(_)),
            "{error:?}"
        );
        let status = crate::grpc::persistence_error_to_status(error, "op");
        assert_eq!(status.code(), tonic::Code::Unavailable);
        let details = openshell_core::rpc_error::decode_details(&status).expect("error details");
        assert_eq!(
            details.error_info().expect("error info").reason,
            "MUTATION_LOCK_TIMEOUT"
        );
        drop(held);
        assert_eq!(runtime.mutation_locks.live_entry_count(), 0);
    }

    #[tokio::test]
    async fn lock_metrics_record_wait_and_timeout() {
        const WAITS: &str = "openshell_server_mutation_lock_wait_seconds_count{scope=\"sandbox\"}";
        const TIMEOUTS: &str = "openshell_server_mutation_lock_timeouts_total{scope=\"sandbox\"}";
        const ERRORS: &str = "openshell_server_mutation_lock_errors_total{scope=\"sandbox\"}";
        let metrics = MetricsCapture::install();
        let runtime = test_runtime().await;
        runtime.set_mutation_lock_timeout_for_tests(Duration::from_millis(50));

        let held = lock_order::branch(runtime.mutation_guard(MutationScope::sandbox("w", "a")))
            .await
            .unwrap();
        assert_eq!(metrics.value(WAITS), Some(1));
        assert_eq!(metrics.value(TIMEOUTS), None);

        assert!(
            runtime
                .mutation_guard(MutationScope::sandbox("w", "a"))
                .await
                .is_err()
        );
        assert_eq!(metrics.value(TIMEOUTS), Some(1));
        assert_eq!(
            metrics.value(ERRORS),
            None,
            "a timeout is not also an error"
        );
        assert_eq!(metrics.value(WAITS), Some(1));

        drop(runtime.lock_sandbox_local("b").await);
        assert_eq!(metrics.value(WAITS), Some(1));
        drop(held);
    }

    #[tokio::test]
    async fn lock_connection_failure_counts_as_a_lock_error_not_a_timeout() {
        const TIMEOUTS: &str = "openshell_server_mutation_lock_timeouts_total{scope=\"sandbox\"}";
        const ERRORS: &str = "openshell_server_mutation_lock_errors_total{scope=\"sandbox\"}";
        let metrics = MetricsCapture::install();
        let url = crate::persistence::PostgresStore::refusing_url_for_tests().await;
        let store = crate::persistence::PostgresStore::connect_lazy_for_tests(&url, 1);
        let runtime =
            super::super::new_test_runtime_for_driver(Arc::new(Store::Postgres(store)), "test")
                .await;
        // Leave enough time to open a lock connection, so the refusal is a
        // database error.
        runtime.set_mutation_lock_timeout_for_tests(
            crate::persistence::mutation_lock::LOCK_CONNECTION_MIN_BUDGET
                + Duration::from_millis(300),
        );

        match runtime
            .mutation_guard(MutationScope::sandbox("w", "a"))
            .await
        {
            Err(PersistenceError::Database(detail)) => assert!(
                detail.starts_with("could not open a mutation lock connection"),
                "{detail}"
            ),
            Err(error) => panic!("expected a database error, got {error:?}"),
            Ok(_) => panic!("nothing listens, yet the guard was acquired"),
        }
        assert_eq!(metrics.value(TIMEOUTS), None);
        assert_eq!(metrics.value(ERRORS), Some(1));
    }

    /// Formatted log output of the current thread's tracing subscriber.
    #[derive(Clone, Default)]
    struct LogLines(Arc<StdMutex<Vec<u8>>>);

    impl LogLines {
        fn count(&self, message: &str) -> usize {
            String::from_utf8_lossy(&self.0.lock().unwrap())
                .matches(message)
                .count()
        }
    }

    impl std::io::Write for LogLines {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn lock_hold_is_recorded_when_a_stalled_guard_is_released() {
        const HOLDS: &str = "openshell_server_mutation_lock_hold_seconds_count{scope=\"sandbox\"}";
        // Holds no longer than the 50 ms wait timeout.
        const SHORT_HOLDS: &str =
            "openshell_server_mutation_lock_hold_seconds_bucket{scope=\"sandbox\",le=\"0.05\"}";
        const HELD_TOO_LONG: &str = "mutation lock held longer than the lock wait timeout";
        let metrics = MetricsCapture::install();
        let logs = LogLines::default();
        let _logs = crate::otel_tracing::test_exporter::install_scoped(
            tracing_subscriber::fmt()
                .with_writer({
                    let logs = logs.clone();
                    move || logs.clone()
                })
                .with_ansi(false)
                .finish(),
        );
        let runtime = test_runtime().await;
        let timeout = Duration::from_millis(50);
        runtime.set_mutation_lock_timeout_for_tests(timeout);

        drop(
            runtime
                .mutation_guard(MutationScope::sandbox("w", "a"))
                .await
                .unwrap(),
        );
        assert_eq!(metrics.value(HOLDS), Some(1));
        assert_eq!(metrics.value(SHORT_HOLDS), Some(1));
        assert_eq!(logs.count(HELD_TOO_LONG), 0, "a short hold does not warn");

        // A stalled holder: a waiter on its scope times out behind it, and the
        // hold is recorded only once the holder releases.
        let stalled = runtime
            .mutation_guard(MutationScope::sandbox("w", "a"))
            .await
            .unwrap();
        let waiter = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .mutation_guard(MutationScope::sandbox("w", "a"))
                    .await
                    .map(drop)
            })
        };
        let result = waiter.await.expect("waiter task");
        assert!(
            matches!(result, Err(PersistenceError::LockTimeout(_))),
            "{result:?}"
        );
        tokio::time::sleep(timeout).await;
        assert_eq!(
            metrics.value(HOLDS),
            Some(1),
            "a failed acquisition holds nothing"
        );

        drop(stalled);
        assert_eq!(metrics.value(HOLDS), Some(2));
        assert_eq!(
            metrics.value(SHORT_HOLDS),
            Some(1),
            "the stalled hold outlasted the wait timeout"
        );
        assert_eq!(logs.count(HELD_TOO_LONG), 1);
    }

    /// Workspaces and sandboxes the random scope mix draws from.
    const MIX_WORKSPACES: usize = 3;
    const MIX_SANDBOXES: usize = 8;

    /// Names of the random scope mix's workspaces and sandboxes.
    struct MixNames {
        workspaces: [String; MIX_WORKSPACES],
        sandboxes: [String; MIX_SANDBOXES],
    }

    impl MixNames {
        fn new(prefix: &str) -> Self {
            Self {
                workspaces: std::array::from_fn(|index| format!("{prefix}w{index}")),
                sandboxes: std::array::from_fn(|index| format!("{prefix}s{index}")),
            }
        }
    }

    /// One step of a random-mix task, as indices into [`MixNames`].
    #[derive(Clone, Copy)]
    enum MixOp {
        Global,
        Workspace(usize),
        Sandbox(usize, usize),
        Lifecycle(usize),
        GatedLifecycle(usize),
    }

    impl MixOp {
        fn random(rng: &mut StdRng) -> Self {
            match rng.random_range(0..4) {
                0 => Self::Global,
                1 => Self::Workspace(rng.random_range(0..MIX_WORKSPACES)),
                2 => Self::Sandbox(
                    rng.random_range(0..MIX_WORKSPACES),
                    rng.random_range(0..MIX_SANDBOXES),
                ),
                _ => {
                    let sandbox = rng.random_range(0..MIX_SANDBOXES);
                    if rng.random_bool(0.5) {
                        Self::GatedLifecycle(sandbox)
                    } else {
                        Self::Lifecycle(sandbox)
                    }
                }
            }
        }

        /// Mutation guards also take `PostgreSQL` advisory locks, so they
        /// exclude conflicting guards on every replica. Lifecycle locks are
        /// process-local.
        const fn is_distributed(self) -> bool {
            matches!(self, Self::Global | Self::Workspace(_) | Self::Sandbox(..))
        }
    }

    /// Holders of each key, changed only while the matching guard is held, so
    /// lost exclusion panics instead of passing silently. A counter is `-1`
    /// under an exclusive holder and otherwise counts shared holders. A
    /// sandbox flag marks the holder of that sandbox key, which does not
    /// depend on the workspace.
    #[derive(Default)]
    struct Occupancy {
        global: AtomicIsize,
        workspaces: [AtomicIsize; MIX_WORKSPACES],
        sandboxes: [AtomicBool; MIX_SANDBOXES],
    }

    impl Occupancy {
        fn share(counter: &AtomicIsize) {
            assert!(
                counter.fetch_add(1, Ordering::SeqCst) >= 0,
                "shared holder entered under an exclusive holder"
            );
        }

        fn exclude(counter: &AtomicIsize) {
            assert!(
                counter
                    .compare_exchange(0, -1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok(),
                "exclusive holder entered while the key was occupied"
            );
        }

        fn claim(sandbox: &AtomicBool) {
            assert!(
                !sandbox.swap(true, Ordering::SeqCst),
                "sandbox entered twice"
            );
        }

        fn enter(&self, op: MixOp) {
            match op {
                MixOp::Global => Self::exclude(&self.global),
                MixOp::Workspace(workspace) => {
                    Self::share(&self.global);
                    Self::exclude(&self.workspaces[workspace]);
                }
                MixOp::Sandbox(workspace, sandbox) => {
                    Self::share(&self.global);
                    Self::share(&self.workspaces[workspace]);
                    Self::claim(&self.sandboxes[sandbox]);
                }
                MixOp::Lifecycle(sandbox) | MixOp::GatedLifecycle(sandbox) => {
                    Self::share(&self.global);
                    Self::claim(&self.sandboxes[sandbox]);
                }
            }
        }

        fn leave(&self, op: MixOp) {
            match op {
                MixOp::Global => self.global.store(0, Ordering::SeqCst),
                MixOp::Workspace(workspace) => {
                    self.workspaces[workspace].store(0, Ordering::SeqCst);
                    self.global.fetch_sub(1, Ordering::SeqCst);
                }
                MixOp::Sandbox(workspace, sandbox) => {
                    self.sandboxes[sandbox].store(false, Ordering::SeqCst);
                    self.workspaces[workspace].fetch_sub(1, Ordering::SeqCst);
                    self.global.fetch_sub(1, Ordering::SeqCst);
                }
                MixOp::Lifecycle(sandbox) | MixOp::GatedLifecycle(sandbox) => {
                    self.sandboxes[sandbox].store(false, Ordering::SeqCst);
                    self.global.fetch_sub(1, Ordering::SeqCst);
                }
            }
        }

        fn assert_empty(&self) {
            assert_eq!(self.global.load(Ordering::SeqCst), 0);
            assert!(
                self.workspaces
                    .iter()
                    .all(|workspace| workspace.load(Ordering::SeqCst) == 0)
            );
            assert!(
                self.sandboxes
                    .iter()
                    .all(|sandbox| !sandbox.load(Ordering::SeqCst))
            );
        }
    }

    /// Enter `op`'s keys, keep them for `hold`, then leave them in reverse
    /// order. `local` is the occupancy of the replica that runs `op`; mutation
    /// guards also enter `fleet`. The caller holds `op`'s guards throughout.
    async fn occupy(local: &Occupancy, fleet: &Occupancy, op: MixOp, hold: Duration) {
        local.enter(op);
        if op.is_distributed() {
            fleet.enter(op);
        }
        tokio::time::sleep(hold).await;
        if op.is_distributed() {
            fleet.leave(op);
        }
        local.leave(op);
    }

    /// Run `tasks` tasks of `iterations` random operations each, spread
    /// round-robin over `replicas`, holding each operation's locks for 0-2 ms.
    /// Every operation must acquire its locks and finish `within`.
    async fn run_random_scope_mix(
        replicas: &[ComputeRuntime],
        prefix: &str,
        tasks: usize,
        iterations: usize,
        within: Duration,
    ) {
        let names = Arc::new(MixNames::new(prefix));
        let fleet = Arc::new(Occupancy::default());
        let locals: Vec<Arc<Occupancy>> = replicas.iter().map(|_| Arc::default()).collect();
        let mut rng = StdRng::seed_from_u64(3528);
        let mut handles = Vec::new();
        for task in 0..tasks {
            let plan: Vec<(MixOp, u64)> = (0..iterations)
                .map(|_| {
                    let op = MixOp::random(&mut rng);
                    (op, rng.random_range(0..=2))
                })
                .collect();
            let replica = task % replicas.len();
            let runtime = replicas[replica].clone();
            let names = Arc::clone(&names);
            let fleet = Arc::clone(&fleet);
            let local = Arc::clone(&locals[replica]);
            handles.push(tokio::spawn(async move {
                for (op, hold_ms) in plan {
                    let hold = Duration::from_millis(hold_ms);
                    match op {
                        MixOp::Global => {
                            let _guard = runtime
                                .mutation_guard(MutationScope::Global)
                                .await
                                .expect("guard");
                            occupy(&local, &fleet, op, hold).await;
                        }
                        MixOp::Workspace(workspace) => {
                            let scope = MutationScope::Workspace(&names.workspaces[workspace]);
                            let _guard = runtime.mutation_guard(scope).await.expect("guard");
                            occupy(&local, &fleet, op, hold).await;
                        }
                        MixOp::Sandbox(workspace, sandbox) => {
                            let scope = MutationScope::sandbox(
                                &names.workspaces[workspace],
                                &names.sandboxes[sandbox],
                            );
                            let _guard = runtime.mutation_guard(scope).await.expect("guard");
                            occupy(&local, &fleet, op, hold).await;
                        }
                        MixOp::Lifecycle(sandbox) => {
                            let _guard =
                                runtime.lock_sandbox_local(&names.sandboxes[sandbox]).await;
                            occupy(&local, &fleet, op, hold).await;
                        }
                        MixOp::GatedLifecycle(sandbox) => {
                            let gate = runtime
                                .lifecycle_gates
                                .lock_for(&names.sandboxes[sandbox])
                                .await;
                            let _guard = runtime.lock_sandbox_for_lifecycle(&gate).await;
                            occupy(&local, &fleet, op, hold).await;
                        }
                    }
                }
            }));
        }

        tokio::time::timeout(within, async {
            for handle in handles {
                handle.await.expect("stress task");
            }
        })
        .await
        .expect("random scope mix finished without a deadlock");
        for runtime in replicas {
            assert_eq!(runtime.mutation_locks.live_entry_count(), 0);
        }
        fleet.assert_empty();
        for local in &locals {
            local.assert_empty();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn random_scope_mix_never_deadlocks() {
        let runtime = test_runtime().await;
        run_random_scope_mix(&[runtime], "", 64, 50, Duration::from_secs(20)).await;
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "platform scope")]
    fn empty_workspace_scope_panics_in_debug_builds() {
        let _ = MutationScope::Workspace("").lock_set();
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    #[should_panic(expected = "mutation lock ordering violated")]
    async fn nested_mutation_guard_panics_in_debug_builds() {
        let runtime = test_runtime().await;
        let _held = runtime
            .mutation_guard(MutationScope::sandbox("w", "a"))
            .await
            .unwrap();
        // A different sandbox, so the scheme alone would not deadlock here.
        let _nested = runtime
            .mutation_guard(MutationScope::sandbox("w", "b"))
            .await;
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn lock_order_branches_are_separate_owners() {
        let runtime = test_runtime().await;
        let (gate_tx, gate_rx) = tokio::sync::oneshot::channel::<()>();
        let first = async {
            let _guard = runtime
                .mutation_guard(MutationScope::sandbox("w", "a"))
                .await
                .unwrap();
            gate_rx.await.unwrap();
        };
        let second = async {
            let _guard = runtime
                .mutation_guard(MutationScope::sandbox("w", "b"))
                .await
                .unwrap();
            gate_tx.send(()).unwrap();
        };
        tokio::join!(lock_order::branch(first), lock_order::branch(second));

        let nested = tokio::spawn({
            let runtime = runtime.clone();
            async move {
                lock_order::branch(async {
                    let _outer = runtime.lock_sandbox_local("c").await;
                    drop(runtime.lock_sandbox_local("d").await);
                })
                .await;
            }
        });
        assert!(
            nested.await.unwrap_err().is_panic(),
            "nesting inside a branch"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn lock_order_check_is_per_task_and_covers_rules_1_and_5() {
        let runtime = test_runtime().await;
        let held = runtime
            .mutation_guard(MutationScope::sandbox("w", "a"))
            .await
            .unwrap();
        // Another task may take a guard while this one holds its own.
        drop(
            assert_proceeds(
                spawn_guard(&runtime, MutationScope::sandbox("w", "b")),
                "another task",
            )
            .await,
        );

        let nested_in_task = tokio::spawn({
            let runtime = runtime.clone();
            async move {
                let _outer = runtime.lock_sandbox_local("c").await;
                drop(runtime.lock_sandbox_local("d").await);
            }
        });
        assert!(
            nested_in_task.await.unwrap_err().is_panic(),
            "rule 4 in a spawned task"
        );

        let gate_under_local = tokio::spawn({
            let runtime = runtime.clone();
            async move {
                let _local = runtime.lock_sandbox_local("e").await;
                drop(runtime.lifecycle_gates.lock_for("e").await);
            }
        });
        assert!(gate_under_local.await.unwrap_err().is_panic(), "rule 1");

        let guard_under_ssh = tokio::spawn({
            let runtime = runtime.clone();
            async move {
                let _ssh = runtime
                    .store
                    .acquire_ssh_identity_mutation_guard()
                    .await
                    .unwrap();
                drop(
                    runtime
                        .mutation_guard(MutationScope::sandbox("w", "f"))
                        .await,
                );
            }
        });
        assert!(guard_under_ssh.await.unwrap_err().is_panic(), "rule 5");

        // Gate first, then local keys, then SSH identity under a guard: allowed.
        let allowed = tokio::spawn({
            let runtime = runtime.clone();
            async move {
                let gate = runtime.lifecycle_gates.lock_for("g").await;
                let guard = runtime
                    .mutation_guard(MutationScope::sandbox("w", "g"))
                    .await
                    .unwrap();
                drop(
                    runtime
                        .store
                        .acquire_ssh_identity_mutation_guard()
                        .await
                        .unwrap(),
                );
                drop(guard);
                drop(runtime.lock_sandbox_for_lifecycle(&gate).await);
            }
        });
        allowed.await.expect("ordered acquisitions");

        drop(held);
        drop(
            runtime
                .mutation_guard(MutationScope::sandbox("w", "a"))
                .await
                .unwrap(),
        );
    }

    #[tokio::test]
    async fn unrelated_supervisor_state_update_does_not_wait_for_sandbox_guard() {
        let runtime = test_runtime().await;
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "mutation-guard-unrelated-a".to_string(),
                name: "mutation-guard-unrelated-a".to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Provisioning as i32);
        runtime.store.put_message(&sandbox).await.unwrap();
        let held = lock_order::branch(runtime.mutation_guard(MutationScope::sandbox(
            "default",
            "mutation-guard-unrelated-b",
        )))
        .await
        .unwrap();

        tokio::time::timeout(
            PROCEEDS_WITHIN,
            runtime.supervisor_session_connected("mutation-guard-unrelated-a", "i"),
        )
        .await
        .expect("an unrelated supervisor update should not wait")
        .expect("supervisor session connected");
        let stored = runtime
            .store
            .get_message::<Sandbox>("mutation-guard-unrelated-a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.phase(), SandboxPhase::Ready as i32);
        drop(held);
    }

    /// A runtime on its own store connected to `schema`, like one gateway
    /// replica.
    async fn postgres_runtime(schema: &TestSchema) -> ComputeRuntime {
        let store = Arc::new(schema.connect_store().await);
        super::super::new_test_runtime_for_driver(store, "test").await
    }

    fn stored_sandbox(sandbox_id: &str, workspace: &str) -> Sandbox {
        Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: sandbox_id.to_string(),
                name: sandbox_id.to_string(),
                workspace: workspace.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
    async fn postgres_compute_guards_random_scope_mix_never_deadlocks() {
        let schema = TestSchema::create("mix").await;
        let replicas = [
            postgres_runtime(&schema).await,
            postgres_runtime(&schema).await,
        ];
        // Advisory locks are database-wide, so the mix uses fresh names.
        let prefix = format!("{}-", Uuid::new_v4().simple());

        run_random_scope_mix(&replicas, &prefix, 32, 20, Duration::from_mins(1)).await;

        for replica in &replicas {
            replica.store.close().await;
        }
        schema.drop_schema().await;
    }

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
    async fn postgres_compute_guard_by_id_uses_the_sandbox_workspace() {
        let schema = TestSchema::create("guard").await;
        let replica_a = postgres_runtime(&schema).await;
        let replica_b = postgres_runtime(&schema).await;
        let workspace = format!("ws-{}", Uuid::new_v4());
        let sandbox_id = format!("sb-{}", Uuid::new_v4());
        replica_a
            .store
            .put_message(&stored_sandbox(&sandbox_id, &workspace))
            .await
            .expect("seed the sandbox");

        // Only the database locks connect the two replicas.
        let held = replica_b
            .mutation_guard(MutationScope::Workspace(&workspace))
            .await
            .expect("workspace guard on replica B");
        let mut by_id = {
            let replica_a = replica_a.clone();
            let sandbox_id = sandbox_id.clone();
            tokio::spawn(async move { replica_a.sandbox_mutation_guard_by_id(&sandbox_id).await })
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut by_id)
                .await
                .is_err(),
            "the by-id guard should wait for the sandbox's workspace"
        );
        drop(held);
        let guard = tokio::time::timeout(PROCEEDS_WITHIN, by_id)
            .await
            .expect("the by-id guard should proceed after release")
            .expect("guard task")
            .expect("by-id guard");
        assert!(guard.is_some(), "the seeded sandbox exists");
        drop(guard);

        assert!(
            replica_a
                .sandbox_mutation_guard_by_id(&format!("sb-{}", Uuid::new_v4()))
                .await
                .expect("by-id guard for an unknown sandbox")
                .is_none()
        );

        replica_a.store.close().await;
        replica_b.store.close().await;
        schema.drop_schema().await;
    }

    /// Measures lock waits in a paced reconnect burst into one replica: one
    /// session every 12 ms (1000 sessions spread over 12 s), all into one
    /// receiving replica with the production lock pool. Run it with
    /// `--no-capture` to see the wait percentiles.
    ///
    /// This capacity check runs the lock pool near saturation, so machine load
    /// moves the waits. `mise run test:rust:postgres` and CI skip it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres:bench"]
    async fn bench_postgres_lock_pool_absorbs_a_12ms_reconnect_burst() {
        /// Sessions that move to the receiving replica.
        const RECONNECTS: usize = 500;
        /// One reconnect every 12 ms, as for 1000 sessions spread over 12 s.
        const RECONNECT_INTERVAL: Duration = Duration::from_millis(12);
        /// Guarded operations per reconnect on the receiver: the pre-ack
        /// endpoint-status reset and one endpoint report.
        const GUARDED_OPS_PER_RECONNECT: usize = 2;
        /// Extra time under the guard, so each critical section takes about
        /// 20 ms, like one against a managed database.
        const CRITICAL_SECTION_PADDING: Duration = Duration::from_millis(15);

        let schema = TestSchema::create("envelope").await;
        // The production lock pool, as on a real receiving replica.
        let receiver = postgres_runtime(&schema).await;
        let workspace = format!("ws-{}", Uuid::new_v4());
        let mut sandbox_ids = Vec::with_capacity(RECONNECTS);
        for _ in 0..RECONNECTS {
            let sandbox_id = format!("sb-{}", Uuid::new_v4());
            receiver
                .store
                .put_message(&stored_sandbox(&sandbox_id, &workspace))
                .await
                .expect("seed a sandbox");
            sandbox_ids.push(sandbox_id);
        }

        let started = tokio::time::Instant::now();
        let reconnects: Vec<_> = sandbox_ids
            .into_iter()
            .enumerate()
            .map(|(index, sandbox_id)| {
                let receiver = receiver.clone();
                let arrives = started
                    + RECONNECT_INTERVAL * u32::try_from(index).expect("reconnect index fits u32");
                tokio::spawn(async move {
                    tokio::time::sleep_until(arrives).await;
                    let mut waits = Vec::with_capacity(GUARDED_OPS_PER_RECONNECT);
                    for op in 0..GUARDED_OPS_PER_RECONNECT {
                        let called = tokio::time::Instant::now();
                        let guard = receiver
                            .sandbox_mutation_guard_by_id(&sandbox_id)
                            .await?
                            .expect("seeded sandbox");
                        waits.push(called.elapsed());
                        let sandbox = receiver
                            .store
                            .get_message::<Sandbox>(&sandbox_id)
                            .await?
                            .expect("seeded sandbox");
                        receiver
                            .store
                            .update_message_cas::<Sandbox, _>(
                                &sandbox_id,
                                sandbox.get_resource_version(),
                                |sandbox| {
                                    sandbox
                                        .metadata
                                        .as_mut()
                                        .expect("sandbox metadata")
                                        .labels
                                        .insert("envelope-op".to_string(), op.to_string());
                                },
                            )
                            .await?;
                        tokio::time::sleep(CRITICAL_SECTION_PADDING).await;
                        drop(guard);
                    }
                    Ok::<_, PersistenceError>(waits)
                })
            })
            .collect();
        let mut waits = Vec::with_capacity(RECONNECTS * GUARDED_OPS_PER_RECONNECT);
        for reconnect in reconnects {
            match reconnect.await.expect("reconnect task") {
                Ok(reconnect_waits) => waits.extend(reconnect_waits),
                Err(error) => panic!("a guarded reconnect operation failed: {error:?}"),
            }
        }

        waits.sort_unstable();
        let percentile = |percent: usize| waits[(waits.len() * percent).div_ceil(100) - 1];
        let (p50, p99) = (percentile(50), percentile(99));
        let max = waits[waits.len() - 1];
        eprintln!(
            "reconnect burst: {} guarded ops from {RECONNECTS} reconnects {RECONNECT_INTERVAL:?} \
             apart into one receiver: lock wait p50 {p50:?}, p99 {p99:?}, max {max:?}",
            waits.len()
        );
        // Waits must stay far from the lock timeout, where requests fail.
        assert!(
            p99 * 5 < MUTATION_LOCK_TIMEOUT,
            "p99 lock wait {p99:?} is too close to the {MUTATION_LOCK_TIMEOUT:?} timeout"
        );

        receiver.store.close().await;
        schema.drop_schema().await;
    }
}
