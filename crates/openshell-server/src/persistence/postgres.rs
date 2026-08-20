// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::mutation_lock::{
    LOCK_CONNECTION_MIN_BUDGET, LockMode, MUTATION_LOCK_POOL_MAX_CONNECTIONS,
    MUTATION_LOCK_TIMEOUT, MUTATION_LOCK_TIMEOUT_SETTING, MutationLockSet,
};
use super::{
    DraftChunkRecord, ObjectCursor, ObjectListQuery, ObjectRecord, PersistenceError,
    PersistenceResult, PolicyRecord, WriteCondition, WriteResult, current_time_ms, map_db_error,
    map_migrate_error,
};
use crate::policy_store::{
    AtomicPolicyRevisionWrite, apply_draft_chunk_evaluation, draft_chunk_evaluation_inputs_match,
    draft_chunk_payload_from_record, draft_chunk_record_from_parts, policy_payload_from_record,
    policy_record_for_atomic_write, policy_record_from_parts, project_policy_revision_onto_sandbox,
};
use openshell_core::SetResourceVersion;
use openshell_core::proto::Sandbox;
use prost::Message;
use sqlx::pool::PoolConnection;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgPool, Postgres, QueryBuilder, Row};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

#[cfg(test)]
pub(super) fn embedded_migration_sql(version: i64) -> Option<&'static str> {
    POSTGRES_MIGRATOR
        .iter()
        .find(|migration| migration.version == version)
        .map(|migration| migration.sql.as_ref())
}

use super::{DELETE_MANY_BATCH_SIZE, DRAFT_CHUNK_OBJECT_TYPE, POLICY_OBJECT_TYPE};

#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: PgPool,
    /// Dedicated connections for session-level mutation advisory locks.
    lock_pool: PgPool,
    /// How acquisitions and guards use the lock pool's connections.
    lock_usage: Arc<LockPoolUsage>,
}

/// Lock-pool connections checked out by acquisitions and guards.
#[derive(Debug)]
struct LockPoolUsage {
    /// Connections the lock pool may open.
    max: u32,
    /// Checked-out connections, each counted until its pool permit is
    /// released.
    in_use: AtomicU32,
    /// How many times `in_use` reached `max`.
    became_full: AtomicU64,
}

/// What a wait for a lock connection saw of the pool when it started.
#[derive(Clone, Copy)]
struct LockPoolSnapshot {
    full: bool,
    became_full: u64,
}

impl LockPoolUsage {
    fn new(max: u32) -> Self {
        Self {
            max,
            in_use: AtomicU32::new(0),
            became_full: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> LockPoolSnapshot {
        // Read the counter first: if the pool fills between the two reads,
        // either read shows it.
        let became_full = self.became_full.load(Ordering::Acquire);
        LockPoolSnapshot {
            full: self.in_use.load(Ordering::Acquire) >= self.max,
            became_full,
        }
    }

    /// Whether every connection was checked out at some point since `start`.
    /// A connection handed from one guard to the next leaves the count one
    /// short only briefly, so a contended pool keeps filling up again.
    fn was_full_since(&self, start: LockPoolSnapshot) -> bool {
        start.full || self.became_full.load(Ordering::Acquire) != start.became_full
    }
}

/// Detail of a lock-pool connection that `PostgreSQL` did not open by the
/// deadline, though it had at least [`LOCK_CONNECTION_MIN_BUDGET`]. `SQLx`
/// retries refused connections, `too_many_connections` (53300), and
/// `cannot_connect_now` (57P03) silently until then.
const LOCK_CONNECTION_NOT_OPENED: &str = "could not open a mutation lock connection: \
     PostgreSQL refused the connection, had no free connection slot, was starting up, \
     or did not answer before the deadline";

/// How long the client waits past the caller's deadline for a lock statement.
///
/// Each statement sets `lock_timeout` to the remaining deadline, so
/// `PostgreSQL` ends the wait on time; this timer only catches a stalled
/// connection.
const LOCK_STATEMENT_CLIENT_GRACE: Duration = Duration::from_millis(500);

/// Bound the complete pool return, including the unlock hook and `SQLx`'s ping.
/// A stalled connection must not retain a lock-pool permit indefinitely.
pub(super) const LOCK_CONNECTION_RELEASE_TIMEOUT: Duration = Duration::from_secs(5);

/// Holds the mutation advisory locks of one acquisition.
///
/// Returned to the lock pool on drop; `after_release` runs
/// `pg_advisory_unlock_all()` before reuse. The entire return is bounded by
/// [`LOCK_CONNECTION_RELEASE_TIMEOUT`]. An acquisition that `PostgreSQL`
/// times out (`55P03`) is returned the same way. A cancelled or otherwise failed
/// acquisition closes its session instead (see [`PendingLockConnection`]).
pub(super) struct PostgresAdvisoryLockGuard {
    connection: PoolConnection<Postgres>,
    checkout: LockConnectionCheckout,
}

/// Holds a session-level advisory lock on a data-pool connection, which is
/// closed on drop.
pub(super) struct PostgresDataPoolLockGuard {
    _connection: PoolConnection<Postgres>,
}

impl Drop for PostgresAdvisoryLockGuard {
    fn drop(&mut self) {
        return_lock_connection(&mut self.connection, std::mem::take(&mut self.checkout));
    }
}

/// Counts one checked-out lock-pool connection in [`LockPoolUsage`] until
/// dropped. Its holder drops it only after the connection's pool permit is
/// released.
#[derive(Default)]
struct LockConnectionCheckout(Option<Arc<LockPoolUsage>>);

impl LockConnectionCheckout {
    fn new(usage: &Arc<LockPoolUsage>) -> Self {
        if usage.in_use.fetch_add(1, Ordering::AcqRel) + 1 >= usage.max {
            usage.became_full.fetch_add(1, Ordering::AcqRel);
        }
        Self(Some(Arc::clone(usage)))
    }
}

impl Drop for LockConnectionCheckout {
    fn drop(&mut self) {
        if let Some(usage) = self.0.take() {
            usage.in_use.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn return_lock_connection(
    connection: &mut PoolConnection<Postgres>,
    checkout: LockConnectionCheckout,
) {
    // SQLx transfers the connection and pool permit into this owned future
    // immediately. Dropping it on timeout closes the socket and releases the
    // permit, including when the unlock hook succeeded but the final ping stalls.
    // This relies on sqlx-core 0.9's doc-hidden `PoolConnection::return_to_pool`;
    // rerun the `postgres_mutation_lock_stalled_release_*` test on any sqlx bump.
    let returning = connection.return_to_pool();
    tokio::spawn(async move {
        let _checkout = checkout;
        if tokio::time::timeout(LOCK_CONNECTION_RELEASE_TIMEOUT, returning)
            .await
            .is_err()
        {
            tracing::warn!(
                "timed out returning PostgreSQL mutation lock connection; discarded connection"
            );
        }
    });
}

#[cfg(test)]
impl PostgresAdvisoryLockGuard {
    /// Backend process id of the session that holds the locks.
    pub(super) async fn backend_pid(&mut self) -> i32 {
        let Self { connection, .. } = self;
        sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut **connection)
            .await
            .expect("read the lock session's backend pid")
    }
}

/// A lock-pool connection whose acquisition is still in progress.
///
/// Dropping it closes the session, which releases every advisory lock the
/// backend holds once its current statement ends. A backend blocked on a lock
/// does not notice the closed socket, so each lock statement carries its own
/// `lock_timeout` to bound that wait by the caller's deadline.
struct PendingLockConnection {
    connection: Option<PoolConnection<Postgres>>,
    checkout: LockConnectionCheckout,
}

impl PendingLockConnection {
    fn new(connection: PoolConnection<Postgres>, usage: &Arc<LockPoolUsage>) -> Self {
        Self {
            connection: Some(connection),
            checkout: LockConnectionCheckout::new(usage),
        }
    }

    fn connection(&mut self) -> &mut PoolConnection<Postgres> {
        self.connection
            .as_mut()
            .expect("pending lock connection is present until disarmed")
    }

    /// Keep the session: every lock was acquired.
    fn into_guard(mut self) -> PostgresAdvisoryLockGuard {
        PostgresAdvisoryLockGuard {
            connection: self
                .connection
                .take()
                .expect("pending lock connection is present until disarmed"),
            checkout: std::mem::take(&mut self.checkout),
        }
    }

    /// Return the healthy session to the pool, whose `after_release` unlocks
    /// any keys it already holds.
    fn release(mut self) {
        if let Some(mut connection) = self.connection.take() {
            return_lock_connection(&mut connection, std::mem::take(&mut self.checkout));
        }
    }
}

impl Drop for PendingLockConnection {
    fn drop(&mut self) {
        if let Some(mut connection) = self.connection.take() {
            // Still closes the session if the task below never runs.
            connection.close_on_drop();
            let checkout = std::mem::take(&mut self.checkout);
            // `close` keeps the pool permit until the session is closed, and
            // the connection counts as checked out until then.
            tokio::spawn(async move {
                let _checkout = checkout;
                let _ =
                    tokio::time::timeout(LOCK_CONNECTION_RELEASE_TIMEOUT, connection.close()).await;
            });
        }
    }
}

/// Pool ceiling used when the operator has not configured one.
///
/// A single shared pool serves every database-backed RPC, so this value is
/// also the gateway's ceiling on concurrent database work. It is high enough
/// for a single-replica gateway against a default-sized server; fleets that
/// outgrow it raise it through `[openshell.gateway] database_max_connections`.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 10;

impl PostgresStore {
    /// Connect and size the pool, falling back to [`DEFAULT_MAX_CONNECTIONS`].
    pub async fn connect(url: &str, max_connections: Option<u32>) -> PersistenceResult<Self> {
        Self::connect_with_lock_pool_size(url, max_connections, MUTATION_LOCK_POOL_MAX_CONNECTIONS)
            .await
    }

    pub(super) async fn connect_with_lock_pool_size(
        url: &str,
        max_connections: Option<u32>,
        lock_pool_size: u32,
    ) -> PersistenceResult<Self> {
        let max_connections = max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS);
        tracing::info!(max_connections, "sizing Postgres connection pool");
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(url)
            .await
            .map_err(|e| map_db_error(&e))?;
        let lock_pool = PgPoolOptions::new()
            .max_connections(lock_pool_size)
            .min_connections(0)
            // Backstop only; callers bound the acquire by their own deadline.
            .acquire_timeout(MUTATION_LOCK_TIMEOUT)
            .after_connect(|connection, _metadata| {
                Box::pin(async move {
                    // Backstop only: every lock statement sets the remaining
                    // deadline of its own acquisition.
                    sqlx::query("SELECT set_config('lock_timeout', $1, false)")
                        .bind(MUTATION_LOCK_TIMEOUT_SETTING)
                        .execute(&mut *connection)
                        .await?;
                    Ok(())
                })
            })
            .after_release(|connection, _metadata| {
                Box::pin(async move {
                    // Scrub every returned lock connection. On error sqlx closes
                    // it, and the backend exit releases whatever it held.
                    sqlx::query("SELECT pg_advisory_unlock_all()")
                        .execute(&mut *connection)
                        .await?;
                    Ok(true)
                })
            })
            .connect_lazy(url)
            .map_err(|e| map_db_error(&e))?;

        Ok(Self {
            pool,
            lock_pool,
            lock_usage: Arc::new(LockPoolUsage::new(lock_pool_size)),
        })
    }

    pub async fn migrate(&self) -> PersistenceResult<()> {
        POSTGRES_MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|e| map_migrate_error(&e))?;
        self.migrate_legacy_time_payloads().await
    }

    async fn migrate_legacy_time_payloads(&self) -> PersistenceResult<()> {
        let mut transaction = self.pool.begin().await.map_err(|e| map_db_error(&e))?;
        // Serialize this application-level data migration across gateway replicas.
        sqlx::query("SELECT pg_advisory_xact_lock(3052)")
            .execute(&mut *transaction)
            .await
            .map_err(|e| map_db_error(&e))?;
        let rows =
            sqlx::query("SELECT id, object_type, payload FROM objects ORDER BY id FOR UPDATE")
                .fetch_all(&mut *transaction)
                .await
                .map_err(|e| map_db_error(&e))?;

        for row in rows {
            let id: String = row.try_get("id").map_err(|e| map_db_error(&e))?;
            let object_type: String = row.try_get("object_type").map_err(|e| map_db_error(&e))?;
            let payload: Vec<u8> = row.try_get("payload").map_err(|e| map_db_error(&e))?;
            let migrated =
                super::legacy_time_wire::migrate(&object_type, &payload).map_err(|error| {
                    PersistenceError::Migration(format!(
                        "failed to migrate {object_type} record {id}: {error}"
                    ))
                })?;
            if migrated != payload {
                sqlx::query("UPDATE objects SET payload = $1 WHERE id = $2")
                    .bind(migrated)
                    .bind(id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(|e| map_db_error(&e))?;
            }
        }

        transaction.commit().await.map_err(|e| map_db_error(&e))
    }

    /// Verify the database is reachable by acquiring a pooled connection
    /// and issuing a protocol-level ping.
    pub async fn ping(&self) -> PersistenceResult<()> {
        let mut conn = self.pool.acquire().await.map_err(|e| map_db_error(&e))?;
        conn.ping().await.map_err(|e| map_db_error(&e))
    }

    /// Acquire `locks` as session-level advisory locks, in ascending key
    /// order, on one lock-pool connection.
    ///
    /// Fails with [`PersistenceError::LockTimeout`] when the lock connections
    /// stay checked out, too little time is left to open one, or a lock is
    /// not granted by `deadline`, and with [`PersistenceError::Database`] when
    /// `PostgreSQL` does not open a lock connection in at least
    /// [`LOCK_CONNECTION_MIN_BUDGET`].
    pub(super) async fn acquire_mutation_locks(
        &self,
        locks: &MutationLockSet,
        deadline: tokio::time::Instant,
    ) -> PersistenceResult<PostgresAdvisoryLockGuard> {
        let usage_at_start = self.lock_usage.snapshot();
        let budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        let connection = match tokio::time::timeout_at(deadline, self.lock_pool.acquire()).await {
            Err(_) | Ok(Err(sqlx::Error::PoolTimedOut)) => {
                return Err(self.lock_connection_timeout(usage_at_start, budget));
            }
            Ok(Err(error)) => {
                return Err(PersistenceError::Database(format!(
                    "could not open a mutation lock connection: {error}"
                )));
            }
            Ok(Ok(connection)) => connection,
        };
        let mut pending = PendingLockConnection::new(connection, &self.lock_usage);
        for (key, mode) in locks.iter() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining < Duration::from_millis(1) {
                // Nothing waits server-side; `after_release` unlocks the keys
                // taken so far.
                pending.release();
                return Err(PersistenceError::LockTimeout(
                    "waiting for a PostgreSQL advisory lock".into(),
                ));
            }
            // `set_config` and the lock run in one statement. A CTE that calls
            // a volatile function is never inlined, and the outer projection
            // needs its row, so `lock_timeout` is set before the lock wait
            // starts. PostgreSQL then abandons the wait at the caller's
            // deadline even if this future is cancelled and the socket closed.
            let sql = match mode {
                LockMode::Shared => {
                    "WITH timeout AS (SELECT set_config('lock_timeout', $1, false)) \
                     SELECT pg_advisory_lock_shared($2) FROM timeout"
                }
                LockMode::Exclusive => {
                    "WITH timeout AS (SELECT set_config('lock_timeout', $1, false)) \
                     SELECT pg_advisory_lock($2) FROM timeout"
                }
            };
            let statement = sqlx::query(sql)
                .bind(format!("{}ms", remaining.as_millis()))
                .bind(key)
                .execute(&mut **pending.connection());
            match tokio::time::timeout_at(deadline + LOCK_STATEMENT_CLIENT_GRACE, statement).await {
                Err(_) => {
                    return Err(PersistenceError::LockTimeout(
                        "waiting for a PostgreSQL advisory lock".into(),
                    ));
                }
                Ok(Err(error)) => {
                    // 55P03 lock_not_available: the statement's own
                    // `lock_timeout` ended the wait. The session is healthy:
                    // return it; `after_release` unlocks the keys already held.
                    if let Some(db) = error.as_database_error()
                        && db.code().as_deref() == Some("55P03")
                    {
                        let detail = db.message().to_string();
                        pending.release();
                        return Err(PersistenceError::LockTimeout(detail));
                    }
                    return Err(map_db_error(&error));
                }
                Ok(Ok(_)) => {}
            }
        }
        Ok(pending.into_guard())
    }

    /// Acquire `key` as a session-level advisory lock on a data-pool
    /// connection instead of the mutation lock pool. Sandbox creation takes
    /// the SSH identity lock while it holds its mutation guard, so a second
    /// lock-pool connection there could exhaust that pool. The wait uses the
    /// mutation lock timeout as its `lock_timeout`. Closing the connection on
    /// drop releases the lock.
    pub(super) async fn acquire_data_pool_lock(
        &self,
        key: i64,
    ) -> PersistenceResult<PostgresDataPoolLockGuard> {
        let mut connection = self.pool.acquire().await.map_err(|e| map_db_error(&e))?;
        connection.close_on_drop();
        sqlx::query("SELECT set_config('lock_timeout', $1, false)")
            .bind(MUTATION_LOCK_TIMEOUT_SETTING)
            .execute(&mut *connection)
            .await
            .map_err(|e| map_db_error(&e))?;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(key)
            .execute(&mut *connection)
            .await
            .map_err(|e| map_db_error(&e))?;
        Ok(PostgresDataPoolLockGuard {
            _connection: connection,
        })
    }

    /// The error of a lock-pool acquire that ran out of time.
    ///
    /// If every lock connection was checked out at some point during the
    /// wait, the acquire waited for one to come back, which is lock
    /// contention. So is a wait that started with less than
    /// [`LOCK_CONNECTION_MIN_BUDGET`] left: an earlier wait, such as for
    /// local keys, used up the deadline. Otherwise the pool had room the whole
    /// time and `PostgreSQL` did not open a new connection.
    fn lock_connection_timeout(
        &self,
        start: LockPoolSnapshot,
        budget: Duration,
    ) -> PersistenceError {
        if budget < LOCK_CONNECTION_MIN_BUDGET || self.lock_usage.was_full_since(start) {
            PersistenceError::LockTimeout("waiting for a mutation lock connection".into())
        } else {
            PersistenceError::Database(LOCK_CONNECTION_NOT_OPENED.into())
        }
    }

    /// Connections the lock pool holds, idle or in use.
    #[cfg(test)]
    pub(super) fn lock_pool_size(&self) -> u32 {
        self.lock_pool.size()
    }

    /// Lock-pool connections that are connected and ready for reuse.
    #[cfg(test)]
    pub(super) fn lock_pool_idle(&self) -> usize {
        self.lock_pool.num_idle()
    }

    /// Test support only: close the underlying connection pools.
    ///
    /// Do not call from runtime code; this tears down the active pools.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn close(&self) {
        self.pool.close().await;
        self.lock_pool.close().await;
    }

    pub async fn put(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<()> {
        let now_ms = current_time_ms();
        let labels_jsonb: Option<serde_json::Value> = labels
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| PersistenceError::Encode(format!("invalid labels JSON: {e}")))?;

        sqlx::query(
            r"
INSERT INTO objects (object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels)
VALUES ($1, $2, $3, $4, $5, $6, $6, COALESCE($7, '{}'::jsonb))
ON CONFLICT (object_type, workspace, name) WHERE name IS NOT NULL DO UPDATE SET
    payload = EXCLUDED.payload,
    updated_at_ms = EXCLUDED.updated_at_ms,
    labels = EXCLUDED.labels
",
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(workspace)
        .bind(payload)
        .bind(now_ms)
        .bind(labels_jsonb)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    /// Create an object; Postgres commits are always durable, so this is
    /// [`Self::put_if`] with [`WriteCondition::MustCreate`].
    pub async fn create_relaxed(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<WriteResult> {
        self.put_if(
            object_type,
            id,
            name,
            workspace,
            payload,
            labels,
            WriteCondition::MustCreate,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_if(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        payload: &[u8],
        labels: Option<&str>,
        condition: WriteCondition,
    ) -> PersistenceResult<WriteResult> {
        let now_ms = current_time_ms();
        let labels_jsonb: Option<serde_json::Value> = labels
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| PersistenceError::Encode(format!("invalid labels JSON: {e}")))?;

        match condition {
            WriteCondition::MustCreate => {
                // Insert only - fail if object exists
                let row = sqlx::query(
                    r"
INSERT INTO objects (object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version)
VALUES ($1, $2, $3, $4, $5, $6, $6, COALESCE($7, '{}'::jsonb), 1)
RETURNING resource_version, created_at_ms, updated_at_ms
",
                )
                .bind(object_type)
                .bind(id)
                .bind(name)
                .bind(workspace)
                .bind(payload)
                .bind(now_ms)
                .bind(labels_jsonb)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| map_db_error(&e))?;

                let resource_version_i64: i64 = row.try_get("resource_version").unwrap_or(1);
                Ok(WriteResult {
                    resource_version: resource_version_i64.max(1).cast_unsigned(),
                    created_at_ms: row.get("created_at_ms"),
                    updated_at_ms: row.get("updated_at_ms"),
                })
            }
            WriteCondition::MatchResourceVersion(expected_version) => {
                // Update with version check using RETURNING
                let row_result = sqlx::query(
                    r"
UPDATE objects
SET payload = $4, labels = COALESCE($5, '{}'::jsonb), updated_at_ms = $6, resource_version = resource_version + 1
WHERE object_type = $1 AND id = $2 AND resource_version = $3
RETURNING resource_version, created_at_ms, updated_at_ms
",
                )
                .bind(object_type)
                .bind(id)
                .bind(i64::try_from(expected_version).unwrap_or(i64::MAX))
                .bind(payload)
                .bind(labels_jsonb)
                .bind(now_ms)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_db_error(&e))?;

                if let Some(row) = row_result {
                    let resource_version_i64: i64 = row.try_get("resource_version").unwrap_or(1);
                    Ok(WriteResult {
                        resource_version: resource_version_i64.max(1).cast_unsigned(),
                        created_at_ms: row.get("created_at_ms"),
                        updated_at_ms: row.get("updated_at_ms"),
                    })
                } else {
                    // The version-matched UPDATE matched no row. Distinguish a
                    // version mismatch (row present, different version) from an
                    // absent row (deleted / never existed). Both are CAS
                    // precondition failures, so report them as typed `Conflict`
                    // rather than a backend-dependent error string: absent rows
                    // carry `current_resource_version: None`.
                    let existing = self.get(object_type, id).await?;
                    Err(PersistenceError::Conflict {
                        current_resource_version: existing.map(|record| record.resource_version),
                    })
                }
            }
            WriteCondition::Unconditional => {
                // Unconditional upsert by name
                let row = sqlx::query(
                    r"
INSERT INTO objects (object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version)
VALUES ($1, $2, $3, $4, $5, $6, $6, COALESCE($7, '{}'::jsonb), 1)
ON CONFLICT (object_type, workspace, name) WHERE name IS NOT NULL DO UPDATE SET
    payload = EXCLUDED.payload,
    updated_at_ms = EXCLUDED.updated_at_ms,
    labels = EXCLUDED.labels,
    resource_version = objects.resource_version + 1
RETURNING resource_version, created_at_ms, updated_at_ms
",
                )
                .bind(object_type)
                .bind(id)
                .bind(name)
                .bind(workspace)
                .bind(payload)
                .bind(now_ms)
                .bind(labels_jsonb)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| map_db_error(&e))?;

                let resource_version_i64: i64 = row.try_get("resource_version").unwrap_or(1);
                Ok(WriteResult {
                    resource_version: resource_version_i64.max(1).cast_unsigned(),
                    created_at_ms: row.get("created_at_ms"),
                    updated_at_ms: row.get("updated_at_ms"),
                })
            }
        }
    }

    pub async fn delete_if(
        &self,
        object_type: &str,
        id: &str,
        expected_resource_version: u64,
    ) -> PersistenceResult<bool> {
        let result = sqlx::query(
            r"
DELETE FROM objects
WHERE object_type = $1 AND id = $2 AND resource_version = $3
",
        )
        .bind(object_type)
        .bind(id)
        .bind(i64::try_from(expected_resource_version).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        if result.rows_affected() > 0 {
            Ok(true)
        } else {
            // Check if object exists to distinguish NotFound from Conflict
            let existing = self.get(object_type, id).await?;
            if let Some(record) = existing {
                Err(PersistenceError::Conflict {
                    current_resource_version: Some(record.resource_version),
                })
            } else {
                Ok(false)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_scoped(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        scope: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<()> {
        let now_ms = current_time_ms();
        let labels_jsonb: Option<serde_json::Value> = labels
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| PersistenceError::Encode(format!("invalid labels JSON: {e}")))?;

        sqlx::query(
            r"
INSERT INTO objects (object_type, id, name, workspace, scope, payload, created_at_ms, updated_at_ms, labels, resource_version)
VALUES ($1, $2, $3, $4, $5, $6, $7, $7, COALESCE($8, '{}'::jsonb), 1)
ON CONFLICT (object_type, workspace, name) WHERE name IS NOT NULL DO UPDATE SET
    scope = EXCLUDED.scope,
    payload = EXCLUDED.payload,
    updated_at_ms = EXCLUDED.updated_at_ms,
    labels = EXCLUDED.labels,
    resource_version = objects.resource_version + 1
",
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(workspace)
        .bind(scope)
        .bind(payload)
        .bind(now_ms)
        .bind(labels_jsonb)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_scoped(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        scope: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<WriteResult> {
        let now_ms = current_time_ms();
        let labels_jsonb: Option<serde_json::Value> = labels
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| PersistenceError::Encode(format!("invalid labels JSON: {e}")))?;

        let row = sqlx::query(
            r"
INSERT INTO objects (object_type, id, name, workspace, scope, payload, created_at_ms, updated_at_ms, labels, resource_version)
VALUES ($1, $2, $3, $4, $5, $6, $7, $7, COALESCE($8, '{}'::jsonb), 1)
RETURNING resource_version, created_at_ms, updated_at_ms
",
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(workspace)
        .bind(scope)
        .bind(payload)
        .bind(now_ms)
        .bind(labels_jsonb)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        let resource_version_i64: i64 = row.try_get("resource_version").unwrap_or(1);
        Ok(WriteResult {
            resource_version: resource_version_i64.max(1).cast_unsigned(),
            created_at_ms: row.get("created_at_ms"),
            updated_at_ms: row.get("updated_at_ms"),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_if_workspace_count_below(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        payload: &[u8],
        labels: Option<&str>,
        max_count: u64,
    ) -> PersistenceResult<Option<WriteResult>> {
        let now_ms = current_time_ms();
        let labels_jsonb: Option<serde_json::Value> = labels
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| PersistenceError::Encode(format!("invalid labels JSON: {e}")))?;
        let mut tx = self.pool.begin().await.map_err(|e| map_db_error(&e))?;

        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
            .bind(object_type)
            .bind(workspace)
            .execute(&mut *tx)
            .await
            .map_err(|e| map_db_error(&e))?;

        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM objects WHERE object_type = $1 AND workspace = $2",
        )
        .bind(object_type)
        .bind(workspace)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;
        let count = u64::try_from(row.0).unwrap_or(0);
        if count >= max_count {
            tx.commit().await.map_err(|e| map_db_error(&e))?;
            return Ok(None);
        }

        let row = sqlx::query(
            r"
INSERT INTO objects (object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version)
VALUES ($1, $2, $3, $4, $5, $6, $6, COALESCE($7, '{}'::jsonb), 1)
RETURNING resource_version, created_at_ms, updated_at_ms
",
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(workspace)
        .bind(payload)
        .bind(now_ms)
        .bind(labels_jsonb)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;

        tx.commit().await.map_err(|e| map_db_error(&e))?;

        let resource_version_i64: i64 = row.try_get("resource_version").unwrap_or(1);
        Ok(Some(WriteResult {
            resource_version: resource_version_i64.max(1).cast_unsigned(),
            created_at_ms: row.get("created_at_ms"),
            updated_at_ms: row.get("updated_at_ms"),
        }))
    }

    pub async fn get(
        &self,
        object_type: &str,
        id: &str,
    ) -> PersistenceResult<Option<ObjectRecord>> {
        let row = sqlx::query(
            r"
SELECT object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version
FROM objects
WHERE object_type = $1 AND id = $2
",
        )
        .bind(object_type)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.map(row_to_object_record))
    }

    pub async fn get_by_name(
        &self,
        object_type: &str,
        workspace: &str,
        name: &str,
    ) -> PersistenceResult<Option<ObjectRecord>> {
        let row = sqlx::query(
            r"
SELECT object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version
FROM objects
WHERE object_type = $1 AND workspace = $2 AND name = $3
",
        )
        .bind(object_type)
        .bind(workspace)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.map(row_to_object_record))
    }

    pub async fn delete(&self, object_type: &str, id: &str) -> PersistenceResult<bool> {
        let result = sqlx::query("DELETE FROM objects WHERE object_type = $1 AND id = $2")
            .bind(object_type)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_many(&self, object_type: &str, ids: &[String]) -> PersistenceResult<u64> {
        let mut deleted = 0_u64;
        for ids in ids.chunks(DELETE_MANY_BATCH_SIZE) {
            let mut query =
                QueryBuilder::<Postgres>::new("DELETE FROM objects WHERE object_type = ");
            query.push_bind(object_type).push(" AND id IN (");
            let mut separated = query.separated(", ");
            for id in ids {
                separated.push_bind(id);
            }
            separated.push_unseparated(")");

            deleted += query
                .build()
                .execute(&self.pool)
                .await
                .map_err(|e| map_db_error(&e))?
                .rows_affected();
        }
        Ok(deleted)
    }

    pub async fn count_in_workspace(
        &self,
        object_type: &str,
        workspace: &str,
    ) -> PersistenceResult<u64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM objects WHERE object_type = $1 AND workspace = $2",
        )
        .bind(object_type)
        .bind(workspace)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(u64::try_from(row.0).unwrap_or(0))
    }

    pub async fn delete_all_in_workspace(
        &self,
        object_type: &str,
        workspace: &str,
    ) -> PersistenceResult<u64> {
        let result = sqlx::query("DELETE FROM objects WHERE object_type = $1 AND workspace = $2")
            .bind(object_type)
            .bind(workspace)
            .execute(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected())
    }

    pub async fn delete_by_scope(&self, object_type: &str, scope: &str) -> PersistenceResult<u64> {
        let result = sqlx::query("DELETE FROM objects WHERE object_type = $1 AND scope = $2")
            .bind(object_type)
            .bind(scope)
            .execute(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected())
    }

    pub async fn delete_by_name(
        &self,
        object_type: &str,
        workspace: &str,
        name: &str,
    ) -> PersistenceResult<bool> {
        let result = sqlx::query(
            "DELETE FROM objects WHERE object_type = $1 AND workspace = $2 AND name = $3",
        )
        .bind(object_type)
        .bind(workspace)
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list(
        &self,
        object_type: &str,
        workspace: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r"
SELECT object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version
FROM objects
WHERE object_type = $1 AND workspace = $2
ORDER BY created_at_ms ASC, name ASC
LIMIT $3 OFFSET $4
",
        )
        .bind(object_type)
        .bind(workspace)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_by_type(
        &self,
        object_type: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r"
SELECT object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version
FROM objects
WHERE object_type = $1
ORDER BY created_at_ms ASC, name ASC, workspace ASC, id ASC
LIMIT $2 OFFSET $3
",
        )
        .bind(object_type)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }
    pub async fn list_after(
        &self,
        object_type: &str,
        workspace: &str,
        after: Option<&ObjectCursor>,
        limit: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = if let Some(cursor) = after {
            sqlx::query("SELECT object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version FROM objects WHERE object_type = $1 AND workspace = $2 AND (created_at_ms, name, id) > ($3, $4, $5) ORDER BY created_at_ms, name, id LIMIT $6").bind(object_type).bind(workspace).bind(cursor.created_at_ms).bind(&cursor.name).bind(&cursor.id).bind(i64::from(limit)).fetch_all(&self.pool).await
        } else {
            sqlx::query("SELECT object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version FROM objects WHERE object_type = $1 AND workspace = $2 ORDER BY created_at_ms, name, id LIMIT $3").bind(object_type).bind(workspace).bind(i64::from(limit)).fetch_all(&self.pool).await
        }.map_err(|e| map_db_error(&e))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }
    pub async fn list_by_type_after(
        &self,
        object_type: &str,
        after: Option<&ObjectCursor>,
        limit: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = if let Some(cursor) = after {
            sqlx::query("SELECT object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version FROM objects WHERE object_type = $1 AND (created_at_ms, name, workspace, id) > ($2, $3, $4, $5) ORDER BY created_at_ms, name, workspace, id LIMIT $6").bind(object_type).bind(cursor.created_at_ms).bind(&cursor.name).bind(&cursor.workspace).bind(&cursor.id).bind(i64::from(limit)).fetch_all(&self.pool).await
        } else {
            sqlx::query("SELECT object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version FROM objects WHERE object_type = $1 ORDER BY created_at_ms, name, workspace, id LIMIT $2").bind(object_type).bind(i64::from(limit)).fetch_all(&self.pool).await
        }.map_err(|e| map_db_error(&e))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_object_page(
        &self,
        object_type: &str,
        query: ObjectListQuery<'_>,
        after: Option<&ObjectCursor>,
        limit: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        use super::parse_label_selector;

        let mut sql = QueryBuilder::<Postgres>::new(
            "SELECT o.object_type, o.id, o.name, o.workspace, o.payload, \
             o.created_at_ms, o.updated_at_ms, o.labels, o.resource_version \
             FROM objects o WHERE o.object_type = ",
        );
        sql.push_bind(object_type);

        match query {
            ObjectListQuery::Workspace(workspace) => {
                sql.push(" AND o.workspace = ").push_bind(workspace);
            }
            ObjectListQuery::AllWorkspaces => {}
            ObjectListQuery::Scope(scope) => {
                sql.push(" AND o.scope = ").push_bind(scope);
            }
            ObjectListQuery::WorkspaceSelector {
                workspace,
                label_selector,
            } => {
                let labels = serde_json::to_value(parse_label_selector(label_selector)?)
                    .map_err(|e| PersistenceError::Encode(e.to_string()))?;
                sql.push(" AND o.workspace = ")
                    .push_bind(workspace)
                    .push(" AND o.labels @> ")
                    .push_bind(labels);
            }
            ObjectListQuery::AllWorkspacesSelector(label_selector) => {
                let labels = serde_json::to_value(parse_label_selector(label_selector)?)
                    .map_err(|e| PersistenceError::Encode(e.to_string()))?;
                sql.push(" AND o.labels @> ").push_bind(labels);
            }
            ObjectListQuery::Membership {
                member_type,
                member_name,
            } => {
                sql.push(
                    " AND o.workspace = '' AND EXISTS (SELECT 1 FROM objects m \
                          WHERE m.object_type = ",
                )
                .push_bind(member_type)
                .push(" AND m.workspace = o.name AND m.name = ")
                .push_bind(member_name)
                .push(")");
            }
            ObjectListQuery::MembershipSelector {
                member_type,
                member_name,
                label_selector,
            } => {
                let labels = serde_json::to_value(parse_label_selector(label_selector)?)
                    .map_err(|e| PersistenceError::Encode(e.to_string()))?;
                sql.push(
                    " AND o.workspace = '' AND EXISTS (SELECT 1 FROM objects m \
                          WHERE m.object_type = ",
                )
                .push_bind(member_type)
                .push(" AND m.workspace = o.name AND m.name = ")
                .push_bind(member_name)
                .push(") AND o.labels @> ")
                .push_bind(labels);
            }
        }

        if let Some(cursor) = after {
            sql.push(" AND (o.created_at_ms, COALESCE(o.name, ''), o.workspace, o.id) > (")
                .push_bind(cursor.created_at_ms)
                .push(", ")
                .push_bind(&cursor.name)
                .push(", ")
                .push_bind(&cursor.workspace)
                .push(", ")
                .push_bind(&cursor.id)
                .push(")");
        }
        sql.push(
            " ORDER BY o.created_at_ms ASC, COALESCE(o.name, '') ASC, \
             o.workspace ASC, o.id ASC LIMIT ",
        )
        .push_bind(i64::from(limit));

        let rows = sql
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_with_membership(
        &self,
        object_type: &str,
        member_type: &str,
        member_name: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r"
SELECT w.object_type, w.id, w.name, w.workspace, w.payload,
       w.created_at_ms, w.updated_at_ms, w.labels, w.resource_version
FROM objects w
WHERE w.object_type = $1 AND w.workspace = ''
AND EXISTS (
    SELECT 1 FROM objects m
    WHERE m.object_type = $2
    AND m.workspace = w.name
    AND m.name = $3
)
ORDER BY w.created_at_ms ASC, w.name ASC
LIMIT $4 OFFSET $5
",
        )
        .bind(object_type)
        .bind(member_type)
        .bind(member_name)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_with_membership_and_selector(
        &self,
        object_type: &str,
        member_type: &str,
        member_name: &str,
        label_selector: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        use super::parse_label_selector;

        let required_labels = parse_label_selector(label_selector)?;
        let labels_jsonb = serde_json::to_value(&required_labels)
            .map_err(|e| PersistenceError::Encode(format!("failed to serialize labels: {e}")))?;

        let rows = sqlx::query(
            r"
SELECT w.object_type, w.id, w.name, w.workspace, w.payload,
       w.created_at_ms, w.updated_at_ms, w.labels, w.resource_version
FROM objects w
WHERE w.object_type = $1 AND w.workspace = ''
AND EXISTS (
    SELECT 1 FROM objects m
    WHERE m.object_type = $2
    AND m.workspace = w.name
    AND m.name = $3
)
AND w.labels @> $4
ORDER BY w.created_at_ms ASC, w.name ASC
LIMIT $5 OFFSET $6
",
        )
        .bind(object_type)
        .bind(member_type)
        .bind(member_name)
        .bind(&labels_jsonb)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_by_scope(
        &self,
        object_type: &str,
        scope: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r"
SELECT object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version
FROM objects
WHERE object_type = $1 AND scope = $2
ORDER BY created_at_ms ASC, name ASC
LIMIT $3 OFFSET $4
",
        )
        .bind(object_type)
        .bind(scope)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_with_selector(
        &self,
        object_type: &str,
        workspace: &str,
        label_selector: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        use super::parse_label_selector;

        let required_labels = parse_label_selector(label_selector)?;
        let labels_jsonb = serde_json::to_value(&required_labels)
            .map_err(|e| PersistenceError::Encode(format!("failed to serialize labels: {e}")))?;

        let rows = sqlx::query(
            r"
SELECT object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version
FROM objects
WHERE object_type = $1 AND workspace = $2 AND labels @> $3
ORDER BY created_at_ms ASC, name ASC
LIMIT $4 OFFSET $5
",
        )
        .bind(object_type)
        .bind(workspace)
        .bind(&labels_jsonb)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_all_with_selector(
        &self,
        object_type: &str,
        label_selector: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        use super::parse_label_selector;

        let required_labels = parse_label_selector(label_selector)?;
        let labels_jsonb = serde_json::to_value(&required_labels)
            .map_err(|e| PersistenceError::Encode(format!("failed to serialize labels: {e}")))?;

        let rows = sqlx::query(
            r"
SELECT object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version
FROM objects
WHERE object_type = $1 AND labels @> $2
ORDER BY created_at_ms ASC, name ASC, workspace ASC, id ASC
LIMIT $3 OFFSET $4
",
        )
        .bind(object_type)
        .bind(&labels_jsonb)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn put_policy_revision(
        &self,
        id: &str,
        sandbox_id: &str,
        workspace: &str,
        version: i64,
        payload: &[u8],
        hash: &str,
    ) -> PersistenceResult<()> {
        let now_ms = current_time_ms();
        let record = PolicyRecord {
            id: id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            version,
            policy_payload: payload.to_vec(),
            policy_hash: hash.to_string(),
            status: "pending".to_string(),
            load_error: None,
            created_at_ms: now_ms,
            loaded_at_ms: None,
            provenance: std::collections::HashMap::default(),
        };
        let wrapped_payload = policy_payload_from_record(&record)?;

        sqlx::query(
            r"
INSERT INTO objects (
    object_type, id, scope, version, status, payload, created_at_ms, updated_at_ms, workspace
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8)
",
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(id)
        .bind(sandbox_id)
        .bind(version)
        .bind("pending")
        .bind(wrapped_payload)
        .bind(now_ms)
        .bind(workspace)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    pub async fn put_policy_revision_atomic(
        &self,
        write: &AtomicPolicyRevisionWrite,
    ) -> PersistenceResult<Sandbox> {
        let now_ms = current_time_ms();
        let record = policy_record_for_atomic_write(write, now_ms);
        let wrapped_payload = policy_payload_from_record(&record)?;
        let mut tx = self.pool.begin().await.map_err(|e| map_db_error(&e))?;

        let row = sqlx::query(
            r"
SELECT payload, resource_version
FROM objects
WHERE object_type = 'sandbox' AND id = $1
FOR UPDATE
",
        )
        .bind(&write.sandbox_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?
        .ok_or_else(|| {
            PersistenceError::Database(format!("sandbox object {} not found", write.sandbox_id))
        })?;

        let sandbox_payload: Vec<u8> = row.get("payload");
        let current_version: i64 = row.try_get("resource_version").unwrap_or(1);
        let current_version = current_version.max(1).cast_unsigned();
        let (mut sandbox, sandbox_changed) =
            project_policy_revision_onto_sandbox(write, &sandbox_payload, current_version)?;

        let resulting_version = if sandbox_changed {
            let result = sqlx::query(
                r"
UPDATE objects
SET payload = $2, updated_at_ms = $3, resource_version = resource_version + 1
WHERE object_type = 'sandbox' AND id = $1 AND resource_version = $4
",
            )
            .bind(&write.sandbox_id)
            .bind(sandbox.encode_to_vec())
            .bind(now_ms)
            .bind(i64::try_from(current_version).unwrap_or(i64::MAX))
            .execute(&mut *tx)
            .await
            .map_err(|e| map_db_error(&e))?;
            if result.rows_affected() != 1 {
                return Err(PersistenceError::Conflict {
                    current_resource_version: Some(current_version),
                });
            }
            current_version.saturating_add(1)
        } else {
            current_version
        };

        sqlx::query(
            r"
INSERT INTO objects (
    object_type, id, scope, version, status, payload, created_at_ms, updated_at_ms, workspace
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8)
",
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(&write.id)
        .bind(&write.sandbox_id)
        .bind(write.version)
        .bind("pending")
        .bind(wrapped_payload)
        .bind(now_ms)
        .bind(&write.workspace)
        .execute(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;

        sqlx::query(
            r"
UPDATE objects
SET status = 'superseded', updated_at_ms = $4
WHERE object_type = $1
  AND scope = $2
  AND version < $3
  AND status IN ('pending', 'loaded')
",
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(&write.sandbox_id)
        .bind(write.version)
        .bind(now_ms)
        .execute(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;

        tx.commit().await.map_err(|e| map_db_error(&e))?;
        sandbox.set_resource_version(resulting_version);
        Ok(sandbox)
    }

    pub async fn get_latest_policy(
        &self,
        sandbox_id: &str,
    ) -> PersistenceResult<Option<PolicyRecord>> {
        let row = sqlx::query(
            r"
SELECT id, scope, version, status, payload, created_at_ms
FROM objects
WHERE object_type = $1 AND scope = $2
ORDER BY version DESC, created_at_ms DESC
LIMIT 1
",
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        row.map(row_to_policy_record).transpose()
    }

    pub async fn get_latest_loaded_policy(
        &self,
        sandbox_id: &str,
    ) -> PersistenceResult<Option<PolicyRecord>> {
        let row = sqlx::query(
            r"
SELECT id, scope, version, status, payload, created_at_ms
FROM objects
WHERE object_type = $1 AND scope = $2 AND status = 'loaded'
ORDER BY version DESC, created_at_ms DESC
LIMIT 1
",
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        row.map(row_to_policy_record).transpose()
    }

    pub async fn get_policy_by_version(
        &self,
        sandbox_id: &str,
        version: i64,
    ) -> PersistenceResult<Option<PolicyRecord>> {
        let row = sqlx::query(
            r"
SELECT id, scope, version, status, payload, created_at_ms
FROM objects
WHERE object_type = $1 AND scope = $2 AND version = $3
",
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(version)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        row.map(row_to_policy_record).transpose()
    }

    pub async fn list_policies(
        &self,
        sandbox_id: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<PolicyRecord>> {
        let rows = sqlx::query(
            r"
SELECT id, scope, version, status, payload, created_at_ms
FROM objects
WHERE object_type = $1 AND scope = $2
ORDER BY version DESC, created_at_ms DESC
LIMIT $3 OFFSET $4
",
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        rows.into_iter().map(row_to_policy_record).collect()
    }

    pub async fn list_policies_before(
        &self,
        sandbox_id: &str,
        limit: u32,
        before_version: Option<i64>,
    ) -> PersistenceResult<Vec<PolicyRecord>> {
        let rows = sqlx::query(
            r"
SELECT id, scope, version, status, payload, created_at_ms
FROM objects
WHERE object_type = $1 AND scope = $2 AND ($3::BIGINT IS NULL OR version < $3)
ORDER BY version DESC
LIMIT $4
",
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(before_version)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        rows.into_iter().map(row_to_policy_record).collect()
    }

    pub async fn update_policy_status(
        &self,
        sandbox_id: &str,
        version: i64,
        status: &str,
        load_error: Option<&str>,
        loaded_at_ms: Option<i64>,
    ) -> PersistenceResult<bool> {
        let Some(mut record) = self.get_policy_by_version(sandbox_id, version).await? else {
            return Ok(false);
        };

        record.status = status.to_string();
        record.load_error = load_error.map(ToOwned::to_owned);
        record.loaded_at_ms = loaded_at_ms;
        let payload = policy_payload_from_record(&record)?;
        let now_ms = current_time_ms();

        let result = sqlx::query(
            r"
UPDATE objects
SET status = $4, payload = $5, updated_at_ms = $6
WHERE object_type = $1 AND scope = $2 AND version = $3
",
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(version)
        .bind(status)
        .bind(payload)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn supersede_older_policies(
        &self,
        sandbox_id: &str,
        before_version: i64,
    ) -> PersistenceResult<u64> {
        let now_ms = current_time_ms();
        let result = sqlx::query(
            r"
UPDATE objects
SET status = 'superseded', updated_at_ms = $4
WHERE object_type = $1
  AND scope = $2
  AND version < $3
  AND status IN ('pending', 'loaded')
",
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(before_version)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected())
    }

    pub async fn put_draft_chunk(
        &self,
        chunk: &DraftChunkRecord,
        dedup_key: Option<&str>,
        workspace: &str,
    ) -> PersistenceResult<String> {
        let payload = draft_chunk_payload_from_record(chunk)?;
        // RETURNING id gives the row's effective id whether INSERT inserted
        // a fresh row or ON CONFLICT updated an existing one. See the
        // matching sqlite path for the rationale.
        let row = sqlx::query(
            r"
INSERT INTO objects (
    object_type, id, scope, status, dedup_key, hit_count, payload, created_at_ms, updated_at_ms, workspace
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (object_type, scope, dedup_key) WHERE dedup_key IS NOT NULL DO UPDATE SET
    hit_count = objects.hit_count + EXCLUDED.hit_count,
    updated_at_ms = EXCLUDED.updated_at_ms
RETURNING id
",
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(&chunk.id)
        .bind(&chunk.sandbox_id)
        .bind(&chunk.status)
        .bind(dedup_key)
        .bind(i64::from(chunk.hit_count))
        .bind(payload)
        .bind(chunk.first_seen_ms)
        .bind(chunk.last_seen_ms)
        .bind(workspace)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(row.get::<String, _>("id"))
    }

    pub async fn get_draft_chunk(&self, id: &str) -> PersistenceResult<Option<DraftChunkRecord>> {
        let row = sqlx::query(
            r"
SELECT id, scope, status, hit_count, payload, created_at_ms, updated_at_ms
FROM objects
WHERE object_type = $1 AND id = $2
",
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        row.map(row_to_draft_chunk_record).transpose()
    }

    pub async fn list_draft_chunks(
        &self,
        sandbox_id: &str,
        status_filter: Option<&str>,
    ) -> PersistenceResult<Vec<DraftChunkRecord>> {
        let rows = if let Some(status) = status_filter {
            sqlx::query(
                r"
SELECT id, scope, status, hit_count, payload, created_at_ms, updated_at_ms
FROM objects
WHERE object_type = $1 AND scope = $2 AND status = $3
ORDER BY created_at_ms DESC
",
            )
            .bind(DRAFT_CHUNK_OBJECT_TYPE)
            .bind(sandbox_id)
            .bind(status)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                r"
SELECT id, scope, status, hit_count, payload, created_at_ms, updated_at_ms
FROM objects
WHERE object_type = $1 AND scope = $2
ORDER BY created_at_ms DESC
",
            )
            .bind(DRAFT_CHUNK_OBJECT_TYPE)
            .bind(sandbox_id)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|e| map_db_error(&e))?;

        rows.into_iter().map(row_to_draft_chunk_record).collect()
    }

    pub async fn update_draft_chunk_status(
        &self,
        id: &str,
        status: &str,
        decided_at_ms: Option<i64>,
        rejection_reason: Option<&str>,
    ) -> PersistenceResult<bool> {
        let Some(mut record) = self.get_draft_chunk(id).await? else {
            return Ok(false);
        };

        record.status = status.to_string();
        record.decided_at_ms = decided_at_ms;
        record.last_seen_ms = current_time_ms();
        if let Some(reason) = rejection_reason {
            record.rejection_reason = reason.to_string();
        }
        let payload = draft_chunk_payload_from_record(&record)?;

        let result = sqlx::query(
            r"
UPDATE objects
SET status = $3, payload = $4, updated_at_ms = $5
WHERE object_type = $1 AND id = $2
",
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(id)
        .bind(status)
        .bind(payload)
        .bind(record.last_seen_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn conditionally_reject_draft_chunk(
        &self,
        id: &str,
        decided_at_ms: i64,
        rejection_reason: &str,
    ) -> PersistenceResult<bool> {
        let Some(mut record) = self.get_draft_chunk(id).await? else {
            return Ok(false);
        };

        if record.status != "pending" {
            return Ok(false);
        }

        record.status = "rejected".to_string();
        record.decided_at_ms = Some(decided_at_ms);
        record.rejection_reason = rejection_reason.to_string();
        record.last_seen_ms = current_time_ms();
        let payload = draft_chunk_payload_from_record(&record)?;

        let result = sqlx::query(
            r"
UPDATE objects
SET status = $3, payload = $4, updated_at_ms = $5
WHERE object_type = $1 AND id = $2 AND status = 'pending'
",
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(id)
        .bind("rejected")
        .bind(payload)
        .bind(record.last_seen_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_draft_chunk_rule(
        &self,
        id: &str,
        proposed_rule: &[u8],
    ) -> PersistenceResult<bool> {
        let Some(mut record) = self.get_draft_chunk(id).await? else {
            return Ok(false);
        };

        if record.status != "pending" {
            return Ok(false);
        }

        record.proposed_rule = proposed_rule.to_vec();
        record.last_seen_ms = current_time_ms();
        let payload = draft_chunk_payload_from_record(&record)?;

        let result = sqlx::query(
            r"
UPDATE objects
SET payload = $3, updated_at_ms = $4
WHERE object_type = $1 AND id = $2 AND status = 'pending'
",
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(id)
        .bind(payload)
        .bind(record.last_seen_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_draft_chunk_evaluation(
        &self,
        chunk: &DraftChunkRecord,
    ) -> PersistenceResult<bool> {
        let payload = draft_chunk_payload_from_record(chunk)?;
        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "payload" = $3, "updated_at_ms" = $4
WHERE "object_type" = $1 AND "id" = $2 AND "status" IN ('pending', 'rejected')
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(&chunk.id)
        .bind(payload)
        .bind(chunk.last_seen_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_draft_chunk_evaluation_if_unchanged(
        &self,
        expected: &DraftChunkRecord,
        evaluated: &DraftChunkRecord,
    ) -> PersistenceResult<bool> {
        let Some(row) = sqlx::query(
            r#"
SELECT "id", "scope", "status", "hit_count", "payload", "created_at_ms", "updated_at_ms"
FROM "objects"
WHERE "object_type" = $1 AND "id" = $2 AND "status" IN ('pending', 'rejected')
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(&expected.id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?
        else {
            return Ok(false);
        };
        let stored_payload: Vec<u8> = row.get("payload");
        let mut current = row_to_draft_chunk_record(row)?;
        if !draft_chunk_evaluation_inputs_match(&current, expected) {
            return Ok(false);
        }
        apply_draft_chunk_evaluation(&mut current, evaluated);
        let payload = draft_chunk_payload_from_record(&current)?;
        // Compare-and-swap on the payload read above: a concurrent edit or
        // evaluation between the read and this write leaves nothing updated.
        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "payload" = $3, "updated_at_ms" = $4
WHERE "object_type" = $1 AND "id" = $2 AND "status" IN ('pending', 'rejected')
  AND "payload" = $5
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(&expected.id)
        .bind(payload)
        .bind(current.last_seen_ms)
        .bind(stored_payload)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_draft_chunks(
        &self,
        sandbox_id: &str,
        status: &str,
    ) -> PersistenceResult<u64> {
        let result = sqlx::query(
            r"
DELETE FROM objects
WHERE object_type = $1 AND scope = $2 AND status = $3
",
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(status)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected())
    }

    pub async fn get_draft_version(&self, sandbox_id: &str) -> PersistenceResult<i64> {
        let rows = sqlx::query(
            r"
SELECT payload
FROM objects
WHERE object_type = $1 AND scope = $2
",
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(sandbox_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        let mut max_version = 0_i64;
        for row in rows {
            let payload: Vec<u8> = row.get("payload");
            let wrapper = draft_chunk_record_from_parts(
                String::new(),
                sandbox_id.to_string(),
                String::new(),
                0,
                &payload,
                0,
                0,
            )?;
            max_version = max_version.max(wrapper.draft_version);
        }
        Ok(max_version)
    }
}

fn row_to_object_record(row: sqlx::postgres::PgRow) -> ObjectRecord {
    let labels_jsonb: Option<serde_json::Value> = row.get("labels");
    let resource_version_i64: i64 = row.try_get("resource_version").unwrap_or(1);
    ObjectRecord {
        object_type: row.get("object_type"),
        id: row.get("id"),
        name: row.get("name"),
        workspace: row.try_get("workspace").unwrap_or_default(),
        payload: row.get("payload"),
        created_at_ms: row.get("created_at_ms"),
        updated_at_ms: row.get("updated_at_ms"),
        labels: labels_jsonb.map(|value| value.to_string()),
        resource_version: resource_version_i64.max(1).cast_unsigned(),
    }
}

fn row_to_policy_record(row: sqlx::postgres::PgRow) -> PersistenceResult<PolicyRecord> {
    let id: String = row.get("id");
    let sandbox_id: String = row.get("scope");
    let version: i64 = row.get("version");
    let status: String = row.get("status");
    let payload: Vec<u8> = row.get("payload");
    let created_at_ms: i64 = row.get("created_at_ms");
    policy_record_from_parts(id, sandbox_id, version, status, &payload, created_at_ms)
}

fn row_to_draft_chunk_record(row: sqlx::postgres::PgRow) -> PersistenceResult<DraftChunkRecord> {
    let id: String = row.get("id");
    let sandbox_id: String = row.get("scope");
    let status: String = row.get("status");
    let hit_count: i64 = row.get("hit_count");
    let payload: Vec<u8> = row.get("payload");
    let created_at_ms: i64 = row.get("created_at_ms");
    let updated_at_ms: i64 = row.get("updated_at_ms");
    draft_chunk_record_from_parts(
        id,
        sandbox_id,
        status,
        hit_count,
        &payload,
        created_at_ms,
        updated_at_ms,
    )
}

#[cfg(test)]
impl PostgresStore {
    /// Test support only: a store whose pools connect on first use, so it
    /// can point at an address where `PostgreSQL` does not answer.
    pub(crate) fn connect_lazy_for_tests(url: &str, lock_pool_size: u32) -> Self {
        Self {
            pool: PgPoolOptions::new()
                .max_connections(10)
                .connect_lazy(url)
                .expect("build the lazy data pool"),
            lock_pool: PgPoolOptions::new()
                .max_connections(lock_pool_size)
                .min_connections(0)
                .acquire_timeout(MUTATION_LOCK_TIMEOUT)
                .connect_lazy(url)
                .expect("build the lazy lock pool"),
            lock_usage: Arc::new(LockPoolUsage::new(lock_pool_size)),
        }
    }

    /// Test support only: a `PostgreSQL` URL on a loopback port where nothing
    /// listens, so every connection attempt is refused.
    pub(crate) async fn refusing_url_for_tests() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve a loopback port");
        let port = listener.local_addr().expect("loopback address").port();
        drop(listener);
        format!("postgres://openshell@127.0.0.1:{port}/openshell")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lock_connection_timeout_is_contention_only_if_the_pool_filled_during_the_wait() {
        let store = PostgresStore::connect_lazy_for_tests(
            &PostgresStore::refusing_url_for_tests().await,
            2,
        );
        let usage = &store.lock_usage;
        let is_contention = |error: PersistenceError| match error {
            PersistenceError::LockTimeout(detail) => {
                assert_eq!(detail, "waiting for a mutation lock connection");
                true
            }
            PersistenceError::Database(detail) => {
                assert_eq!(detail, LOCK_CONNECTION_NOT_OPENED);
                false
            }
            other => panic!("unexpected lock connection error: {other:?}"),
        };

        // The pool never filled: PostgreSQL did not open a connection.
        let start = usage.snapshot();
        let first = LockConnectionCheckout::new(usage);
        assert!(!is_contention(
            store.lock_connection_timeout(start, LOCK_CONNECTION_MIN_BUDGET)
        ));

        // The pool was full when the wait started.
        let second = LockConnectionCheckout::new(usage);
        assert!(is_contention(store.lock_connection_timeout(
            usage.snapshot(),
            LOCK_CONNECTION_MIN_BUDGET
        )));

        // A connection went back and was checked out again during the wait,
        // as when one guard hands its connection to the next.
        drop(second);
        let start = usage.snapshot();
        drop(LockConnectionCheckout::new(usage));
        assert!(is_contention(
            store.lock_connection_timeout(start, LOCK_CONNECTION_MIN_BUDGET)
        ));
        drop(first);
    }

    #[tokio::test]
    async fn lock_connection_timeout_without_time_to_connect_is_a_lock_timeout() {
        let store = PostgresStore::connect_lazy_for_tests(
            &PostgresStore::refusing_url_for_tests().await,
            1,
        );
        // The pool never fills, but an earlier wait left too little time to
        // open a connection.
        let start = store.lock_usage.snapshot();
        let budget = LOCK_CONNECTION_MIN_BUDGET.saturating_sub(Duration::from_millis(1));
        assert!(matches!(
            store.lock_connection_timeout(start, budget),
            PersistenceError::LockTimeout(_)
        ));

        // SQLx retries the refused connection until the deadline.
        let deadline = tokio::time::Instant::now() + LOCK_CONNECTION_MIN_BUDGET / 4;
        match store
            .acquire_mutation_locks(&MutationLockSet::default(), deadline)
            .await
        {
            Err(PersistenceError::LockTimeout(detail)) => {
                assert_eq!(detail, "waiting for a mutation lock connection");
            }
            Err(error) => panic!("expected a lock timeout, got {error:?}"),
            Ok(_) => panic!("nothing listens, yet a lock connection opened"),
        }
        assert_eq!(store.lock_usage.in_use.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn refused_lock_connection_is_a_database_error_not_a_lock_timeout() {
        let store = PostgresStore::connect_lazy_for_tests(
            &PostgresStore::refusing_url_for_tests().await,
            1,
        );
        // SQLx retries a refused connection until the deadline, which leaves
        // ample time to open one.
        let deadline =
            tokio::time::Instant::now() + LOCK_CONNECTION_MIN_BUDGET + Duration::from_millis(300);
        match store
            .acquire_mutation_locks(&MutationLockSet::default(), deadline)
            .await
        {
            Err(PersistenceError::Database(detail)) => assert!(
                detail.starts_with("could not open a mutation lock connection"),
                "{detail}"
            ),
            Err(error) => panic!("expected a database error, got {error:?}"),
            Ok(_) => panic!("nothing listens, yet a lock connection opened"),
        }
        assert_eq!(store.lock_usage.in_use.load(Ordering::Acquire), 0);
    }
}
