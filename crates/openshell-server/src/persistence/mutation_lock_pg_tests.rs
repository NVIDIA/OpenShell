// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `PostgreSQL` tests of the mutation advisory locks: exclusion between two
//! stores (as between two gateway replicas), exclusion against the legacy
//! global key, cleanup after timed-out and cancelled acquisitions, and the
//! lock-pool bound.
//!
//! Advisory locks are database-wide, not per schema, so every test uses
//! random workspace and sandbox ids, and `mise run test:rust:postgres` runs
//! the tests one at a time. The stores here run no migrations: the schema only
//! scopes their connections.

use super::mutation_lock::{
    GLOBAL_MUTATION_LOCK_KEY, MUTATION_LOCK_POOL_MAX_CONNECTIONS, MUTATION_LOCK_TIMEOUT,
    MutationLockKey, MutationLockSet,
};
use super::postgres::LOCK_CONNECTION_RELEASE_TIMEOUT;
use super::test_postgres::TestSchema;
use super::{
    DistributedMutationGuard, PersistenceError, PersistenceResult, PostgresStore, Store,
    map_db_error,
};
use crate::compute::MutationScope;
use sqlx::{Connection, PgConnection, PgPool};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;

/// Deadline of an acquisition that must time out.
const EXPECTED_TIMEOUT: Duration = Duration::from_millis(300);
/// Deadline of an acquisition that must succeed, possibly after a conflicting
/// holder releases.
const PROCEEDS_WITHIN: Duration = Duration::from_secs(5);
/// Deadline of an acquisition that a test interrupts while it waits.
const INTERRUPTED_DEADLINE: Duration = Duration::from_secs(1);
/// How long after an interrupted acquisition's deadline its keys may stay held.
const RELEASED_WITHIN: Duration = Duration::from_secs(1);
/// The client-side backstop fires this long after a lock statement's deadline.
const CLIENT_BACKSTOP_GRACE: Duration = Duration::from_millis(500);
/// How long each holder keeps its locks in the throughput tests.
const HOLD: Duration = Duration::from_millis(20);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

fn random_id(kind: &str) -> String {
    format!("{kind}-{}", uuid::Uuid::new_v4())
}

/// Drop client traffic while keeping sockets open, like a failed network path.
/// Client EOF still closes the upstream socket so `PostgreSQL` can release locks.
struct StallingProxy {
    url: String,
    stalled: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl StallingProxy {
    async fn start(database_url: &str) -> Self {
        let mut url = url::Url::parse(database_url).unwrap();
        let host = url.host_str().expect("TCP PostgreSQL host").to_owned();
        let port = url.port().unwrap_or(5432);
        let upstream_addresses: Vec<_> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .unwrap()
            .collect();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        url.set_host(Some("127.0.0.1")).unwrap();
        url.set_port(Some(listener.local_addr().unwrap().port()))
            .unwrap();
        let (stalled, receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (client, _) = accepted.unwrap();
                        openshell_core::net::set_tcp_nodelay_best_effort(&client);
                        let addresses = upstream_addresses.clone();
                        let stalled = receiver.clone();
                        connections.spawn(async move {
                            let upstream = openshell_core::net::connect_tcp_nodelay_best_effort(
                                &addresses,
                            ).await?;
                            let (mut client_read, mut client_write) = client.into_split();
                            let (mut upstream_read, mut upstream_write) = upstream.into_split();
                            let requests = async {
                                let mut buffer = [0_u8; 8192];
                                loop {
                                    let read = client_read.read(&mut buffer).await?;
                                    if read == 0 {
                                        return Ok::<_, std::io::Error>(());
                                    }
                                    if !*stalled.borrow() {
                                        upstream_write.write_all(&buffer[..read]).await?;
                                    }
                                }
                            };
                            tokio::select! {
                                result = requests => result,
                                result = tokio::io::copy(&mut upstream_read, &mut client_write) => {
                                    result.map(|_| ())
                                }
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Self {
            url: url.into(),
            stalled,
            task,
        }
    }
}

impl Drop for StallingProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A random sandbox id whose key sorts after the global key and the
/// workspace key. Keys are taken in ascending order, so an acquisition of its
/// sandbox scope already holds S(global) and S(workspace) while it waits for
/// the sandbox key.
fn sandbox_id_locked_last(workspace: &str) -> String {
    let taken_first =
        GLOBAL_MUTATION_LOCK_KEY.max(MutationLockKey::Workspace(workspace).advisory_key());
    loop {
        let sandbox = random_id("sb");
        if MutationLockKey::Sandbox(&sandbox).advisory_key() > taken_first {
            return sandbox;
        }
    }
}

/// A disposable schema plus an observer pool for `pg_locks`.
struct LockFixture {
    schema: TestSchema,
    observer: PgPool,
}

impl LockFixture {
    async fn new() -> Self {
        let schema = TestSchema::create("lock").await;
        let observer = PgPool::connect(schema.url())
            .await
            .expect("connect the pg_locks observer");
        Self { schema, observer }
    }

    /// A store with its own data and lock pools, like one gateway replica.
    ///
    /// Its lock pool starts with one idle, connected session, so the first
    /// acquisition spends its deadline on locks rather than on connecting.
    /// Warming takes S(global), so create stores before any test holder
    /// locks.
    async fn store(&self, lock_pool_size: u32) -> Store {
        let store = Store::Postgres(
            PostgresStore::connect_with_lock_pool_size(self.schema.url(), lock_pool_size)
                .await
                .expect("connect a lock store"),
        );
        drop(
            acquire_proceeds(
                &store,
                MutationScope::sandbox(&random_id("ws"), &random_id("sb")),
                "warm the lock pool",
            )
            .await,
        );
        wait_for_idle_lock_connection(&store).await;
        store
    }

    /// A plain session, like a gateway from an earlier release or a test
    /// holder.
    async fn raw_session(&self) -> PgConnection {
        PgConnection::connect(self.schema.url())
            .await
            .expect("connect a raw session")
    }

    /// Granted and waiting holders of one bigint advisory key in this
    /// database.
    async fn lock_count(&self, key: i64) -> i64 {
        let (high, low) = key_halves(key);
        sqlx::query_scalar(
            "SELECT count(*) FROM pg_locks \
             WHERE locktype = 'advisory' AND objsubid = 1 \
               AND classid = $1::bigint::oid AND objid = $2::bigint::oid \
               AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .bind(high)
        .bind(low)
        .fetch_one(&self.observer)
        .await
        .expect("count advisory locks")
    }

    /// Advisory locks held or awaited by one backend.
    async fn session_lock_count(&self, pid: i32) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = $1")
            .bind(pid)
            .fetch_one(&self.observer)
            .await
            .expect("count a session's advisory locks")
    }

    async fn wait_for_lock_count(&self, key: i64, expected: i64, until: Instant, what: &str) {
        loop {
            let count = self.lock_count(key).await;
            if count == expected {
                return;
            }
            assert!(
                Instant::now() < until,
                "{what}: {count} holders remain, expected {expected}"
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// Backend that waits for `key`, once an acquisition blocks on it.
    async fn wait_for_waiting_backend(&self, key: i64, until: Instant) -> i32 {
        let (high, low) = key_halves(key);
        loop {
            let waiting: Option<i32> = sqlx::query_scalar(
                "SELECT pid FROM pg_locks \
                 WHERE locktype = 'advisory' AND NOT granted AND objsubid = 1 \
                   AND classid = $1::bigint::oid AND objid = $2::bigint::oid \
                   AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
            )
            .bind(high)
            .bind(low)
            .fetch_optional(&self.observer)
            .await
            .expect("find the waiting backend");
            if let Some(pid) = waiting {
                return pid;
            }
            assert!(
                Instant::now() < until,
                "no backend waited for the sandbox key before the deadline"
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// Spawn an acquisition of `Sandbox { workspace, sandbox }` on `store`,
    /// where another session holds the sandbox key, and wait until its
    /// backend holds S(global) and S(workspace) and waits for the sandbox
    /// key. Returns the task and the waiting backend's pid.
    async fn spawn_waiting_acquisition(
        &self,
        store: &Store,
        workspace: &str,
        sandbox: &str,
        deadline: Instant,
    ) -> (JoinHandle<PersistenceResult<()>>, i32) {
        let acquisition = {
            let store = store.clone();
            let set = MutationScope::sandbox(workspace, sandbox).lock_set();
            tokio::spawn(async move {
                store
                    .acquire_distributed_mutation_guard(&set, deadline)
                    .await
                    .map(drop)
            })
        };
        let pid = self
            .wait_for_waiting_backend(MutationLockKey::Sandbox(sandbox).advisory_key(), deadline)
            .await;
        assert_eq!(
            self.lock_count(MutationLockKey::Workspace(workspace).advisory_key())
                .await,
            1,
            "the waiting acquisition holds the workspace key"
        );
        assert_eq!(
            self.lock_count(GLOBAL_MUTATION_LOCK_KEY).await,
            1,
            "the waiting acquisition holds the global key"
        );
        (acquisition, pid)
    }

    async fn finish(self, stores: Vec<Store>) {
        for store in stores {
            store.close().await;
        }
        self.observer.close().await;
        self.schema.drop_schema().await;
    }
}

/// `pg_locks` shows a bigint advisory key as its high and low 32 bits.
fn key_halves(key: i64) -> (i64, i64) {
    let [b0, b1, b2, b3, b4, b5, b6, b7] = key.to_be_bytes();
    (
        i64::from(u32::from_be_bytes([b0, b1, b2, b3])),
        i64::from(u32::from_be_bytes([b4, b5, b6, b7])),
    )
}

async fn acquire(
    store: &Store,
    scope: MutationScope<'_>,
    within: Duration,
) -> PersistenceResult<DistributedMutationGuard> {
    store
        .acquire_distributed_mutation_guard(&scope.lock_set(), Instant::now() + within)
        .await
}

async fn acquire_proceeds(
    store: &Store,
    scope: MutationScope<'_>,
    what: &str,
) -> DistributedMutationGuard {
    acquire(store, scope, PROCEEDS_WITHIN)
        .await
        .unwrap_or_else(|error| panic!("{what}: expected the locks, got {error:?}"))
}

/// Wait until `store`'s lock pool has an idle, connected session. A released
/// lock connection returns to the pool from a background task, and an
/// acquisition that starts before then opens a new connection within its own
/// deadline.
async fn wait_for_idle_lock_connection(store: &Store) {
    let Store::Postgres(postgres) = store else {
        panic!("the lock tests use PostgreSQL stores");
    };
    let until = Instant::now() + PROCEEDS_WITHIN;
    while postgres.lock_pool_idle() == 0 {
        assert!(
            Instant::now() < until,
            "no lock connection returned to the pool"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Acquire `scope` on an idle lock connection with a deadline that
/// `PostgreSQL` must end with its lock timeout (55P03, "canceling statement
/// due to lock timeout"). A client-side timeout fails the test: a connect
/// that misses the deadline never reaches the advisory locks.
async fn acquire_times_out(store: &Store, scope: MutationScope<'_>, what: &str) {
    wait_for_idle_lock_connection(store).await;
    match acquire(store, scope, EXPECTED_TIMEOUT).await {
        Err(PersistenceError::LockTimeout(detail)) if detail.contains("lock timeout") => {}
        Err(error) => panic!("{what}: expected PostgreSQL's lock timeout, got {error:?}"),
        Ok(_) => panic!("{what}: expected a lock timeout, but the locks were acquired"),
    }
}

async fn raw_lock(session: &mut PgConnection, key: i64) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(key)
        .execute(session)
        .await
        .map(drop)
}

async fn raw_unlock(session: &mut PgConnection, key: i64) {
    let released: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
        .bind(key)
        .fetch_one(session)
        .await
        .expect("unlock the raw session's key");
    assert!(released, "the raw session held the key");
}

/// Spawn one holder per lock set, spread over `stores`, each keeping its
/// locks for [`HOLD`]; returns how long all of them took.
async fn hold_concurrently(stores: &[Store], sets: Vec<MutationLockSet>) -> Duration {
    let started = Instant::now();
    let holders: Vec<_> = sets
        .into_iter()
        .zip(stores.iter().cycle())
        .map(|(set, store)| {
            let store = store.clone();
            tokio::spawn(async move {
                let guard = store
                    .acquire_distributed_mutation_guard(
                        &set,
                        Instant::now() + MUTATION_LOCK_TIMEOUT,
                    )
                    .await?;
                tokio::time::sleep(HOLD).await;
                drop(guard);
                Ok::<_, PersistenceError>(())
            })
        })
        .collect();
    for holder in holders {
        holder
            .await
            .expect("holder task")
            .expect("holder acquires its locks");
    }
    started.elapsed()
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_mutation_lock_disjoint_sandbox_scopes_hold_concurrently_across_stores() {
    let fixture = LockFixture::new().await;
    let store_a = fixture.store(MUTATION_LOCK_POOL_MAX_CONNECTIONS).await;
    let store_b = fixture.store(MUTATION_LOCK_POOL_MAX_CONNECTIONS).await;
    let workspace = random_id("ws");
    let (sandbox_1, sandbox_2) = (random_id("sb"), random_id("sb"));

    let held_a = acquire_proceeds(
        &store_a,
        MutationScope::sandbox(&workspace, &sandbox_1),
        "store A",
    )
    .await;
    let held_b = acquire_proceeds(
        &store_b,
        MutationScope::sandbox(&workspace, &sandbox_2),
        "store B, another sandbox in the same workspace",
    )
    .await;
    assert_eq!(
        fixture
            .lock_count(MutationLockKey::Workspace(&workspace).advisory_key())
            .await,
        2,
        "both sessions hold the workspace key shared at once"
    );

    drop(held_a);
    drop(held_b);
    fixture.finish(vec![store_a, store_b]).await;
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_mutation_lock_stalled_release_closes_session_and_recovers_pool() {
    let fixture = LockFixture::new().await;
    let proxy = StallingProxy::start(fixture.schema.url()).await;
    let store = Store::Postgres(
        PostgresStore::connect_with_lock_pool_size(&proxy.url, 1)
            .await
            .unwrap(),
    );
    let workspace = random_id("ws");
    let sandbox = random_id("sb");
    let scope = MutationScope::sandbox(&workspace, &sandbox);
    let held = acquire_proceeds(&store, scope, "before the network stalls").await;
    let key = MutationLockKey::Sandbox(&sandbox).advisory_key();
    assert_eq!(fixture.lock_count(key).await, 1);

    proxy.stalled.send_replace(true);
    drop(held);

    // The old pool return waits forever for pg_advisory_unlock_all. Dropping
    // a guard must instead bound cleanup and close the stalled connection.
    fixture
        .wait_for_lock_count(
            key,
            0,
            Instant::now() + LOCK_CONNECTION_RELEASE_TIMEOUT + Duration::from_secs(2),
            "a stalled release must close its lock session",
        )
        .await;
    let Store::Postgres(postgres) = &store else {
        unreachable!();
    };
    assert_eq!(postgres.lock_pool_size(), 0, "the pool permit is recovered");

    proxy.stalled.send_replace(false);
    drop(acquire_proceeds(&store, scope, "after network recovery").await);
    fixture.finish(vec![store]).await;
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_mutation_lock_workspace_exclusive_blocks_same_workspace_sandbox_only() {
    let fixture = LockFixture::new().await;
    let store_a = fixture.store(MUTATION_LOCK_POOL_MAX_CONNECTIONS).await;
    let store_b = fixture.store(MUTATION_LOCK_POOL_MAX_CONNECTIONS).await;
    let (workspace_1, workspace_2) = (random_id("ws"), random_id("ws"));
    let (sandbox_x, sandbox_y) = (random_id("sb"), random_id("sb"));

    let held = acquire_proceeds(&store_a, MutationScope::Workspace(&workspace_1), "store A").await;
    acquire_times_out(
        &store_b,
        MutationScope::sandbox(&workspace_1, &sandbox_x),
        "a sandbox in the held workspace",
    )
    .await;
    drop(
        acquire_proceeds(
            &store_b,
            MutationScope::sandbox(&workspace_2, &sandbox_y),
            "a sandbox in another workspace",
        )
        .await,
    );

    drop(held);
    drop(
        acquire_proceeds(
            &store_b,
            MutationScope::sandbox(&workspace_1, &sandbox_x),
            "the sandbox after the workspace holder releases",
        )
        .await,
    );
    fixture.finish(vec![store_a, store_b]).await;
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_mutation_lock_global_exclusive_blocks_every_scope() {
    let fixture = LockFixture::new().await;
    let store_a = fixture.store(MUTATION_LOCK_POOL_MAX_CONNECTIONS).await;
    let store_b = fixture.store(MUTATION_LOCK_POOL_MAX_CONNECTIONS).await;
    let workspace = random_id("ws");
    let sandbox = random_id("sb");
    let scopes = [
        MutationScope::Global,
        MutationScope::Workspace(""),
        MutationScope::Workspace(&workspace),
        MutationScope::sandbox(&workspace, &sandbox),
    ];

    let held = acquire_proceeds(&store_a, MutationScope::Global, "store A").await;
    for scope in scopes {
        acquire_times_out(&store_b, scope, &format!("{scope:?} behind the global key")).await;
    }

    drop(held);
    for scope in scopes {
        drop(acquire_proceeds(&store_b, scope, &format!("{scope:?} after release")).await);
    }
    fixture.finish(vec![store_a, store_b]).await;
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_mutation_lock_legacy_global_key_holder_excludes_new_scopes() {
    let fixture = LockFixture::new().await;
    let store = fixture.store(MUTATION_LOCK_POOL_MAX_CONNECTIONS).await;
    let workspace = random_id("ws");
    let sandbox = random_id("sb");
    let scope = MutationScope::sandbox(&workspace, &sandbox);

    // A gateway from an earlier release holds the legacy key exclusively.
    let mut legacy = fixture.raw_session().await;
    raw_lock(&mut legacy, GLOBAL_MUTATION_LOCK_KEY)
        .await
        .expect("the legacy holder takes the global key");
    acquire_times_out(&store, scope, "a sandbox scope behind a legacy holder").await;

    raw_unlock(&mut legacy, GLOBAL_MUTATION_LOCK_KEY).await;
    drop(
        acquire_proceeds(
            &store,
            scope,
            "a sandbox scope after the legacy holder releases",
        )
        .await,
    );

    legacy.close().await.expect("close the legacy session");
    fixture.finish(vec![store]).await;
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_mutation_lock_new_scope_holder_excludes_legacy_global_key() {
    let fixture = LockFixture::new().await;
    let store = fixture.store(MUTATION_LOCK_POOL_MAX_CONNECTIONS).await;
    let workspace = random_id("ws");
    let sandbox = random_id("sb");

    let held = acquire_proceeds(
        &store,
        MutationScope::sandbox(&workspace, &sandbox),
        "the new-release holder",
    )
    .await;
    let mut legacy = fixture.raw_session().await;
    sqlx::query("SET lock_timeout = '200ms'")
        .execute(&mut legacy)
        .await
        .expect("bound the legacy lock wait");
    let Err(error) = raw_lock(&mut legacy, GLOBAL_MUTATION_LOCK_KEY).await else {
        panic!("the legacy global lock should wait behind a sandbox scope");
    };
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("55P03"),
        "{error}"
    );
    assert!(
        matches!(map_db_error(&error), PersistenceError::LockTimeout(_)),
        "55P03 maps to a lock timeout"
    );

    drop(held);
    sqlx::query("SET lock_timeout = '5s'")
        .execute(&mut legacy)
        .await
        .expect("bound the legacy lock wait");
    raw_lock(&mut legacy, GLOBAL_MUTATION_LOCK_KEY)
        .await
        .expect("the legacy lock after the new-release holder releases");
    raw_unlock(&mut legacy, GLOBAL_MUTATION_LOCK_KEY).await;

    legacy.close().await.expect("close the legacy session");
    fixture.finish(vec![store]).await;
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_mutation_lock_timeout_releases_held_keys_before_the_holder_does() {
    let fixture = LockFixture::new().await;
    // One lock connection, so a reused session keeps its backend pid.
    let store = fixture.store(1).await;
    let workspace = random_id("ws");
    let sandbox = sandbox_id_locked_last(&workspace);
    let workspace_key = MutationLockKey::Workspace(&workspace).advisory_key();
    let sandbox_key = MutationLockKey::Sandbox(&sandbox).advisory_key();

    // The raw session holds only the sandbox key, so the acquisition's own
    // backend is the only holder of the global and workspace keys.
    let mut holder = fixture.raw_session().await;
    raw_lock(&mut holder, sandbox_key)
        .await
        .expect("the raw session takes the sandbox key");

    let deadline = Instant::now() + INTERRUPTED_DEADLINE;
    let (acquisition, waiting_pid) = fixture
        .spawn_waiting_acquisition(&store, &workspace, &sandbox, deadline)
        .await;

    let result = tokio::time::timeout_at(
        deadline + CLIENT_BACKSTOP_GRACE + RELEASED_WITHIN,
        acquisition,
    )
    .await
    .expect("the acquisition returns by its deadline")
    .expect("acquisition task");
    assert!(
        matches!(result, Err(PersistenceError::LockTimeout(_))),
        "{result:?}"
    );

    // The raw session still holds the sandbox key, yet the global and
    // workspace keys the acquisition took are already released.
    fixture
        .wait_for_lock_count(
            workspace_key,
            0,
            deadline + RELEASED_WITHIN,
            "workspace key after the timeout",
        )
        .await;
    fixture
        .wait_for_lock_count(
            GLOBAL_MUTATION_LOCK_KEY,
            0,
            deadline + RELEASED_WITHIN,
            "global key after the timeout",
        )
        .await;
    assert_eq!(fixture.lock_count(sandbox_key).await, 1);

    // A server-side timeout returns the healthy session to the pool instead
    // of closing it.
    let mut reused = acquire_proceeds(
        &store,
        MutationScope::sandbox(&random_id("ws"), &random_id("sb")),
        "a disjoint scope on the same lock connection",
    )
    .await;
    assert_eq!(reused.postgres_backend_pid().await, Some(waiting_pid));
    drop(reused);

    raw_unlock(&mut holder, sandbox_key).await;
    holder.close().await.expect("close the raw session");
    fixture.finish(vec![store]).await;
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_mutation_lock_cancelled_acquisition_releases_held_keys_by_its_deadline() {
    let fixture = LockFixture::new().await;
    let store = fixture.store(MUTATION_LOCK_POOL_MAX_CONNECTIONS).await;
    let workspace = random_id("ws");
    let sandbox = sandbox_id_locked_last(&workspace);
    let workspace_key = MutationLockKey::Workspace(&workspace).advisory_key();
    let sandbox_key = MutationLockKey::Sandbox(&sandbox).advisory_key();

    let mut holder = fixture.raw_session().await;
    raw_lock(&mut holder, sandbox_key)
        .await
        .expect("the raw session takes the sandbox key");

    // Cancel mid-wait, while the backend holds the global and workspace keys.
    let deadline = Instant::now() + INTERRUPTED_DEADLINE;
    let (acquisition, _) = fixture
        .spawn_waiting_acquisition(&store, &workspace, &sandbox, deadline)
        .await;
    acquisition.abort();
    let Err(error) = acquisition.await else {
        panic!("the cancelled acquisition should not finish");
    };
    assert!(error.is_cancelled());

    // The closed session's backend does not notice the disconnect while it
    // waits, but the statement's own lock_timeout ends the wait at the
    // original deadline. Without it the keys would stay held for the full
    // 10 s session backstop.
    fixture
        .wait_for_lock_count(
            workspace_key,
            0,
            deadline + RELEASED_WITHIN,
            "workspace key after the cancellation",
        )
        .await;
    fixture
        .wait_for_lock_count(
            GLOBAL_MUTATION_LOCK_KEY,
            0,
            deadline + RELEASED_WITHIN,
            "global key after the cancellation",
        )
        .await;

    raw_unlock(&mut holder, sandbox_key).await;
    fixture
        .wait_for_lock_count(
            sandbox_key,
            0,
            Instant::now() + PROCEEDS_WITHIN,
            "sandbox key after the raw session unlocks",
        )
        .await;
    holder.close().await.expect("close the raw session");
    fixture.finish(vec![store]).await;
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_mutation_lock_released_connection_is_reused_without_residual_locks() {
    let fixture = LockFixture::new().await;
    let store = fixture.store(1).await;
    let workspace = random_id("ws");
    let sandbox = random_id("sb");
    let scope = MutationScope::sandbox(&workspace, &sandbox);

    let mut first = acquire_proceeds(&store, scope, "the first acquisition").await;
    let pid = first
        .postgres_backend_pid()
        .await
        .expect("a PostgreSQL guard");
    assert_eq!(fixture.session_lock_count(pid).await, 3);
    drop(first);

    // Returning the connection unlocks everything it held.
    let until = Instant::now() + PROCEEDS_WITHIN;
    while fixture.session_lock_count(pid).await != 0 {
        assert!(
            Instant::now() < until,
            "the released session still holds advisory locks"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    let mut second = acquire_proceeds(&store, scope, "the second acquisition").await;
    assert_eq!(second.postgres_backend_pid().await, Some(pid));
    drop(second);
    fixture.finish(vec![store]).await;
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_mutation_lock_pool_never_exceeds_configured_size() {
    let fixture = LockFixture::new().await;
    let postgres = PostgresStore::connect(fixture.schema.url())
        .await
        .expect("connect a store with the production lock pool");
    let store = Store::Postgres(postgres.clone());
    let workspace = random_id("ws");

    let holders: Vec<_> = (0..32)
        .map(|_| {
            let store = store.clone();
            let workspace = workspace.clone();
            tokio::spawn(async move {
                let sandbox = random_id("sb");
                let guard = acquire(
                    &store,
                    MutationScope::sandbox(&workspace, &sandbox),
                    PROCEEDS_WITHIN,
                )
                .await?;
                tokio::time::sleep(HOLD).await;
                drop(guard);
                Ok::<_, PersistenceError>(())
            })
        })
        .collect();
    let mut largest = 0;
    while !holders.iter().all(JoinHandle::is_finished) {
        largest = largest.max(postgres.lock_pool_size());
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    for holder in holders {
        holder
            .await
            .expect("holder task")
            .expect("every holder acquires its locks");
    }
    largest = largest.max(postgres.lock_pool_size());

    assert_eq!(
        largest, MUTATION_LOCK_POOL_MAX_CONNECTIONS,
        "32 concurrent holders fill the lock pool without exceeding it"
    );
    fixture.finish(vec![store]).await;
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_mutation_lock_unrelated_sandboxes_outpace_global_serialization() {
    const HOLDERS: usize = 64;
    let fixture = LockFixture::new().await;
    let stores = vec![
        fixture.store(MUTATION_LOCK_POOL_MAX_CONNECTIONS).await,
        fixture.store(MUTATION_LOCK_POOL_MAX_CONNECTIONS).await,
    ];
    let workspace = random_id("ws");

    let global = hold_concurrently(
        &stores,
        (0..HOLDERS)
            .map(|_| MutationScope::Global.lock_set())
            .collect(),
    )
    .await;
    let sandboxes = hold_concurrently(
        &stores,
        (0..HOLDERS)
            .map(|_| MutationScope::sandbox(&workspace, &random_id("sb")).lock_set())
            .collect(),
    )
    .await;

    // Global holders serialize (about HOLDERS x HOLD); distinct sandboxes
    // share the two lock pools. Compare the runs, not absolute times.
    assert!(
        sandboxes * 3 < global,
        "distinct sandboxes took {sandboxes:?}, global serialization took {global:?}"
    );
    fixture.finish(stores).await;
}
