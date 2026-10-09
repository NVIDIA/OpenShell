// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `PostgreSQL` tests of the mutation advisory locks: exclusion between two
//! stores (as between two gateway replicas), exclusion against the legacy
//! global key, cleanup after timed-out and cancelled acquisitions, a stalled
//! holder, the lock-pool bound and its in-use gauge, and lock connections that
//! `PostgreSQL` does not open.
//!
//! Advisory locks are database-wide, not per schema, so every test uses
//! random workspace and sandbox ids, and `mise run test:rust:postgres` runs
//! the tests one at a time. Apart from the pool-size test, which connects as
//! the gateway does, the stores here run no migrations: the schema only
//! scopes their connections.

use super::mutation_lock::{
    GLOBAL_MUTATION_LOCK_KEY, LOCK_CONNECTION_MIN_BUDGET, MUTATION_LOCK_POOL_MAX_CONNECTIONS,
    MUTATION_LOCK_TIMEOUT, MutationLockKey, MutationLockSet,
};
use super::postgres::LOCK_CONNECTION_RELEASE_TIMEOUT;
use super::test_postgres::TestSchema;
use super::{
    DistributedMutationGuard, PersistenceError, PersistenceResult, PostgresStore, Store,
    map_db_error,
};
use crate::compute::MutationScope;
use crate::gateway_metrics::{MUTATION_LOCK_CONNECTIONS_IN_USE, MetricsCapture};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_concurrent_sandbox_creates_with_ssh_identity_do_not_exhaust_lock_pool() {
    use crate::credentials::CredentialRuntime;
    use openshell_core::jwt::{
        CredentialEpoch, SandboxLaunchAuthentication, SecretJwt, SessionRotation,
        SupervisorAuthBundle,
    };
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{Sandbox, SandboxPhase, SandboxSpec};
    use openshell_core::{SandboxSessionId, sandbox_generation::SandboxGenerationId};
    use russh::keys::{HashAlg, PrivateKey};
    use std::collections::HashSet;
    use std::sync::Arc;

    let schema = TestSchema::create("ssh_create").await;
    let store = Arc::new(schema.connect_store().await);
    let runtime = crate::compute::new_test_runtime(store.clone()).await;
    let config = crate::Config::new(None);
    runtime.configure_ssh_identities(
        CredentialRuntime::from_config_with_store(&config, store.clone()).unwrap(),
    );
    let authentication = SandboxLaunchAuthentication {
        supervisor: SupervisorAuthBundle {
            session_id: SandboxSessionId::new(),
            runtime_generation: SandboxGenerationId::parse("generation").unwrap(),
            session_rotation: SessionRotation::new(1).unwrap(),
            auth_epoch: CredentialEpoch::new(1).unwrap(),
            gateway_token: SecretJwt::parse("gateway-token").unwrap(),
            gateway_expires_at: 0,
            sandbox_token: SecretJwt::parse("sandbox-token").unwrap(),
            sandbox_expires_at: 0,
            ssh_host_private_key: None,
        },
        gateway_id: "gateway".to_string(),
        verification_keys: Vec::new(),
    };

    let mut pending = Vec::new();
    for _ in 0..MUTATION_LOCK_POOL_MAX_CONNECTIONS {
        let id = random_id("ssh-create");
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: id.clone(),
                name: id.clone(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Provisioning as i32);
        let guards =
            crate::persistence::lock_order::branch(runtime.sandbox_create_guards("default", &id))
                .await
                .expect("each create holds one mutation-pool slot");
        pending.push((sandbox, guards));
    }
    let Store::Postgres(postgres) = store.as_ref() else {
        unreachable!();
    };
    assert_eq!(
        postgres.lock_pool_size(),
        MUTATION_LOCK_POOL_MAX_CONNECTIONS
    );
    assert_eq!(postgres.lock_pool_idle(), 0, "all lock slots are occupied");

    let mut tasks = JoinSet::new();
    for (sandbox, (lifecycle_guard, mutation_guard)) in pending {
        let runtime = runtime.clone();
        let encoded = serde_json::to_vec(&authentication).unwrap();
        tasks.spawn(async move {
            Box::pin(runtime.create_sandbox_authenticated_with_guards(
                sandbox,
                None,
                Some(encoded),
                false,
                lifecycle_guard,
                mutation_guard,
            ))
            .await
        });
    }
    let created = tokio::time::timeout(PROCEEDS_WITHIN, async {
        let mut created = Vec::new();
        while let Some(result) = tasks.join_next().await {
            created.push(
                result
                    .expect("create task")
                    .expect("create with SSH identity"),
            );
        }
        created
    })
    .await
    .expect("SSH setup must progress while all mutation-pool slots are held");
    assert_eq!(created.len(), MUTATION_LOCK_POOL_MAX_CONNECTIONS as usize);

    let identities = crate::ssh_identity::SshIdentityStore::new(
        store.clone(),
        CredentialRuntime::from_config_with_store(&config, store.clone()).unwrap(),
    );
    let mut fingerprints = HashSet::new();
    for mut sandbox in created {
        let fingerprint = sandbox.host_key_fingerprint.clone();
        assert!(!fingerprint.is_empty());
        assert!(
            fingerprints.insert(fingerprint.clone()),
            "distinct SSH keys"
        );
        let mut authentication = authentication.clone();
        identities
            .prepare(&mut sandbox, &mut authentication)
            .await
            .unwrap();
        let private_key = authentication.supervisor.ssh_host_private_key.unwrap();
        let key = PrivateKey::from_openssh(private_key.expose_secret()).unwrap();
        assert_eq!(
            key.public_key().fingerprint(HashAlg::Sha256).to_string(),
            fingerprint
        );
        assert_eq!(sandbox.host_key_fingerprint, fingerprint);
    }

    store.close().await;
    schema.drop_schema().await;
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
            PostgresStore::connect_with_lock_pool_size(self.schema.url(), None, lock_pool_size)
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

/// Wait until `openshell_server_mutation_lock_connections_in_use` reads
/// `expected`. A lock connection goes back to the pool from a background
/// task, and stays counted until then.
async fn wait_for_lock_connections_in_use(
    in_use: &(dyn Fn() -> Option<i64> + Send + Sync),
    expected: i64,
    what: &str,
) {
    let until = Instant::now() + PROCEEDS_WITHIN;
    loop {
        let value = in_use();
        if value == Some(expected) {
            return;
        }
        assert!(
            Instant::now() < until,
            "{what}: {value:?} lock connections in use, expected {expected}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
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
        PostgresStore::connect_with_lock_pool_size(&proxy.url, None, 1)
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
        MutationScope::profiles(""),
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
    // Only a guard acquisition turns 55P03 into a lock timeout; the
    // generic mapping keeps any other session's 55P03 a database error.
    assert!(
        matches!(map_db_error(&error), PersistenceError::Database(_)),
        "a 55P03 outside a guard acquisition is a database error"
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
    let mut stores = Vec::new();
    // The production default, then a configured size above it, both through
    // the entry point the gateway uses.
    for (configured, expected) in [(None, MUTATION_LOCK_POOL_MAX_CONNECTIONS), (Some(6), 6)] {
        let store = Store::connect_with_pool_sizes(fixture.schema.url(), None, configured)
            .await
            .expect("connect a store as the gateway does");
        let Store::Postgres(postgres) = &store else {
            unreachable!("a postgres:// URL connects a PostgreSQL store");
        };
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
            largest, expected,
            "32 concurrent holders fill the lock pool ({configured:?} configured) without exceeding it"
        );
        stores.push(store);
    }
    fixture.finish(stores).await;
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_mutation_lock_connections_gauge_tracks_checked_out_connections() {
    // A current-thread runtime runs the tasks that return lock connections
    // on this thread, so their gauge updates reach the capture.
    let metrics = MetricsCapture::install();
    let in_use = metrics.value_reader(MUTATION_LOCK_CONNECTIONS_IN_USE);
    let fixture = LockFixture::new().await;
    let store = fixture.store(2).await;
    wait_for_lock_connections_in_use(&*in_use, 0, "after warming the pool").await;

    // Two holders on disjoint sandboxes check out the whole pool.
    let workspace = random_id("ws");
    let first = acquire_proceeds(
        &store,
        MutationScope::sandbox(&workspace, &random_id("sb")),
        "the first holder",
    )
    .await;
    let second = acquire_proceeds(
        &store,
        MutationScope::sandbox(&workspace, &random_id("sb")),
        "the second holder",
    )
    .await;
    assert_eq!(in_use(), Some(2));
    drop(first);
    drop(second);
    wait_for_lock_connections_in_use(&*in_use, 0, "after both holders released").await;

    // The raw session holds only the sandbox key, so the store's only
    // checked-out connection is the waiting acquisition's.
    let workspace = random_id("ws");
    let sandbox = sandbox_id_locked_last(&workspace);
    let sandbox_key = MutationLockKey::Sandbox(&sandbox).advisory_key();
    let mut holder = fixture.raw_session().await;
    raw_lock(&mut holder, sandbox_key)
        .await
        .expect("the raw session takes the sandbox key");

    // A wait for a PostgreSQL lock keeps its connection checked out until
    // the lock timeout (55P03) returns it.
    let deadline = Instant::now() + INTERRUPTED_DEADLINE;
    let (acquisition, _) = fixture
        .spawn_waiting_acquisition(&store, &workspace, &sandbox, deadline)
        .await;
    assert_eq!(in_use(), Some(1), "a waiting acquisition is counted");
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
    wait_for_lock_connections_in_use(&*in_use, 0, "after the lock timeout").await;

    // A cancelled acquisition stays counted until its session is closed.
    let deadline = Instant::now() + INTERRUPTED_DEADLINE;
    let (acquisition, _) = fixture
        .spawn_waiting_acquisition(&store, &workspace, &sandbox, deadline)
        .await;
    assert_eq!(in_use(), Some(1), "a waiting acquisition is counted");
    acquisition.abort();
    let Err(error) = acquisition.await else {
        panic!("the cancelled acquisition should not finish");
    };
    assert!(error.is_cancelled());
    wait_for_lock_connections_in_use(&*in_use, 0, "after the cancellation").await;

    raw_unlock(&mut holder, sandbox_key).await;
    holder.close().await.expect("close the raw session");
    fixture.finish(vec![store]).await;
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_mutation_lock_stalled_holder_fails_waiters_by_their_deadline() {
    let fixture = LockFixture::new().await;
    let store_a = fixture.store(MUTATION_LOCK_POOL_MAX_CONNECTIONS).await;
    let store_b = fixture.store(MUTATION_LOCK_POOL_MAX_CONNECTIONS).await;
    let workspace = random_id("ws");
    let stalled = random_id("sb");

    // Nothing bounds a hold, so this holder keeps its locks until the test
    // drops it, like one blocked in a compute driver or middleware call.
    let holder = acquire_proceeds(
        &store_a,
        MutationScope::sandbox(&workspace, &stalled),
        "the stalled holder",
    )
    .await;

    // Waiters that conflict with it on the other store fail with
    // PostgreSQL's lock timeout by their own deadline. They run one at a
    // time, so a queued exclusive request cannot hold up the next one.
    for (scope, what) in [
        (
            MutationScope::sandbox(&workspace, &stalled),
            "the stalled sandbox",
        ),
        (
            MutationScope::Workspace(&workspace),
            "the stalled sandbox's workspace",
        ),
        (MutationScope::Global, "the global scope"),
    ] {
        wait_for_idle_lock_connection(&store_b).await;
        let started = Instant::now();
        acquire_times_out(&store_b, scope, what).await;
        let waited = started.elapsed();
        assert!(
            waited < EXPECTED_TIMEOUT + CLIENT_BACKSTOP_GRACE,
            "{what}: failed after {waited:?}"
        );
    }
    drop(
        acquire_proceeds(
            &store_b,
            MutationScope::sandbox(&workspace, &random_id("sb")),
            "another sandbox in the stalled sandbox's workspace",
        )
        .await,
    );
    drop(
        acquire_proceeds(
            &store_b,
            MutationScope::Workspace(&random_id("ws")),
            "another workspace",
        )
        .await,
    );
    assert_eq!(
        fixture
            .lock_count(MutationLockKey::Sandbox(&stalled).advisory_key())
            .await,
        1,
        "the holder keeps its key after every waiter gave up"
    );

    // Stalled holders that check out every lock connection of store A make
    // its next acquisition fail by its deadline, while store B keeps working.
    let mut fillers = Vec::new();
    for _ in 1..MUTATION_LOCK_POOL_MAX_CONNECTIONS {
        fillers.push(
            acquire_proceeds(
                &store_a,
                MutationScope::sandbox(&random_id("ws"), &random_id("sb")),
                "a holder that fills store A's lock pool",
            )
            .await,
        );
    }
    let started = Instant::now();
    match acquire(
        &store_a,
        MutationScope::sandbox(&random_id("ws"), &random_id("sb")),
        EXPECTED_TIMEOUT,
    )
    .await
    {
        Err(PersistenceError::LockTimeout(detail)) => {
            assert_eq!(detail, "waiting for a mutation lock connection");
        }
        Err(error) => panic!("expected a lock timeout from a full pool, got {error:?}"),
        Ok(_) => panic!("a full lock pool handed out another connection"),
    }
    let waited = started.elapsed();
    assert!(
        waited < EXPECTED_TIMEOUT + CLIENT_BACKSTOP_GRACE,
        "store A failed after {waited:?}"
    );
    drop(
        acquire_proceeds(
            &store_b,
            MutationScope::sandbox(&random_id("ws"), &random_id("sb")),
            "store B while store A's lock pool is full",
        )
        .await,
    );

    drop(fillers);
    drop(holder);
    drop(
        acquire_proceeds(
            &store_b,
            MutationScope::sandbox(&workspace, &stalled),
            "the stalled sandbox after its holder releases",
        )
        .await,
    );
    fixture.finish(vec![store_a, store_b]).await;
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_mutation_lock_connection_failure_is_not_a_lock_timeout() {
    let fixture = LockFixture::new().await;

    // Every lock connection is checked out, so the acquisition waits for one
    // to come back: lock contention. The deadline leaves time to open a
    // connection, so only the full pool makes this a lock timeout.
    let saturated = fixture.store(1).await;
    let held = acquire_proceeds(
        &saturated,
        MutationScope::sandbox(&random_id("ws"), &random_id("sb")),
        "the only lock connection",
    )
    .await;
    match acquire(
        &saturated,
        MutationScope::sandbox(&random_id("ws"), &random_id("sb")),
        LOCK_CONNECTION_MIN_BUDGET + EXPECTED_TIMEOUT,
    )
    .await
    {
        Err(PersistenceError::LockTimeout(detail)) => {
            assert_eq!(detail, "waiting for a mutation lock connection");
        }
        Err(error) => panic!("expected a lock timeout from a full pool, got {error:?}"),
        Ok(_) => panic!("a full lock pool handed out a second connection"),
    }
    drop(held);

    // The pool has room and the deadline leaves time to open a connection,
    // but PostgreSQL never answers one: a database failure, not contention.
    let proxy = StallingProxy::start(fixture.schema.url()).await;
    let unanswered = Store::Postgres(
        PostgresStore::connect_with_lock_pool_size(&proxy.url, None, 1)
            .await
            .expect("connect a store through the proxy"),
    );
    proxy.stalled.send_replace(true);
    match acquire(
        &unanswered,
        MutationScope::sandbox(&random_id("ws"), &random_id("sb")),
        LOCK_CONNECTION_MIN_BUDGET + EXPECTED_TIMEOUT,
    )
    .await
    {
        Err(PersistenceError::Database(detail)) => assert!(
            detail.starts_with("could not open a mutation lock connection"),
            "{detail}"
        ),
        Err(error) => panic!("expected a database error, got {error:?}"),
        Ok(_) => panic!("a stalled PostgreSQL opened a lock connection"),
    }
    proxy.stalled.send_replace(false);

    fixture.finish(vec![saturated, unanswered]).await;
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
