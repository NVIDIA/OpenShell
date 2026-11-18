// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn fixture() -> (tempfile::TempDir, MockServer, Arc<AzureWorkloadIdentity>) {
    openshell_crypto::tls::ensure_default_provider();
    let directory = tempfile::tempdir().unwrap();
    let token_file = directory.path().join("projected-token");
    tokio::fs::write(&token_file, "first-projected-assertion")
        .await
        .unwrap();
    let server = MockServer::start().await;
    let identity = Arc::new(AzureWorkloadIdentity {
        client_id: "11111111-1111-1111-1111-111111111111".into(),
        token_file,
        endpoint: format!("{}/token", server.uri()),
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        token: Mutex::new(None),
    });
    (directory, server, identity)
}

async fn token_response(server: &MockServer, value: &str) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": value, "expires_in": 3600, "token_type": "Bearer"
        })))
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn concurrent_acquisitions_share_one_cached_token() {
    let (_directory, server, identity) = fixture().await;
    token_response(&server, "first-access-token").await;
    let calls = (0..12).map(|_| {
        let identity = Arc::clone(&identity);
        async move { identity.access_token(Duration::from_secs(5)).await.unwrap() }
    });
    for token in futures::future::join_all(calls).await {
        assert_eq!(token, "first-access-token");
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let fields: std::collections::HashMap<_, _> = url::form_urlencoded::parse(&requests[0].body)
        .into_owned()
        .collect();
    assert_eq!(fields["client_assertion"], "first-projected-assertion");
    assert_eq!(fields["scope"], POSTGRES_SCOPE);
    assert_eq!(fields["grant_type"], "client_credentials");
    assert!(!format!("{identity:?}").contains("first-access-token"));
}

#[tokio::test]
async fn expired_cache_reopens_rotated_projected_token() {
    let (directory, server, identity) = fixture().await;
    token_response(&server, "first-access-token").await;
    identity.access_token(Duration::from_secs(5)).await.unwrap();
    identity.token.lock().await.as_mut().unwrap().expires_at = Instant::now();
    let next = directory.path().join("next-token");
    tokio::fs::write(&next, "second-projected-assertion")
        .await
        .unwrap();
    tokio::fs::rename(&next, &identity.token_file)
        .await
        .unwrap();
    server.reset().await;
    token_response(&server, "second-access-token").await;
    assert_eq!(
        identity.access_token(Duration::from_secs(5)).await.unwrap(),
        "second-access-token"
    );
    let requests = server.received_requests().await.unwrap();
    let fields: std::collections::HashMap<_, _> = url::form_urlencoded::parse(&requests[0].body)
        .into_owned()
        .collect();
    assert_eq!(fields["client_assertion"], "second-projected-assertion");
}

#[tokio::test]
async fn failed_refresh_is_redacted_and_recovers_without_fallback() {
    let (_directory, server, identity) = fixture().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(503)
                .set_body_string("first-projected-assertion SECRET-UPSTREAM-TOKEN"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let error = identity
        .access_token(Duration::from_secs(5))
        .await
        .unwrap_err();
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains("first-projected-assertion"));
    assert!(!diagnostic.contains("SECRET-UPSTREAM-TOKEN"));
    assert!(identity.token.lock().await.is_none());
    server.reset().await;
    token_response(&server, "recovered-token").await;
    assert_eq!(
        identity.access_token(Duration::from_secs(5)).await.unwrap(),
        "recovered-token"
    );
}

#[tokio::test]
async fn short_lived_or_malformed_tokens_are_not_cached() {
    let (_directory, server, identity) = fixture().await;
    for response in [
        serde_json::json!({"access_token": "secret", "expires_in": 1, "token_type": "Bearer"}),
        serde_json::json!({"access_token": "", "expires_in": 3600, "token_type": "Bearer"}),
        serde_json::json!({"access_token": "secret", "expires_in": 3600, "token_type": "Other"}),
        serde_json::json!({"access_token": "secret with whitespace", "expires_in": 3600, "token_type": "Bearer"}),
        serde_json::json!({"access_token": "SECRET-MALFORMED", "expires_in": "not-a-number"}),
    ] {
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
        let error = identity
            .access_token(Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("SECRET-MALFORMED"));
        assert!(identity.token.lock().await.is_none());
    }
}

#[tokio::test]
async fn absent_or_oversized_assertion_never_reaches_entra() {
    let (_directory, server, identity) = fixture().await;
    for value in [String::new(), "x".repeat(MAX_CREDENTIAL_BYTES + 1)] {
        tokio::fs::write(&identity.token_file, value).await.unwrap();
        assert!(identity.access_token(Duration::from_secs(5)).await.is_err());
    }
    tokio::fs::remove_file(&identity.token_file).await.unwrap();
    assert!(identity.access_token(Duration::from_secs(5)).await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[test]
fn azure_urls_require_verified_tls_and_never_accept_passwords() {
    let base = "postgresql://mapped-role@server.postgres.database.azure.com/db";
    assert!(validate_url(&format!("{base}?sslmode=verify-full")).is_ok());
    for url in [
        "sqlite::memory:".to_string(),
        base.to_string(),
        format!("{base}?sslmode=require"),
        format!("{base}?sslmode=disable"),
        format!("{base}?sslmode=verify-full&password=URL-SECRET"),
        format!("{base}?sslmode=verify-full&passfile=/tmp/pgpass"),
        format!("{base}?sslmode=verify-full&host=override"),
        "postgresql://role:URL-SECRET@server/db?sslmode=verify-full".into(),
    ] {
        let error = validate_url(&url).unwrap_err();
        assert!(!error.to_string().contains("URL-SECRET"));
    }
}

#[tokio::test]
async fn azure_mode_rejects_sqlite_before_any_identity_lookup() {
    let result = super::super::Store::try_connect_with_database_auth(
        "sqlite::memory:",
        None,
        None,
        openshell_core::config::DatabaseAuthMode::AzureWorkloadIdentity,
    )
    .await;
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("requires PostgreSQL")
    );
}

/// Real `PostgreSQL` validates credentials; only the Entra HTTP endpoint is fake.
/// Controlled password changes prove both replica/pool pairs authenticate new
/// sessions with refreshed credentials rather than merely reusing live sessions.
#[tokio::test]
#[ignore = "requires a disposable PostgreSQL; run mise run test:rust:postgres"]
async fn postgres_azure_refresh_reconnects_both_pools_and_replicas() {
    let url = std::env::var(super::super::test_postgres::TEST_POSTGRES_URL_ENV).unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    let role = format!("azure_wi_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'first-access-token'"
    )))
    .execute(&admin)
    .await
    .unwrap();
    let mut scoped = url::Url::parse(&url).unwrap();
    scoped.set_username(&role).unwrap();
    scoped.set_password(None).unwrap();
    let options: PgConnectOptions = scoped.as_str().parse().unwrap();
    let options = options.ssl_mode(PgSslMode::Disable).password("");
    let (directory, server, identity) = fixture().await;
    token_response(&server, "first-access-token").await;
    let pools: Vec<_> = (0..4)
        .map(|index| {
            CredentialPool::azure(
                PgPoolOptions::new()
                    .max_connections(1)
                    .acquire_timeout(Duration::from_secs(3)),
                options
                    .clone()
                    .application_name(&format!("azure-wi-test-{index}")),
                Arc::clone(&identity),
            )
        })
        .collect();
    for pool in &pools {
        assert_eq!(
            sqlx::query_scalar::<_, i32>("SELECT 1")
                .fetch_one(pool)
                .await
                .unwrap(),
            1
        );
    }
    for pool in [&pools[1], &pools[3]] {
        let mut session = pool.acquire().await.unwrap();
        sqlx::query("SELECT pg_advisory_lock(5560)")
            .execute(&mut *session)
            .await
            .unwrap();
        let locked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock(5560)")
            .fetch_one(&mut *session)
            .await
            .unwrap();
        assert!(locked);
    }
    server.reset().await;
    token_response(&server, "second-access-token").await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER ROLE {role} PASSWORD 'second-access-token'"
    )))
    .execute(&admin)
    .await
    .unwrap();
    tokio::fs::write(directory.path().join("next"), "rotated-projected-assertion")
        .await
        .unwrap();
    tokio::fs::rename(directory.path().join("next"), &identity.token_file)
        .await
        .unwrap();
    identity.token.lock().await.as_mut().unwrap().expires_at = Instant::now();
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1")
        .bind(&role)
        .execute(&admin)
        .await
        .unwrap();
    for pool in &pools {
        assert_eq!(
            sqlx::query_scalar::<_, i32>("SELECT 2")
                .fetch_one(pool)
                .await
                .unwrap(),
            2
        );
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let fields: std::collections::HashMap<_, _> = url::form_urlencoded::parse(&requests[0].body)
        .into_owned()
        .collect();
    assert_eq!(fields["client_assertion"], "rotated-projected-assertion");
    server.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    identity.token.lock().await.as_mut().unwrap().expires_at = Instant::now();
    // Expiry alone must not interrupt healthy physical sessions.
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT 3")
            .fetch_one(&pools[0])
            .await
            .unwrap(),
        3
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1")
        .bind(&role)
        .execute(&admin)
        .await
        .unwrap();
    let error = sqlx::query_scalar::<_, i32>("SELECT 4")
        .fetch_one(&pools[0])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Azure database token exchange"));
    server.reset().await;
    token_response(&server, "second-access-token").await;
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT 5")
            .fetch_one(&pools[0])
            .await
            .unwrap(),
        5
    );
    for pool in pools {
        pool.close().await;
    }
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP ROLE {role}")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

/// Busy pools must wait for reusable sessions even when refresh fails or stalls.
#[tokio::test]
#[ignore = "requires a disposable PostgreSQL; run mise run test:rust:postgres"]
async fn postgres_azure_busy_pools_reuse_sessions_during_identity_outage() {
    let url = std::env::var(super::super::test_postgres::TEST_POSTGRES_URL_ENV).unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    let role = format!("azure_busy_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'busy-pool-token'"
    )))
    .execute(&admin)
    .await
    .unwrap();
    let mut scoped = url::Url::parse(&url).unwrap();
    scoped.set_username(&role).unwrap();
    scoped.set_password(None).unwrap();
    let options: PgConnectOptions = scoped.as_str().parse().unwrap();
    let options = options.ssl_mode(PgSslMode::Disable).password("");

    assert_busy_pool_reuse(&options, "busy-pool-token").await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP ROLE {role}")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

async fn assert_busy_pool_reuse(options: &PgConnectOptions, access_token: &str) {
    for (capacity, delay) in [
        (1, Duration::ZERO),
        (2, Duration::ZERO),
        (2, Duration::from_secs(15)),
    ] {
        let (_directory, server, identity) = fixture().await;
        token_response(&server, access_token).await;
        // Both pool kinds on two replicas use the same acquisition adapter.
        let pools: Vec<_> = (0..4)
            .map(|_| {
                CredentialPool::azure(
                    PgPoolOptions::new()
                        .max_connections(capacity)
                        .acquire_timeout(Duration::from_secs(5)),
                    options.clone(),
                    Arc::clone(&identity),
                )
            })
            .collect();
        for pool in &pools {
            drop(pool.acquire().await.unwrap());
        }
        identity.token.lock().await.as_mut().unwrap().expires_at = Instant::now();
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_delay(delay))
            .mount(&server)
            .await;

        for pool in &pools {
            let mut held = pool.acquire().await.unwrap();
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *held)
                .await
                .unwrap();
            let pool = pool.clone();
            let mut waiter = tokio::spawn(async move { pool.acquire().await });
            // Poll the waiter before release: the original code fails here on 503.
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut waiter)
                    .await
                    .is_err(),
                "busy acquisition must wait for a healthy session during an identity outage"
            );
            held.ping().await.unwrap();
            drop(held);
            let mut reused = tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let actual: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *reused)
                .await
                .unwrap();
            assert_eq!(
                actual, pid,
                "reuse the returned physical session without authentication"
            );
        }
        // If no session returns, retain the same finite acquisition deadline.
        // The checked-out healthy connection must survive the waiter's failure.
        let mut held = pools[0].acquire().await.unwrap();
        let started = Instant::now();
        let error = pools[0].acquire().await.unwrap_err();
        assert!(started.elapsed() >= Duration::from_secs(4));
        assert!(started.elapsed() < Duration::from_secs(7));
        assert!(
            matches!(error, sqlx::Error::Io(ref error) if error.kind() == std::io::ErrorKind::TimedOut)
        );
        held.ping().await.unwrap();
        drop(held);
        if capacity == 1 {
            assert!(
                server.received_requests().await.unwrap().is_empty(),
                "a saturated pool must not request a token while awaiting an existing session"
            );
        }
        for pool in pools {
            pool.close().await;
        }
    }
}

/// Run in an AKS Pod with gateway workload identity and its password-free URL.
/// Only initial credential acquisition uses real Entra. Expired cache entries
/// and an unavailable/stalled issuer reproduce the review scenario deterministically;
/// every physical database session uses the real Azure role and verified TLS.
#[tokio::test]
#[ignore = "requires AKS gateway workload identity and OPENSHELL_DB_URL"]
async fn azure_postgres_busy_pools_reuse_sessions_during_identity_outage() {
    let url = std::env::var("OPENSHELL_DB_URL").unwrap();
    let options = validate_url(&url).unwrap();
    let identity = AzureWorkloadIdentity::from_env().unwrap();
    let token = identity
        .access_token(Duration::from_secs(30))
        .await
        .unwrap();
    // The mock issuer receives only fixture assertions, never the real projected
    // token. Access tokens are used as database passwords and are never printed.
    assert_busy_pool_reuse(&options, &token).await;
}

#[test]
fn credential_unavailability_preserves_database_io_error_classification() {
    use super::super::{PersistenceError, map_db_error};

    // A transport timeout may happen after a statement was sent. It must not
    // gain the pre-acquisition failure classification used by credentials.
    let transport_timeout = sqlx::Error::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "database transport timed out",
    ));
    assert!(matches!(
        map_db_error(&transport_timeout),
        PersistenceError::Database(_)
    ));
    let credential_error = unavailable("Azure credential acquisition failed");
    assert!(matches!(
        map_db_error(&credential_error),
        PersistenceError::Unavailable(message) if message.contains("Azure credential acquisition failed")
    ));
    assert!(matches!(
        map_db_error(&sqlx::Error::PoolTimedOut),
        PersistenceError::Unavailable(_)
    ));
}
