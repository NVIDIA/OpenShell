// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::mutation_lock::{MUTATION_LOCK_POOL_MAX_CONNECTIONS, MUTATION_LOCK_TIMEOUT};
use super::{MutationLockSet, Store};
use std::time::Duration;

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_refresh_locks_coordinate_independent_replica_sessions() {
    let url = std::env::var("OPENSHELL_TEST_POSTGRES_URL")
        .or_else(|_| std::env::var("OPENSHELL_REFRESH_TEST_DATABASE_URL"))
        .expect("disposable database URL");
    let first = Store::connect(&url).await.unwrap();
    let second = Store::connect(&url).await.unwrap();
    let provider = uuid::Uuid::new_v4().to_string();
    let mut mutation_guards = Vec::new();
    for _ in 0..MUTATION_LOCK_POOL_MAX_CONNECTIONS {
        let sandbox = uuid::Uuid::new_v4().to_string();
        mutation_guards.push(
            first
                .acquire_distributed_mutation_guard(
                    &MutationLockSet::sandbox_lifecycle(&sandbox),
                    tokio::time::Instant::now() + MUTATION_LOCK_TIMEOUT,
                )
                .await
                .unwrap(),
        );
    }
    let Store::Postgres(postgres) = &first else {
        unreachable!();
    };
    assert_eq!(
        postgres.lock_pool_size(),
        MUTATION_LOCK_POOL_MAX_CONNECTIONS
    );
    assert_eq!(postgres.lock_pool_idle(), 0);
    let guard = tokio::time::timeout(
        Duration::from_secs(2),
        first.acquire_refresh_guard(&provider, "ACCESS_TOKEN"),
    )
    .await
    .expect("refresh must progress while every mutation-pool slot is held")
    .unwrap();
    // This bypasses the process-local mutex: independent database sessions must
    // still serialize a mint, while unrelated credentials remain independent.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            second.acquire_refresh_guard(&provider, "ACCESS_TOKEN")
        )
        .await
        .is_err()
    );
    let unrelated = tokio::time::timeout(
        Duration::from_secs(2),
        second.acquire_refresh_guard(&provider, "OTHER_KEY"),
    )
    .await
    .unwrap()
    .unwrap();
    drop(unrelated);
    drop(guard);
    let guard = tokio::time::timeout(
        Duration::from_secs(2),
        second.acquire_refresh_guard(&provider, "ACCESS_TOKEN"),
    )
    .await
    .unwrap()
    .unwrap();
    drop(guard);
    drop(mutation_guards);
    first.close().await;
    second.close().await;
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_activation_lock_preserves_legacy_key_without_consuming_data_capacity() {
    let schema = super::test_postgres::TestSchema::create("activation_lock").await;
    let first = Store::connect_with_pool_sizes(schema.url(), Some(2), Some(1))
        .await
        .unwrap();
    let second = Store::connect_with_pool_sizes(schema.url(), Some(2), Some(1))
        .await
        .unwrap();
    let issuer = uuid::Uuid::new_v4().to_string();
    let legacy = first
        .acquire_refresh_guard(&issuer, "migration")
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            second.acquire_credential_activation_guard(&issuer)
        )
        .await
        .is_err()
    );
    drop(legacy);
    let activation = tokio::time::timeout(
        Duration::from_secs(2),
        second.acquire_credential_activation_guard(&issuer),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            first.acquire_refresh_guard(&issuer, "migration")
        )
        .await
        .is_err()
    );
    // One lock-pool slot and one data-pool slot are now retained; database work
    // must still progress with the supported two data connections.
    let credential = second
        .acquire_refresh_guard("provider", "TOKEN")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), second.ping())
        .await
        .unwrap()
        .unwrap();
    drop(credential);
    drop(activation);
    first.close().await;
    second.close().await;
    schema.drop_schema().await;
}
