// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::Store;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_REFRESH_TEST_DATABASE_URL"]
async fn refresh_locks_coordinate_independent_replica_sessions() {
    let url =
        std::env::var("OPENSHELL_REFRESH_TEST_DATABASE_URL").expect("disposable database URL");
    let first = Store::connect(&url).await.unwrap();
    let second = Store::connect(&url).await.unwrap();
    let provider = uuid::Uuid::new_v4().to_string();
    let guard = first
        .acquire_refresh_guard(&provider, "ACCESS_TOKEN")
        .await
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
    first.close().await;
    second.close().await;
}
