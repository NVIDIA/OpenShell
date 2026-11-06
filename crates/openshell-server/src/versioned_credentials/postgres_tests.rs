// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::persistence::test_postgres::TestSchema;
use openshell_credential_issuer::{EmbeddedCredentialIssuer, IssuerConfig};

#[path = "postgres_startup_tests.rs"]
mod startup;

async fn candidates(backend: &dyn CredentialIssuer, id: &str, value: &str) -> Handles {
    let values = HashMap::from([
        ("ACCESS".into(), format!("{value}-access")),
        ("SECRET".into(), format!("{value}-secret")),
        ("SESSION".into(), format!("{value}-session")),
    ]);
    backend
        .store(StoreSecrets {
            owner: SecretOwner::provider("work", "owner", "provider"),
            object_id: Some(id),
            values: &values,
            existing_handles: &Handles::new(),
        })
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_versioned_bundle_cas_coordinates_independent_replicas_without_mixed_outputs() {
    let schema = TestSchema::create("issuer_bundle").await;
    let first_store = Arc::new(schema.connect_store().await);
    let second_store = Arc::new(schema.connect_store().await);
    let backend: Arc<dyn CredentialIssuer> = Arc::new(
        EmbeddedCredentialIssuer::from_config(&IssuerConfig {
            credential_drivers: vec!["test-static".into()],
            ..Default::default()
        })
        .unwrap(),
    );
    let first = VersionedCredentials::new(Arc::clone(&first_store), Arc::clone(&backend)).unwrap();
    let second =
        VersionedCredentials::new(Arc::clone(&second_store), Arc::clone(&backend)).unwrap();
    let owner = SecretOwner::provider("work", "owner", "provider");
    let original = candidates(backend.as_ref(), "original", "original").await;
    let refs = first
        .references
        .adopt_with_expiration(owner, "epoch", &original, None, "adoption")
        .await
        .unwrap();
    let one = candidates(backend.as_ref(), "one", "one").await;
    let two = candidates(backend.as_ref(), "two", "two").await;
    let (a, b) = tokio::join!(
        first.references.activate_bundle(ActivateBundle {
            owner,
            epoch: "epoch",
            references: &refs,
            candidates: &one,
            operation_id: "one",
            expected_generation: 1,
            expiration_time: None,
            grant: None
        }),
        second.references.activate_bundle(ActivateBundle {
            owner,
            epoch: "epoch",
            references: &refs,
            candidates: &two,
            operation_id: "two",
            expected_generation: 1,
            expiration_time: None,
            grant: None
        }),
    );
    assert_ne!(
        a.is_ok(),
        b.is_ok(),
        "exactly one expected-generation activation wins"
    );
    let prefix = if a.is_ok() { "one" } else { "two" };
    let values = second.references.resolve(owner, &refs).await.unwrap();
    assert_eq!(values.len(), 3);
    assert!(values.iter().all(|value| value.version == 2
        && value.generation == 2
        && value.value.starts_with(prefix)));
    first.references.reclaim(owner, 32).await.unwrap();
    let reloaded = second.references.resolve(owner, &refs).await.unwrap();
    assert!(
        reloaded
            .iter()
            .all(|value| value.version == 2 && value.value.starts_with(prefix))
    );
    first_store.close().await;
    second_store.close().await;
    schema.drop_schema().await;
}

#[tokio::test]
#[ignore = "requires OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_versioned_grant_tombstone_and_outputs_are_one_cas_and_survive_restart() {
    let schema = TestSchema::create("issuer_revoke").await;
    let store = Arc::new(schema.connect_store().await);
    let other_store = Arc::new(schema.connect_store().await);
    let backend: Arc<dyn CredentialIssuer> = Arc::new(
        EmbeddedCredentialIssuer::from_config(&IssuerConfig {
            credential_drivers: vec!["test-static".into()],
            ..Default::default()
        })
        .unwrap(),
    );
    let first = VersionedCredentials::new(Arc::clone(&store), Arc::clone(&backend)).unwrap();
    let owner = SecretOwner::provider("work", "owner", "provider");
    let refs = first
        .references
        .prepare_bundle(
            owner,
            "epoch",
            &ReferenceRuntime::pending_handles(
                "test-static",
                ["ACCESS".into(), "SECRET".into(), "SESSION".into()],
            )
            .unwrap(),
            "prepared",
        )
        .await
        .unwrap();
    let grant = first
        .references
        .prepare_grant(owner, "grant", "epoch", b"nonsecret-state")
        .await
        .unwrap();
    let active = first
        .references
        .activate_grant(owner, "grant", grant.resource_version, None)
        .await
        .unwrap();
    let values = candidates(backend.as_ref(), "values", "values").await;
    first
        .references
        .activate_bundle(ActivateBundle {
            owner,
            epoch: "epoch",
            references: &refs,
            candidates: &values,
            operation_id: "mint",
            expected_generation: 0,
            expiration_time: None,
            grant: Some(GrantTransition {
                grant_id: "grant",
                expected_resource_version: active.resource_version,
                state: b"refreshed",
            }),
        })
        .await
        .unwrap();
    let second = VersionedCredentials::new(Arc::clone(&other_store), Arc::clone(&backend)).unwrap();
    let live = second
        .references
        .get_grant(owner, "grant")
        .await
        .unwrap()
        .unwrap();
    let dead = second
        .references
        .tombstone_grant(
            owner,
            "grant",
            live.resource_version,
            b"deleting-with-cleanup",
        )
        .await
        .unwrap();
    assert!(!dead.active && !dead.prepared);
    assert!(first.references.resolve(owner, &refs).await.is_err());
    let reloaded = first
        .references
        .get_grant(owner, "grant")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.state, b"deleting-with-cleanup");
    assert_eq!(reloaded.resource_version, dead.resource_version);
    assert_eq!(
        first
            .references
            .activate_bundle(ActivateBundle {
                owner,
                epoch: "epoch",
                references: &refs,
                candidates: &values,
                operation_id: "stale",
                expected_generation: 1,
                expiration_time: None,
                grant: None
            })
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
    store.close().await;
    other_store.close().await;
    schema.drop_schema().await;
}
