// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::persistence::test_store;
use openshell_core::proto::{
    CredentialHandle, ObjectMeta, ProviderCredentialRefreshRecoveryAction,
};
use openshell_credential_issuer::refresh::{effective_authorization_epoch, refresh_has_expiration};
use std::collections::HashMap;

fn handle(generation: &str) -> CredentialHandle {
    CredentialHandle {
        driver: "test-driver".into(),
        handle: format!("opaque-{generation}"),
        metadata: HashMap::from([("generation".into(), generation.into())]),
    }
}

fn full_state() -> StoredProviderCredentialRefreshState {
    StoredProviderCredentialRefreshState {
        metadata: Some(ObjectMeta {
            id: "refresh-id".into(),
            name: refresh_state_name("provider-id", "ACCESS_TOKEN"),
            workspace: "default".into(),
            created_time: Some(prost_types::Timestamp {
                seconds: 1_700_000_000,
                nanos: 123_456_789,
            }),
            labels: HashMap::from([
                ("example.com/team".into(), "platform".into()),
                ("environment".into(), "test".into()),
            ]),
            resource_version: 73,
            annotations: HashMap::from([
                ("example.com/unrelated".into(), "preserve me".into()),
                (
                    "openshell.nvidia.com/refresh-expiration-present".into(),
                    "true".into(),
                ),
                (
                    "openshell.nvidia.com/refresh-completed-mint".into(),
                    "completed-mint-id".into(),
                ),
            ]),
            deletion_time: Some(prost_types::Timestamp {
                seconds: 1_700_000_100,
                nanos: 987_654_321,
            }),
        }),
        provider_id: "provider-id".into(),
        provider_name: "provider-name".into(),
        credential_key: "ACCESS_TOKEN".into(),
        // Unknown enum integers must survive a read-modify-write, not become Unspecified.
        strategy: 12_345,
        material: HashMap::from([
            ("client_id".into(), "synthetic-client".into()),
            (
                "refresh_token".into(),
                "synthetic-legacy-inline-token".into(),
            ),
        ]),
        secret_material_keys: vec!["refresh_token".into(), "client_secret".into()],
        expires_at_ms: 0,
        next_refresh_at_ms: i64::MAX,
        last_refresh_at_ms: 1_700_000_010_123,
        status: "reauthorization_required".into(),
        last_error: "refresh authorization rejected".into(),
        token_url: "https://example.invalid/token".into(),
        scopes: vec!["scope-b".into(), "scope-a".into()],
        refresh_before: Some(prost_types::Duration {
            seconds: 30,
            nanos: 123_456_789,
        }),
        max_lifetime: Some(prost_types::Duration {
            seconds: 3_600,
            nanos: 987_654_321,
        }),
        additional_output_keys: HashMap::from([
            ("secret_access_key".into(), "PINNED_SECRET_KEY".into()),
            ("session_token".into(), "PINNED_SESSION_TOKEN".into()),
        ]),
        authorization_epoch: "authorization-epoch".into(),
        secret_material_handles: HashMap::from([
            ("refresh_token".into(), handle("current")),
            ("client_secret".into(), handle("client")),
        ]),
        pending_secret_deletions: vec![
            StoredRefreshMaterialDeletion {
                material_key: "refresh_token".into(),
                handle: Some(handle("old-1")),
            },
            StoredRefreshMaterialDeletion {
                material_key: "refresh_token".into(),
                handle: Some(handle("old-2")),
            },
            StoredRefreshMaterialDeletion {
                material_key: "legacy-missing-handle".into(),
                handle: None,
            },
        ],
        recovery_action: ProviderCredentialRefreshRecoveryAction::Reauthorize as i32,
        failure_code: "oauth_invalid_grant".into(),
        provider_error_subtype: "invalid_rapt".into(),
        last_error_at_ms: 1_700_000_020_456,
    }
}

fn version(state: &RefreshState) -> u64 {
    state
        .metadata
        .as_ref()
        .expect("refresh metadata")
        .resource_version
}

fn assert_same_state(actual: &RefreshState, expected: &RefreshState) {
    // Compare the complete protobuf rather than only the fields used by the engine.
    assert_eq!(
        StoredProviderCredentialRefreshState::from(actual),
        StoredProviderCredentialRefreshState::from(expected)
    );
}

#[tokio::test]
async fn v2_round_trip_preserves_all_fields_and_legacy_epoch_inline_material() {
    let adapter = ServerRefreshStore(Arc::new(test_store().await));
    let original = full_state();
    let owned = RefreshState::from(&original);
    assert!(
        refresh_has_expiration(&owned),
        "explicit Unix epoch expiration"
    );
    assert_eq!(
        effective_authorization_epoch(&owned).unwrap(),
        "authorization-epoch"
    );
    let restored = StoredProviderCredentialRefreshState::from(&owned);
    assert_eq!(restored, original);
    // Prost HashMap entry order is not canonical; decode both byte streams to
    // assert wire-value equality without depending on randomized map iteration.
    assert_eq!(
        StoredProviderCredentialRefreshState::decode(restored.encode_to_vec().as_slice()).unwrap(),
        StoredProviderCredentialRefreshState::decode(original.encode_to_vec().as_slice()).unwrap()
    );

    adapter.create(&owned).await.unwrap();
    let persisted = adapter.get_by_id(owned.object_id()).await.unwrap().unwrap();
    let mut expected = owned.clone();
    expected.metadata.as_mut().unwrap().resource_version = 1;
    assert_same_state(&persisted, &expected);

    let mut legacy = original;
    legacy.authorization_epoch.clear();
    legacy.secret_material_handles.clear();
    legacy.pending_secret_deletions.clear();
    legacy
        .metadata
        .as_mut()
        .unwrap()
        .annotations
        .remove("openshell.nvidia.com/refresh-expiration-present");
    let legacy_owned = RefreshState::from(&legacy);
    assert_eq!(
        effective_authorization_epoch(&legacy_owned).unwrap(),
        "refresh-id"
    );
    assert!(!refresh_has_expiration(&legacy_owned));
    assert_eq!(
        StoredProviderCredentialRefreshState::from(&legacy_owned),
        legacy
    );
    let new_version = adapter
        .replace(&legacy_owned, version(&persisted))
        .await
        .unwrap()
        .unwrap();
    let reloaded = adapter
        .get("default", "provider-id", "ACCESS_TOKEN")
        .await
        .unwrap()
        .unwrap();
    legacy.metadata.as_mut().unwrap().resource_version = new_version;
    assert_eq!(
        StoredProviderCredentialRefreshState::from(&reloaded),
        legacy
    );
    assert_eq!(
        effective_authorization_epoch(&reloaded).unwrap(),
        "refresh-id"
    );
    assert_eq!(
        reloaded.material["refresh_token"],
        "synthetic-legacy-inline-token"
    );
    assert!(reloaded.secret_material_handles.is_empty());
    assert!(!refresh_has_expiration(&reloaded));

    // Old records with a nonzero expiration need no presence annotation.
    let mut legacy_expiring = reloaded;
    legacy_expiring.expires_at_ms = 1_700_000_030_789;
    assert!(refresh_has_expiration(&legacy_expiring));
    let round_trip = RefreshState::from(&StoredProviderCredentialRefreshState::from(
        &legacy_expiring,
    ));
    assert_same_state(&round_trip, &legacy_expiring);
    assert!(refresh_has_expiration(&round_trip));
}

#[tokio::test]
async fn sqlite_create_is_unique_and_get_list_hydrate_authoritative_versions() {
    let adapter = ServerRefreshStore(Arc::new(test_store().await));
    let state = RefreshState::from(&full_state());
    adapter.create(&state).await.unwrap();

    let mut duplicate = state.clone();
    duplicate.metadata.as_mut().unwrap().id = "losing-refresh-id".into();
    duplicate.status = "loser".into();
    assert_eq!(
        adapter.create(&duplicate).await.unwrap_err().code(),
        tonic::Code::Aborted
    );
    assert!(
        adapter
            .get_by_id(duplicate.object_id())
            .await
            .unwrap()
            .is_none()
    );

    let loaded = adapter
        .get("default", "provider-id", "ACCESS_TOKEN")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        version(&loaded),
        1,
        "row version overrides serialized version 73"
    );
    let mut winner = loaded.clone();
    winner.status = "winner".into();
    // A serialized version is not the CAS predicate or the resulting row version.
    winner.metadata.as_mut().unwrap().resource_version = 9_999;
    let next_version = adapter
        .replace(&winner, version(&loaded))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next_version, 2);
    winner.metadata.as_mut().unwrap().resource_version = next_version;

    let mut other = state.clone();
    other.provider_id = "other-provider".into();
    let metadata = other.metadata.as_mut().unwrap();
    metadata.id = "other-refresh-id".into();
    metadata.workspace = "other-workspace".into();
    metadata.name = refresh_state_name(&other.provider_id, &other.credential_key);
    adapter.create(&other).await.unwrap();
    other.metadata.as_mut().unwrap().resource_version = 1;

    let by_name = adapter
        .get("default", "provider-id", "ACCESS_TOKEN")
        .await
        .unwrap()
        .unwrap();
    let by_id = adapter.get_by_id(state.object_id()).await.unwrap().unwrap();
    assert_same_state(&by_name, &winner);
    assert_same_state(&by_id, &winner);
    let scoped = adapter.list(Some("provider-id")).await.unwrap();
    assert_eq!(scoped.len(), 1);
    assert_same_state(&scoped[0], &winner);
    let other_scoped = adapter.list(Some("other-provider")).await.unwrap();
    assert_eq!(other_scoped.len(), 1);
    assert_same_state(&other_scoped[0], &other);
    let all = adapter.list(None).await.unwrap();
    assert_eq!(all.len(), 2);
    assert_same_state(
        all.iter()
            .find(|s| s.object_id() == winner.object_id())
            .unwrap(),
        &winner,
    );
    assert_same_state(
        all.iter()
            .find(|s| s.object_id() == other.object_id())
            .unwrap(),
        &other,
    );
    assert!(
        adapter
            .get("other-workspace", "provider-id", "ACCESS_TOKEN")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn sqlite_stale_cas_and_delete_preserve_winner_and_deleted_rows_cannot_resurrect() {
    let adapter = ServerRefreshStore(Arc::new(test_store().await));
    let state = RefreshState::from(&full_state());
    adapter.create(&state).await.unwrap();
    let observed = adapter.get_by_id(state.object_id()).await.unwrap().unwrap();
    let mut winner = observed.clone();
    winner.status = "winner".into();
    winner
        .material
        .insert("client_id".into(), "winning-client".into());
    let winner_version = adapter
        .replace(&winner, version(&observed))
        .await
        .unwrap()
        .unwrap();
    winner.metadata.as_mut().unwrap().resource_version = winner_version;

    let mut loser = observed.clone();
    loser.status = "stale-writer".into();
    assert_eq!(
        adapter.replace(&loser, version(&observed)).await.unwrap(),
        None
    );
    assert_eq!(
        adapter
            .delete(observed.object_id(), version(&observed))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    let current = adapter.get_by_id(state.object_id()).await.unwrap().unwrap();
    assert_same_state(&current, &winner);
    let scoped = adapter.list(Some("provider-id")).await.unwrap();
    assert_eq!(scoped.len(), 1);
    assert_same_state(&scoped[0], &winner);

    adapter
        .delete(winner.object_id(), winner_version)
        .await
        .unwrap();
    // A replace is update-only even when given the last authoritative version.
    assert_eq!(
        adapter.replace(&winner, winner_version).await.unwrap(),
        None
    );
    assert_eq!(
        adapter.replace(&loser, version(&observed)).await.unwrap(),
        None
    );
    assert!(
        adapter
            .get_by_id(winner.object_id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        adapter
            .get("default", "provider-id", "ACCESS_TOKEN")
            .await
            .unwrap()
            .is_none()
    );
    assert!(adapter.list(Some("provider-id")).await.unwrap().is_empty());
    assert!(adapter.list(None).await.unwrap().is_empty());
}
