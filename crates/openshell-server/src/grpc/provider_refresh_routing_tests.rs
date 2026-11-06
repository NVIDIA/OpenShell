// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! These grants deliberately do not exist in the gateway store. Falling back to
//! the local adapter instead of the injected service must fail these assertions.
use super::*;
use async_trait::async_trait;
use openshell_core::proto::ObjectMeta;
use openshell_credential_issuer::refresh::{RefreshChange, RefreshState};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct RefreshProbe {
    records: Mutex<Vec<RefreshState>>,
    listed_snapshot: Option<Vec<RefreshState>>,
    deleted: Mutex<Vec<RefreshState>>,
    gets: AtomicUsize,
    lists: AtomicUsize,
}

#[async_trait]
impl CredentialRefresh for RefreshProbe {
    async fn get(
        &self,
        workspace: &str,
        provider_id: &str,
        key: &str,
    ) -> Result<Option<RefreshState>, Status> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .find(|state| {
                state.object_workspace() == workspace
                    && state.provider_id == provider_id
                    && state.credential_key == key
            })
            .cloned())
    }
    async fn list(&self, provider_id: Option<&str>) -> Result<Vec<RefreshState>, Status> {
        self.lists.fetch_add(1, Ordering::SeqCst);
        if let Some(snapshot) = &self.listed_snapshot {
            return Ok(snapshot.clone());
        }
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|state| provider_id.is_none_or(|id| state.provider_id == id))
            .cloned()
            .collect())
    }
    async fn create(&self, _: RefreshState) -> Result<(), Status> {
        panic!("unexpected create")
    }
    async fn replace(&self, _: RefreshState, _: u64) -> Result<bool, Status> {
        panic!("unexpected replace")
    }
    async fn delete(&self, state: RefreshState) -> Result<(), Status> {
        self.records
            .lock()
            .unwrap()
            .retain(|record| record.object_id() != state.object_id());
        self.deleted.lock().unwrap().push(state);
        Ok(())
    }
    async fn rotate(&self, _: &str, _: &str, _: &str) -> Result<RefreshState, Status> {
        panic!("unexpected rotate")
    }
    async fn ensure_fresh(&self, _: RefreshState) -> Result<RefreshState, Status> {
        panic!("unexpected ensure_fresh")
    }
    async fn sweep(&self) -> Result<Vec<RefreshChange>, Status> {
        panic!("unexpected sweep")
    }
}

fn fixture() -> (Provider, RefreshState, RefreshProbe) {
    let provider = Provider {
        metadata: Some(ObjectMeta {
            id: "provider-id".into(),
            name: "provider".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let grant = RefreshState {
        metadata: Some(ObjectMeta {
            id: "grant-id".into(),
            name: "grant".into(),
            workspace: "default".into(),
            resource_version: 17,
            ..Default::default()
        }),
        provider_id: provider.object_id().into(),
        provider_name: provider.object_name().into(),
        credential_key: "ACCESS_TOKEN".into(),
        strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32,
        authorization_epoch: "epoch".into(),
        additional_output_keys: HashMap::from([("secondary".into(), "SECONDARY_TOKEN".into())]),
        ..Default::default()
    };
    let refresh = RefreshProbe {
        records: Mutex::new(vec![grant.clone()]),
        ..Default::default()
    };
    (provider, grant, refresh)
}

#[tokio::test]
async fn provider_snapshot_and_validation_use_injected_refresh_reads() {
    let store = crate::persistence::test_store().await;
    let (provider, grant, refresh) = fixture();
    store.put_message(&provider).await.unwrap();
    let records =
        load_provider_environment_records(&store, &refresh, "default", &["provider".into()])
            .await
            .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].refresh_states.len(), 1);
    assert_eq!(records[0].refresh_states[0].object_id(), grant.object_id());
    assert_eq!(
        records[0].refresh_states[0]
            .metadata
            .as_ref()
            .unwrap()
            .resource_version,
        17
    );
    let catalog = ProviderProfileSources::with_default_sources()
        .snapshot_catalog(&store, "default")
        .await
        .unwrap();
    let keys = active_provider_environment_keys(
        RefreshStateReader::Runtime(&refresh),
        &catalog,
        &provider,
        0,
    )
    .await
    .unwrap();
    assert!(keys.contains(&"ACCESS_TOKEN".to_string()));
    assert!(keys.contains(&"SECONDARY_TOKEN".to_string()));
    let error = reject_refresh_owned_credential_updates(
        &refresh,
        provider.object_id(),
        &HashMap::from([("ACCESS_TOKEN".into(), "value".into())]),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_eq!(refresh.lists.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn provider_deletion_uses_injected_refresh_lifecycle() {
    let store = crate::persistence::test_store().await;
    let (provider, grant, refresh) = fixture();
    store.put_message(&provider).await.unwrap();
    let credentials = crate::credentials::CredentialRuntime::from_config(
        &openshell_core::Config::new(None).with_credential_drivers(["test-static"]),
    )
    .unwrap();
    assert!(
        delete_provider_record_with_credentials(
            &store,
            &refresh,
            "default",
            &credentials,
            "provider"
        )
        .await
        .unwrap()
    );
    assert!(
        store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .is_none()
    );
    let deleted = refresh.deleted.lock().unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].object_id(), grant.object_id());
    assert_eq!(refresh.gets.load(Ordering::SeqCst), 0);
    assert_eq!(refresh.lists.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn observed_refresh_deletion_preserves_snapshot_without_local_lookup() {
    let (_, observed, refresh) = fixture();
    refresh.records.lock().unwrap()[0]
        .metadata
        .as_mut()
        .unwrap()
        .id = "replacement-grant".into();
    crate::provider_refresh::delete_observed_refresh_state_with_credentials(
        &refresh,
        (&observed).into(),
    )
    .await
    .unwrap();
    let deleted = refresh.deleted.lock().unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].object_id(), observed.object_id());
    assert_eq!(deleted[0].metadata.as_ref().unwrap().resource_version, 17);
    assert_eq!(
        refresh.records.lock().unwrap()[0].object_id(),
        "replacement-grant"
    );
    assert_eq!(refresh.gets.load(Ordering::SeqCst), 0);
    assert_eq!(refresh.lists.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bulk_refresh_deletion_targets_observed_ids_not_concurrent_same_key_winner() {
    let (provider, observed, mut refresh) = fixture();
    refresh.listed_snapshot = Some(vec![observed.clone()]);
    refresh.records.lock().unwrap()[0]
        .metadata
        .as_mut()
        .unwrap()
        .id = "concurrent-winner".into();
    assert_eq!(
        crate::provider_refresh::delete_refresh_states_for_provider_with_credentials(
            &refresh,
            provider.object_id(),
        )
        .await
        .unwrap(),
        1
    );
    let deleted = refresh.deleted.lock().unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].object_id(), observed.object_id());
    assert_eq!(deleted[0].metadata, observed.metadata);
    assert_eq!(
        refresh.records.lock().unwrap()[0].object_id(),
        "concurrent-winner"
    );
    assert_eq!(refresh.gets.load(Ordering::SeqCst), 0);
    assert_eq!(refresh.lists.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn bulk_refresh_deletion_consumes_live_and_cleanup_snapshots_with_same_key() {
    let (provider, live, refresh) = fixture();
    let mut deleting = live.clone();
    deleting.metadata.as_mut().unwrap().id = "cleanup-debt".into();
    deleting.metadata.as_mut().unwrap().deletion_time =
        Some(openshell_core::time::timestamp_from_millis(openshell_core::time::now_ms()).unwrap());
    deleting.status = "deleting".into();
    refresh.records.lock().unwrap().push(deleting.clone());
    assert_eq!(
        crate::provider_refresh::delete_refresh_states_for_provider_with_credentials(
            &refresh,
            provider.object_id(),
        )
        .await
        .unwrap(),
        2
    );
    assert!(refresh.records.lock().unwrap().is_empty());
    let deleted = refresh.deleted.lock().unwrap();
    assert_eq!(deleted.len(), 2);
    assert_eq!(deleted[0].object_id(), live.object_id());
    assert_eq!(deleted[1].object_id(), deleting.object_id());
    assert_eq!(deleted[1].metadata, deleting.metadata);
    assert_eq!(refresh.gets.load(Ordering::SeqCst), 0);
}
