// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::*;
use super::Fixture;
use openshell_credential_issuer::refresh::{CredentialRefresh, RefreshRuntime};

#[tokio::test]
async fn output_store_failure_uses_staged_journal_version_and_sweep_recovers() {
    let f = Fixture::new().await;
    let configured = f
        .runtime
        .configure(&f.provider, f.grant().await, "test-static", None, ())
        .await
        .unwrap();
    let provider = f.current_provider().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"access_token":"recovered", "expires_in":3600})),
        )
        .expect(2)
        .mount(&f.endpoint)
        .await;
    let refresh =
        RefreshRuntime::with_references(f.runtime.clone(), f.issuer.clone(), f.runtime.clone());
    let initial_version = configured.metadata.as_ref().unwrap().resource_version;
    let (hit, release) = f.issuer.gate_next_store();
    f.issuer.fail_next_store();
    let attempt = tokio::spawn({
        let refresh = refresh.clone();
        async move { refresh.ensure_fresh(configured).await }
    });
    hit.await.unwrap();
    let staged = f
        .runtime
        .get("default", provider.object_id(), "TOKEN")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(staged.status, "refresh_committing");
    assert_eq!(staged.next_refresh_at_ms, i64::MAX);
    assert_eq!(
        staged.metadata.as_ref().unwrap().resource_version,
        initial_version + 3
    );
    let staging_id =
        staged.metadata.as_ref().unwrap().annotations["openshell.nvidia.com/issuer-output-staging"]
            .clone();
    release.send(()).unwrap();
    assert_eq!(
        attempt.await.unwrap().unwrap_err().code(),
        Code::Unavailable
    );
    let mut failed = f
        .runtime
        .get_by_id(staged.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failed.status, "error");
    assert_eq!(
        failed.metadata.as_ref().unwrap().resource_version,
        initial_version + 4
    );
    assert_eq!(failed.failure_code, "refresh_failed");
    assert_eq!(
        failed.recovery_action,
        openshell_core::proto::ProviderCredentialRefreshRecoveryAction::Retry as i32
    );
    assert!(failed.next_refresh_at_ms > openshell_core::time::now_ms());
    assert!(failed.next_refresh_at_ms < i64::MAX);
    assert_eq!(
        failed.metadata.as_ref().unwrap().annotations["openshell.nvidia.com/issuer-output-staging"],
        staging_id
    );
    assert!(
        !failed
            .metadata
            .as_ref()
            .unwrap()
            .annotations
            .contains_key("openshell.nvidia.com/refresh-completed-mint")
    );
    let before = f
        .runtime
        .references
        .resolve(owner(&failed), &provider.credential_handles)
        .await
        .unwrap();
    assert_eq!(
        (before[0].value.as_str(), before[0].version),
        ("original", 1)
    );
    // Move only the retry clock forward, not the binding/epoch/configuration.
    let version = failed.metadata.as_ref().unwrap().resource_version;
    failed.next_refresh_at_ms = 0;
    f.runtime.replace(&failed, version).await.unwrap().unwrap();
    assert_eq!(refresh.sweep().await.unwrap().len(), 1);
    let recovered = f
        .runtime
        .get_by_id(failed.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.status, "refreshed");
    assert_eq!(recovered.authorization_epoch, failed.authorization_epoch);
    assert_eq!(recovered.output_references, failed.output_references);
    assert_eq!(recovered.reference_generation, 2);
    assert_eq!(
        recovered.metadata.as_ref().unwrap().annotations["openshell.nvidia.com/issuer-output-staging-debt"],
        staging_id
    );
    let values = f
        .runtime
        .references
        .resolve(owner(&recovered), &provider.credential_handles)
        .await
        .unwrap();
    assert_eq!(
        (values[0].value.as_str(), values[0].version),
        ("recovered", 2)
    );
    assert_eq!(f.current_provider().await, provider);
}

#[derive(Debug)]
struct UncertainOutputs {
    inner: Arc<VersionedCredentials>,
    commit: bool,
}

#[async_trait]
impl ReferenceOutputStore for UncertainOutputs {
    async fn activate(
        &self,
        state: RefreshState,
        version: u64,
        values: HashMap<String, String>,
        expiration: Option<prost_types::Timestamp>,
    ) -> Result<RefreshState, ReferenceActivationError> {
        if self.commit {
            self.inner
                .activate(state, version, values, expiration)
                .await?;
        }
        Err(ReferenceActivationError::Uncertain(Status::unavailable(
            "injected uncertain activation response",
        )))
    }
}

#[tokio::test]
async fn lost_activation_response_preserves_exact_committed_winner() {
    let f = Fixture::new().await;
    let configured = f
        .runtime
        .configure(&f.provider, f.grant().await, "test-static", None, ())
        .await
        .unwrap();
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"access_token":"committed", "expires_in":3600})),
        )
        .expect(1)
        .mount(&f.endpoint)
        .await;
    let refresh = RefreshRuntime::with_references(
        f.runtime.clone(),
        f.issuer.clone(),
        Arc::new(UncertainOutputs {
            inner: f.runtime.clone(),
            commit: true,
        }),
    );
    let committed = refresh.ensure_fresh(configured).await.unwrap();
    assert_eq!(committed.status, "refreshed");
    assert_eq!(committed.reference_generation, 2);
    assert!(refresh.sweep().await.unwrap().is_empty());
    let read = f
        .runtime
        .get_by_id(committed.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.metadata, committed.metadata);
    assert_eq!(read.status, "refreshed");
}

#[tokio::test]
async fn uncertain_activation_without_receipt_stays_parked() {
    let f = Fixture::new().await;
    let configured = f
        .runtime
        .configure(&f.provider, f.grant().await, "test-static", None, ())
        .await
        .unwrap();
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"access_token":"uncertain", "expires_in":3600})),
        )
        .expect(1)
        .mount(&f.endpoint)
        .await;
    let id = configured.object_id().to_owned();
    let refresh = RefreshRuntime::with_references(
        f.runtime.clone(),
        f.issuer.clone(),
        Arc::new(UncertainOutputs {
            inner: f.runtime.clone(),
            commit: false,
        }),
    );
    assert_eq!(
        refresh.ensure_fresh(configured).await.unwrap_err().code(),
        Code::Unavailable
    );
    let parked = f.runtime.get_by_id(&id).await.unwrap().unwrap();
    assert_eq!(parked.status, "refresh_committing");
    assert_eq!(parked.next_refresh_at_ms, i64::MAX);
    assert!(refresh.sweep().await.unwrap().is_empty());
    assert_eq!(
        refresh
            .rotate("default", "provider", "TOKEN")
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
}

#[tokio::test]
async fn losing_configuration_cleanup_debt_never_blocks_or_deletes_winning_grant() {
    let f = Fixture::new().await;
    let winner = f
        .runtime
        .configure(&f.provider, f.grant().await, "test-static", None, ())
        .await
        .unwrap();
    let stale = f.current_provider().await;
    f.runtime
        .store
        .update_message_cas::<openshell_core::proto::Provider, _>(
            stale.object_id(),
            stale.metadata.as_ref().unwrap().resource_version,
            |provider| {
                provider.config.insert("changed".into(), "true".into());
            },
        )
        .await
        .unwrap();
    f.issuer.fail_next_delete();
    assert_eq!(
        f.runtime
            .configure(&stale, f.grant().await, "test-static", None, ())
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    let states = f
        .runtime
        .states(Some(winner.provider_id.as_str()))
        .await
        .unwrap();
    assert_eq!(states.len(), 2);
    let loser = states
        .iter()
        .find(|state| state.object_id() != winner.object_id())
        .unwrap();
    assert_eq!(loser.status, "deleting");
    assert!(loser.metadata.as_ref().unwrap().deletion_time.is_some());
    let live = f
        .runtime
        .get("default", &winner.provider_id, "TOKEN")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(live.object_id(), winner.object_id());
    assert_eq!(
        f.runtime
            .current_refresh_state(&f.current_provider().await, "TOKEN")
            .await
            .unwrap()
            .unwrap()
            .object_id(),
        winner.object_id()
    );
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"access_token":"winning", "expires_in":3600})),
        )
        .expect(2)
        .mount(&f.endpoint)
        .await;
    // Reconstruction must preserve both live authorization and cleanup debt.
    let restarted =
        VersionedCredentials::new(Arc::clone(&f.runtime.store), f.issuer.clone()).unwrap();
    // Normal lookup/rotation works even before the tombstone is swept.
    let refresh =
        RefreshRuntime::with_references(restarted.clone(), f.issuer.clone(), restarted.clone());
    let first = refresh
        .rotate("default", "provider", "TOKEN")
        .await
        .unwrap();
    assert_eq!(first.object_id(), winner.object_id());
    refresh.sweep().await.unwrap();
    assert!(
        f.runtime
            .get_by_id(loser.object_id())
            .await
            .unwrap()
            .is_none()
    );
    let states = f.runtime.states(Some(&winner.provider_id)).await.unwrap();
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].object_id(), winner.object_id());
    let second = refresh
        .rotate("default", "provider", "TOKEN")
        .await
        .unwrap();
    assert_eq!(second.object_id(), winner.object_id());
    assert_eq!(second.reference_generation, 3);
    let provider = f.current_provider().await;
    let values = f
        .runtime
        .references
        .resolve(owner(&second), &provider.credential_handles)
        .await
        .unwrap();
    assert_eq!(
        (values[0].value.as_str(), values[0].version),
        ("winning", 3)
    );
    assert_eq!(
        f.issuer
            .resolve_refresh_material(
                openshell_credential_issuer::refresh::refresh_material_scope(&second),
                &second.secret_material_handles,
            )
            .await
            .unwrap()["client_secret"],
        "secret"
    );
}

struct LostOutputStoreResponse {
    inner: Arc<dyn CredentialIssuer>,
    handles: std::sync::Mutex<Handles>,
}

impl std::fmt::Debug for LostOutputStoreResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LostOutputStoreResponse([REDACTED])")
    }
}

#[async_trait]
impl CredentialIssuer for LostOutputStoreResponse {
    fn validate_handles(&self, handles: &Handles) -> Result<(), Status> {
        self.inner.validate_handles(handles)
    }
    fn stores_provider_credentials(&self) -> bool {
        self.inner.stores_provider_credentials()
    }
    fn storage_owns_handle(&self, handle: &openshell_core::proto::CredentialHandle) -> bool {
        self.inner.storage_owns_handle(handle)
    }
    fn negotiated_extensions(&self) -> &[openshell_core::extension_protocol::NegotiatedExtension] {
        self.inner.negotiated_extensions()
    }
    async fn store(&self, request: StoreSecrets<'_>) -> Result<Handles, Status> {
        let handles = self.inner.store(request).await?;
        *self.handles.lock().unwrap() = handles;
        Err(Status::unavailable("injected lost output-store response"))
    }
    async fn delete(&self, owner: SecretOwner<'_>, handles: &Handles) -> Result<(), Status> {
        self.inner.delete(owner, handles).await
    }
    async fn resolve(
        &self,
        owner: SecretOwner<'_>,
        handles: &Handles,
    ) -> Result<Vec<openshell_credential_issuer::ResolvedSecret>, Status> {
        self.inner.resolve(owner, handles).await
    }
    async fn store_refresh_material_with_object_id(
        &self,
        scope: openshell_credential_issuer::RefreshMaterialScope<'_>,
        object_id: &str,
        material: &HashMap<String, String>,
        existing_handles: &Handles,
    ) -> Result<Handles, Status> {
        self.inner
            .store_refresh_material_with_object_id(scope, object_id, material, existing_handles)
            .await
    }
    async fn resolve_refresh_material(
        &self,
        scope: openshell_credential_issuer::RefreshMaterialScope<'_>,
        handles: &Handles,
    ) -> Result<HashMap<String, String>, Status> {
        self.inner.resolve_refresh_material(scope, handles).await
    }
    async fn delete_refresh_material_handles(
        &self,
        scope: openshell_credential_issuer::RefreshMaterialScope<'_>,
        handles: &Handles,
    ) -> Result<(), Status> {
        self.inner
            .delete_refresh_material_handles(scope, handles)
            .await
    }
    async fn delete_refresh_material_deletions(
        &self,
        scope: openshell_credential_issuer::RefreshMaterialScope<'_>,
        deletions: &[openshell_credential_issuer::RefreshMaterialDeletion],
    ) -> Result<(), Status> {
        self.inner
            .delete_refresh_material_deletions(scope, deletions)
            .await
    }
}

#[tokio::test]
async fn unknown_output_write_keeps_operator_recovery_identity_after_retry_and_deletion() {
    let f = Fixture::new().await;
    let configured = f
        .runtime
        .configure(&f.provider, f.grant().await, "test-static", None, ())
        .await
        .unwrap();
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"access_token":"minted", "expires_in":3600})),
        )
        .expect(2)
        .mount(&f.endpoint)
        .await;
    let backend = Arc::new(LostOutputStoreResponse {
        inner: f.issuer.clone(),
        handles: std::sync::Mutex::new(Handles::new()),
    });
    let adapter = Arc::new(VersionedCredentials {
        backend: backend.clone(),
        ..(*f.runtime).clone()
    });
    let refresh = RefreshRuntime::with_references(f.runtime.clone(), f.issuer.clone(), adapter);
    assert_eq!(
        refresh
            .ensure_fresh(configured.clone())
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    let failed = f
        .runtime
        .get_by_id(configured.object_id())
        .await
        .unwrap()
        .unwrap();
    let write_id =
        failed.metadata.as_ref().unwrap().annotations["openshell.nvidia.com/issuer-output-staging"]
            .clone();
    let unknown_handles = backend.handles.lock().unwrap().clone();
    assert!(unknown_handles["TOKEN"].handle.ends_with(&write_id));
    // These bytes really were stored. They were never published and their
    // unknown handles cannot be reclaimed through the generic backend port.
    assert_eq!(
        f.issuer
            .resolve(owner(&failed), &unknown_handles)
            .await
            .unwrap()[0]
            .value,
        "minted"
    );
    let provider = f.current_provider().await;
    assert_eq!(
        f.runtime
            .references
            .resolve(owner(&failed), &provider.credential_handles)
            .await
            .unwrap()[0]
            .value,
        "original"
    );
    let refresh =
        RefreshRuntime::with_references(f.runtime.clone(), f.issuer.clone(), f.runtime.clone());
    let recovered = refresh
        .rotate("default", "provider", "TOKEN")
        .await
        .unwrap();
    refresh.delete(recovered.clone()).await.unwrap();
    let restarted =
        VersionedCredentials::new(Arc::clone(&f.runtime.store), f.issuer.clone()).unwrap();
    let tombstone = restarted
        .references
        .get_grant(owner(&recovered), recovered.object_id())
        .await
        .unwrap()
        .unwrap();
    let retained = persistence::decode(&tombstone.state).unwrap();
    assert_eq!(retained.status, "deleted");
    assert_eq!(
        retained.metadata.as_ref().unwrap().annotations["openshell.nvidia.com/issuer-output-staging-debt"],
        write_id
    );
    // No cleanup success is fabricated: retained ID + immutable owner identify
    // this outstanding operator/backend recovery debt even after grant cleanup.
    assert_eq!(
        f.issuer
            .resolve(owner(&retained), &unknown_handles)
            .await
            .unwrap()[0]
            .value,
        "minted"
    );
}

#[tokio::test]
async fn foreground_cleanup_selects_bound_deletion_not_abandoned_same_key_tombstones() {
    let f = Fixture::new().await;
    let current = f
        .runtime
        .configure(&f.provider, f.grant().await, "test-static", None, ())
        .await
        .unwrap();
    let stale = f.current_provider().await;
    f.runtime
        .store
        .update_message_cas::<openshell_core::proto::Provider, _>(
            stale.object_id(),
            stale.metadata.as_ref().unwrap().resource_version,
            |provider| {
                provider.config.insert("changed".into(), "true".into());
            },
        )
        .await
        .unwrap();
    f.issuer.fail_next_delete();
    assert_eq!(
        f.runtime
            .configure(&stale, f.grant().await, "test-static", None, ())
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    let provider = f.current_provider().await;
    f.runtime
        .retain_static_outputs(&provider, &current, "test-static")
        .await
        .unwrap();
    let provider = f.current_provider().await;
    let refresh =
        RefreshRuntime::with_references(f.runtime.clone(), f.issuer.clone(), f.runtime.clone());
    f.issuer.fail_next_delete();
    assert!(refresh.delete(current.clone()).await.is_err());
    assert_eq!(
        f.runtime
            .states(Some(&current.provider_id))
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(
        f.runtime
            .get("default", &current.provider_id, "TOKEN")
            .await
            .unwrap()
            .is_none()
    );
    let selected = f
        .runtime
        .current_refresh_state(&provider, "TOKEN")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected.object_id(), current.object_id());
    refresh.delete(selected).await.unwrap();
    assert_eq!(
        f.runtime
            .states(Some(&current.provider_id))
            .await
            .unwrap()
            .len(),
        1
    );
    // The sole remaining loser is still enumerable cleanup debt, never the
    // provider's current configuration or a source of live authorization.
    assert!(
        f.runtime
            .current_refresh_state(&provider, "TOKEN")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        f.runtime
            .get("default", &current.provider_id, "TOKEN")
            .await
            .unwrap()
            .is_none()
    );
    refresh.sweep().await.unwrap();
    assert!(
        f.runtime
            .states(Some(&current.provider_id))
            .await
            .unwrap()
            .is_empty()
    );
}
