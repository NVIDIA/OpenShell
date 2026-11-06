// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{EmbeddedCredentialIssuer, IssuerConfig, StoreSecrets};
use openshell_core::proto::{ObjectMeta, ProviderCredentialRefreshStrategy};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

#[derive(Debug)]
struct MemoryStore {
    state: Mutex<Option<RefreshState>>,
    leases: Arc<AtomicUsize>,
    reject_final: AtomicBool,
}
struct Lease(Arc<AtomicUsize>);
impl RefreshLease for Lease {}
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
#[async_trait]
impl RefreshStateStore for MemoryStore {
    async fn get(&self, _: &str, _: &str, _: &str) -> Result<Option<RefreshState>, Status> {
        Ok(self.state.lock().unwrap().clone())
    }
    async fn get_by_id(&self, _: &str) -> Result<Option<RefreshState>, Status> {
        Ok(self.state.lock().unwrap().clone())
    }
    async fn list(&self, _: Option<&str>) -> Result<Vec<RefreshState>, Status> {
        Ok(self.state.lock().unwrap().clone().into_iter().collect())
    }
    async fn create(&self, state: &RefreshState) -> Result<(), Status> {
        let mut current = self.state.lock().unwrap();
        if current.is_some() {
            return Err(Status::aborted("already configured"));
        }
        *current = Some(state.clone());
        Ok(())
    }
    async fn replace(&self, state: &RefreshState, version: u64) -> Result<Option<u64>, Status> {
        let mut current = self.state.lock().unwrap();
        if current
            .as_ref()
            .and_then(|s| s.metadata.as_ref())
            .map(|m| m.resource_version)
            != Some(version)
            || state.status == "refreshed" && self.reject_final.load(Ordering::SeqCst)
        {
            return Ok(None);
        }
        let mut state = state.clone();
        state.metadata.as_mut().unwrap().resource_version = version + 1;
        *current = Some(state);
        Ok(Some(version + 1))
    }
    async fn delete(&self, _: &str, _: u64) -> Result<(), Status> {
        *self.state.lock().unwrap() = None;
        Ok(())
    }
    async fn acquire(&self, _: &str, _: &str) -> Result<Box<dyn RefreshLease>, Status> {
        self.leases.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Lease(Arc::clone(&self.leases))))
    }
}

#[derive(Debug)]
struct Gateway {
    id: String,
    store: Arc<MemoryStore>,
    live: Mutex<Handles>,
    fail: AtomicBool,
    commits: AtomicUsize,
}
struct Attempt(Arc<Gateway>);
#[async_trait]
impl GatewayRefreshCommit for Arc<Gateway> {
    async fn observe(&self, _: &str, _: &str) -> Result<Box<dyn RefreshAttempt>, Status> {
        Ok(Box::new(Attempt(Self::clone(self))))
    }
}
#[async_trait]
impl RefreshAttempt for Attempt {
    fn owner(&self) -> SecretOwner<'_> {
        SecretOwner::provider("default", &self.0.id, "provider")
    }
    async fn prepare_workspace(&self) -> Result<(), Status> {
        Ok(())
    }
    async fn commit(&self, outputs: RefreshOutputs<'_>) -> Result<Handles, Status> {
        assert!(
            outputs.inline.is_empty(),
            "handle commits must not carry plaintext"
        );
        assert_eq!(self.0.store.leases.load(Ordering::SeqCst), 1);
        assert_eq!(
            self.0.store.state.lock().unwrap().as_ref().unwrap().status,
            "refresh_committing"
        );
        if self.0.fail.load(Ordering::SeqCst) {
            return Err(Status::unavailable("provider commit failed"));
        }
        self.0.commits.fetch_add(1, Ordering::SeqCst);
        let mut live = self.0.live.lock().unwrap();
        Ok(std::mem::replace(
            &mut *live,
            outputs.handles.unwrap().clone(),
        ))
    }
}

struct Fixture {
    server: MockServer,
    store: Arc<MemoryStore>,
    issuer: Arc<EmbeddedCredentialIssuer>,
    gateway: Arc<Gateway>,
}
impl Fixture {
    async fn new() -> Self {
        let server = MockServer::start().await;
        let id = uuid::Uuid::new_v4().to_string();
        let store = Arc::new(MemoryStore {
            state: Mutex::new(Some(RefreshState {
                metadata: Some(ObjectMeta {
                    id: uuid::Uuid::new_v4().to_string(),
                    workspace: "default".into(),
                    resource_version: 1,
                    ..Default::default()
                }),
                provider_id: id.clone(),
                provider_name: "provider".into(),
                credential_key: "TOKEN".into(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                token_url: server.uri(),
                material: HashMap::from([
                    ("client_id".into(), "client".into()),
                    ("client_secret".into(), "secret".into()),
                ]),
                authorization_epoch: uuid::Uuid::new_v4().to_string(),
                status: "configured".into(),
                ..Default::default()
            })),
            leases: Arc::new(AtomicUsize::new(0)),
            reject_final: AtomicBool::new(false),
        });
        let issuer = Arc::new(
            EmbeddedCredentialIssuer::from_config(&IssuerConfig {
                credential_drivers: vec!["test-static".into()],
                ..Default::default()
            })
            .unwrap(),
        );
        let gateway = Arc::new(Gateway {
            id,
            store: Arc::clone(&store),
            live: Mutex::new(Handles::new()),
            fail: AtomicBool::new(false),
            commits: AtomicUsize::new(0),
        });
        Self {
            server,
            store,
            issuer,
            gateway,
        }
    }
    fn runtime(&self) -> RefreshRuntime {
        RefreshRuntime::new(
            self.store.clone(),
            Some(self.issuer.clone()),
            Arc::new(self.gateway.clone()),
        )
    }
    fn snapshot(&self) -> RefreshState {
        self.store.state.lock().unwrap().clone().unwrap()
    }
    async fn token(&self, delay: std::time::Duration) {
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(
                        serde_json::json!({"access_token":"new-secret", "expires_in":3600}),
                    )
                    .set_delay(delay),
            )
            .expect(1)
            .mount(&self.server)
            .await;
    }
}

#[tokio::test]
async fn provider_commit_survives_failed_final_state_cas_without_deleting_live_outputs() {
    let f = Fixture::new().await;
    f.token(std::time::Duration::ZERO).await;
    f.store.reject_final.store(true, Ordering::SeqCst);
    let error = f.runtime().ensure_fresh(f.snapshot()).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::Aborted);
    assert_eq!(f.snapshot().status, "refresh_committing");
    assert_eq!(f.issuer.stored_credential_count(), Some(1));
    let handles = f.gateway.live.lock().unwrap().clone();
    let resolved = f
        .issuer
        .resolve(
            SecretOwner::provider("default", &f.gateway.id, "provider"),
            &handles,
        )
        .await
        .unwrap();
    assert_eq!(resolved[0].value, "new-secret");
    assert!(f.runtime().ensure_fresh(f.snapshot()).await.is_err());
    assert_eq!(f.gateway.commits.load(Ordering::SeqCst), 1);
    assert_eq!(f.store.leases.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rejected_provider_commit_cleans_only_staged_outputs_and_records_backoff() {
    let f = Fixture::new().await;
    f.token(std::time::Duration::ZERO).await;
    f.gateway.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        f.runtime()
            .ensure_fresh(f.snapshot())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    assert_eq!(f.issuer.stored_credential_count(), Some(0));
    let state = f.snapshot();
    assert_eq!(state.status, "error");
    assert!(state.next_refresh_at_ms > openshell_core::time::now_ms());
    assert!(engine::change(&state).completed_mint.is_none());
}

#[tokio::test]
async fn cleanup_failure_is_not_a_provider_commit_failure_and_sweep_returns_committed_generation() {
    let f = Fixture::new().await;
    f.token(std::time::Duration::ZERO).await;
    let old = f
        .issuer
        .store(StoreSecrets {
            owner: SecretOwner::provider("default", &f.gateway.id, "provider"),
            object_id: Some("old"),
            values: &HashMap::from([("TOKEN".into(), "old-secret".into())]),
            existing_handles: &Handles::new(),
        })
        .await
        .unwrap();
    *f.gateway.live.lock().unwrap() = old;
    f.issuer.fail_next_delete();
    let changes = f.runtime().sweep().await.unwrap();
    assert_eq!(f.snapshot().status, "refreshed");
    assert_eq!(changes, vec![engine::change(&f.snapshot())]);
    assert!(changes[0].completed_mint.is_some());
    assert_eq!(changes[0].provider_id, f.gateway.id);
    assert_eq!(changes[0].grant_id, f.snapshot().object_id());
    assert_eq!(
        changes[0].authorization_epoch.as_deref(),
        Some(f.snapshot().authorization_epoch.as_str())
    );
    assert!(changes[0].issuer_namespace.is_none());
    assert!(changes[0].references.is_empty());
    assert!(!format!("{changes:?}").contains("new-secret"));
    assert_eq!(f.gateway.commits.load(Ordering::SeqCst), 1);
    // The retained superseded handle is cleanup debt, not a reason to mint again.
    assert_eq!(f.issuer.stored_credential_count(), Some(2));
}

#[tokio::test]
async fn independent_runtimes_coalesce_and_caller_cancellation_keeps_the_lease() {
    let f = Fixture::new().await;
    let (entered, release) = f.issuer.gate_next_store();
    f.token(std::time::Duration::ZERO).await;
    let snapshot = f.snapshot();
    let runtime = f.runtime();
    let first_snapshot = snapshot.clone();
    let first = tokio::spawn(async move { runtime.ensure_fresh(first_snapshot).await });
    entered.await.unwrap();
    assert_eq!(f.store.leases.load(Ordering::SeqCst), 1);
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let runtime = f.runtime();
    let second = tokio::spawn(async move { runtime.ensure_fresh(snapshot).await });
    release.send(()).unwrap();
    let committed = second.await.unwrap().unwrap();
    assert_eq!(committed.status, "refreshed");
    assert_eq!(f.gateway.commits.load(Ordering::SeqCst), 1);
    assert_eq!(f.store.leases.load(Ordering::SeqCst), 0);
}

fn notification_state(provider_id: &str, grant_id: &str, epoch: &str) -> RefreshState {
    let mut state = RefreshState {
        metadata: Some(ObjectMeta {
            id: grant_id.into(),
            workspace: "default".into(),
            resource_version: 87,
            ..Default::default()
        }),
        provider_id: provider_id.into(),
        provider_name: "same-display-name".into(),
        credential_key: "TOKEN".into(),
        authorization_epoch: epoch.into(),
        status: "refreshed".into(),
        reference_generation: 3,
        material: HashMap::from([("client_secret".into(), "raw-secret-material".into())]),
        ..Default::default()
    };
    for key in ["TOKEN", "SECONDARY"] {
        let projection = crate::references::ReferenceProjection {
            namespace: "durable-embedded-namespace".into(),
            owner: crate::references::OwnerIdentity::of(SecretOwner::provider(
                "default",
                provider_id,
                &state.provider_name,
            )),
            credential_key: key.into(),
            epoch: epoch.into(),
            manifest_id: "fixed-output-manifest".into(),
            reference_id: format!("reference-{key}"),
        };
        state.output_references.insert(
            key.into(),
            openshell_core::proto::CredentialHandle {
                driver: "test-static".into(),
                handle: format!("opaque-handle-{key}"),
                metadata: HashMap::from([(
                    "openshell.issuer.reference.v1".into(),
                    serde_json::to_string(&projection).unwrap(),
                )]),
            },
        );
    }
    state
}

#[test]
fn notification_identity_distinguishes_same_name_owners_grants_and_epochs() {
    use openshell_core::ObjectId as _;

    let first = notification_state("provider-a", "grant-a", "epoch-a");
    let change = engine::change(&first);
    assert_eq!(change.workspace, "default");
    assert_eq!(change.provider_id, "provider-a");
    assert_eq!(change.grant_id, first.object_id());
    assert_eq!(change.authorization_epoch.as_deref(), Some("epoch-a"));
    assert_eq!(
        change.issuer_namespace.as_deref(),
        Some("durable-embedded-namespace")
    );
    for replacement in [
        notification_state("provider-b", "grant-a", "epoch-a"),
        notification_state("provider-a", "grant-b", "epoch-a"),
        notification_state("provider-a", "grant-a", "epoch-b"),
    ] {
        let replacement = engine::change(&replacement);
        assert_eq!(change.provider_name, replacement.provider_name);
        assert_eq!(change.references, replacement.references);
        assert_ne!(change, replacement);
    }
    let mut renamed = first;
    renamed.provider_name = "renamed".into();
    let mut expected = change;
    expected.provider_name = "renamed".into();
    assert_eq!(engine::change(&renamed), expected);
}

#[test]
fn notification_versions_use_one_committed_generation_not_row_versions_or_staging() {
    let mut state = notification_state("provider", "grant", "epoch");
    let change = engine::change(&state);
    assert_eq!(change.references.len(), 2);
    assert_eq!(change.references["TOKEN"], ("reference-TOKEN".into(), 3));
    assert!(change.references.values().all(|(_, version)| *version == 3));
    for status in ["configured", "refreshing", "refresh_committing", "error"] {
        state.status = status.into();
        assert!(engine::change(&state).references.is_empty(), "{status}");
    }
    state.status = "refreshed".into();
    state.reference_generation = 0;
    assert!(engine::change(&state).references.is_empty());
    let debug = format!("{change:?}");
    assert!(!debug.contains("raw-secret-material"));
    assert!(!debug.contains("opaque-handle"));
    assert!(!debug.contains("fixed-output-manifest"));
}

#[test]
fn notification_legacy_epoch_and_deletion_retain_identity_without_versions() {
    let mut legacy = notification_state("provider", "legacy-grant", "");
    legacy.output_references.clear();
    let change = engine::change(&legacy);
    assert_eq!(change.provider_id, "provider");
    assert_eq!(change.grant_id, "legacy-grant");
    assert_eq!(change.authorization_epoch.as_deref(), Some("legacy-grant"));
    assert!(change.issuer_namespace.is_none());
    assert!(change.references.is_empty());

    let mut deleted = notification_state("provider", "grant", "epoch");
    deleted.metadata.as_mut().unwrap().deletion_time = Some(prost_types::Timestamp {
        seconds: 1,
        nanos: 0,
    });
    // A tombstone can retain the last successful status/generation. It must not
    // advertise those outputs as a new committed activation on deletion.
    let change = engine::change(&deleted);
    assert_eq!(change.grant_id, "grant");
    assert_eq!(change.authorization_epoch.as_deref(), Some("epoch"));
    assert!(change.issuer_namespace.is_some());
    assert!(change.references.is_empty());
}

#[test]
fn notification_corrupt_epoch_is_absent_without_fallback_or_panic() {
    let mut state = notification_state("provider", "", "");
    for metadata_missing in [false, true] {
        if metadata_missing {
            state.metadata = None;
        }
        let change = engine::change(&state);
        assert_eq!(change.provider_name, "same-display-name");
        assert_eq!(change.provider_id, "provider");
        assert!(change.grant_id.is_empty());
        assert!(change.authorization_epoch.is_none());
        assert!(change.issuer_namespace.is_none());
        assert!(change.references.is_empty());
    }
}

#[test]
fn notification_malformed_or_mixed_bundles_never_advertise_partial_versions() {
    for field in [
        "namespace",
        "owner",
        "epoch",
        "credential_key",
        "manifest_id",
    ] {
        let mut state = notification_state("provider", "grant", "epoch");
        let handle = state.output_references.get_mut("SECONDARY").unwrap();
        let projection = handle
            .metadata
            .get_mut("openshell.issuer.reference.v1")
            .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(projection).unwrap();
        if field == "owner" {
            value[field]["id"] = "another-provider".into();
        } else {
            value[field] = "another-value".into();
        }
        *projection = serde_json::to_string(&value).unwrap();
        let change = engine::change(&state);
        assert!(change.issuer_namespace.is_none(), "{field}");
        assert!(change.references.is_empty(), "{field}");
    }
    for malformed in [None, Some("not-json"), Some("null")] {
        let mut state = notification_state("provider", "grant", "epoch");
        let metadata = &mut state
            .output_references
            .get_mut("SECONDARY")
            .unwrap()
            .metadata;
        metadata.clear();
        if let Some(value) = malformed {
            metadata.insert("openshell.issuer.reference.v1".into(), value.into());
        }
        let change = engine::change(&state);
        assert!(change.issuer_namespace.is_none());
        assert!(change.references.is_empty());
    }
}
