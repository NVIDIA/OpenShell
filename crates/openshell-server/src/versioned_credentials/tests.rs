// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::proto::{ObjectMeta, Provider, ProviderCredentialRefreshStrategy};
use openshell_credential_issuer::refresh::{
    CredentialRefresh, RefreshRuntime, refresh_material_scope,
};
use openshell_credential_issuer::{EmbeddedCredentialIssuer, IssuerConfig};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

#[path = "refresh_failure_tests.rs"]
mod refresh_failure_tests;

struct Fixture {
    runtime: Arc<VersionedCredentials>,
    issuer: Arc<EmbeddedCredentialIssuer>,
    provider: Provider,
    endpoint: MockServer,
}

impl Fixture {
    async fn new() -> Self {
        let store = Arc::new(Store::connect("sqlite::memory:").await.unwrap());
        let issuer = Arc::new(
            EmbeddedCredentialIssuer::from_config(&IssuerConfig {
                credential_drivers: vec!["test-static".into()],
                ..Default::default()
            })
            .unwrap(),
        );
        let runtime = VersionedCredentials::new(Arc::clone(&store), issuer.clone()).unwrap();
        let mut provider = Provider {
            metadata: Some(ObjectMeta {
                id: uuid::Uuid::new_v4().to_string(),
                name: "provider".into(),
                workspace: "default".into(),
                labels: HashMap::from([("team".into(), "testing".into())]),
                ..Default::default()
            }),
            r#type: "github".into(),
            ..Default::default()
        };
        let owner = SecretOwner::provider("default", provider.object_id(), "provider");
        let values = HashMap::from([("TOKEN".into(), "original".into())]);
        let handles = issuer
            .store(StoreSecrets {
                owner,
                object_id: Some("legacy-object"),
                values: &values,
                existing_handles: &Handles::new(),
            })
            .await
            .unwrap();
        provider.credential_handles = runtime
            .references
            .adopt(owner, &handles, "adopt-static")
            .await
            .unwrap();
        store.put_message(&provider).await.unwrap();
        provider = store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap();
        Self {
            runtime,
            issuer,
            provider,
            endpoint: MockServer::start().await,
        }
    }

    async fn grant(&self) -> RefreshState {
        let mut state = RefreshState {
            metadata: Some(ObjectMeta {
                id: uuid::Uuid::new_v4().to_string(),
                name: "grant-TOKEN".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            provider_id: self.provider.object_id().to_owned(),
            provider_name: "provider".into(),
            credential_key: "TOKEN".into(),
            strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
            strategy_name: Some("oauth2_client_credentials".into()),
            token_url: self.endpoint.uri(),
            material: HashMap::from([("client_id".into(), "client".into())]),
            secret_material_keys: vec!["client_secret".into()],
            authorization_epoch: uuid::Uuid::new_v4().to_string(),
            status: "configured".into(),
            ..Default::default()
        };
        state.secret_material_handles = self
            .issuer
            .store_refresh_material_with_object_id(
                refresh_material_scope(&state),
                &uuid::Uuid::new_v4().to_string(),
                &HashMap::from([("client_secret".into(), "secret".into())]),
                &Handles::new(),
            )
            .await
            .unwrap();
        state
    }

    async fn current_provider(&self) -> Provider {
        self.runtime
            .store
            .get_message::<Provider>(self.provider.object_id())
            .await
            .unwrap()
            .unwrap()
    }
}

#[tokio::test]
async fn versioned_refresh_commits_versions_without_gateway_callback_or_provider_write() {
    let f = Fixture::new().await;
    let configured = f
        .runtime
        .configure(&f.provider, f.grant().await, "test-static", None, ())
        .await
        .unwrap();
    let provider = f.current_provider().await;
    assert_eq!(
        f.runtime
            .store
            .list_with_selector("provider", "default", "team=testing", 10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    let captured = f
        .runtime
        .references
        .resolve(owner(&configured), &provider.credential_handles)
        .await
        .unwrap();
    assert_eq!(captured[0].value, "original");
    assert_eq!(captured[0].version, 1);
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"access_token":"refreshed", "expires_in":3600})),
        )
        .expect(1)
        .mount(&f.endpoint)
        .await;
    let runtime =
        RefreshRuntime::with_references(f.runtime.clone(), f.issuer.clone(), f.runtime.clone());
    assert!(runtime.uses_references());
    let refreshed = runtime.ensure_fresh(configured).await.unwrap();
    let unchanged = f.current_provider().await;
    assert_eq!(
        unchanged, provider,
        "refresh must not mutate provider rows or handles"
    );
    let values = f
        .runtime
        .references
        .resolve(owner(&refreshed), &unchanged.credential_handles)
        .await
        .unwrap();
    assert_eq!(values[0].value, "refreshed");
    assert_eq!(values[0].version, 2);
    assert_eq!(refreshed.reference_generation, 2);
    let change = openshell_credential_issuer::refresh::engine::change(&refreshed);
    assert_eq!(change.workspace, refreshed.object_workspace());
    assert_eq!(change.provider_name, refreshed.provider_name);
    assert_eq!(change.provider_id, f.provider.object_id());
    assert_eq!(change.grant_id, refreshed.object_id());
    assert_eq!(
        change.authorization_epoch.as_deref(),
        Some(refreshed.authorization_epoch.as_str())
    );
    assert_eq!(
        change.issuer_namespace.as_deref(),
        Some(values[0].reference.namespace.as_str())
    );
    assert_eq!(change.references.len(), values.len());
    assert_eq!(
        change.references["TOKEN"].0,
        values[0].reference.reference_id
    );
    assert_eq!(change.references["TOKEN"].1, values[0].version);
    assert_eq!(change.references["TOKEN"].1, refreshed.reference_generation);
    // A previously captured result stays internally coherent after activation.
    assert_eq!(
        (captured[0].value.as_str(), captured[0].version),
        ("original", 1)
    );
    let stored = f
        .runtime
        .get("default", &refreshed.provider_id, "TOKEN")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, "refreshed");
    assert_eq!(stored.reference_generation, 2);
    assert_eq!(
        openshell_credential_issuer::refresh::engine::change(&stored),
        change
    );
}

#[tokio::test]
async fn versioned_refresh_disable_preserves_values_and_reconfiguration_revokes_old_epoch() {
    let f = Fixture::new().await;
    let first = f
        .runtime
        .configure(&f.provider, f.grant().await, "test-static", None, ())
        .await
        .unwrap();
    let provider = f.current_provider().await;
    let second = f
        .runtime
        .configure(&provider, f.grant().await, "test-static", None, ())
        .await
        .unwrap();
    assert_ne!(first.object_id(), second.object_id());
    assert_ne!(first.authorization_epoch, second.authorization_epoch);
    assert!(
        f.runtime
            .references
            .resolve(owner(&first), &first.output_references)
            .await
            .is_err()
    );
    assert_eq!(
        f.runtime
            .states(Some(&first.provider_id))
            .await
            .unwrap()
            .len(),
        1
    );
    let provider = f.current_provider().await;
    f.runtime
        .retain_static_outputs(&provider, &second, "test-static")
        .await
        .unwrap();
    let retained = f.current_provider().await;
    // Retrying after a crash between the provider switch and tombstoning is
    // idempotent, even though its current handles are now static references.
    f.runtime
        .retain_static_outputs(&retained, &second, "test-static")
        .await
        .unwrap();
    let refresh =
        RefreshRuntime::with_references(f.runtime.clone(), f.issuer.clone(), f.runtime.clone());
    refresh.delete(second.clone()).await.unwrap();
    let resolved = f
        .runtime
        .references
        .resolve(owner(&second), &retained.credential_handles)
        .await
        .unwrap();
    assert_eq!(resolved[0].value, "original");
    assert!(
        f.runtime
            .references
            .resolve(owner(&second), &second.output_references)
            .await
            .is_err()
    );
    assert!(
        f.runtime
            .get("default", &second.provider_id, "TOKEN")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn versioned_configure_losing_provider_cas_cannot_activate_a_grant() {
    let f = Fixture::new().await;
    let stale = f.provider.clone();
    let mut newer = stale.clone();
    newer.config.insert("changed".into(), "true".into());
    f.runtime
        .store
        .update_message_cas::<Provider, _>(
            stale.object_id(),
            stale.metadata.as_ref().unwrap().resource_version,
            |current| {
                current.config.clone_from(&newer.config);
            },
        )
        .await
        .unwrap();
    let error = f
        .runtime
        .configure(&stale, f.grant().await, "test-static", None, ())
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Aborted);
    assert!(
        f.runtime
            .states(Some(stale.object_id()))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        f.current_provider().await.credential_handles,
        stale.credential_handles
    );
}

#[tokio::test]
async fn versioned_owner_record_cas_is_update_only_and_survives_reconstruction() {
    let f = Fixture::new().await;
    let first = f
        .runtime
        .configure(&f.provider, f.grant().await, "test-static", None, ())
        .await
        .unwrap();
    let restarted =
        VersionedCredentials::new(Arc::clone(&f.runtime.store), f.issuer.clone()).unwrap();
    let read = restarted
        .get("default", &first.provider_id, "TOKEN")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.output_references, first.output_references);
    assert_eq!(read.reference_generation, 1);
    assert_eq!(read.authorization_epoch, first.authorization_epoch);
    assert!(restarted.replace(&read, 0).await.unwrap().is_none());
    let records = restarted
        .store
        .collect_records(REFERENCE_OBJECT_TYPE, ObjectListQuery::AllWorkspaces)
        .await
        .unwrap();
    let payloads = String::from_utf8(records[0].payload.clone()).unwrap();
    assert!(!payloads.contains("original"));
    assert!(!payloads.contains("\"secret\""));
}

#[test]
fn reference_binding_annotation_names_are_bounded_and_domain_owned() {
    let key = "A".repeat(256);
    let active = annotation_key(&key).unwrap();
    let disabled = disabled_annotation_key(&key).unwrap();
    assert!(active.starts_with("internal.openshell.ai/issuer-grant-"));
    assert!(disabled.starts_with("internal.openshell.ai/issuer-disabled-"));
    assert!(active.split('/').nth(1).unwrap().len() <= 63);
    assert!(disabled.split('/').nth(1).unwrap().len() <= 63);
    assert_ne!(active, annotation_key("B").unwrap());
}

#[tokio::test]
async fn uncertain_provider_publication_preserves_and_recovers_exact_preparation() {
    use prost::Message as _;
    let f = Fixture::new().await;
    let mut state = f.grant().await;
    let identities =
        ReferenceRuntime::pending_handles("test-static", ["TOKEN".to_owned()]).unwrap();
    state.output_references = f
        .runtime
        .references
        .rebind_bundle(
            owner(&state),
            &state.authorization_epoch,
            &f.provider.credential_handles,
            &identities,
            "uncertain-binding-preparation",
        )
        .await
        .unwrap();
    state.reference_generation = 1;
    let prepared = f
        .runtime
        .references
        .prepare_grant(
            owner(&state),
            state.object_id(),
            &state.authorization_epoch,
            &persistence::encode(&state).unwrap(),
        )
        .await
        .unwrap();
    let mut candidate = f.provider.clone();
    candidate
        .credential_handles
        .clone_from(&state.output_references);
    candidate.metadata.as_mut().unwrap().annotations.insert(
        annotation_key("TOKEN").unwrap(),
        serde_json::to_string(&BindingTransition {
            grant_id: state.object_id().into(),
            prepared_version: prepared.resource_version,
            old_grant_id: None,
            old_grant_version: None,
            epoch: state.authorization_epoch.clone(),
            retired_references: std::collections::BTreeMap::default(),
        })
        .unwrap(),
    );
    // A failed/indeterminate read does not justify destructive abandonment.
    let unknown = || PersistenceError::Database("provider response lost".into());
    let error = f
        .runtime
        .reconcile_binding_publication(&candidate, Err(unknown()))
        .await
        .unwrap_err();
    assert!(!error.is_expected());
    assert!(
        f.runtime
            .references
            .get_grant(owner(&state), state.object_id())
            .await
            .unwrap()
            .unwrap()
            .prepared
    );
    // Model UPDATE commit followed by response loss, through the same outcome
    // reconciliation used by configure_inner, with a real SQLite provider row.
    f.runtime
        .store
        .put_if(
            "provider",
            candidate.object_id(),
            "provider",
            "default",
            &candidate.encode_to_vec(),
            None,
            WriteCondition::MatchResourceVersion(
                f.provider.metadata.as_ref().unwrap().resource_version,
            ),
        )
        .await
        .unwrap();
    f.runtime
        .reconcile_binding_publication(&candidate, Err(unknown()))
        .await
        .unwrap();
    let activated = f
        .runtime
        .references
        .activate_grant(
            owner(&state),
            state.object_id(),
            prepared.resource_version,
            None,
        )
        .await
        .unwrap();
    assert!(activated.active);
    assert_eq!(
        f.issuer
            .resolve_refresh_material(
                refresh_material_scope(&state),
                &state.secret_material_handles
            )
            .await
            .unwrap()["client_secret"],
        "secret"
    );
    assert_eq!(
        f.runtime
            .references
            .resolve(owner(&state), &candidate.credential_handles)
            .await
            .unwrap()[0]
            .value,
        "original"
    );
}

#[tokio::test]
async fn public_expiration_tracks_committed_outputs_without_provider_writes() {
    let f = Fixture::new().await;
    f.runtime
        .configure(&f.provider, f.grant().await, "test-static", None, ())
        .await
        .unwrap();
    let provider = f.current_provider().await;
    let refresh =
        RefreshRuntime::with_references(f.runtime.clone(), f.issuer.clone(), f.runtime.clone());
    let mut observed = Vec::new();
    // Keep both values below the existing default maximum-lifetime policy.
    for lifetime in [600, 1800] {
        f.endpoint.reset().await;
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"access_token":format!("token-{lifetime}"),"expires_in":lifetime})
        )).expect(1).mount(&f.endpoint).await;
        refresh
            .rotate("default", "provider", "TOKEN")
            .await
            .unwrap();
        let mut projected = f.current_provider().await;
        assert_eq!(projected, provider);
        f.runtime.project_expirations(&mut projected).await.unwrap();
        let expiration = projected.credential_expiration_times["TOKEN"];
        observed.push(openshell_core::time::timestamp_to_millis(&expiration).unwrap());
        // An independently authored shorter provider limit still wins.
        let mut limited = provider.clone();
        let limit =
            openshell_core::time::timestamp_from_millis(openshell_core::time::now_ms() + 60_000)
                .unwrap();
        limited
            .credential_expiration_times
            .insert("TOKEN".into(), limit);
        f.runtime.project_expirations(&mut limited).await.unwrap();
        assert_eq!(limited.credential_expiration_times["TOKEN"], limit);
    }
    assert!(observed[1] > observed[0] + 1_000_000);
    assert!(
        !f.current_provider()
            .await
            .credential_expiration_times
            .contains_key("TOKEN")
    );
}
