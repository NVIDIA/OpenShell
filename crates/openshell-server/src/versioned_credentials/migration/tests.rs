// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use async_trait::async_trait;
use openshell_core::Config;
use openshell_core::extension_protocol::NegotiatedExtension;
use openshell_core::proto::ObjectMeta;
use openshell_credential_issuer::references::{REFERENCE_OBJECT_TYPE, VersionedSecret};
use openshell_credential_issuer::refresh::{RefreshStateStore, set_refresh_expiration_presence};
use openshell_credential_issuer::{
    CredentialIssuer, RefreshMaterialDeletion, RefreshMaterialScope, ResolvedSecret,
};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Fixture {
    _directory: tempfile::TempDir,
    config: Config,
    file: crate::config_file::ConfigFile,
    store: Arc<crate::persistence::Store>,
    runtime: CredentialRuntime,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let database = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("state.sqlite").display()
        );
        let store = Arc::new(crate::persistence::Store::connect(&database).await.unwrap());
        let key_path =
            serde_json::to_string(&directory.path().join("kek").to_string_lossy()).unwrap();
        let file = toml::from_str(&format!(
            "[openshell.gateway.credential_storage]\nkey_encryption_key_path = {key_path}\n"
        ))
        .unwrap();
        let config = Config::new(None);
        let runtime = CredentialRuntime::from_config_file_with_store(
            &config,
            Some(&file),
            Arc::clone(&store),
        )
        .await
        .unwrap();
        Self {
            _directory: directory,
            config,
            file,
            store,
            runtime,
        }
    }

    async fn backend(&self) -> Arc<dyn CredentialIssuer> {
        let mut options = openshell_credential_issuer::IssuerConfig::from(&self.config);
        options.credential_storage = self
            .file
            .openshell
            .gateway
            .credential_storage
            .clone()
            .unwrap_or_default();
        options
            .driver_configs
            .clone_from(&self.file.openshell.credential_drivers);
        Arc::new(
            openshell_credential_issuer::EmbeddedCredentialIssuer::from_options(
                &options,
                Some(Arc::new(
                    crate::credential_store::ServerDbCredstoreObjectStore::new(Arc::clone(
                        &self.store,
                    )),
                )),
            )
            .await
            .unwrap(),
        )
    }

    fn versioned(&self) -> Arc<VersionedCredentials> {
        VersionedCredentials::new(Arc::clone(&self.store), self.runtime.issuer()).unwrap()
    }

    async fn provider(&self) -> Provider {
        self.store
            .get_message::<Provider>("provider-id")
            .await
            .unwrap()
            .unwrap()
    }

    async fn save(&self, provider: &Provider) {
        self.store.put_message(provider).await.unwrap();
    }

    async fn activation(&self) -> Activation {
        crate::credential_activation::begin(Arc::clone(&self.store), true)
            .await
            .unwrap()
            .unwrap()
    }

    async fn run(&self) -> Arc<VersionedCredentials> {
        let versioned = self.versioned();
        let mut activation = self.activation().await;
        migrate(&self.runtime, &versioned, &mut activation)
            .await
            .unwrap();
        activation.finish().await.unwrap();
        versioned
    }
}

fn provider() -> Provider {
    Provider {
        metadata: Some(ObjectMeta {
            id: "provider-id".into(),
            name: "display-name".into(),
            workspace: "workspace".into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn state() -> RefreshState {
    RefreshState {
        metadata: Some(ObjectMeta {
            id: "legacy-grant-id".into(),
            name: "provider-refresh-provider-id-544f4b454e".into(),
            workspace: "workspace".into(),
            ..Default::default()
        }),
        provider_id: "provider-id".into(),
        provider_name: "display-name".into(),
        credential_key: "TOKEN".into(),
        strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials.into(),
        status: "ready".into(),
        material: HashMap::from([("client_id".into(), "public-client".into())]),
        ..Default::default()
    }
}

async fn save_state(fixture: &Fixture, state: &RefreshState) {
    let legacy: crate::storage_proto::StoredProviderCredentialRefreshStateV2 = state.into();
    crate::refresh_store::put_refresh_state(&fixture.store, &legacy)
        .await
        .unwrap();
}

async fn resolve(versioned: &VersionedCredentials, provider: &Provider) -> Vec<VersionedSecret> {
    versioned
        .references
        .resolve(provider_owner(provider), &provider.credential_handles)
        .await
        .unwrap()
}

#[tokio::test]
async fn raw_handles_are_adopted_at_one_without_rewriting_ciphertext_or_paths() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    provider
        .metadata
        .as_mut()
        .unwrap()
        .labels
        .insert("migration-label".into(), "preserved".into());
    provider.credential_handles = fixture
        .runtime
        .store_provider_credentials(
            "display-name",
            "workspace",
            "provider-id",
            &HashMap::from([("TOKEN".into(), "raw-secret-value".into())]),
            &Handles::new(),
        )
        .await
        .unwrap();
    let old = provider.credential_handles["TOKEN"].clone();
    let before = fixture
        .store
        .collect_records(
            openshell_credential_issuer::persistence::OBJECT_TYPE,
            ObjectListQuery::AllWorkspaces,
        )
        .await
        .unwrap();
    fixture.save(&provider).await;
    let versioned = fixture.run().await;
    let migrated = fixture.provider().await;
    let selected: Vec<Provider> = fixture
        .store
        .collect_messages(ObjectListQuery::WorkspaceSelector {
            workspace: "workspace",
            label_selector: "migration-label=preserved",
        })
        .await
        .unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].object_id(), "provider-id");
    assert_eq!(
        selected[0].metadata.as_ref().unwrap().labels["migration-label"],
        "preserved"
    );
    let projected = &migrated.credential_handles["TOKEN"];
    assert_eq!(projected.driver, old.driver);
    assert_eq!(projected.handle, old.handle);
    for (key, value) in &old.metadata {
        assert_eq!(projected.metadata.get(key), Some(value));
    }
    let values = resolve(&versioned, &migrated).await;
    assert_eq!(values[0].version, 1);
    assert_eq!(values[0].value, "raw-secret-value");
    let after = fixture
        .store
        .collect_records(
            openshell_credential_issuer::persistence::OBJECT_TYPE,
            ObjectListQuery::AllWorkspaces,
        )
        .await
        .unwrap();
    assert_eq!(before.len(), after.len());
    for (before, after) in before.iter().zip(&after) {
        assert_eq!(before.id, after.id);
        assert_eq!(before.payload, after.payload);
        assert_eq!(before.resource_version, after.resource_version);
    }
    let reopened =
        VersionedCredentials::new(Arc::clone(&fixture.store), fixture.backend().await).unwrap();
    let mut activation = fixture.activation().await;
    migrate(&fixture.runtime, &reopened, &mut activation)
        .await
        .unwrap();
    assert_eq!(
        resolve(&reopened, &fixture.provider().await).await[0].version,
        1
    );
    assert_eq!(
        migrated.metadata.unwrap().resource_version,
        fixture.provider().await.metadata.unwrap().resource_version
    );
}

#[tokio::test]
async fn inline_values_switch_atomically_and_no_new_durable_plaintext_is_created() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    provider
        .credentials
        .insert("TOKEN".into(), "inline-provider-secret-marker".into());
    fixture.save(&provider).await;
    let mut legacy = state();
    legacy.material.insert(
        "client_secret".into(),
        "inline-refresh-secret-marker".into(),
    );
    legacy.secret_material_keys.push("client_secret".into());
    legacy.strategy = 987_654; // Unknown legacy values survive, not made mintable.
    legacy.refresh_before = Some(prost_types::Duration {
        seconds: 7,
        nanos: 123_456_789,
    });
    legacy.status = "refresh_in_progress".into();
    legacy.next_refresh_at_ms = i64::MAX;
    save_state(&fixture, &legacy).await;
    let old_row = fixture
        .store
        .get("provider_credential_refresh_state", legacy.object_id())
        .await
        .unwrap()
        .unwrap();
    let versioned = fixture.run().await;
    let migrated = fixture.provider().await;
    assert!(migrated.credentials.is_empty());
    assert!(
        ReferenceProjection::from_handle(&migrated.credential_handles["TOKEN"])
            .unwrap()
            .is_some()
    );
    let current = versioned
        .get_by_id(legacy.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(!current.material.contains_key("client_secret"));
    assert_eq!(current.strategy, 987_654);
    assert_eq!(current.status, "refresh_in_progress");
    assert_eq!(current.next_refresh_at_ms, i64::MAX);
    assert_eq!(current.refresh_before, legacy.refresh_before);
    assert_eq!(current.object_id(), legacy.object_id());
    assert_eq!(current.output_references.len(), 1);
    assert_eq!(current.reference_generation, 1);
    let material = versioned
        .backend
        .resolve_refresh_material(
            refresh_material_scope(&current),
            &current.secret_material_handles,
        )
        .await
        .unwrap();
    assert_eq!(material["client_secret"], "inline-refresh-secret-marker");
    assert_eq!(
        resolve(&versioned, &migrated).await[0].value,
        "inline-provider-secret-marker"
    );
    for object_type in [
        JOURNAL_TYPE,
        REFERENCE_OBJECT_TYPE,
        openshell_credential_issuer::persistence::OBJECT_TYPE,
        "provider",
    ] {
        for record in fixture
            .store
            .collect_records(object_type, ObjectListQuery::AllWorkspaces)
            .await
            .unwrap()
        {
            let text = String::from_utf8_lossy(&record.payload);
            assert!(
                !text.contains("inline-provider-secret-marker"),
                "{object_type}"
            );
            assert!(
                !text.contains("inline-refresh-secret-marker"),
                "{object_type}"
            );
        }
    }
    // Frozen V2 is a recovery input only, never rewritten through a new codec.
    assert_eq!(
        old_row.payload,
        fixture
            .store
            .get("provider_credential_refresh_state", legacy.object_id())
            .await
            .unwrap()
            .unwrap()
            .payload
    );
}

#[tokio::test]
async fn copied_refresh_expiry_is_cleared_but_independent_policy_survives() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    provider.credentials = HashMap::from([
        ("TOKEN".into(), "one".into()),
        ("OTHER".into(), "two".into()),
    ]);
    let copied = openshell_core::time::timestamp_from_millis(42_000).unwrap();
    let independent = openshell_core::time::timestamp_from_millis(99_000).unwrap();
    provider.credential_expiration_times =
        HashMap::from([("TOKEN".into(), copied), ("OTHER".into(), independent)]);
    fixture.save(&provider).await;
    let mut legacy = state();
    legacy.expires_at_ms = 42_000;
    legacy
        .additional_output_keys
        .insert("other_output".into(), "OTHER".into());
    save_state(&fixture, &legacy).await;
    fixture.run().await;
    let migrated = fixture.provider().await;
    assert!(!migrated.credential_expiration_times.contains_key("TOKEN"));
    assert_eq!(migrated.credential_expiration_times["OTHER"], independent);
}

#[tokio::test]
async fn explicit_epoch_expiration_and_legacy_epoch_identity_are_preserved() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    provider.credentials.insert("TOKEN".into(), "secret".into());
    fixture.save(&provider).await;
    let mut legacy = state();
    set_refresh_expiration_presence(&mut legacy, true);
    legacy.authorization_epoch = "explicit-auth-epoch".into();
    save_state(&fixture, &legacy).await;
    let versioned = fixture.run().await;
    let current = versioned
        .get_by_id(legacy.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        effective_authorization_epoch(&current).unwrap(),
        "explicit-auth-epoch"
    );
    assert!(refresh_has_expiration(&current));
    // Expiration at Unix epoch remains explicitly present on the manifest.
    let provider = fixture.provider().await;
    let captured = versioned
        .references
        .resolve_at(
            provider_owner(&provider),
            &provider.credential_handles,
            prost_types::Timestamp {
                seconds: -1,
                nanos: 0,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        captured[0].expiration_time,
        Some(prost_types::Timestamp {
            seconds: 0,
            nanos: 0
        })
    );
}

#[tokio::test]
async fn missing_outputs_remain_fixed_and_pending_instead_of_fabricated_values() {
    let fixture = Fixture::new().await;
    fixture.save(&provider()).await;
    let mut legacy = state();
    legacy.additional_output_keys = HashMap::from([("secondary".into(), "OTHER".into())]);
    save_state(&fixture, &legacy).await;
    let versioned = fixture.run().await;
    let current = versioned
        .get_by_id(legacy.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.output_references.len(), 2);
    assert_eq!(current.reference_generation, 0);
    assert!(
        current
            .output_references
            .values()
            .all(|handle| handle.driver == fixture.runtime.storage_driver_name())
    );
    assert!(
        versioned
            .references
            .resolve(
                provider_owner(&fixture.provider().await),
                &current.output_references
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn missing_or_unsupported_legacy_backend_is_not_successful_adoption() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    provider.credential_handles.insert(
        "TOKEN".into(),
        CredentialHandle {
            driver: "unavailable-legacy-driver".into(),
            handle: "keep-original-bytes".into(),
            metadata: HashMap::new(),
        },
    );
    fixture.save(&provider).await;
    let before = fixture.provider().await;
    let versioned = fixture.versioned();
    let mut activation = fixture.activation().await;
    assert!(
        migrate(&fixture.runtime, &versioned, &mut activation)
            .await
            .is_err()
    );
    assert_eq!(before, fixture.provider().await);
    drop(activation);
    // Preparation failures have not removed inline fields or switched bindings.
    assert!(
        crate::credential_activation::begin(Arc::clone(&fixture.store), false)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn staged_inline_write_restarts_with_exact_journal_and_original_row_intact() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    provider
        .credentials
        .insert("TOKEN".into(), "inline-write-retry-marker".into());
    fixture.save(&provider).await;
    let fault = Arc::new(FaultBackend::new(fixture.runtime.issuer()));
    fault.lose_store_response.store(true, Ordering::SeqCst);
    let versioned = VersionedCredentials::new(Arc::clone(&fixture.store), fault.clone()).unwrap();
    let mut activation = fixture.activation().await;
    assert!(
        migrate(&fixture.runtime, &versioned, &mut activation)
            .await
            .is_err()
    );
    assert_eq!(
        fixture.provider().await.credentials["TOKEN"],
        "inline-write-retry-marker"
    );
    let journal_before = fixture
        .store
        .collect_records(JOURNAL_TYPE, ObjectListQuery::AllWorkspaces)
        .await
        .unwrap();
    assert_eq!(journal_before.len(), 1);
    let intent: Journal = serde_json::from_slice(&journal_before[0].payload).unwrap();
    assert!(intent.handles.is_none());
    drop(activation);
    let resumed_backend = Arc::new(FaultBackend::new(fixture.backend().await));
    let resumed =
        VersionedCredentials::new(Arc::clone(&fixture.store), resumed_backend.clone()).unwrap();
    let mut activation = fixture.activation().await;
    migrate(&fixture.runtime, &resumed, &mut activation)
        .await
        .unwrap();
    assert_eq!(
        fault.write_ids.lock().unwrap().as_slice(),
        std::slice::from_ref(&intent.write_id)
    );
    assert_eq!(
        resumed_backend.write_ids.lock().unwrap().as_slice(),
        &[intent.write_id]
    );
    let values = resolve(&resumed, &fixture.provider().await).await;
    assert_eq!(values[0].version, 1);
    assert_eq!(values[0].value, "inline-write-retry-marker");
}

#[tokio::test]
async fn restart_after_provider_switch_activates_only_exact_prepared_grant() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    let mut state = state();
    let versioned = fixture.versioned();
    state.output_references = ReferenceRuntime::pending_handles(
        fixture.runtime.storage_driver_name(),
        ["TOKEN".to_owned()],
    )
    .unwrap();
    state.output_references = versioned
        .references
        .prepare_bundle(
            owner(&state),
            state.object_id(),
            &state.output_references,
            "prepared-before-provider-switch",
        )
        .await
        .unwrap();
    let grant = versioned
        .references
        .prepare_grant(
            owner(&state),
            state.object_id(),
            state.object_id(),
            &persistence::encode(&state).unwrap(),
        )
        .await
        .unwrap();
    provider.credential_handles = state.output_references.clone();
    provider.metadata.as_mut().unwrap().annotations.insert(
        annotation_key("TOKEN").unwrap(),
        serde_json::to_string(&BindingTransition {
            grant_id: state.object_id().to_owned(),
            prepared_version: grant.resource_version,
            old_grant_id: None,
            old_grant_version: None,
            epoch: state.object_id().to_owned(),
            retired_references: BTreeMap::new(),
        })
        .unwrap(),
    );
    fixture.save(&provider).await;
    let mut activation = fixture.activation().await;
    activation.mark_irreversible().await.unwrap();
    activation.finish().await.unwrap();
    drop(activation);
    let versioned =
        VersionedCredentials::new(Arc::clone(&fixture.store), fixture.backend().await).unwrap();
    let mut activation = fixture.activation().await;
    assert!(activation.already_active());
    migrate(&fixture.runtime, &versioned, &mut activation)
        .await
        .unwrap();
    let current = versioned
        .references
        .get_grant(owner(&state), state.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(current.active);
    assert!(!current.prepared);
    let version = current.resource_version;
    migrate(&fixture.runtime, &versioned, &mut activation)
        .await
        .unwrap();
    assert_eq!(
        versioned
            .references
            .get_grant(owner(&state), state.object_id())
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        version
    );
}

#[tokio::test]
async fn mismatched_prepared_binding_fails_closed_without_activation() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    let state = state();
    let versioned = fixture.versioned();
    let grant = versioned
        .references
        .prepare_grant(
            owner(&state),
            state.object_id(),
            state.object_id(),
            &persistence::encode(&state).unwrap(),
        )
        .await
        .unwrap();
    provider.metadata.as_mut().unwrap().annotations.insert(
        annotation_key("TOKEN").unwrap(),
        serde_json::to_string(&BindingTransition {
            grant_id: state.object_id().to_owned(),
            prepared_version: grant.resource_version,
            old_grant_id: None,
            old_grant_version: None,
            epoch: state.object_id().to_owned(),
            retired_references: BTreeMap::new(),
        })
        .unwrap(),
    );
    fixture.save(&provider).await;
    let mut activation = fixture.activation().await;
    assert!(
        migrate(&fixture.runtime, &versioned, &mut activation)
            .await
            .is_err()
    );
    assert!(
        !versioned
            .references
            .get_grant(owner(&state), state.object_id())
            .await
            .unwrap()
            .unwrap()
            .active
    );
}

#[tokio::test]
async fn completed_activation_never_reimports_frozen_grants_after_disable_or_owner_deletion() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    provider
        .credentials
        .insert("TOKEN".into(), "last-value".into());
    fixture.save(&provider).await;
    let state = state();
    save_state(&fixture, &state).await;
    let versioned = fixture.run().await;
    let current = versioned
        .get_by_id(state.object_id())
        .await
        .unwrap()
        .unwrap();
    versioned
        .references
        .tombstone_grant(
            owner(&current),
            current.object_id(),
            current.metadata.as_ref().unwrap().resource_version,
            &persistence::encode(&current).unwrap(),
        )
        .await
        .unwrap();
    fixture
        .store
        .delete("provider", "provider-id")
        .await
        .unwrap();
    let resumed =
        VersionedCredentials::new(Arc::clone(&fixture.store), fixture.backend().await).unwrap();
    let mut activation = fixture.activation().await;
    migrate(&fixture.runtime, &resumed, &mut activation)
        .await
        .unwrap();
    let stored = resumed
        .references
        .get_grant(owner(&state), state.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.active);
    assert!(
        resumed
            .get_by_id(state.object_id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        fixture
            .store
            .get("provider_credential_refresh_state", state.object_id())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn disabled_binding_recovery_revokes_grant_without_touching_retained_output() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    provider
        .credentials
        .insert("TOKEN".into(), "retained-output".into());
    fixture.save(&provider).await;
    save_state(&fixture, &state()).await;
    let versioned = fixture.run().await;
    let current = versioned
        .get_by_id("legacy-grant-id")
        .await
        .unwrap()
        .unwrap();
    versioned
        .retain_static_outputs(
            &fixture.provider().await,
            &current,
            fixture.runtime.storage_driver_name(),
        )
        .await
        .unwrap();
    let provider = fixture.provider().await;
    let static_handle = provider.credential_handles["TOKEN"].clone();
    let mut activation = fixture.activation().await;
    migrate(&fixture.runtime, &versioned, &mut activation)
        .await
        .unwrap();
    assert!(
        versioned
            .get_by_id(current.object_id())
            .await
            .unwrap()
            .is_none()
    );
    let values = resolve(&versioned, &fixture.provider().await).await;
    assert_eq!(values[0].value, "retained-output");
    assert_eq!(
        fixture.provider().await.credential_handles["TOKEN"],
        static_handle
    );
    migrate(&fixture.runtime, &versioned, &mut activation)
        .await
        .unwrap();
    assert_eq!(
        resolve(&versioned, &fixture.provider().await).await[0].version,
        1
    );
}

#[tokio::test]
async fn internal_typed_handles_preserve_identity_and_duplicate_candidates_do_not_reclaim_live_secrets()
 {
    let fixture = Fixture::new().await;
    let sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: "sandbox-id".into(),
            name: "sandbox-name".into(),
            workspace: "workspace".into(),
            ..Default::default()
        }),
        host_key_fingerprint: "unchanged-fingerprint".into(),
        ..Default::default()
    };
    fixture.store.put_message(&sandbox).await.unwrap();
    let ssh_owner = SecretOwner::sandbox("workspace", "sandbox-id");
    let ssh = fixture
        .runtime
        .store_secrets_with_object_id(
            ssh_owner,
            "old-ssh-path",
            &HashMap::from([("SSH_HOST_PRIVATE_KEY".into(), "private-key-marker".into())]),
            &Handles::new(),
        )
        .await
        .unwrap();
    let identity = serde_json::json!({"fingerprint": "unchanged-fingerprint", "credential_handle": ssh["SSH_HOST_PRIVATE_KEY"].encode_to_vec()});
    fixture
        .store
        .create_scoped(
            "sandbox_ssh_identity_v1",
            "sandbox-ssh:sandbox-id",
            "sandbox-id",
            "workspace",
            "sandbox-id",
            &serde_json::to_vec(&identity).unwrap(),
            None,
        )
        .await
        .unwrap();
    fixture
        .store
        .create_scoped(
            "sandbox_ssh_identity_candidate_v1",
            "candidate-id",
            "candidate-id",
            "workspace",
            "sandbox-id",
            &serde_json::to_vec(&identity).unwrap(),
            None,
        )
        .await
        .unwrap();
    let launch_owner = SecretOwner::supervisor_instance("workspace", "sandbox-id");
    let launch = fixture
        .runtime
        .store_secrets_with_object_id(
            launch_owner,
            "old-launch-path",
            &HashMap::from([(
                "SHARED_INSTANCE_LAUNCH_MATERIAL".into(),
                "registration-marker".into(),
            )]),
            &Handles::new(),
        )
        .await
        .unwrap();
    let payload = serde_json::json!({"route":"route-id", "sandbox_id":"sandbox-id", "generation":"generation", "workspace":"workspace", "phase":"published", "writer":"writer", "material_handle": launch["SHARED_INSTANCE_LAUNCH_MATERIAL"].encode_to_vec()});
    for object_type in [
        "supervisor_instance_assignment",
        "supervisor_instance_material_candidate",
    ] {
        fixture
            .store
            .put_if(
                object_type,
                &format!("{object_type}-route-id"),
                "route-id",
                "workspace",
                &serde_json::to_vec(&payload).unwrap(),
                None,
                WriteCondition::MustCreate,
            )
            .await
            .unwrap();
    }
    let versioned = fixture.run().await;
    assert!(
        fixture
            .store
            .get("sandbox_ssh_identity_candidate_v1", "candidate-id")
            .await
            .unwrap()
            .is_none()
    );
    let record = fixture
        .store
        .get("sandbox_ssh_identity_v1", "sandbox-ssh:sandbox-id")
        .await
        .unwrap()
        .unwrap();
    let updated: serde_json::Value = serde_json::from_slice(&record.payload).unwrap();
    assert_eq!(updated["fingerprint"], "unchanged-fingerprint");
    let bytes: Vec<u8> = serde_json::from_value(updated["credential_handle"].clone()).unwrap();
    let handle = CredentialHandle::decode(bytes.as_slice()).unwrap();
    assert_eq!(handle.handle, ssh["SSH_HOST_PRIVATE_KEY"].handle);
    let value = versioned
        .references
        .resolve(
            ssh_owner,
            &HashMap::from([("SSH_HOST_PRIVATE_KEY".into(), handle)]),
        )
        .await
        .unwrap();
    assert_eq!(value[0].version, 1);
    assert_eq!(value[0].value, "private-key-marker");
    let assignment = fixture
        .store
        .get(
            "supervisor_instance_assignment",
            "supervisor_instance_assignment-route-id",
        )
        .await
        .unwrap()
        .unwrap();
    let candidate = fixture
        .store
        .get(
            "supervisor_instance_material_candidate",
            "supervisor_instance_material_candidate-route-id",
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(assignment.payload, candidate.payload);
    let updated: serde_json::Value = serde_json::from_slice(&assignment.payload).unwrap();
    for key in [
        "route",
        "sandbox_id",
        "generation",
        "workspace",
        "phase",
        "writer",
    ] {
        assert_eq!(updated[key], payload[key]);
    }
    let bytes: Vec<u8> = serde_json::from_value(updated["material_handle"].clone()).unwrap();
    let handle = CredentialHandle::decode(bytes.as_slice()).unwrap();
    assert_eq!(
        handle.handle,
        launch["SHARED_INSTANCE_LAUNCH_MATERIAL"].handle
    );
    assert_eq!(
        versioned
            .references
            .resolve(
                launch_owner,
                &HashMap::from([("SHARED_INSTANCE_LAUNCH_MATERIAL".into(), handle)])
            )
            .await
            .unwrap()[0]
            .value,
        "registration-marker"
    );
    assert_eq!(
        fixture
            .store
            .get_message::<Sandbox>("sandbox-id")
            .await
            .unwrap()
            .unwrap()
            .host_key_fingerprint,
        "unchanged-fingerprint"
    );
}

#[tokio::test]
async fn preparation_restart_keeps_legacy_fields_until_one_provider_cas() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    provider
        .credentials
        .insert("TOKEN".into(), "prepared-inline-marker".into());
    fixture.save(&provider).await;
    save_state(&fixture, &state()).await;
    let provider = fixture.provider().await;
    let mut state: RefreshState = (&crate::refresh_store::list_all_refresh_states(&fixture.store)
        .await
        .unwrap()[0])
        .into();
    let versioned = fixture.versioned();
    let candidates = inline_provider(&fixture.runtime, &versioned, &provider)
        .await
        .unwrap();
    let epoch = effective_authorization_epoch(&state).unwrap().to_owned();
    let operation = identity(&(
        "refresh-outputs",
        OwnerIdentity::of(provider_owner(&provider)),
        state.object_id(),
        &epoch,
    ))
    .unwrap();
    state.output_references = versioned
        .references
        .adopt_with_expiration(
            provider_owner(&provider),
            &epoch,
            &candidates,
            None,
            &operation,
        )
        .await
        .unwrap();
    state.reference_generation = 1;
    versioned
        .references
        .prepare_grant(
            owner(&state),
            state.object_id(),
            &epoch,
            &persistence::encode(&state).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fixture.provider().await, provider);
    // No irreversible switch happened; a compatible legacy reader still has
    // its complete original row while the prepared grant cannot mint.
    assert!(
        crate::credential_activation::begin(Arc::clone(&fixture.store), false)
            .await
            .unwrap()
            .is_none()
    );
    let reopened =
        VersionedCredentials::new(Arc::clone(&fixture.store), fixture.backend().await).unwrap();
    let mut activation = fixture.activation().await;
    migrate(&fixture.runtime, &reopened, &mut activation)
        .await
        .unwrap();
    let migrated = fixture.provider().await;
    assert!(migrated.credentials.is_empty());
    assert_eq!(resolve(&reopened, &migrated).await[0].version, 1);
    assert_eq!(
        reopened
            .references
            .get_grant(owner(&state), state.object_id())
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        2
    );
}

#[tokio::test]
async fn uncertain_inline_refresh_material_write_reuses_its_journal_after_restart() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    provider.credential_handles = fixture
        .runtime
        .store_provider_credentials(
            "display-name",
            "workspace",
            "provider-id",
            &HashMap::from([("TOKEN".into(), "old-output".into())]),
            &Handles::new(),
        )
        .await
        .unwrap();
    fixture.save(&provider).await;
    let mut state = state();
    state.material.insert(
        "client_secret".into(),
        "inline-material-retry-marker".into(),
    );
    // The strategy itself identifies the secret even when the legacy key list
    // omitted it. It must never enter the new issuer non-secret codec.
    save_state(&fixture, &state).await;
    let fault = Arc::new(FaultBackend::new(fixture.runtime.issuer()));
    fault.lose_material_response.store(true, Ordering::SeqCst);
    let versioned = VersionedCredentials::new(Arc::clone(&fixture.store), fault.clone()).unwrap();
    let mut activation = fixture.activation().await;
    assert!(
        migrate(&fixture.runtime, &versioned, &mut activation)
            .await
            .is_err()
    );
    assert_eq!(
        fixture.provider().await.credential_handles,
        provider.credential_handles
    );
    assert!(
        versioned
            .references
            .get_grant(owner(&state), state.object_id())
            .await
            .unwrap()
            .is_none()
    );
    let write_id = fault.material_write_ids.lock().unwrap()[0].clone();
    drop(activation);
    let backend = Arc::new(FaultBackend::new(fixture.backend().await));
    let reopened = VersionedCredentials::new(Arc::clone(&fixture.store), backend.clone()).unwrap();
    let mut activation = fixture.activation().await;
    migrate(&fixture.runtime, &reopened, &mut activation)
        .await
        .unwrap();
    assert_eq!(
        backend.material_write_ids.lock().unwrap().as_slice(),
        &[write_id]
    );
    let current = reopened
        .get_by_id(state.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(!current.material.contains_key("client_secret"));
    assert_eq!(
        reopened
            .backend
            .resolve_refresh_material(
                refresh_material_scope(&current),
                &current.secret_material_handles
            )
            .await
            .unwrap()["client_secret"],
        "inline-material-retry-marker"
    );
    for record in fixture
        .store
        .collect_records(REFERENCE_OBJECT_TYPE, ObjectListQuery::AllWorkspaces)
        .await
        .unwrap()
    {
        assert!(!String::from_utf8_lossy(&record.payload).contains("inline-material-retry-marker"));
    }
}

#[tokio::test]
async fn parked_deletion_preserves_multiple_material_generations_without_cleanup() {
    let fixture = Fixture::new().await;
    let mut state = state();
    state.status = "deleting".into();
    state.metadata.as_mut().unwrap().deletion_time = Some(prost_types::Timestamp {
        seconds: 1,
        nanos: 0,
    });
    for id in ["old-material-one", "old-material-two"] {
        let handles = fixture
            .runtime
            .issuer()
            .store_refresh_material_with_object_id(
                refresh_material_scope(&state),
                id,
                &HashMap::from([("client_secret".into(), id.into())]),
                &Handles::new(),
            )
            .await
            .unwrap();
        state
            .pending_secret_deletions
            .push(RefreshMaterialDeletion {
                material_key: "client_secret".into(),
                handle: Some(handles["client_secret"].clone()),
            });
    }
    save_state(&fixture, &state).await;
    let before = fixture
        .store
        .collect_records(
            openshell_credential_issuer::persistence::OBJECT_TYPE,
            ObjectListQuery::AllWorkspaces,
        )
        .await
        .unwrap();
    let versioned = fixture.run().await;
    let migrated = versioned
        .get_by_id(state.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(migrated.pending_secret_deletions.len(), 2);
    for (old, new) in state
        .pending_secret_deletions
        .iter()
        .zip(&migrated.pending_secret_deletions)
    {
        assert_eq!(old.material_key, new.material_key);
        assert_eq!(old.handle, new.handle);
    }
    let after = fixture
        .store
        .collect_records(
            openshell_credential_issuer::persistence::OBJECT_TYPE,
            ObjectListQuery::AllWorkspaces,
        )
        .await
        .unwrap();
    assert_eq!(before.len(), after.len());
    for (before, after) in before.iter().zip(&after) {
        assert_eq!(before.payload, after.payload);
    }
    let grant = versioned
        .references
        .get_grant(owner(&state), state.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(!grant.active);
}

async fn switch_to_prepared_replacement(
    fixture: &Fixture,
    versioned: &VersionedCredentials,
    old: &RefreshState,
) -> (RefreshState, Provider) {
    let mut replacement = old.clone();
    replacement.metadata.as_mut().unwrap().id = "replacement-grant-id".into();
    replacement.metadata.as_mut().unwrap().resource_version = 0;
    replacement.authorization_epoch = "replacement-epoch".into();
    let identities = ReferenceRuntime::pending_handles(
        fixture.runtime.storage_driver_name(),
        ["TOKEN".to_owned()],
    )
    .unwrap();
    replacement.output_references = versioned
        .references
        .rebind_bundle(
            owner(old),
            &replacement.authorization_epoch,
            &old.output_references,
            &identities,
            "recovery-replacement-outputs",
        )
        .await
        .unwrap();
    replacement.reference_generation = 1;
    let prepared = versioned
        .references
        .prepare_grant(
            owner(&replacement),
            replacement.object_id(),
            &replacement.authorization_epoch,
            &persistence::encode(&replacement).unwrap(),
        )
        .await
        .unwrap();
    let mut provider = fixture.provider().await;
    provider.credential_handles = replacement.output_references.clone();
    provider.metadata.as_mut().unwrap().annotations.insert(
        annotation_key("TOKEN").unwrap(),
        serde_json::to_string(&BindingTransition {
            grant_id: replacement.object_id().to_owned(),
            prepared_version: prepared.resource_version,
            old_grant_id: Some(old.object_id().to_owned()),
            old_grant_version: Some(old.metadata.as_ref().unwrap().resource_version),
            epoch: replacement.authorization_epoch.clone(),
            retired_references: BTreeMap::new(),
        })
        .unwrap(),
    );
    fixture.save(&provider).await;
    (replacement, fixture.provider().await)
}

#[tokio::test]
async fn prepared_binding_recovery_refreshes_only_the_exact_old_grant_version() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    provider
        .metadata
        .as_mut()
        .unwrap()
        .labels
        .insert("recovery-label".into(), "preserved".into());
    provider
        .credentials
        .insert("TOKEN".into(), "retained-recovery-value".into());
    fixture.save(&provider).await;
    save_state(&fixture, &state()).await;
    let versioned = fixture.run().await;
    let mut old = versioned
        .get_by_id("legacy-grant-id")
        .await
        .unwrap()
        .unwrap();
    let (replacement, _) = switch_to_prepared_replacement(&fixture, &versioned, &old).await;

    // A different preparation is not the provider's winning authorization.
    let mut abandoned = replacement.clone();
    abandoned.metadata.as_mut().unwrap().id = "abandoned-grant-id".into();
    abandoned.authorization_epoch = "abandoned-epoch".into();
    let identities = ReferenceRuntime::pending_handles(
        fixture.runtime.storage_driver_name(),
        ["TOKEN".to_owned()],
    )
    .unwrap();
    abandoned.output_references = versioned
        .references
        .prepare_bundle(
            owner(&abandoned),
            &abandoned.authorization_epoch,
            &identities,
            "abandoned-preparation",
        )
        .await
        .unwrap();
    abandoned.reference_generation = 0;
    versioned
        .references
        .prepare_grant(
            owner(&abandoned),
            abandoned.object_id(),
            &abandoned.authorization_epoch,
            &persistence::encode(&abandoned).unwrap(),
        )
        .await
        .unwrap();

    // Crash happened after the provider CAS, before new-grant activation. An
    // old-epoch worker then committed bookkeeping on another compatible replica.
    let stale_version = old.metadata.as_ref().unwrap().resource_version;
    let worker_lease = fixture
        .store
        .acquire_refresh_guard(&old.provider_id, &old.credential_key)
        .await
        .unwrap();
    old.status = "cleanup_advanced".into();
    let advanced = versioned
        .references
        .put_grant(
            owner(&old),
            old.object_id(),
            Some(stale_version),
            effective_authorization_epoch(&old).unwrap(),
            &persistence::encode(&old).unwrap(),
            true,
        )
        .await
        .unwrap();
    assert!(advanced.resource_version > stale_version);
    drop(worker_lease);

    let reopened =
        VersionedCredentials::new(Arc::clone(&fixture.store), fixture.backend().await).unwrap();
    let mut activation = fixture.activation().await;
    migrate(&fixture.runtime, &reopened, &mut activation)
        .await
        .unwrap();
    let current = fixture.provider().await;
    let transition: BindingTransition = serde_json::from_str(
        &current.metadata.as_ref().unwrap().annotations[&annotation_key("TOKEN").unwrap()],
    )
    .unwrap();
    assert_eq!(transition.old_grant_id.as_deref(), Some(old.object_id()));
    assert_eq!(
        transition.old_grant_version,
        Some(advanced.resource_version)
    );
    assert_eq!(transition.grant_id, replacement.object_id());
    let new_grant = reopened
        .references
        .get_grant(owner(&replacement), replacement.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(new_grant.active && !new_grant.prepared);
    assert!(
        !reopened
            .references
            .get_grant(owner(&old), old.object_id())
            .await
            .unwrap()
            .unwrap()
            .active
    );
    let losing = reopened
        .references
        .get_grant(owner(&abandoned), abandoned.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(losing.prepared && !losing.active);
    assert!(
        reopened
            .references
            .resolve(owner(&old), &old.output_references)
            .await
            .is_err()
    );
    reopened
        .references
        .reclaim(owner(&replacement), 16)
        .await
        .unwrap();
    assert_eq!(
        resolve(&reopened, &current).await[0].value,
        "retained-recovery-value"
    );
    let selected: Vec<Provider> = fixture
        .store
        .collect_messages(ObjectListQuery::WorkspaceSelector {
            workspace: "workspace",
            label_selector: "recovery-label=preserved",
        })
        .await
        .unwrap();
    assert_eq!(selected.len(), 1);
    migrate(&fixture.runtime, &reopened, &mut activation)
        .await
        .unwrap();
    assert_eq!(
        reopened
            .references
            .get_grant(owner(&replacement), replacement.object_id())
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        new_grant.resource_version
    );
    reopened
        .references
        .tombstone_grant(
            owner(&replacement),
            replacement.object_id(),
            new_grant.resource_version,
            &persistence::encode(&replacement).unwrap(),
        )
        .await
        .unwrap();
    migrate(&fixture.runtime, &reopened, &mut activation)
        .await
        .unwrap();
    assert!(
        !reopened
            .references
            .get_grant(owner(&replacement), replacement.object_id())
            .await
            .unwrap()
            .unwrap()
            .active
    );
    assert!(
        !reopened
            .references
            .get_grant(owner(&old), old.object_id())
            .await
            .unwrap()
            .unwrap()
            .active
    );
}

#[tokio::test]
async fn stale_recovery_inventory_cannot_activate_a_no_longer_bound_preparation() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    provider
        .credentials
        .insert("TOKEN".into(), "old-value".into());
    fixture.save(&provider).await;
    save_state(&fixture, &state()).await;
    let versioned = fixture.run().await;
    let old = versioned
        .get_by_id("legacy-grant-id")
        .await
        .unwrap()
        .unwrap();
    let original = fixture.provider().await;
    let (replacement, observed) = switch_to_prepared_replacement(&fixture, &versioned, &old).await;
    // The bound annotation changed after startup took its inventory. Only the
    // current exact binding, not that stale inventory, can authorize activation.
    fixture.save(&original).await;
    let mut activation = fixture.activation().await;
    recover_bindings(&versioned, &observed, &mut activation)
        .await
        .unwrap();
    let prepared = versioned
        .references
        .get_grant(owner(&replacement), replacement.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(prepared.prepared && !prepared.active);
    assert!(
        versioned
            .references
            .get_grant(owner(&old), old.object_id())
            .await
            .unwrap()
            .unwrap()
            .active
    );
    assert_eq!(
        resolve(&versioned, &fixture.provider().await).await[0].value,
        "old-value"
    );
}

#[tokio::test]
async fn recovery_cannot_refresh_the_version_of_an_unrelated_or_revoked_old_grant() {
    let fixture = Fixture::new().await;
    let mut provider = provider();
    provider
        .credentials
        .insert("TOKEN".into(), "old-value".into());
    fixture.save(&provider).await;
    save_state(&fixture, &state()).await;
    let versioned = fixture.run().await;
    let old = versioned
        .get_by_id("legacy-grant-id")
        .await
        .unwrap()
        .unwrap();
    let (replacement, mut provider) =
        switch_to_prepared_replacement(&fixture, &versioned, &old).await;
    let mut unrelated = old.clone();
    unrelated.metadata.as_mut().unwrap().id = "unrelated-old-grant".into();
    unrelated.credential_key = "OTHER".into();
    unrelated.authorization_epoch = "unrelated-epoch".into();
    unrelated.output_references.clear();
    versioned
        .references
        .put_grant(
            owner(&unrelated),
            unrelated.object_id(),
            None,
            &unrelated.authorization_epoch,
            &persistence::encode(&unrelated).unwrap(),
            true,
        )
        .await
        .unwrap();
    let annotation = annotation_key("TOKEN").unwrap();
    let mut transition: BindingTransition =
        serde_json::from_str(&provider.metadata.as_ref().unwrap().annotations[&annotation])
            .unwrap();
    transition.old_grant_id = Some(unrelated.object_id().to_owned());
    transition.old_grant_version = Some(1);
    provider.metadata.as_mut().unwrap().annotations.insert(
        annotation.clone(),
        serde_json::to_string(&transition).unwrap(),
    );
    fixture.save(&provider).await;
    let mut activation = fixture.activation().await;
    assert_eq!(
        migrate(&fixture.runtime, &versioned, &mut activation)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert!(
        versioned
            .references
            .get_grant(owner(&unrelated), unrelated.object_id())
            .await
            .unwrap()
            .unwrap()
            .active
    );
    assert!(
        versioned
            .references
            .get_grant(owner(&replacement), replacement.object_id())
            .await
            .unwrap()
            .unwrap()
            .prepared
    );
    transition.old_grant_id = Some(old.object_id().to_owned());
    transition.old_grant_version = Some(old.metadata.as_ref().unwrap().resource_version);
    provider
        .metadata
        .as_mut()
        .unwrap()
        .annotations
        .insert(annotation, serde_json::to_string(&transition).unwrap());
    fixture.save(&provider).await;
    versioned
        .references
        .tombstone_grant(
            owner(&old),
            old.object_id(),
            old.metadata.as_ref().unwrap().resource_version,
            &persistence::encode(&old).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        migrate(&fixture.runtime, &versioned, &mut activation)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert!(
        !versioned
            .references
            .get_grant(owner(&old), old.object_id())
            .await
            .unwrap()
            .unwrap()
            .active
    );
    let prepared = versioned
        .references
        .get_grant(owner(&replacement), replacement.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(prepared.prepared && !prepared.active);
}

struct FaultBackend {
    inner: Arc<dyn CredentialIssuer>,
    lose_store_response: AtomicBool,
    lose_material_response: AtomicBool,
    write_ids: Mutex<Vec<String>>,
    material_write_ids: Mutex<Vec<String>>,
    writes: AtomicUsize,
}
impl FaultBackend {
    fn new(inner: Arc<dyn CredentialIssuer>) -> Self {
        Self {
            inner,
            lose_store_response: AtomicBool::new(false),
            lose_material_response: AtomicBool::new(false),
            write_ids: Mutex::new(Vec::new()),
            material_write_ids: Mutex::new(Vec::new()),
            writes: AtomicUsize::new(0),
        }
    }
}
impl std::fmt::Debug for FaultBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FaultBackend([REDACTED])")
    }
}
#[async_trait]
impl CredentialIssuer for FaultBackend {
    fn validate_handles(&self, handles: &Handles) -> Result<(), Status> {
        self.inner.validate_handles(handles)
    }
    fn stores_provider_credentials(&self) -> bool {
        self.inner.stores_provider_credentials()
    }
    fn storage_owns_handle(&self, handle: &CredentialHandle) -> bool {
        self.inner.storage_owns_handle(handle)
    }
    fn negotiated_extensions(&self) -> &[NegotiatedExtension] {
        self.inner.negotiated_extensions()
    }
    async fn store(&self, request: StoreSecrets<'_>) -> Result<Handles, Status> {
        self.write_ids
            .lock()
            .unwrap()
            .push(request.object_id.unwrap().to_owned());
        self.writes.fetch_add(1, Ordering::SeqCst);
        let result = self.inner.store(request).await?;
        if self.lose_store_response.swap(false, Ordering::SeqCst) {
            return Err(Status::unavailable("injected lost backend write response"));
        }
        Ok(result)
    }
    async fn delete(&self, owner: SecretOwner<'_>, handles: &Handles) -> Result<(), Status> {
        self.inner.delete(owner, handles).await
    }
    async fn resolve(
        &self,
        owner: SecretOwner<'_>,
        handles: &Handles,
    ) -> Result<Vec<ResolvedSecret>, Status> {
        self.inner.resolve(owner, handles).await
    }
    async fn store_refresh_material_with_object_id(
        &self,
        scope: RefreshMaterialScope<'_>,
        id: &str,
        material: &HashMap<String, String>,
        handles: &Handles,
    ) -> Result<Handles, Status> {
        self.material_write_ids.lock().unwrap().push(id.to_owned());
        let result = self
            .inner
            .store_refresh_material_with_object_id(scope, id, material, handles)
            .await?;
        if self.lose_material_response.swap(false, Ordering::SeqCst) {
            return Err(Status::unavailable("injected lost material write response"));
        }
        Ok(result)
    }
    async fn resolve_refresh_material(
        &self,
        scope: RefreshMaterialScope<'_>,
        handles: &Handles,
    ) -> Result<HashMap<String, String>, Status> {
        self.inner.resolve_refresh_material(scope, handles).await
    }
    async fn delete_refresh_material_handles(
        &self,
        scope: RefreshMaterialScope<'_>,
        handles: &Handles,
    ) -> Result<(), Status> {
        self.inner
            .delete_refresh_material_handles(scope, handles)
            .await
    }
    async fn delete_refresh_material_deletions(
        &self,
        scope: RefreshMaterialScope<'_>,
        deletions: &[RefreshMaterialDeletion],
    ) -> Result<(), Status> {
        self.inner
            .delete_refresh_material_deletions(scope, deletions)
            .await
    }
}
