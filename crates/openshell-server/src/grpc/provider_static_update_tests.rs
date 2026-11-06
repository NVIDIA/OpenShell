// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::credentials::CredentialRuntime;
use crate::grpc::MAX_METADATA_ANNOTATIONS_ENTRIES;
use crate::versioned_credentials::{VersionedCredentials, static_updates};
use openshell_core::proto::ObjectMeta;
use openshell_credential_issuer::SecretOwner;
use openshell_credential_issuer::references::ReferenceProjection;
use std::sync::Arc;

struct Fixture {
    directory: tempfile::TempDir,
    config: openshell_core::Config,
    file: crate::config_file::ConfigFile,
    store: Arc<Store>,
    credentials: CredentialRuntime,
    catalog: EffectiveProviderProfileCatalog,
}

impl Fixture {
    async fn new() -> Self {
        Self::new_with_migration_at_annotation_quota(false).await
    }

    async fn new_with_migration_at_annotation_quota(migrate_at_quota: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let database = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("state.sqlite").display()
        );
        let store = Arc::new(Store::connect(&database).await.unwrap());
        let key_path =
            serde_json::to_string(&directory.path().join("kek").to_string_lossy()).unwrap();
        let file = toml::from_str(&format!(
            "[openshell.gateway.credential_storage]\nkey_encryption_key_path = {key_path}\n"
        ))
        .unwrap();
        let key = directory.path().join("intent-key");
        std::fs::write(&key, b"test-only stable private fingerprint material").unwrap();
        let mut config = openshell_core::Config::new(None);
        config.enable_versioned_credentials = !migrate_at_quota;
        config.gateway_jwt = Some(openshell_core::config::GatewayJwtConfig {
            signing_key_path: key,
            public_key_path: directory.path().join("public"),
            kid_path: directory.path().join("kid"),
            gateway_id: "test".into(),
            ttl_secs: None,
        });
        let credentials = CredentialRuntime::from_config_file_with_store(
            &config,
            Some(&file),
            Arc::clone(&store),
        )
        .await
        .unwrap();
        let catalog = ProviderProfileSources::with_default_sources()
            .snapshot_catalog(&store, "default")
            .await
            .unwrap();
        let mut input = Self::input("original", 0);
        if migrate_at_quota {
            input.metadata.as_mut().unwrap().annotations = (0..MAX_METADATA_ANNOTATIONS_ENTRIES)
                .map(|index| (format!("example.com/key-{index}"), "value".into()))
                .collect();
        }
        create_provider_record_validating(&store, "default", &catalog, input, Some(&credentials))
            .await
            .unwrap();
        let credentials = if migrate_at_quota {
            config.enable_versioned_credentials = true;
            CredentialRuntime::from_config_file_with_store(&config, Some(&file), Arc::clone(&store))
                .await
                .unwrap()
        } else {
            credentials
        };
        Self {
            directory,
            config,
            file,
            store,
            credentials,
            catalog,
        }
    }

    fn input(value: &str, version: u64) -> Provider {
        Provider {
            metadata: Some(ObjectMeta {
                name: "static-provider".into(),
                workspace: "default".into(),
                resource_version: version,
                ..Default::default()
            }),
            r#type: "custom".into(),
            credentials: HashMap::from([("TOKEN".into(), value.into())]),
            ..Default::default()
        }
    }

    async fn provider(&self) -> Provider {
        self.store
            .get_message_by_name("default", "static-provider")
            .await
            .unwrap()
            .unwrap()
    }

    fn versioned(&self) -> &Arc<VersionedCredentials> {
        self.credentials.versioned().unwrap()
    }

    async fn update(&self, provider: Provider) -> Result<Provider, Status> {
        update_provider_record_validating(
            &self.store,
            &crate::provider_refresh::test_runtime(&self.store),
            "default",
            &self.catalog,
            provider,
            &[],
            Some(&self.credentials),
        )
        .await
    }

    async fn capture(&self) -> (String, String, u64) {
        let provider = self.provider().await;
        let owner = SecretOwner::provider("default", provider.object_id(), provider.object_name());
        let mut secrets = self
            .versioned()
            .references
            .resolve(owner, &provider.credential_handles)
            .await
            .unwrap();
        let secret = secrets.remove(0);
        (secret.reference.reference_id, secret.value, secret.version)
    }

    /// Pause precisely after provider CAS, before owner-record activation.
    async fn publish_pending(&self, value: &str) -> Provider {
        let mut provider = self.provider().await;
        let update = prepare_provider_credential_update(
            Some(&self.credentials),
            provider.object_name(),
            "default",
            provider.object_id(),
            &HashMap::from([("TOKEN".into(), value.into())]),
            &provider.credential_handles,
        )
        .await
        .unwrap();
        provider.credential_handles.extend(update.published_handles);
        provider.metadata.as_mut().unwrap().annotations.insert(
            static_updates::ANNOTATION.into(),
            update.static_marker.unwrap(),
        );
        let result = self
            .store
            .put_if(
                Provider::object_type(),
                provider.object_id(),
                provider.object_name(),
                "default",
                &provider.encode_to_vec(),
                None,
                WriteCondition::MatchResourceVersion(
                    provider.metadata.as_ref().unwrap().resource_version,
                ),
            )
            .await
            .unwrap();
        provider.metadata.as_mut().unwrap().resource_version = result.resource_version;
        provider
    }
}

#[tokio::test]
async fn versioned_reference_retention_excludes_cold_proofs_from_grant_enumeration() {
    use openshell_credential_issuer::StoreSecrets;
    use openshell_credential_issuer::references::{
        ActivateBundle, REFERENCE_RETENTION_OBJECT_TYPE, ReferenceStateStore,
    };

    let f = Fixture::new().await;
    let provider = f.provider().await;
    let references = provider.credential_handles.clone();
    let owner = SecretOwner::provider("default", provider.object_id(), "static-provider");
    for index in 0..30 {
        let id = format!("retention-regression-{index}");
        let values = HashMap::from([("TOKEN".into(), "same-value".into())]);
        let candidates = f
            .versioned()
            .backend
            .store(StoreSecrets {
                owner,
                object_id: Some(&id),
                values: &values,
                existing_handles: &HashMap::new(),
            })
            .await
            .unwrap();
        f.versioned()
            .references
            .activate_bundle(ActivateBundle {
                owner,
                epoch: "static",
                references: &references,
                candidates: &candidates,
                operation_id: &id,
                expected_generation: index + 1,
                expiration_time: None,
                grant: None,
            })
            .await
            .unwrap();
        f.versioned().references.reclaim(owner, 8).await.unwrap();
    }
    let adapter = crate::versioned_credentials::ServerReferenceStateStore(Arc::clone(&f.store));
    let cold = f
        .store
        .collect_records(
            REFERENCE_RETENTION_OBJECT_TYPE,
            ObjectListQuery::AllWorkspaces,
        )
        .await
        .unwrap();
    assert!(cold.len() >= 30);
    assert_eq!(adapter.list().await.unwrap().len(), 1);
    // An unrelated unreadable proof must not be visited by hot grant/status
    // enumeration. Proof content is validated only on its exact point lookup.
    adapter
        .put_retention("unrelated-proof", b"not an owner record".to_vec())
        .await
        .unwrap();
    assert!(f.versioned().states(None).await.unwrap().is_empty());
    assert_eq!(f.capture().await.2, 31);
}

#[tokio::test]
async fn migrated_provider_at_caller_annotation_quota_remains_updateable() {
    let f = Fixture::new_with_migration_at_annotation_quota(true).await;
    let original = f.provider().await;
    let annotations = &original.metadata.as_ref().unwrap().annotations;
    assert_eq!(annotations.len(), MAX_METADATA_ANNOTATIONS_ENTRIES + 1);
    assert_eq!(annotations["internal.openshell.ai/issuer-migrated-v1"], "1");
    let (reference, _, version) = f.capture().await;
    let mut update = Fixture::input("", 0);
    update.credentials.clear();
    f.update(update.clone()).await.unwrap();
    update.config.insert("setting".into(), "changed".into());
    let updated = f.update(update).await.unwrap();
    assert_eq!(updated.config["setting"], "changed");
    // Public projections intentionally hide gateway-owned markers; persistence
    // must retain them while exposing all 128 caller annotations.
    assert_eq!(
        updated.metadata.unwrap().annotations.len(),
        MAX_METADATA_ANNOTATIONS_ENTRIES
    );
    assert_eq!(
        f.provider().await.metadata.unwrap().annotations,
        *annotations
    );
    assert_eq!(f.capture().await, (reference, "original".into(), version));

    // Ignoring trusted markers must not remove the caller-facing quota.
    let mut excessive = f.provider().await;
    excessive
        .metadata
        .as_mut()
        .unwrap()
        .annotations
        .insert("example.com/one-too-many".into(), "value".into());
    f.store.put_message(&excessive).await.unwrap();
    let mut update = Fixture::input("", 0);
    update.credentials.clear();
    assert_eq!(
        f.update(update).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
}

#[tokio::test]
async fn static_update_same_bytes_preserves_public_reference_and_versions_two_three() {
    let f = Fixture::new().await;
    let (reference, value, version) = f.capture().await;
    assert_eq!((value.as_str(), version), ("original", 1));
    for expected in [2, 3] {
        f.update(Fixture::input("original", 0)).await.unwrap();
        assert_eq!(
            f.capture().await,
            (reference.clone(), "original".into(), expected)
        );
        let provider = f.provider().await;
        static_updates::finish(f.versioned(), &provider)
            .await
            .unwrap();
        assert_eq!(f.capture().await.2, expected, "recovery is idempotent");
    }
}

#[tokio::test]
async fn static_update_validation_and_definite_cas_losers_never_activate() {
    let f = Fixture::new().await;
    let original = f.provider().await;
    let reference = f.capture().await.0;
    let mut invalid = Fixture::input("invalid-candidate", 0);
    invalid
        .config
        .insert("k".repeat(MAX_MAP_KEY_LEN + 1), "invalid".into());
    assert!(f.update(invalid).await.is_err());
    assert_eq!(f.capture().await, (reference.clone(), "original".into(), 1));
    f.update(Fixture::input("winner", 0)).await.unwrap();
    let loser = f
        .update(Fixture::input(
            "loser",
            original.metadata.unwrap().resource_version,
        ))
        .await
        .unwrap_err();
    assert_eq!(loser.code(), tonic::Code::Aborted);
    assert_eq!(f.capture().await, (reference, "winner".into(), 2));
}

#[tokio::test]
async fn static_update_pending_marker_fails_closed_and_restart_recovers_exact_candidate() {
    let f = Fixture::new().await;
    let reference = f.capture().await.0;
    let pending = f.publish_pending("restart-winner").await;
    assert_eq!(
        static_updates::validate(f.versioned(), &pending)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert!(
        f.credentials
            .resolve_provider_handles(&pending, crate::persistence::current_time_ms())
            .await
            .is_err()
    );
    // Staging plus provider CAS alone never mutates the old live value/version.
    assert_eq!(f.capture().await, (reference.clone(), "original".into(), 1));
    let restarted = CredentialRuntime::from_config_file_with_store(
        &f.config,
        Some(&f.file),
        Arc::clone(&f.store),
    )
    .await
    .unwrap();
    static_updates::validate(restarted.versioned().unwrap(), &pending)
        .await
        .unwrap();
    assert_eq!(f.capture().await, (reference, "restart-winner".into(), 2));
    static_updates::recover(restarted.versioned().unwrap())
        .await
        .unwrap();
    assert_eq!(f.capture().await.2, 2);
    let row = f.provider().await;
    let marker = row
        .metadata
        .unwrap()
        .annotations
        .remove(static_updates::ANNOTATION)
        .unwrap();
    assert!(!marker.contains("restart-winner"));
}

#[tokio::test]
async fn static_update_concurrent_provider_cas_has_one_activation() {
    let f = Fixture::new().await;
    let version = f.provider().await.metadata.unwrap().resource_version;
    let reference = f.capture().await.0;
    let (left, right) = tokio::join!(
        f.update(Fixture::input("left", version)),
        f.update(Fixture::input("right", version))
    );
    assert_ne!(left.is_ok(), right.is_ok());
    let loser = if let Err(error) = left {
        error
    } else {
        right.unwrap_err()
    };
    assert_eq!(loser.code(), tonic::Code::Aborted);
    let (actual_reference, value, version) = f.capture().await;
    assert_eq!((actual_reference, version), (reference, 2));
    assert!(matches!(value.as_str(), "left" | "right"));
}

#[tokio::test]
async fn static_update_losing_unpublished_marker_cannot_replace_winner() {
    let f = Fixture::new().await;
    let provider = f.provider().await;
    let staged = prepare_provider_credential_update(
        Some(&f.credentials),
        provider.object_name(),
        "default",
        provider.object_id(),
        &HashMap::from([("TOKEN".into(), "abandoned".into())]),
        &provider.credential_handles,
    )
    .await
    .unwrap();
    let mut unpublished = provider;
    unpublished
        .credential_handles
        .extend(staged.published_handles);
    unpublished.metadata.as_mut().unwrap().annotations.insert(
        static_updates::ANNOTATION.into(),
        staged.static_marker.unwrap(),
    );
    f.update(Fixture::input("winner", 0)).await.unwrap();
    assert_eq!(
        static_updates::finish(f.versioned(), &unpublished)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    assert_eq!(f.capture().await.1, "winner");
    let projection =
        ReferenceProjection::from_handle(&f.provider().await.credential_handles["TOKEN"])
            .unwrap()
            .unwrap();
    assert_eq!(projection.epoch, "static");
}

#[tokio::test]
async fn static_update_multiple_keys_preserve_versions_and_retire_only_staged_aliases() {
    let f = Fixture::new().await;
    let mut input = Fixture::input("same", 0);
    input.credentials.insert("SECOND".into(), "second".into());
    f.update(input.clone()).await.unwrap();
    let before = f.provider().await;
    let owner = SecretOwner::provider("default", before.object_id(), before.object_name());
    let first = f
        .versioned()
        .references
        .resolve(owner, &before.credential_handles)
        .await
        .unwrap();
    let identities: HashMap<_, _> = first
        .into_iter()
        .map(|secret| (secret.credential_key, (secret.reference, secret.version)))
        .collect();
    assert_eq!(identities["TOKEN"].1, 2);
    assert_eq!(identities["SECOND"].1, 1);
    f.update(input).await.unwrap();
    let after = f.provider().await;
    assert_eq!(before.credential_handles, after.credential_handles);
    let second = f
        .versioned()
        .references
        .resolve(owner, &after.credential_handles)
        .await
        .unwrap();
    for secret in second {
        assert_eq!(secret.reference, identities[&secret.credential_key].0);
        assert_eq!(secret.version, identities[&secret.credential_key].1 + 1);
    }
}

struct LostActivationReply {
    inner: crate::versioned_credentials::ServerReferenceStateStore,
    armed: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl openshell_credential_issuer::references::ReferenceStateStore for LostActivationReply {
    async fn get_retention(
        &self,
        id: &str,
    ) -> Result<Option<openshell_credential_issuer::references::ReferenceRecord>, Status> {
        openshell_credential_issuer::references::ReferenceStateStore::get_retention(&self.inner, id)
            .await
    }

    async fn put_retention(&self, id: &str, payload: Vec<u8>) -> Result<(), Status> {
        openshell_credential_issuer::references::ReferenceStateStore::put_retention(
            &self.inner,
            id,
            payload,
        )
        .await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<openshell_credential_issuer::references::ReferenceRecord>, Status> {
        openshell_credential_issuer::references::ReferenceStateStore::get(&self.inner, id).await
    }

    async fn put(&self, id: &str, expected: Option<u64>, payload: Vec<u8>) -> Result<(), Status> {
        openshell_credential_issuer::references::ReferenceStateStore::put(
            &self.inner,
            id,
            expected,
            payload,
        )
        .await?;
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(Status::unavailable(
                "injected lost committed activation reply",
            ));
        }
        Ok(())
    }
}

#[tokio::test]
async fn static_update_lost_activation_response_replays_without_another_version() {
    let f = Fixture::new().await;
    let pending = f.publish_pending("committed-once").await;
    let references = openshell_credential_issuer::references::ReferenceRuntime::new(
        "embedded-v1",
        Arc::clone(&f.versioned().backend),
        Arc::new(LostActivationReply {
            inner: crate::versioned_credentials::ServerReferenceStateStore(Arc::clone(&f.store)),
            armed: std::sync::atomic::AtomicBool::new(true),
        }),
    )
    .unwrap();
    let versioned = VersionedCredentials {
        references: Arc::new(references),
        backend: Arc::clone(&f.versioned().backend),
        store: Arc::clone(&f.store),
    };
    assert_eq!(
        static_updates::finish(&versioned, &pending)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    static_updates::validate(&versioned, &pending)
        .await
        .unwrap();
    assert_eq!(
        (f.capture().await.1, f.capture().await.2),
        ("committed-once".into(), 2)
    );
    static_updates::finish(&versioned, &pending).await.unwrap();
    assert_eq!(f.capture().await.2, 2);
    let mut changed = pending;
    let annotations = &mut changed.metadata.as_mut().unwrap().annotations;
    let mut marker: serde_json::Value =
        serde_json::from_str(&annotations[static_updates::ANNOTATION]).unwrap();
    marker["replacements"][0]["expected_generation"] = 99.into();
    annotations.insert(
        static_updates::ANNOTATION.into(),
        serde_json::to_string(&marker).unwrap(),
    );
    assert_eq!(
        static_updates::validate(&versioned, &changed)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::AlreadyExists
    );
}

#[tokio::test]
async fn configure_refresh_settles_interrupted_static_publication_before_rebinding() {
    use openshell_credential_issuer::refresh::RefreshState;
    let f = Fixture::new().await;
    // This is also the durable state after an unknown successful provider write:
    // the caller did not observe activation, but the exact marker was installed.
    let pending = f.publish_pending("accepted-static-update").await;
    assert!(
        static_updates::validate(f.versioned(), &pending)
            .await
            .is_err()
    );
    let configured = f
        .versioned()
        .configure(
            &pending,
            RefreshState {
                metadata: Some(ObjectMeta {
                    id: uuid::Uuid::new_v4().to_string(),
                    name: "grant-TOKEN".into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                provider_id: pending.object_id().into(),
                provider_name: pending.object_name().into(),
                credential_key: "TOKEN".into(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                strategy_name: Some("oauth2_client_credentials".into()),
                authorization_epoch: uuid::Uuid::new_v4().to_string(),
                status: "configured".into(),
                ..Default::default()
            },
            "openshell-driver-db-credstore",
            None,
            (),
        )
        .await
        .unwrap();
    let current = f.provider().await;
    static_updates::validate(f.versioned(), &current)
        .await
        .unwrap();
    f.versioned()
        .validate_provider_grants(&current)
        .await
        .unwrap();
    let owner = SecretOwner::provider("default", current.object_id(), current.object_name());
    let values = f
        .versioned()
        .references
        .resolve(owner, &configured.output_references)
        .await
        .unwrap();
    assert_eq!(values[0].value, "accepted-static-update");
    static_updates::recover(f.versioned()).await.unwrap();
    let restarted = CredentialRuntime::from_config_file_with_store(
        &f.config,
        Some(&f.file),
        Arc::clone(&f.store),
    )
    .await
    .unwrap();
    let resolved = restarted
        .resolve_provider_handles(&current, crate::persistence::current_time_ms())
        .await
        .unwrap();
    assert_eq!(resolved.values["TOKEN"], "accepted-static-update");
}

#[tokio::test]
async fn interrupted_delete_settles_static_publication_before_revocation_and_restart() {
    let f = Fixture::new().await;
    let pending = f.publish_pending("accepted-before-delete").await;
    let database = format!(
        "sqlite://{}",
        f.directory.path().join("state.sqlite").display()
    );
    let pool = sqlx::SqlitePool::connect(&database).await.unwrap();
    sqlx::query("CREATE TRIGGER stop_provider_delete BEFORE DELETE ON objects WHEN OLD.object_type = 'provider' BEGIN SELECT RAISE(FAIL, 'injected provider deletion interruption'); END")
        .execute(&pool).await.unwrap();
    let refresh = crate::provider_refresh::runtime(&f.store, Some(&f.credentials), None);
    assert!(
        delete_provider_record_with_credentials(
            &f.store,
            &refresh,
            "default",
            &f.credentials,
            "static-provider",
        )
        .await
        .is_err()
    );
    assert!(
        f.store
            .get_message::<Provider>(pending.object_id())
            .await
            .unwrap()
            .is_some()
    );
    // The accepted update was finalized before deletion revoked its destination.
    // Recovery must not attempt to reactivate into that revoked reference.
    static_updates::validate(f.versioned(), &pending)
        .await
        .unwrap();
    let restarted = CredentialRuntime::from_config_file_with_store(
        &f.config,
        Some(&f.file),
        Arc::clone(&f.store),
    )
    .await
    .unwrap();
    static_updates::recover(restarted.versioned().unwrap())
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER stop_provider_delete")
        .execute(&pool)
        .await
        .unwrap();
    let refresh = crate::provider_refresh::runtime(&f.store, Some(&restarted), None);
    assert!(
        delete_provider_record_with_credentials(
            &f.store,
            &refresh,
            "default",
            &restarted,
            "static-provider",
        )
        .await
        .unwrap()
    );
    assert!(
        f.store
            .get_message::<Provider>(pending.object_id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        restarted
            .resolve_provider_handles(&pending, crate::persistence::current_time_ms())
            .await
            .unwrap()
            .values
            .is_empty()
    );
    pool.close().await;
}
