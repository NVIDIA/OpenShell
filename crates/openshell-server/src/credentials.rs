// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway adaptation of the embedded issuer. Provider expiration and private
//! storage records stay here; backend selection and all secret I/O do not.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use openshell_core::extension_protocol::NegotiatedExtension;
use openshell_core::proto::{CredentialHandle, Provider};
use openshell_core::{Config, Result as CoreResult};
pub use openshell_credential_issuer::RefreshMaterialScope;
use openshell_credential_issuer::{
    CredentialIssuer, EmbeddedCredentialIssuer, Handles, IssuerConfig, RefreshMaterialDeletion,
    ResolvedSecret, SecretOwner, StoreSecrets,
};
use tonic::Status;

use crate::credential_store::ServerDbCredstoreObjectStore;
use crate::persistence::Store;
use crate::storage_proto::StoredRefreshMaterialDeletion;

/// Non-secret identity of the exact committed value used by one build.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedCredentialVersion {
    pub reference: String,
    pub version: u64,
    pub authorization_epoch: String,
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct ResolvedProviderCredentials {
    pub versions: HashMap<String, ResolvedCredentialVersion>,
    pub values: HashMap<String, String>,
    pub expires_at_ms: HashMap<String, i64>,
    /// Expired keys remain visible as omission evidence, never as secret values.
    pub expired_keys: HashSet<String>,
}

impl std::fmt::Debug for ResolvedProviderCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolvedProviderCredentials")
            .field("versions", &self.versions)
            .field("credential_keys", &self.values.keys())
            .field("expires_at_ms", &self.expires_at_ms)
            .field("expired_keys", &self.expired_keys)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct CredentialRuntime {
    issuer: Arc<dyn CredentialIssuer>,
    storage_driver: String,
    versioned: Option<Arc<crate::versioned_credentials::VersionedCredentials>>,
    intent_key_path: Option<std::path::PathBuf>,
    // The same allocation as `issuer`, not a second backend. Other issuer
    // implementations need no embedded failure-injection or gate methods.
    #[cfg(test)]
    embedded_test_issuer: Option<Arc<EmbeddedCredentialIssuer>>,
}

impl CredentialRuntime {
    fn from_embedded(issuer: EmbeddedCredentialIssuer) -> Self {
        let storage_driver = issuer.storage_driver_name();
        let issuer = Arc::new(issuer);
        Self {
            storage_driver,
            versioned: None,
            intent_key_path: None,
            #[cfg(test)]
            embedded_test_issuer: Some(Arc::clone(&issuer)),
            issuer,
        }
    }

    pub fn from_config(config: &Config) -> CoreResult<Self> {
        if config.enable_versioned_credentials {
            return Err(openshell_core::Error::config(
                "versioned credentials require asynchronous activation with a durable store",
            ));
        }
        Ok(Self::from_embedded(EmbeddedCredentialIssuer::from_config(
            &IssuerConfig::from(config),
        )?))
    }

    pub fn from_config_with_store(config: &Config, store: Arc<Store>) -> CoreResult<Self> {
        if config.enable_versioned_credentials {
            return Err(openshell_core::Error::config(
                "versioned credentials require asynchronous activation before serving",
            ));
        }
        Ok(Self::from_embedded(
            EmbeddedCredentialIssuer::from_config_with_store(
                &IssuerConfig::from(config),
                Arc::new(ServerDbCredstoreObjectStore::new(store)),
            )?,
        ))
    }

    pub async fn from_config_file(
        config: &Config,
        config_file: Option<&crate::config_file::ConfigFile>,
    ) -> CoreResult<Self> {
        Self::from_config_file_with_optional_store(config, config_file, None).await
    }

    pub async fn from_config_file_with_store(
        config: &Config,
        config_file: Option<&crate::config_file::ConfigFile>,
        store: Arc<Store>,
    ) -> CoreResult<Self> {
        Self::from_config_file_with_optional_store(config, config_file, Some(store)).await
    }

    async fn from_config_file_with_optional_store(
        config: &Config,
        config_file: Option<&crate::config_file::ConfigFile>,
        store: Option<Arc<Store>>,
    ) -> CoreResult<Self> {
        let mut options = IssuerConfig::from(config);
        if let Some(file) = config_file {
            options.credential_storage = file
                .openshell
                .gateway
                .credential_storage
                .clone()
                .unwrap_or_default();
            options
                .driver_configs
                .clone_from(&file.openshell.credential_drivers);
        }
        let adapter = store.as_ref().map(|store| {
            let adapter: Arc<dyn openshell_credential_issuer::persistence::DbCredstoreObjectStore> =
                Arc::new(ServerDbCredstoreObjectStore::new(Arc::clone(store)));
            adapter
        });
        let mut runtime =
            Self::from_embedded(EmbeddedCredentialIssuer::from_options(&options, adapter).await?);
        runtime.intent_key_path = config
            .gateway_jwt
            .as_ref()
            .map(|jwt| jwt.signing_key_path.clone())
            .or_else(|| config.tls.as_ref().map(|tls| tls.key_path.clone()));
        if config.enable_versioned_credentials {
            // Validate before begin() can create a marker or migrate any binding.
            // Use exactly the same key selection/loading as future static writes;
            // do not fall back to another key when the selected one is unusable.
            let path = runtime.intent_key_path.as_deref().ok_or_else(|| {
                openshell_core::Error::config(
                    "versioned credential activation requires readable, stable gateway JWT or TLS private key material",
                )
            })?;
            crate::grpc::mutation_replay::validate_credential_write_key(path)
                .await
                .map_err(|error| openshell_core::Error::config(error.message()))?;
            openshell_credential_issuer::references::backend_recovery::validate_activation(
                &options,
                runtime.negotiated_extensions(),
            )
            .map_err(|error| openshell_core::Error::config(error.message()))?;
        }
        if let Some(store) = store {
            let mut activation = crate::credential_activation::begin(
                Arc::clone(&store),
                config.enable_versioned_credentials,
            )
            .await
            .map_err(|error| openshell_core::Error::config(error.message()))?;
            if let Some(activation) = activation.as_mut() {
                let versioned = crate::versioned_credentials::VersionedCredentials::new(
                    store,
                    runtime.issuer(),
                )
                .map_err(|error| openshell_core::Error::config(error.message()))?;
                crate::versioned_credentials::migrate(&runtime, &versioned, activation)
                    .await
                    .map_err(|error| openshell_core::Error::config(error.message()))?;
                activation
                    .finish()
                    .await
                    .map_err(|error| openshell_core::Error::config(error.message()))?;
                runtime.versioned = Some(versioned);
            }
        } else if config.enable_versioned_credentials {
            return Err(openshell_core::Error::config(
                "versioned credentials require durable issuer persistence",
            ));
        }
        Ok(runtime)
    }

    pub fn is_versioned(&self) -> bool {
        self.versioned.is_some()
    }

    pub(crate) fn versioned(
        &self,
    ) -> Option<&Arc<crate::versioned_credentials::VersionedCredentials>> {
        self.versioned.as_ref()
    }

    pub(crate) fn storage_driver_name(&self) -> &str {
        &self.storage_driver
    }

    pub(crate) fn issuer(&self) -> Arc<dyn CredentialIssuer> {
        Arc::clone(&self.issuer)
    }

    /// Revalidate authorization only, not value generations. The capture keeps
    /// its old coherent values/versions across an ordinary later refresh.
    pub(crate) async fn validate_provider_capture(
        &self,
        provider: &Provider,
        capture: &ResolvedProviderCredentials,
    ) -> Result<(), Status> {
        let Some(versioned) = &self.versioned else {
            return Ok(());
        };
        let metadata = provider
            .metadata
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("provider identity is required"))?;
        let owner = SecretOwner::provider(&metadata.workspace, &metadata.id, &metadata.name);
        let mut handles = Handles::new();
        for (key, version) in &capture.versions {
            let handle = provider
                .credential_handles
                .get(key)
                .ok_or_else(|| Status::aborted("captured credential binding changed"))?;
            let projection =
                openshell_credential_issuer::references::ReferenceProjection::from_handle(handle)?
                    .ok_or_else(|| {
                        Status::aborted("captured credential binding is not versioned")
                    })?;
            if projection.reference_id != version.reference
                || projection.epoch != version.authorization_epoch
            {
                return Err(Status::aborted("captured credential authorization changed"));
            }
            handles.insert(key.clone(), handle.clone());
        }
        if !versioned
            .references
            .validate_bindings(owner, &handles)
            .await?
        {
            return Err(Status::aborted(
                "captured credential authorization was revoked",
            ));
        }
        Ok(())
    }

    pub fn validate_provider_handles(&self, provider: &Provider) -> Result<(), Status> {
        self.issuer.validate_handles(&provider.credential_handles)
    }

    pub fn stores_provider_credentials(&self) -> bool {
        self.issuer.stores_provider_credentials()
    }
    pub fn storage_owns_handle(&self, handle: &CredentialHandle) -> bool {
        self.issuer.storage_owns_handle(handle)
    }
    pub fn negotiated_extensions(&self) -> &[NegotiatedExtension] {
        self.issuer.negotiated_extensions()
    }

    pub async fn store_provider_credentials(
        &self,
        provider_name: &str,
        workspace: &str,
        provider_id: &str,
        credentials: &HashMap<String, String>,
        existing_handles: &Handles,
    ) -> Result<Handles, Status> {
        self.store_provider_credentials_with_object_id(
            provider_name,
            workspace,
            provider_id,
            provider_id,
            credentials,
            existing_handles,
        )
        .await
    }

    pub async fn store_provider_credentials_with_object_id(
        &self,
        provider_name: &str,
        workspace: &str,
        provider_id: &str,
        object_id: &str,
        credentials: &HashMap<String, String>,
        existing_handles: &Handles,
    ) -> Result<Handles, Status> {
        self.store_secrets_with_object_id(
            SecretOwner::provider(workspace, provider_id, provider_name),
            object_id,
            credentials,
            existing_handles,
        )
        .await
    }

    pub async fn store_secrets_with_object_id(
        &self,
        owner: SecretOwner<'_>,
        object_id: &str,
        values: &HashMap<String, String>,
        existing_handles: &Handles,
    ) -> Result<Handles, Status> {
        if let Some(versioned) = &self.versioned {
            let path = self.intent_key_path.as_deref().ok_or_else(|| {
                Status::failed_precondition(
                    "versioned credential writes require stable gateway JWT or TLS key material",
                )
            })?;
            let intent = serde_json::json!({
                "domain": "openshell/issuer-static-write/v1", "owner": openshell_credential_issuer::references::OwnerIdentity::of(owner),
                "write_id": object_id, "values": values,
            });
            let protected =
                crate::grpc::mutation_replay::protect_credential_write(path, &intent).await?;
            return Box::pin(versioned.references.store(
                openshell_credential_issuer::references::StoreReferenceSecrets {
                    owner,
                    epoch: "static",
                    write_id: object_id,
                    protected_intent: &protected,
                    values,
                    existing_handles,
                    expiration_time: None,
                },
            ))
            .await;
        }
        self.issuer
            .store(StoreSecrets {
                owner,
                object_id: Some(object_id),
                values,
                existing_handles,
            })
            .await
    }

    pub async fn delete_provider_credential_handles(
        &self,
        provider_name: &str,
        workspace: &str,
        provider_id: &str,
        handles: &Handles,
    ) -> Result<(), Status> {
        self.delete_secrets(
            SecretOwner::provider(workspace, provider_id, provider_name),
            handles,
        )
        .await
    }

    pub async fn delete_secrets(
        &self,
        owner: SecretOwner<'_>,
        handles: &Handles,
    ) -> Result<(), Status> {
        if let Some(versioned) = &self.versioned {
            versioned.references.delete(owner, handles).await?;
            if let Err(error) = versioned.references.reclaim(owner, 16).await {
                tracing::warn!(code = ?error.code(), "issuer credential cleanup deferred");
            }
            return Ok(());
        }
        self.issuer.delete(owner, handles).await
    }

    pub async fn resolve_provider_handles(
        &self,
        provider: &Provider,
        now_ms: i64,
    ) -> Result<ResolvedProviderCredentials, Status> {
        let metadata = provider.metadata.as_ref();
        let owner = SecretOwner::provider(
            metadata.map_or("", |meta| meta.workspace.as_str()),
            metadata.map_or("", |meta| meta.id.as_str()),
            metadata.map_or("", |meta| meta.name.as_str()),
        );
        if let Some(versioned) = &self.versioned {
            Box::pin(versioned.validate_provider_grants(provider)).await?;
            return Box::pin(resolve_versioned(
                versioned,
                owner,
                &provider.credential_handles,
                &provider.credential_expiration_times,
                now_ms,
            ))
            .await;
        }
        let secrets = self
            .issuer
            .resolve(owner, &provider.credential_handles)
            .await?;
        apply_expiration(
            owner,
            secrets,
            &provider.credential_expiration_times,
            now_ms,
        )
    }

    /// Internal owners have no provider-level expiration. Preserve callers'
    /// existing cutoff (zero for SSH identity and launch material).
    pub async fn resolve_secrets(
        &self,
        owner: SecretOwner<'_>,
        handles: &Handles,
        now_ms: i64,
    ) -> Result<ResolvedProviderCredentials, Status> {
        if let Some(versioned) = &self.versioned {
            return resolve_versioned(versioned, owner, handles, &HashMap::new(), now_ms).await;
        }
        let secrets = self.issuer.resolve(owner, handles).await?;
        apply_expiration(owner, secrets, &HashMap::new(), now_ms)
    }

    pub async fn store_refresh_material_with_object_id(
        &self,
        scope: RefreshMaterialScope<'_>,
        object_id: &str,
        material: &HashMap<String, String>,
        existing_handles: &Handles,
    ) -> Result<Handles, Status> {
        self.issuer
            .store_refresh_material_with_object_id(scope, object_id, material, existing_handles)
            .await
    }

    pub async fn resolve_refresh_material(
        &self,
        scope: RefreshMaterialScope<'_>,
        handles: &Handles,
    ) -> Result<HashMap<String, String>, Status> {
        self.issuer.resolve_refresh_material(scope, handles).await
    }

    pub async fn delete_refresh_material_handles(
        &self,
        scope: RefreshMaterialScope<'_>,
        handles: &Handles,
    ) -> Result<(), Status> {
        self.issuer
            .delete_refresh_material_handles(scope, handles)
            .await
    }

    pub async fn delete_refresh_material_deletions(
        &self,
        scope: RefreshMaterialScope<'_>,
        deletions: &[StoredRefreshMaterialDeletion],
    ) -> Result<(), Status> {
        let deletions: Vec<_> = deletions
            .iter()
            .map(|deletion| RefreshMaterialDeletion {
                material_key: deletion.material_key.clone(),
                handle: deletion.handle.clone(),
            })
            .collect();
        self.issuer
            .delete_refresh_material_deletions(scope, &deletions)
            .await
    }

    #[cfg(test)]
    fn embedded_test_issuer(&self) -> &EmbeddedCredentialIssuer {
        self.embedded_test_issuer
            .as_deref()
            .expect("test credential hooks require an embedded issuer")
    }

    #[cfg(test)]
    pub(crate) fn stored_credential_count(&self) -> Option<usize> {
        self.embedded_test_issuer().stored_credential_count()
    }
    #[cfg(test)]
    pub(crate) fn fail_next_store(&self) {
        self.embedded_test_issuer().fail_next_store();
    }
    #[cfg(test)]
    pub(crate) fn fail_next_delete(&self) {
        self.embedded_test_issuer().fail_next_delete();
    }
    #[cfg(test)]
    pub(crate) fn gate_next_store(&self) -> openshell_credential_issuer::TestGate {
        self.embedded_test_issuer().gate_next_store()
    }
    #[cfg(test)]
    pub(crate) fn gate_next_resolve(&self) -> openshell_credential_issuer::TestGate {
        self.embedded_test_issuer().gate_next_resolve()
    }
}

async fn resolve_versioned(
    versioned: &crate::versioned_credentials::VersionedCredentials,
    owner: SecretOwner<'_>,
    handles: &Handles,
    provider_expirations: &HashMap<String, prost_types::Timestamp>,
    now_ms: i64,
) -> Result<ResolvedProviderCredentials, Status> {
    use openshell_credential_issuer::references::ReferenceProjection;
    let mut bundles: std::collections::BTreeMap<String, Handles> =
        std::collections::BTreeMap::new();
    for (key, handle) in handles {
        let projection = ReferenceProjection::from_handle(handle)?.ok_or_else(|| {
            Status::failed_precondition("legacy credential binding remains after issuer activation")
        })?;
        bundles
            .entry(projection.manifest_id)
            .or_default()
            .insert(key.clone(), handle.clone());
    }
    let now = openshell_core::time::timestamp_from_millis(now_ms)
        .map_err(|_| Status::internal("invalid credential resolution time"))?;
    let mut result = ResolvedProviderCredentials::default();
    for bundle in bundles.into_values() {
        let secrets = match versioned.references.resolve_at(owner, &bundle, now).await {
            Ok(secrets) => secrets,
            Err(error)
                if error.code() == tonic::Code::FailedPrecondition
                    && (error.message() == "issuer reference is expired"
                        || error.message() == "issuer reference is pending or revoked") =>
            {
                result.expired_keys.extend(bundle.into_keys());
                continue;
            }
            Err(error) => return Err(error),
        };
        let mut raw = Vec::with_capacity(secrets.len());
        for secret in secrets {
            result.versions.insert(
                secret.credential_key.clone(),
                ResolvedCredentialVersion {
                    reference: secret.reference.reference_id,
                    version: secret.version,
                    authorization_epoch: secret.reference.epoch,
                },
            );
            raw.push(ResolvedSecret {
                credential_key: secret.credential_key,
                value: secret.value,
                expiration_time: secret.expiration_time,
            });
        }
        let applied = apply_expiration(owner, raw, provider_expirations, now_ms)?;
        result.values.extend(applied.values);
        result.expires_at_ms.extend(applied.expires_at_ms);
        result.expired_keys.extend(applied.expired_keys);
    }
    Ok(result)
}

fn apply_expiration(
    owner: SecretOwner<'_>,
    secrets: Vec<ResolvedSecret>,
    provider_expirations: &HashMap<String, prost_types::Timestamp>,
    now_ms: i64,
) -> Result<ResolvedProviderCredentials, Status> {
    let mut resolved = ResolvedProviderCredentials::default();
    for secret in secrets {
        let credential_key = secret.credential_key;
        let provider_expires_at_ms = provider_expirations
            .get(&credential_key)
            .map(openshell_core::time::timestamp_to_millis)
            .transpose()
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let driver_expires_at_ms = secret
            .expiration_time
            .as_ref()
            .map(openshell_core::time::timestamp_to_millis)
            .transpose()
            .map_err(|error| Status::internal(error.to_string()))?;
        if let Some(expiration) =
            effective_credential_expiration_ms(provider_expires_at_ms, driver_expires_at_ms)
        {
            if expiration <= now_ms {
                tracing::warn!(?owner, %credential_key, ?provider_expires_at_ms, ?driver_expires_at_ms, effective_expires_at_ms = expiration, "skipping expired handle-backed credential");
                resolved.expired_keys.insert(credential_key);
                continue;
            }
            resolved
                .expires_at_ms
                .insert(credential_key.clone(), expiration);
        }
        resolved.values.insert(credential_key, secret.value);
    }
    Ok(resolved)
}

fn effective_credential_expiration_ms(
    provider_expiration_ms: Option<i64>,
    driver_expiration_ms: Option<i64>,
) -> Option<i64> {
    match (provider_expiration_ms, driver_expiration_ms) {
        (Some(provider), Some(driver)) => Some(provider.min(driver)),
        (Some(provider), None) => Some(provider),
        (None, Some(driver)) => Some(driver),
        (None, None) => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::Config;
    use openshell_core::extension_protocol::ExtensionFamily;
    use std::path::Path;
    use tonic::Code;

    #[tokio::test]
    async fn activation_preflights_stable_key_before_marker_or_binding_changes() {
        let directory = tempfile::tempdir().unwrap();
        let file = config_file(&format!(
            "[openshell.gateway.credential_storage]\nkey_encryption_key_path = {}\n",
            toml_path(&directory.path().join("kek")),
        ));
        let store = Arc::new(crate::persistence::test_store().await);
        let original = Provider {
            metadata: Some(openshell_core::proto::ObjectMeta {
                id: "preflight-provider".into(),
                name: "preflight-provider".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            credentials: HashMap::from([("TOKEN".into(), "legacy-test-secret".into())]),
            ..Default::default()
        };
        store.put_message(&original).await.unwrap();
        let before = store
            .get("provider", "preflight-provider")
            .await
            .unwrap()
            .unwrap();
        let key = directory.path().join("intent-key");
        let mut config = Config::new(None);
        config.enable_versioned_credentials = true;
        for scenario in [
            "missing-config",
            "missing-file",
            "empty-file",
            "unreadable-file",
        ] {
            config.gateway_jwt = if scenario == "missing-config" {
                None
            } else {
                Some(openshell_core::config::GatewayJwtConfig {
                    signing_key_path: if scenario == "unreadable-file" {
                        directory.path().to_owned() // read on a directory fails even as root
                    } else {
                        key.clone()
                    },
                    public_key_path: directory.path().join("public"),
                    kid_path: directory.path().join("kid"),
                    gateway_id: "test".into(),
                    ttl_secs: None,
                })
            };
            if scenario == "empty-file" {
                std::fs::write(&key, []).unwrap();
            }
            let error = CredentialRuntime::from_config_file_with_store(
                &config,
                Some(&file),
                Arc::clone(&store),
            )
            .await
            .unwrap_err();
            assert!(
                error.to_string().contains("stable gateway JWT or TLS"),
                "{scenario}: {error}"
            );
            assert!(
                store
                    .get(
                        "credential_issuer_activation",
                        "embedded-credential-references-v1"
                    )
                    .await
                    .unwrap()
                    .is_none(),
                "{scenario} must not create a marker"
            );
            let after = store
                .get("provider", "preflight-provider")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(after.payload, before.payload, "{scenario}");
            assert_eq!(
                after.resource_version, before.resource_version,
                "{scenario}"
            );
            assert!(
                !crate::credential_activation::uses_reference_records(&store)
                    .await
                    .unwrap()
            );
            assert!(
                crate::credential_activation::begin(Arc::clone(&store), false)
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        // Once the selected key is usable, the same database can activate and
        // accept a new protected static write, not merely read migrated values.
        std::fs::write(&key, b"stable test-only private material").unwrap();
        config.tls = Some(openshell_core::config::TlsConfig {
            cert_path: directory.path().join("cert"),
            key_path: key,
            client_ca_path: None,
            require_client_auth: false,
            external_cert_path: None,
            external_key_path: None,
            external_server_names: Vec::new(),
        });
        // A usable TLS key must not mask an unusable preferred JWT key.
        assert!(
            CredentialRuntime::from_config_file_with_store(
                &config,
                Some(&file),
                Arc::clone(&store),
            )
            .await
            .is_err()
        );
        assert!(
            store
                .get(
                    "credential_issuer_activation",
                    "embedded-credential-references-v1"
                )
                .await
                .unwrap()
                .is_none()
        );
        config.gateway_jwt = None;
        let runtime = CredentialRuntime::from_config_file_with_store(
            &config,
            Some(&file),
            Arc::clone(&store),
        )
        .await
        .unwrap();
        assert!(runtime.is_versioned());
        let handles = runtime
            .store_provider_credentials(
                "new-provider",
                "default",
                "new-provider-id",
                &HashMap::from([("TOKEN".into(), "new-test-value".into())]),
                &Handles::new(),
            )
            .await
            .unwrap();
        assert!(!handles.is_empty());
    }

    #[test]
    fn resolved_credential_diagnostics_never_print_values() {
        let resolved = ResolvedProviderCredentials {
            values: HashMap::from([("TOKEN".into(), "private-captured-value".into())]),
            ..Default::default()
        };
        let diagnostic = format!("{resolved:?}");
        assert!(diagnostic.contains("TOKEN"));
        assert!(!diagnostic.contains("private-captured-value"));
    }

    fn provider_with_handle(driver: &str, handle: &str) -> Provider {
        Provider {
            metadata: Some(openshell_core::proto::ObjectMeta {
                name: "openai-local".to_string(),
                ..Default::default()
            }),
            credential_handles: HashMap::from([(
                "OPENAI_API_KEY".to_string(),
                CredentialHandle {
                    driver: driver.to_string(),
                    handle: handle.to_string(),
                    metadata: HashMap::new(),
                },
            )]),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn embedded_test_hooks_share_the_trait_backed_issuer_across_clones() {
        let runtime = CredentialRuntime::from_config(
            &Config::new(None).with_credential_drivers(["test-static"]),
        )
        .unwrap();
        let cloned = runtime.clone();
        let embedded: Arc<dyn CredentialIssuer> =
            runtime.embedded_test_issuer.as_ref().unwrap().clone();
        assert!(Arc::ptr_eq(&runtime.issuer, &embedded));
        assert!(Arc::ptr_eq(&cloned.issuer, &embedded));
        assert!(Arc::ptr_eq(
            runtime.embedded_test_issuer.as_ref().unwrap(),
            cloned.embedded_test_issuer.as_ref().unwrap(),
        ));

        assert_eq!(runtime.stored_credential_count(), Some(0));
        let values = HashMap::from([("TOKEN".to_string(), "test-value".to_string())]);
        let handles = cloned
            .store_provider_credentials(
                "provider",
                "workspace",
                "provider-id",
                &values,
                &Handles::new(),
            )
            .await
            .unwrap();
        assert_eq!(runtime.stored_credential_count(), Some(1));
        runtime
            .delete_provider_credential_handles("provider", "workspace", "provider-id", &handles)
            .await
            .unwrap();
        assert_eq!(cloned.stored_credential_count(), Some(0));
    }

    #[test]
    fn effective_expiration_preserves_timestamp_presence() {
        assert_eq!(effective_credential_expiration_ms(None, None), None);
        assert_eq!(effective_credential_expiration_ms(Some(0), None), Some(0));
        assert_eq!(effective_credential_expiration_ms(None, Some(0)), Some(0));
        assert_eq!(
            effective_credential_expiration_ms(Some(2_000), Some(1_000)),
            Some(1_000)
        );
    }

    #[test]
    fn facade_combines_expiration_and_preserves_omission_evidence() {
        let owner = SecretOwner::provider("workspace", "provider-id", "provider");
        for (provider, backend, now, expected) in [
            (None, None, 1_000, None),
            (Some(3_000), Some(2_000), 1_000, Some(2_000)),
            (Some(2_000), Some(3_000), 1_000, Some(2_000)),
            (Some(0), None, 1_000, Some(0)),
            (None, Some(0), 0, Some(0)),
        ] {
            let provider_expirations = provider
                .map(|ms| {
                    HashMap::from([(
                        "TOKEN".to_string(),
                        openshell_core::time::timestamp_from_millis(ms).unwrap(),
                    )])
                })
                .unwrap_or_default();
            let secrets = vec![ResolvedSecret {
                credential_key: "TOKEN".to_string(),
                value: "test-value".to_string(),
                expiration_time: backend
                    .map(|ms| openshell_core::time::timestamp_from_millis(ms).unwrap()),
            }];
            let resolved = apply_expiration(owner, secrets, &provider_expirations, now).unwrap();
            let expired = expected.is_some_and(|expiration| expiration <= now);
            assert_eq!(resolved.expired_keys.contains("TOKEN"), expired);
            assert_eq!(resolved.values.contains_key("TOKEN"), !expired);
            assert_eq!(
                resolved.expires_at_ms.get("TOKEN").copied(),
                expected.filter(|_| !expired)
            );
        }
    }

    #[tokio::test]
    async fn persisted_legacy_internal_owners_survive_issuer_reconstruction() {
        let directory = tempfile::tempdir().unwrap();
        let path = toml_path(&directory.path().join("key-encryption-key.bin"));
        let file = config_file(&format!(
            "[openshell.gateway.credential_storage]\nkey_encryption_key_path = {path}\n"
        ));
        let config = Config::new(None);
        let store = Arc::new(crate::persistence::test_store().await);
        let runtime =
            CredentialRuntime::from_config_file_with_store(&config, Some(&file), store.clone())
                .await
                .unwrap();
        let mut persisted = Vec::new();
        // Seed the original driver scope through the old provider-shaped entry
        // point, then read it through typed owners in a fresh issuer instance.
        for (name, key) in [
            ("sandbox-ssh-sandbox-id", "SSH_HOST_PRIVATE_KEY"),
            ("sandbox-instance-sandbox-id", "LAUNCH_MATERIAL"),
        ] {
            let handles = runtime
                .store_provider_credentials_with_object_id(
                    name,
                    "workspace",
                    "sandbox-id",
                    "candidate-id",
                    &HashMap::from([(key.to_string(), "test-value".to_string())]),
                    &HashMap::new(),
                )
                .await
                .unwrap();
            persisted.push(handles);
        }
        drop(runtime);
        let runtime =
            CredentialRuntime::from_config_file_with_store(&config, Some(&file), store.clone())
                .await
                .unwrap();
        for (owner, handles) in [
            SecretOwner::sandbox("workspace", "sandbox-id"),
            SecretOwner::supervisor_instance("workspace", "sandbox-id"),
        ]
        .into_iter()
        .zip(persisted)
        {
            let resolved = runtime.resolve_secrets(owner, &handles, 0).await.unwrap();
            assert_eq!(resolved.values.len(), 1);
            assert!(resolved.values.values().all(|value| value == "test-value"));
            runtime.delete_secrets(owner, &handles).await.unwrap();
            for handle in handles.values() {
                assert!(
                    store
                        .get(
                            openshell_credential_issuer::persistence::OBJECT_TYPE,
                            handle.handle.strip_prefix("v1:").unwrap(),
                        )
                        .await
                        .unwrap()
                        .is_none()
                );
            }
        }
    }

    fn config_file(toml: &str) -> crate::config_file::ConfigFile {
        toml::from_str(toml).expect("config file TOML")
    }

    fn toml_path(path: &Path) -> String {
        toml::Value::String(path.display().to_string()).to_string()
    }

    #[test]
    fn built_in_credential_driver_uses_common_negotiation_snapshot() {
        let runtime = CredentialRuntime::from_config(
            &Config::new(None).with_credential_drivers(["test-static"]),
        )
        .unwrap();

        let negotiated = runtime.negotiated_extensions();
        assert_eq!(negotiated.len(), 1);
        assert_eq!(negotiated[0].family, ExtensionFamily::Credentials);
        assert_eq!(negotiated[0].configured_name, "test-static");
        assert_eq!(
            negotiated[0].protocol_major,
            openshell_core::extension_protocol::PROTOCOL_MAJOR
        );
    }

    #[tokio::test]
    async fn runtime_stores_and_resolves_test_static_handles() {
        let config = Config::new(None)
            .with_credential_drivers(["test-static"])
            .with_default_credential_driver(Some("test-static"));
        let runtime = CredentialRuntime::from_config(&config).unwrap();
        let stored = runtime
            .store_provider_credentials(
                "openai-local",
                "test-workspace",
                "test-provider-id",
                &HashMap::from([("OPENAI_API_KEY".to_string(), "sk-test".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        let mut provider = Provider {
            metadata: Some(openshell_core::proto::ObjectMeta {
                name: "openai-local".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        provider.credential_handles = stored;

        let resolved = runtime
            .resolve_provider_handles(&provider, 1_000)
            .await
            .unwrap();

        assert_eq!(
            resolved.values.get("OPENAI_API_KEY").map(String::as_str),
            Some("sk-test")
        );

        provider.credential_expiration_times.insert(
            "OPENAI_API_KEY".to_string(),
            openshell_core::time::timestamp_from_millis(0).unwrap(),
        );
        let expired = runtime
            .resolve_provider_handles(&provider, 1_000)
            .await
            .unwrap();
        assert!(!expired.values.contains_key("OPENAI_API_KEY"));
    }

    #[tokio::test]
    async fn runtime_overwrites_existing_test_static_handle() {
        let config = Config::new(None).with_credential_drivers(["test-static"]);
        let runtime = CredentialRuntime::from_config(&config).unwrap();
        let first = runtime
            .store_provider_credentials(
                "openai-local",
                "test-workspace",
                "test-provider-id",
                &HashMap::from([("OPENAI_API_KEY".to_string(), "sk-first".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        let second = runtime
            .store_provider_credentials(
                "openai-local",
                "test-workspace",
                "test-provider-id",
                &HashMap::from([("OPENAI_API_KEY".to_string(), "sk-second".to_string())]),
                &first,
            )
            .await
            .unwrap();
        assert_eq!(
            first.get("OPENAI_API_KEY").unwrap().handle,
            second.get("OPENAI_API_KEY").unwrap().handle
        );

        let provider = Provider {
            metadata: Some(openshell_core::proto::ObjectMeta {
                name: "openai-local".to_string(),
                ..Default::default()
            }),
            credential_handles: second,
            ..Default::default()
        };

        let resolved = runtime
            .resolve_provider_handles(&provider, 1_000)
            .await
            .unwrap();

        assert_eq!(
            resolved.values.get("OPENAI_API_KEY").map(String::as_str),
            Some("sk-second")
        );
    }

    #[tokio::test]
    async fn runtime_deletes_stored_test_static_handle() {
        let config = Config::new(None).with_credential_drivers(["test-static"]);
        let runtime = CredentialRuntime::from_config(&config).unwrap();
        let stored = runtime
            .store_provider_credentials(
                "openai-local",
                "test-workspace",
                "test-provider-id",
                &HashMap::from([("OPENAI_API_KEY".to_string(), "sk-test".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();

        runtime
            .delete_provider_credential_handles(
                "openai-local",
                "test-workspace",
                "test-provider-id",
                &stored,
            )
            .await
            .unwrap();

        let provider = Provider {
            metadata: Some(openshell_core::proto::ObjectMeta {
                name: "openai-local".to_string(),
                ..Default::default()
            }),
            credential_handles: stored,
            ..Default::default()
        };
        let err = runtime
            .resolve_provider_handles(&provider, 1_000)
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn runtime_uses_configured_in_tree_driver_table() {
        let config = Config::new(None).with_credential_drivers(["test-static"]);
        let file = config_file(
            r#"
[openshell.credential_drivers.test-static]
transport = "in_tree"
backend_specific = "ignored-by-gateway"
"#,
        );
        let runtime = CredentialRuntime::from_config_file(&config, Some(&file))
            .await
            .unwrap();

        let stored = runtime
            .store_provider_credentials(
                "openai-local",
                "test-workspace",
                "test-provider-id",
                &HashMap::from([("OPENAI_API_KEY".to_string(), "sk-test".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();

        assert_eq!(
            stored
                .get("OPENAI_API_KEY")
                .map(|handle| handle.driver.as_str()),
            Some("test-static")
        );
    }

    #[tokio::test]
    async fn runtime_uses_configured_vault_in_tree_driver_table() {
        let token_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(token_file.path(), "dev-token").unwrap();
        let config = Config::new(None).with_credential_drivers(["vault"]);
        let token_path = toml_path(token_file.path());
        let file = config_file(&format!(
            r#"
[openshell.credential_drivers.vault]
transport = "in_tree"
address = "http://127.0.0.1:8200"
auth_method = "token_file"
token_path = {token_path}
"#,
        ));
        let runtime = CredentialRuntime::from_config_file(&config, Some(&file))
            .await
            .unwrap();

        assert!(runtime.stores_provider_credentials());
    }

    #[tokio::test]
    async fn runtime_uses_configured_default_credential_storage() {
        let storage = tempfile::tempdir().unwrap();
        let key_encryption_key_path = storage.path().join("key-encryption-key.bin");
        let store = Arc::new(crate::persistence::test_store().await);
        let config = Config::new(None);
        let key_encryption_key_path_toml = toml_path(&key_encryption_key_path);
        let file = config_file(&format!(
            r"
[openshell.gateway.credential_storage]
key_encryption_key_path = {key_encryption_key_path_toml}
",
        ));
        let runtime = CredentialRuntime::from_config_file_with_store(
            &config,
            Some(&file),
            Arc::clone(&store),
        )
        .await
        .unwrap();

        let stored = runtime
            .store_provider_credentials(
                "openai-local",
                "test-workspace",
                "test-provider-id",
                &HashMap::from([("OPENAI_API_KEY".to_string(), "sk-test".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();

        let handle_id = stored
            .get("OPENAI_API_KEY")
            .and_then(|handle| handle.handle.strip_prefix("v1:"))
            .expect("stored db credstore handle id");
        let credential_record = store
            .get(
                openshell_credential_issuer::persistence::OBJECT_TYPE,
                handle_id,
            )
            .await
            .unwrap()
            .expect("encrypted credential object");
        assert!(
            !String::from_utf8_lossy(&credential_record.payload).contains("sk-test"),
            "credential object payload must not contain plaintext credentials"
        );

        let provider = Provider {
            metadata: Some(openshell_core::proto::ObjectMeta {
                name: "openai-local".to_string(),
                ..Default::default()
            }),
            credential_handles: stored,
            ..Default::default()
        };

        let resolved = runtime
            .resolve_provider_handles(&provider, 1_000)
            .await
            .unwrap();

        assert_eq!(
            resolved.values.get("OPENAI_API_KEY").map(String::as_str),
            Some("sk-test")
        );
    }

    #[tokio::test]
    async fn runtime_rejects_in_tree_table_without_builtin_driver() {
        let config = Config::new(None).with_credential_drivers(["enterprise-secrets"]);
        let file = config_file(
            r#"
[openshell.credential_drivers.enterprise-secrets]
transport = "in_tree"
"#,
        );

        let err = CredentialRuntime::from_config_file(&config, Some(&file))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("no in-tree implementation"));
    }

    #[tokio::test]
    async fn runtime_rejects_unknown_driver_without_driver_table() {
        let config = Config::new(None).with_credential_drivers(["enterprise-secrets"]);

        let err = CredentialRuntime::from_config_file(&config, None)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("not a built-in credential driver"));
        assert!(err.to_string().contains("transport = 'uds'"));
    }

    #[test]
    fn runtime_from_config_rejects_unknown_driver_name() {
        let config = Config::new(None).with_credential_drivers(["enterprise-secrets"]);

        let err = CredentialRuntime::from_config(&config).unwrap_err();

        assert!(err.to_string().contains("not a built-in credential driver"));
    }

    #[tokio::test]
    async fn runtime_rejects_uds_table_without_socket_path() {
        let config = Config::new(None).with_credential_drivers(["vault"]);
        let file = config_file(
            r#"
[openshell.credential_drivers.vault]
transport = "uds"
"#,
        );

        let err = CredentialRuntime::from_config_file(&config, Some(&file))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("socket_path is required"));
    }

    #[tokio::test]
    async fn runtime_rejects_relative_uds_socket_path() {
        let config = Config::new(None).with_credential_drivers(["vault"]);
        let file = config_file(
            r#"
[openshell.credential_drivers.vault]
transport = "uds"
socket_path = "vault.sock"
"#,
        );

        let err = CredentialRuntime::from_config_file(&config, Some(&file))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("socket_path must be absolute"));
    }

    #[tokio::test]
    async fn runtime_rejects_unknown_transport() {
        let config = Config::new(None).with_credential_drivers(["vault"]);
        let file = config_file(
            r#"
[openshell.credential_drivers.vault]
transport = "tcp"
"#,
        );

        let err = CredentialRuntime::from_config_file(&config, Some(&file))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("transport must be"));
    }

    #[tokio::test]
    async fn runtime_rejects_unconnected_enabled_driver_on_resolution() {
        let config = Config::new(None).with_credential_drivers(["vault"]);
        let runtime = CredentialRuntime::from_config(&config).unwrap();

        let err = runtime
            .resolve_provider_handles(&provider_with_handle("vault", "v1:providers/openai"), 1_000)
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("not connected"));
    }
}
