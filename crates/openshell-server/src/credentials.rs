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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedProviderCredentials {
    pub values: HashMap<String, String>,
    pub expires_at_ms: HashMap<String, i64>,
    /// Expired keys remain visible as omission evidence, never as secret values.
    pub expired_keys: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct CredentialRuntime {
    issuer: Arc<dyn CredentialIssuer>,
    // The same allocation as `issuer`, not a second backend. Other issuer
    // implementations need no embedded failure-injection or gate methods.
    #[cfg(test)]
    embedded_test_issuer: Option<Arc<EmbeddedCredentialIssuer>>,
}

impl CredentialRuntime {
    fn from_embedded(issuer: EmbeddedCredentialIssuer) -> Self {
        let issuer = Arc::new(issuer);
        Self {
            #[cfg(test)]
            embedded_test_issuer: Some(Arc::clone(&issuer)),
            issuer,
        }
    }

    /// Browser session tokens stay behind the configured credential issuer;
    /// session metadata stores only their opaque credential handles.
    pub async fn store_application_token(
        &self,
        workspace: &str,
        id: &str,
        token: &str,
    ) -> Result<CredentialHandle, Status> {
        let storage_id = format!("service-session-{id}");
        let mut handles = self
            .store_secrets_with_object_id(
                SecretOwner::application_session(workspace, &storage_id),
                &storage_id,
                &HashMap::from([("gateway-access-token".into(), token.into())]),
                &Handles::new(),
            )
            .await?;
        handles
            .remove("gateway-access-token")
            .ok_or_else(|| Status::internal("application credential handle missing"))
    }

    pub async fn resolve_application_token(
        &self,
        workspace: &str,
        id: &str,
        handle: CredentialHandle,
    ) -> Result<String, Status> {
        let storage_id = format!("service-session-{id}");
        let values = self
            .issuer
            .resolve(
                SecretOwner::application_session(workspace, &storage_id),
                &Handles::from([("gateway-access-token".into(), handle)]),
            )
            .await?;
        if values.len() != 1
            || values[0].credential_key != "gateway-access-token"
            || values[0].value.is_empty()
        {
            return Err(Status::unauthenticated(
                "application credential unavailable",
            ));
        }
        if let Some(expires) = &values[0].expiration_time
            && openshell_core::time::timestamp_to_millis(expires)
                .map_err(|_| Status::unavailable("invalid application credential expiration"))?
                <= openshell_core::time::now_ms()
        {
            return Err(Status::unauthenticated("expired application credential"));
        }
        Ok(values.into_iter().next().unwrap().value)
    }

    pub async fn delete_application_token(
        &self,
        workspace: &str,
        id: &str,
        handle: CredentialHandle,
    ) -> Result<(), Status> {
        let storage_id = format!("service-session-{id}");
        self.delete_secrets(
            SecretOwner::application_session(workspace, &storage_id),
            &Handles::from([("gateway-access-token".into(), handle)]),
        )
        .await
    }

    pub fn from_config(config: &Config) -> CoreResult<Self> {
        Ok(Self::from_embedded(EmbeddedCredentialIssuer::from_config(
            &IssuerConfig::from(config),
        )?))
    }

    pub fn from_config_with_store(config: &Config, store: Arc<Store>) -> CoreResult<Self> {
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
        let store = store.map(|store| {
            let adapter: Arc<dyn openshell_credential_issuer::persistence::DbCredstoreObjectStore> =
                Arc::new(ServerDbCredstoreObjectStore::new(store));
            adapter
        });
        Ok(Self::from_embedded(
            EmbeddedCredentialIssuer::from_options(&options, store).await?,
        ))
    }

    pub(crate) fn issuer(&self) -> Arc<dyn CredentialIssuer> {
        Arc::clone(&self.issuer)
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
