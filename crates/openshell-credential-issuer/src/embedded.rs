// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Extracted credential-driver implementation.

use crate::refresh_material::refresh_material_storage_key;
use crate::{
    Handles, IssuerConfig, RefreshMaterialDeletion, RefreshMaterialScope, ResolvedSecret,
    SecretOwner, StoreSecrets,
};
use async_trait::async_trait;
use openshell_core::Result as CoreResult;
use openshell_core::extension_protocol::NegotiatedExtension;
use openshell_core::proto::CredentialHandle;
use openshell_core::proto::credentials::v1::{
    DeleteCredentialRequest, ResolveCredentialRequest, ResolvedCredential, StoreCredentialRequest,
};
use openshell_driver_db_credstore::{DbCredstoreCredentialDriver, DbCredstoreObjectStore};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use tonic::Status;
mod driver_config;
mod drivers;
#[cfg(any(test, feature = "test-support"))]
mod test_support;
mod transport;
use driver_config::{
    BuiltinCredentialDriverKind, CredentialDriverRegistry, build_configured_driver,
    build_default_in_tree_driver, build_sync_builtin_driver, connect_default_credential_store,
    negotiate_builtin_credential_driver, normalize_driver_name, parse_driver_table,
    unknown_credential_driver_error,
};
#[cfg(any(test, feature = "test-support"))]
use test_support::TestStaticCredentialDriver;
use transport::ManagedCredentialDriverProcess;

#[async_trait]
trait CredentialDriver: std::fmt::Debug + Send + Sync {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status>;

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status>;

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status>;

    #[cfg(any(test, feature = "test-support"))]
    fn stored_credential_count(&self) -> Option<usize> {
        None
    }

    #[cfg(any(test, feature = "test-support"))]
    fn fail_next_store(&self) {}

    #[cfg(any(test, feature = "test-support"))]
    fn fail_next_delete(&self) {}

    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    fn gate_next_resolve(
        &self,
    ) -> Option<(
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    )> {
        None
    }

    #[cfg(any(test, feature = "test-support"))]
    fn gate_next_store(
        &self,
    ) -> Option<(
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    )> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct EmbeddedCredentialIssuer {
    registry: CredentialDriverRegistry,
    drivers: BTreeMap<String, Arc<dyn CredentialDriver>>,
    _driver_processes: Vec<Arc<ManagedCredentialDriverProcess>>,
    negotiated_extensions: Vec<NegotiatedExtension>,
}

impl EmbeddedCredentialIssuer {
    pub fn from_config(config: &IssuerConfig) -> CoreResult<Self> {
        Self::from_config_with_optional_store(config, None)
    }

    pub fn from_config_with_store(
        config: &IssuerConfig,
        store: Arc<dyn DbCredstoreObjectStore>,
    ) -> CoreResult<Self> {
        Self::from_config_with_optional_store(config, Some(store))
    }

    fn from_config_with_optional_store(
        config: &IssuerConfig,
        store: Option<Arc<dyn DbCredstoreObjectStore>>,
    ) -> CoreResult<Self> {
        let registry = CredentialDriverRegistry::from_config(config)?;
        let mut drivers = BTreeMap::new();
        connect_default_credential_store(
            &mut drivers,
            store.clone(),
            &toml::Table::new(),
            registry.requires_default_store(),
        )?;

        for driver_name in registry.enabled_driver_names() {
            if let Some(driver) = build_sync_builtin_driver(driver_name, store.clone()) {
                drivers.insert(driver_name.clone(), driver);
            } else if BuiltinCredentialDriverKind::from_name(driver_name).is_none() {
                return Err(unknown_credential_driver_error(driver_name));
            }
        }

        let negotiated_extensions = drivers
            .keys()
            .map(|name| negotiate_builtin_credential_driver(name))
            .collect::<CoreResult<Vec<_>>>()?;
        Ok(Self {
            registry,
            drivers,
            _driver_processes: Vec::new(),
            negotiated_extensions,
        })
    }

    /// Construct configured backends using the caller's existing object store.
    pub async fn from_options(
        config: &IssuerConfig,
        store: Option<Arc<dyn DbCredstoreObjectStore>>,
    ) -> CoreResult<Self> {
        Self::from_config_file_with_optional_store(config, store).await
    }

    async fn from_config_file_with_optional_store(
        config: &IssuerConfig,
        store: Option<Arc<dyn DbCredstoreObjectStore>>,
    ) -> CoreResult<Self> {
        let registry = CredentialDriverRegistry::from_config(config)?;
        let mut drivers = BTreeMap::new();
        let mut driver_processes = Vec::new();
        let mut negotiated_extensions = Vec::new();
        let default_store_config = &config.credential_storage;
        connect_default_credential_store(
            &mut drivers,
            store.clone(),
            default_store_config,
            registry.requires_default_store(),
        )?;
        if drivers.contains_key(DbCredstoreCredentialDriver::NAME) {
            negotiated_extensions.push(negotiate_builtin_credential_driver(
                DbCredstoreCredentialDriver::NAME,
            )?);
        }

        for driver_name in registry.enabled_driver_names() {
            let driver_config = config
                .driver_configs
                .get(driver_name)
                .map(|value| parse_driver_table(driver_name, value))
                .transpose()?;

            if let Some(driver_config) = driver_config {
                let built =
                    build_configured_driver(driver_name, driver_config, store.clone()).await?;
                drivers.insert(driver_name.clone(), built.driver);
                negotiated_extensions.push(built.negotiated_extension);
                if let Some(process) = built.process {
                    driver_processes.push(process);
                }
            } else {
                let driver = build_default_in_tree_driver(driver_name, store.clone()).await?;
                drivers.insert(driver_name.clone(), driver);
                negotiated_extensions.push(negotiate_builtin_credential_driver(driver_name)?);
            }
        }

        Ok(Self {
            registry,
            drivers,
            _driver_processes: driver_processes,
            negotiated_extensions,
        })
    }

    pub fn validate_handles(&self, handles: &Handles) -> Result<(), Status> {
        self.registry.validate_handles(handles)
    }

    pub fn stores_provider_credentials(&self) -> bool {
        let driver_name = self.registry.storage_owner_name();
        self.drivers.contains_key(&driver_name)
    }

    #[must_use]
    pub fn negotiated_extensions(&self) -> &[NegotiatedExtension] {
        &self.negotiated_extensions
    }

    pub fn storage_owns_handle(&self, handle: &CredentialHandle) -> bool {
        normalize_driver_name(&handle.driver) == self.registry.storage_owner_name()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn stored_credential_count(&self) -> Option<usize> {
        self.drivers
            .get(&self.registry.storage_owner_name())
            .and_then(|driver| driver.stored_credential_count())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn fail_next_store(&self) {
        if let Some(driver) = self.drivers.get(&self.registry.storage_owner_name()) {
            driver.fail_next_store();
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn fail_next_delete(&self) {
        if let Some(driver) = self.drivers.get(&self.registry.storage_owner_name()) {
            driver.fail_next_delete();
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn gate_next_store(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.drivers
            .get(&self.registry.storage_owner_name())
            .and_then(|driver| driver.gate_next_store())
            .expect("test credential driver supports store gating")
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    pub fn gate_next_resolve(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.drivers
            .get(&self.registry.storage_owner_name())
            .and_then(|driver| driver.gate_next_resolve())
            .expect("test credential driver supports resolve gating")
    }

    pub async fn store(&self, request: StoreSecrets<'_>) -> Result<Handles, Status> {
        let StoreSecrets {
            owner,
            object_id,
            values: credentials,
            existing_handles,
        } = request;
        let scope = owner.legacy_scope();
        let provider_name = scope.provider.as_ref();
        let workspace = scope.workspace;
        let provider_id = scope.id;
        let object_id = object_id.unwrap_or(provider_id);
        if credentials.is_empty() {
            return Ok(HashMap::new());
        }
        let driver_name = self.registry.storage_owner_name();
        let driver = self.connected_driver(&driver_name)?;

        let futures = credentials.iter().map(|(credential_key, value)| {
            let driver_name = driver_name.clone();
            let driver = driver.clone();
            async move {
                let existing_handle = existing_handles
                    .get(credential_key)
                    .filter(|handle| normalize_driver_name(&handle.driver) == driver_name)
                    .cloned();
                let replaced_handle = existing_handles
                    .get(credential_key)
                    .filter(|handle| normalize_driver_name(&handle.driver) != driver_name)
                    .cloned();
                let mut handle = driver
                    .store_credential(StoreCredentialRequest {
                        provider: provider_name.to_string(),
                        credential_key: credential_key.clone(),
                        value: value.clone(),
                        existing_handle,
                        workspace: workspace.to_string(),
                        provider_id: provider_id.to_string(),
                        object_id: object_id.to_string(),
                    })
                    .await?;
                handle.driver.clone_from(&driver_name);
                if handle.handle.trim().is_empty() {
                    return Err(Status::internal(format!(
                        "credential driver '{driver_name}' returned an empty handle for provider credential '{credential_key}'"
                    )));
                }
                if let Some(replaced_handle) = replaced_handle {
                    self.delete_credential_handle(
                        owner,
                        credential_key,
                        replaced_handle,
                    )
                    .await?;
                }
                Ok::<_, Status>((credential_key.clone(), handle))
            }
        });
        let results = futures::future::join_all(futures).await;

        let mut successes = HashMap::new();
        let mut first_error: Option<Status> = None;
        for result in results {
            match result {
                Ok((key, handle)) => {
                    successes.insert(key, handle);
                }
                Err(err) if first_error.is_none() => {
                    first_error = Some(err);
                }
                Err(_) => {}
            }
        }

        if let Some(err) = first_error {
            if !successes.is_empty()
                && let Err(cleanup_err) = self.delete(owner, &successes).await
            {
                tracing::warn!(
                    provider_name = %provider_name,
                    error = %cleanup_err,
                    "failed to clean up partially stored credentials after error"
                );
            }
            return Err(err);
        }

        Ok(successes)
    }

    /// Store gateway-only refresh material through the active credential
    /// driver. Material names never become backend keys directly; a
    /// deterministic driver-safe key binds each slot to its injectable
    /// credential without exposing caller-controlled names in backend paths.
    pub async fn store_refresh_material_with_object_id(
        &self,
        scope: RefreshMaterialScope<'_>,
        object_id: &str,
        material: &HashMap<String, String>,
        existing_handles: &HashMap<String, CredentialHandle>,
    ) -> Result<HashMap<String, CredentialHandle>, Status> {
        let mut values_by_storage_key = HashMap::with_capacity(material.len());
        let mut handles_by_storage_key = HashMap::with_capacity(existing_handles.len());
        let mut material_by_storage_key = HashMap::with_capacity(material.len());

        for (material_key, value) in material {
            let storage_key = refresh_material_storage_key(scope.credential_key, material_key)?;
            material_by_storage_key.insert(storage_key.clone(), material_key.clone());
            values_by_storage_key.insert(storage_key, value.clone());
        }
        for (material_key, handle) in existing_handles {
            handles_by_storage_key.insert(
                refresh_material_storage_key(scope.credential_key, material_key)?,
                handle.clone(),
            );
        }

        let stored = self
            .store(StoreSecrets {
                owner: scope.owner(),
                object_id: Some(object_id),
                values: &values_by_storage_key,
                existing_handles: &handles_by_storage_key,
            })
            .await?;
        stored
            .into_iter()
            .map(|(storage_key, handle)| {
                material_by_storage_key
                    .remove(&storage_key)
                    .map(|material_key| (material_key, handle))
                    .ok_or_else(|| {
                        Status::internal(
                            "credential driver returned an unknown refresh material key",
                        )
                    })
            })
            .collect()
    }

    pub async fn resolve_refresh_material(
        &self,
        scope: RefreshMaterialScope<'_>,
        handles: &HashMap<String, CredentialHandle>,
    ) -> Result<HashMap<String, String>, Status> {
        if handles.is_empty() {
            return Ok(HashMap::new());
        }
        let mut material_by_storage_key = HashMap::with_capacity(handles.len());
        let mut storage_handles = HashMap::with_capacity(handles.len());
        for (material_key, handle) in handles {
            let storage_key = refresh_material_storage_key(scope.credential_key, material_key)?;
            material_by_storage_key.insert(storage_key.clone(), material_key.clone());
            storage_handles.insert(storage_key, handle.clone());
        }
        // Refresh inputs have no provider-level expiry. Preserve the legacy
        // zero-time cutoff without manufacturing a provider resource.
        let resolved = self.resolve(scope.owner(), &storage_handles).await?;
        resolved
            .into_iter()
            .filter_map(|secret| {
                match secret
                    .expiration_time
                    .as_ref()
                    .map(openshell_core::time::timestamp_to_millis)
                    .transpose()
                {
                    Ok(Some(expiration)) if expiration <= 0 => None,
                    Ok(_) => Some(Ok(secret)),
                    Err(error) => Some(Err(Status::internal(error.to_string()))),
                }
            })
            .map(|secret| {
                let secret = secret?;
                let storage_key = secret.credential_key;
                let value = secret.value;
                material_by_storage_key
                    .remove(&storage_key)
                    .map(|material_key| (material_key, value))
                    .ok_or_else(|| {
                        Status::internal(
                            "credential driver resolved an unknown refresh material key",
                        )
                    })
            })
            .collect()
    }

    pub async fn delete_refresh_material_handles(
        &self,
        scope: RefreshMaterialScope<'_>,
        handles: &HashMap<String, CredentialHandle>,
    ) -> Result<(), Status> {
        let storage_handles = handles
            .iter()
            .map(|(material_key, handle)| {
                Ok((
                    refresh_material_storage_key(scope.credential_key, material_key)?,
                    handle.clone(),
                ))
            })
            .collect::<Result<Handles, Status>>()?;
        self.delete(scope.owner(), &storage_handles).await
    }

    pub async fn delete_refresh_material_deletions(
        &self,
        scope: RefreshMaterialScope<'_>,
        deletions: &[RefreshMaterialDeletion],
    ) -> Result<(), Status> {
        let futures = deletions.iter().map(|deletion| async move {
            if deletion.material_key.is_empty() {
                return Err(Status::failed_precondition(
                    "pending refresh-material deletion has no material key",
                ));
            }
            let handle = deletion.handle.clone().ok_or_else(|| {
                Status::failed_precondition(
                    "pending refresh-material deletion has no credential handle",
                )
            })?;
            let storage_key =
                refresh_material_storage_key(scope.credential_key, &deletion.material_key)?;
            self.delete_credential_handle(scope.owner(), &storage_key, handle)
                .await
        });
        let results = futures::future::join_all(futures).await;
        let mut first_error = None;
        for result in results {
            if let Err(err) = result
                && first_error.is_none()
            {
                first_error = Some(err);
            }
        }
        if let Some(err) = first_error {
            return Err(err);
        }
        Ok(())
    }

    pub async fn delete(&self, owner: SecretOwner<'_>, handles: &Handles) -> Result<(), Status> {
        let futures = handles.iter().map(|(credential_key, handle)| {
            self.delete_credential_handle(owner, credential_key, handle.clone())
        });
        let results = futures::future::join_all(futures).await;
        let mut first_error: Option<Status> = None;
        for result in results {
            if let Err(err) = result
                && first_error.is_none()
            {
                first_error = Some(err);
            }
        }
        if let Some(err) = first_error {
            return Err(err);
        }
        Ok(())
    }

    async fn delete_credential_handle(
        &self,
        owner: SecretOwner<'_>,
        credential_key: &str,
        handle: CredentialHandle,
    ) -> Result<(), Status> {
        let scope = owner.legacy_scope();
        let provider_name = scope.provider.as_ref();
        let workspace = scope.workspace;
        let provider_id = scope.id;
        let driver_name = self.registry.driver_for_handle(credential_key, &handle)?;
        let driver = self.connected_driver(&driver_name)?;
        driver
            .delete_credential(DeleteCredentialRequest {
                provider: provider_name.to_string(),
                credential_key: credential_key.to_string(),
                handle: Some(handle),
                workspace: workspace.to_string(),
                provider_id: provider_id.to_string(),
            })
            .await
    }

    #[tracing::instrument(
        name = "credentials",
        level = "debug",
        skip_all,
        fields(otel.name = "credentials.resolve_provider_handles")
    )]
    pub async fn resolve(
        &self,
        owner: SecretOwner<'_>,
        handles: &Handles,
    ) -> Result<Vec<ResolvedSecret>, Status> {
        self.registry.validate_handles(handles)?;
        if handles.is_empty() {
            return Ok(Vec::new());
        }
        let scope = owner.legacy_scope();
        let provider_name = scope.provider.into_owned();
        let workspace = scope.workspace.to_string();
        let provider_id = scope.id.to_string();
        let mut request_keys = HashMap::new();
        let mut requests_by_driver: BTreeMap<String, Vec<ResolveCredentialRequest>> =
            BTreeMap::new();

        for (credential_key, handle) in handles {
            let driver_name = self.registry.driver_for_handle(credential_key, handle)?;
            let request_id = format!("credential-{}", request_keys.len());
            request_keys.insert(request_id.clone(), credential_key.clone());

            let mut selected_handle = handle.clone();
            selected_handle.driver.clone_from(&driver_name);
            requests_by_driver
                .entry(driver_name)
                .or_default()
                .push(ResolveCredentialRequest {
                    request_id,
                    provider: provider_name.clone(),
                    credential_key: credential_key.clone(),
                    handle: Some(selected_handle),
                    workspace: workspace.clone(),
                    provider_id: provider_id.clone(),
                });
        }

        let mut resolved = Vec::new();
        let mut seen_responses = HashSet::new();

        for (driver_name, requests) in requests_by_driver {
            let expected_request_ids: HashSet<_> = requests
                .iter()
                .map(|request| request.request_id.clone())
                .collect();
            let driver = self.connected_driver(&driver_name)?;

            let responses = driver.resolve_credentials(requests).await?;
            for response in responses {
                if response.request_id.is_empty() {
                    return Err(Status::internal(format!(
                        "credential driver '{driver_name}' returned a response without request_id"
                    )));
                }
                if !expected_request_ids.contains(&response.request_id) {
                    return Err(Status::internal(format!(
                        "credential driver '{driver_name}' returned unknown request_id '{}'",
                        response.request_id
                    )));
                }
                if !seen_responses.insert(response.request_id.clone()) {
                    return Err(Status::internal(format!(
                        "credential driver '{driver_name}' returned duplicate request_id '{}'",
                        response.request_id
                    )));
                }

                let credential_key = request_keys
                    .get(&response.request_id)
                    .expect("validated response request_id")
                    .clone();

                resolved.push(ResolvedSecret {
                    credential_key,
                    value: response.value,
                    expiration_time: response.expiration_time,
                });
            }

            for request_id in expected_request_ids {
                if !seen_responses.contains(&request_id) {
                    return Err(Status::internal(format!(
                        "credential driver '{driver_name}' did not return a response for request_id '{request_id}'"
                    )));
                }
            }
        }

        Ok(resolved)
    }

    fn connected_driver(&self, driver_name: &str) -> Result<&Arc<dyn CredentialDriver>, Status> {
        self.drivers.get(driver_name).ok_or_else(|| {
            Status::failed_precondition(format!(
                "credential driver '{driver_name}' is enabled but not connected"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::driver_config::*;
    #[cfg(unix)]
    use super::transport::*;
    use super::*;
    use openshell_core::Config;
    #[cfg(unix)]
    use openshell_core::proto::credentials::v1::GetCredentialDriverCapabilitiesResponse;
    use std::path::{Path, PathBuf};
    #[cfg(unix)]
    use std::time::{Duration, Instant};
    #[cfg(unix)]
    use tokio::process::Command;
    use tonic::Code;

    fn handles_with_handle(driver: &str, handle: &str) -> Handles {
        HashMap::from([(
            "OPENAI_API_KEY".to_string(),
            CredentialHandle {
                driver: driver.to_string(),
                handle: handle.to_string(),
                metadata: HashMap::new(),
            },
        )])
    }
    fn driver_table(value: &str) -> toml::Value {
        toml::from_str(value).unwrap()
    }
    fn test_absolute_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(name)
    }
    fn toml_path(path: &Path) -> String {
        toml::Value::String(path.display().to_string()).to_string()
    }

    #[test]
    fn builtin_credential_driver_kind_resolves_known_names() {
        assert_eq!(
            BuiltinCredentialDriverKind::from_name("kubernetes-secrets"),
            Some(BuiltinCredentialDriverKind::KubernetesSecrets)
        );
        assert_eq!(
            BuiltinCredentialDriverKind::from_name("openshell-gateway"),
            None
        );
        assert_eq!(
            BuiltinCredentialDriverKind::from_name("vault"),
            Some(BuiltinCredentialDriverKind::Vault)
        );
        assert_eq!(
            BuiltinCredentialDriverKind::from_name("enterprise-secrets"),
            None
        );
    }

    #[test]
    fn registry_defaults_to_internal_credential_storage() {
        let registry = CredentialDriverRegistry::from_config(&IssuerConfig::default()).unwrap();

        assert_eq!(
            registry.storage_owner_name().as_str(),
            DbCredstoreCredentialDriver::NAME
        );
    }

    #[test]
    fn registry_allows_legacy_inline_credentials_with_default_driver() {
        let registry = CredentialDriverRegistry::from_config(&IssuerConfig::default()).unwrap();

        registry
            .validate_handles(&HashMap::new())
            .expect("legacy inline provider should not require credential handles");
    }

    #[test]
    fn registry_rejects_default_driver_without_external_driver() {
        let config = Config::new(None).with_default_credential_driver(Some("vault"));

        let err = CredentialDriverRegistry::from_config(&IssuerConfig::from(&config)).unwrap_err();

        assert!(err.to_string().contains("default_credential_driver"));
        assert!(err.to_string().contains("requires credential_drivers"));
    }

    #[test]
    fn registry_rejects_empty_handle_driver() {
        let config = Config::new(None).with_credential_drivers(["test-static"]);
        let registry = CredentialDriverRegistry::from_config(&IssuerConfig::from(&config)).unwrap();

        let err = registry
            .validate_handles(&handles_with_handle("", "openai/API_KEY"))
            .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("missing driver"));
    }

    #[test]
    fn registry_rejects_empty_handle_value() {
        let config = Config::new(None).with_credential_drivers(["test-static"]);
        let registry = CredentialDriverRegistry::from_config(&IssuerConfig::from(&config)).unwrap();

        let err = registry
            .validate_handles(&handles_with_handle("test-static", ""))
            .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("missing handle"));
    }

    #[test]
    fn registry_rejects_unknown_handle_driver() {
        let config = Config::new(None).with_credential_drivers(["test-static"]);
        let registry = CredentialDriverRegistry::from_config(&IssuerConfig::from(&config)).unwrap();

        let err = registry
            .validate_handles(&handles_with_handle("vault", "openai/API_KEY"))
            .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("not enabled"));
    }

    #[test]
    fn registry_rejects_default_driver_not_enabled() {
        let config = Config::new(None)
            .with_credential_drivers(["test-static"])
            .with_default_credential_driver(Some("vault"));

        let err = CredentialDriverRegistry::from_config(&IssuerConfig::from(&config)).unwrap_err();

        assert!(err.to_string().contains("default_credential_driver"));
        assert!(err.to_string().contains("not listed"));
    }

    #[test]
    fn registry_rejects_multiple_enabled_drivers() {
        let config = Config::new(None).with_credential_drivers(["test-static", "vault"]);

        let err = CredentialDriverRegistry::from_config(&IssuerConfig::from(&config)).unwrap_err();

        assert!(err.to_string().contains("at most one"));
    }

    #[test]
    fn parse_uds_driver_launch_settings() {
        let socket_path = test_absolute_path("openshell-enterprise-secrets.sock");
        let command = test_absolute_path("openshell-credential-driver-enterprise-secrets");
        let socket_path_toml = toml_path(&socket_path);
        let command_toml = toml_path(&command);
        let parsed = parse_driver_table(
            "enterprise-secrets",
            &driver_table(&format!(
                r#"
transport = "uds"
socket_path = {socket_path_toml}
command = {command_toml}
args = ["--profile", "dev"]
startup_timeout_secs = 3
"#,
            )),
        )
        .unwrap();

        assert_eq!(parsed.transport, CredentialDriverTransport::Uds);
        assert_eq!(parsed.socket_path.as_deref(), Some(socket_path.as_path()));
        assert_eq!(parsed.command.as_deref(), Some(command.as_path()));
        assert_eq!(parsed.args, ["--profile", "dev"]);
        assert_eq!(parsed.startup_timeout_secs, 3);
    }

    #[test]
    fn parse_uds_driver_defaults_to_connect_only() {
        let socket_path = test_absolute_path("openshell-enterprise-secrets.sock");
        let socket_path_toml = toml_path(&socket_path);
        let parsed = parse_driver_table(
            "enterprise-secrets",
            &driver_table(&format!(
                r#"
transport = "uds"
socket_path = {socket_path_toml}
"#,
            )),
        )
        .unwrap();

        assert_eq!(parsed.transport, CredentialDriverTransport::Uds);
        assert!(parsed.command.is_none());
        assert!(parsed.args.is_empty());
        assert_eq!(
            parsed.startup_timeout_secs,
            DEFAULT_CREDENTIAL_DRIVER_STARTUP_TIMEOUT_SECS
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn get_capabilities_has_a_local_timeout() {
        let response = std::future::pending::<
            Result<tonic::Response<GetCredentialDriverCapabilitiesResponse>, Status>,
        >();

        let err = await_credential_driver_capabilities(
            "enterprise-secrets",
            Duration::from_millis(10),
            response,
        )
        .await
        .unwrap_err()
        .into_error();

        assert!(err.to_string().contains("GetCapabilities timed out"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn launched_driver_failed_precondition_is_terminal() {
        let mut child = Command::new("sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let started = Instant::now();

        let err = wait_for_launched_credential_driver_with(
            "enterprise-secrets",
            Path::new("/unused-test-socket"),
            &mut child,
            Duration::from_secs(30),
            || async {
                await_credential_driver_capabilities(
                    "enterprise-secrets",
                    Duration::from_secs(30),
                    std::future::ready(Err(Status::failed_precondition(
                        "credentials extension 'enterprise-secrets' uses unsupported protocol 2.0; gateway supports 1.0",
                    ))),
                )
                .await?;
                unreachable!("failed-precondition response cannot produce capabilities")
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("unsupported protocol 2.0"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn credential_driver_rpc_status_retries_only_transient_failures() {
        for code in [
            Code::Unavailable,
            Code::DeadlineExceeded,
            Code::ResourceExhausted,
            Code::Aborted,
            Code::Internal,
            Code::Unknown,
        ] {
            assert!(
                CredentialDriverReadinessError::rpc_status(
                    "enterprise-secrets",
                    Status::new(code, "not ready"),
                )
                .is_retryable(),
                "{code:?} should be retried"
            );
        }

        for code in [
            Code::InvalidArgument,
            Code::FailedPrecondition,
            Code::PermissionDenied,
            Code::Unauthenticated,
            Code::Unimplemented,
        ] {
            assert!(
                !CredentialDriverReadinessError::rpc_status(
                    "enterprise-secrets",
                    Status::new(code, "incompatible"),
                )
                .is_retryable(),
                "{code:?} should fail immediately"
            );
        }
    }

    #[test]
    fn parse_driver_table_preserves_backend_config_without_transport_fields() {
        let parsed = parse_driver_table(
            "kubernetes-secrets",
            &driver_table(
                r#"
transport = "in_tree"
namespace = "openshell"
"#,
            ),
        )
        .unwrap();

        assert_eq!(
            parsed
                .backend_config
                .get("namespace")
                .and_then(toml::Value::as_str),
            Some("openshell")
        );
        assert!(!parsed.backend_config.contains_key("transport"));
    }

    #[test]
    fn parse_uds_driver_rejects_relative_command() {
        let socket_path_toml = toml_path(&test_absolute_path("openshell-enterprise-secrets.sock"));
        let err = parse_driver_table(
            "enterprise-secrets",
            &driver_table(&format!(
                r#"
transport = "uds"
socket_path = {socket_path_toml}
command = "openshell-credential-driver-enterprise-secrets"
"#,
            )),
        )
        .unwrap_err();

        assert!(err.to_string().contains("command must be absolute"));
    }

    #[test]
    fn parse_uds_driver_rejects_args_without_command() {
        let socket_path_toml = toml_path(&test_absolute_path("openshell-enterprise-secrets.sock"));
        let err = parse_driver_table(
            "enterprise-secrets",
            &driver_table(&format!(
                r#"
transport = "uds"
socket_path = {socket_path_toml}
args = ["--profile", "dev"]
"#,
            )),
        )
        .unwrap_err();

        assert!(err.to_string().contains("args requires command"));
    }

    #[test]
    fn parse_uds_driver_rejects_timeout_without_command() {
        let socket_path_toml = toml_path(&test_absolute_path("openshell-enterprise-secrets.sock"));
        let err = parse_driver_table(
            "enterprise-secrets",
            &driver_table(&format!(
                r#"
transport = "uds"
socket_path = {socket_path_toml}
startup_timeout_secs = 3
"#,
            )),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("startup_timeout_secs requires command")
        );
    }

    #[test]
    fn parse_in_tree_driver_rejects_launch_settings() {
        let err = parse_driver_table(
            "test-static",
            &driver_table(
                r#"
transport = "in_tree"
command = "/usr/local/libexec/openshell-credential-driver-test"
"#,
            ),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("command, args, and startup_timeout_secs require transport = 'uds'")
        );
    }

    #[cfg(unix)]
    #[test]
    fn remove_stale_launched_driver_socket_removes_socket() {
        use std::os::unix::net::UnixListener as StdUnixListener;

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("driver.sock");
        let listener = StdUnixListener::bind(&socket_path).unwrap();

        remove_stale_launched_driver_socket("enterprise-secrets", &socket_path).unwrap();

        drop(listener);
        assert!(!socket_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn remove_stale_launched_driver_socket_rejects_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("driver.sock");
        std::fs::write(&socket_path, "not a socket").unwrap();

        let err =
            remove_stale_launched_driver_socket("enterprise-secrets", &socket_path).unwrap_err();

        assert!(err.to_string().contains("not a Unix socket"));
        assert!(socket_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn remove_stale_launched_driver_socket_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.sock");
        let socket_path = dir.path().join("driver.sock");
        std::os::unix::fs::symlink(&target, &socket_path).unwrap();

        let err =
            remove_stale_launched_driver_socket("enterprise-secrets", &socket_path).unwrap_err();

        assert!(err.to_string().contains("is a symlink"));
        assert!(std::fs::symlink_metadata(&socket_path).is_ok());
    }
}

#[cfg(test)]
mod boundary_tests;
