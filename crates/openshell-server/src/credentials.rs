// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway credential-driver runtime scaffolding.
//!
//! This module owns gateway-level credential-driver selection and resolution
//! dispatch. Concrete production backends and remote UDS transport plug in here
//! in later implementation slices.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Stdio;
use std::sync::Arc;
#[cfg(unix)]
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::{
    io::ErrorKind,
    os::unix::fs::{FileTypeExt, MetadataExt},
};

use async_trait::async_trait;
#[cfg(unix)]
use hyper_util::rt::TokioIo;
use openshell_core::proto::credentials::v1::{
    DeleteCredentialRequest, GetCredentialDriverCapabilitiesRequest, ResolveCredentialRequest,
    ResolveCredentialsRequest, ResolvedCredential, StoreCredentialRequest,
    credential_driver_client::CredentialDriverClient,
};
use openshell_core::proto::{CredentialHandle, Provider};
use openshell_core::{Config, Error, Result as CoreResult};
use openshell_driver_db_credstore::{
    CredentialObjectWrite, DbCredstoreCredentialDriver, DbCredstoreObjectStore,
    DbCredstoreWriteCondition, StoredCredentialObject,
};
use openshell_driver_kubernetes_secrets::KubernetesSecretsCredentialDriver;
use openshell_driver_vault::VaultCredentialDriver;
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tokio::process::Command;
#[cfg(unix)]
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};
#[cfg(unix)]
use tower::service_fn;

use crate::persistence::{PersistenceError, Store, WriteCondition};

const DEFAULT_CREDENTIAL_DRIVER_STARTUP_TIMEOUT_SECS: u64 = 10;
const COMMON_CREDENTIAL_DRIVER_FIELDS: &[&str] = &[
    "transport",
    "socket_path",
    "command",
    "args",
    "startup_timeout_secs",
];
#[cfg(unix)]
const CREDENTIAL_DRIVER_CONNECT_INTERVAL: Duration = Duration::from_millis(100);

#[async_trait]
pub trait CredentialDriver: std::fmt::Debug + Send + Sync {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status>;

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status>;

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedProviderCredentials {
    pub values: HashMap<String, String>,
    pub expires_at_ms: HashMap<String, i64>,
}

#[derive(Debug, Clone)]
pub struct CredentialRuntime {
    registry: CredentialDriverRegistry,
    drivers: BTreeMap<String, Arc<dyn CredentialDriver>>,
    _driver_processes: Vec<Arc<ManagedCredentialDriverProcess>>,
}

impl CredentialRuntime {
    pub fn from_config(config: &Config) -> CoreResult<Self> {
        Self::from_config_with_optional_store(config, None)
    }

    pub fn from_config_with_store(config: &Config, store: Arc<Store>) -> CoreResult<Self> {
        Self::from_config_with_optional_store(config, Some(store))
    }

    fn from_config_with_optional_store(
        config: &Config,
        store: Option<Arc<Store>>,
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

        Ok(Self {
            registry,
            drivers,
            _driver_processes: Vec::new(),
        })
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
        let registry = CredentialDriverRegistry::from_config(config)?;
        let mut drivers = BTreeMap::new();
        let mut driver_processes = Vec::new();
        let empty_config = toml::Table::new();
        let default_store_config = config_file
            .and_then(|file| file.openshell.gateway.credential_storage.as_ref())
            .unwrap_or(&empty_config);
        connect_default_credential_store(
            &mut drivers,
            store.clone(),
            default_store_config,
            registry.requires_default_store(),
        )?;

        for driver_name in registry.enabled_driver_names() {
            let driver_config = config_file
                .and_then(|file| file.openshell.credential_drivers.get(driver_name))
                .map(|value| parse_driver_table(driver_name, value))
                .transpose()?;

            if let Some(driver_config) = driver_config {
                let built =
                    build_configured_driver(driver_name, driver_config, store.clone()).await?;
                drivers.insert(driver_name.clone(), built.driver);
                if let Some(process) = built.process {
                    driver_processes.push(process);
                }
            } else {
                let driver = build_default_in_tree_driver(driver_name, store.clone()).await?;
                drivers.insert(driver_name.clone(), driver);
            }
        }

        Ok(Self {
            registry,
            drivers,
            _driver_processes: driver_processes,
        })
    }

    pub fn validate_provider_handles(&self, provider: &Provider) -> Result<(), Status> {
        self.registry.validate_provider_handles(provider)
    }

    pub fn stores_provider_credentials(&self) -> bool {
        let driver_name = self.registry.storage_owner_name();
        self.drivers.contains_key(&driver_name)
    }

    pub fn storage_owns_handle(&self, handle: &CredentialHandle) -> bool {
        normalize_driver_name(&handle.driver) == self.registry.storage_owner_name()
    }

    pub async fn store_provider_credentials(
        &self,
        provider_name: &str,
        credentials: &HashMap<String, String>,
        existing_handles: &HashMap<String, CredentialHandle>,
    ) -> Result<HashMap<String, CredentialHandle>, Status> {
        if credentials.is_empty() {
            return Ok(HashMap::new());
        }
        let driver_name = self.registry.storage_owner_name();
        let driver = self.connected_driver(&driver_name)?;
        let mut handles = HashMap::with_capacity(credentials.len());

        for (credential_key, value) in credentials {
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
                    provider_name: provider_name.to_string(),
                    credential_key: credential_key.clone(),
                    value: value.clone(),
                    existing_handle,
                })
                .await?;
            handle.driver.clone_from(&driver_name);
            if handle.handle.trim().is_empty() {
                return Err(Status::internal(format!(
                    "credential driver '{driver_name}' returned an empty handle for provider credential '{credential_key}'"
                )));
            }
            if let Some(replaced_handle) = replaced_handle {
                self.delete_provider_credential_handle(
                    provider_name,
                    credential_key,
                    replaced_handle,
                )
                .await?;
            }
            handles.insert(credential_key.clone(), handle);
        }

        Ok(handles)
    }

    pub async fn delete_provider_credential_handles(
        &self,
        provider_name: &str,
        handles: &HashMap<String, CredentialHandle>,
    ) -> Result<(), Status> {
        for (credential_key, handle) in handles {
            self.delete_provider_credential_handle(provider_name, credential_key, handle.clone())
                .await?;
        }
        Ok(())
    }

    async fn delete_provider_credential_handle(
        &self,
        provider_name: &str,
        credential_key: &str,
        handle: CredentialHandle,
    ) -> Result<(), Status> {
        let driver_name = self.registry.driver_for_handle(credential_key, &handle)?;
        let driver = self.connected_driver(&driver_name)?;
        driver
            .delete_credential(DeleteCredentialRequest {
                provider_name: provider_name.to_string(),
                credential_key: credential_key.to_string(),
                handle: Some(handle),
            })
            .await
    }

    pub async fn resolve_provider_handles(
        &self,
        provider: &Provider,
        now_ms: i64,
    ) -> Result<ResolvedProviderCredentials, Status> {
        self.registry.validate_provider_handles(provider)?;
        if provider.credential_handles.is_empty() {
            return Ok(ResolvedProviderCredentials::default());
        }

        let provider_name = provider
            .metadata
            .as_ref()
            .map(|metadata| metadata.name.clone())
            .unwrap_or_default();
        let mut request_keys = HashMap::new();
        let mut requests_by_driver: BTreeMap<String, Vec<ResolveCredentialRequest>> =
            BTreeMap::new();

        for (credential_key, handle) in &provider.credential_handles {
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
                    provider_name: provider_name.clone(),
                    credential_key: credential_key.clone(),
                    handle: Some(selected_handle),
                });
        }

        let mut resolved = ResolvedProviderCredentials::default();
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
                if response.expires_at_ms > 0 && response.expires_at_ms <= now_ms {
                    return Err(Status::failed_precondition(format!(
                        "credential driver '{driver_name}' returned expired credential for provider credential '{credential_key}'"
                    )));
                }
                if response.expires_at_ms > 0 {
                    resolved
                        .expires_at_ms
                        .insert(credential_key.clone(), response.expires_at_ms);
                }
                resolved.values.insert(credential_key, response.value);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuiltinCredentialDriverKind {
    KubernetesSecrets,
    Vault,
    #[cfg(any(test, feature = "test-support"))]
    TestStatic,
}

impl BuiltinCredentialDriverKind {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            KubernetesSecretsCredentialDriver::NAME => Some(Self::KubernetesSecrets),
            VaultCredentialDriver::NAME => Some(Self::Vault),
            #[cfg(any(test, feature = "test-support"))]
            TestStaticCredentialDriver::NAME => Some(Self::TestStatic),
            _ => None,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
fn builtin_credential_driver_names() -> &'static [&'static str] {
    &[
        KubernetesSecretsCredentialDriver::NAME,
        VaultCredentialDriver::NAME,
        TestStaticCredentialDriver::NAME,
    ]
}

#[cfg(not(any(test, feature = "test-support")))]
fn builtin_credential_driver_names() -> &'static [&'static str] {
    &[
        KubernetesSecretsCredentialDriver::NAME,
        VaultCredentialDriver::NAME,
    ]
}

fn unknown_credential_driver_error(driver_name: &str) -> Error {
    Error::config(format!(
        "credential driver '{driver_name}' is not a built-in credential driver and has no [openshell.credential_drivers.{driver_name}] table; configure an external driver with transport = 'uds' or choose one of: {}",
        builtin_credential_driver_names().join(", ")
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDriverRegistry {
    enabled: BTreeSet<String>,
    default_driver: Option<String>,
}

impl CredentialDriverRegistry {
    pub fn from_config(config: &Config) -> CoreResult<Self> {
        let mut enabled = BTreeSet::new();
        for driver in &config.credential_drivers {
            let driver = normalize_driver_name(driver);
            if driver.is_empty() {
                return Err(Error::config(
                    "credential_drivers entries must be non-empty strings",
                ));
            }
            enabled.insert(driver);
        }

        let default_driver = config
            .default_credential_driver
            .as_deref()
            .map(normalize_driver_name)
            .filter(|driver| !driver.is_empty());

        if default_driver.is_some() && enabled.is_empty() {
            return Err(Error::config(
                "default_credential_driver requires credential_drivers to name an external credential driver",
            ));
        }

        if let Some(default_driver) = default_driver.as_deref()
            && !enabled.contains(default_driver)
        {
            return Err(Error::config(format!(
                "default_credential_driver '{default_driver}' is not listed in credential_drivers"
            )));
        }

        if enabled.len() > 1 {
            return Err(Error::config(
                "credential_drivers supports at most one enabled credential driver",
            ));
        }

        Ok(Self {
            enabled,
            default_driver,
        })
    }

    pub fn storage_owner_name(&self) -> String {
        if self.enabled.is_empty() {
            return DbCredstoreCredentialDriver::NAME.to_string();
        }
        if let Some(default_driver) = self.default_driver.clone() {
            return default_driver;
        }
        self.enabled
            .iter()
            .next()
            .expect("enabled is non-empty")
            .clone()
    }

    fn requires_default_store(&self) -> bool {
        self.enabled.is_empty()
    }

    pub fn validate_provider_handles(&self, provider: &Provider) -> Result<(), Status> {
        if provider.credential_handles.is_empty() {
            return Ok(());
        }
        for (credential_key, handle) in &provider.credential_handles {
            self.driver_for_handle(credential_key, handle)?;
        }

        Ok(())
    }

    fn enabled_driver_names(&self) -> impl Iterator<Item = &String> {
        self.enabled.iter()
    }

    fn driver_for_handle(
        &self,
        credential_key: &str,
        handle: &CredentialHandle,
    ) -> Result<String, Status> {
        let driver = normalize_driver_name(&handle.driver);
        if driver.is_empty() {
            return Err(Status::invalid_argument(format!(
                "provider credential_handles['{credential_key}'] is missing driver"
            )));
        }
        if handle.handle.trim().is_empty() {
            return Err(Status::invalid_argument(format!(
                "provider credential_handles['{credential_key}'] is missing handle"
            )));
        }

        if driver == DbCredstoreCredentialDriver::NAME {
            return Ok(driver);
        }

        if !self.enabled.contains(&driver) {
            return Err(Status::invalid_argument(format!(
                "provider credential_handles['{credential_key}'] references credential driver '{driver}' that is not enabled"
            )));
        }

        Ok(driver)
    }
}

fn normalize_driver_name(driver: &str) -> String {
    driver.trim().to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialDriverTransport {
    InTree,
    Uds,
}

#[derive(Debug, Clone, PartialEq)]
struct ConfiguredCredentialDriver {
    transport: CredentialDriverTransport,
    socket_path: Option<PathBuf>,
    command: Option<PathBuf>,
    args: Vec<String>,
    startup_timeout_secs: u64,
    backend_config: toml::Table,
}

fn parse_driver_table(
    driver_name: &str,
    value: &toml::Value,
) -> CoreResult<ConfiguredCredentialDriver> {
    let table = value.as_table().ok_or_else(|| {
        Error::config(format!(
            "[openshell.credential_drivers.{driver_name}] must be a TOML table"
        ))
    })?;

    let transport = table
        .get("transport")
        .map(|value| string_field(driver_name, "transport", value))
        .transpose()?
        .unwrap_or_else(|| "in_tree".to_string());
    let transport = match transport.as_str() {
        "in_tree" => CredentialDriverTransport::InTree,
        "uds" => CredentialDriverTransport::Uds,
        other => {
            return Err(Error::config(format!(
                "[openshell.credential_drivers.{driver_name}] transport must be 'in_tree' or 'uds', got '{other}'"
            )));
        }
    };

    let socket_path = table
        .get("socket_path")
        .map(|value| string_field(driver_name, "socket_path", value))
        .transpose()?
        .map(PathBuf::from);
    let command = table
        .get("command")
        .map(|value| string_field(driver_name, "command", value))
        .transpose()?
        .map(PathBuf::from);
    let args = table
        .get("args")
        .map(|value| string_array_field(driver_name, "args", value))
        .transpose()?
        .unwrap_or_default();
    let startup_timeout_secs = table
        .get("startup_timeout_secs")
        .map(|value| positive_integer_field(driver_name, "startup_timeout_secs", value))
        .transpose()?
        .unwrap_or(DEFAULT_CREDENTIAL_DRIVER_STARTUP_TIMEOUT_SECS);

    if transport == CredentialDriverTransport::Uds {
        let socket_path = socket_path.as_ref().ok_or_else(|| {
            Error::config(format!(
                "[openshell.credential_drivers.{driver_name}] socket_path is required when transport = 'uds'"
            ))
        })?;
        if !socket_path.is_absolute() {
            return Err(Error::config(format!(
                "[openshell.credential_drivers.{driver_name}] socket_path must be absolute"
            )));
        }
        if let Some(command) = command.as_ref()
            && !command.is_absolute()
        {
            return Err(Error::config(format!(
                "[openshell.credential_drivers.{driver_name}] command must be absolute"
            )));
        }
        if command.is_none() && !args.is_empty() {
            return Err(Error::config(format!(
                "[openshell.credential_drivers.{driver_name}] args requires command"
            )));
        }
        if command.is_none() && table.contains_key("startup_timeout_secs") {
            return Err(Error::config(format!(
                "[openshell.credential_drivers.{driver_name}] startup_timeout_secs requires command"
            )));
        }
    } else if command.is_some() || !args.is_empty() || table.contains_key("startup_timeout_secs") {
        return Err(Error::config(format!(
            "[openshell.credential_drivers.{driver_name}] command, args, and startup_timeout_secs require transport = 'uds'"
        )));
    }

    Ok(ConfiguredCredentialDriver {
        transport,
        socket_path,
        command,
        args,
        startup_timeout_secs,
        backend_config: backend_config_table(table),
    })
}

fn backend_config_table(table: &toml::Table) -> toml::Table {
    let mut backend_config = table.clone();
    for field in COMMON_CREDENTIAL_DRIVER_FIELDS {
        backend_config.remove(*field);
    }
    backend_config
}

fn string_field(
    driver_name: &str,
    field_name: &'static str,
    value: &toml::Value,
) -> CoreResult<String> {
    let value = value.as_str().ok_or_else(|| {
        Error::config(format!(
            "[openshell.credential_drivers.{driver_name}] {field_name} must be a string"
        ))
    })?;
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::config(format!(
            "[openshell.credential_drivers.{driver_name}] {field_name} must not be empty"
        )));
    }
    Ok(value.to_string())
}

fn string_array_field(
    driver_name: &str,
    field_name: &'static str,
    value: &toml::Value,
) -> CoreResult<Vec<String>> {
    let values = value.as_array().ok_or_else(|| {
        Error::config(format!(
            "[openshell.credential_drivers.{driver_name}] {field_name} must be an array of strings"
        ))
    })?;

    values
        .iter()
        .map(|value| string_field(driver_name, field_name, value))
        .collect()
}

fn positive_integer_field(
    driver_name: &str,
    field_name: &'static str,
    value: &toml::Value,
) -> CoreResult<u64> {
    let value = value.as_integer().ok_or_else(|| {
        Error::config(format!(
            "[openshell.credential_drivers.{driver_name}] {field_name} must be a positive integer"
        ))
    })?;
    if value <= 0 {
        return Err(Error::config(format!(
            "[openshell.credential_drivers.{driver_name}] {field_name} must be a positive integer"
        )));
    }
    u64::try_from(value).map_err(|_| {
        Error::config(format!(
            "[openshell.credential_drivers.{driver_name}] {field_name} is too large"
        ))
    })
}

fn connect_default_credential_store(
    drivers: &mut BTreeMap<String, Arc<dyn CredentialDriver>>,
    store: Option<Arc<Store>>,
    config: &toml::Table,
    required: bool,
) -> CoreResult<()> {
    if !required && config.is_empty() {
        return Ok(());
    }

    let Some(store) = store else {
        if required {
            return Err(Error::config(
                "default encrypted credential storage requires the gateway object store",
            ));
        }
        return Ok(());
    };

    let object_store: Arc<dyn DbCredstoreObjectStore> =
        Arc::new(ServerDbCredstoreObjectStore::new(store));
    let storage: Arc<dyn CredentialDriver> = Arc::new(DbCredstoreCredentialDriver::from_config(
        object_store,
        config,
    )?);
    drivers.insert(DbCredstoreCredentialDriver::NAME.to_string(), storage);
    Ok(())
}

#[derive(Debug)]
struct BuiltCredentialDriver {
    driver: Arc<dyn CredentialDriver>,
    process: Option<Arc<ManagedCredentialDriverProcess>>,
}

async fn build_configured_driver(
    driver_name: &str,
    config: ConfiguredCredentialDriver,
    store: Option<Arc<Store>>,
) -> CoreResult<BuiltCredentialDriver> {
    match config.transport {
        CredentialDriverTransport::InTree => {
            let driver = build_in_tree_driver(driver_name, Some(&config.backend_config), store)
                .await?
                .ok_or_else(|| {
                    Error::config(format!(
                        "credential driver '{driver_name}' is configured with transport = 'in_tree', but no in-tree implementation is available"
                    ))
                })?;
            Ok(BuiltCredentialDriver {
                driver,
                process: None,
            })
        }
        CredentialDriverTransport::Uds => {
            let socket_path = config
                .socket_path
                .clone()
                .expect("UDS transport requires socket_path during parsing");
            connect_uds_driver(driver_name, config, &socket_path).await
        }
    }
}

async fn build_default_in_tree_driver(
    driver_name: &str,
    store: Option<Arc<Store>>,
) -> CoreResult<Arc<dyn CredentialDriver>> {
    build_in_tree_driver(driver_name, None, store)
        .await?
        .ok_or_else(|| unknown_credential_driver_error(driver_name))
}

async fn build_in_tree_driver(
    name: &str,
    backend_config: Option<&toml::Table>,
    _store: Option<Arc<Store>>,
) -> CoreResult<Option<Arc<dyn CredentialDriver>>> {
    let Some(kind) = BuiltinCredentialDriverKind::from_name(name) else {
        return Ok(None);
    };

    let empty_config = toml::Table::new();
    let backend_config = backend_config.unwrap_or(&empty_config);
    let driver: Arc<dyn CredentialDriver> = match kind {
        BuiltinCredentialDriverKind::KubernetesSecrets => {
            Arc::new(KubernetesSecretsCredentialDriver::from_config(backend_config).await?)
        }
        BuiltinCredentialDriverKind::Vault => {
            Arc::new(VaultCredentialDriver::from_config(backend_config)?)
        }
        #[cfg(any(test, feature = "test-support"))]
        BuiltinCredentialDriverKind::TestStatic => Arc::new(TestStaticCredentialDriver::new()),
    };
    Ok(Some(driver))
}

fn build_sync_builtin_driver(
    name: &str,
    _store: Option<Arc<Store>>,
) -> Option<Arc<dyn CredentialDriver>> {
    #[cfg(any(test, feature = "test-support"))]
    if BuiltinCredentialDriverKind::from_name(name) == Some(BuiltinCredentialDriverKind::TestStatic)
    {
        let driver: Arc<dyn CredentialDriver> = Arc::new(TestStaticCredentialDriver::new());
        return Some(driver);
    }

    let _ = name;
    None
}

#[derive(Debug, Clone)]
struct ServerDbCredstoreObjectStore {
    store: Arc<Store>,
}

impl ServerDbCredstoreObjectStore {
    fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl DbCredstoreObjectStore for ServerDbCredstoreObjectStore {
    async fn get_credential_object(
        &self,
        object_type: &str,
        id: &str,
        operation: &'static str,
    ) -> Result<Option<StoredCredentialObject>, Status> {
        self.store
            .get(object_type, id)
            .await
            .map(|record| {
                record.map(|record| StoredCredentialObject {
                    object_type: record.object_type,
                    id: record.id,
                    payload: record.payload,
                    resource_version: record.resource_version,
                })
            })
            .map_err(|err| default_credential_store_persistence_error_to_status(err, operation))
    }

    async fn put_credential_object(
        &self,
        write: CredentialObjectWrite,
        operation: &'static str,
    ) -> Result<(), Status> {
        let condition = match write.condition {
            DbCredstoreWriteCondition::MustCreate => WriteCondition::MustCreate,
            DbCredstoreWriteCondition::MatchResourceVersion(resource_version) => {
                WriteCondition::MatchResourceVersion(resource_version)
            }
        };
        self.store
            .put_if(
                &write.object_type,
                &write.id,
                &write.name,
                &write.payload,
                write.labels.as_deref(),
                condition,
            )
            .await
            .map(|_| ())
            .map_err(|err| default_credential_store_persistence_error_to_status(err, operation))
    }

    async fn delete_credential_object(
        &self,
        object_type: &str,
        id: &str,
        expected_resource_version: u64,
        operation: &'static str,
    ) -> Result<(), Status> {
        self.store
            .delete_if(object_type, id, expected_resource_version)
            .await
            .map(|_| ())
            .map_err(|err| default_credential_store_persistence_error_to_status(err, operation))
    }
}

fn default_credential_store_persistence_error_to_status(
    err: PersistenceError,
    operation: &str,
) -> Status {
    match err {
        PersistenceError::UniqueViolation { .. } => {
            Status::already_exists(format!("default credential already exists: {err}"))
        }
        PersistenceError::Conflict {
            current_resource_version,
        } => Status::aborted(format!(
            "default credential was modified concurrently during {operation} (current resource_version: {})",
            current_resource_version.unwrap_or(0)
        )),
        PersistenceError::Decode(err) => Status::data_loss(format!(
            "default credential decode failed during {operation}: {err}"
        )),
        PersistenceError::Encode(err) => Status::internal(format!(
            "default credential encode failed during {operation}: {err}"
        )),
        other => Status::unavailable(format!("default credential {operation} failed: {other}")),
    }
}

#[async_trait]
impl CredentialDriver for KubernetesSecretsCredentialDriver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        Self::store_credential(self, request).await
    }

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        Self::delete_credential(self, request).await
    }

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        Self::resolve_credentials(self, requests).await
    }
}

#[async_trait]
impl CredentialDriver for DbCredstoreCredentialDriver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        Self::store_credential(self, request).await
    }

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        Self::delete_credential(self, request).await
    }

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        Self::resolve_credentials(self, requests).await
    }
}

#[async_trait]
impl CredentialDriver for VaultCredentialDriver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        Self::store_credential(self, request).await
    }

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        Self::delete_credential(self, request).await
    }

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        Self::resolve_credentials(self, requests).await
    }
}

#[derive(Debug, Clone)]
#[cfg(unix)]
struct RemoteCredentialDriver {
    channel: Channel,
}

#[cfg(unix)]
impl RemoteCredentialDriver {
    fn new(channel: Channel) -> Self {
        Self { channel }
    }

    fn client(&self) -> CredentialDriverClient<Channel> {
        CredentialDriverClient::new(self.channel.clone())
    }
}

#[cfg(unix)]
#[async_trait]
impl CredentialDriver for RemoteCredentialDriver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        let mut client = self.client();
        let response = client.store_credential(Request::new(request)).await?;
        response
            .into_inner()
            .handle
            .ok_or_else(|| Status::internal("credential driver returned no stored handle"))
    }

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        let mut client = self.client();
        client.delete_credential(Request::new(request)).await?;
        Ok(())
    }

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        let mut client = self.client();
        let response = client
            .resolve_credentials(Request::new(ResolveCredentialsRequest {
                credentials: requests,
            }))
            .await?;
        Ok(response.into_inner().credentials)
    }
}

#[derive(Debug)]
struct ManagedCredentialDriverProcess {
    child: std::sync::Mutex<Option<tokio::process::Child>>,
    socket_path: PathBuf,
}

#[cfg(unix)]
impl ManagedCredentialDriverProcess {
    fn new(child: tokio::process::Child, socket_path: PathBuf) -> Self {
        Self {
            child: std::sync::Mutex::new(Some(child)),
            socket_path,
        }
    }
}

impl Drop for ManagedCredentialDriverProcess {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.take();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(unix)]
async fn connect_uds_driver(
    driver_name: &str,
    config: ConfiguredCredentialDriver,
    socket_path: &Path,
) -> CoreResult<BuiltCredentialDriver> {
    if config.command.is_some() {
        spawn_uds_driver(driver_name, config, socket_path).await
    } else {
        let channel = connect_ready_credential_driver(driver_name, socket_path).await?;
        Ok(BuiltCredentialDriver {
            driver: Arc::new(RemoteCredentialDriver::new(channel)),
            process: None,
        })
    }
}

#[cfg(not(unix))]
async fn connect_uds_driver(
    driver_name: &str,
    _config: ConfiguredCredentialDriver,
    _socket_path: &Path,
) -> CoreResult<BuiltCredentialDriver> {
    Err(Error::config(format!(
        "credential driver '{driver_name}' uses transport = 'uds', but this platform does not support Unix domain sockets"
    )))
}

#[cfg(unix)]
async fn spawn_uds_driver(
    driver_name: &str,
    config: ConfiguredCredentialDriver,
    socket_path: &Path,
) -> CoreResult<BuiltCredentialDriver> {
    let command_path = config
        .command
        .expect("UDS command exists when spawning credential driver");
    let parent = socket_path.parent().ok_or_else(|| {
        Error::execution(format!(
            "credential driver '{driver_name}' socket path '{}' has no parent directory",
            socket_path.display()
        ))
    })?;
    std::fs::create_dir_all(parent).map_err(|err| {
        Error::execution(format!(
            "failed to create credential driver '{driver_name}' socket dir '{}': {err}",
            parent.display()
        ))
    })?;
    remove_stale_launched_driver_socket(driver_name, socket_path)?;

    let mut command = Command::new(&command_path);
    command.kill_on_drop(true);
    command.stdin(Stdio::null());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());
    command.args(&config.args);
    command.arg("--bind-socket").arg(socket_path);

    let mut child = command.spawn().map_err(|err| {
        Error::execution(format!(
            "failed to launch credential driver '{driver_name}' '{}': {err}",
            command_path.display()
        ))
    })?;
    let channel = wait_for_launched_credential_driver(
        driver_name,
        socket_path,
        &mut child,
        Duration::from_secs(config.startup_timeout_secs),
    )
    .await?;
    let process = Arc::new(ManagedCredentialDriverProcess::new(
        child,
        socket_path.to_path_buf(),
    ));
    Ok(BuiltCredentialDriver {
        driver: Arc::new(RemoteCredentialDriver::new(channel)),
        process: Some(process),
    })
}

#[cfg(unix)]
fn remove_stale_launched_driver_socket(driver_name: &str, socket_path: &Path) -> CoreResult<()> {
    let metadata = match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(Error::execution(format!(
                "failed to stat credential driver '{driver_name}' socket '{}': {err}",
                socket_path.display()
            )));
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::execution(format!(
            "credential driver '{driver_name}' socket '{}' is a symlink; refusing to remove it",
            socket_path.display()
        )));
    }
    if !file_type.is_socket() {
        return Err(Error::execution(format!(
            "credential driver '{driver_name}' socket path '{}' exists but is not a Unix socket",
            socket_path.display()
        )));
    }
    let expected_uid = rustix::process::geteuid().as_raw();
    if metadata.uid() != expected_uid {
        return Err(Error::execution(format!(
            "credential driver '{driver_name}' socket '{}' is owned by uid {} but current euid is {}",
            socket_path.display(),
            metadata.uid(),
            expected_uid
        )));
    }
    std::fs::remove_file(socket_path).map_err(|err| {
        Error::execution(format!(
            "failed to remove stale credential driver '{driver_name}' socket '{}': {err}",
            socket_path.display()
        ))
    })
}

#[cfg(unix)]
async fn wait_for_launched_credential_driver(
    driver_name: &str,
    socket_path: &Path,
    child: &mut tokio::process::Child,
    timeout: Duration,
) -> CoreResult<Channel> {
    let deadline = Instant::now() + timeout;
    let mut last_error: Option<String>;

    loop {
        let try_wait_result = child.try_wait().map_err(|err| {
            Error::execution(format!(
                "failed to poll credential driver '{driver_name}' process: {err}"
            ))
        })?;
        if let Some(status) = try_wait_result {
            return Err(Error::execution(format!(
                "credential driver '{driver_name}' exited before becoming ready with status {status}"
            )));
        }

        match connect_ready_credential_driver(driver_name, socket_path).await {
            Ok(channel) => return Ok(channel),
            Err(err) => last_error = Some(err.to_string()),
        }

        if Instant::now() >= deadline {
            return Err(Error::execution(format!(
                "timed out waiting for credential driver '{driver_name}' socket '{}': {}",
                socket_path.display(),
                last_error.unwrap_or_else(|| "unknown error".to_string())
            )));
        }

        tokio::time::sleep(CREDENTIAL_DRIVER_CONNECT_INTERVAL).await;
    }
}

#[cfg(unix)]
async fn connect_ready_credential_driver(
    driver_name: &str,
    socket_path: &Path,
) -> CoreResult<Channel> {
    let channel = connect_credential_driver_socket(driver_name, socket_path).await?;
    let mut client = CredentialDriverClient::new(channel.clone());
    client
        .get_capabilities(Request::new(GetCredentialDriverCapabilitiesRequest {}))
        .await
        .map_err(|status| {
            Error::config(format!(
                "credential driver '{driver_name}' GetCapabilities failed: {status}"
            ))
        })?;
    Ok(channel)
}

#[cfg(unix)]
async fn connect_credential_driver_socket(
    driver_name: &str,
    socket_path: &Path,
) -> CoreResult<Channel> {
    let socket_path = socket_path.to_path_buf();
    let display_path = socket_path.clone();
    Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let socket_path = socket_path.clone();
            async move { UnixStream::connect(socket_path).await.map(TokioIo::new) }
        }))
        .await
        .map_err(|err| {
            Error::transport(format!(
                "failed to connect to credential driver '{driver_name}' socket '{}': {err}",
                display_path.display()
            ))
        })
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
struct TestStaticCredentialDriver {
    values: std::sync::Mutex<HashMap<String, String>>,
}

#[cfg(any(test, feature = "test-support"))]
impl TestStaticCredentialDriver {
    const NAME: &'static str = "test-static";

    fn new() -> Self {
        Self {
            values: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn handle_from_request(
        request_id: &str,
        handle: Option<CredentialHandle>,
    ) -> Result<CredentialHandle, Status> {
        handle.ok_or_else(|| {
            Status::invalid_argument(format!(
                "test-static credential request '{request_id}' is missing handle"
            ))
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
#[async_trait]
impl CredentialDriver for TestStaticCredentialDriver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        let handle = request
            .existing_handle
            .map(|handle| handle.handle)
            .filter(|handle| !handle.trim().is_empty())
            .unwrap_or_else(|| format!("{}:{}", request.provider_name, request.credential_key));
        self.values
            .lock()
            .map_err(|_| Status::internal("test-static credential store lock poisoned"))?
            .insert(handle.clone(), request.value);
        Ok(CredentialHandle {
            driver: Self::NAME.to_string(),
            handle,
            metadata: HashMap::new(),
        })
    }

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        let handle = Self::handle_from_request("delete", request.handle)?;
        self.values
            .lock()
            .map_err(|_| Status::internal("test-static credential store lock poisoned"))?
            .remove(&handle.handle);
        Ok(())
    }

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        let mut responses = Vec::with_capacity(requests.len());
        for request in requests {
            let handle = Self::handle_from_request(&request.request_id, request.handle)?;
            let value = self
                .values
                .lock()
                .map_err(|_| Status::internal("test-static credential store lock poisoned"))?
                .get(&handle.handle)
                .cloned()
                .ok_or_else(|| Status::not_found("test-static credential handle not found"))?;
            responses.push(ResolvedCredential {
                request_id: request.request_id,
                value,
                expires_at_ms: 0,
            });
        }

        Ok(responses)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use openshell_core::proto::{CredentialHandle, Provider};
    use tonic::Code;

    use super::*;

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

    fn config_file(toml: &str) -> crate::config_file::ConfigFile {
        toml::from_str(toml).expect("config file TOML")
    }

    fn driver_table(toml: &str) -> toml::Value {
        toml::from_str(toml).expect("driver table TOML")
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
        let registry = CredentialDriverRegistry::from_config(&Config::new(None)).unwrap();

        assert_eq!(
            registry.storage_owner_name().as_str(),
            DbCredstoreCredentialDriver::NAME
        );
    }

    #[test]
    fn registry_allows_legacy_inline_credentials_with_default_driver() {
        let registry = CredentialDriverRegistry::from_config(&Config::new(None)).unwrap();

        registry
            .validate_provider_handles(&Provider::default())
            .expect("legacy inline provider should not require credential handles");
    }

    #[test]
    fn registry_rejects_default_driver_without_external_driver() {
        let config = Config::new(None).with_default_credential_driver(Some("vault"));

        let err = CredentialDriverRegistry::from_config(&config).unwrap_err();

        assert!(err.to_string().contains("default_credential_driver"));
        assert!(err.to_string().contains("requires credential_drivers"));
    }

    #[test]
    fn registry_rejects_empty_handle_driver() {
        let config = Config::new(None).with_credential_drivers(["test-static"]);
        let registry = CredentialDriverRegistry::from_config(&config).unwrap();

        let err = registry
            .validate_provider_handles(&provider_with_handle("", "openai/API_KEY"))
            .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("missing driver"));
    }

    #[test]
    fn registry_rejects_empty_handle_value() {
        let config = Config::new(None).with_credential_drivers(["test-static"]);
        let registry = CredentialDriverRegistry::from_config(&config).unwrap();

        let err = registry
            .validate_provider_handles(&provider_with_handle("test-static", ""))
            .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("missing handle"));
    }

    #[test]
    fn registry_rejects_unknown_handle_driver() {
        let config = Config::new(None).with_credential_drivers(["test-static"]);
        let registry = CredentialDriverRegistry::from_config(&config).unwrap();

        let err = registry
            .validate_provider_handles(&provider_with_handle("vault", "openai/API_KEY"))
            .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("not enabled"));
    }

    #[test]
    fn registry_rejects_default_driver_not_enabled() {
        let config = Config::new(None)
            .with_credential_drivers(["test-static"])
            .with_default_credential_driver(Some("vault"));

        let err = CredentialDriverRegistry::from_config(&config).unwrap_err();

        assert!(err.to_string().contains("default_credential_driver"));
        assert!(err.to_string().contains("not listed"));
    }

    #[test]
    fn registry_rejects_multiple_enabled_drivers() {
        let config = Config::new(None).with_credential_drivers(["test-static", "vault"]);

        let err = CredentialDriverRegistry::from_config(&config).unwrap_err();

        assert!(err.to_string().contains("at most one"));
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
    }

    #[tokio::test]
    async fn runtime_overwrites_existing_test_static_handle() {
        let config = Config::new(None).with_credential_drivers(["test-static"]);
        let runtime = CredentialRuntime::from_config(&config).unwrap();
        let first = runtime
            .store_provider_credentials(
                "openai-local",
                &HashMap::from([("OPENAI_API_KEY".to_string(), "sk-first".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        let second = runtime
            .store_provider_credentials(
                "openai-local",
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
                &HashMap::from([("OPENAI_API_KEY".to_string(), "sk-test".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();

        runtime
            .delete_provider_credential_handles("openai-local", &stored)
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
        let file = config_file(&format!(
            r#"
[openshell.credential_drivers.vault]
transport = "in_tree"
address = "http://127.0.0.1:8200"
auth_method = "token_file"
token_path = "{}"
"#,
            token_file.path().display()
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
        let file = config_file(&format!(
            r#"
[openshell.gateway.credential_storage]
key_encryption_key_path = "{}"
"#,
            key_encryption_key_path.display()
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
            .get(DbCredstoreCredentialDriver::OBJECT_TYPE, handle_id)
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

    #[test]
    fn parse_uds_driver_launch_settings() {
        let parsed = parse_driver_table(
            "enterprise-secrets",
            &driver_table(
                r#"
transport = "uds"
socket_path = "/tmp/openshell-enterprise-secrets.sock"
command = "/usr/local/libexec/openshell-credential-driver-enterprise-secrets"
args = ["--profile", "dev"]
startup_timeout_secs = 3
"#,
            ),
        )
        .unwrap();

        assert_eq!(parsed.transport, CredentialDriverTransport::Uds);
        assert_eq!(
            parsed.socket_path.as_deref(),
            Some(Path::new("/tmp/openshell-enterprise-secrets.sock"))
        );
        assert_eq!(
            parsed.command.as_deref(),
            Some(Path::new(
                "/usr/local/libexec/openshell-credential-driver-enterprise-secrets"
            ))
        );
        assert_eq!(parsed.args, ["--profile", "dev"]);
        assert_eq!(parsed.startup_timeout_secs, 3);
    }

    #[test]
    fn parse_uds_driver_defaults_to_connect_only() {
        let parsed = parse_driver_table(
            "enterprise-secrets",
            &driver_table(
                r#"
transport = "uds"
socket_path = "/tmp/openshell-enterprise-secrets.sock"
"#,
            ),
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

    #[test]
    fn parse_driver_table_preserves_backend_config_without_transport_fields() {
        let parsed = parse_driver_table(
            "kubernetes-secrets",
            &driver_table(
                r#"
transport = "in_tree"
namespace = "openshell"
allow_reference_namespace = true
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
        assert_eq!(
            parsed
                .backend_config
                .get("allow_reference_namespace")
                .and_then(toml::Value::as_bool),
            Some(true)
        );
        assert!(!parsed.backend_config.contains_key("transport"));
    }

    #[test]
    fn parse_uds_driver_rejects_relative_command() {
        let err = parse_driver_table(
            "enterprise-secrets",
            &driver_table(
                r#"
transport = "uds"
socket_path = "/tmp/openshell-enterprise-secrets.sock"
command = "openshell-credential-driver-enterprise-secrets"
"#,
            ),
        )
        .unwrap_err();

        assert!(err.to_string().contains("command must be absolute"));
    }

    #[test]
    fn parse_uds_driver_rejects_args_without_command() {
        let err = parse_driver_table(
            "enterprise-secrets",
            &driver_table(
                r#"
transport = "uds"
socket_path = "/tmp/openshell-enterprise-secrets.sock"
args = ["--profile", "dev"]
"#,
            ),
        )
        .unwrap_err();

        assert!(err.to_string().contains("args requires command"));
    }

    #[test]
    fn parse_uds_driver_rejects_timeout_without_command() {
        let err = parse_driver_table(
            "enterprise-secrets",
            &driver_table(
                r#"
transport = "uds"
socket_path = "/tmp/openshell-enterprise-secrets.sock"
startup_timeout_secs = 3
"#,
            ),
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
