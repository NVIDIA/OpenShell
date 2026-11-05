// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Extracted credential-driver implementation.

use super::CredentialDriver;
#[cfg(any(test, feature = "test-support"))]
use super::TestStaticCredentialDriver;
use super::transport::{ManagedCredentialDriverProcess, connect_uds_driver};
use crate::{Handles, IssuerConfig};
use openshell_core::extension_protocol::{
    ExtensionFamily, NegotiatedExtension, extension_metadata, gateway_metadata, negotiate,
};
use openshell_core::proto::CredentialHandle;
use openshell_core::{Error, Result as CoreResult};
use openshell_driver_db_credstore::{DbCredstoreCredentialDriver, DbCredstoreObjectStore};
use openshell_driver_kubernetes_secrets::KubernetesSecretsCredentialDriver;
use openshell_driver_vault::VaultCredentialDriver;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use tonic::Status;
pub(super) const DEFAULT_CREDENTIAL_DRIVER_STARTUP_TIMEOUT_SECS: u64 = 10;
const COMMON_CREDENTIAL_DRIVER_FIELDS: &[&str] = &[
    "transport",
    "socket_path",
    "command",
    "args",
    "startup_timeout_secs",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BuiltinCredentialDriverKind {
    KubernetesSecrets,
    Vault,
    #[cfg(any(test, feature = "test-support"))]
    TestStatic,
}

impl BuiltinCredentialDriverKind {
    pub(super) fn from_name(name: &str) -> Option<Self> {
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
pub(super) fn builtin_credential_driver_names() -> &'static [&'static str] {
    &[
        KubernetesSecretsCredentialDriver::NAME,
        VaultCredentialDriver::NAME,
        TestStaticCredentialDriver::NAME,
    ]
}

#[cfg(not(any(test, feature = "test-support")))]
pub(super) fn builtin_credential_driver_names() -> &'static [&'static str] {
    &[
        KubernetesSecretsCredentialDriver::NAME,
        VaultCredentialDriver::NAME,
    ]
}

pub(super) fn unknown_credential_driver_error(driver_name: &str) -> Error {
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
    pub fn from_config(config: &IssuerConfig) -> CoreResult<Self> {
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

    pub(super) fn requires_default_store(&self) -> bool {
        self.enabled.is_empty()
    }

    pub fn validate_handles(&self, handles: &Handles) -> Result<(), Status> {
        for (credential_key, handle) in handles {
            self.driver_for_handle(credential_key, handle)?;
        }

        Ok(())
    }

    pub(super) fn enabled_driver_names(&self) -> impl Iterator<Item = &String> {
        self.enabled.iter()
    }

    pub(super) fn driver_for_handle(
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

pub(super) fn normalize_driver_name(driver: &str) -> String {
    driver.trim().to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CredentialDriverTransport {
    InTree,
    Uds,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct ConfiguredCredentialDriver {
    pub(super) transport: CredentialDriverTransport,
    pub(super) socket_path: Option<PathBuf>,
    pub(super) command: Option<PathBuf>,
    pub(super) args: Vec<String>,
    pub(super) startup_timeout_secs: u64,
    pub(super) backend_config: toml::Table,
}

pub(super) fn parse_driver_table(
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

pub(super) fn backend_config_table(table: &toml::Table) -> toml::Table {
    let mut backend_config = table.clone();
    for field in COMMON_CREDENTIAL_DRIVER_FIELDS {
        backend_config.remove(*field);
    }
    backend_config
}

pub(super) fn string_field(
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

pub(super) fn string_array_field(
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

pub(super) fn positive_integer_field(
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

pub(super) fn connect_default_credential_store(
    drivers: &mut BTreeMap<String, Arc<dyn CredentialDriver>>,
    store: Option<Arc<dyn DbCredstoreObjectStore>>,
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

    let object_store = store;
    let storage: Arc<dyn CredentialDriver> = Arc::new(DbCredstoreCredentialDriver::from_config(
        object_store,
        config,
    )?);
    drivers.insert(DbCredstoreCredentialDriver::NAME.to_string(), storage);
    Ok(())
}

pub(super) fn negotiate_builtin_credential_driver(name: &str) -> CoreResult<NegotiatedExtension> {
    let gateway = gateway_metadata(ExtensionFamily::Credentials);
    negotiate(
        ExtensionFamily::Credentials,
        name,
        &gateway,
        Some(extension_metadata(
            ExtensionFamily::Credentials,
            format!("openshell/{name}"),
            openshell_core::VERSION,
            [],
        )),
    )
    .map_err(|error| Error::config(error.to_string()))
}

#[derive(Debug)]
pub(super) struct BuiltCredentialDriver {
    pub(super) driver: Arc<dyn CredentialDriver>,
    pub(super) process: Option<Arc<ManagedCredentialDriverProcess>>,
    pub(super) negotiated_extension: NegotiatedExtension,
}

pub(super) async fn build_configured_driver(
    driver_name: &str,
    config: ConfiguredCredentialDriver,
    store: Option<Arc<dyn DbCredstoreObjectStore>>,
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
                negotiated_extension: negotiate_builtin_credential_driver(driver_name)?,
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

pub(super) async fn build_default_in_tree_driver(
    driver_name: &str,
    store: Option<Arc<dyn DbCredstoreObjectStore>>,
) -> CoreResult<Arc<dyn CredentialDriver>> {
    build_in_tree_driver(driver_name, None, store)
        .await?
        .ok_or_else(|| unknown_credential_driver_error(driver_name))
}

pub(super) async fn build_in_tree_driver(
    name: &str,
    backend_config: Option<&toml::Table>,
    _store: Option<Arc<dyn DbCredstoreObjectStore>>,
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

pub(super) fn build_sync_builtin_driver(
    name: &str,
    _store: Option<Arc<dyn DbCredstoreObjectStore>>,
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
