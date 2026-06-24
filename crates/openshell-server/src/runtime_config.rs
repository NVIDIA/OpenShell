// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway runtime settings file support.
//!
//! Runtime settings are persisted through the existing gateway-global settings
//! record so the normal `GetSandboxConfig` revision path carries changes to
//! running sandboxes.

use crate::Store;
use crate::grpc::policy::{load_global_settings, save_global_settings};
use crate::grpc::{StoredSettingValue, StoredSettings};
use openshell_core::settings::{self, SettingValueKind};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::{Mutex, watch};
use tonic::Code;
use tracing::{debug, info, warn};

const RUNTIME_CONFIG_SCHEMA_VERSION: u32 = 1;
const WATCH_INTERVAL: Duration = Duration::from_secs(2);
const APPLY_RETRY_LIMIT: usize = 5;

/// Tracks runtime settings currently owned by the runtime config file.
#[derive(Debug, Clone, Default)]
pub struct RuntimeSettingsState {
    managed_keys: Arc<RwLock<BTreeSet<String>>>,
}

impl RuntimeSettingsState {
    pub fn is_managed_key(&self, key: &str) -> bool {
        self.managed_keys
            .read()
            .expect("runtime settings lock poisoned")
            .contains(key)
    }

    pub fn set_managed_keys<I>(&self, keys: I)
    where
        I: IntoIterator<Item = String>,
    {
        *self
            .managed_keys
            .write()
            .expect("runtime settings lock poisoned") = keys.into_iter().collect();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSettingsDocument {
    settings: BTreeMap<String, StoredSettingValue>,
}

impl RuntimeSettingsDocument {
    fn managed_keys(&self) -> impl Iterator<Item = String> + '_ {
        self.settings.keys().cloned()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeConfigError {
    #[error("failed to read runtime config file '{}': {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse runtime config file '{}': {source}", path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error(
        "unsupported runtime config version {version}; this build only supports version {RUNTIME_CONFIG_SCHEMA_VERSION}"
    )]
    UnsupportedVersion { version: u32 },
    #[error("runtime config setting 'policy' is reserved; use global policy APIs instead")]
    ReservedPolicySetting,
    #[error("unknown runtime config setting '{key}'. Allowed keys: {allowed}")]
    UnknownSetting { key: String, allowed: String },
    #[error("runtime config setting '{key}' expects {expected} value; got {actual}")]
    TypeMismatch {
        key: String,
        expected: &'static str,
        actual: &'static str,
    },
    #[error("runtime config setting '{key}' expects one of [{allowed}]; got '{value}'")]
    InvalidStringValue {
        key: String,
        allowed: String,
        value: String,
    },
    #[error("failed to persist runtime settings from '{}': {message}", path.display())]
    Persist { path: PathBuf, message: String },
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeConfig {
    #[serde(default)]
    openshell: RawOpenShellRuntimeRoot,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOpenShellRuntimeRoot {
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    runtime: RawRuntimeSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeSection {
    // Keep this as a key/value map so runtime config files use the same
    // openshell_core::settings registry as CLI and gRPC settings writes.
    #[serde(default)]
    settings: BTreeMap<String, toml::Value>,
}

pub fn load(path: &Path) -> Result<RuntimeSettingsDocument, RuntimeConfigError> {
    let contents = fs::read_to_string(path).map_err(|source| RuntimeConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse(path, &contents)
}

fn parse(path: &Path, contents: &str) -> Result<RuntimeSettingsDocument, RuntimeConfigError> {
    if contents.trim().is_empty() {
        return Ok(RuntimeSettingsDocument {
            settings: BTreeMap::new(),
        });
    }

    let raw: RawRuntimeConfig =
        toml::from_str(contents).map_err(|source| RuntimeConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;

    if let Some(version) = raw.openshell.version
        && version > RUNTIME_CONFIG_SCHEMA_VERSION
    {
        return Err(RuntimeConfigError::UnsupportedVersion { version });
    }

    let mut parsed = BTreeMap::new();
    for (key, value) in raw.openshell.runtime.settings {
        let stored = parse_setting_value(&key, &value)?;
        parsed.insert(key, stored);
    }

    Ok(RuntimeSettingsDocument { settings: parsed })
}

fn parse_setting_value(
    key: &str,
    value: &toml::Value,
) -> Result<StoredSettingValue, RuntimeConfigError> {
    if key == "policy" {
        return Err(RuntimeConfigError::ReservedPolicySetting);
    }

    let setting =
        settings::setting_for_key(key).ok_or_else(|| RuntimeConfigError::UnknownSetting {
            key: key.to_string(),
            allowed: settings::registered_keys_csv(),
        })?;

    match (setting.kind, value) {
        (SettingValueKind::Bool, toml::Value::Boolean(value)) => {
            Ok(StoredSettingValue::Bool(*value))
        }
        (SettingValueKind::Int, toml::Value::Integer(value)) => Ok(StoredSettingValue::Int(*value)),
        (SettingValueKind::String, toml::Value::String(value)) => {
            if let Err(allowed) = setting.validate_string_value(value) {
                return Err(RuntimeConfigError::InvalidStringValue {
                    key: key.to_string(),
                    allowed: allowed.join(", "),
                    value: value.clone(),
                });
            }
            Ok(StoredSettingValue::String(value.clone()))
        }
        (kind, value) => Err(RuntimeConfigError::TypeMismatch {
            key: key.to_string(),
            expected: kind.as_str(),
            actual: toml_value_kind(value),
        }),
    }
}

fn toml_value_kind(value: &toml::Value) -> &'static str {
    match value {
        toml::Value::String(_) => "string",
        toml::Value::Integer(_) => "int",
        toml::Value::Float(_) => "float",
        toml::Value::Boolean(_) => "bool",
        toml::Value::Datetime(_) => "datetime",
        toml::Value::Array(_) => "array",
        toml::Value::Table(_) => "table",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeSettingsApplyOutcome {
    pub changed: bool,
    pub revision: u64,
    pub managed_key_count: usize,
}

pub async fn apply_file(
    path: &Path,
    store: &Store,
    settings_mutex: &Mutex<()>,
    state: &RuntimeSettingsState,
) -> Result<RuntimeSettingsApplyOutcome, RuntimeConfigError> {
    let document = load(path)?;
    apply_document(path, document, store, settings_mutex, state).await
}

pub async fn apply_document(
    path: &Path,
    document: RuntimeSettingsDocument,
    store: &Store,
    settings_mutex: &Mutex<()>,
    state: &RuntimeSettingsState,
) -> Result<RuntimeSettingsApplyOutcome, RuntimeConfigError> {
    let _guard = settings_mutex.lock().await;

    for attempt in 1..=APPLY_RETRY_LIMIT {
        let mut global =
            load_global_settings(store)
                .await
                .map_err(|status| RuntimeConfigError::Persist {
                    path: path.to_path_buf(),
                    message: status.message().to_string(),
                })?;

        let changed = upsert_runtime_settings(&mut global, &document);
        if changed {
            global.revision = global.revision.wrapping_add(1);
            match save_global_settings(store, &global).await {
                Ok(()) => {}
                Err(status) if status.code() == Code::Aborted && attempt < APPLY_RETRY_LIMIT => {
                    debug!(
                        path = %path.display(),
                        attempt,
                        "runtime config settings write conflicted; retrying"
                    );
                    continue;
                }
                Err(status) => {
                    return Err(RuntimeConfigError::Persist {
                        path: path.to_path_buf(),
                        message: status.message().to_string(),
                    });
                }
            }
        }

        let managed_key_count = document.settings.len();
        state.set_managed_keys(document.managed_keys());

        return Ok(RuntimeSettingsApplyOutcome {
            changed,
            revision: global.revision,
            managed_key_count,
        });
    }

    Err(RuntimeConfigError::Persist {
        path: path.to_path_buf(),
        message: "settings were modified concurrently; retry limit exceeded".to_string(),
    })
}

fn upsert_runtime_settings(
    global: &mut StoredSettings,
    document: &RuntimeSettingsDocument,
) -> bool {
    let mut changed = false;
    for (key, value) in &document.settings {
        if global.settings.get(key) != Some(value) {
            global.settings.insert(key.clone(), value.clone());
            changed = true;
        }
    }
    changed
}

pub fn spawn_watcher(
    state: Arc<crate::ServerState>,
    path: PathBuf,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut snapshot = RuntimeFileSnapshot::capture(&path);
        let mut interval = tokio::time::interval(WATCH_INTERVAL);

        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        debug!(
                            path = %path.display(),
                            "runtime config watcher shutting down"
                        );
                        break;
                    }
                }
                _ = interval.tick() => {
                    let next = RuntimeFileSnapshot::capture(&path);
                    if next == snapshot {
                        continue;
                    }
                    snapshot = next;
                    match apply_file(
                        &path,
                        state.store.as_ref(),
                        &state.settings_mutex,
                        &state.runtime_settings,
                    ).await {
                        Ok(outcome) => info!(
                            path = %path.display(),
                            changed = outcome.changed,
                            settings_revision = outcome.revision,
                            managed_key_count = outcome.managed_key_count,
                            "runtime config file reloaded"
                        ),
                        Err(err) => warn!(
                            path = %path.display(),
                            error = %err,
                            "runtime config reload failed; keeping last valid settings"
                        ),
                    }
                }
            }
        }
    });
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeFileSnapshot {
    symlink: Option<FileMetadataSnapshot>,
    target: Option<FileMetadataSnapshot>,
    parent: Option<FileMetadataSnapshot>,
}

impl RuntimeFileSnapshot {
    fn capture(path: &Path) -> Self {
        let parent = path.parent().and_then(|parent| {
            fs::metadata(parent)
                .ok()
                .map(FileMetadataSnapshot::from_metadata)
        });
        let symlink = fs::symlink_metadata(path)
            .ok()
            .map(FileMetadataSnapshot::from_metadata);
        let target = fs::metadata(path)
            .ok()
            .map(FileMetadataSnapshot::from_metadata);
        Self {
            symlink,
            target,
            parent,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileMetadataSnapshot {
    len: u64,
    modified: Option<SystemTime>,
    is_dir: bool,
    is_file: bool,
    is_symlink: bool,
}

impl FileMetadataSnapshot {
    fn from_metadata(metadata: fs::Metadata) -> Self {
        let file_type = metadata.file_type();
        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            is_dir: file_type.is_dir(),
            is_file: file_type.is_file(),
            is_symlink: file_type.is_symlink(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::test_store;
    use std::io::Write;

    fn parse_test(contents: &str) -> Result<RuntimeSettingsDocument, RuntimeConfigError> {
        parse(Path::new("/runtime.toml"), contents)
    }

    #[test]
    fn parses_registered_runtime_settings() {
        let doc = parse_test(
            r#"
[openshell.runtime.settings]
providers_v2_enabled = true
proposal_approval_mode = "auto"
"#,
        )
        .expect("runtime config parses");

        assert_eq!(
            doc.settings.get(settings::PROVIDERS_V2_ENABLED_KEY),
            Some(&StoredSettingValue::Bool(true))
        );
        assert_eq!(
            doc.settings.get(settings::PROPOSAL_APPROVAL_MODE_KEY),
            Some(&StoredSettingValue::String("auto".to_string()))
        );
    }

    #[test]
    fn rejects_unknown_setting() {
        let err = parse_test(
            r"
[openshell.runtime.settings]
unknown_key = true
",
        )
        .expect_err("unknown setting must be rejected");
        assert!(matches!(err, RuntimeConfigError::UnknownSetting { .. }));
    }

    #[test]
    fn rejects_reserved_policy_setting() {
        let err = parse_test(
            r#"
[openshell.runtime.settings]
policy = "deadbeef"
"#,
        )
        .expect_err("policy must be rejected");
        assert!(matches!(err, RuntimeConfigError::ReservedPolicySetting));
    }

    #[test]
    fn rejects_type_mismatch() {
        let err = parse_test(
            r#"
[openshell.runtime.settings]
providers_v2_enabled = "true"
"#,
        )
        .expect_err("bool key must reject string value");
        assert!(matches!(
            err,
            RuntimeConfigError::TypeMismatch {
                expected: "bool",
                actual: "string",
                ..
            }
        ));
    }

    #[test]
    fn rejects_invalid_string_value() {
        let err = parse_test(
            r#"
[openshell.runtime.settings]
proposal_approval_mode = "autom"
"#,
        )
        .expect_err("invalid enum value must be rejected");
        assert!(matches!(err, RuntimeConfigError::InvalidStringValue { .. }));
    }

    #[tokio::test]
    async fn apply_file_preserves_unmanaged_global_settings() {
        let mut tmp = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("tempfile");
        tmp.write_all(
            br"
[openshell.runtime.settings]
providers_v2_enabled = true
",
        )
        .expect("write runtime config");

        let store = test_store().await;
        let settings_mutex = Mutex::new(());
        let runtime_state = RuntimeSettingsState::default();

        let mut existing = StoredSettings::default();
        existing.settings.insert(
            "unmanaged_future_setting".to_string(),
            StoredSettingValue::String("keep".to_string()),
        );
        existing.revision = 7;
        save_global_settings(&store, &existing).await.unwrap();

        let outcome = apply_file(tmp.path(), &store, &settings_mutex, &runtime_state)
            .await
            .expect("apply runtime config");
        assert!(outcome.changed);
        assert_eq!(outcome.revision, 8);
        assert!(runtime_state.is_managed_key(settings::PROVIDERS_V2_ENABLED_KEY));

        let loaded = load_global_settings(&store).await.unwrap();
        assert_eq!(
            loaded.settings.get("unmanaged_future_setting"),
            Some(&StoredSettingValue::String("keep".to_string()))
        );
        assert_eq!(
            loaded.settings.get(settings::PROVIDERS_V2_ENABLED_KEY),
            Some(&StoredSettingValue::Bool(true))
        );
    }

    #[tokio::test]
    async fn apply_file_overrides_only_keys_defined_in_runtime_config() {
        let mut tmp = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("tempfile");
        tmp.write_all(
            br"
[openshell.runtime.settings]
providers_v2_enabled = true
",
        )
        .expect("write runtime config");

        let store = test_store().await;
        let settings_mutex = Mutex::new(());
        let runtime_state = RuntimeSettingsState::default();

        let mut existing = StoredSettings::default();
        existing.settings.insert(
            settings::PROVIDERS_V2_ENABLED_KEY.to_string(),
            StoredSettingValue::Bool(false),
        );
        existing.settings.insert(
            "ocsf_json_enabled".to_string(),
            StoredSettingValue::Bool(true),
        );
        existing.revision = 3;
        save_global_settings(&store, &existing).await.unwrap();

        let outcome = apply_file(tmp.path(), &store, &settings_mutex, &runtime_state)
            .await
            .expect("apply runtime config");
        assert!(outcome.changed);
        assert_eq!(outcome.revision, 4);
        assert!(runtime_state.is_managed_key(settings::PROVIDERS_V2_ENABLED_KEY));
        assert!(!runtime_state.is_managed_key("ocsf_json_enabled"));

        let loaded = load_global_settings(&store).await.unwrap();
        assert_eq!(
            loaded.settings.get(settings::PROVIDERS_V2_ENABLED_KEY),
            Some(&StoredSettingValue::Bool(true)),
            "key defined in runtime config must override the stored global value"
        );
        assert_eq!(
            loaded.settings.get("ocsf_json_enabled"),
            Some(&StoredSettingValue::Bool(true)),
            "key omitted from runtime config must keep its stored global value"
        );
    }

    #[tokio::test]
    async fn apply_file_updates_managed_keys_when_file_removes_a_key() {
        let store = test_store().await;
        let settings_mutex = Mutex::new(());
        let runtime_state = RuntimeSettingsState::default();

        let path = Path::new("/runtime.toml");
        let first = parse_test(
            r"
[openshell.runtime.settings]
providers_v2_enabled = true
ocsf_json_enabled = true
",
        )
        .unwrap();
        apply_document(path, first, &store, &settings_mutex, &runtime_state)
            .await
            .unwrap();
        assert!(runtime_state.is_managed_key("ocsf_json_enabled"));

        let second = parse_test(
            r"
[openshell.runtime.settings]
providers_v2_enabled = true
",
        )
        .unwrap();
        let outcome = apply_document(path, second, &store, &settings_mutex, &runtime_state)
            .await
            .unwrap();
        assert!(!outcome.changed);
        assert!(!runtime_state.is_managed_key("ocsf_json_enabled"));

        let loaded = load_global_settings(&store).await.unwrap();
        assert_eq!(
            loaded.settings.get("ocsf_json_enabled"),
            Some(&StoredSettingValue::Bool(true)),
            "removing a key from the file must not delete the last persisted global value"
        );
    }

    #[tokio::test]
    async fn apply_file_propagates_added_runtime_key_as_authoritative() {
        let store = test_store().await;
        let settings_mutex = Mutex::new(());
        let runtime_state = RuntimeSettingsState::default();

        let mut existing = StoredSettings::default();
        existing.settings.insert(
            "ocsf_json_enabled".to_string(),
            StoredSettingValue::Bool(false),
        );
        existing.revision = 9;
        save_global_settings(&store, &existing).await.unwrap();

        let path = Path::new("/runtime.toml");
        let first = parse_test(
            r"
[openshell.runtime.settings]
providers_v2_enabled = true
",
        )
        .unwrap();
        apply_document(path, first, &store, &settings_mutex, &runtime_state)
            .await
            .unwrap();
        assert!(!runtime_state.is_managed_key("ocsf_json_enabled"));

        let second = parse_test(
            r"
[openshell.runtime.settings]
providers_v2_enabled = true
ocsf_json_enabled = true
",
        )
        .unwrap();
        let outcome = apply_document(path, second, &store, &settings_mutex, &runtime_state)
            .await
            .unwrap();
        assert!(outcome.changed);
        assert_eq!(outcome.revision, 11);
        assert!(runtime_state.is_managed_key("ocsf_json_enabled"));

        let loaded = load_global_settings(&store).await.unwrap();
        assert_eq!(
            loaded.settings.get("ocsf_json_enabled"),
            Some(&StoredSettingValue::Bool(true)),
            "adding a key to the runtime config file must persist and publish that file value"
        );
    }

    #[test]
    fn file_snapshot_changes_after_rewrite() {
        let mut tmp = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("tempfile");
        tmp.write_all(b"one").expect("write first");
        let first = RuntimeFileSnapshot::capture(tmp.path());
        std::thread::sleep(Duration::from_millis(10));
        tmp.as_file_mut().set_len(0).expect("truncate");
        tmp.write_all(b"two-two").expect("write second");
        tmp.as_file_mut().sync_all().expect("sync");
        let second = RuntimeFileSnapshot::capture(tmp.path());
        assert_ne!(first, second);
    }
}
