// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MXC `ContainerConfig` types for schema version `0.5.0-alpha`.
//!
//! Mirrors the wire shape produced by the upstream `mxc-aegis` SDK
//! (`sdk/src/types.ts`). Field naming is `camelCase` over JSON; field
//! presence (`Option`/`skip_serializing_if`) matches the SDK's behaviour.
//!
//! This file intentionally tracks the SDK shape — not the MXC config schema
//! reference — because the SDK is what `wxc-exec` actually consumes for
//! AppContainer (Windows process container) workloads. Notably the SDK uses
//! `appContainer` while the schema doc lists `processContainer` for the
//! older `0.4.0-alpha` schema (renamed in `0.5.0-alpha`).

use serde::{Deserialize, Serialize};

/// Schema version string emitted in the JSON `version` field.
pub const SCHEMA_VERSION: &str = "0.5.0-alpha";

/// Top-level MXC AppContainer container configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerConfig {
    /// Schema version (semver). Always [`SCHEMA_VERSION`] for this module.
    pub version: String,

    /// Externally assigned container identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,

    /// Container lifecycle settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LifecycleConfig>,

    /// Process execution settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessConfig>,

    /// AppContainer (Windows process container) settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_container: Option<AppContainerConfig>,

    /// Filesystem access policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<FilesystemConfig>,

    /// Network access policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkConfig>,

    /// Cross-platform UI configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui: Option<UiConfig>,
}

/// Container lifecycle settings shared across MXC backends.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleConfig {
    /// Destroy the container after execution completes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destroy_on_exit: Option<bool>,
    /// Retain filesystem and network policies after execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preserve_policy: Option<bool>,
}

/// Process execution settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessConfig {
    /// Complete command line to execute. Required by the runner; the
    /// translator emits the empty string and expects callers to fill it.
    pub command_line: String,
    /// Working directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Environment variables as `KEY=VALUE` strings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// Execution timeout in milliseconds. `0` (or omitted) means no timeout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
}

/// Filesystem access policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub readwrite_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub readonly_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_paths: Vec<String>,
}

/// Network enforcement mode (Windows-specific in upstream).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EnforcementMode {
    Capabilities,
    Firewall,
    Both,
}

/// Default network policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DefaultNetworkPolicy {
    Allow,
    Block,
}

/// Network access policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_mode: Option<EnforcementMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_policy: Option<DefaultNetworkPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_hosts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<Proxy>,
}

/// Proxy configuration (Windows only — translator returns an error if
/// requested for a Linux target, mirroring the upstream SDK).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Proxy {
    BuiltinTestServer { builtin_test_server: bool },
    Localhost { localhost: u16 },
    Url { url: String },
}

/// AppContainer (Windows) configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppContainerConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub least_privilege: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui: Option<BaseProcessUiConfig>,
}

/// UI isolation level for the AppContainer process.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UiIsolation {
    Desktop,
    Handles,
    Atoms,
    Container,
}

/// Windows-only AppContainer UI settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BaseProcessUiConfig {
    pub isolation: UiIsolation,
    pub desktop_system_control: bool,
    pub system_settings: String,
    pub ime: bool,
}

impl Default for BaseProcessUiConfig {
    fn default() -> Self {
        Self {
            isolation: UiIsolation::Container,
            desktop_system_control: false,
            system_settings: "none".to_owned(),
            ime: false,
        }
    }
}

/// Clipboard access policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ClipboardPolicy {
    None,
    Read,
    Write,
    All,
}

impl Default for ClipboardPolicy {
    fn default() -> Self {
        Self::None
    }
}

/// Cross-platform UI configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UiConfig {
    pub disable: bool,
    pub clipboard: ClipboardPolicy,
    pub injection: bool,
}

impl Default for UiConfig {
    fn default() -> Self {
        // Mirrors the upstream SDK default: most-restrictive.
        Self {
            disable: true,
            clipboard: ClipboardPolicy::None,
            injection: false,
        }
    }
}
