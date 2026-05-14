// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MXC `ContainerConfig` types for schema version `0.6.0-dev`.
//!
//! This dev schema is **only** used by the IsolationSession backend. It
//! reuses most of the alpha schema but carries an additional
//! `containment = "isolation_session"` discriminant and an
//! `experimental.isolation_session.configurationId` field. The `wxc-exec`
//! invocation **must** include `--experimental` for any config that targets
//! this backend (see [`crate::Schema::DevIsolationSession`]).
//!
//! The shape here is reverse-engineered from the Phase 2 spike
//! (`Finding 3c`); the upstream SDK does not export a strongly typed
//! IsolationSession config. Field names are educated guesses where the
//! spike is silent — flagged below with `ASSUMPTION:` comments.

use serde::{Deserialize, Serialize};

pub use crate::schema_alpha::{
    ClipboardPolicy, DefaultNetworkPolicy, EnforcementMode, FilesystemConfig, LifecycleConfig,
    NetworkConfig, ProcessConfig, Proxy, UiConfig,
};

/// Schema version string emitted in the JSON `version` field.
pub const SCHEMA_VERSION: &str = "0.6.0-dev";

/// Containment discriminant. Currently only `IsolationSession` is meaningful
/// on the dev schema path; alpha-style backends should use the alpha module.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Containment {
    IsolationSession,
}

/// Top-level MXC IsolationSession container configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerConfig {
    /// Schema version (semver). Always [`SCHEMA_VERSION`].
    pub version: String,

    /// Externally assigned container identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,

    /// Always `IsolationSession` for this schema; emitted as
    /// `"isolation_session"` in JSON.
    pub containment: Containment,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LifecycleConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<FilesystemConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui: Option<UiConfig>,

    /// Experimental configuration. Required for IsolationSession.
    pub experimental: Experimental,
}

/// Experimental config block. Only the IsolationSession sub-section is
/// modelled here; other experimental backends (WSLC, seatbelt) are out of
/// scope for this crate.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Experimental {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolation_session: Option<IsolationSessionConfig>,
}

/// IsolationSession-specific settings.
///
/// ASSUMPTION: only `configurationId` is documented in the spike. Additional
/// fields (e.g. profile selectors, broker overrides) will be added when the
/// dev schema firms up.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IsolationSessionConfig {
    /// Opaque identifier for the IsolationSession runner's pre-registered
    /// configuration entry. Required by the IsolationBroker on the host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_id: Option<String>,
}
