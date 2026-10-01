// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Rust guideline compliant 2026-09-19

//! Canonical Cedar schema for `OpenShell`'s experimental Cedar policy engine.
//!
//! This crate owns the single `.cedarschema` source that every Cedar-aware
//! consumer (currently `openshell-policy-cedar`) parses against, plus the
//! entity-type and action name constants that source declares. Consumers
//! reference [`entity_types`] and [`actions`] instead of writing schema
//! string literals of their own, so a renamed entity or action fails to
//! compile at every call site instead of silently drifting.
//! `tests/schema_consistency.rs` asserts the constants stay in sync with the
//! schema.

mod error;

pub use error::CedarSchemaLoadError;

use cedar_policy::Schema;

/// Canonical `.cedarschema` source for the `OpenShell` `Sandbox` namespace.
pub const SANDBOX_SCHEMA_SRC: &str = include_str!("../schema/sandbox.cedarschema");

/// Entity type names declared in [`SANDBOX_SCHEMA_SRC`].
pub mod entity_types {
    /// A sandboxed process; the principal for every sandbox action.
    pub const PROCESS: &str = "Sandbox::Process";
    /// The user identity a [`PROCESS`] runs as.
    pub const USER: &str = "Sandbox::User";
    /// The group identity a [`PROCESS`] runs as.
    pub const GROUP: &str = "Sandbox::Group";
    /// A filesystem path; resource for the `ReadFile`/`WriteFile` actions.
    pub const FILESYSTEM_PATH: &str = "Sandbox::FilesystemPath";
    /// A network destination; resource for the `NetworkConnect` action.
    pub const NETWORK_ENDPOINT: &str = "Sandbox::NetworkEndpoint";
}

/// Action names declared in [`SANDBOX_SCHEMA_SRC`], all in the
/// [`actions::ACTION_TYPE`] entity type.
pub mod actions {
    /// Cedar entity type name shared by every action.
    pub const ACTION_TYPE: &str = "Sandbox::Action";
    /// Read a file at a [`super::entity_types::FILESYSTEM_PATH`].
    pub const READ_FILE: &str = "ReadFile";
    /// Write a file at a [`super::entity_types::FILESYSTEM_PATH`].
    pub const WRITE_FILE: &str = "WriteFile";
    /// Open a connection to a [`super::entity_types::NETWORK_ENDPOINT`].
    pub const NETWORK_CONNECT: &str = "NetworkConnect";
}

/// `NetworkConnect`'s `context` record attribute names.
///
/// Declared in [`SANDBOX_SCHEMA_SRC`]. `String`-typed attributes take `""`
/// for requests where they don't apply (e.g. `COMMAND` for a REST request).
pub mod context_fields {
    /// Absolute path of the calling binary (plain string, not an entity).
    pub const BINARY_PATH: &str = "binary_path";
    /// `Set<String>` of the calling process's ancestor binary paths.
    pub const ANCESTORS: &str = "ancestors";
    /// HTTP method for REST requests.
    pub const METHOD: &str = "method";
    /// REST request path.
    pub const PATH: &str = "path";
    /// SQL command verb for SQL requests.
    pub const COMMAND: &str = "command";
}

/// `NetworkEndpoint`'s entity attribute names, declared in
/// [`SANDBOX_SCHEMA_SRC`].
pub mod endpoint_fields {
    /// Destination host.
    pub const HOST: &str = "host";
    /// Destination port.
    pub const PORT: &str = "port";
    /// L7 protocol label (e.g. `"rest"`).
    pub const PROTOCOL: &str = "protocol";
    /// Precomputed `"{host}:{port}"`, for `Set<String>.contains()` matching.
    pub const HOST_PORT: &str = "host_port";
}

/// Parses [`SANDBOX_SCHEMA_SRC`] into a [`cedar_policy::Schema`].
///
/// # Errors
///
/// Returns [`CedarSchemaLoadError`] if the embedded schema source fails to
/// parse.
pub fn load_schema() -> Result<Schema, CedarSchemaLoadError> {
    let (schema, _warnings) =
        Schema::from_cedarschema_str(SANDBOX_SCHEMA_SRC).map_err(CedarSchemaLoadError::new)?;
    Ok(schema)
}
