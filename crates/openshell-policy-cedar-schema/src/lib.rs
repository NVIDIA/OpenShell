// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

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
    /// The decoded query parameters of one `HttpRequest`, one `String` tag
    /// per key.
    pub const HTTP_QUERY: &str = "Sandbox::HttpQuery";
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
    /// A single L7 request within an already-permitted `NetworkConnect` tunnel.
    pub const HTTP_REQUEST: &str = "HttpRequest";
}

/// `NetworkConnect`'s and `HttpRequest`'s `context` record attribute names.
///
/// Declared in [`SANDBOX_SCHEMA_SRC`]. `String`-typed attributes take `""`
/// for requests where they don't apply (e.g. `COMMAND` for a REST request).
pub mod context_fields {
    /// Absolute path of the calling binary (plain string, not an entity).
    pub const BINARY_PATH: &str = "binary_path";
    /// `Set<String>` of the calling process's ancestor binary paths.
    pub const ANCESTORS: &str = "ancestors";
    /// `Set<String>` of the exact binary paths policies name that resolve,
    /// as symlinks in the sandbox, to the calling binary or an ancestor.
    pub const BINARY_ALIASES: &str = "binary_aliases";
    /// HTTP method for REST requests. On `NetworkConnect` this is always
    /// `""` — see the schema's `NetworkConnect` doc comment.
    pub const METHOD: &str = "method";
    /// REST request path. Always `""` on `NetworkConnect` — see `METHOD`.
    pub const PATH: &str = "path";
    /// SQL command verb for SQL requests. Always `""` on `NetworkConnect` —
    /// see `METHOD`.
    pub const COMMAND: &str = "command";
    /// JSON-RPC method name for JSON-RPC requests. `HttpRequest`-only.
    pub const JSONRPC_METHOD: &str = "jsonrpc_method";
    /// `Bool`: an MCP GET that opens the server-to-client stream.
    /// `HttpRequest`-only.
    pub const JSONRPC_RECEIVE_STREAM: &str = "jsonrpc_receive_stream";
    /// `Bool`: the body carries client-to-server JSON-RPC response frames.
    /// `HttpRequest`-only.
    pub const JSONRPC_RESPONSE: &str = "jsonrpc_response";
    /// MCP `tools/call` tool name. `HttpRequest`-only.
    pub const MCP_TOOL: &str = "mcp_tool";
    /// MCP method classification: `"available"`, `"extension"`, or `""`.
    /// `HttpRequest`-only.
    pub const MCP_METHOD_CLASS: &str = "mcp_method_class";
    /// GraphQL operation type, or `""` for a hash-only persisted query.
    /// `HttpRequest`-only.
    pub const GRAPHQL_OPERATION_TYPE: &str = "graphql_operation_type";
    /// GraphQL operation name, or `""` when anonymous. `HttpRequest`-only.
    pub const GRAPHQL_OPERATION_NAME: &str = "graphql_operation_name";
    /// `Set<String>` of the GraphQL operation's top-level fields.
    /// `HttpRequest`-only.
    pub const GRAPHQL_FIELDS: &str = "graphql_fields";
    /// `ipaddr`: one resolved address of the destination. `NetworkConnect`
    /// only, and optional: absent while the host is unresolved.
    pub const DESTINATION_IP: &str = "destination_ip";
    /// The request's [`super::entity_types::HTTP_QUERY`] entity, whose tags
    /// hold one value per query key. `HttpRequest`-only.
    pub const QUERY: &str = "query";
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
