// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TOML configuration types for the fake driver's scripted response sequences.
//!
//! Each RPC has an ordered list of entries. The driver advances through the list
//! on each call. When the sequence is exhausted the last entry is repeated and a
//! warning is logged.

use serde::Deserialize;

/// Top-level configuration loaded from the `--config` file.
#[derive(Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub validate_sandbox_create: Vec<ValidateSandboxCreateEntry>,
    #[serde(default)]
    pub create_sandbox: Vec<SimpleEntry>,
    #[serde(default)]
    pub get_sandbox: Vec<GetSandboxEntry>,
    #[serde(default)]
    pub list_sandboxes: Vec<ListSandboxesEntry>,
    #[serde(default)]
    pub stop_sandbox: Vec<SimpleEntry>,
    #[serde(default)]
    pub delete_sandbox: Vec<DeleteSandboxEntry>,
    #[serde(default)]
    pub watch_sandboxes: WatchSandboxesConfig,
}

/// A gRPC error to return in place of a success response.
#[derive(Debug, Deserialize)]
pub struct GrpcError {
    /// gRPC status code name, e.g. `"NOT_FOUND"`, `"INVALID_ARGUMENT"`.
    pub code: String,
    pub message: String,
}

impl GrpcError {
    pub fn to_status(&self) -> tonic::Status {
        let code = match self.code.to_uppercase().as_str() {
            "CANCELLED" => tonic::Code::Cancelled,
            "INVALID_ARGUMENT" => tonic::Code::InvalidArgument,
            "DEADLINE_EXCEEDED" => tonic::Code::DeadlineExceeded,
            "NOT_FOUND" => tonic::Code::NotFound,
            "ALREADY_EXISTS" => tonic::Code::AlreadyExists,
            "PERMISSION_DENIED" => tonic::Code::PermissionDenied,
            "RESOURCE_EXHAUSTED" => tonic::Code::ResourceExhausted,
            "FAILED_PRECONDITION" => tonic::Code::FailedPrecondition,
            "ABORTED" => tonic::Code::Aborted,
            "OUT_OF_RANGE" => tonic::Code::OutOfRange,
            "UNIMPLEMENTED" => tonic::Code::Unimplemented,
            "INTERNAL" => tonic::Code::Internal,
            "UNAVAILABLE" => tonic::Code::Unavailable,
            "DATA_LOSS" => tonic::Code::DataLoss,
            "UNAUTHENTICATED" => tonic::Code::Unauthenticated,
            _ => tonic::Code::Unknown,
        };
        tonic::Status::new(code, &self.message)
    }
}

/// Entry for RPCs that return an empty success response.
///
/// Omit `error` for success; set `error` to return a gRPC status error.
#[derive(Debug, Default, Deserialize)]
pub struct SimpleEntry {
    pub error: Option<GrpcError>,
}

/// Entry for `ValidateSandboxCreate`. Same shape as `SimpleEntry` but kept
/// distinct so the config section name is self-documenting.
#[derive(Debug, Default, Deserialize)]
pub struct ValidateSandboxCreateEntry {
    pub error: Option<GrpcError>,
}

/// Entry for `GetSandbox`.
#[derive(Debug, Default, Deserialize)]
pub struct GetSandboxEntry {
    pub error: Option<GrpcError>,
    /// The sandbox to return on success. If absent the RPC returns `NOT_FOUND`.
    pub sandbox: Option<SandboxConfig>,
}

/// Entry for `ListSandboxes`.
#[derive(Debug, Default, Deserialize)]
pub struct ListSandboxesEntry {
    pub error: Option<GrpcError>,
    #[serde(default)]
    pub sandboxes: Vec<SandboxConfig>,
}

/// Entry for `DeleteSandbox`.
#[derive(Debug, Default, Deserialize)]
pub struct DeleteSandboxEntry {
    pub error: Option<GrpcError>,
    /// Whether a resource was deleted. Defaults to `true`.
    #[serde(default = "default_deleted")]
    pub deleted: bool,
}

fn default_deleted() -> bool {
    true
}

/// Simplified sandbox descriptor used in scripted responses.
#[derive(Debug, Default, Deserialize)]
pub struct SandboxConfig {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,
    pub status: Option<SandboxStatusConfig>,
}

/// Simplified sandbox status used in scripted responses.
#[derive(Debug, Default, Deserialize)]
pub struct SandboxStatusConfig {
    #[serde(default)]
    pub sandbox_name: String,
    #[serde(default)]
    pub instance_id: String,
    /// Address the agent service is reachable at (e.g. `"127.0.0.1:12345"`).
    #[serde(default)]
    pub agent_fd: String,
    /// Address the sandbox supervisor service is reachable at.
    #[serde(default)]
    pub sandbox_fd: String,
}

/// Configuration for the `WatchSandboxes` streaming RPC.
///
/// A single flat sequence of events is emitted in order with `delay_ms`
/// between each. The stream closes after the last event.
#[derive(Debug, Deserialize)]
pub struct WatchSandboxesConfig {
    /// Milliseconds to wait between emitting consecutive events.
    #[serde(default = "default_delay_ms")]
    pub delay_ms: u64,
    #[serde(default)]
    pub events: Vec<WatchEventConfig>,
}

fn default_delay_ms() -> u64 {
    100
}

impl Default for WatchSandboxesConfig {
    fn default() -> Self {
        Self {
            delay_ms: default_delay_ms(),
            events: Vec::new(),
        }
    }
}

/// A single event emitted on the `WatchSandboxes` stream.
///
/// Exactly one of `sandbox` or `deleted` should be set.
#[derive(Debug, Deserialize)]
pub struct WatchEventConfig {
    /// Emit a sandbox-updated event with the given snapshot.
    pub sandbox: Option<SandboxConfig>,
    /// Emit a sandbox-deleted event with the given sandbox ID.
    pub deleted: Option<DeletedEventConfig>,
}

#[derive(Debug, Deserialize)]
pub struct DeletedEventConfig {
    pub sandbox_id: String,
}
