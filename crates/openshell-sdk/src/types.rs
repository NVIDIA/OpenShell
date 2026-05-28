// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Curated public types for the high-level SDK surface.
//!
//! These types intentionally diverge from the raw protobuf shapes so future
//! language bindings (TypeScript via napi, Python via `PyO3`) can render them
//! idiomatically. In particular, enum-valued fields use Rust enums that map
//! to string literals in TypeScript rather than numeric proto enums; nested
//! `Option<...>` chains from proto are flattened where one of the wrappers
//! is structurally meaningless.
//!
//! The raw proto clients are still accessible via [`crate::raw`] as an
//! escape hatch for callers who need fields not exposed here.

use openshell_core::proto;
use std::collections::HashMap;
use std::time::Duration;

/// Gateway health snapshot.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Health {
    pub status: ServiceStatus,
    pub version: String,
}

/// Coarse gateway service status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ServiceStatus {
    Unspecified,
    Healthy,
    Degraded,
    Unhealthy,
}

impl From<proto::ServiceStatus> for ServiceStatus {
    fn from(value: proto::ServiceStatus) -> Self {
        match value {
            proto::ServiceStatus::Healthy => Self::Healthy,
            proto::ServiceStatus::Degraded => Self::Degraded,
            proto::ServiceStatus::Unhealthy => Self::Unhealthy,
            proto::ServiceStatus::Unspecified => Self::Unspecified,
        }
    }
}

impl From<i32> for ServiceStatus {
    fn from(value: i32) -> Self {
        proto::ServiceStatus::try_from(value).map_or(Self::Unspecified, Self::from)
    }
}

/// High-level sandbox lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SandboxPhase {
    Unspecified,
    Provisioning,
    Ready,
    Error,
    Deleting,
    Unknown,
}

impl From<proto::SandboxPhase> for SandboxPhase {
    fn from(value: proto::SandboxPhase) -> Self {
        match value {
            proto::SandboxPhase::Unspecified => Self::Unspecified,
            proto::SandboxPhase::Provisioning => Self::Provisioning,
            proto::SandboxPhase::Ready => Self::Ready,
            proto::SandboxPhase::Error => Self::Error,
            proto::SandboxPhase::Deleting => Self::Deleting,
            proto::SandboxPhase::Unknown => Self::Unknown,
        }
    }
}

impl From<i32> for SandboxPhase {
    fn from(value: i32) -> Self {
        proto::SandboxPhase::try_from(value).map_or(Self::Unspecified, Self::from)
    }
}

/// Caller intent for a new sandbox.
///
/// Only the most commonly used fields are exposed. Callers that need the
/// full proto surface (volume claim templates, runtime classes, struct
/// resources, etc.) should drop down to [`crate::raw`].
#[derive(Clone, Debug, Default)]
pub struct SandboxSpec {
    /// Optional user-supplied sandbox name. When empty the server generates one.
    pub name: Option<String>,
    /// Container image reference (e.g. `ghcr.io/nvidia/openshell-community/sandboxes/python:latest`).
    pub image: Option<String>,
    /// Labels attached to the sandbox.
    pub labels: HashMap<String, String>,
    /// Environment variables injected into the sandbox runtime.
    pub environment: HashMap<String, String>,
    /// Provider names to attach.
    pub providers: Vec<String>,
    /// Request a GPU. Driver-specific device selection is configured via
    /// driver config on the raw proto surface (see [`crate::raw`]).
    pub gpu: bool,
}

/// Reference to a sandbox owned by the gateway.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SandboxRef {
    pub id: String,
    pub name: String,
    pub phase: SandboxPhase,
    pub labels: HashMap<String, String>,
    pub resource_version: u64,
}

impl SandboxRef {
    pub(crate) fn from_proto(sandbox: proto::Sandbox) -> Self {
        let phase = sandbox.phase().into();
        let meta = sandbox.metadata.unwrap_or_default();
        Self {
            id: meta.id,
            name: meta.name,
            phase,
            labels: meta.labels,
            resource_version: meta.resource_version,
        }
    }
}

/// Options for listing sandboxes.
#[derive(Clone, Debug, Default)]
pub struct ListOptions {
    /// Maximum sandboxes to return. `0` defers to the server default.
    pub limit: u32,
    /// Offset into the result list.
    pub offset: u32,
    /// Optional Kubernetes-style label selector (e.g. `env=prod,team=core`).
    pub label_selector: Option<String>,
}

/// Options for [`crate::client::OpenShellClient::exec`].
#[derive(Clone, Debug, Default)]
pub struct ExecOptions {
    /// Working directory inside the sandbox.
    pub workdir: Option<String>,
    /// Environment overrides for the exec.
    pub environment: HashMap<String, String>,
    /// Optional command timeout. `None` lets the gateway choose.
    pub timeout: Option<Duration>,
    /// Optional stdin payload.
    pub stdin: Option<Vec<u8>>,
}

/// Result of a non-streaming exec call.
///
/// `stdout` and `stderr` are buffered to the end of the command. Use the
/// raw streaming RPC ([`crate::raw`]) for long-running output.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
