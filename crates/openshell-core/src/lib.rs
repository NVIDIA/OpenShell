// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` Core - shared library for `OpenShell` components.
//!
//! This crate provides:
//! - Protocol buffer definitions and generated code
//! - Configuration management
//! - Common error types
//! - Build version metadata

pub mod activity;
pub mod auth;
pub mod config;
pub mod denial;
pub mod driver_mounts;
pub mod driver_utils;
pub mod error;
pub mod forward;
pub mod google_cloud;
pub mod gpu;
pub mod grpc_client;
pub mod image;
pub mod inference;
pub mod metadata;
pub mod net;
pub mod paths;
pub mod policy;
pub mod progress;
pub mod proposals;
pub mod proto;
pub mod proto_struct;
pub mod provider_credentials;
pub mod sandbox_env;
pub mod secrets;
pub mod settings;
pub mod telemetry;
pub mod time;

pub use config::{
    ComputeDriverKind, Config, GatewayAuthConfig, GatewayInterceptorBindingOverride,
    GatewayInterceptorConfig, GatewayInterceptorFailurePolicy, GatewayInterceptorPhaseConfig,
    GatewayJwtConfig, MtlsAuthConfig, OidcConfig, TlsConfig,
};
pub use error::{ComputeDriverError, Error, Result};
pub use metadata::{GetResourceVersion, ObjectId, ObjectLabels, ObjectName, SetResourceVersion};

/// Build version string derived from git metadata.
///
/// For local builds this is computed by `build.rs` via `git describe` using
/// the guess-next-dev scheme (e.g. `0.0.4-dev.6+g2bf9969`). In Docker/CI
/// builds where `.git` is absent, falls back to `CARGO_PKG_VERSION` which
/// is already set correctly by the build pipeline's sed patch.
pub const VERSION: &str = match option_env!("OPENSHELL_GIT_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// Encoded protobuf `FileDescriptorSet` for every proto in `proto/`.
///
/// Emitted by `build.rs` via `tonic_build::configure().file_descriptor_set_path(...)`.
/// Used by tests in `openshell-server` to enumerate every RPC and verify that
/// each one has an `#[rpc_auth(...)]` declaration on its handler.
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(env!("OPENSHELL_DESCRIPTOR_PATH"));
