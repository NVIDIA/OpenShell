// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway interceptor framework.
//!
//! The gateway integrates this crate once at the gRPC routing boundary. The
//! runtime uses the generated protobuf descriptor set to decode unary
//! `openshell.v1.OpenShell` request frames into protobuf-JSON-shaped values,
//! apply interceptor decisions, and re-encode the request before tonic reaches
//! the handler. Handler modules do not need per-method interceptor hooks.

#![allow(clippy::result_large_err)]

use openshell_core::config::GatewayInterceptorConfig;

pub(crate) mod plan;
pub(crate) mod profile_source;
pub(crate) mod proto_json;
pub mod routes;
pub(crate) mod runtime;

pub use plan::{FailurePolicy, Phase, RpcSelector, parse_duration};
pub use profile_source::{GatewayInterceptorProfileSource, ProviderProfileSourceSnapshot};
pub use proto_json::ProtoJsonCodec;
pub use runtime::{EvaluationContext, GatewayInterceptorRuntime, InterceptedRequest};

#[derive(Debug, thiserror::Error)]
pub enum InterceptorError {
    #[error("invalid interceptor config: {0}")]
    Config(String),
    #[error("interceptor transport error: {0}")]
    Transport(String),
    #[error("invalid interceptor result: {0}")]
    InvalidResult(String),
    #[error("protobuf transcode error: {0}")]
    Transcode(String),
}

pub type Result<T> = std::result::Result<T, InterceptorError>;

/// Return `None` when no interceptors are configured.
pub async fn initialize(
    configs: Vec<GatewayInterceptorConfig>,
) -> Result<Option<GatewayInterceptorRuntime>> {
    if configs.is_empty() {
        return Ok(None);
    }
    let runtime = GatewayInterceptorRuntime::build(configs).await?;
    Ok(Some(runtime))
}
