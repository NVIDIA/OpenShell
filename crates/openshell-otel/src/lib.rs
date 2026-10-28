// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared OpenTelemetry trace and log export support for `OpenShell` services.
//!
//! The crate has two tiers:
//!
//! - Trace-context propagation, always compiled in: W3C `traceparent` /
//!   `tracestate` extraction and injection for HTTP headers, tonic metadata,
//!   and process environments.
//! - The `export` feature (on by default): OTLP/gRPC tracer providers,
//!   tracing layers, compute-driver and gRPC tracing machinery, and the OCSF
//!   log bridge. Services that report to a collector keep the default;
//!   clients that only forward trace context (e.g. the CLI) opt out with
//!   `default-features = false` to keep the exporter stack out of their
//!   binaries.

mod propagation;

pub use propagation::{
    EnvTraceContextInterceptor, HeaderMapExtractor, MetadataMapInjector, TRACEPARENT_ENV,
    TRACESTATE_ENV, TraceContextInterceptor, current_trace_context_carrier,
    current_trace_context_environment, set_parent_from_environment, set_parent_from_trace_context,
    trace_context_environment,
};

#[cfg(feature = "export")]
mod driver;
#[cfg(feature = "export")]
mod grpc;
#[cfg(feature = "export")]
mod logs;
#[cfg(feature = "export")]
mod ocsf;
#[cfg(feature = "export")]
mod setup;

#[cfg(feature = "export")]
pub use driver::{
    BoxGrpcStream, ComputeDriverTracing, DriverTracingConfig, DriverTracingHandle,
    IN_PROCESS_COMPUTE_DRIVER_TARGET, InProcessRpcTracer, install_driver_tracing,
};
#[cfg(feature = "export")]
pub use grpc::{
    COMPUTE_DRIVER_RPC_SERVICE, ComputeDriverRpc, ComputeDriverRpcSpan, RecordGrpcFailure,
    RecordGrpcStatus, TracedGrpcStream, compute_driver_rpc_layer, compute_driver_rpc_operation,
    grpc_status_code_name, record_grpc_status, rpc,
};
#[cfg(feature = "export")]
pub use ocsf::{OcsfOtlp, OcsfOtlpLayer};
#[cfg(feature = "export")]
pub use setup::*;

#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
