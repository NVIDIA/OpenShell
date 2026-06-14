// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Escape hatch — direct access to the generated tonic clients and protobuf
//! types.
//!
//! Use this module when the curated high-level surface in
//! [`crate::client::OpenShellClient`] doesn't expose the RPC or field you
//! need. The high-level surface is sandbox-focused for MVP; inference,
//! providers, policy, logs, settings, SSH, and forwarding all live here.
//!
//! ```ignore
//! use openshell_sdk::{ClientConfig, OpenShellClient};
//! use openshell_sdk::raw::ListProvidersRequest;
//!
//! let client = OpenShellClient::connect(ClientConfig::new("http://127.0.0.1:8080")).await?;
//! let mut grpc = client.raw_grpc();
//! let providers = grpc.list_providers(ListProvidersRequest::default()).await?;
//! ```

pub use openshell_core::proto;
pub use openshell_core::proto::inference_client::InferenceClient;
pub use openshell_core::proto::open_shell_client::OpenShellClient as GrpcClient;
pub use openshell_core::proto::{
    CreateSandboxRequest, DeleteSandboxRequest, ExecSandboxRequest, GetSandboxRequest,
    HealthRequest, ListProvidersRequest, ListSandboxesRequest, Sandbox,
    SandboxPhase as ProtoSandboxPhase, SandboxSpec as ProtoSandboxSpec, SandboxTemplate,
    ServiceStatus as ProtoServiceStatus,
};

/// Type alias for the gRPC client wrapped in the SDK's auth interceptor.
pub type AuthedGrpcClient = GrpcClient<
    tonic::service::interceptor::InterceptedService<
        tonic::transport::Channel,
        crate::EdgeAuthInterceptor,
    >,
>;

/// Type alias for the inference client wrapped in the SDK's auth interceptor.
pub type AuthedInferenceClient = InferenceClient<
    tonic::service::interceptor::InterceptedService<
        tonic::transport::Channel,
        crate::EdgeAuthInterceptor,
    >,
>;
