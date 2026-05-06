// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared types for `openshell-server` integration tests.

use openshell_core::proto::{
    GetClusterInferenceRequest, GetClusterInferenceResponse, GetInferenceBundleRequest,
    GetInferenceBundleResponse, SetClusterInferenceRequest, SetClusterInferenceResponse,
    inference_server::Inference, open_shell_server::OpenShellServer,
};
use tonic::{Response, Status};

/// Re-export the production gateway gRPC decode cap for test stacks.
pub use openshell_server::MAX_GRPC_DECODE_SIZE as MAX_GRPC_DECODE;

/// Wrap an `OpenShell` impl with the same gRPC decode cap as production.
#[must_use]
pub fn openshell_max_decode_server<S>(inner: S) -> OpenShellServer<S> {
    OpenShellServer::new(inner).max_decoding_message_size(MAX_GRPC_DECODE)
}

/// Build a [`GatewayGrpcRouter`](::openshell_server::GatewayGrpcRouter) matching production multiplex
/// wiring: `grpc.health.v1`, reflection (`OpenShell` + `grpc.health` file descriptor sets), the given
/// [`OpenShellServer`], and [`TestInference`].
///
/// Bring into scope with `#[macro_use] mod common;` in the integration test crate root.
macro_rules! gateway_test_grpc_router {
    ($openshell:expr) => {{
        ::openshell_server::GatewayGrpcRouter::new(
            ::openshell_server::GatewayStandardHealth::server(
                ::openshell_server::MAX_GRPC_DECODE_SIZE,
            ),
            ::tonic_reflection::server::Builder::configure()
                .register_encoded_file_descriptor_set(::openshell_core::proto::FILE_DESCRIPTOR_SET)
                .register_encoded_file_descriptor_set(::tonic_health::pb::FILE_DESCRIPTOR_SET)
                .build_v1()
                .expect("OpenShell + grpc.health reflection descriptors"),
            $openshell,
            ::openshell_core::proto::inference_server::InferenceServer::new(
                $crate::common::TestInference,
            )
            .max_decoding_message_size(::openshell_server::MAX_GRPC_DECODE_SIZE),
        )
    }};
}

#[derive(Clone, Default)]
pub struct TestInference;

#[tonic::async_trait]
impl Inference for TestInference {
    async fn get_inference_bundle(
        &self,
        _request: tonic::Request<GetInferenceBundleRequest>,
    ) -> Result<Response<GetInferenceBundleResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn set_cluster_inference(
        &self,
        _request: tonic::Request<SetClusterInferenceRequest>,
    ) -> Result<Response<SetClusterInferenceResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn get_cluster_inference(
        &self,
        _request: tonic::Request<GetClusterInferenceRequest>,
    ) -> Result<Response<GetClusterInferenceResponse>, Status> {
        Err(Status::unimplemented("test"))
    }
}
