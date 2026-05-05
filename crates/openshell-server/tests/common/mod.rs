// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared types for `openshell-server` integration tests.

use openshell_core::proto::{
    GetClusterInferenceRequest, GetClusterInferenceResponse, GetInferenceBundleRequest,
    GetInferenceBundleResponse, SetClusterInferenceRequest, SetClusterInferenceResponse,
    inference_server::Inference,
};
use tonic::{Response, Status};

/// Re-export the production gateway gRPC decode cap for test stacks.
pub use openshell_server::MAX_GRPC_DECODE_SIZE as MAX_GRPC_DECODE;

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
