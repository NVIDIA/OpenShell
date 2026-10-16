// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-process compute contract, separate from the baseline generated gRPC trait.

use crate::proto::compute::v1::{
    UpdateSandboxImageRequest, UpdateSandboxImageResponse, compute_driver_server,
};

/// Gateway-facing in-process compute driver with optional image updates.
///
/// External servers implement the unchanged generated
/// [`compute_driver_server::ComputeDriver`] trait and, when supported, the
/// separate generated `ComputeDriverImageUpdates` service on the same endpoint.
/// In-process drivers use this default unless they advertise image updates.
#[tonic::async_trait]
pub trait ComputeDriver: compute_driver_server::ComputeDriver {
    async fn update_sandbox_image(
        &self,
        _request: tonic::Request<UpdateSandboxImageRequest>,
    ) -> Result<tonic::Response<UpdateSandboxImageResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "storage-preserving image updates are not supported by this driver",
        ))
    }
}
