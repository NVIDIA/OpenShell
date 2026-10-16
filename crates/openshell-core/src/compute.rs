// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in in-process image updates, separate from the baseline driver contract.

use crate::proto::compute::v1::{
    UpdateSandboxImageRequest, UpdateSandboxImageResponse, compute_driver_server,
};

/// Optional in-process image updater, registered separately by a driver factory.
///
/// Existing drivers need only the generated baseline trait, not this extension.
/// Supporting factories opt in through `ComputeDriverFactory::build_with_image_updates`
/// and advertise the image-update capability. External servers use the separate
/// generated `ComputeDriverImageUpdates` service on the same endpoint instead.
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
