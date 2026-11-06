// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in in-process sandbox updates, separate from the baseline driver contract.

use crate::proto::compute::v1::compute_driver_server;

/// Optional in-process configuration updater, registered separately by a driver factory.
///
/// Existing drivers need only the generated baseline trait, not this extension.
/// Supporting factories opt in through `ComputeDriverFactory::build_with_configuration_updates`
/// and advertise the configuration-update capability. External servers use the
/// separate generated `ComputeDriverConfigurationUpdates` service on the same endpoint.
#[tonic::async_trait]
pub trait ComputeDriver: compute_driver_server::ComputeDriver {
    async fn update_sandbox_configuration(
        &self,
        _request: tonic::Request<crate::proto::compute::v1::UpdateSandboxConfigurationRequest>,
    ) -> Result<
        tonic::Response<crate::proto::compute::v1::UpdateSandboxConfigurationResponse>,
        tonic::Status,
    > {
        Err(tonic::Status::unimplemented(
            "sandbox configuration updates are not supported by this driver",
        ))
    }
}
