// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// The compute-driver service boundary uses `tonic::Status` directly so driver
// errors cross the in-process and gRPC implementations with the same shape.
#![allow(clippy::result_large_err)]

//! Apple Container compute driver.

pub mod cli;
pub mod config;
pub mod driver;
pub mod grpc;

pub use config::AppleContainerComputeConfig;
pub use driver::{AppleContainerComputeDriver, SupervisorReadiness};
pub use grpc::ComputeDriverService;
