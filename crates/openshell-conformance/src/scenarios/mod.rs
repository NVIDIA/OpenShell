// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable conformance scenarios exercised by the Cargo test suite.

mod file_transfer;
mod policy_behavior;
mod sandbox_lifecycle;
mod smoke;

pub use file_transfer::{
    FILE_TRANSFER_GIT_FILTERING_SCENARIO, FILE_TRANSFER_PATH_SAFETY_SCENARIO,
    FILE_TRANSFER_ROUND_TRIP_SCENARIO,
};
pub use policy_behavior::{
    MECHANISTIC_PROPOSAL_SCENARIO, NEW_HOSTNAME_PROPOSAL_SCENARIO, POLICY_LOCAL_SCENARIO,
};
pub use sandbox_lifecycle::SANDBOX_LIFECYCLE_SCENARIO;
pub use smoke::SMOKE_SCENARIO;
