// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Registered, portable conformance scenarios.

mod file_transfer;
mod sandbox_lifecycle;
mod smoke;

pub use file_transfer::{
    FILE_TRANSFER_GIT_FILTERING_SCENARIO, FILE_TRANSFER_PATH_SAFETY_SCENARIO,
    FILE_TRANSFER_ROUND_TRIP_SCENARIO, FILE_TRANSFER_SCENARIO,
};
pub use sandbox_lifecycle::{
    SANDBOX_LIFECYCLE_RELAY_READINESS_SCENARIO, SANDBOX_LIFECYCLE_RELAY_RECONNECT_SCENARIO,
    SANDBOX_LIFECYCLE_SCENARIO, SANDBOX_LIFECYCLE_STATE_TRANSITIONS_SCENARIO,
};
pub use smoke::SMOKE_SCENARIO;
