// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Registered, portable conformance scenarios.

mod policy_behavior;
mod sandbox_lifecycle;
mod smoke;

pub use policy_behavior::{
    MECHANISTIC_PROPOSAL_SCENARIO, NEW_HOSTNAME_PROPOSAL_SCENARIO, POLICY_LOCAL_SCENARIO,
};
pub use sandbox_lifecycle::SANDBOX_LIFECYCLE_SCENARIO;
pub use smoke::SMOKE_SCENARIO;
