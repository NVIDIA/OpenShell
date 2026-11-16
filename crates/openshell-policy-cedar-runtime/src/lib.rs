// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

pub use openshell_policy_runtime_interface::{
    L7PolicyContext, binary_resolution, l7, network_middleware, policy_data, policy_types,
};
pub mod cedar_only;
pub mod cedar_provider_rules;
pub use cedar_only::CedarOnlyEngine;

mod backend;
mod protocol;

pub use openshell_policy::runtime_validation as policy_validation;
