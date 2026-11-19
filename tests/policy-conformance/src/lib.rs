// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cross-backend policy conformance tests. This package ships no runtime code.

#[cfg(test)]
use openshell_policy_cedar_runtime::{cedar_only, cedar_provider_rules};
#[cfg(all(test, unix))]
use openshell_policy_runtime_interface::binary_resolution;
#[cfg(test)]
use openshell_supervisor_network::{l7, opa, policy_engine, policy_types};

#[cfg(test)]
mod cedar_integration;
#[cfg(test)]
mod conformance;
