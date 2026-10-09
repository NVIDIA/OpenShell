// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operator-owned endpoint registration; launch payloads never select a route.

pub use openshell_core::isolation_registration::BackendRegistration;
use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendRegistrations {
    pub backends: Vec<BackendRegistration>,
}
