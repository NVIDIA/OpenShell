// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Registered, portable conformance scenarios.

mod sandbox_continuity;
mod sandbox_lifecycle;
mod smoke;

pub use sandbox_continuity::SANDBOX_CONTINUITY_SCENARIO;
pub use sandbox_lifecycle::SANDBOX_LIFECYCLE_SCENARIO;
pub use smoke::SMOKE_SCENARIO;
