// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Platform-wide supervisor middleware cardinality limits.

/// Largest number of middleware configurations accepted in one sandbox policy.
pub const MAX_MIDDLEWARE_CONFIGS: usize = 10;
/// Largest number of middleware stages selected for one request.
pub const MAX_MIDDLEWARE_CHAIN_STAGES: usize = MAX_MIDDLEWARE_CONFIGS;
/// Largest combined number of include and exclude patterns in one selector.
pub const MAX_MIDDLEWARE_SELECTOR_PATTERNS: usize = 32;
/// Largest number of findings accepted from one middleware stage.
pub const MAX_MIDDLEWARE_FINDINGS_PER_STAGE: usize = 32;
/// Largest number of findings retained and emitted for one complete chain.
pub const MAX_MIDDLEWARE_CHAIN_FINDINGS: usize =
    MAX_MIDDLEWARE_CHAIN_STAGES * MAX_MIDDLEWARE_FINDINGS_PER_STAGE;
