// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed CDI policy resolution for platforms other than Linux.

use std::collections::HashSet;
use std::hash::BuildHasher;

use super::{CdiContext, CdiDerivedRequirements, CdiError};

pub fn resolve_cdi_context(_context: &CdiContext) -> Result<CdiDerivedRequirements, CdiError> {
    Err(CdiError::UnsupportedPlatform)
}

pub fn validate_cdi_requirements<S: BuildHasher>(
    _requirements: &CdiDerivedRequirements,
    _writable_file_allowlist: &HashSet<String, S>,
) -> Result<(), CdiError> {
    Err(CdiError::UnsupportedPlatform)
}
