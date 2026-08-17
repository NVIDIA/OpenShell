// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed CDI policy resolution for platforms other than Linux.

use std::collections::HashSet;
use std::hash::BuildHasher;

use super::{CdiContext, CdiDerivedRequirements, CdiError};

pub fn resolve_cdi_context<S: BuildHasher>(
    _context: &CdiContext,
    _writable_file_allowlist: &HashSet<String, S>,
) -> Result<CdiDerivedRequirements, CdiError> {
    Err(CdiError::UnsupportedPlatform)
}
