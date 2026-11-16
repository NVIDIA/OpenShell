// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The supervisor and sandbox-boundary side of the contract: what a reader
//! checks about a document before it acts on it.

use std::collections::BTreeMap;

use crate::model::BackendError;

/// Validate driver-specific immutable coordinates before a boundary binds them.
///
/// Claim values are opaque to the common protocol, but empty or
/// whitespace-bearing identifiers cannot safely distinguish runtime objects.
pub fn validate_resource_claims(claims: &BTreeMap<String, String>) -> Result<(), BackendError> {
    for (key, value) in claims {
        if key.is_empty() || key.chars().any(char::is_whitespace) {
            return Err(BackendError::Descriptor(
                "boundary resource-claim keys must be non-empty and contain no whitespace"
                    .to_string(),
            ));
        }
        if value.is_empty() || value.chars().any(char::is_whitespace) {
            return Err(BackendError::Descriptor(format!(
                "boundary resource claim {key:?} must be non-empty and contain no whitespace"
            )));
        }
    }
    Ok(())
}
