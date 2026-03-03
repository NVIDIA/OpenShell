// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{DiscoveredProvider, DiscoveryContext, ProviderDiscoverySpec, ProviderError};

pub fn discover_with_spec(
    spec: &ProviderDiscoverySpec,
    context: &dyn DiscoveryContext,
) -> Result<Option<DiscoveredProvider>, ProviderError> {
    let mut discovered = DiscoveredProvider::default();

    for key in spec.credential_env_vars {
        if let Some(value) = context.env_var(key)
            && !value.trim().is_empty()
        {
            discovered
                .credentials
                .entry((*key).to_string())
                .or_insert(value);
        }
    }

    if discovered.is_empty() {
        Ok(None)
    } else {
        Ok(Some(discovered))
    }
}
