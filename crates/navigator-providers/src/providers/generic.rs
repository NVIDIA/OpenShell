// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{DiscoveredProvider, ProviderError, ProviderPlugin};

pub struct GenericProvider;

impl ProviderPlugin for GenericProvider {
    fn id(&self) -> &'static str {
        "generic"
    }

    fn discover_existing(&self) -> Result<Option<DiscoveredProvider>, ProviderError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::GenericProvider;
    use crate::ProviderPlugin;

    #[test]
    fn generic_provider_discovery_is_empty_by_default() {
        let provider = GenericProvider;
        let discovered = provider.discover_existing().expect("discovery");
        assert!(discovered.is_none());
    }
}
