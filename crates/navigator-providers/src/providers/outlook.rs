// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{DiscoveredProvider, ProviderError, ProviderPlugin};

pub struct OutlookProvider;

impl ProviderPlugin for OutlookProvider {
    fn id(&self) -> &'static str {
        "outlook"
    }

    fn discover_existing(&self) -> Result<Option<DiscoveredProvider>, ProviderError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::OutlookProvider;
    use crate::ProviderPlugin;

    #[test]
    fn outlook_provider_discovery_is_empty_by_default() {
        let provider = OutlookProvider;
        let discovered = provider.discover_existing().expect("discovery");
        assert!(discovered.is_none());
    }
}
