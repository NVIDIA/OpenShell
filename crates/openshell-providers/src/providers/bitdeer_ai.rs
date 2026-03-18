// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    ProviderDiscoverySpec, ProviderError, ProviderPlugin, RealDiscoveryContext, discover_with_spec,
};

pub struct BitdeerAiProvider;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "bitdeer-ai",
    credential_env_vars: &["BITDEERAI_API_KEY"],
};

impl ProviderPlugin for BitdeerAiProvider {
    fn id(&self) -> &'static str {
        SPEC.id
    }

    fn discover_existing(&self) -> Result<Option<crate::DiscoveredProvider>, ProviderError> {
        discover_with_spec(&SPEC, &RealDiscoveryContext)
    }

    fn credential_env_vars(&self) -> &'static [&'static str] {
        SPEC.credential_env_vars
    }
}

#[cfg(test)]
mod tests {
    use super::SPEC;
    use crate::discover_with_spec;
    use crate::test_helpers::MockDiscoveryContext;

    #[test]
    fn discovers_bitdeer_ai_env_credentials() {
        let ctx = MockDiscoveryContext::new().with_env("BITDEERAI_API_KEY", "bd-test-key-123");
        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");
        assert_eq!(
            discovered.credentials.get("BITDEERAI_API_KEY"),
            Some(&"bd-test-key-123".to_string())
        );
    }
}
