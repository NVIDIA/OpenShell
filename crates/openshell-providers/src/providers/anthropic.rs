// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::ProviderDiscoverySpec;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "anthropic",
    credential_env_vars: &["ANTHROPIC_API_KEY"],
};

#[cfg(test)]
mod tests {
    use super::SPEC;
    use crate::discover_with_spec;
    use crate::test_helpers::MockDiscoveryContext;

    #[test]
    fn discovers_anthropic_env_credentials() {
        let ctx = MockDiscoveryContext::new().with_env("ANTHROPIC_API_KEY", "sk-ant-test");
        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");
        assert_eq!(
            discovered.credentials.get("ANTHROPIC_API_KEY"),
            Some(&"sk-ant-test".to_string())
        );
    }
}
