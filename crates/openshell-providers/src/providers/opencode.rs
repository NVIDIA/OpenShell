// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    ProviderDiscoverySpec, ProviderError, ProviderPlugin, RealDiscoveryContext, discover_with_spec,
};

pub struct OpencodeProvider;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "opencode",
    credential_env_vars: &["OPENCODE_API_KEY", "OPENROUTER_API_KEY", "OPENAI_API_KEY"],
};

impl ProviderPlugin for OpencodeProvider {
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

    fn assert_discovers_declared_opencode_credential(key: &str, value: &str) {
        let ctx = MockDiscoveryContext::new().with_env(key, value);
        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");

        assert_eq!(discovered.credentials.get(key), Some(&value.to_string()));
    }

    fn assert_github_credentials_are_not_discovered_as_opencode(ctx: MockDiscoveryContext) {
        let discovered = discover_with_spec(&SPEC, &ctx).expect("discovery");

        assert!(
            discovered.is_none(),
            "GitHub token discovery must stay fully separate from opencode provider discovery for the current Copilot-targeted contract"
        );
    }

    #[test]
    fn discovers_opencode_api_key_credential() {
        assert_discovers_declared_opencode_credential("OPENCODE_API_KEY", "op-key");
    }

    #[test]
    fn discovers_openrouter_api_key_credential() {
        assert_discovers_declared_opencode_credential("OPENROUTER_API_KEY", "openrouter-key");
    }

    #[test]
    fn discovers_openai_api_key_credential() {
        assert_discovers_declared_opencode_credential("OPENAI_API_KEY", "openai-key");
    }

    #[test]
    fn does_not_claim_github_token_discovery_as_opencode_credential() {
        assert_github_credentials_are_not_discovered_as_opencode(
            MockDiscoveryContext::new().with_env("GITHUB_TOKEN", "gh-token"),
        );
    }

    #[test]
    fn does_not_claim_gh_token_discovery_as_opencode_credential() {
        assert_github_credentials_are_not_discovered_as_opencode(
            MockDiscoveryContext::new().with_env("GH_TOKEN", "gh-token"),
        );
    }

    #[test]
    fn does_not_claim_github_discovery_when_both_github_token_env_vars_are_present() {
        assert_github_credentials_are_not_discovered_as_opencode(
            MockDiscoveryContext::new()
                .with_env("GITHUB_TOKEN", "github-token")
                .with_env("GH_TOKEN", "gh-token"),
        );
    }
}
