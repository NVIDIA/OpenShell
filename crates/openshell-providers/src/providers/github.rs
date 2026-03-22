// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    discover_with_spec, ProviderDiscoverySpec, ProviderError, ProviderPlugin, RealDiscoveryContext,
};
use std::path::PathBuf;

pub struct GithubProvider;
const OPENCODE_AUTH_JSON_CREDENTIAL_KEY: &str = "OPENCODE_AUTH_JSON";

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "github",
    credential_env_vars: &["GITHUB_TOKEN", "GH_TOKEN"],
};

impl ProviderPlugin for GithubProvider {
    fn id(&self) -> &'static str {
        SPEC.id
    }

    fn discover_existing(&self) -> Result<Option<crate::DiscoveredProvider>, ProviderError> {
        discover_existing_with_context(&RealDiscoveryContext)
    }

    fn credential_env_vars(&self) -> &'static [&'static str] {
        SPEC.credential_env_vars
    }
}

fn discover_existing_with_context(
    context: &dyn crate::DiscoveryContext,
) -> Result<Option<crate::DiscoveredProvider>, ProviderError> {
    let mut discovered = discover_with_spec(&SPEC, context)?.unwrap_or_default();

    let auth_path = context
        .env_var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
        .join(".local/share/opencode/auth.json");

    if let Some(contents) = context.read_file(&auth_path)
        && !contents.trim().is_empty()
    {
        discovered
            .credentials
            .insert(OPENCODE_AUTH_JSON_CREDENTIAL_KEY.to_string(), contents);
    }

    if discovered.is_empty() {
        Ok(None)
    } else {
        Ok(Some(discovered))
    }
}

#[cfg(test)]
mod tests {
    use super::SPEC;
    use crate::discover_with_spec;
    use crate::test_helpers::MockDiscoveryContext;
    use std::collections::HashMap;

    #[test]
    fn discovers_github_env_credentials() {
        let ctx = MockDiscoveryContext::new().with_env("GH_TOKEN", "gh-token");
        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");
        assert_eq!(
            discovered.credentials.get("GH_TOKEN"),
            Some(&"gh-token".to_string())
        );
    }

    #[test]
    fn discovers_github_token_env_alias() {
        let ctx = MockDiscoveryContext::new().with_env("GITHUB_TOKEN", "github-token");
        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");

        assert_eq!(
            discovered.credentials.get("GITHUB_TOKEN"),
            Some(&"github-token".to_string())
        );
    }

    #[test]
    fn discovers_both_github_token_env_vars_for_copilot_targeted_path() {
        let ctx = MockDiscoveryContext::new()
            .with_env("GITHUB_TOKEN", "github-token")
            .with_env("GH_TOKEN", "gh-token");
        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");

        assert_eq!(
            discovered.credentials,
            HashMap::from([
                ("GITHUB_TOKEN".to_string(), "github-token".to_string()),
                ("GH_TOKEN".to_string(), "gh-token".to_string()),
            ])
        );
    }

    #[test]
    fn discovers_opencode_auth_json_as_additional_github_credential() {
        let ctx = MockDiscoveryContext::new()
            .with_env("HOME", "/home/alice")
            .with_file(
            "/home/alice/.local/share/opencode/auth.json",
            r#"{"github-copilot":{"type":"oauth","access":"tok","refresh":"tok","expires":0}}"#,
        );

        let discovered = super::discover_existing_with_context(&ctx)
            .expect("discovery")
            .expect("provider");

        assert_eq!(
            discovered
                .credentials
                .get(super::OPENCODE_AUTH_JSON_CREDENTIAL_KEY),
            Some(&r#"{"github-copilot":{"type":"oauth","access":"tok","refresh":"tok","expires":0}}"#.to_string())
        );
    }
}
