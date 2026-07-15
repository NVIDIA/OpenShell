// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::{DiscoveredProvider, Provider, ProviderError, ProviderPlugin};

pub struct AnthropicOauthProvider;

/// Placeholder injected as `ANTHROPIC_AUTH_TOKEN` so agent CLIs (Claude Code,
/// Anthropic SDKs) authenticate without prompting for an interactive login.
/// `ANTHROPIC_AUTH_TOKEN` is used instead of `ANTHROPIC_API_KEY` because
/// Claude Code asks for confirmation before trusting an environment API key
/// but accepts an auth token silently. The value never reaches Anthropic:
/// `inference.local` replaces caller-supplied `Authorization` and injects the
/// real subscription token at the egress boundary.
pub const ANTHROPIC_AUTH_TOKEN_PLACEHOLDER: &str = "inference-local";

/// Base URL agents inside the sandbox must use to reach the model. The
/// subscription OAuth token is proxy-only, so direct calls to
/// `api.anthropic.com` cannot authenticate; all traffic goes through the
/// gateway's inference endpoint.
pub const ANTHROPIC_BASE_URL_VALUE: &str = "https://inference.local";

impl ProviderPlugin for AnthropicOauthProvider {
    fn id(&self) -> &'static str {
        "anthropic-oauth"
    }

    fn discover_existing(&self) -> Result<Option<DiscoveredProvider>, ProviderError> {
        // OAuth material is harvested via `--from-claude-login`, not env
        // scanning, and the access token must never be treated as an
        // injectable env credential.
        Ok(None)
    }

    fn inject_env(&self, _provider: &Provider, env: &mut HashMap<String, String>) {
        env.entry("ANTHROPIC_BASE_URL".to_string())
            .or_insert_with(|| ANTHROPIC_BASE_URL_VALUE.to_string());
        env.entry("ANTHROPIC_AUTH_TOKEN".to_string())
            .or_insert_with(|| ANTHROPIC_AUTH_TOKEN_PLACEHOLDER.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_base_url_and_placeholder_auth_token() {
        let provider = Provider {
            r#type: "anthropic-oauth".to_string(),
            ..Default::default()
        };
        let mut env = HashMap::new();
        AnthropicOauthProvider.inject_env(&provider, &mut env);

        assert_eq!(
            env.get("ANTHROPIC_BASE_URL").map(String::as_str),
            Some(ANTHROPIC_BASE_URL_VALUE)
        );
        assert_eq!(
            env.get("ANTHROPIC_AUTH_TOKEN").map(String::as_str),
            Some(ANTHROPIC_AUTH_TOKEN_PLACEHOLDER)
        );
        assert!(
            !env.contains_key("ANTHROPIC_API_KEY"),
            "must not inject an API key: Claude Code prompts before trusting it"
        );
    }

    #[test]
    fn does_not_override_existing_values() {
        let provider = Provider {
            r#type: "anthropic-oauth".to_string(),
            ..Default::default()
        };
        let mut env = HashMap::from([(
            "ANTHROPIC_BASE_URL".to_string(),
            "https://custom.example".to_string(),
        )]);
        AnthropicOauthProvider.inject_env(&provider, &mut env);

        assert_eq!(
            env.get("ANTHROPIC_BASE_URL").map(String::as_str),
            Some("https://custom.example")
        );
    }

    #[test]
    fn discovery_finds_nothing() {
        assert!(
            AnthropicOauthProvider
                .discover_existing()
                .expect("discovery should not error")
                .is_none()
        );
    }
}
