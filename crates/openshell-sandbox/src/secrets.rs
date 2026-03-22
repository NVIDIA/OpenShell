// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::child_env::ToolAdapter;

const PLACEHOLDER_PREFIX: &str = "openshell:resolve:env:";

#[derive(Debug, Clone, Default)]
pub(crate) struct SecretResolver {
    by_placeholder: HashMap<String, String>,
}

impl SecretResolver {
    pub(crate) fn from_provider_env(
        provider_env: HashMap<String, String>,
    ) -> (HashMap<String, String>, Option<Self>) {
        if provider_env.is_empty() {
            return (HashMap::new(), None);
        }

        let mut child_env = HashMap::with_capacity(provider_env.len());
        let mut by_placeholder = HashMap::with_capacity(provider_env.len());

        for (key, value) in provider_env {
            let placeholder = placeholder_for_env_key(&key);
            child_env.insert(key, placeholder.clone());
            by_placeholder.insert(placeholder, value);
        }

        (child_env, Some(Self { by_placeholder }))
    }

    pub(crate) fn from_tool_provider_env(
        tool: ToolAdapter,
        provider_env: HashMap<String, String>,
    ) -> Result<(HashMap<String, String>, Option<Self>), String> {
        if provider_env.is_empty() {
            return Ok((HashMap::new(), None));
        }

        let allowed_keys = allowed_env_keys(tool);
        let mut filtered = HashMap::with_capacity(provider_env.len());

        for (key, value) in provider_env {
            if !allowed_keys.contains(&key.as_str()) {
                return Err(format!(
                    "tool '{}' does not allow projecting provider env key '{}'",
                    tool.command_name(),
                    key
                ));
            }
            filtered.insert(key, value);
        }

        Ok(Self::from_provider_env(filtered))
    }

    pub(crate) fn resolve_placeholder(&self, value: &str) -> Option<&str> {
        self.by_placeholder.get(value).map(String::as_str)
    }

    pub(crate) fn rewrite_header_value(&self, value: &str) -> Option<String> {
        if let Some(secret) = self.resolve_placeholder(value.trim()) {
            return Some(secret.to_string());
        }

        let trimmed = value.trim();
        let split_at = trimmed.find(char::is_whitespace)?;
        let prefix = &trimmed[..split_at];
        let candidate = trimmed[split_at..].trim();
        let secret = self.resolve_placeholder(candidate)?;
        Some(format!("{prefix} {secret}"))
    }
}

fn allowed_env_keys(tool: ToolAdapter) -> &'static [&'static str] {
    match tool {
        ToolAdapter::ClaudeCode => &["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"],
        ToolAdapter::OpenCode => &[
            "OPENCODE_API_KEY",
            "OPENROUTER_API_KEY",
            "OPENAI_API_KEY",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "OPENCODE_AUTH_JSON",
        ],
    }
}

pub(crate) fn placeholder_for_env_key(key: &str) -> String {
    format!("{PLACEHOLDER_PREFIX}{key}")
}

pub(crate) fn rewrite_http_header_block(raw: &[u8], resolver: Option<&SecretResolver>) -> Vec<u8> {
    let Some(resolver) = resolver else {
        return raw.to_vec();
    };

    let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) else {
        return raw.to_vec();
    };

    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_str.split("\r\n");
    let Some(request_line) = lines.next() else {
        return raw.to_vec();
    };

    let mut output = Vec::with_capacity(raw.len());
    output.extend_from_slice(request_line.as_bytes());
    output.extend_from_slice(b"\r\n");

    for line in lines {
        if line.is_empty() {
            break;
        }

        output.extend_from_slice(rewrite_header_line(line, resolver).as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&raw[header_end..]);
    output
}

pub(crate) fn rewrite_header_line(line: &str, resolver: &SecretResolver) -> String {
    let Some((name, value)) = line.split_once(':') else {
        return line.to_string();
    };

    match resolver.rewrite_header_value(value.trim()) {
        Some(rewritten) => format!("{name}: {rewritten}"),
        None => line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_env_is_replaced_with_placeholders() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("ANTHROPIC_API_KEY".to_string(), "sk-test".to_string())]
                .into_iter()
                .collect(),
        );

        assert_eq!(
            child_env.get("ANTHROPIC_API_KEY"),
            Some(&"openshell:resolve:env:ANTHROPIC_API_KEY".to_string())
        );
        assert_eq!(
            resolver
                .as_ref()
                .and_then(|resolver| resolver
                    .resolve_placeholder("openshell:resolve:env:ANTHROPIC_API_KEY")),
            Some("sk-test")
        );
    }

    #[test]
    fn rewrites_exact_placeholder_header_values() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("CUSTOM_TOKEN".to_string(), "secret-token".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");

        assert_eq!(
            rewrite_header_line("x-api-key: openshell:resolve:env:CUSTOM_TOKEN", &resolver),
            "x-api-key: secret-token"
        );
    }

    #[test]
    fn rewrites_bearer_placeholder_header_values() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("ANTHROPIC_API_KEY".to_string(), "sk-test".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");

        assert_eq!(
            rewrite_header_line(
                "Authorization: Bearer openshell:resolve:env:ANTHROPIC_API_KEY",
                &resolver,
            ),
            "Authorization: Bearer sk-test"
        );
    }

    #[test]
    fn rewrites_http_header_blocks_and_preserves_body() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("CUSTOM_TOKEN".to_string(), "secret-token".to_string())]
                .into_iter()
                .collect(),
        );

        let raw = b"POST /v1 HTTP/1.1\r\nAuthorization: Bearer openshell:resolve:env:CUSTOM_TOKEN\r\nContent-Length: 5\r\n\r\nhello";
        let rewritten = rewrite_http_header_block(raw, resolver.as_ref());
        let rewritten = String::from_utf8(rewritten).expect("utf8");

        assert!(rewritten.contains("Authorization: Bearer secret-token\r\n"));
        assert!(rewritten.ends_with("\r\n\r\nhello"));
    }

    /// Exercises the placeholder lifecycle in this module: provider env values
    /// become child-visible placeholders, and placeholder-bearing HTTP headers
    /// are rewritten to real secrets before forwarding.
    #[test]
    fn full_round_trip_child_env_to_rewritten_headers() {
        let provider_env: HashMap<String, String> = [
            (
                "ANTHROPIC_API_KEY".to_string(),
                "sk-real-key-12345".to_string(),
            ),
            (
                "CUSTOM_SERVICE_TOKEN".to_string(),
                "tok-real-svc-67890".to_string(),
            ),
        ]
        .into_iter()
        .collect();

        let (child_env, resolver) = SecretResolver::from_provider_env(provider_env);

        // Child process reads placeholders from the environment
        let auth_value = child_env.get("ANTHROPIC_API_KEY").unwrap();
        let token_value = child_env.get("CUSTOM_SERVICE_TOKEN").unwrap();
        assert!(auth_value.starts_with(PLACEHOLDER_PREFIX));
        assert!(token_value.starts_with(PLACEHOLDER_PREFIX));

        // Child constructs an HTTP request using those placeholders
        let raw = format!(
            "GET /v1/messages HTTP/1.1\r\n\
             Host: api.example.com\r\n\
             Authorization: Bearer {auth_value}\r\n\
             x-api-key: {token_value}\r\n\
             Content-Length: 0\r\n\r\n"
        );

        // Proxy rewrites headers
        let rewritten = rewrite_http_header_block(raw.as_bytes(), resolver.as_ref());
        let rewritten = String::from_utf8(rewritten).expect("utf8");

        // Real secrets must appear in the rewritten headers
        assert!(
            rewritten.contains("Authorization: Bearer sk-real-key-12345\r\n"),
            "Expected rewritten Authorization header, got: {rewritten}"
        );
        assert!(
            rewritten.contains("x-api-key: tok-real-svc-67890\r\n"),
            "Expected rewritten x-api-key header, got: {rewritten}"
        );

        // Placeholders must not appear
        assert!(
            !rewritten.contains("openshell:resolve:env:"),
            "Placeholder leaked into rewritten request: {rewritten}"
        );

        // Request line and non-secret headers must be preserved
        assert!(rewritten.starts_with("GET /v1/messages HTTP/1.1\r\n"));
        assert!(rewritten.contains("Host: api.example.com\r\n"));
        assert!(rewritten.contains("Content-Length: 0\r\n"));
    }

    #[test]
    fn non_secret_headers_are_not_modified() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("API_KEY".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
        );

        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\nContent-Type: text/plain\r\n\r\n";
        let rewritten = rewrite_http_header_block(raw, resolver.as_ref());
        // The output should be byte-identical since no placeholders are present
        assert_eq!(raw.as_slice(), rewritten.as_slice());
    }

    #[test]
    fn empty_provider_env_produces_no_resolver() {
        let (child_env, resolver) = SecretResolver::from_provider_env(HashMap::new());
        assert!(child_env.is_empty());
        assert!(resolver.is_none());
    }

    #[test]
    fn tool_projection_allows_only_documented_claude_keys() {
        let (child_env, resolver) = SecretResolver::from_tool_provider_env(
            ToolAdapter::ClaudeCode,
            [
                ("ANTHROPIC_API_KEY".to_string(), "sk-test".to_string()),
                ("CLAUDE_API_KEY".to_string(), "sk-alt".to_string()),
            ]
            .into_iter()
            .collect(),
        )
        .expect("claude projection succeeds");

        assert_eq!(child_env.len(), 2);
        assert!(resolver.is_some());
    }

    #[test]
    fn tool_projection_rejects_disallowed_claude_key() {
        let error = SecretResolver::from_tool_provider_env(
            ToolAdapter::ClaudeCode,
            [
                ("ANTHROPIC_API_KEY".to_string(), "sk-test".to_string()),
                ("GITHUB_TOKEN".to_string(), "gh-test".to_string()),
            ]
            .into_iter()
            .collect(),
        )
        .expect_err("unexpected github token must be rejected for claude tool adapter");

        assert!(error
            .contains("tool 'claude' does not allow projecting provider env key 'GITHUB_TOKEN'"));
    }

    #[test]
    fn tool_projection_allows_documented_opencode_keys() {
        let (child_env, resolver) = SecretResolver::from_tool_provider_env(
            ToolAdapter::OpenCode,
            [
                ("OPENCODE_API_KEY".to_string(), "opc-test".to_string()),
                ("GITHUB_TOKEN".to_string(), "gh-test".to_string()),
            ]
            .into_iter()
            .collect(),
        )
        .expect("opencode projection succeeds");

        assert_eq!(child_env.len(), 2);
        assert!(resolver.is_some());
    }

    #[test]
    fn tool_projection_allows_provider_carried_opencode_auth_json() {
        let (child_env, resolver) = SecretResolver::from_tool_provider_env(
            ToolAdapter::OpenCode,
            [(
                "OPENCODE_AUTH_JSON".to_string(),
                r#"{"github-copilot":{"type":"oauth"}}"#.to_string(),
            )]
            .into_iter()
            .collect(),
        )
        .expect("opencode projection succeeds for provider-carried auth json");
        let resolver = resolver.expect("resolver");

        assert_eq!(
            child_env.get("OPENCODE_AUTH_JSON"),
            Some(&placeholder_for_env_key("OPENCODE_AUTH_JSON"))
        );
        assert_eq!(
            resolver.resolve_placeholder(&placeholder_for_env_key("OPENCODE_AUTH_JSON")),
            Some(r#"{"github-copilot":{"type":"oauth"}}"#)
        );
    }

    #[test]
    fn tool_projection_allows_both_documented_opencode_github_tokens() {
        let (child_env, resolver) = SecretResolver::from_tool_provider_env(
            ToolAdapter::OpenCode,
            [
                ("GITHUB_TOKEN".to_string(), "ghu-test".to_string()),
                ("GH_TOKEN".to_string(), "ghs-test".to_string()),
            ]
            .into_iter()
            .collect(),
        )
        .expect("opencode projection succeeds for github token aliases");
        let resolver = resolver.expect("resolver");

        assert_eq!(
            child_env.get("GITHUB_TOKEN"),
            Some(&placeholder_for_env_key("GITHUB_TOKEN"))
        );
        assert_eq!(
            child_env.get("GH_TOKEN"),
            Some(&placeholder_for_env_key("GH_TOKEN"))
        );
        assert_eq!(
            resolver.resolve_placeholder(&placeholder_for_env_key("GITHUB_TOKEN")),
            Some("ghu-test")
        );
        assert_eq!(
            resolver.resolve_placeholder(&placeholder_for_env_key("GH_TOKEN")),
            Some("ghs-test")
        );
    }

    #[test]
    fn tool_projection_rejects_unrelated_opencode_key() {
        let error = SecretResolver::from_tool_provider_env(
            ToolAdapter::OpenCode,
            [
                ("GITHUB_TOKEN".to_string(), "gh-test".to_string()),
                ("UNRELATED_TOKEN".to_string(), "nope".to_string()),
            ]
            .into_iter()
            .collect(),
        )
        .expect_err("unexpected keys must be rejected for opencode tool adapter");

        assert!(error.contains(
            "tool 'opencode' does not allow projecting provider env key 'UNRELATED_TOKEN'"
        ));
    }

    #[test]
    fn opencode_token_placeholders_resolve_only_when_forwarding_headers() {
        let (child_env, resolver) = SecretResolver::from_tool_provider_env(
            ToolAdapter::OpenCode,
            [
                ("GITHUB_TOKEN".to_string(), "ghu-test".to_string()),
                ("GH_TOKEN".to_string(), "ghs-test".to_string()),
            ]
            .into_iter()
            .collect(),
        )
        .expect("opencode projection succeeds for github token aliases");

        let github_placeholder = child_env.get("GITHUB_TOKEN").expect("github placeholder");
        let gh_placeholder = child_env.get("GH_TOKEN").expect("gh placeholder");

        assert_eq!(github_placeholder, &placeholder_for_env_key("GITHUB_TOKEN"));
        assert_eq!(gh_placeholder, &placeholder_for_env_key("GH_TOKEN"));
        assert!(!github_placeholder.contains("ghu-test"));
        assert!(!gh_placeholder.contains("ghs-test"));

        let body = format!("body={gh_placeholder}");

        let raw = format!(
            "POST /v1/chat/completions HTTP/1.1\r\n\
             Authorization: Bearer {github_placeholder}\r\n\
             X-GitHub-Token: {gh_placeholder}\r\n\
             Content-Length: {}\r\n\r\n\
             {body}",
            body.len()
        );

        assert!(raw.contains(github_placeholder));
        assert!(raw.contains(gh_placeholder));
        assert!(!raw.contains("ghu-test"));
        assert!(!raw.contains("ghs-test"));

        let rewritten = rewrite_http_header_block(raw.as_bytes(), resolver.as_ref());
        let rewritten = String::from_utf8(rewritten).expect("utf8");

        assert!(rewritten.contains("Authorization: Bearer ghu-test\r\n"));
        assert!(rewritten.contains("X-GitHub-Token: ghs-test\r\n"));
        assert!(rewritten.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(rewritten.ends_with(&format!("\r\n\r\nbody={gh_placeholder}")));
    }

    #[test]
    fn rewrite_with_no_resolver_returns_original() {
        let raw = b"GET / HTTP/1.1\r\nAuthorization: Bearer my-token\r\n\r\n";
        let rewritten = rewrite_http_header_block(raw, None);
        assert_eq!(raw.as_slice(), rewritten.as_slice());
    }
}
