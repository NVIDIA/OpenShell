// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

const PLACEHOLDER_PREFIX: &str = "nemo-placeholder:env:";

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
            Some(&"nemo-placeholder:env:ANTHROPIC_API_KEY".to_string())
        );
        assert_eq!(
            resolver
                .as_ref()
                .and_then(|resolver| resolver
                    .resolve_placeholder("nemo-placeholder:env:ANTHROPIC_API_KEY")),
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
            rewrite_header_line("x-api-key: nemo-placeholder:env:CUSTOM_TOKEN", &resolver),
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
                "Authorization: Bearer nemo-placeholder:env:ANTHROPIC_API_KEY",
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

        let raw = b"POST /v1 HTTP/1.1\r\nAuthorization: Bearer nemo-placeholder:env:CUSTOM_TOKEN\r\nContent-Length: 5\r\n\r\nhello";
        let rewritten = rewrite_http_header_block(raw, resolver.as_ref());
        let rewritten = String::from_utf8(rewritten).expect("utf8");

        assert!(rewritten.contains("Authorization: Bearer secret-token\r\n"));
        assert!(rewritten.ends_with("\r\n\r\nhello"));
    }
}
