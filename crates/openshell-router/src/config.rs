// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use std::path::Path;
use std::time::Duration;

pub use openshell_core::inference::AuthHeader;

use crate::RouterError;

pub const DEFAULT_ROUTE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Deserialize)]
pub struct RouterConfig {
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    pub name: String,
    pub endpoint: String,
    pub model: String,
    #[serde(default)]
    pub provider_type: Option<String>,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
}

/// A fully-resolved route ready for the router to forward requests.
///
/// The router is provider-agnostic — all provider-specific decisions
/// (auth header style, default headers, passthrough headers, base URL) are made by the
/// caller during resolution.
#[derive(Clone)]
pub struct ResolvedRoute {
    /// Route name used for identification (e.g. "inference.local", "sandbox-system").
    pub name: String,
    pub endpoint: String,
    pub model: String,
    pub api_key: String,
    pub protocols: Vec<String>,
    /// How to inject the API key on outgoing requests.
    pub auth: AuthHeader,
    /// Extra headers injected on every request (e.g. `anthropic-version`).
    pub default_headers: Vec<(String, String)>,
    /// Client-supplied headers that may be forwarded to the upstream backend.
    pub passthrough_headers: Vec<String>,
    /// Per-request timeout for proxied inference calls.
    pub timeout: Duration,
}

impl std::fmt::Debug for ResolvedRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedRoute")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("model", &self.model)
            .field("api_key", &"[REDACTED]")
            .field("protocols", &self.protocols)
            .field("auth", &self.auth)
            .field("default_headers", &self.default_headers)
            .field("passthrough_headers", &self.passthrough_headers)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl RouterConfig {
    pub fn load_from_file(path: &Path) -> Result<Self, RouterError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            RouterError::Internal(format!(
                "failed to read router config {}: {e}",
                path.display()
            ))
        })?;
        let config: Self = serde_yml::from_str(&content).map_err(|e| {
            RouterError::Internal(format!(
                "failed to parse router config {}: {e}",
                path.display()
            ))
        })?;
        config.resolve()
    }

    fn resolve(self) -> Result<Self, RouterError> {
        // Validate that all routes can resolve their API keys
        for route in &self.routes {
            route.resolve_api_key()?;
        }
        Ok(self)
    }

    pub fn resolve_routes(&self) -> Result<Vec<ResolvedRoute>, RouterError> {
        self.routes.iter().map(RouteConfig::resolve).collect()
    }
}

impl RouteConfig {
    fn resolve_api_key(&self) -> Result<String, RouterError> {
        if let Some(key) = &self.api_key {
            return Ok(key.clone());
        }
        if let Some(env_var) = &self.api_key_env {
            return std::env::var(env_var).map_err(|_| {
                RouterError::Internal(format!(
                    "environment variable {env_var} not set for route '{}'",
                    self.name
                ))
            });
        }
        Err(RouterError::Internal(format!(
            "route '{}' has neither api_key nor api_key_env",
            self.name
        )))
    }

    fn resolve(&self) -> Result<ResolvedRoute, RouterError> {
        let protocols = openshell_core::inference::normalize_protocols(&self.protocols);
        if protocols.is_empty() {
            return Err(RouterError::Internal(format!(
                "route '{}' has no protocols",
                self.name
            )));
        }

        let (auth, default_headers, passthrough_headers) =
            route_headers_from_provider_type(self.provider_type.as_deref());

        Ok(ResolvedRoute {
            name: self.name.clone(),
            endpoint: self.endpoint.clone(),
            model: self.model.clone(),
            api_key: self.resolve_api_key()?,
            protocols,
            auth,
            default_headers,
            passthrough_headers,
            timeout: DEFAULT_ROUTE_TIMEOUT,
        })
    }
}

/// Derive auth header style, default headers, and passthrough headers from a
/// provider type string.
///
/// Delegates to [`openshell_core::inference::route_headers_for_provider_type`]
/// which uses the centralized `InferenceProviderProfile` registry.
fn route_headers_from_provider_type(
    provider_type: Option<&str>,
) -> (AuthHeader, Vec<(String, String)>, Vec<String>) {
    openshell_core::inference::route_headers_for_provider_type(provider_type.unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn load_from_file_valid_yaml_round_trip() {
        let yaml = r#"
routes:
  - name: inference.local
    endpoint: http://localhost:8000/v1
    model: llama-3
    protocols: [openai_chat_completions]
    api_key: sk-test-key
  - name: inference.local
    endpoint: https://api.openai.com/v1
    model: gpt-4o
    protocols: [openai_chat_completions, anthropic_messages]
    api_key: sk-prod-key
"#;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(yaml.as_bytes()).unwrap();

        let config = RouterConfig::load_from_file(f.path()).unwrap();
        assert_eq!(config.routes.len(), 2);
        assert_eq!(config.routes[0].name, "inference.local");
        assert_eq!(config.routes[1].name, "inference.local");

        let resolved = config.resolve_routes().unwrap();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].api_key, "sk-test-key");
        assert_eq!(resolved[1].model, "gpt-4o");
        assert_eq!(
            resolved[1].protocols,
            vec!["openai_chat_completions", "anthropic_messages"]
        );
    }

    #[test]
    fn load_from_file_invalid_yaml_returns_error() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"not: [valid: yaml: {{{{").unwrap();

        let err = RouterConfig::load_from_file(f.path()).unwrap_err();
        assert!(
            matches!(err, RouterError::Internal(_)),
            "expected Internal error, got: {err:?}"
        );
    }

    #[test]
    fn load_from_file_missing_api_key_returns_error() {
        let yaml = r#"
routes:
  - name: inference.local
    endpoint: http://localhost:8000/v1
    model: llama-3
    protocols: [openai_chat_completions]
"#;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(yaml.as_bytes()).unwrap();

        let err = RouterConfig::load_from_file(f.path()).unwrap_err();
        assert!(
            matches!(err, RouterError::Internal(_)),
            "expected Internal error for missing api_key, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("neither api_key nor api_key_env"),
            "error should mention missing key: {msg}"
        );
    }

    #[test]
    fn load_from_file_api_key_env_resolves_from_environment() {
        let yaml = r#"
routes:
  - name: inference.local
    endpoint: http://localhost:8000/v1
    model: llama-3
    protocols: [openai_chat_completions]
    api_key_env: NAV_TEST_API_KEY_FOR_YAML_TEST
"#;
        // SAFETY: this test runs single-threaded; no other thread reads this var.
        unsafe { std::env::set_var("NAV_TEST_API_KEY_FOR_YAML_TEST", "from-env") };
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(yaml.as_bytes()).unwrap();

        let config = RouterConfig::load_from_file(f.path()).unwrap();
        let resolved = config.resolve_routes().unwrap();
        assert_eq!(resolved[0].api_key, "from-env");

        unsafe { std::env::remove_var("NAV_TEST_API_KEY_FOR_YAML_TEST") };
    }

    #[test]
    fn load_from_file_nonexistent_path_returns_error() {
        let err = RouterConfig::load_from_file(Path::new("/nonexistent/routes.yaml")).unwrap_err();
        assert!(
            matches!(err, RouterError::Internal(_)),
            "expected Internal error, got: {err:?}"
        );
    }

    #[test]
    fn resolved_route_debug_redacts_api_key() {
        let route = ResolvedRoute {
            name: "test".to_string(),
            endpoint: "https://api.example.com/v1".to_string(),
            model: "test-model".to_string(),
            api_key: "sk-super-secret-key-12345".to_string(),
            protocols: vec!["openai_chat_completions".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: Vec::new(),
            passthrough_headers: Vec::new(),
            timeout: DEFAULT_ROUTE_TIMEOUT,
        };
        let debug_output = format!("{route:?}");
        assert!(
            !debug_output.contains("sk-super-secret-key-12345"),
            "Debug output must not contain raw API key: {debug_output}"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should show [REDACTED] for api_key: {debug_output}"
        );
    }

    #[test]
    fn auth_from_anthropic_provider_uses_custom_header() {
        let (auth, headers, passthrough_headers) =
            route_headers_from_provider_type(Some("anthropic"));
        assert_eq!(auth, AuthHeader::Custom("x-api-key"));
        assert!(headers.iter().any(|(k, _)| k == "anthropic-version"));
        assert!(
            passthrough_headers
                .iter()
                .any(|name| name == "anthropic-beta")
        );
    }

    #[test]
    fn auth_from_openai_provider_uses_bearer() {
        let (auth, headers, passthrough_headers) = route_headers_from_provider_type(Some("openai"));
        assert_eq!(auth, AuthHeader::Bearer);
        assert!(headers.is_empty());
        assert!(
            passthrough_headers
                .iter()
                .any(|name| name == "openai-organization")
        );
    }

    #[test]
    fn auth_from_none_defaults_to_bearer() {
        let (auth, headers, passthrough_headers) = route_headers_from_provider_type(None);
        assert_eq!(auth, AuthHeader::Bearer);
        assert!(headers.is_empty());
        assert!(passthrough_headers.is_empty());
    }
}
