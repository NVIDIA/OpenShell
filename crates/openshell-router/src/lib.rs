// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod backend;
pub mod config;
mod mock;

pub use backend::{
    ProxyResponse, StreamingProxyResponse, ValidatedEndpoint, ValidationFailure,
    ValidationFailureKind, verify_backend_endpoint,
};
use config::{ResolvedRoute, RouterConfig};
use tracing::info;

#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("route not found for route '{0}'")]
    RouteNotFound(String),
    #[error("no compatible route for protocol '{0}'")]
    NoCompatibleRoute(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("upstream unavailable: {0}")]
    UpstreamUnavailable(String),
    #[error("upstream protocol error: {0}")]
    UpstreamProtocol(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug)]
pub struct Router {
    routes: Vec<ResolvedRoute>,
    client: reqwest::Client,
}

/// Select a route from `candidates` using alias-first, model-second,
/// protocol-fallback strategy.
///
/// 1. If `model_hint` is provided, find a candidate whose `name` (alias)
///    matches the hint **and** whose protocols include `protocol`.
/// 2. Else if `model_hint` is provided, find a candidate whose `model`
///    matches the hint **and** whose protocols include `protocol`.
/// 3. Otherwise, return the first candidate whose protocols contain `protocol`.
fn select_route<'a>(
    candidates: &'a [ResolvedRoute],
    protocol: &str,
    model_hint: Option<&str>,
) -> Option<&'a ResolvedRoute> {
    if let Some(hint) = model_hint {
        let normalized_hint = hint.trim().to_ascii_lowercase();
        // 1. Alias match (route name == model hint).
        if let Some(r) = candidates.iter().find(|r| {
            r.name.trim().to_ascii_lowercase() == normalized_hint
                && r.protocols.iter().any(|p| p == protocol)
        }) {
            return Some(r);
        }
        // 2. Model ID match (route model == model hint).
        if let Some(r) = candidates.iter().find(|r| {
            r.model.trim().to_ascii_lowercase() == normalized_hint
                && r.protocols.iter().any(|p| p == protocol)
        }) {
            return Some(r);
        }
    }
    // 3. First protocol-compatible route.
    candidates
        .iter()
        .find(|r| r.protocols.iter().any(|p| p == protocol))
}

impl Router {
    pub fn new() -> Result<Self, RouterError> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| RouterError::Internal(format!("failed to build HTTP client: {e}")))?;
        Ok(Self {
            routes: Vec::new(),
            client,
        })
    }

    pub fn from_config(config: &RouterConfig) -> Result<Self, RouterError> {
        let resolved = config.resolve_routes()?;
        let mut router = Self::new()?;
        router.routes = resolved;
        Ok(router)
    }

    /// Proxy a raw HTTP request to the first compatible route from `candidates`.
    ///
    /// When `model_hint` is provided, the router first looks for a candidate whose
    /// `name` (alias) matches the hint.  If no alias matches, it falls back to
    /// protocol-based selection (first candidate whose `protocols` list contains
    /// `source_protocol`).
    pub async fn proxy_with_candidates(
        &self,
        source_protocol: &str,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: bytes::Bytes,
        candidates: &[ResolvedRoute],
        model_hint: Option<&str>,
    ) -> Result<ProxyResponse, RouterError> {
        let normalized_source = source_protocol.trim().to_ascii_lowercase();
        let route = select_route(candidates, &normalized_source, model_hint)
            .ok_or_else(|| RouterError::NoCompatibleRoute(source_protocol.to_string()))?;

        info!(
            protocols = %route.protocols.join(","),
            endpoint = %route.endpoint,
            method = %method,
            path = %path,
            "routing proxy inference request"
        );

        if mock::is_mock_route(route) {
            info!(endpoint = %route.endpoint, "returning mock response");
            return Ok(mock::mock_response(route, &normalized_source));
        }

        backend::proxy_to_backend(
            &self.client,
            route,
            &normalized_source,
            method,
            path,
            headers,
            body,
        )
        .await
    }

    /// Streaming variant of [`proxy_with_candidates`](Self::proxy_with_candidates).
    ///
    /// Returns response headers immediately without buffering the body.
    /// The caller streams body chunks via [`StreamingProxyResponse::response`].
    pub async fn proxy_with_candidates_streaming(
        &self,
        source_protocol: &str,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: bytes::Bytes,
        candidates: &[ResolvedRoute],
        model_hint: Option<&str>,
    ) -> Result<StreamingProxyResponse, RouterError> {
        let normalized_source = source_protocol.trim().to_ascii_lowercase();
        let route = select_route(candidates, &normalized_source, model_hint)
            .ok_or_else(|| RouterError::NoCompatibleRoute(source_protocol.to_string()))?;

        info!(
            protocols = %route.protocols.join(","),
            endpoint = %route.endpoint,
            method = %method,
            path = %path,
            "routing proxy inference request (streaming)"
        );

        if mock::is_mock_route(route) {
            info!(endpoint = %route.endpoint, "returning mock response (buffered)");
            let buffered = mock::mock_response(route, &normalized_source);
            return Ok(StreamingProxyResponse::from_buffered(buffered));
        }

        backend::proxy_to_backend_streaming(
            &self.client,
            route,
            &normalized_source,
            method,
            path,
            headers,
            body,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{RouteConfig, RouterConfig};

    fn test_config() -> RouterConfig {
        RouterConfig {
            routes: vec![RouteConfig {
                name: "inference.local".to_string(),
                endpoint: "http://localhost:8000/v1".to_string(),
                model: "meta/llama-3.1-8b-instruct".to_string(),
                provider_type: None,
                protocols: vec!["openai_chat_completions".to_string()],
                api_key: Some("test-key".to_string()),
                api_key_env: None,
            }],
        }
    }

    #[test]
    fn router_resolves_routes_from_config() {
        let router = Router::from_config(&test_config()).unwrap();
        assert_eq!(router.routes.len(), 1);
        assert_eq!(router.routes[0].protocols, vec!["openai_chat_completions"]);
    }

    #[test]
    fn config_missing_api_key_returns_error() {
        let config = RouterConfig {
            routes: vec![RouteConfig {
                name: "inference.local".to_string(),
                endpoint: "http://localhost".to_string(),
                model: "test-model".to_string(),
                provider_type: None,
                protocols: vec!["openai_chat_completions".to_string()],
                api_key: None,
                api_key_env: None,
            }],
        };
        let err = Router::from_config(&config).unwrap_err();
        assert!(matches!(err, RouterError::Internal(_)));
    }

    fn make_route(name: &str, protocols: Vec<&str>) -> ResolvedRoute {
        ResolvedRoute {
            name: name.to_string(),
            endpoint: "http://localhost".to_string(),
            model: format!("{name}-model"),
            api_key: "key".to_string(),
            protocols: protocols.into_iter().map(String::from).collect(),
            auth: config::AuthHeader::Bearer,
            default_headers: Vec::new(),
            timeout: std::time::Duration::from_secs(60),
        }
    }

    #[test]
    fn select_route_protocol_fallback_when_no_hint() {
        let routes = vec![
            make_route("ollama-local", vec!["openai_chat_completions"]),
            make_route("anthropic-prod", vec!["anthropic_messages"]),
        ];
        let r = select_route(&routes, "anthropic_messages", None).unwrap();
        assert_eq!(r.name, "anthropic-prod");
    }

    #[test]
    fn select_route_alias_match_takes_priority() {
        let routes = vec![
            make_route("ollama-local", vec!["openai_chat_completions"]),
            make_route(
                "openai-prod",
                vec!["openai_chat_completions", "openai_responses"],
            ),
        ];
        // Both support openai_chat_completions, but hint selects the second one.
        let r = select_route(&routes, "openai_chat_completions", Some("openai-prod")).unwrap();
        assert_eq!(r.name, "openai-prod");
    }

    #[test]
    fn select_route_alias_must_also_match_protocol() {
        let routes = vec![
            make_route("ollama-local", vec!["openai_chat_completions"]),
            make_route("anthropic-prod", vec!["anthropic_messages"]),
        ];
        // Hint says "anthropic-prod" but protocol is openai_chat_completions — can't use it.
        // Falls back to protocol match → ollama-local.
        let r = select_route(&routes, "openai_chat_completions", Some("anthropic-prod")).unwrap();
        assert_eq!(r.name, "ollama-local");
    }

    #[test]
    fn select_route_no_match_returns_none() {
        let routes = vec![make_route("ollama-local", vec!["openai_chat_completions"])];
        assert!(select_route(&routes, "anthropic_messages", None).is_none());
    }

    #[test]
    fn select_route_alias_match_is_case_insensitive() {
        let routes = vec![
            make_route("My-GPT", vec!["openai_chat_completions"]),
            make_route("anthropic-prod", vec!["anthropic_messages"]),
        ];
        let r = select_route(&routes, "openai_chat_completions", Some("my-gpt")).unwrap();
        assert_eq!(r.name, "My-GPT");
    }

    #[test]
    fn select_route_model_id_match() {
        // When the hint doesn't match any alias but does match a route's model,
        // that route is selected.
        let routes = vec![
            make_route("ollama-local", vec!["openai_responses"]),
            make_route("openai-codex", vec!["openai_responses"]),
        ];
        // openai-codex has model "openai-codex-model"; ollama-local has "ollama-local-model".
        // Hint "openai-codex-model" doesn't match any alias, but matches the model field.
        let r = select_route(&routes, "openai_responses", Some("openai-codex-model")).unwrap();
        assert_eq!(r.name, "openai-codex");
    }

    #[test]
    fn select_route_alias_beats_model_id() {
        // Alias match takes priority over model ID match.
        let mut routes = vec![
            make_route("ollama-local", vec!["openai_chat_completions"]),
            make_route("openai-prod", vec!["openai_chat_completions"]),
        ];
        // Give ollama-local a model that matches the second route's name.
        routes[0].model = "openai-prod".to_string();
        let r = select_route(&routes, "openai_chat_completions", Some("openai-prod")).unwrap();
        // Alias match wins: route named "openai-prod", not the one with model="openai-prod".
        assert_eq!(r.name, "openai-prod");
    }
}
