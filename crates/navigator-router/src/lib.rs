// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod backend;
pub mod config;
mod mock;

use std::time::Duration;

pub use backend::ProxyResponse;
use config::{ResolvedRoute, RouterConfig};
use tracing::info;

#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("route not found for routing_hint '{0}'")]
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

impl Router {
    pub fn new() -> Result<Self, RouterError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
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
    /// Filters candidates by `source_protocol` compatibility (exact match against
    /// one of the route's `protocols`), then forwards to the first match.
    pub async fn proxy_with_candidates(
        &self,
        source_protocol: &str,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: bytes::Bytes,
        candidates: &[ResolvedRoute],
    ) -> Result<ProxyResponse, RouterError> {
        let normalized_source = source_protocol.trim().to_ascii_lowercase();
        let route = candidates
            .iter()
            .find(|r| r.protocols.iter().any(|p| p == &normalized_source))
            .ok_or_else(|| RouterError::NoCompatibleRoute(source_protocol.to_string()))?;

        info!(
            routing_hint = %route.routing_hint,
            protocols = %route.protocols.join(","),
            endpoint = %route.endpoint,
            method = %method,
            path = %path,
            "routing proxy inference request"
        );

        if mock::is_mock_route(route) {
            info!(routing_hint = %route.routing_hint, "returning mock response");
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{RouteConfig, RouterConfig};

    fn test_config() -> RouterConfig {
        RouterConfig {
            routes: vec![
                RouteConfig {
                    routing_hint: "local".to_string(),
                    endpoint: "http://localhost:8000/v1".to_string(),
                    model: "meta/llama-3.1-8b-instruct".to_string(),
                    protocols: vec!["openai_chat_completions".to_string()],
                    api_key: Some("test-key".to_string()),
                    api_key_env: None,
                },
                RouteConfig {
                    routing_hint: "frontier".to_string(),
                    endpoint: "http://localhost:8000/v1".to_string(),
                    model: "meta/llama-3.1-70b-instruct".to_string(),
                    protocols: vec!["openai_chat_completions".to_string()],
                    api_key: Some("test-key".to_string()),
                    api_key_env: None,
                },
            ],
        }
    }

    #[test]
    fn router_resolves_routes_from_config() {
        let router = Router::from_config(&test_config()).unwrap();
        assert_eq!(router.routes.len(), 2);
        assert_eq!(router.routes[0].routing_hint, "local");
        assert_eq!(router.routes[0].protocols, vec!["openai_chat_completions"]);
    }

    #[test]
    fn config_missing_api_key_returns_error() {
        let config = RouterConfig {
            routes: vec![RouteConfig {
                routing_hint: "test".to_string(),
                endpoint: "http://localhost".to_string(),
                model: "test-model".to_string(),
                protocols: vec!["openai_chat_completions".to_string()],
                api_key: None,
                api_key_env: None,
            }],
        };
        let err = Router::from_config(&config).unwrap_err();
        assert!(matches!(err, RouterError::Internal(_)));
    }
}
