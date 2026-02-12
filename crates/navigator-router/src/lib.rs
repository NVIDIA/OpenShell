mod backend;
pub mod config;

use std::time::Duration;

use config::{ResolvedRoute, RouterConfig};
use navigator_core::proto::{CompletionRequest, CompletionResponse};
use tracing::info;

#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("route not found for routing_hint '{0}'")]
    RouteNotFound(String),
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
        let routes = config.resolve_routes()?;
        let mut router = Self::new()?;
        router.routes = routes;
        Ok(router)
    }

    pub async fn completion(
        &self,
        request: &CompletionRequest,
    ) -> Result<CompletionResponse, RouterError> {
        self.completion_with_candidates(request, &self.routes).await
    }

    pub async fn completion_with_candidates(
        &self,
        request: &CompletionRequest,
        candidates: &[ResolvedRoute],
    ) -> Result<CompletionResponse, RouterError> {
        let route = resolve_route_from_candidates(candidates, &request.routing_hint)?;
        self.completion_for_route(route, request).await
    }

    pub async fn completion_for_route(
        &self,
        route: &ResolvedRoute,
        request: &CompletionRequest,
    ) -> Result<CompletionResponse, RouterError> {
        info!(
            routing_hint = %route.routing_hint,
            model = %route.model,
            endpoint = %route.endpoint,
            "routing completion request"
        );

        backend::call_backend(&self.client, route, request).await
    }
}

fn resolve_route_from_candidates<'a>(
    routes: &'a [ResolvedRoute],
    routing_hint: &str,
) -> Result<&'a ResolvedRoute, RouterError> {
    if routing_hint.is_empty() {
        return routes
            .first()
            .ok_or_else(|| RouterError::Internal("no routes configured".to_string()));
    }

    routes
        .iter()
        .find(|r| r.routing_hint == routing_hint)
        .ok_or_else(|| RouterError::RouteNotFound(routing_hint.to_string()))
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
                    api_key: Some("test-key".to_string()),
                    api_key_env: None,
                },
                RouteConfig {
                    routing_hint: "frontier".to_string(),
                    endpoint: "http://localhost:8000/v1".to_string(),
                    model: "meta/llama-3.1-70b-instruct".to_string(),
                    api_key: Some("test-key".to_string()),
                    api_key_env: None,
                },
            ],
        }
    }

    #[test]
    fn resolve_known_hint() {
        let router = Router::from_config(&test_config()).unwrap();
        let route = resolve_route_from_candidates(&router.routes, "frontier").unwrap();
        assert_eq!(route.model, "meta/llama-3.1-70b-instruct");
    }

    #[test]
    fn resolve_empty_hint_falls_back_to_first() {
        let router = Router::from_config(&test_config()).unwrap();
        let route = resolve_route_from_candidates(&router.routes, "").unwrap();
        assert_eq!(route.model, "meta/llama-3.1-8b-instruct");
    }

    #[test]
    fn resolve_unknown_hint_returns_error() {
        let router = Router::from_config(&test_config()).unwrap();
        let err = resolve_route_from_candidates(&router.routes, "unknown").unwrap_err();
        assert!(matches!(err, RouterError::RouteNotFound(_)));
    }

    #[test]
    fn resolve_from_external_candidates_works() {
        let router = Router::new().unwrap();
        let candidates = vec![ResolvedRoute {
            routing_hint: "local".to_string(),
            endpoint: "http://localhost:8000/v1".to_string(),
            model: "test/model".to_string(),
            api_key: "test-key".to_string(),
        }];
        let route = resolve_route_from_candidates(&candidates, "local").unwrap();
        assert_eq!(route.model, "test/model");
        assert!(router.routes.is_empty());
    }

    #[test]
    fn config_missing_api_key_returns_error() {
        let config = RouterConfig {
            routes: vec![RouteConfig {
                routing_hint: "test".to_string(),
                endpoint: "http://localhost".to_string(),
                model: "test-model".to_string(),
                api_key: None,
                api_key_env: None,
            }],
        };
        let err = Router::from_config(&config).unwrap_err();
        assert!(matches!(err, RouterError::Internal(_)));
    }
}
