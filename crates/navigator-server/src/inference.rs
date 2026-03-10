// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use navigator_core::proto::{
    ClusterInferenceConfig, GetClusterInferenceRequest, GetClusterInferenceResponse,
    GetInferenceBundleRequest, GetInferenceBundleResponse, InferenceRoute, Provider, ResolvedRoute,
    SetClusterInferenceRequest, SetClusterInferenceResponse, inference_server::Inference,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::{
    ServerState,
    persistence::{ObjectId, ObjectName, ObjectType, Store},
};

#[derive(Debug)]
pub struct InferenceService {
    state: Arc<ServerState>,
}

impl InferenceService {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

const CLUSTER_INFERENCE_ROUTE_NAME: &str = "inference.local";

impl ObjectType for InferenceRoute {
    fn object_type() -> &'static str {
        "inference_route"
    }
}

impl ObjectId for InferenceRoute {
    fn object_id(&self) -> &str {
        &self.id
    }
}

impl ObjectName for InferenceRoute {
    fn object_name(&self) -> &str {
        &self.name
    }
}

#[tonic::async_trait]
impl Inference for InferenceService {
    async fn get_inference_bundle(
        &self,
        _request: Request<GetInferenceBundleRequest>,
    ) -> Result<Response<GetInferenceBundleResponse>, Status> {
        resolve_inference_bundle(self.state.store.as_ref())
            .await
            .map(Response::new)
    }

    async fn set_cluster_inference(
        &self,
        request: Request<SetClusterInferenceRequest>,
    ) -> Result<Response<SetClusterInferenceResponse>, Status> {
        let req = request.into_inner();
        let route = upsert_cluster_inference_route(
            self.state.store.as_ref(),
            &req.provider_name,
            &req.model_id,
        )
        .await?;

        let config = route
            .config
            .as_ref()
            .ok_or_else(|| Status::internal("managed route missing config"))?;

        Ok(Response::new(SetClusterInferenceResponse {
            provider_name: config.provider_name.clone(),
            model_id: config.model_id.clone(),
            version: route.version,
        }))
    }

    async fn get_cluster_inference(
        &self,
        _request: Request<GetClusterInferenceRequest>,
    ) -> Result<Response<GetClusterInferenceResponse>, Status> {
        let route = self
            .state
            .store
            .get_message_by_name::<InferenceRoute>(CLUSTER_INFERENCE_ROUTE_NAME)
            .await
            .map_err(|e| Status::internal(format!("fetch route failed: {e}")))?
            .ok_or_else(|| {
                Status::not_found(
                    "cluster inference is not configured; run 'openshell cluster inference set --provider <name> --model <id>'",
                )
            })?;

        let config = route
            .config
            .as_ref()
            .ok_or_else(|| Status::internal("managed route missing config"))?;

        if config.provider_name.trim().is_empty() || config.model_id.trim().is_empty() {
            return Err(Status::failed_precondition(
                "managed route is missing provider/model metadata",
            ));
        }

        Ok(Response::new(GetClusterInferenceResponse {
            provider_name: config.provider_name.clone(),
            model_id: config.model_id.clone(),
            version: route.version,
        }))
    }
}

async fn upsert_cluster_inference_route(
    store: &Store,
    provider_name: &str,
    model_id: &str,
) -> Result<InferenceRoute, Status> {
    if provider_name.trim().is_empty() {
        return Err(Status::invalid_argument("provider_name is required"));
    }
    if model_id.trim().is_empty() {
        return Err(Status::invalid_argument("model_id is required"));
    }

    let provider = store
        .get_message_by_name::<Provider>(provider_name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| {
            Status::failed_precondition(format!("provider '{provider_name}' not found"))
        })?;

    // Validate provider shape at set time; endpoint/auth are resolved from the
    // provider record when generating sandbox bundles.
    let _ = resolve_provider_route(&provider)?;

    let config = build_cluster_inference_config(&provider, model_id);

    let existing = store
        .get_message_by_name::<InferenceRoute>(CLUSTER_INFERENCE_ROUTE_NAME)
        .await
        .map_err(|e| Status::internal(format!("fetch route failed: {e}")))?;

    let route = if let Some(existing) = existing {
        InferenceRoute {
            id: existing.id,
            name: existing.name,
            config: Some(config),
            version: existing.version.saturating_add(1),
        }
    } else {
        InferenceRoute {
            id: uuid::Uuid::new_v4().to_string(),
            name: CLUSTER_INFERENCE_ROUTE_NAME.to_string(),
            config: Some(config),
            version: 1,
        }
    };

    store
        .put_message(&route)
        .await
        .map_err(|e| Status::internal(format!("persist route failed: {e}")))?;

    Ok(route)
}

fn build_cluster_inference_config(provider: &Provider, model_id: &str) -> ClusterInferenceConfig {
    ClusterInferenceConfig {
        provider_name: provider.name.clone(),
        model_id: model_id.to_string(),
    }
}

struct ResolvedProviderRoute {
    provider_type: String,
    base_url: String,
    protocols: Vec<String>,
    api_key: String,
}

fn resolve_provider_route(provider: &Provider) -> Result<ResolvedProviderRoute, Status> {
    let provider_type = provider.r#type.trim().to_ascii_lowercase();

    let profile = navigator_core::inference::profile_for(&provider_type).ok_or_else(|| {
        Status::invalid_argument(format!(
            "provider '{name}' has unsupported type '{provider_type}' for cluster inference \
                 (supported: openai, anthropic, nvidia)",
            name = provider.name
        ))
    })?;

    let api_key =
        find_provider_api_key(provider, profile.credential_key_names).ok_or_else(|| {
            Status::invalid_argument(format!(
                "provider '{name}' has no usable API key credential",
                name = provider.name
            ))
        })?;

    let base_url = find_provider_config_value(provider, profile.base_url_config_keys)
        .unwrap_or_else(|| profile.default_base_url.to_string())
        .trim()
        .to_string();

    if base_url.is_empty() {
        return Err(Status::invalid_argument(format!(
            "provider '{name}' resolved to empty base_url",
            name = provider.name
        )));
    }

    Ok(ResolvedProviderRoute {
        provider_type,
        base_url,
        protocols: profile.protocols.iter().map(|p| (*p).to_string()).collect(),
        api_key,
    })
}

fn find_provider_api_key(provider: &Provider, preferred_key_names: &[&str]) -> Option<String> {
    for key in preferred_key_names {
        if let Some(value) = provider.credentials.get(*key)
            && !value.trim().is_empty()
        {
            return Some(value.clone());
        }
    }

    let mut keys = provider.credentials.keys().collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        if let Some(value) = provider.credentials.get(key)
            && !value.trim().is_empty()
        {
            return Some(value.clone());
        }
    }

    None
}

fn find_provider_config_value(provider: &Provider, preferred_keys: &[&str]) -> Option<String> {
    for key in preferred_keys {
        if let Some(value) = provider.config.get(*key)
            && !value.trim().is_empty()
        {
            return Some(value.clone());
        }
    }
    None
}

/// Resolve the inference bundle (managed cluster route + revision hash).
async fn resolve_inference_bundle(store: &Store) -> Result<GetInferenceBundleResponse, Status> {
    let routes = resolve_managed_cluster_route(store)
        .await?
        .into_iter()
        .collect::<Vec<_>>();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    // Compute a simple revision from route contents for cache freshness checks.
    let revision = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for r in &routes {
            r.name.hash(&mut hasher);
            r.base_url.hash(&mut hasher);
            r.model_id.hash(&mut hasher);
            r.api_key.hash(&mut hasher);
            r.protocols.hash(&mut hasher);
            r.provider_type.hash(&mut hasher);
        }
        format!("{:016x}", hasher.finish())
    };

    Ok(GetInferenceBundleResponse {
        routes,
        revision,
        generated_at_ms: now_ms,
    })
}

async fn resolve_managed_cluster_route(store: &Store) -> Result<Option<ResolvedRoute>, Status> {
    let route = store
        .get_message_by_name::<InferenceRoute>(CLUSTER_INFERENCE_ROUTE_NAME)
        .await
        .map_err(|e| Status::internal(format!("fetch route failed: {e}")))?;

    let Some(route) = route else {
        return Ok(None);
    };

    let Some(config) = route.config.as_ref() else {
        return Ok(None);
    };

    if config.provider_name.trim().is_empty() {
        return Err(Status::failed_precondition(
            "managed route is missing provider_name",
        ));
    }

    if config.model_id.trim().is_empty() {
        return Err(Status::failed_precondition(
            "managed route is missing model_id",
        ));
    }

    let provider = store
        .get_message_by_name::<Provider>(&config.provider_name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| {
            Status::failed_precondition(format!(
                "configured provider '{}' was not found",
                config.provider_name
            ))
        })?;

    let resolved = resolve_provider_route(&provider)?;

    Ok(Some(ResolvedRoute {
        name: CLUSTER_INFERENCE_ROUTE_NAME.to_string(),
        base_url: resolved.base_url,
        model_id: config.model_id.clone(),
        api_key: resolved.api_key,
        protocols: resolved.protocols,
        provider_type: resolved.provider_type,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_route(name: &str, provider_name: &str, model_id: &str) -> InferenceRoute {
        InferenceRoute {
            id: format!("id-{name}"),
            name: name.to_string(),
            config: Some(ClusterInferenceConfig {
                provider_name: provider_name.to_string(),
                model_id: model_id.to_string(),
            }),
            version: 1,
        }
    }

    fn make_provider(name: &str, provider_type: &str, key_name: &str, key_value: &str) -> Provider {
        Provider {
            id: format!("provider-{name}"),
            name: name.to_string(),
            r#type: provider_type.to_string(),
            credentials: std::iter::once((key_name.to_string(), key_value.to_string())).collect(),
            config: std::collections::HashMap::new(),
        }
    }

    #[tokio::test]
    async fn upsert_cluster_route_creates_and_increments_version() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store should connect");

        let provider = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-test");
        store
            .put_message(&provider)
            .await
            .expect("provider should persist");

        let first = upsert_cluster_inference_route(&store, "openai-dev", "gpt-4o")
            .await
            .expect("first set should succeed");
        assert_eq!(first.name, CLUSTER_INFERENCE_ROUTE_NAME);
        assert_eq!(first.version, 1);

        let second = upsert_cluster_inference_route(&store, "openai-dev", "gpt-4.1")
            .await
            .expect("second set should succeed");
        assert_eq!(second.version, 2);
        assert_eq!(second.id, first.id);

        let config = second.config.as_ref().expect("config");
        assert_eq!(config.provider_name, "openai-dev");
        assert_eq!(config.model_id, "gpt-4.1");
    }

    #[tokio::test]
    async fn resolve_managed_route_returns_none_when_missing() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store should connect");

        let route = resolve_managed_cluster_route(&store)
            .await
            .expect("resolution should not fail");
        assert!(route.is_none());
    }

    #[tokio::test]
    async fn bundle_happy_path_returns_managed_route() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");

        let provider = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-test");
        store
            .put_message(&provider)
            .await
            .expect("persist provider");

        let route = make_route(CLUSTER_INFERENCE_ROUTE_NAME, "openai-dev", "mock/model-a");
        store.put_message(&route).await.expect("persist route");

        let resp = resolve_inference_bundle(&store)
            .await
            .expect("bundle should resolve");

        assert_eq!(resp.routes.len(), 1);
        assert_eq!(resp.routes[0].name, CLUSTER_INFERENCE_ROUTE_NAME);
        assert_eq!(resp.routes[0].model_id, "mock/model-a");
        assert_eq!(resp.routes[0].provider_type, "openai");
        assert_eq!(resp.routes[0].api_key, "sk-test");
        assert_eq!(resp.routes[0].base_url, "https://api.openai.com/v1");
        assert!(!resp.revision.is_empty());
        assert!(resp.generated_at_ms > 0);
    }

    #[tokio::test]
    async fn bundle_without_cluster_route_returns_empty_routes() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");

        let resp = resolve_inference_bundle(&store)
            .await
            .expect("bundle should resolve");
        assert!(resp.routes.is_empty());
    }

    #[tokio::test]
    async fn bundle_revision_is_stable_for_same_route() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");

        let provider = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-test");
        store
            .put_message(&provider)
            .await
            .expect("persist provider");

        let route = make_route(
            CLUSTER_INFERENCE_ROUTE_NAME,
            "openai-dev",
            "mock/model-stable",
        );
        store.put_message(&route).await.expect("persist route");

        let resp1 = resolve_inference_bundle(&store)
            .await
            .expect("first resolve");
        let resp2 = resolve_inference_bundle(&store)
            .await
            .expect("second resolve");

        assert_eq!(
            resp1.revision, resp2.revision,
            "same route should produce same revision"
        );
    }

    #[tokio::test]
    async fn resolve_managed_route_derives_from_provider() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store should connect");

        let provider = Provider {
            id: "provider-1".to_string(),
            name: "openai-dev".to_string(),
            r#type: "openai".to_string(),
            credentials: std::iter::once(("OPENAI_API_KEY".to_string(), "sk-test".to_string()))
                .collect(),
            config: std::iter::once((
                "OPENAI_BASE_URL".to_string(),
                "https://station.example.com/v1".to_string(),
            ))
            .collect(),
        };
        store
            .put_message(&provider)
            .await
            .expect("provider should persist");

        let route = InferenceRoute {
            id: "r-1".to_string(),
            name: CLUSTER_INFERENCE_ROUTE_NAME.to_string(),
            config: Some(ClusterInferenceConfig {
                provider_name: "openai-dev".to_string(),
                model_id: "test/model".to_string(),
            }),
            version: 7,
        };
        store
            .put_message(&route)
            .await
            .expect("route should persist");

        let managed = resolve_managed_cluster_route(&store)
            .await
            .expect("route should resolve")
            .expect("managed route should exist");

        assert_eq!(managed.base_url, "https://station.example.com/v1");
        assert_eq!(managed.api_key, "sk-test");
        assert_eq!(managed.provider_type, "openai");
        assert_eq!(
            managed.protocols,
            vec![
                "openai_chat_completions".to_string(),
                "openai_completions".to_string(),
                "openai_responses".to_string(),
                "model_discovery".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn resolve_managed_route_reflects_provider_key_rotation() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store should connect");

        let provider = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-initial");
        store
            .put_message(&provider)
            .await
            .expect("provider should persist");

        let route = make_route(CLUSTER_INFERENCE_ROUTE_NAME, "openai-dev", "test/model");
        store
            .put_message(&route)
            .await
            .expect("route should persist");

        let first = resolve_managed_cluster_route(&store)
            .await
            .expect("route should resolve")
            .expect("managed route should exist");
        assert_eq!(first.api_key, "sk-initial");

        let rotated_provider = Provider {
            id: provider.id,
            name: provider.name,
            r#type: provider.r#type,
            credentials: std::iter::once(("OPENAI_API_KEY".to_string(), "sk-rotated".to_string()))
                .collect(),
            config: provider.config,
        };
        store
            .put_message(&rotated_provider)
            .await
            .expect("provider rotation should persist");

        let second = resolve_managed_cluster_route(&store)
            .await
            .expect("route should resolve")
            .expect("managed route should exist");
        assert_eq!(second.api_key, "sk-rotated");
    }
}
