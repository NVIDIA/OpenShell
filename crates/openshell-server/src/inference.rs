// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::proto::{
    ClusterInferenceConfig, GetClusterInferenceRequest, GetClusterInferenceResponse,
    GetInferenceBundleRequest, GetInferenceBundleResponse, InferenceRoute, Provider, ResolvedRoute,
    SetClusterInferenceRequest, SetClusterInferenceResponse, ValidatedEndpoint,
    inference_server::Inference,
};
use openshell_router::config::ResolvedRoute as RouterResolvedRoute;
use openshell_router::{ValidationFailureKind, verify_backend_endpoint};
use std::sync::Arc;
use std::time::Duration;
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
const SANDBOX_SYSTEM_ROUTE_NAME: &str = "sandbox-system";

/// Map a request `route_name` to the canonical store key.
///
/// Empty string defaults to `CLUSTER_INFERENCE_ROUTE_NAME` for backward compat.
fn effective_route_name(name: &str) -> Result<&str, Status> {
    match name.trim() {
        "" | "inference.local" => Ok(CLUSTER_INFERENCE_ROUTE_NAME),
        "sandbox-system" => Ok(SANDBOX_SYSTEM_ROUTE_NAME),
        other => Err(Status::invalid_argument(format!(
            "unknown route_name '{other}'; expected 'inference.local' or 'sandbox-system'"
        ))),
    }
}

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
        let route_name = effective_route_name(&req.route_name)?;
        let verify = !req.no_verify;
        let route = upsert_cluster_inference_route(
            self.state.store.as_ref(),
            route_name,
            &req.provider_name,
            &req.model_id,
            req.timeout_secs,
            verify,
        )
        .await?;

        let config = route
            .route
            .config
            .as_ref()
            .ok_or_else(|| Status::internal("managed route missing config"))?;

        Ok(Response::new(SetClusterInferenceResponse {
            provider_name: config.provider_name.clone(),
            model_id: config.model_id.clone(),
            version: route.route.version,
            route_name: route_name.to_string(),
            validation_performed: !route.validation.is_empty(),
            validated_endpoints: route.validation,
            timeout_secs: config.timeout_secs,
        }))
    }

    async fn get_cluster_inference(
        &self,
        request: Request<GetClusterInferenceRequest>,
    ) -> Result<Response<GetClusterInferenceResponse>, Status> {
        let req = request.into_inner();
        let route_name = effective_route_name(&req.route_name)?;
        let route = self
            .state
            .store
            .get_message_by_name::<InferenceRoute>(route_name)
            .await
            .map_err(|e| Status::internal(format!("fetch route failed: {e}")))?
            .ok_or_else(|| {
                Status::not_found(format!(
                    "inference route '{route_name}' is not configured; run 'openshell inference set --provider <name> --model <id>'"
                ))
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
            route_name: route_name.to_string(),
            timeout_secs: config.timeout_secs,
        }))
    }
}

async fn upsert_cluster_inference_route(
    store: &Store,
    route_name: &str,
    provider_name: &str,
    model_id: &str,
    timeout_secs: u64,
    verify: bool,
) -> Result<UpsertedInferenceRoute, Status> {
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

    let resolved = resolve_provider_route(&provider)?;
    let validation = if verify {
        vec![verify_provider_endpoint(&provider.name, model_id, &resolved).await?]
    } else {
        Vec::new()
    };

    let config = build_cluster_inference_config(&provider, model_id, timeout_secs);

    let existing = store
        .get_message_by_name::<InferenceRoute>(route_name)
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
            name: route_name.to_string(),
            config: Some(config),
            version: 1,
        }
    };

    store
        .put_message(&route)
        .await
        .map_err(|e| Status::internal(format!("persist route failed: {e}")))?;

    Ok(UpsertedInferenceRoute { route, validation })
}

fn build_cluster_inference_config(
    provider: &Provider,
    model_id: &str,
    timeout_secs: u64,
) -> ClusterInferenceConfig {
    ClusterInferenceConfig {
        provider_name: provider.name.clone(),
        model_id: model_id.to_string(),
        timeout_secs,
    }
}

struct ResolvedProviderRoute {
    provider_type: String,
    route: RouterResolvedRoute,
}

#[derive(Debug)]
struct UpsertedInferenceRoute {
    route: InferenceRoute,
    validation: Vec<ValidatedEndpoint>,
}

fn resolve_provider_route(provider: &Provider) -> Result<ResolvedProviderRoute, Status> {
    let provider_type = provider.r#type.trim().to_ascii_lowercase();

    let profile = openshell_core::inference::profile_for(&provider_type).ok_or_else(|| {
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
        route: RouterResolvedRoute {
            name: provider.name.clone(),
            endpoint: base_url,
            model: String::new(),
            api_key,
            protocols: profile.protocols.iter().map(|p| (*p).to_string()).collect(),
            auth: profile.auth.clone(),
            default_headers: profile
                .default_headers
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
            passthrough_headers: profile
                .passthrough_headers
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            timeout: openshell_router::config::DEFAULT_ROUTE_TIMEOUT,
        },
    })
}

fn validation_failure(
    provider_name: &str,
    model_id: &str,
    base_url: &str,
    details: &str,
    next_steps: &str,
) -> Status {
    Status::failed_precondition(format!(
        "failed to verify inference endpoint for provider '{provider_name}' and model '{model_id}' at '{base_url}': {details}. Next steps: {next_steps}, or retry with '--no-verify' if you want to skip verification"
    ))
}

fn validation_next_steps(kind: ValidationFailureKind) -> &'static str {
    match kind {
        ValidationFailureKind::Credentials => {
            "verify the provider API key and any required auth headers"
        }
        ValidationFailureKind::RateLimited => {
            "retry later or verify quota/limits on the upstream provider"
        }
        ValidationFailureKind::RequestShape => {
            "confirm the provider type, base URL, and model identifier"
        }
        ValidationFailureKind::Connectivity => {
            "check that the service is running, confirm the base URL and protocol, and verify credentials"
        }
        ValidationFailureKind::UpstreamHealth => {
            "check whether the endpoint is healthy and serving requests"
        }
        ValidationFailureKind::Unexpected => {
            "confirm the endpoint URL, protocol, credentials, and model identifier"
        }
    }
}

async fn verify_provider_endpoint(
    provider_name: &str,
    model_id: &str,
    route: &ResolvedProviderRoute,
) -> Result<ValidatedEndpoint, Status> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| Status::internal(format!("build validation client failed: {err}")))?;
    let mut route = route.route.clone();
    route.model = model_id.to_string();

    verify_backend_endpoint(&client, &route)
        .await
        .map(|validated| ValidatedEndpoint {
            url: validated.url,
            protocol: validated.protocol,
        })
        .map_err(|err| {
            validation_failure(
                provider_name,
                model_id,
                &route.endpoint,
                &err.details,
                validation_next_steps(err.kind),
            )
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

/// Resolve the inference bundle (all managed routes + revision hash).
async fn resolve_inference_bundle(store: &Store) -> Result<GetInferenceBundleResponse, Status> {
    let mut routes = Vec::new();
    if let Some(r) = resolve_route_by_name(store, CLUSTER_INFERENCE_ROUTE_NAME).await? {
        routes.push(r);
    }
    if let Some(r) = resolve_route_by_name(store, SANDBOX_SYSTEM_ROUTE_NAME).await? {
        routes.push(r);
    }

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
            r.timeout_secs.hash(&mut hasher);
        }
        format!("{:016x}", hasher.finish())
    };

    Ok(GetInferenceBundleResponse {
        routes,
        revision,
        generated_at_ms: now_ms,
    })
}

async fn resolve_route_by_name(
    store: &Store,
    route_name: &str,
) -> Result<Option<ResolvedRoute>, Status> {
    let route = store
        .get_message_by_name::<InferenceRoute>(route_name)
        .await
        .map_err(|e| Status::internal(format!("fetch route failed: {e}")))?;

    let Some(route) = route else {
        return Ok(None);
    };

    let Some(config) = route.config.as_ref() else {
        return Ok(None);
    };

    if config.provider_name.trim().is_empty() {
        return Err(Status::failed_precondition(format!(
            "route '{route_name}' is missing provider_name"
        )));
    }

    if config.model_id.trim().is_empty() {
        return Err(Status::failed_precondition(format!(
            "route '{route_name}' is missing model_id"
        )));
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
        name: route_name.to_string(),
        base_url: resolved.route.endpoint,
        model_id: config.model_id.clone(),
        api_key: resolved.route.api_key,
        protocols: resolved.route.protocols,
        provider_type: resolved.provider_type,
        timeout_secs: config.timeout_secs,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_route(name: &str, provider_name: &str, model_id: &str) -> InferenceRoute {
        InferenceRoute {
            id: format!("id-{name}"),
            name: name.to_string(),
            config: Some(ClusterInferenceConfig {
                provider_name: provider_name.to_string(),
                model_id: model_id.to_string(),
                timeout_secs: 0,
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

    fn make_provider_with_base_url(
        name: &str,
        provider_type: &str,
        key_name: &str,
        key_value: &str,
        base_url_key: &str,
        base_url: &str,
    ) -> Provider {
        Provider {
            config: std::iter::once((base_url_key.to_string(), base_url.to_string())).collect(),
            ..make_provider(name, provider_type, key_name, key_value)
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

        let first = upsert_cluster_inference_route(
            &store,
            CLUSTER_INFERENCE_ROUTE_NAME,
            "openai-dev",
            "gpt-4o",
            0,
            false,
        )
        .await
        .expect("first set should succeed");
        assert_eq!(first.route.name, CLUSTER_INFERENCE_ROUTE_NAME);
        assert_eq!(first.route.version, 1);

        let second = upsert_cluster_inference_route(
            &store,
            CLUSTER_INFERENCE_ROUTE_NAME,
            "openai-dev",
            "gpt-4.1",
            0,
            false,
        )
        .await
        .expect("second set should succeed");
        assert_eq!(second.route.version, 2);
        assert_eq!(second.route.id, first.route.id);

        let config = second.route.config.as_ref().expect("config");
        assert_eq!(config.provider_name, "openai-dev");
        assert_eq!(config.model_id, "gpt-4.1");
    }

    #[tokio::test]
    async fn resolve_managed_route_returns_none_when_missing() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store should connect");

        let route = resolve_route_by_name(&store, CLUSTER_INFERENCE_ROUTE_NAME)
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
                timeout_secs: 0,
            }),
            version: 7,
        };
        store
            .put_message(&route)
            .await
            .expect("route should persist");

        let managed = resolve_route_by_name(&store, CLUSTER_INFERENCE_ROUTE_NAME)
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

        let first = resolve_route_by_name(&store, CLUSTER_INFERENCE_ROUTE_NAME)
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

        let second = resolve_route_by_name(&store, CLUSTER_INFERENCE_ROUTE_NAME)
            .await
            .expect("route should resolve")
            .expect("managed route should exist");
        assert_eq!(second.api_key, "sk-rotated");
    }

    #[tokio::test]
    async fn upsert_system_route_creates_with_correct_name() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");

        let provider = make_provider("anthropic-dev", "anthropic", "ANTHROPIC_API_KEY", "sk-ant");
        store.put_message(&provider).await.expect("persist");

        let route = upsert_cluster_inference_route(
            &store,
            SANDBOX_SYSTEM_ROUTE_NAME,
            "anthropic-dev",
            "claude-sonnet-4-20250514",
            0,
            false,
        )
        .await
        .expect("should succeed");

        assert_eq!(route.route.name, SANDBOX_SYSTEM_ROUTE_NAME);
        assert_eq!(route.route.version, 1);
        let config = route.route.config.as_ref().expect("config");
        assert_eq!(config.provider_name, "anthropic-dev");
        assert_eq!(config.model_id, "claude-sonnet-4-20250514");
    }

    #[tokio::test]
    async fn bundle_includes_both_user_and_system_routes() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");

        let openai = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-oai");
        store.put_message(&openai).await.expect("persist openai");
        let anthropic = make_provider("anthropic-dev", "anthropic", "ANTHROPIC_API_KEY", "sk-ant");
        store
            .put_message(&anthropic)
            .await
            .expect("persist anthropic");

        let user_route = make_route(CLUSTER_INFERENCE_ROUTE_NAME, "openai-dev", "gpt-4o");
        store
            .put_message(&user_route)
            .await
            .expect("persist user route");
        let system_route = make_route(
            SANDBOX_SYSTEM_ROUTE_NAME,
            "anthropic-dev",
            "claude-sonnet-4-20250514",
        );
        store
            .put_message(&system_route)
            .await
            .expect("persist system route");

        let resp = resolve_inference_bundle(&store)
            .await
            .expect("bundle should resolve");

        assert_eq!(resp.routes.len(), 2);
        assert_eq!(resp.routes[0].name, CLUSTER_INFERENCE_ROUTE_NAME);
        assert_eq!(resp.routes[0].model_id, "gpt-4o");
        assert_eq!(resp.routes[1].name, SANDBOX_SYSTEM_ROUTE_NAME);
        assert_eq!(resp.routes[1].model_id, "claude-sonnet-4-20250514");
    }

    #[tokio::test]
    async fn bundle_with_only_system_route() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");

        let provider = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-test");
        store.put_message(&provider).await.expect("persist");
        let system_route = make_route(SANDBOX_SYSTEM_ROUTE_NAME, "openai-dev", "gpt-4o-mini");
        store.put_message(&system_route).await.expect("persist");

        let resp = resolve_inference_bundle(&store)
            .await
            .expect("bundle should resolve");

        assert_eq!(resp.routes.len(), 1);
        assert_eq!(resp.routes[0].name, SANDBOX_SYSTEM_ROUTE_NAME);
        assert_eq!(resp.routes[0].model_id, "gpt-4o-mini");
    }

    #[tokio::test]
    async fn get_returns_system_route_when_requested() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");

        let provider = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-test");
        store.put_message(&provider).await.expect("persist");

        upsert_cluster_inference_route(
            &store,
            SANDBOX_SYSTEM_ROUTE_NAME,
            "openai-dev",
            "gpt-4o-mini",
            0,
            false,
        )
        .await
        .expect("upsert should succeed");

        let route = store
            .get_message_by_name::<InferenceRoute>(SANDBOX_SYSTEM_ROUTE_NAME)
            .await
            .expect("fetch should succeed")
            .expect("route should exist");

        assert_eq!(route.name, SANDBOX_SYSTEM_ROUTE_NAME);
        let config = route.config.as_ref().expect("config");
        assert_eq!(config.model_id, "gpt-4o-mini");
    }

    #[tokio::test]
    async fn upsert_cluster_route_verifies_endpoint_when_requested() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer sk-test"))
            .and(header("content-type", "application/json"))
            .and(body_partial_json(serde_json::json!({
                "model": "gpt-4o-mini",
                "max_completion_tokens": 32,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                "model": "gpt-4o-mini"
            })))
            .mount(&mock_server)
            .await;

        let provider = make_provider_with_base_url(
            "openai-dev",
            "openai",
            "OPENAI_API_KEY",
            "sk-test",
            "OPENAI_BASE_URL",
            &mock_server.uri(),
        );
        store
            .put_message(&provider)
            .await
            .expect("persist provider");

        let route = upsert_cluster_inference_route(
            &store,
            CLUSTER_INFERENCE_ROUTE_NAME,
            "openai-dev",
            "gpt-4o-mini",
            0,
            true,
        )
        .await
        .expect("validation should succeed");

        assert_eq!(route.route.version, 1);
        assert_eq!(route.validation.len(), 1);
        assert_eq!(route.validation[0].protocol, "openai_chat_completions");
    }

    #[tokio::test]
    async fn upsert_cluster_route_rejects_failed_validation() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_string("bad key"))
            .mount(&mock_server)
            .await;

        let provider = make_provider_with_base_url(
            "openai-dev",
            "openai",
            "OPENAI_API_KEY",
            "sk-test",
            "OPENAI_BASE_URL",
            &mock_server.uri(),
        );
        store
            .put_message(&provider)
            .await
            .expect("persist provider");

        let err = upsert_cluster_inference_route(
            &store,
            CLUSTER_INFERENCE_ROUTE_NAME,
            "openai-dev",
            "gpt-4o-mini",
            0,
            true,
        )
        .await
        .expect_err("validation should fail");

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            err.message()
                .contains("failed to verify inference endpoint")
        );
        assert!(err.message().contains("verify the provider API key"));
        assert!(err.message().contains("--no-verify"));

        let persisted = store
            .get_message_by_name::<InferenceRoute>(CLUSTER_INFERENCE_ROUTE_NAME)
            .await
            .expect("fetch route")
            .is_none();
        assert!(persisted, "route should not persist on failed validation");
    }

    #[tokio::test]
    async fn upsert_cluster_route_skips_validation_by_default() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");
        let provider = make_provider_with_base_url(
            "openai-dev",
            "openai",
            "OPENAI_API_KEY",
            "sk-test",
            "OPENAI_BASE_URL",
            "http://127.0.0.1:9",
        );
        store
            .put_message(&provider)
            .await
            .expect("persist provider");

        let route = upsert_cluster_inference_route(
            &store,
            CLUSTER_INFERENCE_ROUTE_NAME,
            "openai-dev",
            "gpt-4o-mini",
            0,
            false,
        )
        .await
        .expect("non-verified route should persist");

        assert_eq!(route.route.version, 1);
        assert!(route.validation.is_empty());
    }

    #[test]
    fn effective_route_name_defaults_empty_to_inference_local() {
        assert_eq!(
            effective_route_name("").unwrap(),
            CLUSTER_INFERENCE_ROUTE_NAME
        );
        assert_eq!(
            effective_route_name("  ").unwrap(),
            CLUSTER_INFERENCE_ROUTE_NAME
        );
        assert_eq!(
            effective_route_name("inference.local").unwrap(),
            CLUSTER_INFERENCE_ROUTE_NAME
        );
    }

    #[test]
    fn effective_route_name_accepts_sandbox_system() {
        assert_eq!(
            effective_route_name("sandbox-system").unwrap(),
            SANDBOX_SYSTEM_ROUTE_NAME
        );
    }

    #[test]
    fn effective_route_name_rejects_unknown_name() {
        let err = effective_route_name("unknown-route").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
