// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use navigator_core::proto::{
    DeleteInferenceRouteRequest, DeleteInferenceRouteResponse, GetSandboxInferenceBundleRequest,
    GetSandboxInferenceBundleResponse, InferenceRoute, InferenceRouteResponse,
    ListInferenceRoutesRequest, ListInferenceRoutesResponse, Sandbox, SandboxResolvedRoute,
    UpdateInferenceRouteRequest, inference_server::Inference,
};
use prost::Message;
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::{
    ServerState,
    persistence::{ObjectId, ObjectName, ObjectType, Store, generate_name},
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
    async fn get_sandbox_inference_bundle(
        &self,
        request: Request<GetSandboxInferenceBundleRequest>,
    ) -> Result<Response<GetSandboxInferenceBundleResponse>, Status> {
        let req = request.into_inner();
        resolve_sandbox_inference_bundle(self.state.store.as_ref(), &req.sandbox_id)
            .await
            .map(Response::new)
    }

    async fn create_inference_route(
        &self,
        request: Request<navigator_core::proto::CreateInferenceRouteRequest>,
    ) -> Result<Response<InferenceRouteResponse>, Status> {
        let req = request.into_inner();
        let mut spec = req
            .route
            .ok_or_else(|| Status::invalid_argument("route is required"))?;
        normalize_route_protocols(&mut spec);
        validate_route_spec(&spec)?;

        let name = if req.name.is_empty() {
            generate_name()
        } else {
            req.name
        };

        let existing = self
            .state
            .store
            .get_message_by_name::<InferenceRoute>(&name)
            .await
            .map_err(|e| Status::internal(format!("fetch route failed: {e}")))?;

        if existing.is_some() {
            return Err(Status::already_exists("route already exists"));
        }

        let route = InferenceRoute {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            spec: Some(spec),
        };

        self.state
            .store
            .put_message(&route)
            .await
            .map_err(|e| Status::internal(format!("persist route failed: {e}")))?;

        Ok(Response::new(InferenceRouteResponse { route: Some(route) }))
    }

    async fn update_inference_route(
        &self,
        request: Request<UpdateInferenceRouteRequest>,
    ) -> Result<Response<InferenceRouteResponse>, Status> {
        let request = request.into_inner();
        if request.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        let mut spec = request
            .route
            .ok_or_else(|| Status::invalid_argument("route is required"))?;
        normalize_route_protocols(&mut spec);
        validate_route_spec(&spec)?;

        let existing = self
            .state
            .store
            .get_message_by_name::<InferenceRoute>(&request.name)
            .await
            .map_err(|e| Status::internal(format!("fetch route failed: {e}")))?;

        let Some(existing) = existing else {
            return Err(Status::not_found("route not found"));
        };

        // Preserve the stored id; update payload fields only.
        let route = InferenceRoute {
            id: existing.id,
            name: existing.name,
            spec: Some(spec),
        };

        self.state
            .store
            .put_message(&route)
            .await
            .map_err(|e| Status::internal(format!("persist route failed: {e}")))?;

        Ok(Response::new(InferenceRouteResponse { route: Some(route) }))
    }

    async fn delete_inference_route(
        &self,
        request: Request<DeleteInferenceRouteRequest>,
    ) -> Result<Response<DeleteInferenceRouteResponse>, Status> {
        let name = request.into_inner().name;
        if name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        let deleted = self
            .state
            .store
            .delete_by_name(InferenceRoute::object_type(), &name)
            .await
            .map_err(|e| Status::internal(format!("delete route failed: {e}")))?;

        Ok(Response::new(DeleteInferenceRouteResponse { deleted }))
    }

    async fn list_inference_routes(
        &self,
        request: Request<ListInferenceRoutesRequest>,
    ) -> Result<Response<ListInferenceRoutesResponse>, Status> {
        let request = request.into_inner();
        let limit = if request.limit == 0 {
            100
        } else {
            request.limit
        };

        let records = self
            .state
            .store
            .list(InferenceRoute::object_type(), limit, request.offset)
            .await
            .map_err(|e| Status::internal(format!("list routes failed: {e}")))?;

        let mut routes = Vec::with_capacity(records.len());
        for record in records {
            let route = InferenceRoute::decode(record.payload.as_slice())
                .map_err(|e| Status::internal(format!("decode route failed: {e}")))?;
            routes.push(route);
        }

        Ok(Response::new(ListInferenceRoutesResponse { routes }))
    }
}

#[allow(clippy::result_large_err)]
fn validate_route_spec(spec: &navigator_core::proto::InferenceRouteSpec) -> Result<(), Status> {
    if spec.routing_hint.trim().is_empty() {
        return Err(Status::invalid_argument("route.routing_hint is required"));
    }
    if spec.base_url.trim().is_empty() {
        return Err(Status::invalid_argument("route.base_url is required"));
    }
    if navigator_core::inference::normalize_protocols(&spec.protocols).is_empty() {
        return Err(Status::invalid_argument("route.protocols is required"));
    }
    if spec.model_id.trim().is_empty() {
        return Err(Status::invalid_argument("route.model_id is required"));
    }
    Ok(())
}

fn normalize_route_protocols(spec: &mut navigator_core::proto::InferenceRouteSpec) {
    spec.protocols = navigator_core::inference::normalize_protocols(&spec.protocols);
}

/// Resolve a full inference bundle for a sandbox.
///
/// Loads the sandbox from the store, extracts the inference policy, filters
/// routes by `allowed_routes`, and computes a revision hash.
async fn resolve_sandbox_inference_bundle(
    store: &Store,
    sandbox_id: &str,
) -> Result<GetSandboxInferenceBundleResponse, Status> {
    if sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }

    let sandbox = store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("failed to load sandbox: {e}")))?
        .ok_or_else(|| Status::not_found(format!("sandbox {sandbox_id} not found")))?;

    let policy = sandbox
        .spec
        .as_ref()
        .and_then(|s| s.policy.as_ref())
        .and_then(|p| p.inference.as_ref());

    let allowed_routes = match policy {
        Some(inference_policy) => {
            if inference_policy.allowed_routes.is_empty() {
                return Err(Status::permission_denied(
                    "sandbox inference policy has no allowed routes",
                ));
            }
            inference_policy.allowed_routes.clone()
        }
        None => {
            return Err(Status::permission_denied(
                "sandbox has no inference policy configured",
            ));
        }
    };

    let routes = list_sandbox_routes(store, &allowed_routes).await?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    // Compute a simple revision from route contents for cache freshness checks.
    let revision = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for r in &routes {
            r.routing_hint.hash(&mut hasher);
            r.base_url.hash(&mut hasher);
            r.model_id.hash(&mut hasher);
            r.api_key.hash(&mut hasher);
            r.protocols.hash(&mut hasher);
        }
        format!("{:016x}", hasher.finish())
    };

    Ok(GetSandboxInferenceBundleResponse {
        routes,
        revision,
        generated_at_ms: now_ms,
    })
}

/// Resolve inference routes from the store as sandbox-ready bundle entries.
///
/// Routes are matched by `routing_hint` against the `allowed_routes` list
/// from the sandbox's inference policy. Only enabled routes are returned.
async fn list_sandbox_routes(
    store: &Store,
    allowed_routes: &[String],
) -> Result<Vec<SandboxResolvedRoute>, Status> {
    let mut allowed_set = std::collections::HashSet::new();
    for name in allowed_routes {
        allowed_set.insert(name.as_str());
    }

    let records = store
        .list(InferenceRoute::object_type(), 500, 0)
        .await
        .map_err(|e| Status::internal(format!("list routes failed: {e}")))?;

    let mut routes = Vec::new();
    for record in records {
        let route = InferenceRoute::decode(record.payload.as_slice())
            .map_err(|e| Status::internal(format!("decode route failed: {e}")))?;
        let Some(spec) = route.spec.as_ref() else {
            continue;
        };
        if !spec.enabled {
            continue;
        }
        if !allowed_set.contains(spec.routing_hint.as_str()) {
            continue;
        }

        let protocols = navigator_core::inference::normalize_protocols(&spec.protocols);
        if protocols.is_empty() {
            continue;
        }

        routes.push(SandboxResolvedRoute {
            routing_hint: spec.routing_hint.clone(),
            base_url: spec.base_url.clone(),
            model_id: spec.model_id.clone(),
            api_key: spec.api_key.clone(),
            protocols,
        });
    }

    Ok(routes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use navigator_core::proto::InferenceRouteSpec;

    fn make_route(id: &str, name: &str, routing_hint: &str, enabled: bool) -> InferenceRoute {
        InferenceRoute {
            id: id.to_string(),
            name: name.to_string(),
            spec: Some(InferenceRouteSpec {
                routing_hint: routing_hint.to_string(),
                base_url: "https://example.com/v1".to_string(),
                api_key: "test-key".to_string(),
                model_id: "test/model".to_string(),
                enabled,
                protocols: vec!["openai_chat_completions".to_string()],
            }),
        }
    }

    #[test]
    fn validate_route_spec_requires_fields() {
        let spec = InferenceRouteSpec {
            routing_hint: String::new(),
            base_url: String::new(),
            api_key: String::new(),
            model_id: String::new(),
            enabled: true,
            protocols: Vec::new(),
        };
        let err = validate_route_spec(&spec).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn normalize_route_protocols_dedupes_and_lowercases() {
        let mut spec = InferenceRouteSpec {
            routing_hint: "local".to_string(),
            base_url: "https://example.com/v1".to_string(),
            api_key: "test-key".to_string(),
            model_id: "model".to_string(),
            enabled: true,
            protocols: vec![
                "OpenAI_Chat_Completions".to_string(),
                "openai_chat_completions".to_string(),
                "anthropic_messages".to_string(),
            ],
        };

        normalize_route_protocols(&mut spec);

        assert_eq!(
            spec.protocols,
            vec![
                "openai_chat_completions".to_string(),
                "anthropic_messages".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn list_sandbox_routes_returns_enabled_allowed_routes() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store should connect");

        let route_disabled = make_route("r-1", "route-a", "local", false);
        store
            .put_message(&route_disabled)
            .await
            .expect("disabled route should persist");

        let route_enabled = make_route("r-2", "route-b", "local", true);
        store
            .put_message(&route_enabled)
            .await
            .expect("enabled route should persist");

        let routes = list_sandbox_routes(&store, &["local".to_string()])
            .await
            .expect("routes should resolve");

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].routing_hint, "local");
        assert_eq!(routes[0].protocols, vec!["openai_chat_completions"]);
    }

    #[tokio::test]
    async fn list_sandbox_routes_filters_by_allowed_routes() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store should connect");

        let route = make_route("r-1", "route-c", "frontier", true);
        store
            .put_message(&route)
            .await
            .expect("route should persist");

        let routes = list_sandbox_routes(&store, &["local".to_string()])
            .await
            .expect("routes should resolve");
        assert!(routes.is_empty());
    }

    // -- resolve_sandbox_inference_bundle tests --

    fn make_sandbox(id: &str, allowed_routes: Option<Vec<String>>) -> Sandbox {
        use navigator_core::proto::SandboxSpec;

        let policy =
            allowed_routes.map(|routes| navigator_core::proto::sandbox::v1::SandboxPolicy {
                inference: Some(navigator_core::proto::sandbox::v1::InferencePolicy {
                    allowed_routes: routes,
                    ..Default::default()
                }),
                ..Default::default()
            });

        Sandbox {
            id: id.to_string(),
            name: format!("sandbox-{id}"),
            spec: Some(SandboxSpec {
                policy,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn bundle_happy_path_returns_matching_routes() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");

        let sandbox = make_sandbox("sb-1", Some(vec!["local".into()]));
        store.put_message(&sandbox).await.expect("persist sandbox");

        let route = make_route("r-1", "route-a", "local", true);
        store.put_message(&route).await.expect("persist route");

        let resp = resolve_sandbox_inference_bundle(&store, "sb-1")
            .await
            .expect("bundle should resolve");

        assert_eq!(resp.routes.len(), 1);
        assert_eq!(resp.routes[0].routing_hint, "local");
        assert!(!resp.revision.is_empty());
        assert!(resp.generated_at_ms > 0);
    }

    #[tokio::test]
    async fn bundle_missing_sandbox_id_returns_invalid_argument() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");

        let err = resolve_sandbox_inference_bundle(&store, "")
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn bundle_sandbox_not_found_returns_not_found() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");

        let err = resolve_sandbox_inference_bundle(&store, "nonexistent")
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn bundle_no_inference_policy_returns_permission_denied() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");

        // Sandbox with no inference policy (None)
        let sandbox = make_sandbox("sb-2", None);
        store.put_message(&sandbox).await.expect("persist sandbox");

        let err = resolve_sandbox_inference_bundle(&store, "sb-2")
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(
            err.message().contains("no inference policy"),
            "message: {}",
            err.message()
        );
    }

    #[tokio::test]
    async fn bundle_empty_allowed_routes_returns_permission_denied() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");

        // Sandbox with empty allowed_routes
        let sandbox = make_sandbox("sb-3", Some(vec![]));
        store.put_message(&sandbox).await.expect("persist sandbox");

        let err = resolve_sandbox_inference_bundle(&store, "sb-3")
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(
            err.message().contains("no allowed routes"),
            "message: {}",
            err.message()
        );
    }

    #[tokio::test]
    async fn bundle_revision_is_stable_for_same_routes() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store");

        let sandbox = make_sandbox("sb-4", Some(vec!["local".into()]));
        store.put_message(&sandbox).await.expect("persist sandbox");

        let route = make_route("r-1", "route-a", "local", true);
        store.put_message(&route).await.expect("persist route");

        let resp1 = resolve_sandbox_inference_bundle(&store, "sb-4")
            .await
            .expect("first resolve");
        let resp2 = resolve_sandbox_inference_bundle(&store, "sb-4")
            .await
            .expect("second resolve");

        assert_eq!(
            resp1.revision, resp2.revision,
            "same routes should produce same revision"
        );
    }

    #[tokio::test]
    async fn list_sandbox_routes_keeps_multi_protocols_in_single_route() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store should connect");

        let route = InferenceRoute {
            id: "r-1".to_string(),
            name: "route-multi".to_string(),
            spec: Some(InferenceRouteSpec {
                routing_hint: "local".to_string(),
                base_url: "https://example.com/v1".to_string(),
                api_key: "test-key".to_string(),
                model_id: "test/model".to_string(),
                enabled: true,
                protocols: vec![
                    "openai_chat_completions".to_string(),
                    "anthropic_messages".to_string(),
                ],
            }),
        };
        store
            .put_message(&route)
            .await
            .expect("route should persist");

        let routes = list_sandbox_routes(&store, &["local".to_string()])
            .await
            .expect("routes should resolve");

        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].protocols,
            vec![
                "openai_chat_completions".to_string(),
                "anthropic_messages".to_string()
            ]
        );
    }
}
