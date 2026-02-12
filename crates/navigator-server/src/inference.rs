use navigator_core::proto::{
    CompletionRequest, CompletionResponse, DeleteInferenceRouteRequest,
    DeleteInferenceRouteResponse, InferenceRoute, InferenceRouteResponse,
    ListInferenceRoutesRequest, ListInferenceRoutesResponse, Sandbox, UpdateInferenceRouteRequest,
    inference_server::Inference,
};
use navigator_router::{RouterError, config::ResolvedRoute};
use prost::Message;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::{
    ServerState,
    persistence::{ObjectId, ObjectType, Store},
};

const SANDBOX_ID_HEADER: &str = "x-sandbox-id";

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

#[tonic::async_trait]
impl Inference for InferenceService {
    async fn completion(
        &self,
        request: Request<CompletionRequest>,
    ) -> Result<Response<CompletionResponse>, Status> {
        let sandbox_id = request
            .metadata()
            .get(SANDBOX_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if sandbox_id.is_empty() {
            return Err(Status::unauthenticated("x-sandbox-id header is required"));
        }

        let req = request.into_inner();

        let sandbox = self
            .state
            .store
            .get_message::<Sandbox>(&sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("failed to load sandbox: {e}")))?
            .ok_or_else(|| Status::not_found(format!("sandbox {sandbox_id} not found")))?;

        let policy = sandbox
            .spec
            .as_ref()
            .and_then(|s| s.policy.as_ref())
            .and_then(|p| p.inference.as_ref());

        if req.routing_hint.is_empty() {
            return Err(Status::invalid_argument("routing_hint is required"));
        }

        let allowed_hints = match policy {
            Some(inference_policy) => {
                if !inference_policy
                    .allowed_routing_hints
                    .iter()
                    .any(|h| h == &req.routing_hint)
                {
                    warn!(
                        sandbox_id = %sandbox_id,
                        routing_hint = %req.routing_hint,
                        "inference request denied by sandbox policy"
                    );
                    return Err(Status::permission_denied(format!(
                        "routing_hint '{}' not allowed for sandbox {sandbox_id}",
                        req.routing_hint
                    )));
                }
                inference_policy.allowed_routing_hints.clone()
            }
            None => {
                return Err(Status::permission_denied(
                    "sandbox has no inference policy configured",
                ));
            }
        };

        let routes = list_resolved_routes(self.state.store.as_ref(), &allowed_hints).await?;
        if routes.is_empty() {
            return Err(Status::failed_precondition(
                "no enabled routes available for sandbox policy",
            ));
        }

        let router = self.state.router.as_ref().ok_or_else(|| {
            Status::unavailable("inference router is not configured on this server")
        })?;

        info!(
            sandbox_id = %sandbox_id,
            routing_hint = %req.routing_hint,
            candidate_routes = routes.len(),
            "processing inference completion request"
        );

        let response = router
            .completion_with_candidates(&req, &routes)
            .await
            .map_err(router_error_to_status)?;

        Ok(Response::new(response))
    }

    async fn create_inference_route(
        &self,
        request: Request<navigator_core::proto::CreateInferenceRouteRequest>,
    ) -> Result<Response<InferenceRouteResponse>, Status> {
        let spec = request
            .into_inner()
            .route
            .ok_or_else(|| Status::invalid_argument("route is required"))?;
        validate_route_spec(&spec)?;

        let route = InferenceRoute {
            id: uuid::Uuid::new_v4().to_string(),
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
        if request.id.is_empty() {
            return Err(Status::invalid_argument("id is required"));
        }
        let spec = request
            .route
            .ok_or_else(|| Status::invalid_argument("route is required"))?;
        validate_route_spec(&spec)?;

        let exists = self
            .state
            .store
            .get_message::<InferenceRoute>(&request.id)
            .await
            .map_err(|e| Status::internal(format!("fetch route failed: {e}")))?;
        if exists.is_none() {
            return Err(Status::not_found("route not found"));
        }

        let route = InferenceRoute {
            id: request.id,
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
        let id = request.into_inner().id;
        if id.is_empty() {
            return Err(Status::invalid_argument("id is required"));
        }

        let deleted = self
            .state
            .store
            .delete(InferenceRoute::object_type(), &id)
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

fn validate_route_spec(spec: &navigator_core::proto::InferenceRouteSpec) -> Result<(), Status> {
    if spec.routing_hint.trim().is_empty() {
        return Err(Status::invalid_argument("route.routing_hint is required"));
    }
    if spec.base_url.trim().is_empty() {
        return Err(Status::invalid_argument("route.base_url is required"));
    }
    if spec.protocol.trim().is_empty() {
        return Err(Status::invalid_argument("route.protocol is required"));
    }
    if spec.api_key.trim().is_empty() {
        return Err(Status::invalid_argument("route.api_key is required"));
    }
    if spec.model_id.trim().is_empty() {
        return Err(Status::invalid_argument("route.model_id is required"));
    }
    Ok(())
}

async fn list_resolved_routes(
    store: &Store,
    allowed_hints: &[String],
) -> Result<Vec<ResolvedRoute>, Status> {
    let mut allowed_set = std::collections::HashSet::new();
    for hint in allowed_hints {
        allowed_set.insert(hint.as_str());
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

        routes.push(ResolvedRoute {
            routing_hint: spec.routing_hint.clone(),
            endpoint: spec.base_url.clone(),
            model: spec.model_id.clone(),
            api_key: spec.api_key.clone(),
        });
    }

    Ok(routes)
}

fn router_error_to_status(err: RouterError) -> Status {
    match err {
        RouterError::RouteNotFound(hint) => {
            Status::invalid_argument(format!("no route configured for routing_hint '{hint}'"))
        }
        RouterError::Unauthorized(msg) => Status::unauthenticated(msg),
        RouterError::UpstreamUnavailable(msg) => Status::unavailable(msg),
        RouterError::UpstreamProtocol(msg) | RouterError::Internal(msg) => Status::internal(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use navigator_core::proto::InferenceRouteSpec;

    fn make_route(id: &str, routing_hint: &str, enabled: bool) -> InferenceRoute {
        InferenceRoute {
            id: id.to_string(),
            spec: Some(InferenceRouteSpec {
                routing_hint: routing_hint.to_string(),
                base_url: "https://example.com/v1".to_string(),
                protocol: "openai_chat_completions".to_string(),
                api_key: "test-key".to_string(),
                model_id: "test/model".to_string(),
                enabled,
            }),
        }
    }

    #[test]
    fn validate_route_spec_requires_fields() {
        let spec = InferenceRouteSpec {
            routing_hint: String::new(),
            base_url: String::new(),
            protocol: String::new(),
            api_key: String::new(),
            model_id: String::new(),
            enabled: true,
        };
        let err = validate_route_spec(&spec).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn list_resolved_routes_returns_enabled_allowed_routes() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store should connect");

        let route_disabled = make_route("r-1", "local", false);
        store
            .put_message(&route_disabled)
            .await
            .expect("disabled route should persist");

        let route_enabled = make_route("r-2", "local", true);
        store
            .put_message(&route_enabled)
            .await
            .expect("enabled route should persist");

        let routes = list_resolved_routes(&store, &["local".to_string()])
            .await
            .expect("routes should resolve");

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].routing_hint, "local");
    }

    #[tokio::test]
    async fn list_resolved_routes_filters_by_allowed_hints() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store should connect");

        let route = make_route("r-1", "frontier", true);
        store
            .put_message(&route)
            .await
            .expect("route should persist");

        let routes = list_resolved_routes(&store, &["local".to_string()])
            .await
            .expect("routes should resolve");
        assert!(routes.is_empty());
    }
}
