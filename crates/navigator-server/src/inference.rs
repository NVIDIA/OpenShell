use navigator_core::proto::{
    DeleteInferenceRouteRequest, DeleteInferenceRouteResponse, HttpHeader, InferenceRoute,
    InferenceRouteResponse, ListInferenceRoutesRequest, ListInferenceRoutesResponse,
    ProxyInferenceRequest, ProxyInferenceResponse, Sandbox, UpdateInferenceRouteRequest,
    inference_server::Inference,
};
use navigator_router::{RouterError, config::ResolvedRoute};
use prost::Message;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;

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
    async fn proxy_inference(
        &self,
        request: Request<ProxyInferenceRequest>,
    ) -> Result<Response<ProxyInferenceResponse>, Status> {
        let req = request.into_inner();

        if req.sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }

        let sandbox = self
            .state
            .store
            .get_message::<Sandbox>(&req.sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("failed to load sandbox: {e}")))?
            .ok_or_else(|| Status::not_found(format!("sandbox {} not found", req.sandbox_id)))?;

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

        let routes = list_resolved_routes(self.state.store.as_ref(), &allowed_routes).await?;
        if routes.is_empty() {
            return Err(Status::failed_precondition(
                "no enabled routes available for sandbox policy",
            ));
        }

        let inference_router = self.state.router.as_ref().ok_or_else(|| {
            Status::unavailable("inference router is not configured on this server")
        })?;

        let headers: Vec<(String, String)> = req
            .http_headers
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect();

        info!(
            sandbox_id = %req.sandbox_id,
            source_protocol = %req.source_protocol,
            method = %req.http_method,
            path = %req.http_path,
            candidate_routes = routes.len(),
            "processing proxy inference request"
        );

        let response = inference_router
            .proxy_with_candidates(
                &req.source_protocol,
                &req.http_method,
                &req.http_path,
                headers,
                bytes::Bytes::from(req.http_body),
                &routes,
            )
            .await
            .map_err(router_error_to_status)?;

        let resp_headers: Vec<HttpHeader> = response
            .headers
            .into_iter()
            .map(|(name, value)| HttpHeader { name, value })
            .collect();

        Ok(Response::new(ProxyInferenceResponse {
            http_status: i32::from(response.status),
            http_headers: resp_headers,
            http_body: response.body.to_vec(),
        }))
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

/// Resolve inference routes from the store, filtered by allowed route names.
///
/// Routes are matched by `routing_hint` against the `allowed_routes` list
/// from the sandbox's inference policy. Only enabled routes are returned.
async fn list_resolved_routes(
    store: &Store,
    allowed_routes: &[String],
) -> Result<Vec<ResolvedRoute>, Status> {
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

        routes.push(ResolvedRoute {
            routing_hint: spec.routing_hint.clone(),
            endpoint: spec.base_url.clone(),
            model: spec.model_id.clone(),
            api_key: spec.api_key.clone(),
            protocols,
        });
    }

    Ok(routes)
}

fn router_error_to_status(err: RouterError) -> Status {
    match err {
        RouterError::RouteNotFound(hint) => {
            Status::invalid_argument(format!("no route configured for routing_hint '{hint}'"))
        }
        RouterError::NoCompatibleRoute(protocol) => Status::failed_precondition(format!(
            "no compatible route for source protocol '{protocol}'"
        )),
        RouterError::Unauthorized(msg) => Status::unauthenticated(msg),
        RouterError::UpstreamUnavailable(msg) => Status::unavailable(msg),
        RouterError::UpstreamProtocol(msg) | RouterError::Internal(msg) => Status::internal(msg),
    }
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
    async fn list_resolved_routes_returns_enabled_allowed_routes() {
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

        let routes = list_resolved_routes(&store, &["local".to_string()])
            .await
            .expect("routes should resolve");

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].routing_hint, "local");
        assert_eq!(routes[0].protocols, vec!["openai_chat_completions"]);
    }

    #[tokio::test]
    async fn list_resolved_routes_filters_by_allowed_routes() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("store should connect");

        let route = make_route("r-1", "route-c", "frontier", true);
        store
            .put_message(&route)
            .await
            .expect("route should persist");

        let routes = list_resolved_routes(&store, &["local".to_string()])
            .await
            .expect("routes should resolve");
        assert!(routes.is_empty());
    }

    #[tokio::test]
    async fn list_resolved_routes_keeps_multi_protocols_in_single_route() {
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

        let routes = list_resolved_routes(&store, &["local".to_string()])
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
