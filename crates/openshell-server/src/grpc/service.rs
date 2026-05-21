// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;

use openshell_core::ObjectId;
use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::{
    DeleteServiceRequest, DeleteServiceResponse, ExposeServiceRequest, GetServiceRequest,
    ListServicesRequest, ListServicesResponse, Sandbox, ServiceEndpoint, ServiceEndpointResponse,
};
use prost::Message as _;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::ServerState;
use crate::persistence::{ObjectType, WriteCondition};
use crate::service_routing;

const MAX_SERVICE_NAME_LEN: usize = 28;
const MAX_SANDBOX_NAME_LEN: usize = 28;

pub(super) async fn handle_expose_service(
    state: &Arc<ServerState>,
    request: Request<ExposeServiceRequest>,
) -> Result<Response<ServiceEndpointResponse>, Status> {
    let req = request.into_inner();
    validate_endpoint_name("sandbox", &req.sandbox, MAX_SANDBOX_NAME_LEN)?;
    validate_optional_endpoint_name("service", &req.service, MAX_SERVICE_NAME_LEN)?;
    if req.target_port == 0 || req.target_port > u32::from(u16::MAX) {
        return Err(Status::invalid_argument("target_port must be in 1..=65535"));
    }

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.sandbox)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;

    let now = super::current_time_ms();
    let key = service_routing::endpoint_key(&req.sandbox, &req.service);

    // Fetch existing endpoint to determine create vs. update path
    let existing = state
        .store
        .get_message_by_name::<ServiceEndpoint>(&key)
        .await
        .map_err(|e| Status::internal(format!("fetch endpoint failed: {e}")))?;

    let (id, created_at_ms, condition, created) = if let Some(existing) = existing {
        // Update path: preserve id and created_at, use CAS to prevent conflicts
        let resource_version = existing
            .metadata
            .as_ref()
            .map_or(0, |metadata| metadata.resource_version);
        (
            existing.object_id().to_string(),
            existing
                .metadata
                .as_ref()
                .map_or(now, |metadata| metadata.created_at_ms),
            WriteCondition::MatchResourceVersion(resource_version),
            false,
        )
    } else {
        // Create path: new id and created_at, use MustCreate to prevent races
        (
            Uuid::new_v4().to_string(),
            now,
            WriteCondition::MustCreate,
            true,
        )
    };

    let labels_json = serde_json::to_string(&HashMap::from([(
        "sandbox".to_string(),
        req.sandbox.clone(),
    )]))
    .map_err(|e| Status::internal(format!("serialize labels failed: {e}")))?;

    let endpoint = ServiceEndpoint {
        metadata: Some(ObjectMeta {
            id: id.clone(),
            name: key.clone(),
            created_at_ms,
            labels: HashMap::from([("sandbox".to_string(), req.sandbox.clone())]),
            resource_version: 0,
        }),
        sandbox_id: sandbox.object_id().to_string(),
        sandbox_name: req.sandbox.clone(),
        service_name: req.service.clone(),
        target_port: req.target_port,
        domain: true,
    };

    // Single-attempt CAS write: fails with ABORTED on concurrent modification
    let result = state
        .store
        .put_if(
            ServiceEndpoint::object_type(),
            &id,
            &key,
            &endpoint.encode_to_vec(),
            Some(&labels_json),
            condition,
        )
        .await
        .map_err(|e| super::persistence_error_to_status(e, "expose service"))?;

    let mut endpoint = endpoint;
    if let Some(ref mut meta) = endpoint.metadata {
        meta.resource_version = result.resource_version;
    }

    let url = service_routing::endpoint_url(&state.config, &req.sandbox, &req.service)
        .unwrap_or_default();
    service_routing::emit_service_endpoint_config_event(&endpoint, &url, created);

    Ok(Response::new(ServiceEndpointResponse {
        endpoint: Some(endpoint),
        url,
    }))
}

pub(super) async fn handle_get_service(
    state: &Arc<ServerState>,
    request: Request<GetServiceRequest>,
) -> Result<Response<ServiceEndpointResponse>, Status> {
    let req = request.into_inner();
    validate_endpoint_name("sandbox", &req.sandbox, MAX_SANDBOX_NAME_LEN)?;
    validate_optional_endpoint_name("service", &req.service, MAX_SERVICE_NAME_LEN)?;

    let endpoint = get_service_endpoint(state, &req.sandbox, &req.service)
        .await?
        .ok_or_else(|| Status::not_found("service endpoint not found"))?;

    Ok(Response::new(service_endpoint_response(state, endpoint)))
}

pub(super) async fn handle_list_services(
    state: &Arc<ServerState>,
    request: Request<ListServicesRequest>,
) -> Result<Response<ListServicesResponse>, Status> {
    let req = request.into_inner();
    if !req.sandbox.is_empty() {
        validate_endpoint_name("sandbox", &req.sandbox, MAX_SANDBOX_NAME_LEN)?;
    }

    let limit = super::clamp_limit(req.limit, 100, super::MAX_PAGE_SIZE);
    let endpoints: Vec<ServiceEndpoint> = if req.sandbox.is_empty() {
        state.store.list_messages(limit, req.offset).await
    } else {
        state
            .store
            .list_messages_with_selector(&format!("sandbox={}", req.sandbox), limit, req.offset)
            .await
    }
    .map_err(|e| Status::internal(format!("list endpoints failed: {e}")))?;

    let services = endpoints
        .into_iter()
        .map(|ep| service_endpoint_response(state, ep))
        .collect();

    Ok(Response::new(ListServicesResponse { services }))
}

pub(super) async fn handle_delete_service(
    state: &Arc<ServerState>,
    request: Request<DeleteServiceRequest>,
) -> Result<Response<DeleteServiceResponse>, Status> {
    let req = request.into_inner();
    validate_endpoint_name("sandbox", &req.sandbox, MAX_SANDBOX_NAME_LEN)?;
    validate_optional_endpoint_name("service", &req.service, MAX_SERVICE_NAME_LEN)?;

    let endpoint = get_service_endpoint(state, &req.sandbox, &req.service).await?;
    let Some(endpoint) = endpoint else {
        return Ok(Response::new(DeleteServiceResponse { deleted: false }));
    };

    let key = service_routing::endpoint_key(&req.sandbox, &req.service);
    let deleted = state
        .store
        .delete_by_name(ServiceEndpoint::object_type(), &key)
        .await
        .map_err(|e| Status::internal(format!("delete endpoint failed: {e}")))?;

    if deleted {
        service_routing::emit_service_endpoint_delete_event(&endpoint);
    }

    Ok(Response::new(DeleteServiceResponse { deleted }))
}

async fn get_service_endpoint(
    state: &Arc<ServerState>,
    sandbox: &str,
    service: &str,
) -> Result<Option<ServiceEndpoint>, Status> {
    let key = service_routing::endpoint_key(sandbox, service);
    state
        .store
        .get_message_by_name::<ServiceEndpoint>(&key)
        .await
        .map_err(|e| Status::internal(format!("fetch endpoint failed: {e}")))
}

fn service_endpoint_response(
    state: &Arc<ServerState>,
    endpoint: ServiceEndpoint,
) -> ServiceEndpointResponse {
    let url = service_routing::endpoint_url(
        &state.config,
        &endpoint.sandbox_name,
        &endpoint.service_name,
    )
    .unwrap_or_default();
    ServiceEndpointResponse {
        endpoint: Some(endpoint),
        url,
    }
}

#[allow(clippy::result_large_err)]
fn validate_endpoint_name(field: &str, value: &str, max_len: usize) -> Result<(), Status> {
    if value.is_empty() {
        return Err(Status::invalid_argument(format!("{field} is required")));
    }
    validate_non_empty_endpoint_name(field, value, max_len)
}

#[allow(clippy::result_large_err)]
fn validate_optional_endpoint_name(field: &str, value: &str, max_len: usize) -> Result<(), Status> {
    if value.is_empty() {
        return Ok(());
    }
    validate_non_empty_endpoint_name(field, value, max_len)
}

#[allow(clippy::result_large_err)]
fn validate_non_empty_endpoint_name(
    field: &str,
    value: &str,
    max_len: usize,
) -> Result<(), Status> {
    if value.len() > max_len {
        return Err(Status::invalid_argument(format!(
            "{field} must be at most {max_len} characters for sandbox service routing"
        )));
    }
    if value.contains("--") {
        return Err(Status::invalid_argument(format!(
            "{field} must not contain '--'"
        )));
    }
    if !is_dns_label(value) {
        return Err(Status::invalid_argument(format!(
            "{field} must be a lowercase DNS label"
        )));
    }
    Ok(())
}

fn is_dns_label(value: &str) -> bool {
    if value.starts_with('-') || value.ends_with('-') {
        return false;
    }
    value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::test_support::test_server_state;
    use openshell_core::proto::SandboxPhase;

    async fn seed_sandbox(state: &Arc<ServerState>, name: &str) {
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: format!("sandbox-{name}"),
                    name: name.to_string(),
                    created_at_ms: 1_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                spec: Some(openshell_core::proto::SandboxSpec::default()),
                phase: SandboxPhase::Ready as i32,
                ..Default::default()
            })
            .await
            .unwrap();
    }

    #[test]
    fn validates_good_endpoint_name() {
        validate_endpoint_name("service", "web-api", 28).unwrap();
    }

    #[test]
    fn validates_empty_optional_service_name() {
        validate_optional_endpoint_name("service", "", 28).unwrap();
    }

    #[test]
    fn rejects_separator_in_endpoint_name() {
        assert!(validate_endpoint_name("service", "web--api", 28).is_err());
    }

    #[test]
    fn rejects_empty_required_endpoint_name() {
        assert!(validate_endpoint_name("sandbox", "", 28).is_err());
    }

    #[test]
    fn rejects_uppercase_endpoint_name() {
        assert!(validate_endpoint_name("service", "Web", 28).is_err());
    }

    #[tokio::test]
    async fn endpoint_lifecycle_round_trip() {
        let state = test_server_state().await;
        seed_sandbox(&state, "my-sandbox").await;

        let exposed = handle_expose_service(
            &state,
            Request::new(ExposeServiceRequest {
                sandbox: "my-sandbox".to_string(),
                service: "web".to_string(),
                target_port: 8080,
                domain: true,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(exposed.endpoint.as_ref().unwrap().target_port, 8080);

        let listed = handle_list_services(
            &state,
            Request::new(ListServicesRequest {
                sandbox: "my-sandbox".to_string(),
                limit: 0,
                offset: 0,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed.services.len(), 1);
        assert_eq!(
            listed.services[0].endpoint.as_ref().unwrap().service_name,
            "web"
        );

        let fetched = handle_get_service(
            &state,
            Request::new(GetServiceRequest {
                sandbox: "my-sandbox".to_string(),
                service: "web".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(fetched.endpoint.as_ref().unwrap().target_port, 8080);

        let deleted = handle_delete_service(
            &state,
            Request::new(DeleteServiceRequest {
                sandbox: "my-sandbox".to_string(),
                service: "web".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(deleted.deleted);

        let err = handle_get_service(
            &state,
            Request::new(GetServiceRequest {
                sandbox: "my-sandbox".to_string(),
                service: "web".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        let listed = handle_list_services(
            &state,
            Request::new(ListServicesRequest {
                sandbox: "my-sandbox".to_string(),
                limit: 0,
                offset: 0,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(listed.services.is_empty());
    }

    #[tokio::test]
    async fn concurrent_expose_service_handles_cas_properly() {
        let state = test_server_state().await;
        seed_sandbox(&state, "my-sandbox").await;

        // Spawn two concurrent expose_service calls for the same endpoint
        let state1 = state.clone();
        let handle1 = tokio::spawn(async move {
            handle_expose_service(
                &state1,
                Request::new(ExposeServiceRequest {
                    sandbox: "my-sandbox".to_string(),
                    service: "web".to_string(),
                    target_port: 8080,
                    domain: true,
                }),
            )
            .await
        });

        let state2 = state.clone();
        let handle2 = tokio::spawn(async move {
            handle_expose_service(
                &state2,
                Request::new(ExposeServiceRequest {
                    sandbox: "my-sandbox".to_string(),
                    service: "web".to_string(),
                    target_port: 9090,
                    domain: true,
                }),
            )
            .await
        });

        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        // One should succeed with MustCreate, the other may fail with ABORTED or succeed with update
        let successes = [&result1, &result2].iter().filter(|r| r.is_ok()).count();

        // At least one should succeed
        assert!(
            successes >= 1,
            "at least one expose should succeed, got: {result1:?}, {result2:?}"
        );

        // Only one endpoint should exist
        let listed = handle_list_services(
            &state,
            Request::new(ListServicesRequest {
                sandbox: "my-sandbox".to_string(),
                limit: 0,
                offset: 0,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed.services.len(), 1);
    }

    #[tokio::test]
    async fn concurrent_expose_service_update_uses_cas() {
        let state = test_server_state().await;
        seed_sandbox(&state, "my-sandbox").await;

        // Create an initial endpoint
        handle_expose_service(
            &state,
            Request::new(ExposeServiceRequest {
                sandbox: "my-sandbox".to_string(),
                service: "web".to_string(),
                target_port: 7070,
                domain: true,
            }),
        )
        .await
        .unwrap();

        // Spawn two concurrent updates
        let state1 = state.clone();
        let handle1 = tokio::spawn(async move {
            handle_expose_service(
                &state1,
                Request::new(ExposeServiceRequest {
                    sandbox: "my-sandbox".to_string(),
                    service: "web".to_string(),
                    target_port: 8080,
                    domain: true,
                }),
            )
            .await
        });

        let state2 = state.clone();
        let handle2 = tokio::spawn(async move {
            handle_expose_service(
                &state2,
                Request::new(ExposeServiceRequest {
                    sandbox: "my-sandbox".to_string(),
                    service: "web".to_string(),
                    target_port: 9090,
                    domain: true,
                }),
            )
            .await
        });

        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        // One should succeed, one may fail with ABORTED due to CAS conflict
        let successes = [&result1, &result2].iter().filter(|r| r.is_ok()).count();

        assert!(
            successes >= 1,
            "at least one update should succeed, got: {result1:?}, {result2:?}"
        );

        // The endpoint should have one of the new port values
        let fetched = handle_get_service(
            &state,
            Request::new(GetServiceRequest {
                sandbox: "my-sandbox".to_string(),
                service: "web".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let port = fetched.endpoint.as_ref().unwrap().target_port;
        assert!(
            port == 8080 || port == 9090,
            "port should be one of the updated values, got {port}"
        );
        assert_ne!(port, 7070, "port should not be the original value");
    }
}
