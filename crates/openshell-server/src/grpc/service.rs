// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;

use openshell_core::ObjectId;
use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::{
    ExposeServiceRequest, Sandbox, ServiceEndpoint, ServiceEndpointResponse,
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::ServerState;
use crate::local_domain;

const MAX_SERVICE_NAME_LEN: usize = 28;
const MAX_SANDBOX_NAME_LEN: usize = 28;

pub(super) async fn handle_expose_service(
    state: &Arc<ServerState>,
    request: Request<ExposeServiceRequest>,
) -> Result<Response<ServiceEndpointResponse>, Status> {
    let req = request.into_inner();
    validate_endpoint_name("sandbox", &req.sandbox, MAX_SANDBOX_NAME_LEN)?;
    validate_endpoint_name("service", &req.service, MAX_SERVICE_NAME_LEN)?;
    if req.target_port == 0 || req.target_port > u32::from(u16::MAX) {
        return Err(Status::invalid_argument("target_port must be in 1..=65535"));
    }

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.sandbox)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;

    let now =
        super::current_time_ms().map_err(|e| Status::internal(format!("clock error: {e}")))?;
    let key = local_domain::endpoint_key(&req.sandbox, &req.service);
    let id = match state
        .store
        .get_message_by_name::<ServiceEndpoint>(&key)
        .await
    {
        Ok(Some(existing)) => existing.object_id().to_string(),
        Ok(None) => Uuid::new_v4().to_string(),
        Err(e) => return Err(Status::internal(format!("fetch endpoint failed: {e}"))),
    };

    let endpoint = ServiceEndpoint {
        metadata: Some(ObjectMeta {
            id,
            name: key,
            created_at_ms: now,
            labels: HashMap::from([("sandbox".to_string(), req.sandbox.clone())]),
        }),
        sandbox_id: sandbox.object_id().to_string(),
        sandbox_name: req.sandbox.clone(),
        service_name: req.service.clone(),
        target_port: req.target_port,
        domain: req.domain,
    };

    state
        .store
        .put_message(&endpoint)
        .await
        .map_err(|e| Status::internal(format!("persist endpoint failed: {e}")))?;

    let url = if req.domain {
        local_domain::endpoint_url(&state.config, &req.sandbox, &req.service).unwrap_or_default()
    } else {
        String::new()
    };

    Ok(Response::new(ServiceEndpointResponse {
        endpoint: Some(endpoint),
        url,
    }))
}

#[allow(clippy::result_large_err)]
fn validate_endpoint_name(field: &str, value: &str, max_len: usize) -> Result<(), Status> {
    if value.is_empty() {
        return Err(Status::invalid_argument(format!("{field} is required")));
    }
    if value.len() > max_len {
        return Err(Status::invalid_argument(format!(
            "{field} must be at most {max_len} characters for local-domain routing"
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

    #[test]
    fn validates_good_endpoint_name() {
        validate_endpoint_name("service", "web-api", 28).unwrap();
    }

    #[test]
    fn rejects_separator_in_endpoint_name() {
        assert!(validate_endpoint_name("service", "web--api", 28).is_err());
    }

    #[test]
    fn rejects_uppercase_endpoint_name() {
        assert!(validate_endpoint_name("service", "Web", 28).is_err());
    }
}
