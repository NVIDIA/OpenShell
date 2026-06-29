// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use openshell_core::proto::{
    HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding, MiddlewareManifest,
    ValidateConfigRequest, ValidateConfigResponse,
};
use tonic::{Request, Response, Status};

use crate::{
    API_VERSION, BUILTIN_SECRETS, HTTP_REQUEST_OPERATION, PRE_CREDENTIALS_PHASE, builtins,
    safe_reason, validate_builtin_config,
};

#[derive(Debug, Default)]
pub struct InProcessMiddlewareService;

#[tonic::async_trait]
impl SupervisorMiddleware for InProcessMiddlewareService {
    async fn describe(
        &self,
        _request: Request<()>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        Ok(Response::new(MiddlewareManifest {
            api_version: API_VERSION.into(),
            name: "openshell/in-process".into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![MiddlewareBinding {
                id: BUILTIN_SECRETS.into(),
                operation: HTTP_REQUEST_OPERATION.into(),
                phase: PRE_CREDENTIALS_PHASE.into(),
            }],
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let request = request.into_inner();
        let config = request.config.unwrap_or_default();
        let validation = validate_builtin_config(&request.binding_id, &config);
        Ok(Response::new(match validation {
            Ok(()) => ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            },
            Err(err) => ValidateConfigResponse {
                valid: false,
                reason: safe_reason(&err.to_string()),
            },
        }))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        let request = request.into_inner();
        let result = match request.binding_id.as_str() {
            BUILTIN_SECRETS => builtins::secrets::evaluate_http_request(&request),
            other => Err(miette::miette!(
                "middleware implementation '{other}' is not available in phase 1"
            )),
        }
        .map_err(|err| Status::invalid_argument(safe_reason(&err.to_string())))?;
        Ok(Response::new(result))
    }
}
