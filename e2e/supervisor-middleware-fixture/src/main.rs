// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Scripted gRPC middleware used exclusively by the focused middleware E2E lane.

use std::time::Duration;

use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    Decision, ExistingHeaderAction, HeaderMutation, HttpRequestEvaluation, HttpRequestResult,
    MiddlewareBinding, MiddlewareManifest, SupervisorMiddlewareOperation,
    SupervisorMiddlewarePhase, ValidateConfigRequest, ValidateConfigResponse, WriteHeader,
    header_mutation,
};
use serde_json::Value;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

const REGISTRATION_NAME: &str = "e2e-scripted";
const PHASE: SupervisorMiddlewarePhase = SupervisorMiddlewarePhase::PreCredentials;
const MAX_BODY_BYTES: usize = 4 * 1024;

#[derive(Debug, Default)]
struct ScriptedMiddleware;

#[tonic::async_trait]
impl SupervisorMiddleware for ScriptedMiddleware {
    async fn describe(
        &self,
        _request: Request<()>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        Ok(Response::new(MiddlewareManifest {
            name: "openshell-e2e-middleware-fixture".into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: PHASE as i32,
                max_body_bytes: 4 * 1024,
                timeout: String::new(),
            }],
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let request = request.into_inner();
        let fields = request.config.unwrap_or_default().fields;
        let valid = request.middleware_name == REGISTRATION_NAME
            && !fields.contains_key("reject_fixture_config");
        Ok(Response::new(ValidateConfigResponse {
            valid,
            reason: if valid {
                String::new()
            } else if request.middleware_name != REGISTRATION_NAME {
                format!("unsupported middleware name '{}'", request.middleware_name)
            } else {
                "fixture configuration rejected".into()
            },
        }))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        let request = request.into_inner();
        if request.middleware_name != REGISTRATION_NAME {
            return Err(Status::invalid_argument(format!(
                "unsupported middleware name '{}'",
                request.middleware_name
            )));
        }
        if request.phase != PHASE as i32 {
            return Err(Status::invalid_argument(format!(
                "unsupported phase '{}'",
                request.phase
            )));
        }
        let action = serde_json::from_slice::<Value>(&request.body)
            .ok()
            .and_then(|value| {
                value
                    .get("_e2e_action")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "allow".into());

        let result = match action.as_str() {
            "deny" => HttpRequestResult {
                decision: Decision::Deny as i32,
                reason: "blocked by e2e fixture".into(),
                reason_code: "fixture_denial".into(),
                ..Default::default()
            },
            "redact" => HttpRequestResult {
                decision: Decision::Allow as i32,
                body: br#"{"payload":"[REDACTED]"}"#.to_vec(),
                has_body: true,
                header_mutations: vec![HeaderMutation {
                    operation: Some(header_mutation::Operation::Write(WriteHeader {
                        name: "x-openshell-middleware-fixture".into(),
                        value: "redacted".into(),
                        on_existing: ExistingHeaderAction::Overwrite as i32,
                    })),
                }],
                ..Default::default()
            },
            "error" => return Err(Status::unavailable("fixture evaluation failed")),
            "timeout" => {
                // The E2E registration uses a 500 ms deadline. Sleeping for
                // two seconds leaves enough margin for loaded CI hosts.
                tokio::time::sleep(Duration::from_secs(2)).await;
                HttpRequestResult {
                    decision: Decision::Allow as i32,
                    ..Default::default()
                }
            }
            "invalid" => HttpRequestResult {
                decision: Decision::Unspecified as i32,
                ..Default::default()
            },
            "oversize" => HttpRequestResult {
                decision: Decision::Allow as i32,
                body: vec![b'x'; MAX_BODY_BYTES + 1],
                has_body: true,
                ..Default::default()
            },
            _ => HttpRequestResult {
                decision: Decision::Allow as i32,
                ..Default::default()
            },
        };

        Ok(Response::new(result))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::var("OPENSHELL_E2E_MIDDLEWARE_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:50051".into())
        .parse()?;

    Server::builder()
        .add_service(SupervisorMiddlewareServer::new(ScriptedMiddleware))
        .serve(address)
        .await?;
    Ok(())
}
