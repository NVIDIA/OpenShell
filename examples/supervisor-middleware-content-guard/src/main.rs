// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Example OpenShell supervisor middleware service.
//!
//! The content guard redacts or denies configured terms in HTTP request and
//! response bodies through HTTP session hooks (`EvaluateHttpRequestSession`
//! and `EvaluateHttpResponseSession`), and in WebSocket text messages. Its
//! manifest requires the `openshell.supervisor-middleware.http-session`
//! capability, which gateways and supervisors that predate HTTP session hooks
//! do not support, so they refuse it at Describe.

mod guard;
mod http;
mod websocket;

use std::net::SocketAddr;

use clap::Parser;
use openshell_core::extension_protocol::{
    ExtensionFamily, http_session_middleware_metadata, validate_gateway_metadata,
};
use openshell_core::middleware::{HttpResultStream, WebSocketResponseStream};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    HttpEvent, HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding,
    MiddlewareDescribeRequest, MiddlewareManifest, SupervisorMiddlewareOperation,
    SupervisorMiddlewarePhase, ValidateConfigRequest, ValidateConfigResponse,
    WebSocketSessionEvent,
};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::guard::{GuardConfig, MAX_PAYLOAD_BYTES};

const MANIFEST_NAME: &str = "example/content-guard-service";

#[derive(Debug, Parser)]
#[command(about = "Run the example OpenShell supervisor middleware service")]
struct Cli {
    /// Address on which to serve plaintext gRPC.
    #[arg(long, default_value = "127.0.0.1:50051")]
    bind: SocketAddr,
}

#[derive(Debug, Default)]
struct ContentGuard;

fn http_binding(
    operation: SupervisorMiddlewareOperation,
    phase: SupervisorMiddlewarePhase,
) -> MiddlewareBinding {
    MiddlewareBinding {
        operation: operation as i32,
        phase: phase as i32,
        max_payload_bytes: MAX_PAYLOAD_BYTES,
        ..Default::default()
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for ContentGuard {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;
    type EvaluateHttpRequestSessionStream = HttpResultStream;
    type EvaluateHttpResponseSessionStream = HttpResultStream;

    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        let manifest = MiddlewareManifest {
            name: MANIFEST_NAME.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![
                http_binding(
                    SupervisorMiddlewareOperation::HttpRequest,
                    SupervisorMiddlewarePhase::PreCredentials,
                ),
                http_binding(
                    SupervisorMiddlewareOperation::HttpResponse,
                    SupervisorMiddlewarePhase::PreReturn,
                ),
                MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::WebsocketMessage as i32,
                    phase: websocket::PHASE as i32,
                    max_payload_bytes: MAX_PAYLOAD_BYTES,
                    ..Default::default()
                },
            ],
            expected_audience: String::new(),
            extension: Some(http_session_middleware_metadata(
                MANIFEST_NAME,
                openshell_core::VERSION,
            )),
        };
        validate_gateway_metadata(
            ExtensionFamily::SupervisorMiddleware,
            MANIFEST_NAME,
            manifest.extension.as_ref(),
            request.into_inner().gateway,
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
        Ok(Response::new(manifest))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let request = request.into_inner();
        Ok(Response::new(
            match GuardConfig::parse(request.config.as_ref()) {
                Ok(_) => ValidateConfigResponse {
                    valid: true,
                    reason: String::new(),
                },
                Err(reason) => ValidateConfigResponse {
                    valid: false,
                    reason,
                },
            },
        ))
    }

    async fn evaluate_http_request(
        &self,
        _request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        // v1 HTTP hooks. This service implements HTTP session hooks only.
        Err(Status::unimplemented(
            "content guard implements HTTP session hooks only",
        ))
    }

    async fn evaluate_http_request_session(
        &self,
        request: Request<tonic::Streaming<HttpEvent>>,
    ) -> Result<Response<Self::EvaluateHttpRequestSessionStream>, Status> {
        Ok(Response::new(http::stage_stream(request.into_inner())))
    }

    async fn evaluate_http_response_session(
        &self,
        request: Request<tonic::Streaming<HttpEvent>>,
    ) -> Result<Response<Self::EvaluateHttpResponseSessionStream>, Status> {
        Ok(Response::new(http::stage_stream(request.into_inner())))
    }

    async fn evaluate_web_socket_session(
        &self,
        request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Ok(Response::new(websocket::websocket_stream(
            request.into_inner(),
        )))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    println!("serving {MANIFEST_NAME} on http://{}", cli.bind);
    Server::builder()
        .add_service(SupervisorMiddlewareServer::new(ContentGuard))
        .serve(cli.bind)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use openshell_core::extension_protocol::{
        SUPERVISOR_MIDDLEWARE_HTTP_SESSION, gateway_metadata,
    };

    use super::*;

    #[tokio::test]
    async fn manifest_advertises_http_session_hook_and_websocket_bindings() {
        let manifest = SupervisorMiddleware::describe(
            &ContentGuard,
            Request::new(MiddlewareDescribeRequest {
                gateway: Some(gateway_metadata(ExtensionFamily::SupervisorMiddleware)),
            }),
        )
        .await
        .expect("describe")
        .into_inner();

        let operations: Vec<_> = manifest
            .bindings
            .iter()
            .map(|binding| binding.operation)
            .collect();
        assert_eq!(
            operations,
            [
                SupervisorMiddlewareOperation::HttpRequest as i32,
                SupervisorMiddlewareOperation::HttpResponse as i32,
                SupervisorMiddlewareOperation::WebsocketMessage as i32,
            ]
        );
        let extension = manifest.extension.expect("extension metadata");
        assert!(
            extension
                .required_capabilities
                .iter()
                .any(|capability| capability == SUPERVISOR_MIDDLEWARE_HTTP_SESSION)
        );
    }

    #[tokio::test]
    async fn describe_rejects_missing_gateway_metadata() {
        let error = SupervisorMiddleware::describe(
            &ContentGuard,
            Request::new(MiddlewareDescribeRequest::default()),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .message()
                .contains("gateway did not provide protocol metadata")
        );
    }

    #[test]
    fn example_policy_is_valid() {
        let policy = openshell_policy::parse_sandbox_policy(include_str!("../policy.yaml"))
            .expect("example policy must parse");
        openshell_policy::validate_sandbox_policy(&policy).expect("example policy must be valid");
    }
}
