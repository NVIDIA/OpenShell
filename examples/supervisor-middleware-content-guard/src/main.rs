// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Example OpenShell supervisor middleware service.
//!
//! The content guard redacts or denies configured terms in HTTP request and
//! response bodies through HTTP middleware protocol 2 (`EvaluateHttp`), and
//! in WebSocket text messages. It requires the
//! `openshell.supervisor-middleware.http-v2` capability, so a gateway or
//! supervisor that predates HTTP protocol 2 refuses it at Describe.

mod guard;
mod http;
mod websocket;

use std::net::SocketAddr;

use clap::Parser;
use openshell_core::extension_protocol::{
    ExtensionFamily, SUPERVISOR_MIDDLEWARE_HTTP_V2, extension_metadata_with_requirements,
    validate_gateway_metadata,
};
use openshell_core::middleware::{HttpResultStream, WebSocketResponseStream};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    HttpBodyMode, HttpEvent, HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding,
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
        http_protocol_version: 2,
        supported_http_body_modes: vec![HttpBodyMode::Buffered as i32, HttpBodyMode::Stream as i32],
        ..Default::default()
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for ContentGuard {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;
    type EvaluateHttpStream = HttpResultStream;

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
            extension: Some(extension_metadata_with_requirements(
                ExtensionFamily::SupervisorMiddleware,
                MANIFEST_NAME,
                openshell_core::VERSION,
                [],
                [SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string()],
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
        // HTTP protocol 1. This service implements HTTP protocol 2 only.
        Err(Status::unimplemented(
            "content guard implements HTTP middleware protocol 2 only",
        ))
    }

    async fn evaluate_http(
        &self,
        request: Request<tonic::Streaming<HttpEvent>>,
    ) -> Result<Response<Self::EvaluateHttpStream>, Status> {
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
    use openshell_core::extension_protocol::gateway_metadata;

    use super::*;

    #[tokio::test]
    async fn manifest_advertises_http_protocol_2_and_websocket_bindings() {
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
            .map(|binding| (binding.operation, binding.http_protocol_version))
            .collect();
        assert_eq!(
            operations,
            [
                (SupervisorMiddlewareOperation::HttpRequest as i32, 2),
                (SupervisorMiddlewareOperation::HttpResponse as i32, 2),
                (SupervisorMiddlewareOperation::WebsocketMessage as i32, 0),
            ]
        );
        assert!(
            manifest
                .extension
                .unwrap()
                .required_capabilities
                .contains(&SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string())
        );
    }

    #[tokio::test]
    async fn describe_refuses_peers_without_http_protocol_2() {
        let mut released = gateway_metadata(ExtensionFamily::SupervisorMiddleware);
        released
            .supported_capabilities
            .retain(|capability| capability != SUPERVISOR_MIDDLEWARE_HTTP_V2);
        let error = SupervisorMiddleware::describe(
            &ContentGuard,
            Request::new(MiddlewareDescribeRequest {
                gateway: Some(released),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

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
