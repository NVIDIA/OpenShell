// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

use clap::Parser;
use openshell_core::middleware::{HttpResponseResultStream, WebSocketResponseStream};
use openshell_core::proto::middleware::v1::http_response_pre_return_server::{
    HttpResponsePreReturn, HttpResponsePreReturnServer,
};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    Decision, ExistingHeaderAction, HeaderMutation, HttpRequestEvaluation, HttpRequestResult,
    HttpResponseBlockDelivery, HttpResponseBodyMode, HttpResponseBodyResult,
    HttpResponseBodyTransform, HttpResponseEvent, HttpResponseEventResult,
    HttpResponsePreflightInspect, HttpResponsePreflightResult, HttpResponsePreflightSkip,
    HttpResponseTrailersResult, MiddlewareBinding, MiddlewareManifest,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, ValidateConfigRequest,
    ValidateConfigResponse, WebSocketMessage, WebSocketMessageResult, WebSocketPreflightAction,
    WebSocketPreflightDecision, WebSocketSessionEvent, WebSocketSessionEventResult, WriteHeader,
    header_mutation, http_response_body_result, http_response_body_transform,
    http_response_body_unit, http_response_event, http_response_event_result,
    http_response_preflight_result, web_socket_message, web_socket_message_result,
    web_socket_session_event, web_socket_session_event_result,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

const MANIFEST_NAME: &str = "example/protocol-service";
const PHASE: SupervisorMiddlewarePhase = SupervisorMiddlewarePhase::PreCredentials;
const MAX_PAYLOAD_BYTES: u64 = 256 * 1024;
mod request;
mod response;
mod websocket;

#[derive(Debug, Parser)]
#[command(about = "Run the example OpenShell supervisor middleware service")]
struct Cli {
    /// Address on which to serve plaintext gRPC.
    #[arg(long, default_value = "127.0.0.1:50051")]
    bind: SocketAddr,
}

#[derive(Debug, Default)]
struct ProtocolDemo;

#[tonic::async_trait]
impl SupervisorMiddleware for ProtocolDemo {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;

    async fn describe(
        &self,
        _request: Request<()>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        Ok(Response::new(MiddlewareManifest {
            name: MANIFEST_NAME.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![
                MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: PHASE as i32,
                    max_payload_bytes: MAX_PAYLOAD_BYTES,
                    timeout: String::new(),
                },
                MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::WebsocketMessage as i32,
                    phase: PHASE as i32,
                    max_payload_bytes: MAX_PAYLOAD_BYTES,
                    timeout: String::new(),
                },
                MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                    phase: SupervisorMiddlewarePhase::PreReturn as i32,
                    max_payload_bytes: MAX_PAYLOAD_BYTES,
                    timeout: String::new(),
                },
            ],
            expected_audience: String::new(),
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let valid = request
            .get_ref()
            .config
            .as_ref()
            .is_none_or(|config| config.fields.is_empty());
        Ok(Response::new(ValidateConfigResponse {
            valid,
            reason: if valid {
                String::new()
            } else {
                "protocol demo takes no configuration".into()
            },
        }))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        request::evaluate(request.into_inner()).map(Response::new)
    }

    async fn evaluate_web_socket_session(
        &self,
        request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Ok(Response::new(websocket::stream(request.into_inner())))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    println!("serving {MANIFEST_NAME} on http://{}", cli.bind);
    Server::builder()
        .add_service(SupervisorMiddlewareServer::new(ProtocolDemo))
        .add_service(HttpResponsePreReturnServer::new(ProtocolDemo))
        .serve(cli.bind)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_policy_is_valid() {
        let policy = openshell_policy::parse_sandbox_policy(include_str!("../policy.yaml"))
            .expect("example policy parses");
        openshell_policy::validate_sandbox_policy(&policy).expect("example policy is valid");
    }

    #[tokio::test]
    async fn manifest_advertises_all_three_v1_hooks() {
        let manifest = SupervisorMiddleware::describe(&ProtocolDemo, Request::new(()))
            .await
            .unwrap()
            .into_inner();
        let bindings: Vec<_> = manifest
            .bindings
            .iter()
            .map(|binding| (binding.operation, binding.phase))
            .collect();
        assert_eq!(
            bindings,
            vec![
                (
                    SupervisorMiddlewareOperation::HttpRequest as i32,
                    PHASE as i32
                ),
                (
                    SupervisorMiddlewareOperation::WebsocketMessage as i32,
                    PHASE as i32
                ),
                (
                    SupervisorMiddlewareOperation::HttpResponse as i32,
                    SupervisorMiddlewarePhase::PreReturn as i32
                ),
            ]
        );
    }
}
