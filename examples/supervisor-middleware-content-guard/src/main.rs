// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod guard;
mod http_legacy;
mod http_v2;
#[cfg(test)]
mod protocol_tests;
mod websocket;

use std::net::SocketAddr;

use clap::Parser;
use openshell_core::extension_protocol::{
    ExtensionFamily, SUPERVISOR_MIDDLEWARE_HTTP_V2, extension_metadata, peer_supports,
    validate_gateway_metadata,
};
use openshell_core::middleware::{
    HttpResponseResultStream, HttpResultStream, WebSocketResponseStream,
};
use openshell_core::proto::middleware::v1::http_request_pre_credentials_server::{
    HttpRequestPreCredentials, HttpRequestPreCredentialsServer,
};
use openshell_core::proto::middleware::v1::http_response_pre_return_server::{
    HttpResponsePreReturn, HttpResponsePreReturnServer,
};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    HttpBodyMode, HttpEvent, HttpRequestEvaluation, HttpRequestResult, HttpResponseEvent,
    MiddlewareBinding, MiddlewareDescribeRequest, MiddlewareManifest,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, ValidateConfigRequest,
    ValidateConfigResponse, WebSocketSessionEvent,
};
use tonic::transport::Server;
use tonic::transport::server::Router;
use tonic::{Request, Response, Status, Streaming};

use crate::guard::{GuardConfig, MAX_PAYLOAD_BYTES};
use crate::http_v2::Direction;

const MANIFEST_NAME: &str = "example/content-guard-service";
const PHASE: SupervisorMiddlewarePhase = SupervisorMiddlewarePhase::PreCredentials;

#[derive(Debug, Parser)]
#[command(about = "Run the example OpenShell supervisor middleware service")]
struct Cli {
    /// Address on which to serve plaintext gRPC.
    #[arg(long, default_value = "127.0.0.1:50051")]
    bind: SocketAddr,
}

fn validate_phase(phase: i32) -> Result<(), String> {
    if phase != PHASE as i32 {
        return Err(format!("unsupported phase '{phase}'"));
    }
    Ok(())
}

/// Build the manifest for one Describe caller. HTTP bindings use version 2 for
/// callers that support it and the legacy protocol otherwise. The service
/// advertises `http-v2` as supported, not required, so callers without it
/// still accept the service.
fn manifest(http_v2: bool) -> MiddlewareManifest {
    let http_binding = |operation: SupervisorMiddlewareOperation, phase| {
        let binding = MiddlewareBinding {
            operation: operation as i32,
            phase: phase as i32,
            max_payload_bytes: MAX_PAYLOAD_BYTES,
            ..Default::default()
        };
        if http_v2 {
            MiddlewareBinding {
                http_protocol_version: 2,
                supported_http_body_modes: vec![HttpBodyMode::Buffered as i32],
                ..binding
            }
        } else {
            binding
        }
    };
    MiddlewareManifest {
        name: MANIFEST_NAME.into(),
        service_version: env!("CARGO_PKG_VERSION").into(),
        bindings: vec![
            http_binding(SupervisorMiddlewareOperation::HttpRequest, PHASE),
            MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::WebsocketMessage as i32,
                phase: PHASE as i32,
                max_payload_bytes: MAX_PAYLOAD_BYTES,
                ..Default::default()
            },
            http_binding(
                SupervisorMiddlewareOperation::HttpResponse,
                SupervisorMiddlewarePhase::PreReturn,
            ),
        ],
        expected_audience: String::new(),
        extension: Some(extension_metadata(
            ExtensionFamily::SupervisorMiddleware,
            MANIFEST_NAME,
            openshell_core::VERSION,
            [SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string()],
        )),
    }
}

#[derive(Debug, Default)]
struct ContentGuard;

#[tonic::async_trait]
impl SupervisorMiddleware for ContentGuard {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;

    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        let caller = request.into_inner().gateway;
        let http_v2 = caller
            .as_ref()
            .is_some_and(|caller| peer_supports(caller, SUPERVISOR_MIDDLEWARE_HTTP_V2));
        let manifest = manifest(http_v2);
        validate_gateway_metadata(
            ExtensionFamily::SupervisorMiddleware,
            MANIFEST_NAME,
            manifest.extension.as_ref(),
            caller,
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
        Ok(Response::new(manifest))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let request = request.into_inner();
        let validation = GuardConfig::parse(request.config.as_ref());
        Ok(Response::new(match validation {
            Ok(_) => ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            },
            Err(reason) => ValidateConfigResponse {
                valid: false,
                reason,
            },
        }))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        http_legacy::evaluate_request(request.into_inner()).map(Response::new)
    }

    async fn evaluate_web_socket_session(
        &self,
        request: Request<Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Ok(Response::new(websocket::session_stream(
            request.into_inner(),
        )))
    }
}

#[tonic::async_trait]
impl HttpRequestPreCredentials for ContentGuard {
    type EvaluateHttpStream = HttpResultStream;

    async fn evaluate_http(
        &self,
        request: Request<Streaming<HttpEvent>>,
    ) -> Result<Response<Self::EvaluateHttpStream>, Status> {
        Ok(Response::new(http_v2::stage_stream(
            Direction::Request,
            request.into_inner(),
        )))
    }
}

#[tonic::async_trait]
impl HttpResponsePreReturn for ContentGuard {
    type EvaluateStream = HttpResponseResultStream;
    type EvaluateHttpStream = HttpResultStream;

    async fn evaluate(
        &self,
        request: Request<Streaming<HttpResponseEvent>>,
    ) -> Result<Response<Self::EvaluateStream>, Status> {
        Ok(Response::new(http_legacy::response_stream(
            request.into_inner(),
        )))
    }

    async fn evaluate_http(
        &self,
        request: Request<Streaming<HttpEvent>>,
    ) -> Result<Response<Self::EvaluateHttpStream>, Status> {
        Ok(Response::new(http_v2::stage_stream(
            Direction::Response,
            request.into_inner(),
        )))
    }
}

/// Every gRPC service the binary serves. `HttpRequestPreCredentials` carries
/// only version 2; the legacy request RPC lives on `SupervisorMiddleware`.
fn router() -> Router {
    Server::builder()
        .add_service(SupervisorMiddlewareServer::new(ContentGuard))
        .add_service(HttpRequestPreCredentialsServer::new(ContentGuard))
        .add_service(HttpResponsePreReturnServer::new(ContentGuard))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    println!("serving {MANIFEST_NAME} on http://{}", cli.bind);
    router().serve(cli.bind).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use openshell_core::extension_protocol::{
        gateway_metadata, gateway_metadata_with_capabilities, negotiate,
    };
    use openshell_core::proto::extension::v1::PeerMetadata;

    use super::*;

    async fn describe(caller: Option<PeerMetadata>) -> Result<MiddlewareManifest, Status> {
        SupervisorMiddleware::describe(
            &ContentGuard,
            Request::new(MiddlewareDescribeRequest { gateway: caller }),
        )
        .await
        .map(Response::into_inner)
    }

    fn http_v2_caller() -> PeerMetadata {
        gateway_metadata_with_capabilities(
            ExtensionFamily::SupervisorMiddleware,
            [SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string()],
        )
    }

    /// The bindings `OpenShell` v0.1.2 registers for this service.
    fn v0_1_2_bindings() -> Vec<MiddlewareBinding> {
        [
            (SupervisorMiddlewareOperation::HttpRequest, PHASE),
            (SupervisorMiddlewareOperation::WebsocketMessage, PHASE),
            (
                SupervisorMiddlewareOperation::HttpResponse,
                SupervisorMiddlewarePhase::PreReturn,
            ),
        ]
        .into_iter()
        .map(|(operation, phase)| MiddlewareBinding {
            operation: operation as i32,
            phase: phase as i32,
            max_payload_bytes: MAX_PAYLOAD_BYTES,
            request_timeout: None,
            http_protocol_version: 0,
            supported_http_body_modes: Vec::new(),
        })
        .collect()
    }

    #[tokio::test]
    async fn describe_returns_legacy_bindings_to_callers_without_http_v2() {
        let caller = gateway_metadata(ExtensionFamily::SupervisorMiddleware);
        assert!(!peer_supports(&caller, SUPERVISOR_MIDDLEWARE_HTTP_V2));

        let manifest = describe(Some(caller.clone())).await.expect("describe");

        assert_eq!(manifest.bindings, v0_1_2_bindings());
        negotiate(
            ExtensionFamily::SupervisorMiddleware,
            "content-guard-example",
            &caller,
            manifest.extension,
        )
        .expect("a caller without http-v2 accepts the service");
    }

    #[tokio::test]
    async fn describe_returns_version_2_http_bindings_to_callers_with_http_v2() {
        let caller = http_v2_caller();

        let manifest = describe(Some(caller.clone())).await.expect("describe");

        let mut expected = v0_1_2_bindings();
        for index in [0, 2] {
            expected[index].http_protocol_version = 2;
            expected[index].supported_http_body_modes = vec![HttpBodyMode::Buffered as i32];
        }
        assert_eq!(manifest.bindings, expected);
        let negotiated = negotiate(
            ExtensionFamily::SupervisorMiddleware,
            "content-guard-example",
            &caller,
            manifest.extension,
        )
        .expect("an http-v2 caller accepts the service");
        assert!(
            negotiated
                .supported_capabilities
                .contains(&SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string())
        );
        assert!(
            !negotiated
                .required_capabilities
                .contains(&SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string())
        );
    }

    #[tokio::test]
    async fn describe_rejects_missing_gateway_metadata() {
        let error = describe(None).await.unwrap_err();

        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
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
