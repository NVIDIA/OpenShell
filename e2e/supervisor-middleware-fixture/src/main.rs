// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authenticated gRPC middleware used by the focused middleware E2E lane.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use openshell_core::middleware::WebSocketResponseStream;
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    Decision, ExistingHeaderAction, HeaderMutation, HttpRequestEvaluation, HttpRequestResult,
    MiddlewareBinding, MiddlewareManifest, SupervisorMiddlewareOperation,
    SupervisorMiddlewarePhase, ValidateConfigRequest, ValidateConfigResponse,
    WebSocketSessionEvent, WriteHeader, header_mutation,
};
use openshell_sdk::extension::{ExtensionCallerKind, GatewayJwtAuthenticator};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

const REGISTRATION_NAME: &str = "e2e-scripted";
const PHASE: SupervisorMiddlewarePhase = SupervisorMiddlewarePhase::PreCredentials;
const MAX_PAYLOAD_BYTES: u64 = 4 * 1024;

#[derive(Debug)]
struct Config {
    listen: SocketAddr,
    tls_cert: PathBuf,
    tls_key: PathBuf,
    gateway_public_key: PathBuf,
    gateway_key_id: String,
    gateway_issuer: String,
    audience: String,
}

impl Config {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            listen: required_env("OPENSHELL_E2E_MIDDLEWARE_LISTEN")?.parse()?,
            tls_cert: required_env("OPENSHELL_E2E_MIDDLEWARE_TLS_CERT")?.into(),
            tls_key: required_env("OPENSHELL_E2E_MIDDLEWARE_TLS_KEY")?.into(),
            gateway_public_key: required_env("OPENSHELL_E2E_GATEWAY_PUBLIC_KEY")?.into(),
            gateway_key_id: required_env("OPENSHELL_E2E_GATEWAY_KEY_ID")?,
            gateway_issuer: required_env("OPENSHELL_E2E_GATEWAY_ISSUER")?,
            audience: required_env("OPENSHELL_E2E_MIDDLEWARE_AUDIENCE")?,
        })
    }
}

fn required_env(name: &str) -> Result<String, std::env::VarError> {
    std::env::var(name)
}

#[derive(Debug)]
struct ScriptedMiddleware {
    authenticator: Arc<GatewayJwtAuthenticator>,
    audience: String,
}

impl ScriptedMiddleware {
    fn authenticate<T>(
        &self,
        request: &Request<T>,
        allowed: &[ExtensionCallerKind],
    ) -> Result<(), Status> {
        let caller = self.authenticator.authenticate_request(request)?;
        if allowed.contains(&caller.kind) {
            Ok(())
        } else {
            Err(Status::permission_denied(
                "caller kind is not authorized for this middleware RPC",
            ))
        }
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for ScriptedMiddleware {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;

    async fn describe(&self, request: Request<()>) -> Result<Response<MiddlewareManifest>, Status> {
        self.authenticate(
            &request,
            &[
                ExtensionCallerKind::Gateway,
                ExtensionCallerKind::Supervisor,
            ],
        )?;
        Ok(Response::new(MiddlewareManifest {
            name: "openshell-e2e-middleware-fixture".into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: PHASE as i32,
                max_payload_bytes: MAX_PAYLOAD_BYTES,
                timeout: String::new(),
            }],
            expected_audience: self.audience.clone(),
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        self.authenticate(&request, &[ExtensionCallerKind::Gateway])?;
        let valid = request.get_ref().middleware_name == REGISTRATION_NAME;
        Ok(Response::new(ValidateConfigResponse {
            valid,
            reason: if valid {
                String::new()
            } else {
                "unsupported middleware registration".into()
            },
        }))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        self.authenticate(&request, &[ExtensionCallerKind::Supervisor])?;
        let request = request.into_inner();
        if request.middleware_name != REGISTRATION_NAME || request.phase != PHASE as i32 {
            return Err(Status::invalid_argument(
                "unsupported middleware registration or phase",
            ));
        }

        let body = String::from_utf8(request.body)
            .map_err(|_| Status::invalid_argument("fixture requires a UTF-8 request body"))?;
        let replacement = body.replace("raw-secret", "[REDACTED]");
        Ok(Response::new(HttpRequestResult {
            decision: Decision::Allow as i32,
            body: replacement.into_bytes(),
            has_body: true,
            header_mutations: vec![HeaderMutation {
                operation: Some(header_mutation::Operation::Write(WriteHeader {
                    name: "x-openshell-middleware-fixture".into(),
                    value: "evaluated".into(),
                    on_existing: ExistingHeaderAction::Overwrite as i32,
                })),
            }],
            ..Default::default()
        }))
    }

    async fn evaluate_web_socket_session(
        &self,
        _request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Err(Status::unimplemented(
            "the HTTP-only E2E fixture does not implement WebSocket middleware",
        ))
    }
}

async fn read(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    tokio::fs::read(path).await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let cert = read(&config.tls_cert).await?;
    let key = read(&config.tls_key).await?;
    let public_key = read(&config.gateway_public_key).await?;
    let authenticator = GatewayJwtAuthenticator::from_ed25519_pem(
        &public_key,
        config.gateway_key_id,
        config.gateway_issuer,
        config.audience.clone(),
    )?;
    let service = ScriptedMiddleware {
        authenticator: Arc::new(authenticator),
        audience: config.audience,
    };

    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(cert, key)))?
        .add_service(SupervisorMiddlewareServer::new(service))
        .serve(config.listen)
        .await?;
    Ok(())
}
