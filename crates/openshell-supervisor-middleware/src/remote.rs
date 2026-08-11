// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::middleware::HttpRequestView;
use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use openshell_core::proto::{
    HttpRequestEvaluation, HttpRequestResult, MiddlewareManifest, ValidateConfigRequest,
    ValidateConfigResponse,
};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Response, Status};

use crate::MIDDLEWARE_GRPC_MESSAGE_BYTES;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// Adapts the borrowed runtime request contract to the owned protobuf service
/// contract only when dispatch crosses a gRPC-shaped boundary.
#[derive(Clone)]
pub struct GrpcMiddlewareService {
    service: Arc<dyn SupervisorMiddleware>,
}

impl GrpcMiddlewareService {
    /// Connect an operator registration and wrap its generated gRPC client.
    pub async fn connect(registration_name: &str, grpc_endpoint: &str) -> Result<Self> {
        Ok(Self {
            service: Arc::new(
                RemoteMiddlewareService::connect(registration_name, grpc_endpoint).await?,
            ),
        })
    }

    /// Wrap a protobuf-shaped service used by transport-boundary tests.
    #[cfg(test)]
    pub fn from_service(service: Arc<dyn SupervisorMiddleware>) -> Self {
        Self { service }
    }

    /// Forward a manifest request through the protobuf service contract.
    pub async fn describe(&self) -> std::result::Result<Response<MiddlewareManifest>, Status> {
        self.service.describe(Request::new(())).await
    }

    /// Materialize the owned configuration request required by gRPC.
    pub async fn validate_config(
        &self,
        middleware_name: &str,
        config: &prost_types::Struct,
    ) -> std::result::Result<Response<ValidateConfigResponse>, Status> {
        self.service
            .validate_config(Request::new(ValidateConfigRequest {
                config: Some(config.clone()),
                middleware_name: middleware_name.to_string(),
            }))
            .await
    }

    /// Materialize an owned protobuf evaluation immediately before transport.
    pub async fn evaluate_http_request(
        &self,
        request: HttpRequestView<'_>,
    ) -> std::result::Result<Response<HttpRequestResult>, Status> {
        self.service
            .evaluate_http_request(Request::new(HttpRequestEvaluation {
                phase: request.phase() as i32,
                context: Some(request.context().clone()),
                config: Some(request.config().clone()),
                target: Some(request.target().clone()),
                headers: request.headers().to_vec(),
                body: request.body().to_vec(),
                middleware_name: request.middleware_name().to_string(),
            }))
            .await
    }
}

#[derive(Clone)]
pub struct RemoteMiddlewareService {
    client: SupervisorMiddlewareClient<Channel>,
}

impl RemoteMiddlewareService {
    pub async fn connect(registration_name: &str, grpc_endpoint: &str) -> Result<Self> {
        let mut endpoint = Endpoint::from_shared(grpc_endpoint.to_string())
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "middleware registration '{registration_name}' has an invalid grpc_endpoint"
                )
            })?
            .http2_keep_alive_interval(HTTP2_KEEP_ALIVE_INTERVAL)
            .keep_alive_while_idle(true)
            .keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT)
            .http2_adaptive_window(true);

        if grpc_endpoint.starts_with("https://") {
            endpoint = endpoint
                .tls_config(ClientTlsConfig::new().with_enabled_roots())
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!("middleware registration '{registration_name}' could not configure TLS")
                })?;
        }

        let channel = endpoint
            .connect_timeout(CONNECT_TIMEOUT)
            .connect()
            .await
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "middleware registration '{registration_name}' could not connect to {grpc_endpoint}"
                )
            })?;

        Ok(Self {
            client: SupervisorMiddlewareClient::new(channel)
                .max_decoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES),
        })
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for RemoteMiddlewareService {
    async fn describe(
        &self,
        request: Request<()>,
    ) -> std::result::Result<Response<MiddlewareManifest>, Status> {
        let mut client = self.client.clone();
        client.describe(request).await
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> std::result::Result<Response<ValidateConfigResponse>, Status> {
        let mut client = self.client.clone();
        client.validate_config(request).await
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> std::result::Result<Response<HttpRequestResult>, Status> {
        let mut client = self.client.clone();
        client.evaluate_http_request(request).await
    }
}
