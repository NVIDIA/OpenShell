// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use openshell_core::proto::{
    HttpRequestEvaluation, HttpRequestResult, MiddlewareManifest, ValidateConfigRequest,
    ValidateConfigResponse,
};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Response, Status};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RPC_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct RemoteMiddlewareService {
    registration_name: String,
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
            })?;
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
            registration_name: registration_name.to_string(),
            client: SupervisorMiddlewareClient::new(channel),
        })
    }

    async fn with_timeout<T>(
        &self,
        operation: &'static str,
        future: impl Future<Output = std::result::Result<Response<T>, Status>>,
    ) -> std::result::Result<Response<T>, Status> {
        tokio::time::timeout(RPC_TIMEOUT, future)
            .await
            .map_err(|_| {
                Status::deadline_exceeded(format!(
                    "middleware '{}' {operation} timed out",
                    self.registration_name
                ))
            })?
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for RemoteMiddlewareService {
    async fn describe(
        &self,
        request: Request<()>,
    ) -> std::result::Result<Response<MiddlewareManifest>, Status> {
        let mut client = self.client.clone();
        self.with_timeout("Describe", client.describe(request))
            .await
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> std::result::Result<Response<ValidateConfigResponse>, Status> {
        let mut client = self.client.clone();
        self.with_timeout("ValidateConfig", client.validate_config(request))
            .await
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> std::result::Result<Response<HttpRequestResult>, Status> {
        let mut client = self.client.clone();
        self.with_timeout("EvaluateHttpRequest", client.evaluate_http_request(request))
            .await
    }
}
