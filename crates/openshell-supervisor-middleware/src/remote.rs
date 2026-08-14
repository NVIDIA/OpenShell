// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::middleware::{
    HttpRequestView, SupervisorMiddlewareEndpoint, WebSocketResponseStream,
};
use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
use openshell_core::proto::{
    HttpRequestEvaluation, HttpRequestResult, MiddlewareManifest, ValidateConfigRequest,
    ValidateConfigResponse, WebSocketSessionEvent,
};
use openshell_extension_core::{
    BearerTokenInterceptor, BearerTokenSlot, ExtensionChannelConfig, ExtensionServerTrust,
    connect_channel,
};
use std::sync::Arc;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Request, Response, Status};

use crate::MIDDLEWARE_GRPC_MESSAGE_BYTES;

type ExtensionChannel = InterceptedService<Channel, BearerTokenInterceptor>;

/// Adapts the borrowed runtime request contract to the owned protobuf service
/// contract only when dispatch crosses a gRPC-shaped boundary.
#[derive(Clone)]
pub struct GrpcMiddlewareService {
    service: Arc<dyn SupervisorMiddlewareEndpoint>,
}

impl GrpcMiddlewareService {
    /// Connect an operator registration and wrap its generated gRPC client.
    pub async fn connect(
        registration_name: &str,
        grpc_endpoint: &str,
        tls_ca_cert_pem: &[u8],
        bearer: Option<BearerTokenSlot>,
    ) -> Result<Self> {
        Ok(Self {
            service: Arc::new(
                RemoteMiddlewareService::connect(
                    registration_name,
                    grpc_endpoint,
                    tls_ca_cert_pem,
                    bearer,
                )
                .await?,
            ),
        })
    }

    /// Wrap a protobuf-shaped service used by transport-boundary tests.
    #[cfg(test)]
    pub fn from_service(service: Arc<dyn SupervisorMiddlewareEndpoint>) -> Self {
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

    /// Open a remote WebSocket middleware stream through the gRPC adapter.
    pub async fn open_websocket_session(
        &self,
        receiver: tokio::sync::mpsc::Receiver<WebSocketSessionEvent>,
    ) -> std::result::Result<WebSocketResponseStream, Status> {
        self.service.open_websocket_session(receiver).await
    }
}

#[derive(Clone)]
pub struct RemoteMiddlewareService {
    client: SupervisorMiddlewareClient<ExtensionChannel>,
}

impl RemoteMiddlewareService {
    pub async fn connect(
        registration_name: &str,
        grpc_endpoint: &str,
        tls_ca_cert_pem: &[u8],
        bearer: Option<BearerTokenSlot>,
    ) -> Result<Self> {
        let mut config = ExtensionChannelConfig::new(grpc_endpoint);
        if !tls_ca_cert_pem.is_empty() {
            config = config
                .with_server_trust(ExtensionServerTrust::CustomCaPem(tls_ca_cert_pem.to_vec()));
        }
        let channel = connect_channel(&config)
            .await
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "middleware registration '{registration_name}' could not connect to {grpc_endpoint}"
                )
            })?;
        let interceptor =
            bearer.map_or_else(BearerTokenInterceptor::disabled, |slot| slot.interceptor());
        let channel = InterceptedService::new(channel, interceptor);

        Ok(Self {
            client: SupervisorMiddlewareClient::new(channel)
                .max_decoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES),
        })
    }
}

#[tonic::async_trait]
impl SupervisorMiddlewareEndpoint for RemoteMiddlewareService {
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

    async fn open_websocket_session(
        &self,
        receiver: tokio::sync::mpsc::Receiver<WebSocketSessionEvent>,
    ) -> std::result::Result<WebSocketResponseStream, Status> {
        let mut client = self.client.clone();
        let responses = client
            .evaluate_web_socket_session(Request::new(tokio_stream::wrappers::ReceiverStream::new(
                receiver,
            )))
            .await?
            .into_inner();
        Ok(Box::pin(responses))
    }
}
