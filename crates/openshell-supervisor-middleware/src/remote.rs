// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::middleware::{
    HttpRequestSessionResultStream, HttpRequestView, HttpResponseResultStream,
    HttpResponseSessionResultStream, SupervisorMiddlewareEndpoint, WebSocketResponseStream,
};
use openshell_core::proto::middleware::v1::http_response_pre_return_client::HttpResponsePreReturnClient;
use openshell_core::proto::middleware::v1::http_session_middleware_client::HttpSessionMiddlewareClient;
use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
use openshell_core::proto::{
    HttpRequestEvaluation, HttpRequestResult, HttpRequestSessionEvent, HttpResponseEvent,
    HttpResponseSessionEvent, MiddlewareDescribeRequest, MiddlewareManifest, ValidateConfigRequest,
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
        self.service
            .describe(Request::new(MiddlewareDescribeRequest {
                gateway: Some(openshell_core::extension_protocol::gateway_metadata(
                    openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                )),
            }))
            .await
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

    /// Open a remote HTTP response pre-return stream through the gRPC adapter.
    pub async fn open_http_response_pre_return(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpResponseEvent>,
    ) -> std::result::Result<HttpResponseResultStream, Status> {
        self.service.open_http_response_pre_return(receiver).await
    }

    /// Open a remote HTTP session hook request exchange through the gRPC
    /// adapter.
    pub async fn open_http_request_session(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpRequestSessionEvent>,
    ) -> std::result::Result<HttpRequestSessionResultStream, Status> {
        self.service.open_http_request_session(receiver).await
    }

    /// Open a remote HTTP session hook response exchange through the gRPC
    /// adapter.
    pub async fn open_http_response_session(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpResponseSessionEvent>,
    ) -> std::result::Result<HttpResponseSessionResultStream, Status> {
        self.service.open_http_response_session(receiver).await
    }
}

#[derive(Clone)]
pub struct RemoteMiddlewareService {
    client: SupervisorMiddlewareClient<ExtensionChannel>,
    response_client: HttpResponsePreReturnClient<ExtensionChannel>,
    http_session_client: HttpSessionMiddlewareClient<ExtensionChannel>,
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
            client: SupervisorMiddlewareClient::new(channel.clone())
                .max_decoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES),
            response_client: HttpResponsePreReturnClient::new(channel.clone())
                .max_decoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES),
            http_session_client: HttpSessionMiddlewareClient::new(channel)
                .max_decoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES),
        })
    }
}

#[tonic::async_trait]
impl SupervisorMiddlewareEndpoint for RemoteMiddlewareService {
    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
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
        // v1 HTTP hooks stay callable until their removal in 0.2.0.
        #[allow(deprecated)]
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

    async fn open_http_response_pre_return(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpResponseEvent>,
    ) -> std::result::Result<HttpResponseResultStream, Status> {
        let mut client = self.response_client.clone();
        // v1 HTTP hooks stay callable until their removal in 0.2.0.
        #[allow(deprecated)]
        let responses = client
            .evaluate(Request::new(tokio_stream::wrappers::ReceiverStream::new(
                receiver,
            )))
            .await?
            .into_inner();
        Ok(Box::pin(responses))
    }

    async fn open_http_request_session(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpRequestSessionEvent>,
    ) -> std::result::Result<HttpRequestSessionResultStream, Status> {
        let mut client = self.http_session_client.clone();
        let responses = client
            .evaluate_request(Request::new(tokio_stream::wrappers::ReceiverStream::new(
                receiver,
            )))
            .await?
            .into_inner();
        Ok(Box::pin(responses))
    }

    async fn open_http_response_session(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpResponseSessionEvent>,
    ) -> std::result::Result<HttpResponseSessionResultStream, Status> {
        let mut client = self.http_session_client.clone();
        let responses = client
            .evaluate_response(Request::new(tokio_stream::wrappers::ReceiverStream::new(
                receiver,
            )))
            .await?
            .into_inner();
        Ok(Box::pin(responses))
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use openshell_core::proto::middleware::v1::http_session_middleware_server::{
        HttpSessionMiddleware, HttpSessionMiddlewareServer,
    };
    use openshell_core::proto::{
        HttpContinue, HttpPreflightResult, HttpRequestSessionPreflight, HttpRequestSessionResult,
        HttpResponseSessionPreflight, HttpResponseSessionResult, SupervisorMiddlewarePhase,
        http_preflight_result, http_request_session_event, http_request_session_result,
        http_response_session_event, http_response_session_result,
    };
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    use super::*;

    struct SessionService;

    fn continue_without_body() -> HttpPreflightResult {
        HttpPreflightResult {
            decision: Some(http_preflight_result::Decision::ContinueWithoutBody(
                HttpContinue::default(),
            )),
            ..Default::default()
        }
    }

    #[tonic::async_trait]
    impl HttpSessionMiddleware for SessionService {
        type EvaluateRequestStream = HttpRequestSessionResultStream;
        type EvaluateResponseStream = HttpResponseSessionResultStream;

        async fn evaluate_request(
            &self,
            request: Request<tonic::Streaming<HttpRequestSessionEvent>>,
        ) -> std::result::Result<Response<Self::EvaluateRequestStream>, Status> {
            let event = request
                .into_inner()
                .message()
                .await?
                .expect("request event");
            let Some(http_request_session_event::Event::Preflight(preflight)) = event.event else {
                panic!("expected request preflight");
            };
            assert_eq!(
                preflight.phase,
                SupervisorMiddlewarePhase::PreCredentials as i32
            );
            Ok(Response::new(Box::pin(futures::stream::iter([Ok(
                HttpRequestSessionResult {
                    result: Some(http_request_session_result::Result::PreflightResult(
                        continue_without_body(),
                    )),
                },
            )]))))
        }

        async fn evaluate_response(
            &self,
            request: Request<tonic::Streaming<HttpResponseSessionEvent>>,
        ) -> std::result::Result<Response<Self::EvaluateResponseStream>, Status> {
            let event = request
                .into_inner()
                .message()
                .await?
                .expect("response event");
            let Some(http_response_session_event::Event::Preflight(preflight)) = event.event else {
                panic!("expected response preflight");
            };
            assert_eq!(preflight.phase, SupervisorMiddlewarePhase::PreReturn as i32);
            Ok(Response::new(Box::pin(futures::stream::iter([Ok(
                HttpResponseSessionResult {
                    result: Some(http_response_session_result::Result::PreflightResult(
                        continue_without_body(),
                    )),
                },
            )]))))
        }
    }

    #[tokio::test]
    async fn http_session_rpcs_share_channel_and_rotating_bearer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let (authorization_tx, mut authorization_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(HttpSessionMiddlewareServer::with_interceptor(
                    SessionService,
                    move |request: Request<()>| {
                        authorization_tx
                            .send(
                                request
                                    .metadata()
                                    .get("authorization")
                                    .expect("authorization metadata")
                                    .to_str()
                                    .expect("ASCII authorization")
                                    .to_owned(),
                            )
                            .expect("record authorization");
                        Ok(request)
                    },
                ))
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("serve");
        });
        let bearer = BearerTokenSlot::new("request-token", i64::MAX).expect("bearer");
        let client = RemoteMiddlewareService::connect(
            "test/http-session",
            &format!("http://{address}"),
            &[],
            Some(bearer.clone()),
        )
        .await
        .expect("connect");

        let (request_tx, request_rx) = mpsc::channel(1);
        request_tx
            .send(HttpRequestSessionEvent {
                event: Some(http_request_session_event::Event::Preflight(
                    HttpRequestSessionPreflight {
                        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                        ..Default::default()
                    },
                )),
            })
            .await
            .expect("send request");
        drop(request_tx);
        let mut requests = client
            .open_http_request_session(request_rx)
            .await
            .expect("request RPC");
        assert_eq!(
            requests
                .next()
                .await
                .expect("request result")
                .expect("request status")
                .result,
            Some(http_request_session_result::Result::PreflightResult(
                continue_without_body()
            ))
        );
        assert_eq!(
            authorization_rx.recv().await.as_deref(),
            Some("Bearer request-token")
        );

        bearer
            .update("response-token", i64::MAX)
            .expect("rotate bearer");
        let (response_tx, response_rx) = mpsc::channel(1);
        response_tx
            .send(HttpResponseSessionEvent {
                event: Some(http_response_session_event::Event::Preflight(
                    HttpResponseSessionPreflight {
                        phase: SupervisorMiddlewarePhase::PreReturn as i32,
                        ..Default::default()
                    },
                )),
            })
            .await
            .expect("send response");
        drop(response_tx);
        let mut responses = client
            .open_http_response_session(response_rx)
            .await
            .expect("response RPC");
        assert_eq!(
            responses
                .next()
                .await
                .expect("response result")
                .expect("response status")
                .result,
            Some(http_response_session_result::Result::PreflightResult(
                continue_without_body()
            ))
        );
        assert_eq!(
            authorization_rx.recv().await.as_deref(),
            Some("Bearer response-token")
        );

        drop((requests, responses, client));
        shutdown_tx.send(()).expect("shutdown");
        server.await.expect("server task");
    }
}
