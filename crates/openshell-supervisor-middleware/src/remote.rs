// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::middleware::{
    HttpRequestHookResultStream, HttpRequestView, HttpResponseHookResultStream,
    HttpResponseResultStream, SupervisorMiddlewareEndpoint, WebSocketResponseStream,
};
use openshell_core::proto::middleware::v1::http_hooks_client::HttpHooksClient;
use openshell_core::proto::middleware::v1::http_response_pre_return_client::HttpResponsePreReturnClient;
use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
use openshell_core::proto::{
    HttpRequestEvaluation, HttpRequestHookEvent, HttpRequestResult, HttpResponseEvent,
    HttpResponseHookEvent, MiddlewareDescribeRequest, MiddlewareManifest, ValidateConfigRequest,
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

    /// Open a remote HTTP hook request exchange through the gRPC
    /// adapter.
    pub async fn open_http_request_hook(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpRequestHookEvent>,
    ) -> std::result::Result<HttpRequestHookResultStream, Status> {
        self.service.open_http_request_hook(receiver).await
    }

    /// Open a remote HTTP hook response exchange through the gRPC
    /// adapter.
    pub async fn open_http_response_hook(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpResponseHookEvent>,
    ) -> std::result::Result<HttpResponseHookResultStream, Status> {
        self.service.open_http_response_hook(receiver).await
    }
}

#[derive(Clone)]
pub struct RemoteMiddlewareService {
    client: SupervisorMiddlewareClient<ExtensionChannel>,
    response_client: HttpResponsePreReturnClient<ExtensionChannel>,
    http_hooks_client: HttpHooksClient<ExtensionChannel>,
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
            http_hooks_client: HttpHooksClient::new(channel)
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
        // Legacy HTTP hooks stay callable until their removal in 0.2.0.
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
        // Legacy HTTP hooks stay callable until their removal in 0.2.0.
        #[allow(deprecated)]
        let responses = client
            .evaluate(Request::new(tokio_stream::wrappers::ReceiverStream::new(
                receiver,
            )))
            .await?
            .into_inner();
        Ok(Box::pin(responses))
    }

    async fn open_http_request_hook(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpRequestHookEvent>,
    ) -> std::result::Result<HttpRequestHookResultStream, Status> {
        let mut client = self.http_hooks_client.clone();
        let responses = client
            .evaluate_http_request_hook(Request::new(tokio_stream::wrappers::ReceiverStream::new(
                receiver,
            )))
            .await?
            .into_inner();
        Ok(Box::pin(responses))
    }

    async fn open_http_response_hook(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpResponseHookEvent>,
    ) -> std::result::Result<HttpResponseHookResultStream, Status> {
        let mut client = self.http_hooks_client.clone();
        let responses = client
            .evaluate_http_response_hook(Request::new(tokio_stream::wrappers::ReceiverStream::new(
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
    use openshell_core::proto::middleware::v1::http_hooks_server::{HttpHooks, HttpHooksServer};
    use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
        SupervisorMiddleware, SupervisorMiddlewareServer,
    };
    use openshell_core::proto::{
        HttpContinue, HttpPreflightResult, HttpRequestHookPreflight, HttpRequestHookResult,
        HttpResponseHookPreflight, HttpResponseHookResult, SupervisorMiddlewarePhase,
        http_preflight_result, http_request_hook_event, http_request_hook_result,
        http_response_hook_event, http_response_hook_result,
    };
    use openshell_extension_core::call_with_retries;
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    use super::*;

    struct HttpHooksService;

    fn continue_without_body() -> HttpPreflightResult {
        HttpPreflightResult {
            decision: Some(http_preflight_result::Decision::ContinueWithoutBody(
                HttpContinue::default(),
            )),
            ..Default::default()
        }
    }

    #[tonic::async_trait]
    impl HttpHooks for HttpHooksService {
        type EvaluateHttpRequestHookStream = HttpRequestHookResultStream;
        type EvaluateHttpResponseHookStream = HttpResponseHookResultStream;

        async fn evaluate_http_request_hook(
            &self,
            request: Request<tonic::Streaming<HttpRequestHookEvent>>,
        ) -> std::result::Result<Response<Self::EvaluateHttpRequestHookStream>, Status> {
            let event = request
                .into_inner()
                .message()
                .await?
                .expect("request event");
            let Some(http_request_hook_event::Event::Preflight(preflight)) = event.event else {
                panic!("expected request preflight");
            };
            assert_eq!(
                preflight.phase,
                SupervisorMiddlewarePhase::PreCredentials as i32
            );
            Ok(Response::new(Box::pin(futures::stream::iter([Ok(
                HttpRequestHookResult {
                    result: Some(http_request_hook_result::Result::PreflightResult(
                        continue_without_body(),
                    )),
                },
            )]))))
        }

        async fn evaluate_http_response_hook(
            &self,
            request: Request<tonic::Streaming<HttpResponseHookEvent>>,
        ) -> std::result::Result<Response<Self::EvaluateHttpResponseHookStream>, Status> {
            let event = request
                .into_inner()
                .message()
                .await?
                .expect("response event");
            let Some(http_response_hook_event::Event::Preflight(preflight)) = event.event else {
                panic!("expected response preflight");
            };
            assert_eq!(preflight.phase, SupervisorMiddlewarePhase::PreReturn as i32);
            Ok(Response::new(Box::pin(futures::stream::iter([Ok(
                HttpResponseHookResult {
                    result: Some(http_response_hook_result::Result::PreflightResult(
                        continue_without_body(),
                    )),
                },
            )]))))
        }
    }

    #[tokio::test]
    async fn http_hooks_rpcs_share_channel_and_rotating_bearer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let (authorization_tx, mut authorization_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(HttpHooksServer::with_interceptor(
                    HttpHooksService,
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
            "test/http-hooks",
            &format!("http://{address}"),
            &[],
            Some(bearer.clone()),
        )
        .await
        .expect("connect");

        let (request_tx, request_rx) = mpsc::channel(1);
        request_tx
            .send(HttpRequestHookEvent {
                event: Some(http_request_hook_event::Event::Preflight(
                    HttpRequestHookPreflight {
                        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                        ..Default::default()
                    },
                )),
            })
            .await
            .expect("send request");
        drop(request_tx);
        let mut requests = client
            .open_http_request_hook(request_rx)
            .await
            .expect("request RPC");
        assert_eq!(
            requests
                .next()
                .await
                .expect("request result")
                .expect("request status")
                .result,
            Some(http_request_hook_result::Result::PreflightResult(
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
            .send(HttpResponseHookEvent {
                event: Some(http_response_hook_event::Event::Preflight(
                    HttpResponseHookPreflight {
                        phase: SupervisorMiddlewarePhase::PreReturn as i32,
                        ..Default::default()
                    },
                )),
            })
            .await
            .expect("send response");
        drop(response_tx);
        let mut responses = client
            .open_http_response_hook(response_rx)
            .await
            .expect("response RPC");
        assert_eq!(
            responses
                .next()
                .await
                .expect("response result")
                .expect("response status")
                .result,
            Some(http_response_hook_result::Result::PreflightResult(
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

    struct CountingMiddleware {
        handled: Arc<std::sync::atomic::AtomicUsize>,
        /// With a receiver, a request call reports its arrival and is never
        /// answered.
        received: Option<mpsc::UnboundedSender<()>>,
    }

    #[tonic::async_trait]
    impl SupervisorMiddleware for CountingMiddleware {
        type EvaluateWebSocketSessionStream = WebSocketResponseStream;

        async fn describe(
            &self,
            _request: Request<MiddlewareDescribeRequest>,
        ) -> std::result::Result<Response<MiddlewareManifest>, Status> {
            Ok(Response::new(MiddlewareManifest::default()))
        }

        async fn validate_config(
            &self,
            _request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<Response<ValidateConfigResponse>, Status> {
            Ok(Response::new(ValidateConfigResponse::default()))
        }

        async fn evaluate_http_request(
            &self,
            _request: Request<HttpRequestEvaluation>,
        ) -> std::result::Result<Response<HttpRequestResult>, Status> {
            self.handled
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(received) = &self.received {
                let _ = received.send(());
                std::future::pending::<()>().await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            Ok(Response::new(HttpRequestResult::default()))
        }

        async fn evaluate_web_socket_session(
            &self,
            _request: Request<tonic::Streaming<WebSocketSessionEvent>>,
        ) -> std::result::Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
            Err(Status::unimplemented("not used"))
        }
    }

    /// Serves connections accepted from `listener` until the returned sender
    /// fires, then drains. The listener stays open, so the next server takes
    /// over the connections that arrive meanwhile, as an instance that
    /// inherits the listening socket does.
    fn serve_counting_middleware(
        listener: Arc<TcpListener>,
        handled: Arc<std::sync::atomic::AtomicUsize>,
    ) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let incoming = futures::stream::unfold(listener, |listener| async move {
            let accepted = listener.accept().await.map(|(stream, _)| stream);
            Some((accepted, listener))
        });
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(SupervisorMiddlewareServer::new(CountingMiddleware {
                    handled,
                    received: None,
                }))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("serve");
        });
        (shutdown_tx, server)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unary_calls_are_answered_once_across_service_hand_overs() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let handled = Arc::new(AtomicUsize::new(0));
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.expect("bind"));
        let address = listener.local_addr().expect("address");
        let (mut shutdown, mut server) =
            serve_counting_middleware(listener.clone(), handled.clone());
        let client = RemoteMiddlewareService::connect(
            "test/restart",
            &format!("http://{address}"),
            &[],
            None,
        )
        .await
        .expect("connect");

        let stop = Arc::new(AtomicBool::new(false));
        let callers: Vec<_> = (0..8)
            .map(|_| {
                let client = client.clone();
                let stop = stop.clone();
                tokio::spawn(async move {
                    let mut answered = 0_usize;
                    while !stop.load(Ordering::SeqCst) {
                        call_with_retries(None, || {
                            client.evaluate_http_request(Request::new(
                                HttpRequestEvaluation::default(),
                            ))
                        })
                        .await
                        .expect("call answered across a hand-over");
                        answered += 1;
                    }
                    answered
                })
            })
            .collect();

        for _ in 0..10 {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            let (next_shutdown, next_server) =
                serve_counting_middleware(listener.clone(), handled.clone());
            shutdown.send(()).expect("server running");
            server.await.expect("server drained");
            (shutdown, server) = (next_shutdown, next_server);
        }
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        stop.store(true, Ordering::SeqCst);

        let mut answered = 0;
        for caller in callers {
            answered += caller.await.expect("caller");
        }
        assert!(answered > 0);
        assert_eq!(
            answered,
            handled.load(Ordering::SeqCst),
            "every call reached a handler exactly once"
        );
    }

    /// A call the service received is not sent again when its connection is
    /// reset, although another connection is accepted straight away.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_call_the_service_received_is_not_sent_again_after_a_reset() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let handled = Arc::new(AtomicUsize::new(0));
        let (received_tx, mut received) = mpsc::unbounded_channel();
        let backend = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let backend_address = backend.local_addr().expect("address");
        let server = tokio::spawn({
            let handled = handled.clone();
            async move {
                Server::builder()
                    .add_service(SupervisorMiddlewareServer::new(CountingMiddleware {
                        handled,
                        received: Some(received_tx),
                    }))
                    .serve_with_incoming(TcpListenerStream::new(backend))
                    .await
                    .expect("serve");
            }
        });

        // The client reaches the service through a relay, so the test can
        // reset an established connection while the relay keeps accepting.
        let relay = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = relay.local_addr().expect("address");
        let (connections_tx, mut connections) = mpsc::unbounded_channel();
        let relay = tokio::spawn(async move {
            loop {
                let (mut client_side, _) = relay.accept().await.expect("accept");
                let (reset_tx, reset_rx) = oneshot::channel::<()>();
                let _ = connections_tx.send(reset_tx);
                tokio::spawn(async move {
                    let mut service_side =
                        openshell_core::net::connect_tcp_nodelay_best_effort(backend_address)
                            .await
                            .expect("connect to service");
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut client_side, &mut service_side) => {}
                        _ = reset_rx => {
                            // Closing with unread data and no linger sends RST.
                            client_side.set_zero_linger().expect("linger");
                        }
                    }
                });
            }
        });

        let client =
            RemoteMiddlewareService::connect("test/reset", &format!("http://{address}"), &[], None)
                .await
                .expect("connect");
        let call = tokio::spawn(async move {
            call_with_retries(None, || {
                client.evaluate_http_request(Request::new(HttpRequestEvaluation::default()))
            })
            .await
        });

        received
            .recv()
            .await
            .expect("the service received the call");
        connections
            .recv()
            .await
            .expect("relayed connection")
            .send(())
            .expect("reset the connection");

        let status = tokio::time::timeout(std::time::Duration::from_secs(10), call)
            .await
            .expect("the call ends")
            .expect("caller")
            .expect_err("the call fails");
        assert_ne!(status.code(), tonic::Code::Ok);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(
            handled.load(Ordering::SeqCst),
            1,
            "the call reached a handler once: {status:?}"
        );

        relay.abort();
        server.abort();
    }
}
