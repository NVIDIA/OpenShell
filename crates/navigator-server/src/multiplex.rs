// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protocol multiplexing for gRPC and HTTP on the same port.
//!
//! This module implements connection-level multiplexing that routes requests
//! to either the gRPC service or HTTP endpoints based on the request headers.

use bytes::Bytes;
use http::{Request, Response};
use http_body::Body;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use navigator_core::proto::{inference_server::InferenceServer, navigator_server::NavigatorServer};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tower::ServiceExt;

use crate::{NavigatorService, ServerState, http_router, inference::InferenceService};

/// Maximum inbound gRPC message size (1 MB).
///
/// Replaces tonic's implicit 4 MB default with a conservative limit to
/// bound memory allocation from a single request. Sandbox creation is
/// the largest payload and well within this cap under normal use.
const MAX_GRPC_DECODE_SIZE: usize = 1_048_576;

/// Multiplexed gRPC/HTTP service.
#[derive(Clone)]
pub struct MultiplexService {
    state: Arc<ServerState>,
}

impl MultiplexService {
    /// Create a new multiplex service.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }

    /// Serve a connection, routing to gRPC or HTTP based on content-type.
    pub async fn serve<S>(&self, stream: S) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let navigator = NavigatorServer::new(NavigatorService::new(self.state.clone()))
            .max_decoding_message_size(MAX_GRPC_DECODE_SIZE);
        let inference = InferenceServer::new(InferenceService::new(self.state.clone()))
            .max_decoding_message_size(MAX_GRPC_DECODE_SIZE);
        let grpc_service = GrpcRouter::new(navigator, inference);
        let http_service = http_router(self.state.clone());

        let service = MultiplexedService::new(grpc_service, http_service);

        Builder::new(TokioExecutor::new())
            .serve_connection_with_upgrades(TokioIo::new(stream), service)
            .await?;

        Ok(())
    }
}

/// Combined gRPC service that routes between `OpenShell` and Inference services
/// based on the request path prefix.
#[derive(Clone)]
pub struct GrpcRouter<N, I> {
    navigator: N,
    inference: I,
}

impl<N, I> GrpcRouter<N, I> {
    fn new(navigator: N, inference: I) -> Self {
        Self {
            navigator,
            inference,
        }
    }
}

const INFERENCE_PATH_PREFIX: &str = "/navigator.inference.v1.Inference/";

impl<N, I, B> tower::Service<Request<B>> for GrpcRouter<N, I>
where
    N: tower::Service<Request<B>> + Clone + Send + 'static,
    N::Response: Send,
    N::Future: Send,
    N::Error: Send,
    I: tower::Service<Request<B>, Response = N::Response, Error = N::Error>
        + Clone
        + Send
        + 'static,
    I::Future: Send,
    B: Send + 'static,
{
    type Response = N::Response;
    type Error = N::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let is_inference = req.uri().path().starts_with(INFERENCE_PATH_PREFIX);

        if is_inference {
            let mut svc = self.inference.clone();
            Box::pin(async move { svc.ready().await?.call(req).await })
        } else {
            let mut svc = self.navigator.clone();
            Box::pin(async move { svc.ready().await?.call(req).await })
        }
    }
}

/// Service that multiplexes between gRPC and HTTP.
#[derive(Clone)]
pub struct MultiplexedService<G, H> {
    grpc: G,
    http: H,
}

impl<G, H> MultiplexedService<G, H> {
    /// Create a new multiplexed service from gRPC and HTTP services.
    #[must_use]
    pub fn new(grpc: G, http: H) -> Self {
        Self { grpc, http }
    }
}

impl<G, H, GBody, HBody> hyper::service::Service<Request<Incoming>> for MultiplexedService<G, H>
where
    G: tower::Service<Request<BoxBody>, Response = Response<GBody>> + Clone + Send + 'static,
    G::Future: Send,
    G::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    GBody: Body<Data = Bytes> + Send + 'static,
    GBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    H: tower::Service<Request<BoxBody>, Response = Response<HBody>> + Clone + Send + 'static,
    H::Future: Send,
    H::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    HBody: Body<Data = Bytes> + Send + 'static,
    HBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<BoxBody>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let is_grpc = req
            .headers()
            .get("content-type")
            .is_some_and(|v| v.as_bytes().starts_with(b"application/grpc"));

        if is_grpc {
            let mut grpc = self.grpc.clone();
            Box::pin(async move {
                let (parts, body) = req.into_parts();
                let body = body.map_err(Into::into).boxed_unsync();
                let req = Request::from_parts(parts, BoxBody(body));

                let res = grpc
                    .ready()
                    .await
                    .map_err(Into::into)?
                    .call(req)
                    .await
                    .map_err(Into::into)?;

                let (parts, body) = res.into_parts();
                let body = body.map_err(Into::into).boxed_unsync();
                Ok(Response::from_parts(parts, BoxBody(body)))
            })
        } else {
            let mut http = self.http.clone();
            Box::pin(async move {
                let (parts, body) = req.into_parts();
                let body = body.map_err(Into::into).boxed_unsync();
                let req = Request::from_parts(parts, BoxBody(body));

                let res = http
                    .ready()
                    .await
                    .map_err(Into::into)?
                    .call(req)
                    .await
                    .map_err(Into::into)?;

                let (parts, body) = res.into_parts();
                let body = body.map_err(Into::into).boxed_unsync();
                Ok(Response::from_parts(parts, BoxBody(body)))
            })
        }
    }
}

/// Boxed body type for uniform handling.
pub struct BoxBody(
    http_body_util::combinators::UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>,
);

impl Body for BoxBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.0).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.0.size_hint()
    }
}
