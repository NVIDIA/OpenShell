// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use tokio_stream::StreamExt as _;

/// Stalled streams hold received data unread, as the boundary does when a
/// workload stops reading a relayed download. Other streams echo one chunk.
#[derive(Clone)]
struct StallingPeer {
    stalled: Arc<std::sync::Mutex<Vec<tonic::Streaming<ExchangeFrame>>>>,
}

#[tonic::async_trait]
impl SandboxProtocol for StallingPeer {
    type ExchangeStream = TestGrpcStream;
    type MediateStream = TestGrpcStream<MediateFrame>;

    async fn exchange(
        &self,
        request: tonic::Request<tonic::Streaming<ExchangeFrame>>,
    ) -> Result<tonic::Response<Self::ExchangeStream>, tonic::Status> {
        let stall = request.metadata().get("x-stall").is_some();
        let mut inbound = request.into_inner();
        test_bind(&mut inbound).await;
        let (outbound, receiver) = tokio::sync::mpsc::channel(1);
        if stall {
            self.stalled.lock().unwrap().push(inbound);
        } else {
            tokio::spawn(async move {
                if let Ok(Some(chunk)) = inbound.message().await {
                    let request = chunk_data(chunk).unwrap();
                    let request: RequestEnvelope = decode_frame(&request).unwrap();
                    let response = ResponseEnvelope {
                        request_id: request.request_id,
                        response: Response::Exited {
                            status: ExitStatusWire::Exited(23),
                        },
                    };
                    let _ = outbound
                        .send(Ok(
                            crate::isolation_protocol::response_chunk(&response).unwrap()
                        ))
                        .await;
                }
            });
        }
        Ok(tonic::Response::new(Box::pin(ReceiverStream::new(
            receiver,
        ))))
    }

    async fn mediate(
        &self,
        _request: tonic::Request<tonic::Streaming<MediateFrame>>,
    ) -> Result<tonic::Response<Self::MediateStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("flow-control fixture"))
    }
}

/// Mirror the boundary server's HTTP/2 settings.
async fn start_boundary(peer: StallingPeer) -> tonic::transport::Channel {
    let certificate = test_certificate();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = certificate.server_config.clone();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(config)
            .accept(socket)
            .await
            .unwrap();
        let incoming = tokio_stream::iter([Ok::<_, std::io::Error>(TestTlsIo(Box::new(tls)))])
            .chain(tokio_stream::pending());
        tonic::transport::Server::builder()
            .max_concurrent_streams(crate::boundary_protocol::BOUNDARY_MAX_CONCURRENT_STREAMS)
            .initial_stream_window_size(crate::boundary_protocol::BOUNDARY_STREAM_WINDOW_BYTES)
            .initial_connection_window_size(
                crate::boundary_protocol::BOUNDARY_CONNECTION_WINDOW_BYTES,
            )
            .add_service(IsolationBackendServer::new(TestIsolationBackend::default()))
            .add_service(SandboxProtocolServer::new(peer))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    let client = BoundaryClient::new(
        tls_runtime_descriptor(address, certificate.client_tls),
        test_bearer(&"a".repeat(32)),
    );
    client
        .build_grpc_channel(&BoundaryCredential::capture(&client.sandbox_bearer).unwrap())
        .await
        .unwrap()
        .0
}

/// Push into one stalled stream until the peer stops granting credit.
async fn saturate(channel: tonic::transport::Channel) -> tokio::sync::mpsc::Sender<ExchangeFrame> {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    sender
        .send(exchange_frame(TEST_BOUNDARY_HANDLE))
        .await
        .unwrap();
    let mut request = tonic::Request::new(ReceiverStream::new(receiver));
    request
        .metadata_mut()
        .insert("x-stall", "1".parse().unwrap());
    let mut client = SandboxProtocolClient::new(channel);
    tokio::spawn(async move {
        let _response = client.exchange(request).await;
        std::future::pending::<()>().await;
    });
    let chunk = vec![0_u8; 32 * 1024];
    while tokio::time::timeout(
        Duration::from_millis(300),
        sender.send(data_chunk(chunk.clone())),
    )
    .await
    .is_ok()
    {}
    sender
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_relays_cannot_starve_other_streams() {
    let channel = start_boundary(StallingPeer {
        stalled: Arc::default(),
    })
    .await;
    let mut saturating = tokio::task::JoinSet::new();
    for _ in 0..MAX_NETWORK_STREAMS {
        saturating.spawn(saturate(channel.clone()));
    }
    let mut stalled = Vec::new();
    while let Some(sender) = saturating.join_next().await {
        stalled.push(sender.unwrap());
    }

    let auth: tonic::metadata::AsciiMetadataValue = "Bearer test".parse().unwrap();
    let exchange = async {
        let mut stream = open_grpc_client_stream_with_authorization(
            channel,
            GrpcStreamKind::Exchange,
            auth,
            TEST_BOUNDARY_HANDLE,
        )
        .await
        .unwrap();
        let request = RequestEnvelope::new(Request::Wait {
            process_id: "main".into(),
        })
        .unwrap();
        stream
            .write_all(&encode_frame(&request).unwrap())
            .await
            .unwrap();
        crate::boundary_protocol::read_frame_async::<_, ResponseEnvelope>(&mut stream)
            .await
            .unwrap()
            .response
    };
    let pong = tokio::time::timeout(Duration::from_secs(3), exchange)
        .await
        .expect("stalled relay streams must not exhaust connection-level credit");
    assert!(matches!(
        pong,
        Response::Exited {
            status: ExitStatusWire::Exited(23)
        }
    ));
    drop(stalled);
}
