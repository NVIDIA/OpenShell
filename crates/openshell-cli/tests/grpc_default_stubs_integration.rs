// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use openshell_core::proto::{self, open_shell_client::OpenShellClient};
use openshell_server::test_support::grpc::open_shell_server::{OpenShell, OpenShellServer};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Endpoint, Server};

struct EmptyGateway;

#[tonic::async_trait]
impl OpenShell for EmptyGateway {}

#[tokio::test]
async fn production_client_gets_unimplemented_for_every_unused_rpc_shape() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, stopped) = oneshot::channel();
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(OpenShellServer::new(EmptyGateway))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = stopped.await;
            })
            .await
    });
    let channel = Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .unwrap();
    let mut client = OpenShellClient::new(channel);

    let unary = client.health(proto::HealthRequest {}).await.unwrap_err();
    let added_rpc = client
        .get_sandbox_provider_access_token(proto::GetSandboxProviderAccessTokenRequest::default())
        .await
        .unwrap_err();
    let server_stream = client
        .watch_sandbox(proto::WatchSandboxRequest::default())
        .await
        .unwrap_err();
    let client_stream = client
        .push_sandbox_logs(tokio_stream::empty::<proto::PushSandboxLogsRequest>())
        .await
        .unwrap_err();
    let bidirectional = client
        .exec_sandbox_interactive(tokio_stream::empty::<proto::ExecSandboxInput>())
        .await
        .unwrap_err();
    for status in [
        unary,
        added_rpc,
        server_stream,
        client_stream,
        bidirectional,
    ] {
        assert_eq!(status.code(), tonic::Code::Unimplemented);
    }

    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}
