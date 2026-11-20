// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use futures::StreamExt;
use openshell_core::proto::{self, TcpForwardFrame, tcp_forward_frame};
use openshell_server::test_support::grpc::open_shell_server::{OpenShell, OpenShellServer};
use std::process::Stdio;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

const TOKEN: &str = "test-ssh-session";

struct Gateway {
    relay_status: Status,
    port: u16,
    revoked: Arc<AtomicBool>,
}

#[tonic::async_trait]
impl OpenShell for Gateway {
    async fn create_ssh_session(
        &self,
        _: Request<proto::CreateSshSessionRequest>,
    ) -> Result<Response<proto::CreateSshSessionResponse>, Status> {
        Ok(Response::new(proto::CreateSshSessionResponse {
            sandbox_id: "id-repro".into(),
            token: TOKEN.into(),
            gateway_host: "127.0.0.1".into(),
            gateway_port: self.port.into(),
            gateway_scheme: "http".into(),
            ..proto::CreateSshSessionResponse::default()
        }))
    }

    async fn forward_tcp(
        &self,
        req: Request<tonic::Streaming<TcpForwardFrame>>,
    ) -> Result<Response<tonic::codegen::BoxStream<TcpForwardFrame>>, Status> {
        let mut inbound = req.into_inner();
        let init = inbound.message().await?.and_then(|f| f.payload);
        assert!(
            matches!(init, Some(tcp_forward_frame::Payload::Init(i)) if i.authorization_token == TOKEN)
        );
        let status = self.relay_status.clone();
        let stream = futures::stream::once(async move {
            // Leave stdin open after one chunk traverses the proxy.
            let frame = inbound.message().await.unwrap().unwrap();
            assert!(matches!(frame.payload, Some(tcp_forward_frame::Payload::Data(data)) if data == b"probe"));
            (status.code() != tonic::Code::Ok).then_some(Err(status))
        }).filter_map(futures::future::ready);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn revoke_ssh_session(
        &self,
        req: Request<proto::RevokeSshSessionRequest>,
    ) -> Result<Response<proto::RevokeSshSessionResponse>, Status> {
        let req = req.into_inner();
        assert!(req.token == TOKEN, "unexpected token in revocation");
        assert!(req.allow_missing);
        self.revoked.store(true, Ordering::SeqCst);
        Ok(Response::new(proto::RevokeSshSessionResponse::default()))
    }
}

async fn proxy_exits_with_stdin_open(relay_status: Status) {
    let expected_code = relay_status.code();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let revoked = Arc::new(AtomicBool::new(false));
    let gateway = Gateway {
        relay_status,
        port: address.port(),
        revoked: revoked.clone(),
    };
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(OpenShellServer::new(gateway))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let config = tempfile::tempdir().unwrap();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_openshell"))
        .args([
            "ssh-proxy",
            "--server",
            &format!("http://{address}"),
            "--sandbox",
            "repro",
        ])
        .env("XDG_CONFIG_HOME", config.path())
        .env("OPENSHELL_TELEMETRY_ENABLED", "false")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"probe")
        .await
        .unwrap();
    // Keep child.stdin alive throughout wait: closing it would conceal the bug.
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("SSH proxy must exit even while the parent holds stdin open")
        .unwrap();
    let mut stderr = String::new();
    tokio::io::AsyncReadExt::read_to_string(child.stderr.as_mut().unwrap(), &mut stderr)
        .await
        .unwrap();
    if expected_code == tonic::Code::Ok {
        assert!(status.success(), "{stderr}");
    } else {
        assert!(!status.success(), "relay failure must propagate to SSH");
        assert!(stderr.contains("Deadline expired"), "{stderr}");
    }
    assert!(revoked.load(Ordering::SeqCst));
    server.abort();
}

#[tokio::test]
async fn proxy_exits_after_relay_error_with_stdin_open() {
    proxy_exits_with_stdin_open(Status::deadline_exceeded("relay open timed out")).await;
}

#[tokio::test]
async fn proxy_exits_after_clean_relay_close_with_stdin_open() {
    proxy_exits_with_stdin_open(Status::ok("")).await;
}
