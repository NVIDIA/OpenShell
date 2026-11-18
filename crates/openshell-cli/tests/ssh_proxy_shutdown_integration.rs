// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use openshell_core::proto::{TcpForwardFrame, tcp_forward_frame};
use prost::Message;
use std::convert::Infallible;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

async fn proxy_exits_with_stdin_open(relay_status: tonic::Status) {
    let expected_code = relay_status.code();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
            let status = relay_status.clone();
            async move {
                assert_eq!(request.uri().path(), "/openshell.v1.OpenShell/ForwardTcp");
                let body = StreamBody::new(futures::stream::once(async move {
                    // Wait until stdin actually traverses the proxy. After this
                    // chunk its reader blocks again, with the parent pipe open.
                    let mut inbound = request.into_body();
                    let mut pending = Vec::new();
                    'input: while let Some(frame) = inbound.frame().await {
                        if let Ok(data) = frame.unwrap().into_data() {
                            pending.extend_from_slice(&data);
                            while pending.len() >= 5 {
                                let length =
                                    u32::from_be_bytes(pending[1..5].try_into().unwrap()) as usize;
                                if pending.len() < 5 + length {
                                    break;
                                }
                                let frame =
                                    TcpForwardFrame::decode(&pending[5..5 + length]).unwrap();
                                pending.drain(..5 + length);
                                if matches!(frame.payload, Some(tcp_forward_frame::Payload::Data(data)) if data == b"probe")
                                {
                                    break 'input;
                                }
                            }
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let trailers = status.into_http::<()>().into_parts().0.headers;
                    Ok::<Frame<Bytes>, Infallible>(Frame::trailers(trailers))
                }));
                let mut response = hyper::Response::new(body);
                response
                    .headers_mut()
                    .insert("content-type", "application/grpc".parse().unwrap());
                Ok::<_, Infallible>(response)
            }
        });
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(socket), service)
            .await;
    });
    let config = tempfile::tempdir().unwrap();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_openshell"))
        .args([
            "ssh-proxy",
            "--gateway",
            &format!("http://{address}/proxy/connect"),
            "--sandbox",
            "repro",
            "--token",
            "test-token",
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
    server.abort();
}

#[tokio::test]
async fn proxy_exits_after_relay_error_with_stdin_open() {
    proxy_exits_with_stdin_open(tonic::Status::deadline_exceeded("relay open timed out")).await;
}

#[tokio::test]
async fn proxy_exits_after_clean_relay_close_with_stdin_open() {
    proxy_exits_with_stdin_open(tonic::Status::ok("")).await;
}
