// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration test: WebSocket upgrade through the L7 relay.
//!
//! Spins up a dummy WebSocket echo server, connects a client through the
//! `L7Provider::relay` pipeline, validates the 101 upgrade succeeds, and
//! exchanges a WebSocket text frame bidirectionally.
//!
//! This test exercises the full upgrade path described in issue #652:
//! 1. Client sends HTTP GET with `Upgrade: websocket` headers
//! 2. Relay forwards to upstream, upstream responds with 101
//! 3. Relay detects 101, validates client Upgrade headers, returns `Upgraded`
//! 4. Caller forwards overflow + switches to `copy_bidirectional`
//! 5. Client and server exchange a WebSocket text message
//!
//! Reproduction scenario from #652: raw socket test sends upgrade request
//! through the proxy, receives 101, then verifies WebSocket frames flow.

use futures::SinkExt;
use futures::stream::StreamExt;
use openshell_sandbox::l7::provider::{BodyLength, L7Provider, L7Request, RelayOutcome};
use openshell_sandbox::l7::rest::RestProvider;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

/// Start a minimal WebSocket echo server on an ephemeral port.
async fn start_ws_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ws_stream = accept_async(stream).await.unwrap();
        let (mut write, mut read) = ws_stream.split();

        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    write
                        .send(Message::Text(format!("echo: {text}").into()))
                        .await
                        .unwrap();
                }
                Ok(Message::Close(_)) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    addr
}

/// Build raw HTTP upgrade request bytes (mimics the reproduction script from #652).
fn build_ws_upgrade_request(host: &str) -> Vec<u8> {
    format!(
        "GET / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: RylUQAh3p5cysfOlexgubw==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    )
    .into_bytes()
}

/// Build a masked WebSocket text frame (client -> server must be masked per RFC 6455).
fn build_ws_text_frame(payload: &[u8]) -> Vec<u8> {
    let mask_key: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];
    let mut frame = Vec::new();
    frame.push(0x81); // FIN + text opcode
    frame.push(0x80 | payload.len() as u8); // masked + length
    frame.extend_from_slice(&mask_key);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask_key[i % 4]);
    }
    frame
}

/// Core test: WebSocket upgrade through `L7Provider::relay`, then exchange a message.
///
/// This mirrors the reproduction steps from issue #652:
/// - Send WebSocket upgrade → receive 101 → verify frames flow bidirectionally
/// - Previously, 101 was treated as a generic 1xx and frames were dropped
#[tokio::test]
async fn websocket_upgrade_through_l7_relay_exchanges_message() {
    let ws_addr = start_ws_echo_server().await;

    // Open a real TCP connection to the WebSocket server (simulates upstream)
    let mut upstream = TcpStream::connect(ws_addr).await.unwrap();

    // In-memory duplex for the client side of the relay
    let (mut client_app, mut client_proxy) = tokio::io::duplex(8192);

    let host = format!("127.0.0.1:{}", ws_addr.port());
    let raw_header = build_ws_upgrade_request(&host);

    let req = L7Request {
        action: "GET".to_string(),
        target: "/".to_string(),
        query_params: HashMap::new(),
        raw_header,
        body_length: BodyLength::None,
    };

    // Run the relay in a background task (simulates what relay_rest does)
    let relay_handle = tokio::spawn(async move {
        let outcome = RestProvider
            .relay(&req, &mut client_proxy, &mut upstream)
            .await
            .expect("relay should succeed");

        match outcome {
            RelayOutcome::Upgraded { overflow } => {
                // This is what handle_upgrade() does in relay.rs
                if !overflow.is_empty() {
                    client_proxy.write_all(&overflow).await.unwrap();
                    client_proxy.flush().await.unwrap();
                }
                let _ = tokio::io::copy_bidirectional(&mut client_proxy, &mut upstream).await;
            }
            other => panic!("Expected Upgraded, got {other:?}"),
        }
    });

    // Client side: read the 101 response headers byte-by-byte
    // (mirrors the reproduction script's recv() after sending the upgrade)
    let mut response_buf = Vec::new();
    let mut tmp = [0u8; 1];
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            client_app.read_exact(&mut tmp).await.unwrap();
            response_buf.push(tmp[0]);
            if response_buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
    })
    .await
    .expect("should receive 101 headers within 5 seconds");

    let response_str = String::from_utf8_lossy(&response_buf);
    assert!(
        response_str.contains("101 Switching Protocols"),
        "should receive 101, got: {response_str}"
    );

    // ---- This is the part that was broken before the fix (issue #652) ----
    // Previously, after 101, the relay re-entered the HTTP parsing loop and
    // all WebSocket frames were silently dropped. The reproduction script
    // would see RECV2: TIMEOUT here.

    // Send a WebSocket text frame
    let frame = build_ws_text_frame(b"hello");
    client_app.write_all(&frame).await.unwrap();
    client_app.flush().await.unwrap();

    // Read the echo response (unmasked server -> client frame)
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut header = [0u8; 2];
        client_app.read_exact(&mut header).await.unwrap();

        let fin_opcode = header[0];
        assert_eq!(fin_opcode & 0x0F, 1, "should be text frame");
        assert!(fin_opcode & 0x80 != 0, "FIN bit should be set");

        let len = (header[1] & 0x7F) as usize;
        let mut payload_buf = vec![0u8; len];
        client_app.read_exact(&mut payload_buf).await.unwrap();
        let text = String::from_utf8(payload_buf).unwrap();
        assert_eq!(
            text, "echo: hello",
            "server should echo our message back through the relay"
        );
    })
    .await
    .expect("should receive WebSocket echo within 5 seconds (previously timed out per #652)");

    // Clean shutdown
    let close_frame = [0x88, 0x82, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8];
    let _ = client_app.write_all(&close_frame).await;
    drop(client_app);

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), relay_handle).await;
}

/// Test that a normal (non-upgrade) HTTP request still works correctly
/// after the relay_response changes. Ensures the 101 detection doesn't
/// break regular HTTP traffic.
#[tokio::test]
async fn normal_http_request_still_works_after_relay_changes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Simple HTTP echo server
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let mut total = 0;
        loop {
            let n = stream.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        stream.flush().await.unwrap();
    });

    let mut upstream = TcpStream::connect(addr).await.unwrap();
    let (mut client_read, mut client_proxy) = tokio::io::duplex(8192);

    let raw_header = format!(
        "GET /api HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        addr.port()
    )
    .into_bytes();

    let req = L7Request {
        action: "GET".to_string(),
        target: "/api".to_string(),
        query_params: HashMap::new(),
        raw_header,
        body_length: BodyLength::None,
    };

    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        RestProvider.relay(&req, &mut client_proxy, &mut upstream),
    )
    .await
    .expect("should not deadlock")
    .expect("relay should succeed");

    assert!(
        matches!(outcome, RelayOutcome::Reusable),
        "normal 200 response should be Reusable, got {outcome:?}"
    );

    client_proxy.shutdown().await.unwrap();
    let mut received = Vec::new();
    client_read.read_to_end(&mut received).await.unwrap();
    let body = String::from_utf8_lossy(&received);
    assert!(body.contains("200 OK"), "should forward 200 response");
    assert!(body.contains("ok"), "should forward response body");
}
