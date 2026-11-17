// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::net::{connect_tcp_nodelay_best_effort, set_tcp_nodelay_best_effort};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;

async fn respond_json(stream: &mut TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(response.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
}

#[tokio::test]
async fn subtree_path_credential_sends_while_the_same_client_long_polls() {
    openshell_crypto::tls::ensure_default_provider();
    // Without subtree matching, getUpdates is rejected before reaching upstream.
    // Serializing requests by credential would instead block sendMessage until
    // the poll is released, and fail the bounded send below.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        const MESSAGE_BODY: &str = r#"{"chat_id":42,"text":"hello"}"#;
        const SEND_RESPONSE: &str = r#"{"ok":true,"result":{"message_id":1}}"#;
        const POLL_RESPONSE: &str = r#"{"ok":true,"result":[]}"#;

        let (child_env, resolver) = placed_test_resolver(
            HashMap::from([("TELEGRAM_TOKEN".into(), "123456:synthetic".into())]),
            "api.telegram.org",
            &[("TELEGRAM_TOKEN", "path", "/bot{credential}/**")],
        );
        let resolver = Arc::new(resolver.unwrap());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let (poll_started_tx, poll_started_rx) = oneshot::channel();
        let (release_poll_tx, release_poll_rx) = oneshot::channel();

        // Only the external Bot API is simulated; request parsing, placement,
        // substitution, body forwarding, and response relay use production code.
        let upstream = tokio::spawn(async move {
            let (mut poll, _) = upstream_listener.accept().await.unwrap();
            set_tcp_nodelay_best_effort(&poll);
            let request = RestProvider::default()
                .parse_request(&mut poll)
                .await
                .unwrap()
                .unwrap();
            assert!(
                String::from_utf8_lossy(&request.raw_header)
                    .starts_with("GET /bot123456:synthetic/getUpdates?timeout=30 HTTP/1.1\r\n")
            );
            poll_started_tx.send(()).unwrap();

            let (mut send, _) = upstream_listener.accept().await.unwrap();
            set_tcp_nodelay_best_effort(&send);
            let request = RestProvider::default()
                .parse_request(&mut send)
                .await
                .unwrap()
                .unwrap();
            assert!(
                String::from_utf8_lossy(&request.raw_header)
                    .starts_with("POST /bot123456:synthetic/sendMessage HTTP/1.1\r\n")
            );
            let header_end = request
                .raw_header
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4;
            let mut body = request.raw_header[header_end..].to_vec();
            let received = body.len();
            assert!(received <= MESSAGE_BODY.len());
            body.resize(MESSAGE_BODY.len(), 0);
            send.read_exact(&mut body[received..]).await.unwrap();
            assert_eq!(body, MESSAGE_BODY.as_bytes());
            respond_json(&mut send, SEND_RESPONSE).await;

            release_poll_rx.await.unwrap();
            respond_json(&mut poll, POLL_RESPONSE).await;
        });
        let proxy = tokio::spawn(async move {
            let mut requests = JoinSet::new();
            for _ in 0..2 {
                let (mut client, _) = proxy_listener.accept().await.unwrap();
                set_tcp_nodelay_best_effort(&client);
                let resolver = Arc::clone(&resolver);
                requests.spawn(async move {
                    let request = RestProvider::default()
                        .parse_request(&mut client)
                        .await
                        .unwrap()
                        .unwrap();
                    let mut upstream = connect_tcp_nodelay_best_effort(upstream_address)
                        .await
                        .unwrap();
                    relay_http_request_with_resolver(
                        &request,
                        &mut client,
                        &mut upstream,
                        Some(&resolver),
                    )
                    .await
                    .expect("relay must permit both methods with the same credential");
                });
            }
            while let Some(result) = requests.join_next().await {
                result.unwrap();
            }
        });

        let client = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .build()
            .unwrap();
        let base_url = format!("http://{proxy_address}/bot{}", child_env["TELEGRAM_TOKEN"]);
        // Client::clone shares the same client and its connection pool.
        let poll_client = client.clone();
        let poll_url = format!("{base_url}/getUpdates?timeout=30");
        let poll = tokio::spawn(async move { poll_client.get(poll_url).send().await.unwrap() });
        poll_started_rx
            .await
            .expect("upstream must receive the credential-bearing long poll");

        let sent = client
            .post(format!("{base_url}/sendMessage"))
            .header("content-type", "application/json")
            .body(MESSAGE_BODY)
            .send()
            .await
            .unwrap();
        assert_eq!(sent.status(), reqwest::StatusCode::OK);
        assert_eq!(sent.text().await.unwrap(), SEND_RESPONSE);
        assert!(
            !poll.is_finished(),
            "send must finish before the poll returns"
        );

        release_poll_tx.send(()).unwrap();
        let updates = poll.await.unwrap();
        assert_eq!(updates.status(), reqwest::StatusCode::OK);
        assert_eq!(updates.text().await.unwrap(), POLL_RESPONSE);
        upstream.await.unwrap();
        proxy.await.unwrap();
    })
    .await
    .expect("sending must finish without waiting for the pending long poll");
}
