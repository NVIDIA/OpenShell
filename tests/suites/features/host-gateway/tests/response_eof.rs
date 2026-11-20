// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A sandbox client sees the connection close when a host server closes it
//! after an HTTP response, whatever framing the response uses.

use host_server_support::{TEST_HOST, TcpServer};
use sandbox_clients_support::{ReadEnd, http_raw};
use testkit::policy;
use testkit::{Context, PYTHON_BINARIES, ResultExt as _};

/// Responses the server sends, then closes the connection. Each ends the
/// response a different way: an HTTP/1.0 body length, `Connection: close`
/// with a body length, and `Connection: close` with a chunked body.
const RESPONSES: [&str; 3] = [
    "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nOK\n",
    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\nOK\n",
    "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nOK\n\r\n0\r\n\r\n",
];

/// The client sends a request that doesn't ask the server to close, so only
/// the server's close ends the read. A client that goes idle instead got the
/// response but not the close.
#[testkit::test]
async fn sandbox_receives_eof_after_closing_http_response(cx: &mut Context) -> testkit::Result {
    let mut servers = Vec::new();
    let mut allowed = policy::base();
    for response in RESPONSES {
        let server = TcpServer::reply_when_idle(response).await?;
        policy::allow(
            &mut allowed,
            "host_server",
            TEST_HOST,
            server.port,
            PYTHON_BINARIES,
        );
        servers.push((response, server));
    }

    let sandbox = cx
        .sandbox("eof")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(allowed)
        .create_ready()
        .await?;

    for (response, server) in &servers {
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {TEST_HOST}:{}\r\n\r\n",
            server.port
        );
        let reply = http_raw(&sandbox, TEST_HOST, server.port, request.as_bytes())
            .await
            .context(format!("request {response:?} from the host server"))?;
        testkit::ensure!(
            reply.received_text().lines().any(|line| line == "OK"),
            "the client did not get the body of {response:?}: {reply:?}"
        );
        testkit::ensure!(
            reply.read_end == Some(ReadEnd::Closed),
            "the client did not see the server close after {response:?}: {reply:?}"
        );
    }
    Ok(())
}
