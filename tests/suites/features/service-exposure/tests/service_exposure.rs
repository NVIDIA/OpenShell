// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exposed sandbox services and the application's `Authorization` header.
//!
//! The sandbox runs a server that echoes the request's `Authorization`
//! header, and the test requests it through the gateway with
//! `cx.service_get`.

use std::time::Duration;

use testkit::{Context, Poll, ResultExt as _, poll_until};

const SERVICE_PORT: &str = "4500";
const BEARER_TOKEN: &str = "Bearer openshell-e2e-application-token";
/// How long an exposed service may take to start answering, or to apply a
/// changed authorization mode.
const SERVICE_TIMEOUT: Duration = Duration::from_mins(1);
const HEADER_ECHO_SERVER: &str = r#"
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.headers.get("Authorization", "").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass

ThreadingHTTPServer(("127.0.0.1", 4500), Handler).serve_forever()
"#;

/// An exposed service doesn't receive the client's `Authorization` header by
/// default. Exposing it again with `--authorization-mode bearer-passthrough`
/// forwards the header unchanged.
#[testkit::test]
async fn bearer_passthrough_preserves_authorization_header(cx: &mut Context) -> testkit::Result {
    let builder = cx
        .cli_sandbox("svc")
        .image(testkit::python_image())
        .args(["--expose", SERVICE_PORT, "--output", "json", "--detach"])
        .command(["python3", "-c", HEADER_ECHO_SERVER]);
    let name = builder.name().to_string();
    let created: serde_json::Value = builder
        .run()
        .await?
        .success()
        .context(format!("create sandbox {name}"))?
        .json()?;
    let sandbox = cx.adopt(&name).await?;
    let service_url = created["service_urls"][""]
        .as_str()
        .ok_or_else(|| testkit::Error::msg(format!("no unnamed service URL in {created}")))?
        .to_string();
    sandbox.wait_ready().await?;

    wait_for_authorization(cx, &service_url, "")
        .await
        .context("the default mode strips Authorization")?;

    cx.cli([
        "service",
        "expose",
        &name,
        SERVICE_PORT,
        "--authorization-mode",
        "bearer-passthrough",
    ])
    .await?
    .success()?;
    wait_for_authorization(cx, &service_url, BEARER_TOKEN)
        .await
        .context("bearer-passthrough mode preserves Authorization")
}

/// Request `service_url` with [`BEARER_TOKEN`] until the service echoes
/// `expected`. Connection errors and the gateway's statuses for a service
/// that isn't reachable yet are retried; any other answer fails.
async fn wait_for_authorization(
    cx: &Context,
    service_url: &str,
    expected: &str,
) -> testkit::Result {
    poll_until(
        &format!("{service_url} to receive Authorization {expected:?}"),
        SERVICE_TIMEOUT,
        Duration::from_millis(250),
        async || {
            let response = match cx
                .service_get(service_url, &[("authorization", BEARER_TOKEN)])
                .await
            {
                Ok(response) => response,
                Err(error) => return Ok(Poll::Pending(error.to_string())),
            };
            match response.status {
                200 if response.body == expected => Ok(Poll::Ready(())),
                200 => Err(testkit::Error::msg(format!(
                    "the service received Authorization {:?}",
                    response.body
                ))),
                // Bad gateway, precondition failed, service unavailable.
                502 | 412 | 503 => Ok(Poll::Pending(format!(
                    "status {} with body {:?}",
                    response.status, response.body
                ))),
                status => Err(testkit::Error::msg(format!(
                    "the service answered status {status} with body {:?}",
                    response.body
                ))),
            }
        },
    )
    .await
}
