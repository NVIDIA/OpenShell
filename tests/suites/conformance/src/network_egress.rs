// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Transparent egress: what the supervisor does with connections a workload
//! makes straight to a destination, without proxy settings. Policy reloads
//! apply to open connections, `tls: skip` relays raw bytes, middleware
//! inspects or blocks traffic, and pipelined requests are authorized one at
//! a time.
//!
//! Ported from the `proxy_egress_pipeline` e2e tests. The upstream servers
//! run on the test host ([`host_server_support`]).

use std::time::Duration;

use host_server_support::{HttpRecorder, Request, Response, TEST_HOST, TcpServer};
use sandbox_clients_support::{self as clients, http, http_raw, scripts};
use serde_json::Value;
use testkit::policy::{self, Endpoint as _};
use testkit::sdk::raw::proto;
use testkit::{Context, PYTHON_BINARIES, Result, ResultExt as _, Sandbox};

/// Files [`scripts::RELOAD_KEEP_ALIVE_CLIENT`] signals through.
const RELOAD_READY: &str = "/tmp/proxy-reload-ready";
const RELOAD_GO: &str = "/tmp/proxy-reload-go";
const RELOAD_RESULT: &str = "/tmp/proxy-reload-result";
const RELOAD_LOG: &str = "/tmp/proxy-reload-client.log";

/// The reply [`TcpServer::reply_when_idle`] gives a pipelined request, so the
/// connection stays usable for the next one.
const PIPELINE_REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// A policy reload that removes access applies to new connections and to a
/// keep-alive connection opened before it: the next request on that
/// connection isn't forwarded.
#[testkit::test]
async fn policy_reload_denies_new_and_open_connections(cx: &mut Context) -> testkit::Result {
    let server = HttpRecorder::serve(|_| Response::text("ok").keep_alive()).await?;
    let allowed = allow_server(server.port);
    let sandbox = cx
        .sandbox("reld")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(allowed.clone())
        .create_ready()
        .await?;
    policy::set(&sandbox, &allowed).await?;

    let port = server.port.to_string();
    sandbox
        .exec([
            "sh",
            "-c",
            &format!("nohup python3 -c \"$1\" {TEST_HOST} {port} >{RELOAD_LOG} 2>&1 &"),
            "reload-client",
            scripts::RELOAD_KEEP_ALIVE_CLIENT,
        ])
        .await?
        .success()
        .context("start the keep-alive client")?;
    wait_for_file(&sandbox, RELOAD_READY).await?;
    expect_statuses(&sandbox, server.port, |status| status == Some(200))
        .await
        .context("before the reload")?;

    policy::set(&sandbox, &policy::base()).await?;
    sandbox
        .exec(["touch", RELOAD_GO])
        .await?
        .success()
        .context("release the keep-alive client")?;
    let result: Value = serde_json::from_str(wait_for_file(&sandbox, RELOAD_RESULT).await?.trim())
        .context("parse the keep-alive client's result")?;
    testkit::ensure!(
        result["failed_closed"] == true,
        "the open connection forwarded a request after the reload: {result}"
    );
    expect_statuses(&sandbox, server.port, |status| status != Some(200))
        .await
        .context("after the reload")
}

/// The gateway rejects a policy update with two endpoints for one host and
/// port, one of them `tls: skip`. The sandbox keeps its policy revisions and
/// still forwards requests under the active policy.
#[testkit::test]
async fn ambiguous_policy_update_is_rejected_and_active_policy_kept(
    cx: &mut Context,
) -> testkit::Result {
    let server = HttpRecorder::serve(|_| Response::text("ok").keep_alive()).await?;
    let allowed = allow_server(server.port);
    let sandbox = cx
        .sandbox("ambig")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(allowed.clone())
        .create_ready()
        .await?;
    policy::set(&sandbox, &allowed).await?;
    expect_statuses(&sandbox, server.port, |status| status == Some(200))
        .await
        .context("before the rejected update")?;
    let revisions = sandbox.policy_revisions().await?;
    let connections = server.connections();

    let mut ambiguous = policy::base();
    policy::allow(
        &mut ambiguous,
        "terminating",
        TEST_HOST,
        server.port,
        PYTHON_BINARIES,
    );
    policy::allow(
        &mut ambiguous,
        "passthrough",
        TEST_HOST,
        server.port,
        PYTHON_BINARIES,
    )
    .tls_skip();
    let file = testkit::YamlFile::new(&policy::to_yaml(&ambiguous)?)?;
    let output = cx
        .cli([
            "policy",
            "set",
            sandbox.name(),
            "--policy",
            file.path()?,
            "--wait",
            "--timeout",
            "120",
        ])
        .await?
        .failure()?;
    testkit::ensure!(
        output.report_text().contains("ambiguity validation failed"),
        "the rejection doesn't explain the ambiguity:\n{}",
        output.report_text()
    );

    let after = sandbox.policy_revisions().await?;
    testkit::ensure!(
        after == revisions,
        "the rejected policy changed the revisions:\nbefore: {revisions}\nafter: {after}"
    );
    expect_statuses(&sandbox, server.port, |status| status == Some(200))
        .await
        .context("after the rejected update")?;
    testkit::ensure!(
        server.connections() > connections,
        "requests under the active policy didn't reach the server"
    );
    Ok(())
}

/// An endpoint with `tls: skip` relays bytes that are neither HTTP nor TLS
/// unchanged in both directions.
#[testkit::test]
async fn tls_skip_relays_opaque_bytes(cx: &mut Context) -> testkit::Result {
    let server = TcpServer::echo().await?;
    let mut policy = policy::base();
    allow(&mut policy, server.port).tls_skip();
    let sandbox = cx
        .sandbox("tlskp")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(policy)
        .create_ready()
        .await?;
    let mut payload = vec![0x00, 0xff, 0x13, 0x37, 0x80, 0x0a];
    payload.extend_from_slice(b"not-http-or-tls");
    payload.extend(0..64_u8);
    expect_echo(&sandbox, server.port, &payload).await
}

/// A redacting middleware rewrites an API key in each request body before
/// it reaches upstream.
#[testkit::test]
async fn middleware_redacts_request_bodies(cx: &mut Context) -> testkit::Result {
    let server = HttpRecorder::serve(|request: &Request| {
        Response::new(200)
            .header("Content-Type", "application/json")
            .body(request.body.clone())
    })
    .await?;
    let policy = middleware_policy(server.port, "fail_closed", "")?;
    let sandbox = cx
        .sandbox("redct")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(policy)
        .create_ready()
        .await?;
    for request in ["first", "second"] {
        let reply = http(
            &sandbox,
            TEST_HOST,
            server.port,
            &clients::Request::new("POST", "/middleware")
                .header("Content-Type", "application/json")
                .body(r#"{"api_key":"sk-1234567890abcdef"}"#),
        )
        .await?;
        let echoed: Option<Value> = reply
            .response
            .as_ref()
            .and_then(|response| serde_json::from_slice(&response.body).ok());
        testkit::ensure!(
            reply.status() == Some(200)
                && echoed.is_some_and(|body| body["api_key"] == "[REDACTED]"),
            "the {request} request reached upstream unredacted: {reply:?}"
        );
    }
    Ok(())
}

/// A `fail_closed` middleware blocks traffic it can't inspect before any
/// byte reaches upstream, and the sandbox logs why.
#[testkit::test]
async fn fail_closed_middleware_blocks_uninspectable_traffic(cx: &mut Context) -> testkit::Result {
    let server = TcpServer::echo().await?;
    let policy = middleware_policy(server.port, "fail_closed", "")?;
    let sandbox = cx
        .sandbox("fclos")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(policy)
        .create_ready()
        .await?;
    let mut payload = vec![0x00, 0xff, 0x13, 0x37];
    payload.extend_from_slice(b"not-http-or-tls");
    let reply = http_raw(&sandbox, TEST_HOST, server.port, &payload).await?;
    let denial = reply.received_text();
    testkit::ensure!(
        reply.connect.is_connected()
            && (denial.is_empty()
                || denial.contains("HTTP/1.1 403 Forbidden")
                    && denial.contains("unsupported_l7_protocol")),
        "expected the middleware to block the payload: {reply:?}"
    );
    // Give a forwarded payload time to arrive before checking it didn't.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let received = server.received();
    testkit::ensure!(
        received.is_empty(),
        "the payload reached upstream: {:?}",
        String::from_utf8_lossy(&received)
    );
    sandbox
        .logs_until("the middleware denial", |logs| {
            logs.contains("openshell.middleware.traffic_uninspectable")
                && logs.contains(
                    "Unsupported tunnel protocol cannot be inspected by required middleware",
                )
        })
        .await?;
    Ok(())
}

/// A `fail_open` middleware on a `tls: skip` endpoint lets traffic it can't
/// inspect through unchanged.
#[testkit::test]
async fn fail_open_middleware_relays_uninspectable_traffic(cx: &mut Context) -> testkit::Result {
    let server = TcpServer::echo().await?;
    let policy = middleware_policy(server.port, "fail_open", "        tls: skip\n")?;
    let sandbox = cx
        .sandbox("fopen")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(policy)
        .create_ready()
        .await?;
    let mut payload = vec![0x00, 0xff, 0x13, 0x37, 0x80];
    payload.extend_from_slice(b"middleware-bypass");
    expect_echo(&sandbox, server.port, &payload).await?;
    let received = server.received();
    testkit::ensure!(
        received == payload,
        "upstream received {:?}; expected the payload unchanged",
        String::from_utf8_lossy(&received)
    );
    Ok(())
}

/// A denied request pipelined behind an allowed one is answered with `403`
/// and never reaches upstream, not even as extra bytes after the first
/// request. The relay strips the hop-by-hop `Connection` header.
#[testkit::test]
async fn pipelined_request_is_authorized_separately(cx: &mut Context) -> testkit::Result {
    let server = TcpServer::reply_when_idle(PIPELINE_REPLY).await?;
    let sandbox = cx
        .sandbox("pipe")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(rest_policy(server.port, "GET")?)
        .create_ready()
        .await?;
    let target = format!("{TEST_HOST}:{}", server.port);
    let requests = format!(
        "GET /allowed HTTP/1.1\r\nHost: {target}\r\nConnection: keep-alive\r\n\r\n\
         POST /blocked HTTP/1.1\r\nHost: {target}\r\nContent-Length: 0\r\n\r\n"
    );
    run_pipeline(&sandbox, server.port, &requests).await?;
    let received = String::from_utf8_lossy(&server.received()).into_owned();
    testkit::ensure!(
        received.starts_with("GET /allowed HTTP/1.1\r\n")
            && !received.to_ascii_lowercase().contains("\r\nconnection:")
            && !received.contains("/blocked"),
        "expected only the allowed request upstream, without Connection; got:\n{received}"
    );
    Ok(())
}

/// A denied request pipelined behind an allowed chunked request is
/// authorized on its own: upstream sees the chunked request whole and
/// nothing after it.
#[testkit::test]
async fn chunked_pipelined_request_is_authorized_separately(cx: &mut Context) -> testkit::Result {
    let server = TcpServer::reply_when_idle(PIPELINE_REPLY).await?;
    let sandbox = cx
        .sandbox("chunk")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(rest_policy(server.port, "POST")?)
        .create_ready()
        .await?;
    let target = format!("{TEST_HOST}:{}", server.port);
    let requests = format!(
        "POST /allowed HTTP/1.1\r\nHost: {target}\r\nTransfer-Encoding: chunked\r\n\
         Connection: keep-alive\r\n\r\n0\r\n\r\n\
         DELETE /blocked HTTP/1.1\r\nHost: {target}\r\nContent-Length: 0\r\n\r\n"
    );
    run_pipeline(&sandbox, server.port, &requests).await?;
    let received = String::from_utf8_lossy(&server.received()).into_owned();
    testkit::ensure!(
        received.starts_with("POST /allowed HTTP/1.1\r\n")
            && received.ends_with("0\r\n\r\n")
            && !received.contains("/blocked"),
        "expected only the allowed chunked request upstream; got:\n{received}"
    );
    Ok(())
}

/// [`policy::base`] with the image's Python allowed to reach `TEST_HOST` on
/// `port`.
fn allow_server(port: u16) -> proto::SandboxPolicy {
    let mut policy = policy::base();
    allow(&mut policy, port);
    policy
}

fn allow(policy: &mut proto::SandboxPolicy, port: u16) -> &mut proto::NetworkEndpoint {
    policy::allow(policy, "egress", TEST_HOST, port, PYTHON_BINARIES)
}

/// An endpoint on `port` with the `openshell/regex` redacting middleware,
/// `on_error`, and the extra endpoint YAML in `endpoint_options`.
fn middleware_policy(
    port: u16,
    on_error: &str,
    endpoint_options: &str,
) -> Result<proto::SandboxPolicy> {
    policy::base_with(&format!(
        r#"network_middlewares:
  regex-redactor:
    name: Redact API tokens
    middleware: openshell/regex
    order: 10
    config:
      mode: redact
    on_error: {on_error}
    endpoints:
      include: ["{TEST_HOST}"]
      exclude: []
network_policies:
  egress:
    name: egress
    endpoints:
      - host: {TEST_HOST}
        port: {port}
{endpoint_options}    binaries: {binaries}
"#,
        binaries = policy::binaries_yaml(PYTHON_BINARIES),
    ))
}

/// A REST endpoint on `port` that allows only `method` on `/allowed`.
fn rest_policy(port: u16, method: &str) -> Result<proto::SandboxPolicy> {
    policy::base_with(&format!(
        r"network_policies:
  egress:
    name: egress
    endpoints:
      - host: {TEST_HOST}
        port: {port}
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: {method}
              path: /allowed
    binaries: {binaries}
",
        binaries = policy::binaries_yaml(PYTHON_BINARIES),
    ))
}

/// Send `requests` pipelined in one write, and fail unless the first gets
/// `200` and the second a `403` with `policy_denied`.
async fn run_pipeline(sandbox: &Sandbox, port: u16, requests: &str) -> Result {
    let reply = http_raw(sandbox, TEST_HOST, port, requests.as_bytes()).await?;
    let received = reply.received_text();
    let denial_error = received
        .split_once("HTTP/1.1 403 Forbidden\r\n")
        .and_then(|(_, denial)| denial.split_once("\r\n\r\n"))
        .and_then(|(_, body)| {
            serde_json::Deserializer::from_str(body)
                .into_iter::<Value>()
                .next()?
                .ok()
        })
        .and_then(|body| body.get("error")?.as_str().map(str::to_owned));
    testkit::ensure!(
        reply.status() == Some(200)
            && received.matches("HTTP/1.1 ").count() == 2
            && denial_error.as_deref() == Some("policy_denied"),
        "expected 200 then 403 with policy_denied; got {reply:?}"
    );
    Ok(())
}

/// Send `GET /first` and `GET /second` on new connections, and fail unless
/// `expected` accepts both statuses. A request without a response is `None`.
async fn expect_statuses(
    sandbox: &Sandbox,
    port: u16,
    expected: impl Fn(Option<u16>) -> bool,
) -> Result {
    for path in ["/first", "/second"] {
        let reply = http(sandbox, TEST_HOST, port, &clients::Request::get(path)).await?;
        testkit::ensure!(
            expected(reply.status()),
            "unexpected outcome for {path}: {reply:?}"
        );
    }
    Ok(())
}

/// Send `payload` and fail unless the same bytes come back.
async fn expect_echo(sandbox: &Sandbox, port: u16, payload: &[u8]) -> Result {
    let reply = http_raw(sandbox, TEST_HOST, port, payload).await?;
    testkit::ensure!(
        reply.received == payload,
        "the payload changed in transit: {reply:?}"
    );
    Ok(())
}

/// The contents of `path` in the sandbox, once it exists. A timeout reports
/// the keep-alive client's log.
async fn wait_for_file(sandbox: &Sandbox, path: &str) -> Result<String> {
    Ok(sandbox
        .poll_exec(
            &format!("{path} to appear"),
            Duration::from_secs(60),
            [
                "sh",
                "-c",
                &format!("cat {path} || {{ cat {RELOAD_LOG}; exit 1; }}"),
            ],
            |output| output.exit_code == 0,
        )
        .await?
        .stdout)
}
