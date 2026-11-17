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

use host_server_support::{HttpRecorder, Request, Response, TcpServer};
use serde_json::{Value, json};
use testkit::policy::{self, Endpoint as _};
use testkit::sdk::raw::proto;
use testkit::{Context, PYTHON_BINARIES, Result, ResultExt as _, Sandbox};

use crate::support::{
    TEST_HOST, expect_values, json_result, python_binaries_yaml, python_sandbox, run_python,
};

const STATUS_CLIENT: &str = include_str!("scripts/status_client.py");
const RELOAD_KEEP_ALIVE_CLIENT: &str = include_str!("scripts/reload_keep_alive_client.py");
const ECHO_CLIENT: &str = include_str!("scripts/echo_client.py");
const UNINSPECTABLE_CLIENT: &str = include_str!("scripts/uninspectable_client.py");
const REDACTION_CLIENT: &str = include_str!("scripts/redaction_client.py");
const PIPELINE_CLIENT: &str = include_str!("scripts/pipeline_client.py");

/// Files [`RELOAD_KEEP_ALIVE_CLIENT`] signals through.
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
    let sandbox = python_sandbox(cx, "reload", allowed.clone()).await?;
    policy::set(&sandbox, &allowed).await?;

    let port = server.port.to_string();
    sandbox
        .exec([
            "sh",
            "-c",
            &format!("nohup python3 -c \"$1\" {TEST_HOST} {port} >{RELOAD_LOG} 2>&1 &"),
            "reload-client",
            RELOAD_KEEP_ALIVE_CLIENT,
        ])
        .await?
        .success()
        .context("start the keep-alive client")?;
    wait_for_file(&sandbox, RELOAD_READY).await?;
    expect_statuses(&sandbox, &port, |status| status == 200)
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
    expect_statuses(&sandbox, &port, |status| status != 200)
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
    let sandbox = python_sandbox(cx, "ambig", allowed.clone()).await?;
    policy::set(&sandbox, &allowed).await?;
    let port = server.port.to_string();
    expect_statuses(&sandbox, &port, |status| status == 200)
        .await
        .context("before the rejected update")?;
    let revisions = policy_revisions(cx, &sandbox).await?;
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

    let after = policy_revisions(cx, &sandbox).await?;
    testkit::ensure!(
        after == revisions,
        "the rejected policy changed the revisions:\nbefore: {revisions}\nafter: {after}"
    );
    expect_statuses(&sandbox, &port, |status| status == 200)
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
    let sandbox = python_sandbox(cx, "tlsskip", policy).await?;
    let mut payload = vec![0x00, 0xff, 0x13, 0x37, 0x80, 0x0a];
    payload.extend_from_slice(b"not-http-or-tls");
    payload.extend(0..64_u8);
    run_python(
        &sandbox,
        ECHO_CLIENT,
        &[TEST_HOST, &server.port.to_string(), &hex(&payload)],
    )
    .await?
    .expect_stdout("ECHO_OK\n")?;
    Ok(())
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
    let sandbox = python_sandbox(cx, "redact", policy).await?;
    let output = run_python(
        &sandbox,
        REDACTION_CLIENT,
        &[TEST_HOST, &server.port.to_string()],
    )
    .await?;
    let result = json_result(&output)?;
    for request in ["first", "second"] {
        expect_values(&result[request], &[("api_key", json!("[REDACTED]"))])
            .context(format!("the {request} request"))?;
    }
    Ok(())
}

/// A `fail_closed` middleware blocks traffic it can't inspect before any
/// byte reaches upstream, and the sandbox logs why.
#[testkit::test]
async fn fail_closed_middleware_blocks_uninspectable_traffic(cx: &mut Context) -> testkit::Result {
    let server = TcpServer::echo().await?;
    let policy = middleware_policy(server.port, "fail_closed", "")?;
    let sandbox = python_sandbox(cx, "failclosed", policy).await?;
    run_python(
        &sandbox,
        UNINSPECTABLE_CLIENT,
        &[TEST_HOST, &server.port.to_string()],
    )
    .await?
    .expect_stdout("BLOCKED\n")?;
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
    let sandbox = python_sandbox(cx, "failopen", policy).await?;
    let mut payload = vec![0x00, 0xff, 0x13, 0x37, 0x80];
    payload.extend_from_slice(b"middleware-bypass");
    run_python(
        &sandbox,
        ECHO_CLIENT,
        &[TEST_HOST, &server.port.to_string(), &hex(&payload)],
    )
    .await?
    .expect_stdout("ECHO_OK\n")?;
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
    let sandbox = python_sandbox(cx, "pipeline", rest_policy(server.port, "GET")?).await?;
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
    let sandbox = python_sandbox(cx, "chunked", rest_policy(server.port, "POST")?).await?;
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
        binaries = python_binaries_yaml(),
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
        binaries = python_binaries_yaml(),
    ))
}

/// Send `requests` pipelined in one write, and fail unless the first gets
/// `200` and the second `403`.
async fn run_pipeline(sandbox: &Sandbox, port: u16, requests: &str) -> Result {
    let output = run_python(
        sandbox,
        PIPELINE_CLIENT,
        &[TEST_HOST, &port.to_string(), requests],
    )
    .await?;
    let result = json_result(&output)?;
    let statuses: Vec<&str> = result["statuses"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    testkit::ensure!(
        statuses.len() == 2
            && statuses[0].starts_with("HTTP/1.1 200")
            && statuses.contains(&"HTTP/1.1 403 Forbidden"),
        "expected 200 then 403; got {statuses:?}"
    );
    Ok(())
}

/// Run [`STATUS_CLIENT`] and fail unless both its requests got a status
/// `expected` accepts. A failed connection counts as status 0.
async fn expect_statuses(sandbox: &Sandbox, port: &str, expected: impl Fn(i64) -> bool) -> Result {
    let output = run_python(sandbox, STATUS_CLIENT, &[TEST_HOST, port]).await?;
    let result = json_result(&output)?;
    for request in ["first", "second"] {
        let status = result[request].as_i64().unwrap_or(0);
        testkit::ensure!(
            expected(status),
            "unexpected {request} request outcome: {result}"
        );
    }
    Ok(())
}

/// The sandbox's policy revisions, from `policy list --output json`.
async fn policy_revisions(cx: &Context, sandbox: &Sandbox) -> Result<Value> {
    cx.cli(["policy", "list", sandbox.name(), "--output", "json"])
        .await?
        .success()?
        .json()
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
