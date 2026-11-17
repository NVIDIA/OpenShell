// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential gating: which endpoints a provider credential may reach, and
//! what the supervisor forwards upstream in REST bodies and WebSocket frames.
//!
//! Ported from the e2e tests added in NVIDIA/OpenShell#5264, the credential
//! test in `proxy_egress_pipeline`, and `websocket_conformance`. The upstream
//! servers run on the test host ([`host_server_support`]), so the suite
//! requires sandboxes to reach the test host as `host.openshell.internal`.

use std::time::Duration;

use host_server_support::{HttpRecorder, Request, TEXT_REPLY, WebSocketRecorder};
use testkit::policy::{self, Access, Endpoint as _};
use testkit::sdk::raw::proto;
use testkit::{Context, Error, GrpcCode, PYTHON_BINARIES, Result, ResultExt as _, Sandbox};

use crate::support::{self, TEST_HOST, python_binaries_yaml};

const CREDENTIAL_REWRITE_CLIENT: &str = include_str!("scripts/credential_rewrite_client.py");
const WEBSOCKET_TEXT_CLIENT: &str = include_str!("scripts/websocket_text_client.py");

const TOKEN_ENV: &str = "E2E_GATING_TOKEN";
const TEST_SECRET: &str = "e2e-gating-secret-value";
const PLACEHOLDER_PREFIX: &str = "openshell:resolve:env:";

/// POSTs a body containing the provider's token to `TEST_HOST` on the port
/// in `argv[1]`, directly rather than through a proxy.
const BODY_CLIENT: &str = r#"
import os, sys, urllib.request
body = ("prefix-" + os.environ["E2E_GATING_TOKEN"] + "-suffix").encode()
request = urllib.request.Request(f"http://host.openshell.internal:{sys.argv[1]}/token", data=body, headers={"Content-Type": "text/plain"})
urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=10).read()
"#;

/// Upgrades to WebSocket at `TEST_HOST` on the port in `argv[1]`, sends one
/// binary frame, and waits briefly for the connection to be closed.
const WEBSOCKET_CLIENT: &str = r#"
import base64, os, socket, sys
host, port = "host.openshell.internal", int(sys.argv[1])
with socket.create_connection((host, port), timeout=10) as sock:
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall(f"GET /ws HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            sys.exit(f"closed during the upgrade: {response!r}")
        response += chunk
    if not response.startswith(b"HTTP/1.1 101"):
        sys.exit(f"upgrade failed: {response!r}")
    payload, mask = b"binary-credential-channel", os.urandom(4)
    sock.sendall(bytes([0x82, 0x80 | len(payload)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
    sock.settimeout(3)
    try:
        sock.recv(4096)
    except (TimeoutError, ConnectionError):
        pass
"#;

/// Prints `TOKEN_ABSENT`, `TOKEN_PLACEHOLDER`, or `TOKEN_UNSAFE` for the
/// provider's environment variable, without printing its value.
const TOKEN_PRESENCE: &str = r#"if [ "${E2E_GATING_TOKEN+x}" != x ]; then
  echo TOKEN_ABSENT
else
  case "$E2E_GATING_TOKEN" in
    openshell:resolve:env:*) echo TOKEN_PLACEHOLDER ;;
    *) echo TOKEN_UNSAFE ;;
  esac
fi"#;

/// A provider whose profile declares the REST and WebSocket servers as its
/// endpoints keeps the credential placeholder in a REST body.
#[testkit::test]
async fn profile_rest_endpoint_keeps_body_placeholder(cx: &mut Context) -> testkit::Result {
    let server = HttpRecorder::start("ok").await?;
    let websocket = WebSocketRecorder::start().await?;
    let provider = install_gating_provider(cx, Some((server.port, websocket.port))).await?;

    let mut policy = policy::base();
    allow(&mut policy, server.port)
        .rest(Access::Full)
        .request_body_credential_rewrite(false);
    let sandbox = create_sandbox(cx, "rest", policy, &[&provider]).await?;
    run_python(&sandbox, BODY_CLIENT, server.port).await?;
    expect_placeholder_body(&server).await
}

/// A provider's WebSocket endpoint completes the handshake but doesn't
/// forward a binary frame, which the supervisor can't inspect for the
/// credential. The same client in a sandbox without the provider gets its
/// binary frame through, which shows the denial comes from the credential.
#[testkit::test]
async fn profile_websocket_endpoint_denies_binary_frames(cx: &mut Context) -> testkit::Result {
    let server = HttpRecorder::start("ok").await?;
    let websocket = WebSocketRecorder::start().await?;
    let provider = install_gating_provider(cx, Some((server.port, websocket.port))).await?;

    let control = WebSocketRecorder::start().await?;
    let binary_seen = send_binary_frame(cx, "wsctl", &control, &[]).await?;
    testkit::ensure!(
        binary_seen,
        "the binary frame didn't reach upstream from a sandbox without the provider"
    );

    let binary_seen = send_binary_frame(cx, "ws", &websocket, &[&provider]).await?;
    testkit::ensure!(
        !binary_seen,
        "credentialed WebSocket binary frame reached upstream"
    );
    Ok(())
}

/// The gateway rejects a policy that binds a provider to an L4-only
/// endpoint or to an endpoint with `tls: skip`, and accepts an L4 endpoint
/// that opts in to uninspected credentials.
#[testkit::test]
async fn policy_binding_requires_inspection_or_opt_in(cx: &mut Context) -> testkit::Result {
    let server = HttpRecorder::start("ok").await?;
    let provider = install_gating_provider(cx, None).await?;

    let mut l4 = policy::base();
    allow(&mut l4, server.port).credential_binding(&provider);
    // The wording checks follow the #5264 tests.
    let error = expect_rejected(cx, "l4", l4, &provider).await?;
    testkit::ensure!(error.contains("credentialed endpoint"), "{error}");
    testkit::ensure!(error.contains("L4-only"), "{error}");

    let mut tls_skip = policy::base();
    allow(&mut tls_skip, server.port)
        .rest(Access::Full)
        .tls_skip()
        .credential_binding(&provider);
    let error = expect_rejected(cx, "tls", tls_skip, &provider).await?;
    testkit::ensure!(error.contains("credentialed endpoint"), "{error}");
    testkit::ensure!(error.contains("tls:") && error.contains("skip"), "{error}");

    let mut opt_in = policy::base();
    allow(&mut opt_in, server.port)
        .allow_uninspected_credentials()
        .credential_binding(&provider);
    let sandbox = create_sandbox(cx, "optin", opt_in, &[&provider]).await?;
    sandbox.exec(["true"]).await?.success()?;
    Ok(())
}

/// A policy binding to a REST endpoint without body rewriting sends the
/// credential placeholder upstream, not the secret.
#[testkit::test]
async fn policy_binding_rest_body_keeps_placeholder_without_rewrite(
    cx: &mut Context,
) -> testkit::Result {
    let server = HttpRecorder::start("ok").await?;
    let provider = install_gating_provider(cx, None).await?;

    let mut policy = policy::base();
    allow(&mut policy, server.port)
        .rest(Access::Full)
        .request_body_credential_rewrite(false)
        .credential_binding(&provider);
    let sandbox = create_sandbox(cx, "body", policy, &[&provider]).await?;
    run_python(&sandbox, BODY_CLIENT, server.port).await?;
    expect_placeholder_body(&server).await
}

/// A policy binding with `request_body_credential_rewrite: true` replaces
/// the placeholder in the REST body with the secret upstream.
#[testkit::test]
async fn policy_binding_rest_body_rewrite_sends_secret_upstream(
    cx: &mut Context,
) -> testkit::Result {
    let server = HttpRecorder::start("ok").await?;
    let provider = install_gating_provider(cx, None).await?;

    let mut policy = policy::base();
    allow(&mut policy, server.port)
        .rest(Access::Full)
        .request_body_credential_rewrite(true)
        .credential_binding(&provider);
    let sandbox = create_sandbox(cx, "rw", policy, &[&provider]).await?;
    run_python(&sandbox, BODY_CLIENT, server.port).await?;
    let request = one_request(&server).await?;
    testkit::ensure!(
        request.body == format!("prefix-{TEST_SECRET}-suffix"),
        "expected the secret in the body upstream; got {}",
        redact(&request)
    );
    Ok(())
}

/// Binding and unbinding a provider with `policy set --wait` adds and
/// removes its environment variable in a running sandbox.
#[testkit::test]
async fn policy_binding_updates_provider_environment_live(cx: &mut Context) -> testkit::Result {
    let server = HttpRecorder::start("ok").await?;
    let provider = install_gating_provider(cx, None).await?;

    let policy_binding = |bind: bool| {
        let mut policy = policy::base();
        let endpoint = allow(&mut policy, server.port)
            .rest(Access::Full)
            .request_body_credential_rewrite(false);
        if bind {
            endpoint.credential_binding(&provider);
        }
        policy
    };
    let (unbound, bound) = (policy_binding(false), policy_binding(true));

    let sandbox = create_sandbox(cx, "live", unbound.clone(), &[&provider]).await?;
    wait_for_token(&sandbox, "TOKEN_ABSENT").await?;

    policy::set(&sandbox, &bound)
        .await
        .context("bind the provider")?;
    wait_for_token(&sandbox, "TOKEN_PLACEHOLDER").await?;

    policy::set(&sandbox, &unbound)
        .await
        .context("unbind the provider")?;
    wait_for_token(&sandbox, "TOKEN_ABSENT").await
}

/// A provider whose profile declares a REST endpoint with body rewriting
/// gets its placeholder replaced with the secret in both the
/// `Authorization` header and the body of every request, with no
/// placeholder left upstream.
#[testkit::test]
async fn profile_rest_endpoint_rewrites_header_and_body(cx: &mut Context) -> testkit::Result {
    let server = HttpRecorder::start("ok").await?;
    let sandbox = profile_endpoint_sandbox(
        cx,
        "rewrite",
        &format!(
            "{{host: {TEST_HOST}, port: {}, path: /probe, protocol: rest, access: full, \
             enforcement: enforce, request_body_credential_rewrite: true}}",
            server.port
        ),
    )
    .await?;
    support::run_python(
        &sandbox,
        CREDENTIAL_REWRITE_CLIENT,
        &[TEST_HOST, &server.port.to_string()],
    )
    .await?
    .expect_stdout("REWRITE_OK\n")?;

    let requests = server.wait_for_requests(2).await?;
    let authorization = format!("Bearer {TEST_SECRET}");
    for request in &requests {
        testkit::ensure!(
            request.header("authorization").as_deref() == Some(authorization.as_str())
                && request.body.contains(TEST_SECRET)
                && !request.head.contains(PLACEHOLDER_PREFIX)
                && !request.body.contains(PLACEHOLDER_PREFIX),
            "expected the secret in the header and body upstream; got {}",
            redact(request)
        );
    }
    Ok(())
}

/// A provider whose profile declares a WebSocket endpoint with
/// `websocket_credential_rewrite` gets its placeholder replaced with the
/// secret in a text frame.
#[testkit::test]
async fn profile_websocket_endpoint_rewrites_text_frames(cx: &mut Context) -> testkit::Result {
    let server = WebSocketRecorder::start().await?;
    let sandbox = profile_endpoint_sandbox(
        cx,
        "wstext",
        &format!(
            "{{host: {TEST_HOST}, port: {}, path: /ws, protocol: websocket, \
             enforcement: enforce, access: read-write, websocket_credential_rewrite: true}}",
            server.port
        ),
    )
    .await?;
    support::run_python(
        &sandbox,
        WEBSOCKET_TEXT_CLIENT,
        &[TEST_HOST, &server.port.to_string()],
    )
    .await?
    .expect_stdout(&format!("{TEXT_REPLY}\n"))?;

    let texts = server.texts();
    testkit::ensure!(
        texts.len() == 1
            && texts[0].contains(TEST_SECRET)
            && !texts[0].contains(PLACEHOLDER_PREFIX),
        "expected one text frame with the secret upstream; got {:?}",
        texts
            .iter()
            .map(|text| text.replace(TEST_SECRET, "<secret>"))
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// Run [`WEBSOCKET_CLIENT`] against `server` in a sandbox with `providers`,
/// and return whether its binary frame reached `server`.
async fn send_binary_frame(
    cx: &Context,
    suffix: &str,
    server: &WebSocketRecorder,
    providers: &[&str],
) -> Result<bool> {
    let mut policy = policy::base();
    allow(&mut policy, server.port).websocket(Access::ReadWrite);
    let sandbox = create_sandbox(cx, suffix, policy, providers).await?;
    run_python(&sandbox, WEBSOCKET_CLIENT, server.port).await?;
    server
        .wait_for_handshake()
        .await
        .context("upstream should receive the WebSocket handshake")?;
    server.wait_until_finished().await
}

/// Let the image's Python reach `TEST_HOST` on `port`.
fn allow(policy: &mut proto::SandboxPolicy, port: u16) -> &mut proto::NetworkEndpoint {
    policy::allow(
        policy,
        "credential_gating",
        TEST_HOST,
        port,
        PYTHON_BINARIES,
    )
}

/// Install a run-unique provider holding `TEST_SECRET` in `TOKEN_ENV`. With
/// `endpoints`, its profile declares the REST and WebSocket ports as its
/// endpoints; without, a policy must bind the provider explicitly.
async fn install_gating_provider(cx: &Context, endpoints: Option<(u16, u16)>) -> Result<String> {
    let endpoints = endpoints.map_or_else(Vec::new, |(rest, websocket)| {
        vec![
            format!("{{host: {TEST_HOST}, port: {rest}, protocol: rest, access: full}}"),
            format!(
                "{{host: {TEST_HOST}, port: {websocket}, protocol: websocket, access: read-write}}"
            ),
        ]
    });
    install_provider_with_endpoints(cx, &endpoints).await
}

/// A long-running sandbox with a provider from
/// [`install_provider_with_endpoints`] whose profile declares `endpoint`, a
/// YAML flow mapping, and a policy that allows the same endpoint.
async fn profile_endpoint_sandbox(cx: &Context, suffix: &str, endpoint: &str) -> Result<Sandbox> {
    let provider = install_provider_with_endpoints(cx, &[endpoint.to_string()]).await?;
    let policy = policy::base_with(&format!(
        "network_policies:
  credential_gating:
    name: credential_gating
    endpoints: [{endpoint}]
    binaries: {binaries}
",
        binaries = python_binaries_yaml(),
    ))?;
    create_sandbox(cx, suffix, policy, &[&provider]).await
}

/// Install a run-unique provider holding `TEST_SECRET` in `TOKEN_ENV`, whose
/// profile declares `endpoints`, each a YAML flow mapping.
async fn install_provider_with_endpoints(cx: &Context, endpoints: &[String]) -> Result<String> {
    let name = cx.name("cg");
    let endpoints = if endpoints.is_empty() {
        String::new()
    } else {
        format!("endpoints: [{}]\n", endpoints.join(", "))
    };
    let binaries: String = PYTHON_BINARIES
        .iter()
        .map(|path| format!("  - path: {path}\n"))
        .collect();
    let profile = format!(
        "id: {name}
display_name: E2E Credential Gating
category: other
credentials:
  - name: token
    env_vars: [{TOKEN_ENV}]
    required: true
    auth_style: bearer
    header_name: authorization
{endpoints}binaries:
{binaries}"
    );
    cx.install_provider(&name, &profile, &[(TOKEN_ENV, TEST_SECRET)])
        .await?;
    Ok(name)
}

fn sandbox_with(
    cx: &Context,
    suffix: &str,
    policy: proto::SandboxPolicy,
    providers: &[&str],
) -> testkit::SandboxBuilder {
    cx.sandbox(suffix)
        .policy(policy)
        .image(testkit::python_image())
        .spec(|spec| spec.providers = providers.iter().map(ToString::to_string).collect())
        .command(["sleep", "infinity"])
}

/// Create a long-running sandbox from the Python image with `policy` and
/// `providers`, and wait until it is Ready.
async fn create_sandbox(
    cx: &Context,
    suffix: &str,
    policy: proto::SandboxPolicy,
    providers: &[&str],
) -> Result<Sandbox> {
    sandbox_with(cx, suffix, policy, providers)
        .create_ready()
        .await
}

/// Fail unless the gateway rejects the sandbox as a failed precondition, and
/// return the rejection.
async fn expect_rejected(
    cx: &Context,
    suffix: &str,
    policy: proto::SandboxPolicy,
    provider: &str,
) -> Result<String> {
    match sandbox_with(cx, suffix, policy, &[provider]).create().await {
        Ok(sandbox) => Err(Error::msg(format!(
            "the gateway accepted sandbox {}",
            sandbox.name()
        ))),
        Err(error) if error.grpc_code() == Some(GrpcCode::FailedPrecondition) => {
            Ok(error.to_string())
        }
        Err(error) => Err(error.context("expected a failed precondition")),
    }
}

/// Run `script` with the image's Python and `port` as its argument.
async fn run_python(sandbox: &Sandbox, script: &str, port: u16) -> Result {
    let port = port.to_string();
    sandbox
        .exec(["python3", "-c", script, &port])
        .await?
        .success()
        .context("run the client in the sandbox")?;
    Ok(())
}

/// The one request `server` saw.
async fn one_request(server: &HttpRecorder) -> Result<Request> {
    let mut requests = server.wait_for_requests(1).await?;
    testkit::ensure!(
        requests.len() == 1,
        "expected one request upstream; got {}",
        requests.len()
    );
    Ok(requests.remove(0))
}

/// Fail unless `server` saw one request whose body has the credential
/// placeholder in place of the token, and the secret appears nowhere in it.
async fn expect_placeholder_body(server: &HttpRecorder) -> Result {
    let request = one_request(server).await?;
    testkit::ensure!(
        request
            .body
            .starts_with(&format!("prefix-{PLACEHOLDER_PREFIX}"))
            && request.body.ends_with("-suffix")
            && !request.head.contains(TEST_SECRET)
            && !request.body.contains(TEST_SECRET),
        "expected the placeholder in the body upstream and no secret; got {}",
        redact(&request)
    );
    Ok(())
}

/// `request` for a failure message, with the secret replaced.
fn redact(request: &Request) -> String {
    format!("{}\n\n{}", request.head, request.body).replace(TEST_SECRET, "<secret>")
}

/// Wait until new exec sessions report `expected` from [`TOKEN_PRESENCE`].
async fn wait_for_token(sandbox: &Sandbox, expected: &str) -> Result {
    sandbox
        .poll_exec(
            &format!("the provider environment to report {expected}"),
            Duration::from_secs(30),
            ["sh", "-lc", TOKEN_PRESENCE],
            |output| output.stdout.contains(expected),
        )
        .await?;
    Ok(())
}
