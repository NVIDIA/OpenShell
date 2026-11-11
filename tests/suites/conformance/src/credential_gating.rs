// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential gating: which endpoints a provider credential may reach, and
//! what the supervisor forwards upstream in REST bodies and WebSocket frames.
//!
//! Ported from the e2e tests added in NVIDIA/OpenShell#5264. The upstream
//! servers run on the test host ([`host_server_support`]), so the suite
//! requires sandboxes to reach the test host as `host.openshell.internal`.

use std::time::Duration;

use host_server_support::{HttpRecorder, Request, WebSocketRecorder};
use testkit::policy::{self, Access, Endpoint as _};
use testkit::sdk::raw::proto;
use testkit::{
    Context, Error, GrpcCode, PYTHON_BINARIES, Poll, Result, ResultExt as _, Sandbox, YamlFile,
};

const TEST_HOST: &str = "host.openshell.internal";
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

    set_policy(cx, &sandbox, &bound)
        .await
        .context("bind the provider")?;
    wait_for_token(&sandbox, "TOKEN_PLACEHOLDER").await?;

    set_policy(cx, &sandbox, &unbound)
        .await
        .context("unbind the provider")?;
    wait_for_token(&sandbox, "TOKEN_ABSENT").await
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
    let name = cx.name("cg");
    let endpoints = endpoints.map_or_else(String::new, |(rest, websocket)| {
        format!(
            "endpoints:
  - host: {TEST_HOST}
    port: {rest}
    protocol: rest
    access: full
  - host: {TEST_HOST}
    port: {websocket}
    protocol: websocket
    access: read-write
"
        )
    });
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
        .spec(|spec| {
            spec.image = Some(testkit::python_image());
            spec.providers = providers.iter().map(ToString::to_string).collect();
        })
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
    let sandbox = sandbox_with(cx, suffix, policy, providers).create().await?;
    sandbox.wait_ready().await?;
    Ok(sandbox)
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
    testkit::poll_until(
        &format!("the provider environment to report {expected}"),
        Duration::from_secs(30),
        Duration::from_millis(500),
        async || {
            let output = sandbox.exec(["sh", "-lc", TOKEN_PRESENCE]).await?;
            Ok(if output.stdout.contains(expected) {
                Poll::Ready(())
            } else {
                Poll::Pending(format!(
                    "exit {}; stdout: {}; stderr: {}",
                    output.exit_code,
                    output.stdout.trim(),
                    output.stderr.trim()
                ))
            })
        },
    )
    .await
}

/// Replace `sandbox`'s policy with `policy` and wait until it is applied.
async fn set_policy(cx: &Context, sandbox: &Sandbox, policy: &proto::SandboxPolicy) -> Result {
    let file = YamlFile::new(&policy::to_yaml(policy)?)?;
    cx.cli([
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
    .success()
    .context("policy set")?;
    Ok(())
}
