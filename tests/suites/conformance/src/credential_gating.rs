// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential gating: which endpoints a provider credential may reach, and
//! what the supervisor forwards upstream in REST bodies and WebSocket frames.
//!
//! Ported from the e2e tests added in ai-openshell/openshell#5264, the credential
//! test in `proxy_egress_pipeline`, and `websocket_conformance`. The upstream
//! servers run on the test host ([`host_server_support`]), so the suite
//! requires sandboxes to reach the test host as `host.openshell.internal`.

use std::time::Duration;

use host_server_support::{
    HttpRecorder, Request, Response, TEST_HOST, TEXT_REPLY, WebSocketRecorder, allow_host,
};
use sandbox_clients_support::{self as clients, http, scripts};
use serde_json::json;
use testkit::policy::{self, Access, Endpoint as _};
use testkit::sdk::raw::proto;
use testkit::{Context, Error, GrpcCode, PYTHON_BINARIES, Result, ResultExt as _, Sandbox};

const BASH: &str = "/usr/bin/bash";

const TOKEN_ENV: &str = "E2E_GATING_TOKEN";
const TEST_SECRET: &str = "e2e-gating-secret-value";
const PLACEHOLDER_PREFIX: &str = "openshell:resolve:env:";

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
    allow_host(&mut policy, "credential_gating", server.port)
        .rest(Access::Full)
        .request_body_credential_rewrite(false);
    let sandbox = create_sandbox(cx, "rest", policy, &[&provider]).await?;
    post_token_body(&sandbox, server.port).await?;
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
    allow_host(&mut l4, "credential_gating", server.port).credential_binding(&provider);
    // The wording checks follow the #5264 tests.
    let error = expect_rejected(cx, "l4", l4, &provider).await?;
    testkit::ensure!(error.contains("credentialed endpoint"), "{error}");
    testkit::ensure!(error.contains("L4-only"), "{error}");

    let mut tls_skip = policy::base();
    allow_host(&mut tls_skip, "credential_gating", server.port)
        .rest(Access::Full)
        .tls_skip()
        .credential_binding(&provider);
    let error = expect_rejected(cx, "tls", tls_skip, &provider).await?;
    testkit::ensure!(error.contains("credentialed endpoint"), "{error}");
    testkit::ensure!(error.contains("tls:") && error.contains("skip"), "{error}");

    let mut opt_in = policy::base();
    allow_host(&mut opt_in, "credential_gating", server.port)
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
    allow_host(&mut policy, "credential_gating", server.port)
        .rest(Access::Full)
        .request_body_credential_rewrite(false)
        .credential_binding(&provider);
    let sandbox = create_sandbox(cx, "body", policy, &[&provider]).await?;
    post_token_body(&sandbox, server.port).await?;
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
    allow_host(&mut policy, "credential_gating", server.port)
        .rest(Access::Full)
        .request_body_credential_rewrite(true)
        .credential_binding(&provider);
    let sandbox = create_sandbox(cx, "rw", policy, &[&provider]).await?;
    post_token_body(&sandbox, server.port).await?;
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
        let endpoint = allow_host(&mut policy, "credential_gating", server.port)
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
        "rwrt",
        &format!(
            "{{host: {TEST_HOST}, port: {}, path: /probe, protocol: rest, access: full, \
             enforcement: enforce, request_body_credential_rewrite: true}}",
            server.port
        ),
    )
    .await?;
    let token = provider_token(&sandbox).await?;
    let body = json!({ "credential": token }).to_string();
    for _ in 0..2 {
        let reply = http(
            &sandbox,
            TEST_HOST,
            server.port,
            &clients::Request::new("POST", "/probe")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(body.clone()),
        )
        .await?;
        testkit::ensure!(
            reply.status() == Some(200),
            "expected 200; got {:?}",
            reply.status()
        );
    }

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
        "wstxt",
        &format!(
            "{{host: {TEST_HOST}, port: {}, path: /ws, protocol: websocket, \
             enforcement: enforce, access: read-write, websocket_credential_rewrite: true}}",
            server.port
        ),
    )
    .await?;
    sandbox
        .run_python(
            scripts::WEBSOCKET_TEXT_CLIENT,
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

/// A provider's credential resolves only at the endpoints its profile
/// declares: another provider's endpoint and an undeclared path on its own
/// endpoint get `403`, and the sandbox logs the mismatch without the secret
/// or its variable name.
#[testkit::test]
async fn profile_endpoints_bind_static_credentials(cx: &mut Context) -> testkit::Result {
    const SECRET_A: &str = "e2e-bound-secret";
    const SECRET_B: &str = "e2e-provider-b-secret";
    let authorized = |request: &Request| {
        let authorized = request.header("authorization").as_deref()
            == Some(format!("Bearer {SECRET_A}").as_str());
        Response::json(&json!({ "authorized": authorized }))
    };
    let server_a = HttpRecorder::serve(authorized).await?;
    let server_b = HttpRecorder::serve(authorized).await?;
    let provider_a =
        install_bound_provider(cx, "binda", "BOUND_TOKEN_A", SECRET_A, server_a.port).await?;
    let provider_b =
        install_bound_provider(cx, "bindb", "BOUND_TOKEN_B", SECRET_B, server_b.port).await?;

    let endpoint = |port| {
        format!(
            "{{host: {TEST_HOST}, port: {port}, path: /**, protocol: rest, access: full, \
             enforcement: enforce}}"
        )
    };
    let policy = policy::base_with(&format!(
        "network_policies:
  binding:
    name: binding
    endpoints: [{}, {}]
    binaries: [{{path: {BASH}}}]
",
        endpoint(server_a.port),
        endpoint(server_b.port),
    ))?;
    let sandbox = cx
        .python_sandbox("bind", policy)
        .providers([provider_a, provider_b])
        .create_ready()
        .await?;
    let output = sandbox
        .exec([
            BASH,
            "-c",
            scripts::BOUND_CREDENTIAL_CLIENT,
            "bash",
            TEST_HOST,
            &server_a.port.to_string(),
            &server_b.port.to_string(),
        ])
        .await?
        .success()?;
    testkit::ensure!(
        output.stdout.trim()
            == r#"ALLOWED={"authorized":true} ENDPOINT_DENIED=403 PATH_DENIED=403"#,
        "expected the credential only at its bound endpoint and path; got {}",
        output.stdout.replace(SECRET_A, "<secret>")
    );

    let logs = sandbox
        .logs_until("the endpoint mismatch", |logs| {
            logs.contains("openshell.provider_credential.endpoint_mismatch")
                && logs.contains("credential_endpoint_mismatch")
        })
        .await?;
    for leaked in [SECRET_A, SECRET_B, "BOUND_TOKEN_A", "BOUND_TOKEN_B"] {
        testkit::ensure!(
            !logs.contains(leaked),
            "the sandbox logs contain a credential value or variable name"
        );
    }
    Ok(())
}

/// Run [`scripts::WEBSOCKET_BINARY_CLIENT`] against `server` in a sandbox with `providers`,
/// and return whether its binary frame reached `server`.
async fn send_binary_frame(
    cx: &Context,
    suffix: &str,
    server: &WebSocketRecorder,
    providers: &[&str],
) -> Result<bool> {
    let mut policy = policy::base();
    allow_host(&mut policy, "credential_gating", server.port).websocket(Access::ReadWrite);
    let sandbox = create_sandbox(cx, suffix, policy, providers).await?;
    sandbox
        .run_python(
            scripts::WEBSOCKET_BINARY_CLIENT,
            &[TEST_HOST, &server.port.to_string()],
        )
        .await?;
    server
        .wait_for_handshake()
        .await
        .context("upstream should receive the WebSocket handshake")?;
    server.wait_until_finished().await
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
        binaries = policy::binaries_yaml(PYTHON_BINARIES),
    ))?;
    create_sandbox(cx, suffix, policy, &[&provider]).await
}

/// Install a provider named `cx.name(suffix)` holding `secret` in `env_var`,
/// whose profile binds it to `/allowed/**` on `TEST_HOST` at `port` for
/// [`BASH`].
async fn install_bound_provider(
    cx: &Context,
    suffix: &str,
    env_var: &str,
    secret: &str,
    port: u16,
) -> Result<String> {
    let name = cx.name(suffix);
    let profile = format!(
        "id: {name}
display_name: E2E static endpoint binding
category: other
credentials:
  - name: bound_token
    env_vars: [{env_var}]
    required: true
    auth_style: bearer
    header_name: authorization
endpoints:
  - {{host: {TEST_HOST}, port: {port}, path: /allowed/**, protocol: rest, access: full, enforcement: enforce}}
binaries: [{BASH}]
"
    );
    cx.install_provider(&name, &profile, &[(env_var, secret)])
        .await?;
    Ok(name)
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
    cx.python_sandbox(suffix, policy)
        .providers(providers.iter().copied())
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

/// The provider token's placeholder, as the sandbox's environment holds it.
async fn provider_token(sandbox: &Sandbox) -> Result<String> {
    let output = sandbox
        .exec(["printenv", TOKEN_ENV])
        .await?
        .success()
        .context("read the provider token from the sandbox environment")?;
    Ok(output.stdout.trim().to_string())
}

/// POST `prefix-<token>-suffix` to `/token` on `TEST_HOST` at `port`, and
/// fail unless it gets `200`.
async fn post_token_body(sandbox: &Sandbox, port: u16) -> Result {
    let token = provider_token(sandbox).await?;
    let reply = http(
        sandbox,
        TEST_HOST,
        port,
        &clients::Request::new("POST", "/token")
            .header("Content-Type", "text/plain")
            .body(format!("prefix-{token}-suffix")),
    )
    .await?;
    testkit::ensure!(
        reply.status() == Some(200),
        "expected 200; got {:?}",
        reply.status()
    );
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
