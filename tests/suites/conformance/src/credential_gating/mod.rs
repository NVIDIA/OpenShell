// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential gating: which endpoints a provider credential may reach, and
//! what the supervisor does with the credential in REST bodies and WebSocket
//! frames.
//!
//! Ported from `e2e/rust/tests/credential_gating.rs` (NVIDIA/OpenShell#5264).
//! Each test imports its own provider profile and creates a provider under a
//! name unique to the run; cleanup deletes them after the test's sandboxes.
//! The probe servers run where the tests run, which is the host the gateway
//! runs its sandboxes on, and the sandbox clients reach them through
//! `host.openshell.internal`, so a gateway on a remote cluster can't run this
//! suite.

mod client;
mod probe;

use std::time::Duration;

use testkit::sdk::raw::proto;
use testkit::{Context, Error, Poll, Result, ResultExt as _, Sandbox};

use client::{KEY_PRESENCE_SCRIPT, binary_websocket_client_script, body_client_script};
use probe::{BinaryWebSocketProbeServer, HttpProbeServer};

const TEST_HOST: &str = "host.openshell.internal";
const TOKEN_ENV: &str = "E2E_GATING_TOKEN";
const TEST_SECRET: &str = "e2e-gating-secret-value";
const PLACEHOLDER_PREFIX: &str = "openshell:resolve:env:";

/// A provider whose profile declares the REST and WebSocket probes as its
/// endpoints keeps the credential placeholder in a REST body.
#[testkit::test]
async fn profile_rest_endpoint_keeps_body_placeholder(cx: &mut Context) -> testkit::Result {
    let server = HttpProbeServer::start().await?;
    let websocket = BinaryWebSocketProbeServer::start().await?;
    let provider = install_provider(cx, &profile(Some((server.port, websocket.port)))).await?;

    let policy = policy(
        server.port,
        &[
            "protocol: rest",
            "access: full",
            "request_body_credential_rewrite: false",
        ],
    );
    let sandbox = create_sandbox(cx, "rest", &policy, &provider).await?;
    let output = run(
        &sandbox,
        &["python3", "-c", &body_client_script(server.port)],
    )
    .await?;
    testkit::ensure!(output.contains("BODY_TEXT"), "{output}");
    expect_one_body(&server, true, false).await
}

/// A provider's WebSocket endpoint completes the handshake but doesn't
/// forward a binary frame, which the supervisor can't inspect for the
/// credential.
#[testkit::test]
async fn profile_websocket_endpoint_denies_binary_frames(cx: &mut Context) -> testkit::Result {
    let server = HttpProbeServer::start().await?;
    let websocket = BinaryWebSocketProbeServer::start().await?;
    let provider = install_provider(cx, &profile(Some((server.port, websocket.port)))).await?;

    let policy = policy(
        websocket.port,
        &["protocol: websocket", "access: read-write"],
    );
    let sandbox = create_sandbox(cx, "ws", &policy, &provider).await?;
    let script = binary_websocket_client_script(websocket.port);
    let output = run(&sandbox, &["python3", "-c", &script]).await?;
    testkit::ensure!(output.contains("BINARY_DENIED"), "{output}");
    websocket
        .wait_for_handshake()
        .await
        .context("upstream should receive the WebSocket handshake")?;
    testkit::ensure!(
        !websocket.binary_seen(),
        "credentialed WebSocket binary frame reached upstream"
    );
    Ok(())
}

/// The gateway rejects a policy that binds a provider to an L4-only
/// endpoint or to an endpoint with `tls: skip`, and accepts an L4 endpoint
/// that opts in to uninspected credentials.
#[testkit::test]
async fn policy_binding_requires_inspection_or_opt_in(cx: &mut Context) -> testkit::Result {
    let server = HttpProbeServer::start().await?;
    let provider = install_provider(cx, &profile(None)).await?;
    let binding = credential_binding(&provider);

    let l4 = policy(server.port, &[&binding]);
    let error = expect_rejected(cx, "l4", &l4, &provider).await?;
    testkit::ensure!(error.contains("credentialed endpoint"), "{error}");
    testkit::ensure!(error.contains("L4-only"), "{error}");

    let tls_skip = policy(
        server.port,
        &["protocol: rest", "access: full", "tls: skip", &binding],
    );
    let error = expect_rejected(cx, "tls", &tls_skip, &provider).await?;
    testkit::ensure!(error.contains("credentialed endpoint"), "{error}");
    testkit::ensure!(error.contains("tls:") && error.contains("skip"), "{error}");

    let opt_in = policy(
        server.port,
        &["allow_uninspected_credentials: true", &binding],
    );
    let sandbox = create_sandbox(cx, "optin", &opt_in, &provider).await?;
    let output = run(&sandbox, &["echo", "ENDPOINTLESS_OPT_IN_ACCEPTED"]).await?;
    testkit::ensure!(output.contains("ENDPOINTLESS_OPT_IN_ACCEPTED"), "{output}");
    Ok(())
}

/// A policy binding to a REST endpoint without body rewriting sends the
/// credential placeholder upstream, not the secret.
#[testkit::test]
async fn policy_binding_rest_body_keeps_placeholder_without_rewrite(
    cx: &mut Context,
) -> testkit::Result {
    let server = HttpProbeServer::start().await?;
    let provider = install_provider(cx, &profile(None)).await?;

    let policy = policy(
        server.port,
        &[
            "protocol: rest",
            "access: full",
            "request_body_credential_rewrite: false",
            &credential_binding(&provider),
        ],
    );
    let sandbox = create_sandbox(cx, "body", &policy, &provider).await?;
    let output = run(
        &sandbox,
        &["python3", "-c", &body_client_script(server.port)],
    )
    .await?;
    testkit::ensure!(output.contains("BODY_TEXT"), "{output}");
    expect_one_body(&server, true, false).await
}

/// A policy binding with `request_body_credential_rewrite: true` replaces
/// the placeholder in the REST body with the secret upstream, and the
/// secret doesn't reach the sandbox.
#[testkit::test]
async fn policy_binding_rest_body_rewrite_sends_secret_upstream(
    cx: &mut Context,
) -> testkit::Result {
    let server = HttpProbeServer::start().await?;
    let provider = install_provider(cx, &profile(None)).await?;

    let policy = policy(
        server.port,
        &[
            "protocol: rest",
            "access: full",
            "request_body_credential_rewrite: true",
            &credential_binding(&provider),
        ],
    );
    let sandbox = create_sandbox(cx, "rw", &policy, &provider).await?;
    let output = run(
        &sandbox,
        &["python3", "-c", &body_client_script(server.port)],
    )
    .await?;
    testkit::ensure!(
        output.contains("BODY_REWRITTEN"),
        "the client did not report BODY_REWRITTEN"
    );
    testkit::ensure!(
        !output.contains(TEST_SECRET),
        "the secret reached the sandbox"
    );
    testkit::ensure!(
        !output.contains(PLACEHOLDER_PREFIX),
        "the client printed the placeholder"
    );
    expect_one_body(&server, false, true).await
}

/// Binding and unbinding a provider with `policy set --wait` adds and
/// removes its environment variable in a running sandbox.
#[testkit::test]
async fn policy_binding_updates_provider_environment_live(cx: &mut Context) -> testkit::Result {
    let server = HttpProbeServer::start().await?;
    let provider = install_provider(cx, &profile(None)).await?;
    let unbound = policy(
        server.port,
        &[
            "protocol: rest",
            "access: full",
            "request_body_credential_rewrite: false",
        ],
    );
    let bound = policy(
        server.port,
        &[
            "protocol: rest",
            "access: full",
            "request_body_credential_rewrite: false",
            &credential_binding(&provider),
        ],
    );

    let sandbox = create_sandbox(cx, "live", &unbound, &provider).await?;
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

/// A provider profile with one bearer credential in `TOKEN_ENV`. With
/// `endpoints`, it declares the REST and WebSocket probe ports as its
/// endpoints; without, a policy must bind the provider explicitly.
fn profile(endpoints: Option<(u16, u16)>) -> String {
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
    format!(
        "id: PROFILE_ID
display_name: E2E Credential Gating
category: other
credentials:
  - name: token
    env_vars: [{TOKEN_ENV}]
    required: true
    auth_style: bearer
    header_name: authorization
{endpoints}binaries:
  - path: /usr/bin/python*
  - path: /usr/local/bin/python*
  - path: /sandbox/.uv/python/*/bin/python*
"
    )
}

/// A sandbox policy that lets the image's Python reach `TEST_HOST` on
/// `port`, with `endpoint` as extra fields of that endpoint.
fn policy(port: u16, endpoint: &[&str]) -> String {
    let endpoint: String = endpoint
        .iter()
        .map(|field| format!("        {field}\n"))
        .collect();
    format!(
        "version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  credential_gating:
    name: credential_gating
    endpoints:
      - host: {TEST_HOST}
        port: {port}
{endpoint}    binaries:
      - path: /usr/bin/python*
      - path: /usr/local/bin/python*
      - path: /sandbox/.uv/python/*/bin/python*
"
    )
}

/// The endpoint field that binds `provider`'s credential in a policy.
fn credential_binding(provider: &str) -> String {
    format!("credential_binding: {{provider: {provider}}}")
}

/// Import `profile` under a run-unique ID and create a provider of that type
/// with the same name, holding `TEST_SECRET`. Returns the name. Cleanup
/// deletes the provider, then the profile, after the test's sandboxes.
async fn install_provider(cx: &Context, profile: &str) -> Result<String> {
    let name = cx.name("cg");
    // Both deletes succeed for a missing resource, so register them before
    // the creates. Hooks run last registered first.
    for kind in ["profile", "provider"] {
        let cli = cx.cli_handle();
        let owned = name.clone();
        cx.on_cleanup(format!("delete {kind} {name}"), async move || {
            cli.run([kind, "delete", &owned]).await?.success()?;
            Ok(())
        });
    }

    let file = YamlFile::new(&profile.replace("PROFILE_ID", &name))?;
    cx.cli(["profile", "import", "--file", file.path()?])
        .await?
        .success()
        .context(format!("import profile {name}"))?;
    // `--credential KEY` reads the value from the CLI's environment, so the
    // secret isn't in the reported command.
    cx.cli_with_env(
        &[(TOKEN_ENV, TEST_SECRET)],
        [
            "provider",
            "create",
            "--name",
            &name,
            "--type",
            &name,
            "--credential",
            TOKEN_ENV,
        ],
    )
    .await?
    .success()
    .context(format!("create provider {name}"))?;
    Ok(name)
}

fn parse_policy(yaml: &str) -> Result<proto::SandboxPolicy> {
    openshell_policy::parse_sandbox_policy(yaml)
        .map_err(|error| Error::msg(format!("{error:?}")))
        .context("parse the test policy")
}

fn sandbox_with(
    cx: &Context,
    suffix: &str,
    policy: &str,
    provider: &str,
) -> Result<testkit::SandboxBuilder> {
    Ok(cx
        .sandbox(suffix)
        .policy(parse_policy(policy)?)
        .spec(|spec| {
            spec.image = Some(testkit::python_image());
            spec.providers = vec![provider.to_string()];
        })
        .command(["sleep", "infinity"]))
}

/// Create a long-running sandbox from the Python image with `policy` and
/// `provider`, and wait until it is Ready.
async fn create_sandbox(
    cx: &Context,
    suffix: &str,
    policy: &str,
    provider: &str,
) -> Result<Sandbox> {
    let sandbox = sandbox_with(cx, suffix, policy, provider)?.create().await?;
    sandbox.wait_ready().await?;
    Ok(sandbox)
}

/// Fail unless the gateway rejects the sandbox, and return the rejection.
async fn expect_rejected(
    cx: &Context,
    suffix: &str,
    policy: &str,
    provider: &str,
) -> Result<String> {
    match sandbox_with(cx, suffix, policy, provider)?.create().await {
        Ok(sandbox) => Err(Error::msg(format!(
            "the gateway accepted sandbox {}",
            sandbox.name()
        ))),
        Err(error) => Ok(error.to_string()),
    }
}

/// Run `command` in `sandbox`; it must exit 0. Returns stdout and stderr.
async fn run(sandbox: &Sandbox, command: &[&str]) -> Result<String> {
    let output = sandbox.exec(command.iter().copied()).await?;
    testkit::ensure!(
        output.exit_code == 0,
        "{command:?} exited with {}; stdout: {}; stderr: {}",
        output.exit_code,
        output.stdout.trim(),
        output.stderr.trim()
    );
    Ok(format!("{}{}", output.stdout, output.stderr))
}

/// Fail unless the HTTP probe saw exactly one request, with the placeholder
/// and the secret as expected.
async fn expect_one_body(server: &HttpProbeServer, placeholder: bool, secret: bool) -> Result {
    let observations = server.wait_for_observations(1).await?;
    testkit::ensure!(
        observations.len() == 1,
        "expected one request at the HTTP probe; observations: {observations:?}"
    );
    testkit::ensure!(
        observations[0].saw_placeholder == placeholder && observations[0].saw_secret == secret,
        "expected placeholder={placeholder} secret={secret} upstream; saw {:?}",
        observations[0]
    );
    Ok(())
}

/// Wait until new exec sessions report `expected` from
/// [`KEY_PRESENCE_SCRIPT`].
async fn wait_for_token(sandbox: &Sandbox, expected: &str) -> Result {
    testkit::poll_until(
        &format!("the provider environment to report {expected}"),
        Duration::from_secs(30),
        Duration::from_millis(500),
        async || {
            let output = sandbox.exec(["sh", "-lc", KEY_PRESENCE_SCRIPT]).await?;
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
async fn set_policy(cx: &Context, sandbox: &Sandbox, policy: &str) -> Result {
    let file = YamlFile::new(policy)?;
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

/// YAML in a temporary file, for CLI commands that read one. The file is
/// removed when dropped.
struct YamlFile(tempfile::NamedTempFile);

impl YamlFile {
    fn new(contents: &str) -> Result<Self> {
        let file = tempfile::Builder::new()
            .suffix(".yaml")
            .tempfile()
            .map_err(|error| Error::from_error(&error))
            .context("create a temporary YAML file")?;
        std::fs::write(file.path(), contents)
            .map_err(|error| Error::from_error(&error))
            .context(format!("write {}", file.path().display()))?;
        Ok(Self(file))
    }

    fn path(&self) -> Result<&str> {
        self.0
            .path()
            .to_str()
            .ok_or_else(|| Error::msg(format!("{} is not UTF-8", self.0.path().display())))
    }
}
