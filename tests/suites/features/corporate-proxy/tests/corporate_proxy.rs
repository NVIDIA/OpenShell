// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox egress through a corporate proxy that the gateway's driver is
//! configured with.
//!
//! The environment runs one proxy (see `corporate-proxy-support`). It serves
//! TLS, requires Basic auth and intercepts the TLS in every tunnel, re-signing
//! it with its own CA, and logs each CONNECT. The gateway's `no_proxy` sends
//! one destination port, the bypass port, direct.
//!
//! The upstreams are TLS servers on the test host with certificates from a
//! [`TestCa`] that nothing trusts, so only the proxy's re-signed certificate
//! can satisfy a client that verifies.
//!
//! Ported from `e2e/rust/tests/docker_corporate_proxy.rs` and
//! `podman_corporate_proxy.rs`, which started their own proxy per test and
//! rewrote the gateway's configuration.

use std::time::Duration;

use container_engine_support::Engine;
use corporate_proxy_support::{Auth, Connect, CorporateProxy, Outcome};
use host_server_support::{HttpRecorder, Identity, TEST_HOST, TestCa};
use testkit::policy::{self, Endpoint as _};
use testkit::sdk::raw::proto;
use testkit::{Context, PYTHON_BINARIES, Poll, ResultExt as _, Sandbox};

/// Requests `https://<argv[2]>:<port>/` for each `<name>:<port>:<attempts>`
/// after `argv[2]` and prints one JSON object of results by name. With
/// `argv[1]` `verify`, the client verifies the server against the image's
/// trust store, which the driver adds the proxy's CA to; with `insecure`, it
/// doesn't verify. A failed request is retried, since a policy reload while
/// the sandbox starts can deny it once.
const CLIENT: &str = r#"
import json, ssl, sys, time, urllib.request

mode, host = sys.argv[1], sys.argv[2]
if mode == "verify":
    context = ssl.create_default_context()
else:
    context = ssl._create_unverified_context()

def fetch(port, attempts):
    result = {"status": -1, "error": "not attempted"}
    for attempt in range(attempts):
        if attempt:
            time.sleep(1)
        try:
            url = f"https://{host}:{port}/"
            with urllib.request.urlopen(url, timeout=30, context=context) as response:
                return {"status": response.status, "body": response.read().decode()}
        except Exception as error:
            result = {"status": -1, "error": f"{type(error).__name__}: {error}"}
    return result

results = {}
for spec in sys.argv[3:]:
    name, port, attempts = spec.split(":")
    results[name] = fetch(int(port), int(attempts))
print(json.dumps(results))
"#;

/// The address ranges a sandbox may reach `host.openshell.internal` at,
/// across drivers.
const HOST_RANGES: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"];

/// How long the driver may take to remove a deleted sandbox's secret.
const SECRET_REMOVAL_TIMEOUT: Duration = Duration::from_mins(1);

/// A policy-approved request goes through the proxy with its credentials and
/// a validated IP as the CONNECT target. A denied one never reaches the
/// proxy, and one to the bypass port is dialed direct. On Podman, the
/// credentials reach the supervisor in a per-sandbox secret that deleting
/// the sandbox removes.
///
/// The workload's tunnels skip the supervisor's TLS inspection and don't
/// verify the server, so the proxy's interception doesn't matter here.
#[testkit::test]
async fn approved_egress_uses_authenticated_proxy(cx: &mut Context) -> testkit::Result {
    let proxy = CorporateProxy::from_env()?;
    let identity = TestCa::new()?.leaf(&[TEST_HOST])?;
    let allowed = upstream(&identity, format!("allowed-{}", cx.run_id()), None).await?;
    let denied = upstream(&identity, format!("denied-{}", cx.run_id()), None).await?;
    let bypass = upstream(
        &identity,
        format!("bypass-{}", cx.run_id()),
        Some(proxy.bypass_port()),
    )
    .await?;

    let mut policy = policy::base();
    for port in [allowed.port, bypass.port] {
        allow(&mut policy, port).tls_skip();
    }
    let cursor = proxy.log_cursor()?;
    let sandbox = python_sandbox(cx, "cpegr", policy).await?;
    let results = fetch(
        &sandbox,
        "insecure",
        &[
            ("allowed", allowed.port, 6),
            ("bypass", bypass.port, 6),
            ("denied", denied.port, 1),
        ],
    )
    .await?;
    let connects = proxy.connects_since(&cursor)?;
    let report = log_report(&connects);

    expect_body(&results, "allowed", &allowed, &report)?;
    let to_allowed = connects_to(&connects, allowed.port);
    testkit::ensure!(
        to_allowed
            .iter()
            .any(|connect| connect.auth == Auth::Ok && connect.host() != TEST_HOST),
        "the proxy saw no authenticated CONNECT to a validated IP on port {}:\n{report}",
        allowed.port
    );
    testkit::ensure!(
        connects.iter().all(|connect| connect.auth == Auth::Ok),
        "every CONNECT should carry the proxy's credentials:\n{report}"
    );

    expect_denied(&results, &denied, &connects, &report)?;

    expect_body(&results, "bypass", &bypass, &report)?;
    testkit::ensure!(
        connects_to(&connects, bypass.port).is_empty(),
        "the bypass port {} is in no_proxy, so its requests must not reach the proxy:\n{report}",
        bypass.port
    );

    if cx.compute_driver().await? == "podman" {
        expect_secret_removed_with(&sandbox).await?;
    }
    Ok(())
}

/// The proxy's CA, which the driver adds to the sandbox's trust bundle, is
/// trusted both by the supervisor when it inspects TLS and by the workload
/// when its TLS goes through the tunnel unchanged.
#[testkit::test]
async fn intercepting_proxy_ca_is_trusted_by_supervisor_and_workload(
    cx: &mut Context,
) -> testkit::Result {
    let proxy = CorporateProxy::from_env()?;
    let identity = TestCa::new()?.leaf(&[TEST_HOST])?;
    let inspected = upstream(&identity, format!("inspected-{}", cx.run_id()), None).await?;
    let raw = upstream(&identity, format!("raw-{}", cx.run_id()), None).await?;
    let denied = upstream(&identity, format!("denied-{}", cx.run_id()), None).await?;

    let mut policy = policy::base();
    allow(&mut policy, inspected.port);
    allow(&mut policy, raw.port).tls_skip();
    let cursor = proxy.log_cursor()?;
    let sandbox = python_sandbox(cx, "cpca", policy).await?;
    let results = fetch(
        &sandbox,
        "verify",
        &[
            ("inspected", inspected.port, 6),
            ("raw", raw.port, 6),
            ("denied", denied.port, 1),
        ],
    )
    .await?;
    let connects = proxy.connects_since(&cursor)?;
    let report = log_report(&connects);

    expect_body(&results, "inspected", &inspected, &report)
        .context("the supervisor should trust the proxy's re-signed certificate")?;
    expect_body(&results, "raw", &raw, &report)
        .context("the workload should trust the proxy's re-signed certificate")?;
    for server in [&inspected, &raw] {
        testkit::ensure!(
            connects_to(&connects, server.port)
                .iter()
                .any(|connect| connect.result == Outcome::Intercepted),
            "the proxy intercepted no tunnel to port {}:\n{report}",
            server.port
        );
    }
    expect_denied(&results, &denied, &connects, &report)
}

/// A TLS server on the test host that answers every request with its
/// marker.
struct Upstream {
    server: HttpRecorder,
    marker: String,
    port: u16,
}

/// Start an [`Upstream`] answering with `marker`, on `port` or a random free
/// one.
async fn upstream(
    identity: &Identity,
    marker: String,
    port: Option<u16>,
) -> testkit::Result<Upstream> {
    let mut builder = HttpRecorder::builder().tls(identity);
    if let Some(port) = port {
        builder = builder.port(port);
    }
    let server = builder.start(marker.clone()).await?;
    Ok(Upstream {
        port: server.port,
        server,
        marker,
    })
}

/// Let the image's Python reach `TEST_HOST` on `port`, under a network
/// policy of its own.
fn allow(policy: &mut proto::SandboxPolicy, port: u16) -> &mut proto::NetworkEndpoint {
    let endpoint = policy::allow(
        policy,
        &format!("upstream_{port}"),
        TEST_HOST,
        port,
        PYTHON_BINARIES,
    );
    endpoint.allowed_ips = HOST_RANGES.iter().map(ToString::to_string).collect();
    endpoint
}

async fn python_sandbox(
    cx: &Context,
    suffix: &str,
    policy: proto::SandboxPolicy,
) -> testkit::Result<Sandbox> {
    cx.sandbox(suffix)
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(policy)
        .create_ready()
        .await
}

/// Run [`CLIENT`] in `sandbox` for each `(name, port, attempts)`.
async fn fetch(
    sandbox: &Sandbox,
    mode: &str,
    targets: &[(&str, u16, u32)],
) -> testkit::Result<serde_json::Value> {
    let mut args = vec![mode.to_string(), TEST_HOST.to_string()];
    args.extend(
        targets
            .iter()
            .map(|(name, port, attempts)| format!("{name}:{port}:{attempts}")),
    );
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    sandbox.run_python(CLIENT, &args).await?.last_json()
}

fn connects_to(connects: &[Connect], port: u16) -> Vec<&Connect> {
    connects
        .iter()
        .filter(|connect| connect.port() == Some(port))
        .collect()
}

fn log_report(connects: &[Connect]) -> String {
    if connects.is_empty() {
        return "the proxy logged no CONNECT".to_string();
    }
    let lines: Vec<String> = connects.iter().map(ToString::to_string).collect();
    format!("the proxy logged:\n{}", lines.join("\n"))
}

/// Fail unless the request `name` got `upstream`'s response.
fn expect_body(
    results: &serde_json::Value,
    name: &str,
    upstream: &Upstream,
    report: &str,
) -> testkit::Result {
    let result = &results[name];
    testkit::ensure!(
        result["status"] == 200 && result["body"].as_str() == Some(upstream.marker.as_str()),
        "the {name} request to port {} failed: {result}\n{report}",
        upstream.port
    );
    Ok(())
}

/// The policy denied the request to `denied`, so it neither reached the
/// proxy nor the server.
fn expect_denied(
    results: &serde_json::Value,
    denied: &Upstream,
    connects: &[Connect],
    report: &str,
) -> testkit::Result {
    testkit::ensure!(
        results["denied"]["status"] != 200 && denied.server.requests().is_empty(),
        "the policy-denied request to port {} reached the server: {}",
        denied.port,
        results["denied"]
    );
    testkit::ensure!(
        connects_to(connects, denied.port).is_empty(),
        "the policy-denied port {} must not reach the proxy:\n{report}",
        denied.port
    );
    Ok(())
}

/// Podman's driver gives the supervisor the proxy credentials in a
/// per-sandbox secret: it exists while the sandbox runs, and deleting the
/// sandbox removes it.
async fn expect_secret_removed_with(sandbox: &Sandbox) -> testkit::Result {
    let engine = Engine::from_env()?;
    let secret = format!("openshell-proxy-auth-{}", sandbox.id());
    testkit::ensure!(
        engine.secret_exists(&secret).await?,
        "Podman secret {secret} should hold the running sandbox's proxy credentials"
    );
    sandbox.delete().await?;
    testkit::poll_until(
        &format!("removal of Podman secret {secret}"),
        SECRET_REMOVAL_TIMEOUT,
        Duration::from_secs(1),
        async || {
            Ok(if engine.secret_exists(&secret).await? {
                Poll::Pending(format!("{secret} still exists"))
            } else {
                Poll::Ready(())
            })
        },
    )
    .await
}
