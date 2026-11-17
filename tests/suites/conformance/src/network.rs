// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox networking: direct connections the sandbox refuses, loopback
//! traffic it leaves alone, and listening sockets whose lifetime it must not
//! extend.
//!
//! Ported from the `bypass_detection`, `listener_lifetime`, and `no_proxy`
//! e2e tests, and the destination denials in `proxy_egress_pipeline`.

use std::time::Duration;

use serde_json::json;
use testkit::{Context, ResultExt as _, policy};

use crate::support::{
    expect_values, json_result, python_binaries_yaml, python_sandbox, run_python,
};

const BYPASS_CLIENT: &str = include_str!("scripts/bypass_client.py");
const DESTINATION_DENIALS_CLIENT: &str = include_str!("scripts/destination_denials_client.py");
const LOCALHOST_CLIENT: &str = include_str!("scripts/localhost_client.py");
const LISTENER_LIFETIME_PROBE: &str = include_str!("scripts/listener_lifetime_probe.py");
const PRECONNECT_OWNER: &str = include_str!("scripts/preconnect_owner.py");
const SOCKET_NOT_INHERITED: &str = include_str!("scripts/socket_not_inherited.py");

/// A direct TCP connection that bypasses the proxy is denied with a
/// permission error well before the socket's 10-second timeout.
#[testkit::test]
async fn direct_connect_bypass_is_denied_promptly(cx: &mut Context) -> testkit::Result {
    let sandbox = python_sandbox(cx, "bypass", policy::base()).await?;
    let output = run_python(&sandbox, BYPASS_CLIENT, &[]).await?;
    let result = json_result(&output)?;
    testkit::ensure!(
        result["bypass_result"] == "denied",
        "expected the direct connect to be denied; got {result}"
    );
    let elapsed = result["elapsed_ms"].as_u64().unwrap_or(u64::MAX);
    testkit::ensure!(
        elapsed < 8000,
        "the denial took {elapsed} ms; expected under 8000"
    );
    Ok(())
}

/// Connections to cloud metadata, a Kubernetes API port, and an address
/// outside an endpoint's `allowed_ips` fail with `EACCES` even though the
/// policy names them.
#[testkit::test]
async fn reserved_destinations_fail_with_eacces_even_when_allowed(
    cx: &mut Context,
) -> testkit::Result {
    let policy = policy::base_with(&format!(
        r#"network_policies:
  destination_denials:
    name: destination_denials
    endpoints:
      - {{ host: 169.254.169.254, port: 80 }}
      - {{ host: 127.0.0.1, port: 80 }}
      - {{ host: 203.0.113.10, port: 6443 }}
      - host: 203.0.113.10
        port: 8080
        allowed_ips: ["198.51.100.0/24"]
    binaries: {binaries}
"#,
        binaries = python_binaries_yaml(),
    ))?;
    let sandbox = python_sandbox(cx, "denials", policy).await?;
    let output = run_python(&sandbox, DESTINATION_DENIALS_CLIENT, &[]).await?;
    expect_values(
        &json_result(&output)?,
        &[
            ("metadata", json!(13)),
            ("control_plane", json!(13)),
            ("outside_allowed_ips", json!(13)),
        ],
    )
}

/// A process can serve and fetch HTTP on 127.0.0.1 without proxy variables
/// in its environment.
#[testkit::test]
async fn localhost_is_reachable_without_proxy_environment(cx: &mut Context) -> testkit::Result {
    let sandbox = python_sandbox(cx, "local", policy::base()).await?;
    let output = run_python(&sandbox, LOCALHOST_CLIENT, &[]).await?;
    expect_values(
        &json_result(&output)?,
        &[
            ("proxy_env_absent", json!(true)),
            ("payload", json!({"message": "hello"})),
        ],
    )
}

/// Closing a listener, or exiting while holding one, frees its port: new
/// connections are refused and the port can be bound again. A later exec
/// doesn't inherit the exited child's listener.
#[testkit::test]
async fn closed_or_exited_listener_releases_its_port(cx: &mut Context) -> testkit::Result {
    let sandbox = python_sandbox(cx, "listen", policy::base()).await?;
    let output = run_python(&sandbox, LISTENER_LIFETIME_PROBE, &[]).await?;
    let inode = json_result(&output)?[1].to_string();
    run_python(&sandbox, SOCKET_NOT_INHERITED, &[&inode])
        .await
        .context("a later exec inherited the closed listener")?;
    Ok(())
}

/// An exec doesn't inherit a socket that the sandbox's main process opened
/// without close-on-exec.
#[testkit::test]
async fn exec_does_not_inherit_main_process_socket(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("preconn")
        .policy(policy::base())
        .image(testkit::python_image())
        .command(["python3", "-c", PRECONNECT_OWNER])
        .create_ready()
        .await?;
    let inode = sandbox
        .poll_exec(
            "the main process to publish its socket inode",
            Duration::from_secs(30),
            ["cat", "/sandbox/preconnect-inode"],
            |output| output.exit_code == 0 && output.stdout.trim().parse::<u64>().is_ok(),
        )
        .await?
        .stdout;
    run_python(&sandbox, SOCKET_NOT_INHERITED, &[inode.trim()])
        .await
        .context("the exec inherited the main process's socket")?;
    Ok(())
}
