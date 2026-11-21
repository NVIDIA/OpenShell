// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox networking: direct connections the sandbox refuses, loopback
//! traffic it leaves alone, and listening sockets whose lifetime it must not
//! extend.
//!
//! Ported from the e2e tests this change removes from `e2e/rust/tests/`:
//! `bypass_detection.rs`, `listener_lifetime.rs`, `no_proxy.rs` (its
//! `sandbox_reaches_localhost_without_proxy_environment` is
//! [`localhost_is_reachable_without_proxy_environment`]), and the
//! destination denials in `proxy_egress_pipeline.rs`.

use std::time::Duration;

use sandbox_clients_support::{connect, scripts};
use serde_json::json;
use testkit::{Context, PYTHON_BINARIES, ResultExt as _, policy};

/// `EACCES`, the errno the sandbox denies a reserved destination with.
const EACCES: i32 = 13;

/// A direct TCP connection that bypasses the proxy is denied with a
/// permission error well before the socket's 10-second timeout.
#[testkit::test]
async fn direct_connect_bypass_is_denied_promptly(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .python_sandbox("bypas", policy::base())
        .create_ready()
        .await?;
    let probe = connect(&sandbox, "198.51.100.1", 80).await?;
    testkit::ensure!(
        probe.outcome.is_permission_denied(),
        "expected the direct connect to be denied; got {probe:?}"
    );
    testkit::ensure!(
        probe.elapsed < Duration::from_secs(8),
        "the denial took {:?}; expected under 8 s",
        probe.elapsed
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
        binaries = policy::binaries_yaml(PYTHON_BINARIES),
    ))?;
    let sandbox = cx.python_sandbox("deny", policy).create_ready().await?;
    for (destination, host, port) in [
        ("metadata", "169.254.169.254", 80),
        ("control_plane", "203.0.113.10", 6443),
        ("outside_allowed_ips", "203.0.113.10", 8080),
    ] {
        let probe = connect(&sandbox, host, port).await?;
        testkit::ensure!(
            probe.outcome.errno() == Some(EACCES),
            "expected EACCES for {destination}; got {probe:?}"
        );
    }
    Ok(())
}

/// A process can serve and fetch HTTP on 127.0.0.1 without proxy variables
/// in its environment.
#[testkit::test]
async fn localhost_is_reachable_without_proxy_environment(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .python_sandbox("local", policy::base())
        .create_ready()
        .await?;
    let result = sandbox
        .run_python(scripts::LOCALHOST_CLIENT, &[])
        .await?
        .last_json()?;
    testkit::ensure!(
        result["proxy_env_absent"] == true && result["payload"] == json!({"message": "hello"}),
        "expected a local fetch without proxy variables; got {result}"
    );
    Ok(())
}

/// Closing a listener, or exiting while holding one, frees its port: new
/// connections are refused and the port can be bound again. A later exec
/// doesn't inherit the exited child's listener.
#[testkit::test]
async fn closed_or_exited_listener_releases_its_port(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .python_sandbox("lsten", policy::base())
        .create_ready()
        .await?;
    let inode = sandbox
        .run_python(scripts::LISTENER_LIFETIME_PROBE, &[])
        .await?
        .last_json()?[1]
        .to_string();
    sandbox
        .run_python(scripts::SOCKET_NOT_INHERITED, &[&inode])
        .await
        .context("a later exec inherited the closed listener")?;
    Ok(())
}

/// An exec doesn't inherit a socket that the sandbox's main process opened
/// without close-on-exec.
#[testkit::test]
async fn exec_does_not_inherit_main_process_socket(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("prcon")
        .policy(policy::base())
        .image(testkit::python_image())
        .command(["python3", "-c", scripts::PRECONNECT_OWNER])
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
    sandbox
        .run_python(scripts::SOCKET_NOT_INHERITED, &[inode.trim()])
        .await
        .context("the exec inherited the main process's socket")?;
    Ok(())
}
