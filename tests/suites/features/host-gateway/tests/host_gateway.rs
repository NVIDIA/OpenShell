// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `host.openshell.internal` names the host from inside a sandbox, on every
//! compute driver.
//!
//! The test starts an HTTP server where the tests run, which is the host the
//! gateway runs its sandboxes on, and runs a client in a sandbox from the
//! Python test image ([`testkit::python_image`]) that requests a page from that
//! server through the name.

use host_server_support::HttpRecorder;
use testkit::policy;
use testkit::{Context, PYTHON_BINARIES, Result, ResultExt as _, YamlFile};

/// The image's Python, which needs nothing beyond its standard library. The
/// policy allows [`PYTHON_BINARIES`], the real paths behind `python3` in
/// `testkit::python_image()` images, because a rule matches the executable
/// behind a symlink.
const PYTHON: &str = "python3";

/// Requests `/` from `host.openshell.internal` on the port in `argv[1]` and
/// prints the response. The server listens before the sandbox is created,
/// and a Ready sandbox's network is up, so the client doesn't retry.
const CLIENT: &str = r#"
import socket, sys

host, port = "host.openshell.internal", int(sys.argv[1])
with socket.create_connection((host, port), timeout=10) as conn:
    conn.sendall(f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode())
    response = b""
    while chunk := conn.recv(4096):
        response += chunk
print(response.decode(errors="replace"))
"#;

/// A sandbox from the Python test image resolves `host.openshell.internal`
/// and gets a response from a server the test runs on the host. The default
/// policy denies all network access, so the test passes one that lets only the
/// image's Python reach the server's port.
#[testkit::test]
async fn python_sandbox_reaches_host_server(cx: &mut Context) -> testkit::Result {
    let marker = format!("host-gateway-{}", cx.run_id());
    let server = HttpRecorder::start(marker.clone()).await?;
    let policy = YamlFile::new(&policy(server.port)?)?;
    let port = server.port.to_string();
    let image = testkit::python_image();

    // The client runs through `sandbox exec` in a Ready sandbox, not as the
    // main process. A gateway with several replicas (k3s-ha) can refuse to
    // attach to a main process that already finished with "sandbox is not
    // ready" when the request reaches a replica that doesn't hold the
    // sandbox's session.
    let name = cx.name("hg");
    cx.track(&name);
    cx.cli([
        "sandbox",
        "create",
        "--name",
        &name,
        "--from",
        &image,
        "--policy",
        policy.path()?,
        "--detach",
        "--no-tty",
        "--",
        "sh",
        "-c",
        "exec sleep infinity",
    ])
    .await?
    .success()
    .context(format!("create a sandbox from {image}"))?;
    cx.adopt(&name).await?.wait_ready().await?;

    let client = cx
        .cli([
            "sandbox", "exec", "--name", &name, "--no-tty", "--", PYTHON, "-c", CLIENT, &port,
        ])
        .await?
        .success()
        .context("run the client in the sandbox")?;
    testkit::ensure!(
        client.stdout.contains(&marker),
        "the client did not get the host server's response:\n{}{}",
        client.stdout,
        client.stderr
    );
    Ok(())
}

/// A sandbox policy that allows the image's Python ([`PYTHON`]) to
/// connect to `host.openshell.internal` on `port`. The endpoint names only the
/// host and port, as the policy docs describe, so the driver's address for the
/// name is what makes it reachable, not an `allowed_ips` range.
fn policy(port: u16) -> Result<String> {
    let mut policy = policy::base();
    policy::allow(
        &mut policy,
        "host_server",
        "host.openshell.internal",
        port,
        PYTHON_BINARIES,
    );
    policy::to_yaml(&policy)
}
