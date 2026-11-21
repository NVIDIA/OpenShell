// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `host.openshell.internal` names the host from inside a sandbox, on every
//! compute driver.
//!
//! The test starts an HTTP server where the tests run, which is the host the
//! gateway runs its sandboxes on, and runs a client in a sandbox from the
//! Python test image ([`testkit::python_image`]) that requests a page from that
//! server through the name.

use host_server_support::{HttpRecorder, TEST_HOST, allow_host};
use testkit::policy;
use testkit::sdk::raw::proto;
use testkit::{Context, ResultExt as _};

fn main() -> std::process::ExitCode {
    testkit::main()
}

/// The image's Python, which needs nothing beyond its standard library. The
/// policy allows [`PYTHON_BINARIES`], the real paths behind `python3` in
/// `testkit::python_image()` images, because a rule matches the executable
/// behind a symlink.
const PYTHON: &str = "python3";

/// Requests `/` from the host named in `argv[1]` on the port in `argv[2]` and
/// prints the response. The server listens before the sandbox is created,
/// and the network is up before the main process starts, so the client
/// doesn't retry.
const CLIENT: &str = r#"
import socket, sys

host, port = sys.argv[1], int(sys.argv[2])
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
    let image = testkit::python_image();

    // The client runs as the main process. It usually finishes before the CLI
    // attaches, so on a gateway with several replicas (k3s-ha) this also
    // covers attaching to a finished main process through a replica that
    // doesn't hold the sandbox's supervisor session.
    let client = cx
        .cli_sandbox("hg")
        .image(image.clone())
        .policy_yaml(policy::to_yaml(&policy(server.port))?)
        .command([PYTHON, "-c", CLIENT, TEST_HOST, &server.port.to_string()])
        .run()
        .await?
        .success()
        .context(format!(
            "run the client as the main process of a sandbox from {image}"
        ))?;
    testkit::ensure!(
        client.stdout.contains(&marker),
        "the client did not get the host server's response:\n{}{}",
        client.stdout,
        client.stderr
    );
    Ok(())
}

/// A sandbox policy that allows the image's Python ([`PYTHON`]) to
/// connect to [`TEST_HOST`] on `port`. The endpoint names only the
/// host and port, as the policy docs describe, so the driver's address for the
/// name is what makes it reachable, not an `allowed_ips` range.
fn policy(port: u16) -> proto::SandboxPolicy {
    let mut policy = policy::base();
    allow_host(&mut policy, "host_server", port);
    policy
}
