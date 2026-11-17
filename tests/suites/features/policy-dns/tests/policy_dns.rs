// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy DNS answers a sandbox's lookup of an allowed name with a synthetic
//! address. Clients keep resolved addresses in their own DNS caches (libcurl
//! for 60 s, the JDK for 30 s), so the address must keep taking new
//! connections for a while after the lookup.
//!
//! Only the Docker and Podman drivers offer policy DNS, so this is a features
//! suite. The upstream server runs on the test host
//! ([`host_server_support`]) and the sandbox reaches it as
//! `host.openshell.internal`.

use std::time::Duration;

use host_server_support::HttpRecorder;
use testkit::policy;
use testkit::sdk::raw::proto;
use testkit::{Context, PYTHON_BINARIES, Result, ResultExt as _, Sandbox};

const TEST_HOST: &str = "host.openshell.internal";

/// How long the client keeps the address before connecting again. It is past
/// the supervisor's current 30 s mapping ceiling and within the 60 s that
/// NVIDIA/OpenShell#4674 asks for.
const CACHED_ADDRESS_AGE: Duration = Duration::from_secs(45);

/// Resolves `TEST_HOST` the way a client does and prints the synthetic IPv4
/// address policy DNS handed out.
const RESOLVE: &str = r#"
import socket, sys
answers = socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), socket.AF_INET, socket.SOCK_STREAM)
synthetic = [a[4][0] for a in answers if a[4][0].startswith(("198.18.", "198.19."))]
if not synthetic:
    sys.exit(f"no policy DNS address for {sys.argv[1]}: {answers}")
print(synthetic[0])
"#;

/// Connects to the address in `argv[1]` on the port in `argv[2]`, as a client
/// with a cached answer does, and prints the response.
const CONNECT: &str = r#"
import socket, sys
address, port = sys.argv[1], int(sys.argv[2])
with socket.create_connection((address, port), timeout=10) as conn:
    conn.sendall(f"GET / HTTP/1.1\r\nHost: host.openshell.internal:{port}\r\nConnection: close\r\n\r\n".encode())
    response = b""
    while chunk := conn.recv(4096):
        response += chunk
print(response.decode(errors="replace"))
"#;

/// A new connection to a policy DNS address, made after the client has kept
/// the address for [`CACHED_ADDRESS_AGE`], reaches the allowed server while
/// the policy still allows the name. An address policy DNS never handed out
/// is refused. Regression test for NVIDIA/OpenShell#4674.
#[testkit::test]
async fn cached_address_takes_new_connections(cx: &mut Context) -> testkit::Result {
    let marker = format!("policy-dns-{}", cx.run_id());
    let server = HttpRecorder::start(marker.clone()).await?;
    let port = server.port.to_string();
    let sandbox = cx
        .sandbox("pdns")
        .image(testkit::python_image())
        .policy(policy(server.port))
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;

    let address = python(&sandbox, RESOLVE, TEST_HOST, &port)
        .await?
        .success()
        .context("resolve the host through policy DNS")?
        .stdout
        .trim()
        .to_string();

    expect_response(&sandbox, &address, &port, &marker)
        .await
        .context(format!("connect to {address} right after the lookup"))?;

    tokio::time::sleep(CACHED_ADDRESS_AGE).await;
    expect_response(&sandbox, &address, &port, &marker)
        .await
        .context(format!(
            "connect to {address} {}s after the lookup, without a new lookup",
            CACHED_ADDRESS_AGE.as_secs()
        ))?;

    // The last address in the synthetic range, which a sandbox with one
    // allowed name is never handed.
    python(&sandbox, CONNECT, "198.19.255.254", &port)
        .await?
        .failure()
        .context("connect to a synthetic address policy DNS never handed out")?;
    Ok(())
}

async fn python(
    sandbox: &Sandbox,
    script: &str,
    target: &str,
    port: &str,
) -> Result<testkit::ExecOutput> {
    sandbox.exec(["python3", "-c", script, target, port]).await
}

/// Fail unless a new connection to `address` gets the server's response.
async fn expect_response(sandbox: &Sandbox, address: &str, port: &str, marker: &str) -> Result {
    let output = python(sandbox, CONNECT, address, port).await?.success()?;
    testkit::ensure!(
        output.stdout.contains(marker),
        "the client did not get the host server's response:\n{}{}",
        output.stdout,
        output.stderr
    );
    Ok(())
}

/// Let the image's Python reach `TEST_HOST` on `port`.
fn policy(port: u16) -> proto::SandboxPolicy {
    let mut policy = policy::base();
    policy::allow(&mut policy, "host_server", TEST_HOST, port, PYTHON_BINARIES);
    policy
}
