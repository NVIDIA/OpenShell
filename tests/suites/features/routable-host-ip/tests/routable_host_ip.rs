// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A policy endpoint whose host is an IP literal reaches that address
//! transparently, whether `allowed_ips` names it or not.
//!
//! The servers run on the test host, and the sandbox reaches them by the
//! address `host.openshell.internal` resolves to. Not conformance, because
//! that address must be one the supervisor lets an IP literal reach: rootless
//! Podman's is link-local, which is always blocked.
//!
//! Ported from the `proxy_egress_pipeline` e2e test of IP literals, which
//! used two support containers on the e2e network instead.

use host_server_support::{HttpRecorder, TEST_HOST};
use sandbox_clients_support::{Request, http};
use testkit::policy;
use testkit::{Context, PYTHON_BINARIES, ResultExt as _};

/// Requests reach a server by an IP literal endpoint with `allowed_ips` for
/// that address, and another by an IP literal endpoint without it.
#[testkit::test]
async fn ip_literal_endpoints_reach_the_host(cx: &mut Context) -> testkit::Result {
    let explicit = HttpRecorder::start("explicit").await?;
    let implicit = HttpRecorder::start("implicit").await?;
    let sandbox = cx
        .sandbox("hstip")
        .policy(policy::base())
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;
    let ip = sandbox
        .run_python(
            "import socket, sys; print(socket.gethostbyname(sys.argv[1]))",
            &[TEST_HOST],
        )
        .await
        .context(format!("resolve {TEST_HOST} in the sandbox"))?
        .stdout
        .trim()
        .to_string();

    let mut ip_policy = policy::base();
    policy::allow(
        &mut ip_policy,
        "explicit",
        &ip,
        explicit.port,
        PYTHON_BINARIES,
    )
    .allowed_ips = vec![format!("{ip}/32")];
    policy::allow(
        &mut ip_policy,
        "implicit",
        &ip,
        implicit.port,
        PYTHON_BINARIES,
    );
    policy::set(&sandbox, &ip_policy).await?;

    for (mode, server) in [("explicit allowed_ips", &explicit), ("implicit", &implicit)] {
        for path in ["/first", "/second"] {
            let reply = http(&sandbox, &ip, server.port, &Request::get(path)).await?;
            testkit::ensure!(
                reply.status() == Some(200),
                "{mode} request to {ip}:{}{path} failed: {reply:?}",
                server.port
            );
        }
    }
    Ok(())
}
