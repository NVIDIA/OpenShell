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

use host_server_support::HttpRecorder;
use serde_json::Value;
use testkit::policy;
use testkit::{Context, PYTHON_BINARIES, ResultExt as _};

/// Sends two GET requests to `argv[1]:argv[2]` and prints their statuses as
/// one JSON line.
const STATUS_CLIENT: &str = include_str!("../../../conformance/src/scripts/status_client.py");

const RESOLVE: &str = "import socket; print(socket.gethostbyname('host.openshell.internal'))";

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
        .exec(["python3", "-c", RESOLVE])
        .await?
        .success()
        .context("resolve host.openshell.internal in the sandbox")?
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
        let output = sandbox
            .exec([
                "python3",
                "-c",
                STATUS_CLIENT,
                &ip,
                &server.port.to_string(),
            ])
            .await?
            .success()
            .context(format!("run the {mode} client"))?;
        let result: Value = output
            .stdout
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str(line.trim()).ok())
            .ok_or_else(|| {
                testkit::Error::msg(format!(
                    "no JSON result from the {mode} client:\n{}\n{}",
                    output.stdout, output.stderr
                ))
            })?;
        testkit::ensure!(
            result["first"] == 200 && result["second"] == 200,
            "{mode} requests to {ip}:{} failed: {result}",
            server.port
        );
    }
    Ok(())
}
