// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A policy endpoint whose host is an IP literal reaches that address
//! transparently, whether `allowed_ips` names it or not.
//!
//! The servers run on the test host. The sandbox can't learn the host's
//! address, since policy DNS answers it with a synthetic one, so the test
//! reaches a server by `host.openshell.internal` first and takes the address
//! the server saw the request arrive at. A supervisor on the host network
//! (Docker's and Podman's default) arrives on loopback, which an IP literal
//! can't reach, so the test uses the host's outbound address instead; that
//! supervisor shares it. Not conformance, because
//! that address must be one the supervisor lets an IP literal reach: rootless
//! Podman's is link-local, which is always blocked.
//!
//! Ported from the `proxy_egress_pipeline` e2e test of IP literals, which
//! used two support containers on the e2e network instead.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};

use host_server_support::{HttpRecorder, TEST_HOST, allow_host};
use sandbox_clients_support::{Request, http};
use testkit::policy;
use testkit::{Context, PYTHON_BINARIES};

fn main() -> std::process::ExitCode {
    testkit::main()
}

/// Requests reach a server by an IP literal endpoint with `allowed_ips` for
/// that address, and another by an IP literal endpoint without it.
#[testkit::test]
async fn ip_literal_endpoints_reach_the_host(cx: &mut Context) -> testkit::Result {
    let explicit = HttpRecorder::start("explicit").await?;
    let implicit = HttpRecorder::start("implicit").await?;
    let mut name_policy = policy::base();
    allow_host(&mut name_policy, "by_name", explicit.port);
    let sandbox = cx
        .python_sandbox("hstip", name_policy)
        .create_ready()
        .await?;
    let reply = http(
        &sandbox,
        TEST_HOST,
        explicit.port,
        &Request::get("/by-name"),
    )
    .await?;
    testkit::ensure!(
        reply.status() == Some(200),
        "request to {TEST_HOST}:{} failed: {reply:?}",
        explicit.port
    );
    let arrived_on = explicit
        .requests()
        .first()
        .and_then(|request| request.local_addr)
        .ok_or_else(|| testkit::Error::msg("the host server didn't record its address"))?
        .ip();
    let host_ip = if arrived_on.is_loopback() {
        outbound_address()?
    } else {
        arrived_on
    };
    let ip = host_ip.to_string();
    let prefix = if host_ip.is_ipv4() { 32 } else { 128 };

    let mut ip_policy = policy::base();
    policy::allow(
        &mut ip_policy,
        "explicit",
        &ip,
        explicit.port,
        PYTHON_BINARIES,
    )
    .allowed_ips = vec![format!("{ip}/{prefix}")];
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

/// The test host's address on its default route. Connecting a UDP socket
/// sends nothing; it only picks the route.
fn outbound_address() -> testkit::Result<IpAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9))?;
    let address = socket.local_addr()?.ip();
    testkit::ensure!(
        !address.is_loopback() && !address.is_unspecified(),
        "the test host has no outbound address, only {address}"
    );
    Ok(address)
}
