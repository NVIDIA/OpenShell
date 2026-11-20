// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Docker and Podman sandboxes reach TCP endpoints without a proxy: policy
//! DNS answers a policy host with a synthetic address in `198.18.0.0/15`,
//! and the supervisor forwards connections to that address only for the
//! endpoints and binaries the policy allows.
//!
//! The fixture echoes what each connection sends. It runs on the host, which
//! sandboxes reach through `host.openshell.internal`. A fixture container on
//! Podman's network wouldn't do: the Podman supervisor shares the host's
//! network namespace, so policy DNS asks the host's resolver, which doesn't
//! know the network's aliases.

use std::net::IpAddr;
use std::time::Duration;

use host_server_support::{TEST_HOST, TcpServer, free_port};
use sandbox_clients_support::{Http, Python, http_raw};
use testkit::sdk::raw::proto;
use testkit::{Context, Error, PYTHON_BINARIES, Sandbox, policy};

/// A name no policy allows. Policy DNS refuses it, and the denial must not
/// break later exec sessions.
const UNLISTED_HOST: &str = "unlisted-exec-recovery.openshell.test";
/// Longer than the longest time a synthetic address stays mapped without a
/// lookup.
const MAPPING_TTL: Duration = Duration::from_secs(31);
/// Native TCP to an allowed host resolves through policy DNS and reaches the
/// fixture, also by the synthetic address after its mapping's lifetime, as
/// an IPv4-mapped IPv6 address, and on the endpoint's second port. A wrong
/// port, the fixture's real address on an allowed port and on a port the
/// policy doesn't list, and an unlisted host are denied, and exec still works
/// after the denials.
#[testkit::test]
async fn native_tcp_uses_policy_dns_and_fails_closed(cx: &mut Context) -> testkit::Result {
    let fixture = Fixture::start(cx).await?;
    let sandbox = cx
        .sandbox("ttcp")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(native_tcp_policy(&fixture)?)
        .create_ready()
        .await?;

    let synthetic = synthetic_address(&sandbox, &Python::default(), &fixture).await?;
    expect_echo(&sandbox, &fixture.host, fixture.port, b"probe").await?;
    tokio::time::sleep(MAPPING_TTL).await;
    expect_echo(
        &sandbox,
        &synthetic.to_string(),
        fixture.port,
        b"expired-cache-probe",
    )
    .await?;
    expect_echo(
        &sandbox,
        &format!("::ffff:{synthetic}"),
        fixture.port,
        b"mapped-probe",
    )
    .await?;
    expect_echo(
        &sandbox,
        &fixture.host,
        fixture.second_port,
        b"second-port-probe",
    )
    .await?;

    for (host, port) in [
        (fixture.host.as_str(), fixture.wrong_port),
        (fixture.real_ip.as_str(), fixture.port),
        (fixture.real_ip.as_str(), fixture.unlisted_port),
        (UNLISTED_HOST, fixture.port),
    ] {
        let reply = http_raw(&sandbox, host, port, b"blocked").await?;
        testkit::ensure!(
            reply.received != b"blocked",
            "{host}:{port} should be denied; got {reply:?}"
        );
    }
    let received = fixture.received();
    testkit::ensure!(
        !received.contains("blocked"),
        "a denied connection reached the fixture:\n{received}"
    );

    sandbox
        .exec(["sh", "-c", "printf post-denial-exec-ok"])
        .await?
        .expect_stdout("post-denial-exec-ok")?;

    let allowed = format!("-> {}:{}", fixture.host, fixture.port);
    sandbox
        .logs_until("the allowed and denied transparent connections", |logs| {
            logs.contains(&allowed)
                && logs.contains("Denied staged transparent connection")
                && logs.contains(UNLISTED_HOST)
                && logs.contains("policy_dns_ineligible")
        })
        .await?;
    Ok(())
}

/// Echo servers on the host, and the ports and addresses a test needs
/// around them.
struct Fixture {
    /// The name the policy allows.
    host: String,
    port: u16,
    /// Another port the policy's endpoint lists.
    second_port: u16,
    /// A port the fixture listens on that the policy doesn't list.
    unlisted_port: u16,
    /// A port the policy doesn't allow.
    wrong_port: u16,
    /// An address that reaches the fixture without policy DNS. The host's
    /// address as the sandbox sees it varies by setup; loopback is never
    /// reachable without policy DNS either.
    real_ip: String,
    servers: Vec<TcpServer>,
}

impl Fixture {
    async fn start(cx: &Context) -> testkit::Result<Self> {
        let driver = cx.compute_driver().await?;
        testkit::ensure!(
            matches!(driver.as_str(), "docker" | "podman"),
            "this suite needs a Docker or Podman gateway; the gateway uses {driver}"
        );
        let servers = vec![
            TcpServer::echo().await?,
            TcpServer::echo().await?,
            TcpServer::echo().await?,
        ];
        Ok(Self {
            host: TEST_HOST.to_string(),
            port: servers[0].port,
            second_port: servers[1].port,
            unlisted_port: servers[2].port,
            wrong_port: free_port().await?,
            real_ip: "127.0.0.1".to_string(),
            servers,
        })
    }

    /// Everything the fixture has received so far.
    fn received(&self) -> String {
        self.servers
            .iter()
            .map(|server| String::from_utf8_lossy(&server.received()).into_owned())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Lets the image's Python reach the fixture's two ports by its name, at
/// private addresses.
fn native_tcp_policy(fixture: &Fixture) -> testkit::Result<proto::SandboxPolicy> {
    policy::base_with(&format!(
        r#"network_policies:
  native_tcp:
    name: native_tcp
    endpoints:
      - host: {host}
        ports: [{port}, {second_port}]
        protocol: tcp
        allowed_ips: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    binaries: {binaries}
"#,
        host = fixture.host,
        port = fixture.port,
        second_port = fixture.second_port,
        binaries = policy::binaries_yaml(PYTHON_BINARIES),
    ))
}

/// Resolve the fixture's name under `python` and return the synthetic
/// address policy DNS answered with.
async fn synthetic_address(
    sandbox: &Sandbox,
    python: &Python,
    fixture: &Fixture,
) -> testkit::Result<IpAddr> {
    let resolved = python.resolve(sandbox, &fixture.host, fixture.port).await?;
    resolved
        .addresses()
        .iter()
        .copied()
        .find(is_synthetic)
        .ok_or_else(|| {
            Error::msg(format!(
                "{} did not resolve to a synthetic 198.18.0.0/15 address: {resolved:?}",
                fixture.host
            ))
        })
}

/// Whether `address` is in `198.18.0.0/15`, where policy DNS allocates.
fn is_synthetic(address: &IpAddr) -> bool {
    matches!(address, IpAddr::V4(v4) if v4.octets()[0] == 198 && v4.octets()[1] & 0xfe == 18)
}

/// Send `bytes` to `host:port` and expect the fixture to echo them.
async fn expect_echo(
    sandbox: &Sandbox,
    host: &str,
    port: u16,
    bytes: &[u8],
) -> testkit::Result<Http> {
    let reply = http_raw(sandbox, host, port, bytes).await?;
    testkit::ensure!(
        reply.received == bytes,
        "expected {host}:{port} to echo {:?}; got {reply:?}",
        String::from_utf8_lossy(bytes)
    );
    Ok(reply)
}
