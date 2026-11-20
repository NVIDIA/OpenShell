// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Docker and Podman sandboxes reach TCP endpoints without a proxy: policy
//! DNS answers a policy host with a synthetic address in `198.18.0.0/15`,
//! and the supervisor forwards connections to that address only for the
//! endpoints and binaries the policy allows.
//!
//! The fixture echoes what each connection sends. On Docker it runs on the
//! host, which sandboxes reach through `host.openshell.internal`. On Podman it
//! runs in a container on the gateway's network, named by
//! `OPENSHELL_TEST_CONTAINER_NETWORK`, which sandboxes reach by its network
//! alias.

use std::net::IpAddr;
use std::time::Duration;

use container_engine_support::{EchoContainer, Engine};
use host_server_support::{TEST_HOST, TcpServer, free_port};
use sandbox_clients_support::{Http, Python, http_raw};
use testkit::sdk::raw::proto;
use testkit::{Context, Error, PYTHON_BINARIES, Sandbox, policy};

/// A name no policy allows. Policy DNS refuses it, and the denial must not
/// break later exec sessions.
const UNLISTED_HOST: &str = "unlisted-exec-recovery.openshell.test";
/// Ports the Podman fixture listens on. Port 53 checks that TCP to the DNS
/// port of an allowed host is forwarded, not taken for a DNS query, and
/// 15001 is the supervisor's transparent listener port.
const CONTAINER_PORT: u16 = 5432;
const CONTAINER_TCP_DNS_PORT: u16 = 53;
const CONTAINER_TRANSPARENT_PORT: u16 = 15001;
/// Longer than the longest time a synthetic address stays mapped without a
/// lookup.
const MAPPING_TTL: Duration = Duration::from_secs(31);
/// Native TCP to an allowed host resolves through policy DNS and reaches the
/// fixture, also by the synthetic address after its mapping's lifetime, as
/// an IPv4-mapped IPv6 address, and on TCP port 53. A wrong port, the
/// fixture's real address, the transparent listener port and an unlisted
/// host are denied, and exec still works after the denials.
#[testkit::test]
async fn native_tcp_uses_policy_dns_and_fails_closed(cx: &mut Context) -> testkit::Result {
    let fixture = Fixture::start(cx, "ttcp-fixture.openshell.test").await?;
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
        fixture.tcp_dns_port,
        b"tcp-53-probe",
    )
    .await?;

    for (host, port) in [
        (fixture.host.as_str(), fixture.wrong_port),
        (fixture.real_ip.as_str(), fixture.port),
        (fixture.real_ip.as_str(), fixture.transparent_port),
        (UNLISTED_HOST, fixture.port),
    ] {
        let reply = http_raw(&sandbox, host, port, b"blocked").await?;
        testkit::ensure!(
            reply.received != b"blocked",
            "{host}:{port} should be denied; got {reply:?}"
        );
    }
    let received = fixture.received().await?;
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

/// The echo fixture the sandbox reaches, and the ports and addresses a test
/// needs around it.
struct Fixture {
    /// The name the policy allows.
    host: String,
    port: u16,
    tcp_dns_port: u16,
    transparent_port: u16,
    /// A port the policy doesn't allow.
    wrong_port: u16,
    /// An address that reaches the fixture without policy DNS.
    real_ip: String,
    kind: FixtureKind,
}

enum FixtureKind {
    Host(Vec<TcpServer>),
    Container(EchoContainer),
}

impl Fixture {
    /// On Docker, echo servers on the host. On Podman, a container with
    /// network alias `alias` on the gateway's network.
    async fn start(cx: &Context, alias: &str) -> testkit::Result<Self> {
        match cx.compute_driver().await?.as_str() {
            "docker" => Self::start_on_host().await,
            "podman" => Self::start_in_container(cx, alias).await,
            driver => Err(Error::msg(format!(
                "this suite needs a Docker or Podman gateway; the gateway uses {driver}"
            ))),
        }
    }

    async fn start_on_host() -> testkit::Result<Self> {
        let servers = vec![
            TcpServer::echo().await?,
            TcpServer::echo().await?,
            TcpServer::echo().await?,
        ];
        Ok(Self {
            host: TEST_HOST.to_string(),
            port: servers[0].port,
            tcp_dns_port: servers[1].port,
            transparent_port: servers[2].port,
            wrong_port: free_port().await?,
            // The host's address as the sandbox sees it varies by Docker
            // setup; loopback is never reachable without policy DNS either.
            real_ip: "127.0.0.1".to_string(),
            kind: FixtureKind::Host(servers),
        })
    }

    async fn start_in_container(cx: &Context, alias: &str) -> testkit::Result<Self> {
        let engine = Engine::from_env()?;
        let container = EchoContainer::start(
            cx,
            &engine,
            alias,
            &[
                CONTAINER_PORT,
                CONTAINER_TCP_DNS_PORT,
                CONTAINER_TRANSPARENT_PORT,
            ],
        )
        .await?;
        Ok(Self {
            host: alias.to_string(),
            port: CONTAINER_PORT,
            tcp_dns_port: CONTAINER_TCP_DNS_PORT,
            transparent_port: CONTAINER_TRANSPARENT_PORT,
            wrong_port: CONTAINER_PORT + 1,
            real_ip: container.ip.clone(),
            kind: FixtureKind::Container(container),
        })
    }

    /// Everything the fixture has received so far.
    async fn received(&self) -> testkit::Result<String> {
        Ok(match &self.kind {
            FixtureKind::Host(servers) => servers
                .iter()
                .map(|server| String::from_utf8_lossy(&server.received()).into_owned())
                .collect::<Vec<_>>()
                .join("\n"),
            FixtureKind::Container(container) => container.received().await?,
        })
    }
}

/// Lets the image's Python reach the fixture's port and TCP DNS port by its
/// name, at private addresses.
fn native_tcp_policy(fixture: &Fixture) -> testkit::Result<proto::SandboxPolicy> {
    policy::base_with(&format!(
        r#"network_policies:
  native_tcp:
    name: native_tcp
    endpoints:
      - host: {host}
        ports: [{port}, {tcp_dns_port}]
        protocol: tcp
        allowed_ips: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    binaries: {binaries}
"#,
        host = fixture.host,
        port = fixture.port,
        tcp_dns_port = fixture.tcp_dns_port,
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
