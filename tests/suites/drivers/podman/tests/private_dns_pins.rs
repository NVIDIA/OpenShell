// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy DNS pins a host's private address to the binaries of the rule that
//! names the host, so a binary another rule allows can't borrow the pin.
//!
//! It runs only on Podman: the fixture must be a private address the sandbox
//! reaches by name, a container on the gateway's network. On Docker the
//! fixture would run on the host behind `host.openshell.internal`, which the
//! supervisor trusts as the host gateway for any rule that matches it.

use std::net::IpAddr;

use container_engine_support::{EchoContainer, Engine};
use sandbox_clients_support::{Python, Resolve};
use testkit::{Context, Error, Sandbox, policy};

const FIXTURE_HOST: &str = "dns-pins.openshell.test";
const FIXTURE_PORT: u16 = 5432;
const DECLARED_PYTHON: &str = "/sandbox/declared-python";
const WILDCARD_PYTHON: &str = "/sandbox/wildcard-python";

/// A copy of `python3` that a rule names exactly reaches the fixture. A copy
/// that only a wildcard rule matching the same name allows resolves the name
/// but can't connect through the exact rule's pin.
#[testkit::test]
async fn private_dns_pins_do_not_cross_binary_rules(cx: &mut Context) -> testkit::Result {
    cx.expect_compute_driver("podman").await?;
    let engine = Engine::from_env()?;
    let fixture = EchoContainer::start(cx, &engine, FIXTURE_HOST, &[FIXTURE_PORT]).await?;
    let fixture_ip: IpAddr = fixture
        .ip
        .parse()
        .map_err(|_| Error::msg(format!("fixture address {:?} isn't an IP", fixture.ip)))?;
    testkit::ensure!(
        matches!(fixture_ip, IpAddr::V4(v4) if v4.is_private()),
        "the fixture must have a private address to check private pins; it has {fixture_ip}"
    );

    let sandbox = cx
        .sandbox("pins")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(policy::base_with(&format!(
            r#"network_policies:
  declared:
    name: declared
    endpoints:
      - {{host: {FIXTURE_HOST}, port: {FIXTURE_PORT}, protocol: tcp}}
    binaries: {declared}
  wildcard:
    name: wildcard
    endpoints:
      - {{host: "*.openshell.test", port: {FIXTURE_PORT}, protocol: tcp}}
    binaries: {wildcard}
"#,
            declared = policy::binaries_yaml(&[DECLARED_PYTHON]),
            wildcard = policy::binaries_yaml(&[WILDCARD_PYTHON]),
        ))?)
        .create_ready()
        .await?;
    sandbox
        .exec([
            "sh",
            "-c",
            &format!(
                "set -e; cp \"$(command -v python3)\" {DECLARED_PYTHON}; \
                 cp \"$(command -v python3)\" {WILDCARD_PYTHON}"
            ),
        ])
        .await?
        .success()?;
    // A copied interpreter still needs its original standard library.
    let home = sandbox
        .exec(["python3", "-c", "import sys; print(sys.base_prefix)"])
        .await?
        .success()?
        .stdout
        .trim()
        .to_string();
    let declared = Python::new(DECLARED_PYTHON).env("PYTHONHOME", &home);
    let wildcard = Python::new(WILDCARD_PYTHON).env("PYTHONHOME", &home);

    expect_synthetic(&sandbox, &declared).await?;
    let reply = declared
        .http_raw(&sandbox, FIXTURE_HOST, FIXTURE_PORT, b"authorized-control")
        .await?;
    testkit::ensure!(
        reply.received == b"authorized-control",
        "the exactly allowed binary did not reach the fixture: {reply:?}"
    );

    expect_synthetic(&sandbox, &wildcard).await?;
    let reply = wildcard
        .http_raw(&sandbox, FIXTURE_HOST, FIXTURE_PORT, b"blocked-probe")
        .await?;
    testkit::ensure!(
        reply.received != b"blocked-probe",
        "the wildcard binary reached the fixture through the exact rule's pin: {reply:?}"
    );

    let received = fixture.received().await?;
    testkit::ensure!(
        received.contains("authorized-control") && !received.contains("blocked-probe"),
        "expected only the exactly allowed binary's bytes at the fixture; got:\n{received}"
    );
    Ok(())
}

/// Expect `python` to resolve the fixture to a synthetic address in
/// `198.18.0.0/15`, where policy DNS allocates.
async fn expect_synthetic(sandbox: &Sandbox, python: &Python) -> testkit::Result {
    let resolved = python.resolve(sandbox, FIXTURE_HOST, FIXTURE_PORT).await?;
    let synthetic = |address: &IpAddr| matches!(address, IpAddr::V4(v4) if v4.octets()[0] == 198 && v4.octets()[1] & 0xfe == 18);
    testkit::ensure!(
        matches!(&resolved, Resolve::Addresses(addresses) if addresses.iter().any(synthetic)),
        "{FIXTURE_HOST} did not resolve to a synthetic address: {resolved:?}"
    );
    Ok(())
}
