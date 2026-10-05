// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::container::is_e2e_driver;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::{SandboxGuard, unique_sandbox_name};

const AUTHENTICATED_USERNAME: &str = "openshell-client";
const DOCKER_EXPOSURE_SCRIPT: &str = r#"printf 'exposure=%s|%s|%s|%s|%s\n' "$(id -u)" "$(id -g)" "$(id -un)" "$(hostname)" "$(hostname -f 2>/dev/null || hostname)""#;
const IDENTITY_EXPOSURE_SCRIPT: &str =
    r#"printf 'exposure=%s|%s|%s||\n' "$(id -u)" "$(id -g)" "$(id -un)""#;

#[derive(Debug)]
struct Exposure {
    #[cfg_attr(not(feature = "e2e-docker"), allow(dead_code))]
    fqdn: String,
    gid: String,
    #[cfg_attr(not(feature = "e2e-docker"), allow(dead_code))]
    hostname: String,
    uid: String,
    username: String,
}

fn parse_exposure(output: &str) -> Exposure {
    let output = strip_ansi(output);
    let value = output
        .lines()
        .find_map(|line| line.find("exposure=").map(|index| &line[index + 9..]))
        .expect("sandbox output should contain exposure values");
    let fields = value.split('|').collect::<Vec<_>>();
    let [uid, gid, username, hostname, fqdn] = fields.as_slice() else {
        panic!("unexpected exposure output: {value}");
    };

    Exposure {
        fqdn: (*fqdn).to_string(),
        gid: (*gid).to_string(),
        hostname: (*hostname).to_string(),
        uid: (*uid).to_string(),
        username: (*username).to_string(),
    }
}

#[cfg(feature = "e2e-docker")]
fn parent_fqdn() -> String {
    let hostname = dns_lookup::get_hostname().expect("read parent hostname");
    let hostname = hostname.trim();
    assert!(!hostname.is_empty(), "parent hostname must not be empty");
    if hostname.contains('.') {
        return hostname.to_string();
    }

    let Ok(addresses) = dns_lookup::lookup_host(hostname) else {
        return hostname.to_string();
    };
    let addresses = addresses.collect::<Vec<_>>();
    let Some(address) = addresses
        .iter()
        .find(|address| !address.is_loopback())
        .or_else(|| addresses.first())
    else {
        return hostname.to_string();
    };
    let Ok(fqdn) = dns_lookup::lookup_addr(address) else {
        return hostname.to_string();
    };
    let fqdn = fqdn.trim_end_matches('.');

    if fqdn.is_empty() {
        hostname.to_string()
    } else {
        fqdn.to_string()
    }
}

#[tokio::test]
async fn sandbox_identity_exposure_is_opt_in() {
    let supports_username =
        is_e2e_driver("docker") || is_e2e_driver("podman") || is_e2e_driver("vm");
    if !supports_username {
        eprintln!("Skipping sandbox identity exposure test for unsupported driver");
        return;
    }

    let script = if is_e2e_driver("docker") {
        DOCKER_EXPOSURE_SCRIPT
    } else {
        IDENTITY_EXPOSURE_SCRIPT
    };
    let mut baseline = SandboxGuard::create(&["--no-tty", "--", "sh", "-c", script])
        .await
        .expect("create baseline sandbox");
    let baseline_exposure = parse_exposure(&baseline.create_output);

    let mut args = vec!["--username"];
    if is_e2e_driver("docker") {
        args.push("--hostname");
    }
    args.extend(["--no-tty", "--", "sh", "-c", script]);
    let mut exposed = SandboxGuard::create(&args)
        .await
        .expect("create sandbox with identity exposure");
    let exposed_values = parse_exposure(&exposed.create_output);

    assert_eq!(exposed_values.uid, baseline_exposure.uid);
    assert_eq!(exposed_values.gid, baseline_exposure.gid);
    assert_ne!(baseline_exposure.username, AUTHENTICATED_USERNAME);
    assert_eq!(exposed_values.username, AUTHENTICATED_USERNAME);

    #[cfg(feature = "e2e-docker")]
    if is_e2e_driver("docker") {
        let fqdn = parent_fqdn();
        let hostname = fqdn.split_once('.').map_or(fqdn.as_str(), |(name, _)| name);

        assert_ne!(baseline_exposure.fqdn, fqdn);
        assert_eq!(exposed_values.hostname, hostname);
        assert_eq!(exposed_values.fqdn, fqdn);
    }

    baseline.cleanup().await;
    exposed.cleanup().await;
}

#[tokio::test]
async fn unsupported_driver_rejects_identity_exposure() {
    if is_e2e_driver("docker") || is_e2e_driver("podman") || is_e2e_driver("vm") {
        return;
    }

    for (flag, message) in [
        ("--hostname", "requires the Docker compute driver"),
        (
            "--username",
            "requires the Docker, Podman, or VM compute driver",
        ),
    ] {
        let output = openshell_cmd()
            .args([
                "sandbox",
                "create",
                "--detach",
                "--name",
                &unique_sandbox_name(),
                flag,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .expect("run unsupported identity exposure request");
        let combined = strip_ansi(&format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));

        assert!(
            !output.status.success(),
            "{flag} unexpectedly succeeded:\n{combined}"
        );
        assert!(
            combined.contains(message),
            "{flag} did not report the driver requirement:\n{combined}"
        );
    }
}
