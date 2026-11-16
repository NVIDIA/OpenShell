// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! An incoherent driver proxy table is fatal, rather than leaving every dial
//! direct while looking configured. A bypass list without a proxy URL means
//! the operator believed proxying was in effect.

// Only Docker, Podman and the VM driver have a proxy table.
#![cfg(all(
    unix,
    any(
        feature = "compute-driver-docker",
        feature = "compute-driver-podman",
        feature = "compute-driver-vm"
    )
))]

use std::fs;
use std::path::PathBuf;
use std::process::Output;
use std::time::Duration;

/// Drivers with an upstream proxy table, compiled into this gateway.
const DRIVERS: &[&str] = &[
    #[cfg(feature = "compute-driver-docker")]
    "docker",
    #[cfg(feature = "compute-driver-podman")]
    "podman",
    #[cfg(feature = "compute-driver-vm")]
    "vm",
];

struct Fixture {
    root: tempfile::TempDir,
    config: PathBuf,
}

impl Fixture {
    /// A gateway config that selects `driver` and sets only `no_proxy` in its
    /// table.
    fn incoherent(driver: &str) -> Self {
        let root = tempfile::tempdir().expect("fixture root");
        let config = root.path().join("gateway.toml");
        fs::write(
            &config,
            format!(
                "[openshell]
version = 2
[openshell.gateway]
disable_tls = true
bind_address = \"127.0.0.1:0\"
compute_driver = {driver:?}
[openshell.gateway.auth]
allow_unauthenticated_users = true
[openshell.drivers.{driver}]
no_proxy = \"10.0.0.0/8\"
"
            ),
        )
        .expect("gateway configuration");
        Self { root, config }
    }

    async fn run(&self, args: &[&str]) -> Output {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_openshell-gateway"));
        command
            .env_clear()
            .env("HOME", self.root.path())
            .env("PATH", "/usr/bin:/bin")
            .env("NO_COLOR", "1")
            .env("XDG_CONFIG_HOME", self.root.path().join("config-home"))
            .env("XDG_STATE_HOME", self.root.path().join("state-home"))
            .args(args)
            .kill_on_drop(true);
        tokio::time::timeout(Duration::from_secs(30), command.output())
            .await
            .expect("the gateway must exit instead of starting")
            .expect("run openshell-gateway")
    }

    fn config_path(&self) -> &str {
        self.config.to_str().expect("UTF-8 config path")
    }
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[tokio::test]
async fn preflight_rejects_no_proxy_without_proxy() {
    for driver in DRIVERS {
        let fixture = Fixture::incoherent(driver);
        let original = fs::read(&fixture.config).expect("original config");
        let output = fixture
            .run(&["config", "preflight", "--path", fixture.config_path()])
            .await;
        let report = combined(&output);
        assert!(
            !output.status.success(),
            "preflight accepted an incoherent [openshell.drivers.{driver}] proxy table:\n{report}"
        );
        assert!(
            report.contains("category=malformed"),
            "preflight did not classify the {driver} config as malformed:\n{report}"
        );
        assert_eq!(
            fs::read(&fixture.config).expect("config after preflight"),
            original,
            "preflight changed the {driver} config"
        );
    }
}

#[tokio::test]
async fn startup_rejects_no_proxy_without_proxy_and_names_the_keys() {
    for driver in DRIVERS {
        let fixture = Fixture::incoherent(driver);
        let output = fixture.run(&["--config", fixture.config_path()]).await;
        let report = combined(&output);
        assert!(
            !output.status.success(),
            "the gateway started with an incoherent [openshell.drivers.{driver}] proxy table:\n{report}"
        );
        // Matched on the key names, not the wording, so error wrapping can
        // change.
        assert!(
            report.contains("no_proxy") && report.contains("https_proxy"),
            "the {driver} startup error does not name the offending keys:\n{report}"
        );
    }
}
