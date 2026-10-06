// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(all(unix, feature = "compute-driver-vm"))]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

struct Fixture {
    root: tempfile::TempDir,
    tools: PathBuf,
    config: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("fixture root");
        let tools = root.path().join("tools");
        fs::create_dir(&tools).expect("tools directory");
        let config = root.path().join("gateway.toml");
        let fixture = Self {
            root,
            tools,
            config,
        };
        fixture.write_config(Some("vm"));
        for name in ["mke2fs", "debugfs", "e2fsck"] {
            fixture.tool(name, &format!(
                "test \"$1\" = -V || exit 64\ntest \"$#\" = 1 || exit 65\nread ignored && exit 66\ntest \"$PREFLIGHT_TEST_ENV\" = inherited || exit 67\necho '{name} 1.47.4' >&2"
            ));
        }
        fixture
    }

    fn write_config(&self, driver: Option<&str>) {
        let selector =
            driver.map_or_else(String::new, |name| format!("compute_driver = {name:?}\n"));
        // TOML serialization preserves quotes and escapes in the fixture path.
        let state_dir = toml::Value::try_from(self.root.path().join("vm-state"))
            .expect("serialize VM state directory");
        fs::write(&self.config, format!(
            "[ryno]\nversion = 2\n[ryno.gateway]\ndisable_tls = true\n{selector}[ryno.drivers.vm]\nbootstrap_image = 'unreachable.invalid/vm:must-not-pull'\nstate_dir = {state_dir}\n"
        )).expect("gateway configuration");
    }

    fn tool(&self, name: &str, body: &str) {
        let path = self.tools.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("tool fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("executable fixture");
    }

    fn command(&self, replay: &[&str]) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_ryno-gateway"));
        command
            .env_clear()
            .env("HOME", self.root.path())
            .env("PATH", &self.tools)
            .env("XDG_CONFIG_HOME", self.root.path().join("config-home"))
            .env("XDG_STATE_HOME", self.root.path().join("state-home"))
            .env("PREFLIGHT_TEST_ENV", "inherited")
            .args(["config", "preflight"])
            .kill_on_drop(true);
        if replay.is_empty() {
            command.arg("--path").arg(&self.config);
        } else {
            command
                .arg("--")
                .arg("--config")
                .arg(&self.config)
                .args(replay);
        }
        command
    }

    async fn run(&self, replay: &[&str]) -> Output {
        let original_config = fs::read(&self.config).expect("original config");
        let mut command = self.command(replay);
        let output = tokio::time::timeout(Duration::from_secs(15), command.output())
            .await
            .expect("preflight must finish")
            .expect("run gateway preflight");
        assert_eq!(
            fs::read(&self.config).expect("unchanged config"),
            original_config
        );
        for name in ["vm-state", "state-home", "config-home", ".local"] {
            assert!(
                !self.root.path().join(name).exists(),
                "preflight created {name}"
            );
        }
        output
    }
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn normalized_diagnostic(output: &Output) -> String {
    // Terminal line wrapping can split an error sentence after a long path.
    combined(output)
        .split_whitespace()
        .filter(|word| *word != "│")
        .collect::<Vec<_>>()
        .join(" ")
}

#[tokio::test]
async fn local_vm_reports_tools_without_starting_driver_or_creating_state() {
    let fixture = Fixture::new();
    let output = fixture.run(&[]).await;
    assert!(output.status.success(), "{}", combined(&output));
    let report = String::from_utf8_lossy(&output.stdout);
    for name in ["mke2fs", "debugfs", "e2fsck"] {
        let path = fixture
            .tools
            .join(name)
            .canonicalize()
            .expect("selected path");
        assert!(
            report.contains(path.to_str().expect("UTF-8 path")),
            "{report}"
        );
    }
    // PATH contains only the filesystem fixtures, never a VM driver binary.
    assert!(!fixture.tools.join("ryno-driver-vm").exists());
}

#[tokio::test]
async fn config_file_retains_selected_tool_error_and_corrective_guidance() {
    let fixture = Fixture::new();
    fixture.tool("debugfs", "echo 'fixture loader failure' >&2\nexit 42");
    let output = fixture.run(&[]).await;
    assert!(!output.status.success());
    let report = combined(&output);
    for expected in [
        "debugfs",
        "fixture loader failure",
        "42",
        "gateway service PATH",
        "mke2fs",
    ] {
        assert!(report.contains(expected), "missing {expected}: {report}");
    }
    assert!(
        report.contains(fixture.tools.to_str().expect("tool path")),
        "{report}"
    );
}

#[tokio::test]
async fn local_vm_rejects_nonexecutable_and_unsupported_tools() {
    let fixture = Fixture::new();
    fs::set_permissions(
        fixture.tools.join("mke2fs"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let output = fixture.run(&[]).await;
    assert!(!output.status.success());
    let report = normalized_diagnostic(&output);
    assert!(report.contains("not an executable file"), "{report}");

    fixture.tool("mke2fs", "echo 'mke2fs 1.42.13' >&2");
    let output = fixture.run(&[]).await;
    assert!(!output.status.success());
    let report = normalized_diagnostic(&output);
    assert!(report.contains("not a supported mke2fs"), "{report}");
}

#[tokio::test]
async fn local_vm_rejects_hanging_tool_with_deadline() {
    let fixture = Fixture::new();
    fixture.tool("mke2fs", "exec /bin/sleep 30");
    let start = std::time::Instant::now();
    let output = fixture.run(&[]).await;
    assert!(!output.status.success());
    // normalized_diagnostic: macOS TMPDIR paths are long enough to wrap this
    // sentence mid-phrase; compare whitespace-insensitively like the tests above.
    assert!(
        normalized_diagnostic(&output).contains("timed out after 5 seconds"),
        "{}",
        combined(&output)
    );
    assert!(start.elapsed() < Duration::from_secs(12));
}

#[tokio::test]
async fn signals_stop_probe_wrapper_and_descendants_before_cli_exit() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    use std::process::Stdio;

    for signal in [Signal::SIGINT, Signal::SIGTERM] {
        let fixture = Fixture::new();
        let ready = fixture.root.path().join("probe-ready");
        let survived = fixture.root.path().join("survived-signal");
        fixture.tool(
            "mke2fs",
            &format!(
                "(echo ready > '{}'; /bin/sleep 2; echo survived > '{}') &\nwait",
                ready.display(),
                survived.display()
            ),
        );
        let child = fixture
            .command(&[])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("preflight process");
        let pid =
            Pid::from_raw(i32::try_from(child.id().expect("gateway PID")).expect("valid PID"));
        tokio::time::timeout(Duration::from_secs(5), async {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("probe descendant ready");
        kill(pid, signal).expect("signal gateway");
        let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
            .await
            .expect("signal cleanup deadline")
            .expect("preflight exit");
        assert!(!output.status.success());
        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert!(!survived.exists(), "probe descendant survived {signal}");
        assert!(
            combined(&output).contains(&format!("interrupted by {signal}")),
            "{}",
            combined(&output)
        );
        assert!(!fixture.root.path().join("vm-state").exists());
    }
}

#[tokio::test]
async fn remote_vm_reports_unperformed_checks_without_running_local_tools() {
    let fixture = Fixture::new();
    fixture.tool("mke2fs", "echo 'local tool must not run' >&2\nexit 42");
    let socket = fixture.root.path().join("absent-remote.sock");
    let output = fixture
        .run(&["--compute-driver-socket", socket.to_str().unwrap()])
        .await;
    assert!(output.status.success(), "{}", combined(&output));
    assert!(combined(&output).contains("host tool checks not performed for a remote endpoint"));
    assert!(!combined(&output).contains("local tool must not run"));
    assert!(!Path::new(&socket).exists());
}

#[tokio::test]
async fn vm_table_without_selection_does_not_probe_tools() {
    let fixture = Fixture::new();
    fixture.write_config(None);
    fixture.tool("mke2fs", "exit 42");
    let output = fixture.run(&[]).await;
    assert!(output.status.success(), "{}", combined(&output));
    assert!(!combined(&output).contains("VM host tool"));
}

#[cfg(feature = "compute-driver-docker")]
#[tokio::test]
async fn unrelated_driver_does_not_require_vm_tools() {
    let fixture = Fixture::new();
    fixture.tool("mke2fs", "exit 42");
    let output = fixture.run(&["--compute-driver", "docker"]).await;
    assert!(output.status.success(), "{}", combined(&output));
    assert!(!combined(&output).contains("VM host tool"));
}
