// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration test for the actual enforcement boundary of the
//! `wxc_exec_path` absolute-path requirement: the real `openshell-gateway`
//! binary's `config preflight` subcommand, selecting the `mxc` compute
//! driver.
//!
//! `openshell_driver_mxc::MxcComputeConfig::validate_configuration` already
//! has unit coverage, but that only proves the validation function itself is
//! correct -- it says nothing about whether `MxcFactory::validate_config` (in
//! `src/lib.rs`) still calls it. Before this fix, that factory method was a
//! no-op that discarded the parsed config entirely, so a regression back to
//! that shape would leave every unit test passing while a relative
//! `wxc_exec_path` again reached gateway startup. Spawning the real compiled
//! binary through its actual CLI entry point exercises the whole chain: CLI
//! parsing, TOML config loading, driver selection, `MxcFactory::validate_config`,
//! and `MxcComputeConfig::validate_configuration`.
//!
//! These tests assert only pass/fail, not the diagnostic's exact wording:
//! `openshell_server::cli::run_effective_config_preflight` replaces any
//! validation failure with a generic "malformed" message whenever a config
//! file path is in play (`ConfigPreflightError::invalid_current`), so the
//! specific `wxc_exec_path` wording from `validate_configuration` is not
//! observable through this boundary today. That message-masking behavior is
//! pre-existing and unrelated to this fix.

#![cfg(all(target_os = "windows", feature = "compute-driver-mxc"))]

use std::io::Write;
use std::process::Command;

/// Run `openshell-gateway config preflight` against a disposable TOML config
/// with the `mxc` driver selected. Returns whether the process exited
/// successfully and its captured stderr.
fn run_preflight(toml_body: &str) -> (bool, String) {
    let mut config_file = tempfile::NamedTempFile::new().expect("create temp config file");
    write!(config_file, "{toml_body}").expect("write temp config file");

    let output = Command::new(env!("CARGO_BIN_EXE_openshell-gateway"))
        .arg("config")
        .arg("preflight")
        .env("OPENSHELL_GATEWAY_CONFIG", config_file.path())
        .env("OPENSHELL_COMPUTE_DRIVER", "mxc")
        .env("OPENSHELL_DISABLE_TLS", "true")
        .env_remove("OPENSHELL_DRIVERS")
        .output()
        .expect("spawn openshell-gateway config preflight");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output.status.success(), stderr)
}

#[test]
fn config_preflight_rejects_omitted_wxc_exec_path() {
    let (ok, stderr) = run_preflight(
        r"
[openshell]
version = 2
",
    );
    assert!(
        !ok,
        "omitted wxc_exec_path must fail preflight, stderr: {stderr}"
    );
}

#[test]
fn config_preflight_rejects_relative_wxc_exec_path() {
    let (ok, stderr) = run_preflight(
        r#"
[openshell]
version = 2

[openshell.drivers.mxc]
wxc_exec_path = "wxc-exec.exe"
"#,
    );
    assert!(
        !ok,
        "a relative wxc_exec_path must fail preflight, stderr: {stderr}"
    );
}

#[test]
fn config_preflight_accepts_absolute_wxc_exec_path() {
    let (ok, stderr) = run_preflight(
        r#"
[openshell]
version = 2

[openshell.drivers.mxc]
wxc_exec_path = "C:\\mxc-kit\\bin\\wxc-exec.exe"
"#,
    );
    assert!(
        ok,
        "an absolute wxc_exec_path must pass preflight, stderr: {stderr}"
    );
}
