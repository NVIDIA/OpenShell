// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Strict mode reaches the plan check from both the flag and the environment
//! variable CI can set. The cpu-tests plan only has an amd64 environment, so
//! on any other host strict mode must refuse it and a plain run must not.

use std::path::Path;
use std::process::{Command, Output};

fn dry_run(strict_flag: Option<&str>, strict_env: Option<&str>) -> Output {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut command = Command::new(env!("CARGO_BIN_EXE_openshell-test-runner"));
    command
        .current_dir(&root)
        .args(["test", "--plan", "tests/plans/cpu-tests.yaml", "--dry-run"])
        .env_remove("OPENSHELL_TEST_STRICT");
    if let Some(flag) = strict_flag {
        command.arg(flag);
    }
    if let Some(value) = strict_env {
        command.env("OPENSHELL_TEST_STRICT", value);
    }
    command.output().expect("run openshell-test-runner")
}

fn assert_strict(output: &Output, strict: bool) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let refused = strict && !cfg!(target_arch = "x86_64");
    assert_eq!(output.status.success(), !refused, "{stderr}");
    assert_eq!(
        stderr.contains("strict mode refuses this plan"),
        refused,
        "{stderr}"
    );
}

#[test]
fn strict_mode_is_off_by_default() {
    assert_strict(&dry_run(None, None), false);
    assert_strict(&dry_run(None, Some("false")), false);
    assert_strict(&dry_run(Some("--strict=false"), None), false);
}

#[test]
fn strict_mode_is_on_from_the_flag_or_the_environment() {
    assert_strict(&dry_run(Some("--strict"), None), true);
    assert_strict(&dry_run(None, Some("true")), true);
}
