// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::{Command, Stdio};

pub struct CliOutput {
    #[allow(dead_code)]
    pub stdout: String,
    pub combined: String,
    pub code: i32,
}

pub fn run(config_dir: &Path, system_dir: &Path, args: &[&str]) -> CliOutput {
    let output = Command::new(env!("CARGO_BIN_EXE_openshell"))
        .args(args)
        .env("XDG_CONFIG_HOME", config_dir)
        .env("HOME", config_dir)
        .env("OPENSHELL_SYSTEM_GATEWAY_DIR", system_dir)
        .env("OPENSHELL_NO_BROWSER", "1")
        .env_remove("OPENSHELL_GATEWAY")
        .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
        .stdin(Stdio::null())
        .output()
        .expect("run openshell");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    CliOutput {
        combined: format!("{stdout}{stderr}"),
        stdout,
        code: output.status.code().unwrap_or(-1),
    }
}

pub fn run_isolated(args: &[&str]) -> CliOutput {
    let config_dir = tempfile::tempdir().expect("create isolated user config dir");
    let system_dir = tempfile::tempdir().expect("create isolated system config dir");
    run(config_dir.path(), system_dir.path(), args)
}
