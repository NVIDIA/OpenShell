// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const CAPTURE: &str = include_str!("../examples/openclaw-capture.mjs");
const RUNNER: &str = include_str!("../examples/run-openclaw-forward-test.ps1");

#[cfg(windows)]
#[test]
fn runner_restores_openclaw_environment_after_success_and_failure() {
    let directory = tempfile::tempdir().unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
        .arg(root.join("tests/openclaw_environment_cleanup.ps1"))
        .arg("-RunnerPath")
        .arg(root.join("examples/run-openclaw-forward-test.ps1"))
        .arg("-TestDirectory")
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("PASS: 4 environment restoration cases")
    );
}

#[test]
fn capture_preloads_appcontainer_safe_realpath_before_openclaw() {
    let patch = CAPTURE
        .find("fs.promises.realpath = promisify(fs.realpath)")
        .expect("capture must install the callback realpath compatibility binding");
    let import = CAPTURE
        .find("await import(pathToFileURL(entry).href)")
        .expect("capture must import the OpenClaw entry point");

    assert!(
        patch < import,
        "realpath compatibility must be installed before OpenClaw loads"
    );
    assert!(CAPTURE.contains("syncBuiltinESMExports()"));
}

#[test]
fn runner_limits_package_group_dacl_grants_to_writable_data_directories() {
    assert!(RUNNER.contains("*S-1-15-2-1:(OI)(CI)(M)"));
    assert!(RUNNER.contains("*S-1-15-2-2:(OI)(CI)(M)"));
    assert!(
        RUNNER.contains("Grant-AppContainerWritableDirectory (Join-Path $shareDirNorm \"home\")")
    );
    assert!(
        RUNNER.contains("Grant-AppContainerWritableDirectory (Join-Path $shareDirNorm \"temp\")")
    );
    assert!(!RUNNER.contains("Grant-AppContainerWritableDirectory $shareDirNorm"));
}
