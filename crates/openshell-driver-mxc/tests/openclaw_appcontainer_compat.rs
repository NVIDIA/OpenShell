// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const CAPTURE: &str = include_str!("../examples/openclaw-capture.mjs");
const RUNNER: &str = include_str!("../examples/run-openclaw-forward-test.ps1");
const PROCESS_CONTAINER_CONFIG: &str = include_str!("../examples/mxc-openclaw-gateway.toml");
const ISOLATION_CONFIG: &str = include_str!("../examples/mxc-openclaw-isolation.toml");
const LOCAL_NETWORK_CONFIG: &str = include_str!("../examples/mxc-openclaw-localnet.toml");

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
fn runner_preserves_the_node_main_symlink_inside_processcontainer() {
    let node = RUNNER
        .find("$shareDirToml/node.exe")
        .expect("runner must launch the staged Node.js binary");
    let preserve_main = RUNNER[node..]
        .find("--preserve-symlinks-main")
        .map(|offset| node + offset)
        .expect("runner must prevent Node's pre-entrypoint realpath of the drive root");
    let capture = RUNNER[node..]
        .find("$shareDirToml/openclaw-capture.mjs")
        .map(|offset| node + offset)
        .expect("runner must launch the OpenClaw capture entry point");

    assert!(
        preserve_main < capture,
        "--preserve-symlinks-main must be a Node option before the main module"
    );
    assert!(
        !RUNNER.contains("Grant-AppContainerWritableDirectory $shareDirNorm"),
        "the runtime workaround must not widen the share grant to the drive root"
    );
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

#[test]
fn runner_uses_lifecycle_readiness_and_preserves_failure_diagnostics() {
    assert!(RUNNER.contains("sandbox target_ready received"));
    assert!(
        !RUNNER.contains("Select-String -Path $gwLog -Pattern '\\[gateway\\].*ready'"),
        "target readiness must come from the lifecycle event, not log polling"
    );
    assert!(RUNNER.contains("$failureMessage = $_.Exception.Message"));
    assert!(RUNNER.contains("failure            : $failureSummary"));
    assert!(RUNNER.contains("$fwdProc.WaitForExit(5000)"));
    assert!(RUNNER.contains("$deleteCode = $LASTEXITCODE"));
    assert!(RUNNER.contains("$gw.WaitForExit(5000)"));
}

#[test]
fn openclaw_gateway_configs_declare_the_current_schema() {
    for (name, config) in [
        ("process-container", PROCESS_CONTAINER_CONFIG),
        ("isolation", ISOLATION_CONFIG),
        ("local-network", LOCAL_NETWORK_CONFIG),
    ] {
        let config = config
            .parse::<toml::Value>()
            .unwrap_or_else(|error| panic!("{name} config must be valid TOML: {error}"));
        assert_eq!(
            config
                .get("openshell")
                .and_then(|openshell| openshell.get("version"))
                .and_then(toml::Value::as_integer),
            Some(2),
            "{name} config must declare the current OpenShell schema",
        );
    }
}
