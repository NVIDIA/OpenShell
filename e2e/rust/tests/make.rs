// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-local-container-driver")]

//! GNU Make must launch recipes without changing the workload identity.

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::container::ImageGuard;
use openshell_e2e::harness::sandbox::SandboxGuard;

const DOCKERFILE: &str = r"FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends make python3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10002 sandbox \
    && useradd -u 10001 -g sandbox -m sandbox
WORKDIR /sandbox
USER sandbox
";

const RECIPE: &str = r#"set -eu
test "$(id -u):$(id -g)" = 10001:10002
/usr/bin/true
printf 'all: ; @true\n' > /tmp/Makefile
make -f /tmp/Makefile
python3 -c 'import os; assert os.getresuid() == (10001,)*3; assert os.getresgid() == (10002,)*3'
printf 'MAKE_RECIPE_OK\n'
"#;

#[tokio::test]
async fn make_launches_recipes_as_non_root_oci_user() {
    let context = tempfile::tempdir().expect("create image context");
    let dockerfile = context.path().join("Dockerfile");
    std::fs::write(&dockerfile, DOCKERFILE).expect("write Make workload Dockerfile");
    let image = ImageGuard::build("make-identity", &dockerfile, context.path())
        .expect("build Ubuntu GNU Make image");

    // A distinct UID and GID ensure each filter uses the correct identity.
    // Start a persistent workload so both canonical launch and exec exercise
    // the filter installed by the real sandbox runtime. Keep the main process
    // alive on failure so the regression retains Make's error output.
    let startup = format!(
        "({RECIPE})\nstatus=$?\nprintf 'MAKE_STARTUP_STATUS=%s\\n' \"$status\"\nsleep infinity"
    );
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--from", image.tag(), "--no-tty"],
        &["sh", "-c", &startup],
        "MAKE_STARTUP_STATUS=",
    )
    .await
    .expect("GNU Make recipe must run during workload startup");

    let output = sandbox
        .exec(&["sh", "-c", RECIPE])
        .await
        .expect("GNU Make recipe must run through sandbox exec");
    assert!(output.contains("MAKE_RECIPE_OK"), "recipe output: {output}");
    assert!(
        sandbox.create_output.contains("MAKE_STARTUP_STATUS=0"),
        "startup recipe failed: {}",
        sandbox.create_output
    );

    let terminal = openshell_cmd()
        .args([
            "sandbox",
            "exec",
            "--name",
            &sandbox.name,
            "--tty",
            "--",
            "sh",
            "-c",
            RECIPE,
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .expect("run GNU Make with a terminal");
    assert!(
        terminal.status.success(),
        "terminal recipe failed: {}{}",
        String::from_utf8_lossy(&terminal.stdout),
        String::from_utf8_lossy(&terminal.stderr)
    );
    assert!(String::from_utf8_lossy(&terminal.stdout).contains("MAKE_RECIPE_OK"));
    sandbox.cleanup().await;
}
