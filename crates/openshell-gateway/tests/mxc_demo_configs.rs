// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "windows")]
#[test]
fn shipped_mxc_inference_configs_pass_gateway_preflight() {
    let examples =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../openshell-driver-mxc/examples");

    for name in ["mxc-ollama.toml", "mxc-inference.toml"] {
        let path = examples.join(name);
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_openshell-gateway"))
            .args(["config", "preflight", "--path"])
            .arg(&path)
            .output()
            .unwrap_or_else(|error| panic!("failed to run gateway preflight for {name}: {error}"));

        assert!(
            output.status.success(),
            "gateway preflight rejected {name}:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
