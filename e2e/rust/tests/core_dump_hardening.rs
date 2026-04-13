// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use openshell_e2e::harness::sandbox::SandboxGuard;

#[tokio::test]
async fn sandbox_processes_disable_core_dumps() {
    let mut sb = SandboxGuard::create(&[
        "--",
        "sh",
        "-lc",
        "test \"$(ulimit -c)\" = 0 && echo core-limit-ok",
    ])
    .await
    .expect("sandbox create should succeed");

    assert!(
        sb.create_output.contains("core-limit-ok"),
        "expected sandbox output to confirm core dumps are disabled:\n{}",
        sb.create_output,
    );

    sb.cleanup().await;
}
