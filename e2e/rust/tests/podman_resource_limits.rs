// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

//! Podman-specific E2E coverage verifying that declared sandbox CPU/memory
//! resource limits are actually enforced by cgroups inside the workload, not
//! just echoed back by the API/template layer.
//!
//! `e2e/rust/tests/sandbox_templates.rs` already verifies that
//! `sandbox template create --cpu ... --memory ...` is stored and returned
//! correctly, but it never inspects the resulting container's real resource
//! state. This test creates a sandbox with those flags directly and reads the
//! cgroup v2 interface files from inside the sandbox itself, so it exercises
//! the actual enforcement boundary the workload experiences.

use openshell_e2e::harness::sandbox::SandboxGuard;

const CGROUP_READ_POLICY: &str = r"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /lib64, /proc, /etc, /sys/fs/cgroup]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
network_policies: {}
";

const CPU_REQUEST: &str = "500m";
const MEMORY_REQUEST: &str = "512Mi";

// "500m" (500 millicores) becomes a 50000us quota over Podman's 100000us
// (100ms) CFS period — see
// crates/openshell-driver-podman/src/container.rs's parse_cpu_to_microseconds.
// Verified directly against a real `podman run --cpus=0.5` container, whose
// cpu.max reads "50000 100000".
const EXPECTED_CPU_MAX: &str = "50000 100000";

// "512Mi" (mebibytes) becomes exactly 512 * 1024 * 1024 bytes — see
// crates/openshell-driver-podman/src/container.rs's parse_memory_to_bytes.
// Verified directly against a real `podman run --memory=512m` container,
// whose memory.max reads "536870912".
const EXPECTED_MEMORY_MAX: &str = "536870912";

#[tokio::test]
async fn sandbox_resource_limits_are_enforced_via_cgroups() {
    if std::env::var("OPENSHELL_E2E_DRIVER").as_deref() != Ok("podman") {
        eprintln!("Skipping Podman resource-limit test: e2e driver is not podman");
        return;
    }

    let policy = tempfile::NamedTempFile::new().expect("create cgroup read policy file");
    std::fs::write(policy.path(), CGROUP_READ_POLICY).expect("write cgroup read policy");
    let policy_path = policy.path().to_str().expect("policy path is UTF-8");
    let mut sandbox = SandboxGuard::create(&[
        "--cpu",
        CPU_REQUEST,
        "--memory",
        MEMORY_REQUEST,
        "--policy",
        policy_path,
    ])
    .await
    .expect("sandbox create with resource limits should succeed");

    let memory_max = sandbox
        .exec(&["cat", "/sys/fs/cgroup/memory.max"])
        .await
        .expect("read memory.max from sandbox cgroup")
        .trim()
        .to_string();
    assert_eq!(
        memory_max, EXPECTED_MEMORY_MAX,
        "sandbox cgroup should enforce the declared {MEMORY_REQUEST} memory limit, got {memory_max}"
    );

    let cpu_max = sandbox
        .exec(&["cat", "/sys/fs/cgroup/cpu.max"])
        .await
        .expect("read cpu.max from sandbox cgroup")
        .trim()
        .to_string();
    assert_eq!(
        cpu_max, EXPECTED_CPU_MAX,
        "sandbox cgroup should enforce the declared {CPU_REQUEST} CPU limit, got {cpu_max}"
    );

    sandbox.cleanup().await;
}
