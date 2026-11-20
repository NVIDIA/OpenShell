// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Declared sandbox CPU and memory limits are enforced by the workload's
//! cgroup, not just stored and returned by the API.
//!
//! Conformance checks that a template stores its resources. It can't check
//! enforcement: not every driver enforces limits, and those that do report it
//! in their gateway info capabilities. This test runs where the driver reports
//! both limits, and reads the cgroup v2 files from inside the sandbox.

use testkit::{Context, Error};

const CGROUP_READ_POLICY: &str = "version: 1
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
/// A 50000us quota over a 100000us CFS period, what `--cpus=0.5` gives a
/// container.
const EXPECTED_CPU_MAX: &str = "50000 100000";
/// 512 * 1024 * 1024 bytes.
const EXPECTED_MEMORY_MAX: &str = "536870912";

/// A sandbox created with `--cpu 500m --memory 512Mi` reads those limits from
/// its own `cpu.max` and `memory.max`.
#[testkit::test]
async fn declared_limits_are_enforced_by_the_sandbox_cgroup(cx: &mut Context) -> testkit::Result {
    let info = cx.gateway_info().await?;
    let resources = info
        .compute_drivers
        .first()
        .and_then(|driver| driver.capabilities.as_ref())
        .and_then(|capabilities| capabilities.resource_capabilities.as_ref())
        .ok_or_else(|| Error::msg("the gateway reports no compute driver resource capabilities"))?;
    let cpu = resources
        .cpu
        .as_ref()
        .is_some_and(|cpu| cpu.limit_supported);
    let memory = resources
        .memory
        .as_ref()
        .is_some_and(|memory| memory.limit_supported);
    testkit::ensure!(
        cpu && memory,
        "this suite needs a driver that enforces CPU and memory limits; the gateway reports cpu={cpu}, memory={memory}"
    );

    let sandbox = cx
        .cli_sandbox("rl")
        .args(["--cpu", CPU_REQUEST, "--memory", MEMORY_REQUEST])
        .policy_yaml(CGROUP_READ_POLICY)
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;

    for (file, expected, request) in [
        ("memory.max", EXPECTED_MEMORY_MAX, MEMORY_REQUEST),
        ("cpu.max", EXPECTED_CPU_MAX, CPU_REQUEST),
    ] {
        let path = format!("/sys/fs/cgroup/{file}");
        let output = sandbox.exec(["cat", path.as_str()]).await?.success()?;
        let value = output.stdout.trim();
        testkit::ensure!(
            value == expected,
            "{path} reads {value:?}; expected {expected:?} for the declared {request} limit"
        );
    }
    Ok(())
}
