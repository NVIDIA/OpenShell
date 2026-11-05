// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CDI device injection on the Docker and Podman compute drivers.
//!
//! Each test creates a sandbox that selects one scenario device and checks what
//! the workload sees against the scenario's published expectations. See the
//! `cdi` crate for how the scenarios and their checks work. No GPU hardware is
//! needed.

use testkit::Context;

/// A file mounted by the CDI spec under a directory the sandbox baseline
/// already makes read-only needs nothing derived from the spec: the workload
/// can read the mount and cannot write it. The spec-level environment variable
/// and mount every scenario carries show that the spec's edits and the
/// device's edits merge.
#[testkit::test]
async fn mount_under_read_only_baseline(cx: &mut Context) -> testkit::Result {
    cdi::scenario(cx, "mount-under-read-only-baseline").await
}
