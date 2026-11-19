// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workloads suite: real tools doing realistic tasks in sandboxes. Each
//! module is one workload.
//!
//! `cargo test` and nextest run the tests as this library's unit tests.
//! `#[testkit::test]` also registers them, so the `openshell-workloads`
//! program in `src/main.rs` runs them by linking this library.
//!
//! Each workload runs in its own image, which the environment provides and
//! names in an `OPENSHELL_TEST_WORKLOAD_<NAME>_IMAGE` variable. The tmachine
//! `workloads` environments build the images from the Dockerfiles in this
//! directory and publish the variables; to run a workload elsewhere, build its
//! image into the gateway's image store and set the variable. A missing
//! variable fails the test.

mod make;

/// The image the environment provides for a workload, from `var`.
fn workload_image(var: &str) -> testkit::Result<String> {
    std::env::var(var)
        .ok()
        .filter(|image| !image.trim().is_empty())
        .ok_or_else(|| {
            testkit::Error::msg(format!(
                "{var} is not set; it names the workload's image (see tests/suites/workloads/README.md)"
            ))
        })
}
