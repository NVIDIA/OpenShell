// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Active compute-driver detection for tests with driver-specific assumptions.

/// Returns true and prints a skip notice when running against the kube driver.
///
/// Tests that depend on docker/podman host-network features (e.g.
/// `host.openshell.internal` reachability, sibling-container test servers)
/// can early-return when this is true.
pub fn skip_if_kube(reason: &str) -> bool {
    if matches!(
        std::env::var("OPENSHELL_E2E_DRIVER").as_deref(),
        Ok("kubernetes")
    ) {
        eprintln!("skipping on kubernetes driver: {reason}");
        return true;
    }
    false
}
