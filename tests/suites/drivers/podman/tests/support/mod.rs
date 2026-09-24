// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_conformance::OpenShellRunner;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct GatewayInfo {
    status: String,
    compute_drivers: Vec<ComputeDriver>,
}

#[derive(Debug, Deserialize)]
struct ComputeDriver {
    name: String,
    capabilities: ComputeDriverCapabilities,
}

#[derive(Debug, Deserialize)]
struct ComputeDriverCapabilities {
    driver_name: String,
}

/// Require the target gateway to use Podman as its only compute driver.
///
/// This interrogates the running gateway rather than accepting a runner
/// environment variable. A driver-specific suite must fail, rather than skip,
/// when it is pointed at the wrong gateway.
pub async fn assert_podman_gateway(runner: &OpenShellRunner) -> Result<(), String> {
    let result = runner
        .step("preflight/driver-podman")
        .description("gateway reports Podman as its only compute driver")
        .with_timeout(Duration::from_secs(10))
        .run(&["gateway", "info", "--output", "json"])
        .await
        .map_err(|error| format!("could not query gateway compute drivers: {error}"))?;
    result.require_success()?;

    let info = result
        .json::<GatewayInfo>()
        .map_err(|error| format!("gateway returned invalid driver information: {error}"))?;
    if info.status != "healthy" {
        return Err(format!(
            "Podman test suite requires a healthy gateway; gateway status is {:?}",
            info.status
        ));
    }

    let driver_names = info
        .compute_drivers
        .iter()
        .map(|driver| driver.name.as_str())
        .collect::<Vec<_>>();
    let podman_only = matches!(info.compute_drivers.as_slice(), [driver]
        if driver.name == "podman" && driver.capabilities.driver_name == "podman");
    if !podman_only {
        return Err(format!(
            "Podman test suite requires exactly one Podman compute driver; gateway reported {driver_names:?}"
        ));
    }

    Ok(())
}
