// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman-driver user-namespace integration tests.

mod support;

use openshell_conformance::OpenShellRunner;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use support::assert_podman_gateway;

const SANDBOX_TIMEOUT: Duration = Duration::from_secs(300);
const PODMAN_TEST_INPUT_DIR_ENV: &str = "OPENSHELL_TEST_INPUT_DIR";
const PODMAN_TEST_IMAGE_ENV: &str = "OPENSHELL_PODMAN_TEST_IMAGE";

/// Verify that the gateway's user-namespace configuration matches Podman's
/// direct behavior for the same profile.
///
/// The test runs a short-lived sandbox command and compares its user-namespace
/// mapping with the direct-Podman reference stored at
/// `OPENSHELL_TEST_INPUT_DIR/reference-uid-map`. The tmachine pre-test
/// playbook creates that reference in the same gateway-user context. This deliberately
/// avoids baking a particular Podman mapping into OpenShell's test contract.
///
#[tokio::test]
async fn configured_userns_matches_podman_reference() {
    let mut runner = OpenShellRunner::from_env("podman-userns")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        assert_podman_gateway(&runner).await?;

        let test_input_dir = std::env::var_os(PODMAN_TEST_INPUT_DIR_ENV)
            .map(PathBuf::from)
            .ok_or_else(|| format!("{PODMAN_TEST_INPUT_DIR_ENV} must name the Podman test-input directory"))?;
        let expected_path = test_input_dir.join("reference-uid-map");
        let expected_uid_map = fs::read_to_string(&expected_path).map_err(|error| {
            format!(
                "could not read Podman reference UID map {}: {error}",
                expected_path.display()
            )
        })?;
        let expected_uid_map = normalize_uid_map(&expected_uid_map).ok_or_else(|| {
            format!(
                "Podman reference UID map {} contains no mappings",
                expected_path.display()
            )
        })?;

        let workload_image = std::env::var(PODMAN_TEST_IMAGE_ENV)
            .ok()
            .filter(|image| !image.trim().is_empty());
        let sandbox_name = format!("pu-{}", runner.id());
        runner.track_sandbox(&sandbox_name);
        let mut create_args = vec!["sandbox", "create", "--name", &sandbox_name];
        if let Some(image) = workload_image.as_deref() {
            create_args.extend(["--from", image]);
        }
        create_args.extend(["--no-tty", "--", "cat", "/proc/self/uid_map"]);
        let run = runner
            .step("userns/uid-map")
            .description("sandbox exposes its UID map")
            .with_timeout(SANDBOX_TIMEOUT)
            .run(&create_args)
            .await
            .map_err(|error| error.to_string())?;
        run.require_success()?;
        let sandbox_uid_map = normalize_uid_map(run.stdout()).ok_or_else(|| {
            run.failure_diagnostic("sandbox returns a non-empty UID map")
        })?;
        if sandbox_uid_map != expected_uid_map {
            return Err(format!(
                "sandbox UID map differs from the direct Podman reference:\nexpected:\n{expected_uid_map}\nactual:\n{sandbox_uid_map}"
            ));
        }
        Ok(())
    }
    .await;

    if let Err(error) = runner.finish(result).await {
        panic!("Podman userns test failed:\n{error}");
    }
}

fn normalize_uid_map(value: &str) -> Option<String> {
    let mut mappings: Vec<(u64, u64, u64)> = Vec::new();
    for line in value.lines() {
        let fields = line
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>();
        let Ok(fields) = fields else { continue };
        let [inside, outside, length] = fields.as_slice() else {
            continue;
        };
        if let Some(previous) = mappings.last_mut()
            && previous.0.checked_add(previous.2) == Some(*inside)
            && previous.1.checked_add(previous.2) == Some(*outside)
        {
            previous.2 += *length;
        } else {
            mappings.push((*inside, *outside, *length));
        }
    }
    (!mappings.is_empty()).then(|| {
        mappings
            .iter()
            .map(|(inside, outside, length)| format!("{inside} {outside} {length}"))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

#[test]
fn adjacent_uid_ranges_match_a_combined_mapping() {
    assert_eq!(
        normalize_uid_map("0 0 1\n1 1 65535\n"),
        normalize_uid_map("0 0 65536\n")
    );
}
