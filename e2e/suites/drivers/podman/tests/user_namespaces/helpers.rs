// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_e2e_support::OpenShellRunner;
use std::time::Duration;

use super::gateway::GatewayFixture;

const WORKSPACE_AND_UID_MAP_PROBE: &str = r#"set -eu
workload_owner="$(id -u):$(id -g)"
workspace_owner="$(stat -c '%u:%g' /sandbox)"
printf 'workload-owner=%s\nworkspace-owner=%s\n' "$workload_owner" "$workspace_owner"
test "$(id -u)" -ne 0
test "$workspace_owner" = "$workload_owner"
probe=$(mktemp /sandbox/userns-probe.XXXXXX)
printf 'workspace probe\n' > "$probe"
rm "$probe"
echo podman-userns-workspace-ok
cat /proc/self/uid_map
"#;

pub async fn assert_workspace_and_uid_map(
    gateway: &GatewayFixture,
    runner: &mut OpenShellRunner,
) -> Result<(), String> {
    let reference = gateway.reference_uid_map().await?;
    let expected = normalize_uid_map(&reference)
        .ok_or_else(|| "direct Podman returned no UID mappings".to_string())?;
    let sandbox_name = format!("pu-{}", runner.id());
    runner.track_sandbox(&sandbox_name);
    let result = runner
        .step("userns/workspace-and-uid-map")
        .description("non-root sandbox owns and can write to its workspace")
        .with_timeout(Duration::from_secs(300))
        .run(&[
            "sandbox",
            "create",
            "--name",
            &sandbox_name,
            "--from",
            gateway.image(),
            "--no-tty",
            "--",
            "sh",
            "-c",
            WORKSPACE_AND_UID_MAP_PROBE,
        ])
        .await
        .map_err(|error| error.to_string())?;
    result.require_success()?;
    if !result.stdout().contains("podman-userns-workspace-ok") {
        return Err(result.failure_diagnostic("non-root workload owns and can write to /sandbox"));
    }
    let actual = normalize_uid_map(result.stdout())
        .ok_or_else(|| result.failure_diagnostic("sandbox returns a non-empty UID map"))?;
    if actual != expected {
        return Err(format!(
            "UID map differs from direct Podman:\nexpected:\n{expected}\nactual:\n{actual}"
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::normalize_uid_map;

    #[test]
    fn adjacent_uid_ranges_match_a_combined_mapping() {
        assert_eq!(
            normalize_uid_map("0 0 1\n1 1 65535\n"),
            normalize_uid_map("0 0 65536\n")
        );
    }
}
