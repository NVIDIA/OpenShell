// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! GPU workload validation e2e tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use openshell_e2e::harness::cli::{run_cli, wait_for_sandbox_phase};
use openshell_e2e::harness::output::{extract_field, strip_ansi};
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde::Deserialize;
use serial_test::serial;
use tokio::time::timeout;

const WORKLOAD_MANIFEST_ENV: &str = "OPENSHELL_E2E_WORKLOAD_MANIFEST";
const GPU_WORKLOAD_SUCCESS_MARKER: &str = "OPENSHELL_GPU_WORKLOAD_SUCCESS";
const GPU_WORKLOAD_FAILURE_MARKER: &str = "OPENSHELL_GPU_WORKLOAD_FAILURE";
const WORKLOAD_SANDBOX_CREATE_TIMEOUT: Duration = Duration::from_secs(600);
const WORKLOAD_PHASE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Deserialize)]
struct WorkloadManifest {
    workloads: Vec<WorkloadDefinition>,
}

#[derive(Clone, Debug, Deserialize)]
struct WorkloadDefinition {
    name: String,
    image: String,
    command: Vec<String>,
    expect: WorkloadExpectation,
    #[serde(default)]
    requirements: WorkloadRequirements,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum WorkloadExpectation {
    Pass,
    Fail,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct WorkloadRequirements {
    #[serde(default)]
    gpu: bool,
}

fn default_workload_manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../gpu/images/.build/workloads.yaml")
}

fn workload_manifest_path() -> PathBuf {
    std::env::var(WORKLOAD_MANIFEST_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map_or_else(default_workload_manifest_path, PathBuf::from)
}

fn load_workload_manifest() -> Option<WorkloadManifest> {
    let path = workload_manifest_path();
    let explicit_override = std::env::var(WORKLOAD_MANIFEST_ENV)
        .ok()
        .is_some_and(|value| !value.trim().is_empty());

    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(err) if !explicit_override && err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "skipping GPU workload validation: no workload manifest at {}. \
                 Run `mise run e2e:workloads:build` to create the local manifest \
                 or set {WORKLOAD_MANIFEST_ENV} to an external manifest.",
                path.display()
            );
            return None;
        }
        Err(err) => panic!("failed to read workload manifest {}: {err}", path.display()),
    };

    let manifest: WorkloadManifest = serde_yml::from_str(&contents).unwrap_or_else(|err| {
        panic!(
            "failed to parse workload manifest {}: {err}",
            path.display()
        )
    });
    assert!(
        !manifest.workloads.is_empty(),
        "workload manifest {} contains no workloads",
        path.display()
    );
    Some(manifest)
}

struct WorkloadRun {
    guard: SandboxGuard,
    output: String,
    exit_code: i32,
}

async fn run_workload(workload: &WorkloadDefinition) -> Result<WorkloadRun, String> {
    let mut args = vec![
        "sandbox".to_string(),
        "create".to_string(),
        "--gpu".to_string(),
        "--from".to_string(),
        workload.image.clone(),
        "--".to_string(),
    ];
    args.extend(workload.command.clone());
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();

    let (output, exit_code) = timeout(WORKLOAD_SANDBOX_CREATE_TIMEOUT, run_cli(&arg_refs))
        .await
        .map_err(|_| {
            format!(
                "GPU workload sandbox create timed out after {WORKLOAD_SANDBOX_CREATE_TIMEOUT:?}"
            )
        })?;
    let clean_output = strip_ansi(&output);
    let sandbox_name = extract_field(&clean_output, "Created sandbox")
        .or_else(|| extract_field(&clean_output, "Name"))
        .ok_or_else(|| {
            format!("could not parse sandbox name from create output:\n{clean_output}")
        })?;

    Ok(WorkloadRun {
        guard: SandboxGuard::manage_existing(sandbox_name),
        output: clean_output,
        exit_code,
    })
}

async fn assert_expected_pass(workload: &WorkloadDefinition) {
    let mut run = run_workload(workload).await.unwrap_or_else(|err| {
        panic!(
            "GPU workload '{}' expected success but sandbox create failed:\n{err}",
            workload.name
        )
    });

    assert_eq!(
        run.exit_code, 0,
        "GPU workload '{}' expected success. Output:\n{}",
        workload.name, run.output
    );
    wait_for_sandbox_phase(&run.guard.name, "Completed", WORKLOAD_PHASE_TIMEOUT)
        .await
        .unwrap_or_else(|err| {
            panic!(
                "GPU workload '{}' did not retain Completed status:\n{err}",
                workload.name
            )
        });

    assert!(
        run.output.contains(GPU_WORKLOAD_SUCCESS_MARKER),
        "expected success marker {GPU_WORKLOAD_SUCCESS_MARKER} for workload '{}' image {} in sandbox output:\n{}",
        workload.name,
        workload.image,
        run.output,
    );
    run.guard.cleanup().await;
}

async fn assert_expected_fail(workload: &WorkloadDefinition) {
    let mut run = run_workload(workload).await.unwrap_or_else(|err| {
        panic!(
            "GPU workload '{}' could not be started:\n{err}",
            workload.name
        )
    });

    assert_ne!(
        run.exit_code, 0,
        "GPU workload '{}' unexpectedly succeeded. Output:\n{}",
        workload.name, run.output
    );
    wait_for_sandbox_phase(&run.guard.name, "Error", WORKLOAD_PHASE_TIMEOUT)
        .await
        .unwrap_or_else(|err| {
            panic!(
                "GPU workload '{}' did not retain Error status:\n{err}",
                workload.name
            )
        });
    let (details, get_exit_code) = run_cli(&["sandbox", "get", &run.guard.name]).await;
    let clean_details = strip_ansi(&details);
    assert_eq!(
        get_exit_code, 0,
        "could not inspect failed GPU workload '{}':\n{clean_details}",
        workload.name
    );
    assert!(
        clean_details.contains(&format!("Exit Code: {}", run.exit_code)),
        "failed GPU workload '{}' did not retain exit code {}:\n{clean_details}",
        workload.name,
        run.exit_code,
    );
    assert!(
        run.output.contains(GPU_WORKLOAD_FAILURE_MARKER),
        "expected failure marker {GPU_WORKLOAD_FAILURE_MARKER} for workload '{}' image {} in failure output:\n{}",
        workload.name,
        workload.image,
        run.output,
    );
    run.guard.cleanup().await;
}

#[tokio::test]
#[serial(gpu)]
async fn gpu_workload_manifest_runs_expected_workloads() {
    let Some(manifest) = load_workload_manifest() else {
        return;
    };

    let gpu_workloads = manifest
        .workloads
        .into_iter()
        .filter(|workload| workload.requirements.gpu)
        .collect::<Vec<_>>();

    assert!(
        !gpu_workloads.is_empty(),
        "workload manifest contains no GPU-tagged workloads"
    );

    for workload in gpu_workloads {
        assert!(
            !workload.command.is_empty(),
            "workload '{}' must declare a non-empty command",
            workload.name
        );

        match workload.expect {
            WorkloadExpectation::Pass => assert_expected_pass(&workload).await,
            WorkloadExpectation::Fail => assert_expected_fail(&workload).await,
        }
    }
}
