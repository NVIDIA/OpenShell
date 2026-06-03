// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! GPU workload validation e2e tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde::Deserialize;
use serial_test::serial;
use tokio::time::timeout;

const WORKLOAD_MANIFEST_ENV: &str = "OPENSHELL_E2E_WORKLOAD_MANIFEST";
const GPU_WORKLOAD_SUCCESS_MARKER: &str = "OPENSHELL_GPU_WORKLOAD_SUCCESS";
const GPU_WORKLOAD_FAILURE_MARKER: &str = "OPENSHELL_GPU_WORKLOAD_FAILURE";
const WORKLOAD_SANDBOX_CREATE_TIMEOUT: Duration = Duration::from_secs(600);

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

async fn create_workload_sandbox(args: &[&str]) -> Result<SandboxGuard, String> {
    timeout(WORKLOAD_SANDBOX_CREATE_TIMEOUT, SandboxGuard::create(args))
        .await
        .map_err(|_| {
            format!(
                "GPU workload sandbox create timed out after {WORKLOAD_SANDBOX_CREATE_TIMEOUT:?}"
            )
        })?
}

async fn assert_expected_pass(workload: &WorkloadDefinition) {
    let mut args = vec![
        "--gpu".to_string(),
        "--from".to_string(),
        workload.image.clone(),
        "--".to_string(),
    ];
    args.extend(workload.command.clone());
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();

    let mut guard = create_workload_sandbox(&arg_refs)
        .await
        .unwrap_or_else(|err| {
            panic!(
                "GPU workload '{}' expected success but sandbox create failed:\n{err}",
                workload.name
            )
        });

    let clean_output = strip_ansi(&guard.create_output);
    guard.cleanup().await;

    assert!(
        clean_output.contains(GPU_WORKLOAD_SUCCESS_MARKER),
        "expected success marker {GPU_WORKLOAD_SUCCESS_MARKER} for workload '{}' image {} in sandbox output:\n{clean_output}",
        workload.name,
        workload.image,
    );
}

async fn assert_expected_fail(workload: &WorkloadDefinition) {
    let mut args = vec![
        "--gpu".to_string(),
        "--from".to_string(),
        workload.image.clone(),
        "--".to_string(),
    ];
    args.extend(workload.command.clone());
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();

    match create_workload_sandbox(&arg_refs).await {
        Ok(mut guard) => {
            let clean_output = strip_ansi(&guard.create_output);
            guard.cleanup().await;
            panic!(
                "GPU workload '{}' unexpectedly succeeded. Output:\n{clean_output}",
                workload.name
            );
        }
        Err(err) => {
            let clean_output = strip_ansi(&err);
            assert!(
                clean_output.contains(GPU_WORKLOAD_FAILURE_MARKER),
                "expected failure marker {GPU_WORKLOAD_FAILURE_MARKER} for workload '{}' image {} in failure output:\n{clean_output}",
                workload.name,
                workload.image,
            );
        }
    }
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
