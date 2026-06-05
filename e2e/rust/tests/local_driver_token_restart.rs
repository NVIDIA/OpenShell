// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! Local-driver E2E regression for sandbox supervisor restart from bootstrap
//! JWT material. Docker and Podman supervisors reload their mounted token file
//! after a container restart. VM sandboxes reboot from persisted driver state
//! after the VM driver restarts. Local single-player gateway configs should
//! mint that token with `exp = 0` so reconnect does not depend on token refresh.

use std::fs;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use base64::Engine as _;
use openshell_e2e::harness::cli::{wait_for_healthy, wait_for_sandbox_exec_contains};
use openshell_e2e::harness::container::{ContainerEngine, e2e_driver};
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::sandbox::SandboxGuard;
use prost::Message;
use tokio::time::sleep;

const READY_MARKER: &str = "local-driver-token-restart-ready";
const RESTART_FILE: &str = "/sandbox/local-driver-token-restart-state";
const CONTAINER_TOKEN_MOUNT_PATH: &str = "/etc/openshell/auth/sandbox.jwt";
const VM_STATE_DIR_ENV: &str = "OPENSHELL_E2E_VM_STATE_DIR";

#[derive(Clone, PartialEq, Message)]
struct PersistedDriverSandbox {
    #[prost(string, tag = "2")]
    name: String,
    #[prost(message, optional, tag = "4")]
    spec: Option<PersistedDriverSandboxSpec>,
}

#[derive(Clone, PartialEq, Message)]
struct PersistedDriverSandboxSpec {
    #[prost(string, tag = "11")]
    sandbox_token: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalDriver {
    Docker,
    Podman,
    Vm,
}

impl LocalDriver {
    fn from_env() -> Option<Self> {
        match e2e_driver().as_deref() {
            Some("docker") => Some(Self::Docker),
            Some("podman") => Some(Self::Podman),
            Some("vm") => Some(Self::Vm),
            _ => None,
        }
    }

    fn is_container(self) -> bool {
        matches!(self, Self::Docker | Self::Podman)
    }

    fn container_filters(self, namespace: &str, sandbox_name: &str) -> Vec<String> {
        match self {
            Self::Docker => vec![
                "label=openshell.ai/managed-by=openshell".to_string(),
                format!("label=openshell.ai/sandbox-namespace={namespace}"),
                format!("label=openshell.ai/sandbox-name={sandbox_name}"),
            ],
            Self::Podman => vec![
                "label=openshell.managed=true".to_string(),
                format!("label=openshell.sandbox-name={sandbox_name}"),
            ],
            Self::Vm => Vec::new(),
        }
    }
}

fn run_engine(engine: &ContainerEngine, args: &[String]) -> Result<String, String> {
    let output = engine
        .command()
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| format!("failed to run {} {}: {err}", engine.name(), args.join(" ")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    if !output.status.success() {
        return Err(format!(
            "{} {} failed (exit {:?}):\n{combined}",
            engine.name(),
            args.join(" "),
            output.status.code()
        ));
    }
    Ok(stdout.trim().to_string())
}

fn sandbox_container_id(
    engine: &ContainerEngine,
    driver: LocalDriver,
    namespace: &str,
    sandbox_name: &str,
) -> Result<String, String> {
    let mut args = vec!["ps".to_string(), "-aq".to_string()];
    for filter in driver.container_filters(namespace, sandbox_name) {
        args.push("--filter".to_string());
        args.push(filter);
    }

    let stdout = run_engine(engine, &args)?;
    let ids = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    match ids.as_slice() {
        [id] => Ok((*id).to_string()),
        [] => Err(format!(
            "no {driver:?} container found for sandbox '{sandbox_name}' in namespace '{namespace}'"
        )),
        _ => Err(format!(
            "multiple {driver:?} containers found for sandbox '{sandbox_name}' in namespace '{namespace}': {ids:?}"
        )),
    }
}

fn container_running(engine: &ContainerEngine, container_id: &str) -> Result<bool, String> {
    let output = run_engine(
        engine,
        &[
            "inspect".to_string(),
            "-f".to_string(),
            "{{.State.Running}}".to_string(),
            container_id.to_string(),
        ],
    )?;
    match output.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!(
            "unexpected running state for container {container_id}: {other}"
        )),
    }
}

async fn wait_for_container_running(
    engine: &ContainerEngine,
    container_id: &str,
    expected: bool,
    timeout: Duration,
) -> Result<(), String> {
    let start = Instant::now();

    loop {
        let last_state = match container_running(engine, container_id) {
            Ok(running) if running == expected => return Ok(()),
            Ok(running) => format!("running={running}"),
            Err(err) => err,
        };

        if start.elapsed() > timeout {
            return Err(format!(
                "container {container_id} did not reach running={expected} within {}s. Last state: {last_state}",
                timeout.as_secs()
            ));
        }
        sleep(Duration::from_secs(1)).await;
    }
}

fn read_bootstrap_token(engine: &ContainerEngine, container_id: &str) -> Result<String, String> {
    run_engine(
        engine,
        &[
            "exec".to_string(),
            container_id.to_string(),
            "cat".to_string(),
            CONTAINER_TOKEN_MOUNT_PATH.to_string(),
        ],
    )
}

fn read_vm_bootstrap_token(sandbox_name: &str) -> Result<String, String> {
    let state_dir = std::env::var_os(VM_STATE_DIR_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{VM_STATE_DIR_ENV} must be set for VM restart coverage"))?;
    let sandboxes_dir = state_dir.join("sandboxes");
    let entries = fs::read_dir(&sandboxes_dir)
        .map_err(|err| format!("read VM sandboxes dir '{}': {err}", sandboxes_dir.display()))?;

    let mut decoded_names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| {
            format!(
                "read VM sandbox dir entry under '{}': {err}",
                sandboxes_dir.display()
            )
        })?;
        let request_path = entry.path().join("sandbox.pb");
        let bytes = match fs::read(&request_path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(format!(
                    "read VM sandbox request '{}': {err}",
                    request_path.display()
                ));
            }
        };

        let sandbox = PersistedDriverSandbox::decode(bytes.as_slice()).map_err(|err| {
            format!(
                "decode VM sandbox request '{}': {err}",
                request_path.display()
            )
        })?;
        decoded_names.push(sandbox.name.clone());
        if sandbox.name != sandbox_name {
            continue;
        }

        let spec = sandbox
            .spec
            .ok_or_else(|| format!("VM sandbox '{sandbox_name}' is missing driver spec"))?;
        if spec.sandbox_token.trim().is_empty() {
            return Err(format!(
                "VM sandbox '{sandbox_name}' persisted driver spec has no sandbox token"
            ));
        }
        return Ok(spec.sandbox_token);
    }

    Err(format!(
        "no VM sandbox request found for '{sandbox_name}' under '{}'. Decoded sandbox names: {decoded_names:?}",
        sandboxes_dir.display()
    ))
}

fn token_exp_claim(token: &str) -> Result<i64, String> {
    let payload_b64 = token
        .trim()
        .split('.')
        .nth(1)
        .ok_or_else(|| "sandbox JWT has no payload segment".to_string())?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|err| format!("failed to decode sandbox JWT payload: {err}"))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|err| format!("failed to parse sandbox JWT claims: {err}"))?;
    claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| format!("sandbox JWT missing integer exp claim: {claims}"))
}

fn require_non_expiring_token(token: &str, context: &str) -> Result<(), String> {
    let exp = token_exp_claim(token)?;
    if exp != 0 {
        return Err(format!("{context} should use exp=0, got exp={exp}"));
    }
    Ok(())
}

async fn restart_container_sandbox(
    engine: &ContainerEngine,
    driver: LocalDriver,
    namespace: &str,
    sandbox_name: &str,
) -> Result<(), String> {
    let container_id = sandbox_container_id(engine, driver, namespace, sandbox_name)?;
    let token = read_bootstrap_token(engine, &container_id)?;
    require_non_expiring_token(&token, "local-driver bootstrap JWT")?;

    run_engine(engine, &["stop".to_string(), container_id.clone()])?;
    wait_for_container_running(engine, &container_id, false, Duration::from_secs(60)).await?;

    run_engine(engine, &["start".to_string(), container_id.clone()])?;
    wait_for_container_running(engine, &container_id, true, Duration::from_secs(60)).await
}

async fn restart_vm_sandbox(gateway: &ManagedGateway, sandbox_name: &str) -> Result<(), String> {
    let token = read_vm_bootstrap_token(sandbox_name)?;
    require_non_expiring_token(&token, "VM bootstrap JWT")?;

    gateway.stop()?;
    gateway.start()?;
    wait_for_healthy(Duration::from_secs(120)).await
}

async fn wait_for_driver_reconnect(
    driver: LocalDriver,
    sandbox_name: &str,
) -> Result<(), String> {
    match driver {
        LocalDriver::Docker | LocalDriver::Podman => {
            wait_for_sandbox_exec_contains(
                sandbox_name,
                &["cat", RESTART_FILE],
                "before-local-driver-restart",
                Duration::from_secs(240),
            )
            .await
        }
        LocalDriver::Vm => {
            wait_for_sandbox_exec_contains(
                sandbox_name,
                &["echo", "vm-reconnect-ok"],
                "vm-reconnect-ok",
                Duration::from_secs(240),
            )
            .await
        }
    }
}

#[tokio::test]
async fn local_driver_sandbox_restarts_with_non_expiring_bootstrap_jwt() {
    let Some(driver) = LocalDriver::from_env() else {
        eprintln!("Skipping local-driver token restart test: e2e driver is not Docker, Podman, or VM");
        return;
    };
    let namespace = if driver.is_container() {
        let Some(namespace) = std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE")
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            eprintln!(
                "Skipping local-driver token restart test: OPENSHELL_E2E_SANDBOX_NAMESPACE is unavailable"
            );
            return;
        };
        Some(namespace)
    } else {
        None
    };
    let engine = driver.is_container().then(ContainerEngine::from_env);
    let gateway = if driver == LocalDriver::Vm {
        let Some(gateway) = ManagedGateway::from_env().expect("load managed e2e gateway metadata")
        else {
            eprintln!(
                "Skipping local-driver token restart test: VM e2e gateway is not managed by this test run"
            );
            return;
        };
        Some(gateway)
    } else {
        None
    };

    wait_for_healthy(Duration::from_secs(30))
        .await
        .expect("gateway should start healthy");

    let script = format!(
        "echo before-local-driver-restart > {RESTART_FILE}; echo {READY_MARKER}; while true; do sleep 1; done"
    );
    let mut sandbox = SandboxGuard::create_keep(&["sh", "-lc", &script], READY_MARKER)
        .await
        .expect("create long-running local-driver sandbox");

    match driver {
        LocalDriver::Docker | LocalDriver::Podman => {
            let engine = engine.as_ref().expect("container engine should be set");
            let namespace = namespace
                .as_deref()
                .expect("container namespace should be set");
            restart_container_sandbox(engine, driver, namespace, &sandbox.name)
                .await
                .expect("restart sandbox container");
        }
        LocalDriver::Vm => {
            let gateway = gateway.as_ref().expect("managed VM gateway should be set");
            restart_vm_sandbox(gateway, &sandbox.name)
                .await
                .expect("restart e2e VM gateway");
        }
    }

    wait_for_driver_reconnect(driver, &sandbox.name)
        .await
        .expect("sandbox supervisor should reconnect after local-driver restart");

    sandbox.cleanup().await;
}
