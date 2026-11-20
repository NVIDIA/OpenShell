// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! VM-driver E2E regression for sandbox bootstrap JWT material. Launch-scoped
//! bootstrap tokens must remain valid long enough for driver recovery, so
//! restarting the VM gateway reconnects the running sandbox. The Docker and
//! Podman stop-is-terminal checks live in `tests/suites/drivers`.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use openshell_e2e::harness::cli::{wait_for_healthy, wait_for_sandbox_exec_contains};
use openshell_e2e::harness::container::e2e_driver;
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::sandbox::SandboxGuard;
use prost::Message;

const READY_MARKER: &str = "local-driver-token-restart-ready";
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

fn require_unexpired_token(token: &str, context: &str) -> Result<(), String> {
    let exp = token_exp_claim(token)?;
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("system clock is before Unix epoch: {err}"))?
            .as_secs(),
    )
    .map_err(|_| "current Unix timestamp does not fit in i64".to_string())?;
    // Sandbox session tokens use exp=0 when no TTL is configured.
    if exp != 0 && exp <= now {
        return Err(format!(
            "{context} should expire in the future, got exp={exp}, now={now}"
        ));
    }
    Ok(())
}

async fn restart_vm_sandbox(gateway: &ManagedGateway, sandbox_name: &str) -> Result<(), String> {
    let token = read_vm_bootstrap_token(sandbox_name)?;
    require_unexpired_token(&token, "VM bootstrap JWT")?;

    gateway.stop()?;
    gateway.start()?;
    wait_for_healthy(Duration::from_mins(2)).await
}

#[tokio::test]
async fn vm_gateway_restart_reconnects_sandbox() {
    if e2e_driver().as_deref() != Some("vm") {
        eprintln!("Skipping VM driver restart test: e2e driver is not VM");
        return;
    }
    let Some(gateway) = ManagedGateway::from_env().expect("load managed e2e gateway metadata")
    else {
        eprintln!(
            "Skipping VM driver restart test: VM e2e gateway is not managed by this test run"
        );
        return;
    };

    wait_for_healthy(Duration::from_secs(30))
        .await
        .expect("gateway should start healthy");

    let script = format!("echo {READY_MARKER}; while true; do sleep 1; done");
    let mut sandbox = SandboxGuard::create_keep(&["sh", "-lc", &script], READY_MARKER)
        .await
        .expect("create long-running VM sandbox");

    restart_vm_sandbox(&gateway, &sandbox.name)
        .await
        .expect("restart e2e VM gateway");
    wait_for_sandbox_exec_contains(
        &sandbox.name,
        &["echo", "vm-reconnect-ok"],
        "vm-reconnect-ok",
        Duration::from_mins(4),
    )
    .await
    .expect("sandbox supervisor should reconnect after VM driver restart");

    sandbox.cleanup().await;
}
