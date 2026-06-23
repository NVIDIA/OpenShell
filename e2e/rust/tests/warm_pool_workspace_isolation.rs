// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Warm-pool workspace isolation (issue #1879, remediation #6).
//!
//! Validates the security-critical invariant that a warm-pooled sandbox's
//! writable `/sandbox` workspace is single-use: a secret written by one
//! sandbox must never be visible to a later sandbox claimed from the same
//! pool. With the ephemeral `emptyDir` workspace model the kubelet reclaims
//! `/sandbox` with the pod, so a re-claim always starts pristine.
//!
//! This test only runs when warm pooling is enabled in the deployed gateway —
//! set `OPENSHELL_E2E_WARM_POOL=1` and deploy with `server.warmPool.enabled`
//! (e.g. `OPENSHELL_E2E_KUBE_EXTRA_VALUES=deploy/helm/openshell/ci/values-warm-pool.yaml`).
//! It skips otherwise so the default Kubernetes e2e (cold path) is unaffected.

#![cfg(feature = "e2e-kubernetes")]

use std::io::Write as _;
use std::process::Stdio;

use openshell_e2e::harness::binary::{openshell_cmd, openshell_tty_cmd};
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const MARKER_PATH: &str = "/sandbox/TENANT-A-SECRET";

/// Label the Kubernetes driver stamps onto every sandbox-bound object, carrying
/// the gateway sandbox id (`openshell.ai/sandbox-id`). The warm path also sets
/// it on the `SandboxClaim`, so it doubles as the selector that tells a bound
/// warm claim apart from a cold (claim-less) Sandbox.
const SANDBOX_ID_LABEL: &str = "openshell.ai/sandbox-id";

fn warm_pool_enabled() -> bool {
    std::env::var("OPENSHELL_E2E_WARM_POOL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn normalize(output: &str) -> String {
    strip_ansi(output).replace('\r', "")
}

/// Run `sandbox create --no-keep -- sh -c <script>` and return combined output.
/// `--no-keep` tears the sandbox (and its warm claim) down after the command,
/// which is exactly the single-use teardown path under test.
async fn run_in_fresh_sandbox(script: &str) -> String {
    let mut cmd = openshell_tty_cmd(&["sandbox", "create", "--no-keep", "--", "sh", "-c", script]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = cmd.output().await.expect("spawn openshell sandbox create");
    let combined = normalize(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    assert!(
        output.status.success(),
        "sandbox create should succeed (exit {:?}):\n{combined}",
        output.status.code()
    );
    combined
}

#[tokio::test]
async fn warm_pool_workspace_is_not_reused_across_claims() {
    if !warm_pool_enabled() {
        eprintln!("skipping: OPENSHELL_E2E_WARM_POOL not set (warm pooling disabled)");
        return;
    }

    // Sandbox A: write a sensitive marker into the writable workspace.
    let wrote = run_in_fresh_sandbox(&format!(
        "echo TENANT-A-SECRET > {MARKER_PATH} && test -f {MARKER_PATH} && echo WROTE_MARKER"
    ))
    .await;
    assert!(
        wrote.contains("WROTE_MARKER"),
        "expected to write the workspace marker in sandbox A:\n{wrote}"
    );

    // Sandbox B: claimed fresh from the same pool. The marker must be absent —
    // the prior claim's workspace was single-use and reclaimed.
    let checked = run_in_fresh_sandbox(&format!(
        "if [ -f {MARKER_PATH} ]; then echo WORKSPACE_LEAKED; else echo WORKSPACE_CLEAN; fi"
    ))
    .await;
    assert!(
        checked.contains("WORKSPACE_CLEAN"),
        "re-claimed sandbox must not see the prior workspace marker:\n{checked}"
    );
    assert!(
        !checked.contains("WORKSPACE_LEAKED"),
        "workspace data leaked across warm-pool claims:\n{checked}"
    );
}

#[tokio::test]
async fn warm_pool_shared_volume_is_read_only() {
    if !warm_pool_enabled() {
        eprintln!("skipping: OPENSHELL_E2E_WARM_POOL not set (warm pooling disabled)");
        return;
    }
    // Only runs when a shared read-only volume is configured for the pool; its
    // mount path is provided via OPENSHELL_E2E_WARM_POOL_SHARED_MOUNT.
    let Ok(mount) = std::env::var("OPENSHELL_E2E_WARM_POOL_SHARED_MOUNT") else {
        eprintln!("skipping: OPENSHELL_E2E_WARM_POOL_SHARED_MOUNT not set");
        return;
    };

    let result = run_in_fresh_sandbox(&format!(
        "if touch {mount}/openshell-write-probe 2>/dev/null; then echo SHARED_WRITABLE; else echo SHARED_READONLY; fi"
    ))
    .await;
    assert!(
        result.contains("SHARED_READONLY"),
        "the shared data volume must be mounted read-only:\n{result}"
    );
}

// ---------------------------------------------------------------------------
// Cold-fallback guard
// ---------------------------------------------------------------------------

/// Build a minimal, valid sandbox policy with no network rules. Its contents
/// are irrelevant to the routing decision — *any* per-request policy forces the
/// cold path, since the warm pool can only run the baseline image policy.
fn write_minimal_policy() -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create temp policy file");
    let policy = r"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox
";
    file.write_all(policy.as_bytes())
        .expect("write temp policy file");
    file.flush().expect("flush temp policy file");
    file
}

/// Resolve the gateway sandbox id for a sandbox display name via
/// `sandbox list --output json`.
async fn sandbox_id_for(name: &str) -> String {
    let mut cmd = openshell_cmd();
    // `--limit` covers the server's max page size so the lookup never depends on
    // total sandbox count: the default 100-row first page is ordered oldest-first,
    // which could paginate a freshly-created sandbox out of view on a long-lived
    // cluster.
    cmd.args(["sandbox", "list", "--limit", "1000", "--output", "json"]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = cmd.output().await.expect("spawn openshell sandbox list");
    assert!(
        output.status.success(),
        "sandbox list should succeed (exit {:?}):\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let list: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("parse sandbox list JSON");
    list.as_array()
        .expect("sandbox list JSON should be an array")
        .iter()
        .find(|s| s.get("name").and_then(|v| v.as_str()) == Some(name))
        .and_then(|s| s.get("id").and_then(|v| v.as_str()))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("sandbox '{name}' not found in:\n{stdout}"))
}

/// True if a `SandboxClaim` exists for the given sandbox id (i.e. the warm path
/// was taken). Selects across all namespaces by the sandbox-id label so the
/// check is independent of the claim's `metadata.name` and the deploy namespace.
async fn warm_claim_exists(sandbox_id: &str) -> bool {
    let mut cmd = tokio::process::Command::new("kubectl");
    cmd.args([
        "get",
        "sandboxclaims.extensions.agents.x-k8s.io",
        "--all-namespaces",
        "-l",
        &format!("{SANDBOX_ID_LABEL}={sandbox_id}"),
        "-o",
        "name",
    ]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = cmd.output().await.expect("spawn kubectl");
    assert!(
        output.status.success(),
        "kubectl get sandboxclaims should succeed (exit {:?}):\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    !String::from_utf8_lossy(&output.stdout).trim().is_empty()
}

async fn kubectl_available() -> bool {
    tokio::process::Command::new("kubectl")
        .args(["version", "--client=true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A request carrying a custom policy must NOT be served from the warm pool:
/// the pool only runs the baseline image policy, so honoring the warm path
/// would silently downgrade the requested policy. The Kubernetes driver
/// enforces this in `warm_eligible` (gateway sets `disallow_warm_pool` whenever
/// a per-sandbox policy is present), and the routing decision is observable at
/// the API-object level — a warm request binds a `SandboxClaim`, a cold one
/// does not.
#[tokio::test]
async fn custom_policy_request_falls_back_to_cold_no_warm_claim() {
    if !warm_pool_enabled() {
        eprintln!("skipping: OPENSHELL_E2E_WARM_POOL not set (warm pooling disabled)");
        return;
    }
    if !kubectl_available().await {
        eprintln!("skipping: kubectl not available to inspect SandboxClaims");
        return;
    }

    // Baseline: a default request is warm-eligible and binds a SandboxClaim.
    // This proves the deployment under test really has a live warm pool, so the
    // missing claim below is genuine cold-fallback and not an absent pool.
    let warm = SandboxGuard::create(&["--", "sh", "-c", "echo READY"])
        .await
        .expect("create default (warm) sandbox");
    let warm_id = sandbox_id_for(&warm.name).await;
    assert!(
        warm_claim_exists(&warm_id).await,
        "a default request should bind a warm-pool SandboxClaim (id={warm_id}); \
         without this the cold-fallback assertion below would pass vacuously"
    );

    // Guard under test: a custom-policy request must fall back to cold — no
    // SandboxClaim. A bound claim here means the requested policy was silently
    // downgraded to the pool baseline, which is a security regression.
    let policy = write_minimal_policy();
    let cold = SandboxGuard::create(&[
        "--policy",
        policy.path().to_str().expect("policy path is valid UTF-8"),
        "--",
        "sh",
        "-c",
        "echo READY",
    ])
    .await
    .expect("create custom-policy (cold) sandbox");
    let cold_id = sandbox_id_for(&cold.name).await;
    assert!(
        !warm_claim_exists(&cold_id).await,
        "a custom-policy request must fall back to the cold path (no SandboxClaim); \
         a bound claim means the requested policy was silently downgraded to the \
         pool baseline (id={cold_id})"
    );
}
