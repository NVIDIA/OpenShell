// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-docker")]

//! A rejected image/provider composition must never launch its main process.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::{openshell_bin, openshell_cmd};
use openshell_e2e::harness::cli::run_cli;
use openshell_e2e::harness::container::{ContainerEngine, ImageGuard};
use openshell_e2e::harness::output::strip_ansi;

const MARKER: &str = "/sandbox/activation-count";
const WORKLOAD: &str = "echo started >> /sandbox/activation-count; exec sleep infinity";
const POLICY: &str = r"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /etc, /dev/urandom]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  image_api:
    endpoints:
      - host: api.example.com
        port: 443
    binaries:
      - path: /usr/bin/curl
";

struct Resources {
    sandbox: String,
    standalone_sandbox: Option<String>,
    provider: String,
}

impl Drop for Resources {
    fn drop(&mut self) {
        // Deletion drains asynchronously; retry dependencies on panic as well.
        let bin = openshell_bin();
        let _ = std::process::Command::new(&bin)
            .args(["sandbox", "delete", &self.sandbox])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if let Some(sandbox) = &self.standalone_sandbox {
            let _ = std::process::Command::new(&bin)
                .args(["sandbox", "delete", sandbox])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        for _ in 0..20 {
            let deleted = std::process::Command::new(&bin)
                .args(["provider", "delete", &self.provider])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if deleted.is_ok_and(|status| status.success()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let _ = std::process::Command::new(&bin)
            .args(["provider", "profile", "delete", &self.provider])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

async fn cli_ok(args: &[&str]) {
    let (output, code) = run_cli(args).await;
    assert_eq!(code, 0, "{} failed:\n{output}", args.join(" "));
}

fn container_id(engine: &ContainerEngine, name: &str) -> String {
    role_container_id(engine, name, "sandbox")
}

fn role_container_id(engine: &ContainerEngine, name: &str, role: &str) -> String {
    let output = engine
        .command()
        .args([
            "ps",
            "--quiet",
            "--filter",
            &format!("label=openshell.ai/sandbox-name={name}"),
            "--filter",
            &format!("label=openshell.ai/isolation-role={role}"),
        ])
        .output()
        .expect("find sandbox container");
    assert!(output.status.success(), "container lookup failed");
    let ids = String::from_utf8_lossy(&output.stdout);
    let ids: Vec<_> = ids.split_whitespace().collect();
    assert_eq!(
        ids.len(),
        1,
        "expected one running {role} container: {ids:?}"
    );
    ids[0].to_string()
}

fn assert_marker(engine: &ContainerEngine, container: &str, started: bool) {
    let script = if started {
        format!("test -f {MARKER} && test \"$(wc -l < {MARKER})\" -eq 1")
    } else {
        format!("test ! -e {MARKER}")
    };
    let output = engine
        .command()
        .args(["exec", container, "sh", "-c", &script])
        .output()
        .expect("inspect actual workload marker");
    assert!(
        output.status.success(),
        "workload marker assertion failed (started={started}): {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn wait_for_marker(engine: &ContainerEngine, container: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let output = engine
            .command()
            .args(["exec", container, "test", "-f", MARKER])
            .output()
            .unwrap();
        if output.status.success() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "admitted workload did not start"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_marker(engine, container, true);
}

fn build_policy_image(context: &Path, label: &str, policy: &str) -> ImageGuard {
    std::fs::write(context.join("policy.yaml"), policy).unwrap();
    std::fs::write(context.join("Dockerfile"), r#"FROM public.ecr.aws/docker/library/python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/* \
    && groupadd sandbox && useradd -m -g sandbox sandbox && mkdir -p /sandbox && chown sandbox:sandbox /sandbox
COPY policy.yaml /etc/openshell/policy.yaml
WORKDIR /sandbox
USER sandbox
CMD ["sh", "-c", "echo started >> /sandbox/activation-count; exec sleep infinity"]
"#).unwrap();
    ImageGuard::build(label, &context.join("Dockerfile"), context).unwrap()
}

#[tokio::test]
async fn invalid_image_provider_bundle_waits_for_repair_before_launch() {
    let suffix = format!("{:016x}", rand::random::<u64>());
    let standalone = format!("al-{suffix}");
    let resources = Resources {
        sandbox: format!("ac-{suffix}"),
        standalone_sandbox: Some(standalone.clone()),
        provider: format!("ap-{suffix}"),
    };
    let context = tempfile::tempdir().unwrap();
    let image = build_policy_image(context.path(), "policy-activation", POLICY);
    // The very same embedded policy is valid before provider composition.
    tokio::time::timeout(
        Duration::from_secs(120),
        cli_ok(&[
            "sandbox",
            "create",
            "--name",
            &standalone,
            "--detach",
            "--from",
            image.tag(),
            "--",
            "sh",
            "-c",
            WORKLOAD,
        ]),
    )
    .await
    .expect("standalone image policy activates");
    let engine = ContainerEngine::from_env().unwrap();
    wait_for_marker(&engine, &container_id(&engine, &standalone)).await;
    cli_ok(&["sandbox", "delete", &standalone]).await;

    let profile = context.path().join("provider.yaml");
    std::fs::write(
        &profile,
        format!(
            r"id: {}
display_name: Activation test
category: other
credentials:
  - name: token
    env_vars: [ACTIVATION_TOKEN]
    required: true
    auth_style: bearer
    header_name: authorization
endpoints:
  - host: api.example.com
    port: 443
    protocol: rest
    access: full
binaries:
  - path: /usr/bin/curl
",
            resources.provider
        ),
    )
    .unwrap();
    cli_ok(&[
        "provider",
        "profile",
        "import",
        "--file",
        profile.to_str().unwrap(),
    ])
    .await;
    cli_ok(&[
        "provider",
        "create",
        "--name",
        &resources.provider,
        "--type",
        &resources.provider,
        "--credential",
        "ACTIVATION_TOKEN=activation-test-not-a-real-secret",
    ])
    .await;
    let mut create = openshell_cmd()
        .args([
            "sandbox",
            "create",
            "--name",
            &resources.sandbox,
            "--detach",
            "--from",
            image.tag(),
            "--provider",
            &resources.provider,
            "--",
            "sh",
            "-c",
            WORKLOAD,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start sandbox create");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let (output, code) =
            run_cli(&["sandbox", "get", &resources.sandbox, "--output", "json"]).await;
        let clean = strip_ansi(&output);
        if code == 0 && clean.contains("ConfigurationInvalid") {
            let details: serde_json::Value = serde_json::from_str(&clean).expect("sandbox JSON");
            let phase = details
                .get("phase")
                .and_then(serde_json::Value::as_str)
                .expect("sandbox detail must expose a phase string");
            assert_eq!(
                phase, "Provisioning",
                "rejected configuration must not be usable"
            );
            assert!(!clean.contains("activation-test-not-a-real-secret"));
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "configuration did not reject:\n{clean}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let container = container_id(&engine, &resources.sandbox);
    let supervisor = role_container_id(&engine, &resources.sandbox, "supervisor");
    assert_marker(&engine, &container, false);
    // Repeated observation distinguishes a stable gate from a crash/relaunch loop.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(container_id(&engine, &resources.sandbox), container);
    assert_eq!(
        role_container_id(&engine, &resources.sandbox, "supervisor"),
        supervisor
    );
    let restarts = engine
        .command()
        .args(["inspect", "--format", "{{.RestartCount}}", &supervisor])
        .output()
        .expect("inspect supervisor restart count");
    assert!(restarts.status.success());
    assert_eq!(
        String::from_utf8_lossy(&restarts.stdout).trim(),
        "0",
        "invalid configuration must not crash-loop"
    );
    assert_marker(&engine, &container, false);
    let logs = engine
        .command()
        .args(["logs", &supervisor])
        .output()
        .expect("read quarantined supervisor logs");
    assert!(logs.status.success());
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&logs.stdout),
        String::from_utf8_lossy(&logs.stderr)
    );
    assert_eq!(
        logs.matches("credentialed endpoint 'api.example.com:443'")
            .count(),
        1,
        "unchanged startup rejection must be logged only once: {logs}"
    );
    assert!(!logs.contains("Creating OPA engine from proto policy data"));
    let repaired = context.path().join("repaired.yaml");
    std::fs::write(
        &repaired,
        POLICY.replace(
            "        port: 443",
            "        port: 443\n        protocol: rest\n        access: full",
        ),
    )
    .unwrap();
    cli_ok(&[
        "policy",
        "set",
        &resources.sandbox,
        "--policy",
        repaired.to_str().unwrap(),
    ])
    .await;
    let status = tokio::time::timeout(Duration::from_secs(120), create.wait())
        .await
        .expect("create completes after repair")
        .expect("wait for create");
    assert!(status.success(), "create failed after valid repair");
    wait_for_marker(&engine, &container).await;
    // An invalid later replacement must not displace the admitted live policy.
    let (output, code) = run_cli(&[
        "policy",
        "set",
        &resources.sandbox,
        "--policy",
        context.path().join("policy.yaml").to_str().unwrap(),
    ])
    .await;
    assert_ne!(
        code, 0,
        "unsafe replacement unexpectedly succeeded: {output}"
    );
    assert_marker(&engine, &container, true);
    // An explicit stop/start must run the admission gate again before the saved
    // command launches. Clear the marker to distinguish that new launch.
    let removed = engine
        .command()
        .args(["exec", &container, "rm", "-f", MARKER])
        .status()
        .unwrap();
    assert!(removed.success());
    cli_ok(&["sandbox", "stop", &resources.sandbox]).await;
    tokio::time::timeout(
        Duration::from_secs(120),
        cli_ok(&["sandbox", "start", &resources.sandbox]),
    )
    .await
    .expect("repaired configuration revalidates on restart");
    let restarted_container = container_id(&engine, &resources.sandbox);
    wait_for_marker(&engine, &restarted_container).await;
    drop(create);
    drop(resources);
    drop(image);
}

async fn wait_for_admission(name: &str, phase: &str, admission: &str) -> serde_json::Value {
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let (output, code) = run_cli(&["sandbox", "get", name, "--output", "json"]).await;
            if code == 0 {
                let details: serde_json::Value =
                    serde_json::from_str(&strip_ansi(&output)).expect("sandbox JSON");
                if details["phase"] == phase
                    && details["configuration_admission"]["state"] == admission
                {
                    return details;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("sandbox did not reach {phase} with {admission} admission"))
}

fn running_container_start(engine: &ContainerEngine, container: &str) -> String {
    let output = engine
        .command()
        .args(["inspect", container])
        .output()
        .expect("inspect runtime container");
    assert!(output.status.success());
    let inspected: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(inspected[0]["State"]["Running"], true);
    assert_eq!(inspected[0]["RestartCount"], 0, "runtime must not restart");
    inspected[0]["State"]["StartedAt"]
        .as_str()
        .expect("container start time")
        .to_owned()
}

#[tokio::test]
async fn image_policy_missing_provider_recovers_after_attachment_without_relaunch() {
    let suffix = format!("{:016x}", rand::random::<u64>());
    let resources = Resources {
        sandbox: format!("ar-{suffix}"),
        standalone_sandbox: None,
        provider: format!("ap-{suffix}"),
    };
    let context = tempfile::tempdir().unwrap();
    let policy = POLICY.replace(
        "        port: 443",
        &format!(
            "        port: 443\n        protocol: rest\n        access: full\n        credential_binding:\n          provider: {}",
            resources.provider
        ),
    );
    let image = build_policy_image(context.path(), "missing-provider-activation", &policy);
    let profile = context.path().join("provider.yaml");
    // The image owns endpoint selection. An explicit credential binding requires
    // an endpointless profile, so attachment alone makes this policy valid.
    std::fs::write(
        &profile,
        format!(
            r"id: {}
display_name: Startup repair test
category: other
credentials:
  - name: token
    env_vars: [ACTIVATION_TOKEN]
    required: true
    auth_style: bearer
    header_name: authorization
endpoints: []
binaries: []
",
            resources.provider
        ),
    )
    .unwrap();
    cli_ok(&[
        "provider",
        "profile",
        "import",
        "--file",
        profile.to_str().unwrap(),
    ])
    .await;
    cli_ok(&[
        "provider",
        "create",
        "--name",
        &resources.provider,
        "--type",
        &resources.provider,
        "--credential",
        "ACTIVATION_TOKEN=activation-test-not-a-real-secret",
    ])
    .await;
    // No policy or provider is supplied at create time: the rejected write must
    // originate from the supervisor loading the policy embedded in the image.
    let mut create = openshell_cmd()
        .env_remove("OPENSHELL_SANDBOX_POLICY")
        .args([
            "sandbox",
            "create",
            "--name",
            &resources.sandbox,
            "--detach",
            "--from",
            image.tag(),
            "--no-auto-providers",
            "--",
            "sh",
            "-c",
            WORKLOAD,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start sandbox create");
    let rejected = wait_for_admission(&resources.sandbox, "Provisioning", "rejected").await;
    let sandbox_id = rejected["id"].as_str().expect("sandbox ID").to_owned();
    assert!(
        rejected["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|condition| {
                condition["type"] == "ConfigurationReady"
                    && condition["status"] == "False"
                    && condition["reason"] == "ConfigurationInvalid"
            })
    );
    let engine = ContainerEngine::from_env().unwrap();
    let container = container_id(&engine, &resources.sandbox);
    let supervisor = role_container_id(&engine, &resources.sandbox, "supervisor");
    let container_start = running_container_start(&engine, &container);
    let supervisor_start = running_container_start(&engine, &supervisor);
    assert_marker(&engine, &container, false);
    // Observe several reconciliation attempts while the exact rejected input
    // remains unchanged. The runtime must stay alive without launching main.
    tokio::time::sleep(Duration::from_secs(12)).await;
    assert_marker(&engine, &container, false);
    assert_eq!(container_id(&engine, &resources.sandbox), container);
    assert_eq!(
        role_container_id(&engine, &resources.sandbox, "supervisor"),
        supervisor
    );
    assert_eq!(
        running_container_start(&engine, &container),
        container_start
    );
    assert_eq!(
        running_container_start(&engine, &supervisor),
        supervisor_start
    );
    let logs = engine
        .command()
        .args(["logs", &supervisor])
        .output()
        .unwrap();
    assert!(logs.status.success());
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&logs.stdout),
        String::from_utf8_lossy(&logs.stderr)
    );
    assert_eq!(logs.matches("Gateway rejected the image policy").count(), 1);
    assert!(logs.contains("not attached to the sandbox"));
    assert!(!logs.contains("activation-test-not-a-real-secret"));

    // Do not wait on the attachment receipt: saving the image policy changes
    // its configuration identity. Observe the sandbox's current admission.
    assert!(
        create.try_wait().expect("inspect sandbox create").is_none(),
        "create must wait for the image policy to become valid"
    );
    cli_ok(&[
        "sandbox",
        "provider",
        "attach",
        &resources.sandbox,
        &resources.provider,
        "-o",
        "json",
    ])
    .await;
    let status = tokio::time::timeout(Duration::from_secs(120), create.wait())
        .await
        .expect("create completes after provider attachment")
        .expect("wait for create");
    assert!(status.success(), "create failed after provider attachment");
    let accepted = wait_for_admission(&resources.sandbox, "Ready", "accepted").await;
    assert_eq!(accepted["id"], sandbox_id);
    assert_eq!(container_id(&engine, &resources.sandbox), container);
    assert_eq!(
        role_container_id(&engine, &resources.sandbox, "supervisor"),
        supervisor
    );
    assert_eq!(
        running_container_start(&engine, &container),
        container_start
    );
    assert_eq!(
        running_container_start(&engine, &supervisor),
        supervisor_start
    );
    wait_for_marker(&engine, &container).await;
    let (saved, code) = run_cli(&[
        "policy",
        "get",
        &resources.sandbox,
        "--base",
        "--output",
        "json",
    ])
    .await;
    assert_eq!(code, 0, "fetch saved image policy: {saved}");
    let saved: serde_json::Value =
        serde_json::from_str(&strip_ansi(&saved)).expect("saved policy JSON");
    assert_eq!(
        saved["policy"]["network_policies"]["image_api"]["endpoints"][0]["credential_binding"]["provider"],
        resources.provider
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_marker(&engine, &container, true);
    drop(create);
    drop(resources);
    drop(image);
}
