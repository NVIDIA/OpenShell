// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Full gateway/supervisor qualification. Run only through the opt-in owned
//! gateway wrapper; authenticated API/exec, not direct driver test fixtures.

use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;
use testkit::sdk::raw::{AuthedGrpcClient, AuthedSandboxUpdatesClient, proto};
use testkit::{Context, ResultExt as _};

const POLICY: &str = "version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /bin, /sbin, /lib, /lib64, /etc, /app, /proc, /dev/urandom]
  read_write: [/tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: '1234'
  run_as_group: '1235'
network_policies: {}
";

fn docker(args: &[&str]) -> Value {
    let output = Command::new("docker")
        .args(args)
        .output()
        .expect("Docker test inspection");
    assert!(
        output.status.success(),
        "Docker inspection failed: {args:?}"
    );
    serde_json::from_slice(&output.stdout).expect("Docker JSON")
}

fn container(sandbox_id: &str) -> Value {
    let namespace = std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE").expect("owned namespace");
    let output = Command::new("docker")
        .args([
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            &format!("label=openshell.ai/sandbox-id={sandbox_id}"),
            "--filter",
            &format!("label=openshell.ai/sandbox-namespace={namespace}"),
            "--filter",
            "label=openshell.ai/isolation-role=sandbox",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let ids = String::from_utf8(output.stdout).unwrap();
    let ids: Vec<_> = ids.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(ids.len(), 1, "one owned native workload");
    docker(&["inspect", ids[0]])[0].clone()
}

fn workspace_volume(container: &Value) -> String {
    let mounts: Vec<_> = container["Mounts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|mount| mount["Destination"] == "/sandbox" && mount["Type"] == "volume")
        .collect();
    assert_eq!(mounts.len(), 1);
    mounts[0]["Name"].as_str().unwrap().into()
}

fn owned_volumes(sandbox_id: &str) -> Vec<String> {
    let output = Command::new("docker")
        .args([
            "volume",
            "ls",
            "-q",
            "--filter",
            &format!("label=openshell.ai/sandbox-id={sandbox_id}"),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn descriptor_path(sandbox_id: &str) -> PathBuf {
    let root = PathBuf::from(std::env::var_os("XDG_STATE_HOME").expect("owned wrapper state"));
    let pid = PathBuf::from(std::env::var_os("OPENSHELL_E2E_GATEWAY_PID_FILE").unwrap());
    assert_eq!(
        root.parent(),
        pid.parent(),
        "fault injection is limited to the wrapper's private state"
    );
    let mut pending = vec![(root, 0)];
    let mut matches = Vec::new();
    while let Some((directory, depth)) = pending.pop() {
        assert!(depth < 8);
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let metadata = entry.file_type().unwrap();
            if metadata.is_dir() {
                pending.push((entry.path(), depth + 1));
            } else if metadata.is_file() && entry.file_name() == "runtime-descriptor.json" {
                let value: Value =
                    serde_json::from_slice(&fs::read(entry.path()).unwrap()).unwrap();
                if value["boundary_id"] == sandbox_id {
                    matches.push(entry.path());
                }
            }
        }
    }
    assert_eq!(matches.len(), 1);
    matches.remove(0)
}

async fn get(client: &mut AuthedGrpcClient, workspace: &str, name: &str) -> proto::Sandbox {
    client
        .get_sandbox(proto::GetSandboxRequest {
            workspace_scope: Some(proto::workspace_selector(workspace)),
            name: name.into(),
        })
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap()
}

async fn update(
    client: &mut AuthedGrpcClient,
    updates: &mut AuthedSandboxUpdatesClient,
    workspace: &str,
    name: &str,
    id: &str,
    image: &str,
) -> proto::Sandbox {
    // Stop's final watch update can race its response. Retry only a definite
    // CAS conflict with a fresh version/request ID, never ambiguous acceptance.
    for attempt in 0..20 {
        let current = get(client, workspace, name).await;
        let metadata = current.metadata.unwrap();
        assert_eq!(metadata.id, id);
        assert_eq!(
            current.status.unwrap().phase,
            proto::SandboxPhase::Stopped as i32
        );
        let mut request = tonic::Request::new(proto::UpdateSandboxRequest {
            workspace_scope: Some(proto::workspace_selector(workspace)),
            name: name.into(),
            image: Some(image.into()),
            expected_resource_version: metadata.resource_version,
            request_id: uuid::Uuid::new_v4().to_string(),
            ..Default::default()
        });
        request.set_timeout(Duration::from_secs(70));
        match updates.update_sandbox(request).await {
            Ok(response) => return response.into_inner().sandbox.unwrap(),
            Err(error) => {
                let conflict = error.code() == tonic::Code::Aborted
                    && testkit::sdk::SdkError::from_status(error.clone())
                        .error_details()
                        .is_some_and(|details| {
                            details
                                .error_info()
                                .is_some_and(|info| info.reason == "RESOURCE_VERSION_CONFLICT")
                        });
                assert!(conflict && attempt < 19, "image update failed: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    unreachable!()
}

async fn restart_owned_gateway() {
    let path = |key| PathBuf::from(std::env::var_os(key).expect("owned wrapper restart metadata"));
    let binary = path("OPENSHELL_E2E_GATEWAY_BIN");
    let args_path = path("OPENSHELL_E2E_GATEWAY_ARGS_FILE");
    let pid_path = path("OPENSHELL_E2E_GATEWAY_PID_FILE");
    let log_path = path("OPENSHELL_E2E_GATEWAY_LOG");
    assert_eq!(args_path.parent(), pid_path.parent());
    assert_eq!(args_path.parent(), log_path.parent());
    let pid = fs::read_to_string(&pid_path)
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    let process = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .unwrap();
    assert!(
        process.status.success()
            && String::from_utf8_lossy(&process.stdout).contains(binary.to_str().unwrap())
    );
    assert!(
        Command::new("kill")
            .arg(pid.to_string())
            .status()
            .unwrap()
            .success()
    );
    let mut stopped = false;
    for _ in 0..120 {
        let process = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "stat="])
            .output()
            .unwrap();
        if !process.status.success()
            || String::from_utf8_lossy(&process.stdout)
                .trim()
                .starts_with('Z')
        {
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(stopped, "owned gateway must stop normally; no force-kill");
    let args = fs::read(args_path).unwrap();
    let args: Vec<_> = args
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| std::str::from_utf8(part).unwrap())
        .collect();
    let log = OpenOptions::new().append(true).open(log_path).unwrap();
    let mut child = Command::new(binary)
        .args(args)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    fs::write(pid_path, format!("{}\n", child.id())).unwrap();
    // The outer wrapper owns shutdown through the updated PID file. Reap an
    // early exit while the test is active without stopping the gateway before
    // testkit has cleaned up any tracked sandbox after a failed assertion.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    testkit::Gateway::from_env()
        .unwrap()
        .wait_ready(Duration::from_secs(120))
        .await
        .unwrap();
}

/// Authenticated workload use survives a stopped image replacement and gateway
/// restart with stable workspace/SSH identity, then API deletion removes data.
#[testkit::test]
async fn authenticated_replacement_restart_and_removal(cx: &mut Context) -> testkit::Result {
    assert_eq!(
        std::env::var("OPENSHELL_E2E_DOCKER_IMAGE_UPDATES").as_deref(),
        Ok("1"),
        "use the owned opt-in wrapper"
    );
    // Require restart metadata before creating any resources.
    std::env::var("OPENSHELL_E2E_GATEWAY_PID_FILE").expect("owned gateway required");
    cx.expect_compute_driver("docker").await?;
    let selected = testkit::Gateway::from_env()?;
    assert!(
        selected.endpoint.starts_with("https://"),
        "qualify authenticated TLS, not plaintext"
    );
    assert!(
        selected.describe().contains("(mTLS "),
        "qualify a mutually authenticated gateway"
    );
    let original_image =
        std::env::var("OPENSHELL_DOCKER_UPDATE_IMAGE_A").expect("prepared image A");
    let target_image = std::env::var("OPENSHELL_DOCKER_UPDATE_IMAGE_B").expect("prepared image B");
    let gateway = selected.connect().await?;
    let mut client = gateway.raw_grpc();
    let mut updates = gateway.raw_sandbox_updates();
    let sandbox = cx
        .cli_sandbox("image")
        .image(&original_image)
        .policy_yaml(POLICY)
        .command(["/bin/sh", "-c", "exec sleep 86400"])
        .create_ready()
        .await?;
    let original = get(&mut client, &selected.workspace, sandbox.name()).await;
    let id = &original.metadata.as_ref().unwrap().id;
    let mut unauthenticated_config = testkit::sdk::ClientConfig::new(&selected.endpoint);
    unauthenticated_config.ca_cert = Some(
        fs::read(std::env::var_os("OPENSHELL_E2E_GATEWAY_CA_CERT").expect("fixture CA")).unwrap(),
    );
    let unauthenticated_rejected =
        match testkit::sdk::OpenShellClient::connect(unauthenticated_config).await {
            Err(_) => true,
            Ok(anonymous) => anonymous
                .raw_grpc()
                .get_sandbox(proto::GetSandboxRequest {
                    workspace_scope: Some(proto::workspace_selector(&selected.workspace)),
                    name: sandbox.name().into(),
                })
                .await
                .is_err(),
        };
    assert!(
        unauthenticated_rejected,
        "the same gateway must reject a client without its mTLS identity"
    );
    assert_eq!(
        get(&mut client, &selected.workspace, sandbox.name())
            .await
            .metadata
            .unwrap()
            .id,
        *id
    );
    let fingerprint = &original.host_key_fingerprint;
    assert!(fingerprint.starts_with("SHA256:"));
    let before = container(id);
    assert_eq!(
        before["Config"]["Labels"]["openshell.ai/docker-workspace-storage"],
        "persistent-v1"
    );
    let volume = workspace_volume(&before);
    let volume_before = docker(&["volume", "inspect", &volume]);
    sandbox.exec(["/bin/sh", "-c", "test \"$(id -u):$(id -g)\" = 1234:1235; cat /app/version; printf preserved-session > /sandbox/session-record"]).await?.expect_stdout("A\n")?;
    cx.cli([
        "sandbox",
        "exec",
        sandbox.name(),
        "--",
        "/bin/cat",
        "/sandbox/session-record",
    ])
    .await?
    .success()?
    .expect_stdout("preserved-session")?;
    sandbox.stop().await?;
    let updated = update(
        &mut client,
        &mut updates,
        &selected.workspace,
        sandbox.name(),
        id,
        &target_image,
    )
    .await;
    assert_eq!(updated.metadata.as_ref().unwrap().id, *id);
    assert_eq!(updated.host_key_fingerprint, *fingerprint);
    let replaced = container(id);
    assert_ne!(replaced["Id"], before["Id"]);
    assert_ne!(replaced["Image"], before["Image"]);
    assert_eq!(workspace_volume(&replaced), volume);
    assert_eq!(replaced["State"]["Running"], false);
    sandbox.start().await?;
    sandbox.wait_ready().await?;
    let descriptor = descriptor_path(id);
    let previous_descriptor = fs::read(&descriptor).unwrap();
    sandbox
        .exec([
            "/bin/sh",
            "-c",
            "cat /app/version; cat /sandbox/session-record",
        ])
        .await?
        .expect_stdout("B\npreserved-session")?;
    cx.cli([
        "sandbox",
        "exec",
        sandbox.name(),
        "--",
        "/bin/cat",
        "/app/version",
    ])
    .await?
    .success()?
    .expect_stdout("B\n")?;
    restart_owned_gateway().await;
    sandbox
        .wait_ready()
        .await
        .context("same sandbox ready after gateway restart")?;
    sandbox
        .exec([
            "/bin/sh",
            "-c",
            "cat /app/version; cat /sandbox/session-record",
        ])
        .await?
        .expect_stdout("B\npreserved-session")?;
    cx.cli([
        "sandbox",
        "exec",
        sandbox.name(),
        "--",
        "/bin/cat",
        "/sandbox/session-record",
    ])
    .await?
    .success()?
    .expect_stdout("preserved-session")?;
    let restarted = selected.connect().await?;
    let recovered = get(
        &mut restarted.raw_grpc(),
        &selected.workspace,
        sandbox.name(),
    )
    .await;
    assert_eq!(recovered.metadata.as_ref().unwrap().id, *id);
    assert_eq!(recovered.host_key_fingerprint, *fingerprint);
    assert_eq!(container(id)["Id"], replaced["Id"]);
    assert_eq!(
        docker(&["volume", "inspect", &volume])[0]["CreatedAt"],
        volume_before[0]["CreatedAt"]
    );
    sandbox.stop().await?;
    sandbox.start().await?;
    sandbox.wait_ready().await?;
    sandbox
        .exec(["/bin/cat", "/sandbox/session-record"])
        .await?
        .expect_stdout("preserved-session")?;
    sandbox.stop().await?;
    let current: Value = serde_json::from_slice(&fs::read(&descriptor).unwrap()).unwrap();
    let previous: Value = serde_json::from_slice(&previous_descriptor).unwrap();
    assert_ne!(current["generation"], previous["generation"]);
    // Recreate the reviewed interruption: the bootstrap is from a newer
    // launch, but only the old descriptor survived. No running workload is
    // changed, and neither credential file is exported or printed.
    fs::write(&descriptor, &previous_descriptor).unwrap();
    sandbox.start().await?;
    sandbox.wait_ready().await?;
    sandbox
        .exec(["/bin/cat", "/sandbox/session-record"])
        .await?
        .expect_stdout("preserved-session")?;
    cx.cli([
        "sandbox",
        "exec",
        sandbox.name(),
        "--",
        "/bin/cat",
        "/app/version",
    ])
    .await?
    .success()?
    .expect_stdout("B\n")?;
    let repaired: Value = serde_json::from_slice(&fs::read(&descriptor).unwrap()).unwrap();
    let bootstrap: Value = serde_json::from_slice(
        &fs::read(descriptor.with_file_name("boundary-bootstrap.json")).unwrap(),
    )
    .unwrap();
    assert_ne!(repaired["generation"], previous["generation"]);
    assert_eq!(repaired["generation"], bootstrap["generation"]);
    assert_eq!(repaired["session_id"], bootstrap["session_id"]);
    assert_eq!(
        repaired["provisioning_evidence"],
        bootstrap["provisioning_evidence"]
    );
    let retained_volumes = owned_volumes(id);
    assert!(retained_volumes.contains(&volume) && retained_volumes.len() >= 4);
    sandbox.delete().await?;
    sandbox.expect_absent().await?;
    let native_id = replaced["Id"].as_str().unwrap();
    assert!(
        !Command::new("docker")
            .args(["container", "inspect", native_id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        !Command::new("docker")
            .args(["volume", "inspect", &volume])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        owned_volumes(id).is_empty(),
        "API deletion removed all sandbox-owned volumes"
    );
    assert!(
        !descriptor.exists(),
        "API deletion removed private runtime state"
    );
    println!(
        "qualification passed: authenticated mTLS API and SSH exec on A and B; stable sandbox/SSH identity and workspace; gateway restart; Stop/Start; interrupted credential-publication repair; API deletion removed native workload, all {} owned volumes and private runtime state",
        retained_volumes.len()
    );
    Ok(())
}
