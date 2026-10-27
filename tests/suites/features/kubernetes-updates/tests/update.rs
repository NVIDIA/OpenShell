// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exercise the public image-update RPC in both Agent Sandbox API-version lanes.
//! Kubernetes checks are scoped to test-owned resources.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;
use std::sync::LazyLock;
use testkit::sdk::raw::{AuthedGrpcClient, AuthedSandboxUpdatesClient, proto};
use testkit::{Context, Sandbox};

// Multi-platform release manifests; no test-local tags or cluster image loads.
const ORIGINAL_IMAGE_DEFAULT: &str = "mirror.gcr.io/library/alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507";
const UPDATED_IMAGE_DEFAULT: &str = "mirror.gcr.io/library/alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8";
const SENTINEL_PATH: &str = "/sandbox/.image-update-sentinel";

// CI can use a private mirror without changing the tested image versions.
static ORIGINAL_IMAGE: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OPENSHELL_E2E_UPDATE_ORIGINAL_IMAGE")
        .unwrap_or_else(|_| ORIGINAL_IMAGE_DEFAULT.into())
});
static UPDATED_IMAGE: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OPENSHELL_E2E_UPDATE_TARGET_IMAGE")
        .unwrap_or_else(|_| UPDATED_IMAGE_DEFAULT.into())
});

fn request_id() -> String {
    let mut bytes = rand::random::<[u8; 16]>();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn rpc<T>(body: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(body);
    request.set_timeout(Duration::from_secs(60));
    request
}

async fn get_sandbox(client: &mut AuthedGrpcClient, workspace: &str, name: &str) -> proto::Sandbox {
    client
        .get_sandbox(rpc(proto::GetSandboxRequest {
            workspace_scope: Some(proto::workspace_selector(workspace)),
            name: name.to_owned(),
        }))
        .await
        .expect("get test sandbox")
        .into_inner()
        .sandbox
        .expect("Sandbox response")
}

/// Stop can still be followed by driver-watch status writes. Refresh the CAS
/// version on a definite conflict, without retrying ambiguous driver failures.
async fn update_stopped_sandbox(
    client: &mut AuthedGrpcClient,
    updates: &mut AuthedSandboxUpdatesClient,
    workspace: &str,
    mut request: proto::UpdateSandboxRequest,
) -> (proto::Sandbox, proto::UpdateSandboxRequest) {
    let mut sandbox_id = None;
    for attempt in 0..20 {
        let current = get_sandbox(client, workspace, &request.name).await;
        let metadata = current.metadata.as_ref().expect("sandbox metadata");
        let id = sandbox_id.get_or_insert_with(|| metadata.id.clone());
        assert_eq!(
            &metadata.id, id,
            "conditional retry must not target a replacement"
        );
        let status = current.status.as_ref().expect("sandbox status");
        assert_eq!(status.phase, proto::SandboxPhase::Stopped as i32);
        assert!(
            status
                .provisioning
                .as_ref()
                .is_none_or(|record| !record.driver_operation_pending),
            "do not retry a newly selected update over a pending operation"
        );
        request.expected_resource_version = metadata.resource_version;
        if attempt > 0 && !request.request_id.is_empty() {
            // A changed version is a new request payload, not a replay.
            request.request_id = request_id();
        }
        match updates.update_sandbox(rpc(request.clone())).await {
            Ok(response) => {
                return (
                    response.into_inner().sandbox.expect("updated Sandbox"),
                    request,
                );
            }
            Err(error) => {
                let conflict = error.code() == tonic::Code::Aborted
                    && testkit::sdk::SdkError::from_status(error.clone())
                        .error_details()
                        .is_some_and(|details| {
                            details.error_info().is_some_and(|info| {
                                info.domain == "openshell.nvidia.com"
                                    && info.reason == "RESOURCE_VERSION_CONFLICT"
                            })
                        });
                assert!(
                    conflict && attempt < 19,
                    "update stopped sandbox: {error:?}"
                );
                eprintln!(
                    "refreshing sandbox {} after version conflict: {error}",
                    request.name
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    unreachable!("final conflict fails the test")
}

async fn kubectl_mutation(args: &[&str]) -> std::process::Output {
    let namespace = std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE").expect("test namespace");
    let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE").expect("test context");
    tokio::process::Command::new("kubectl")
        .args([
            "--context",
            &context,
            "--namespace",
            &namespace,
            "--request-timeout=30s",
        ])
        .args(args)
        .kill_on_drop(true)
        .output()
        .await
        .expect("kubectl mutation")
}

/// Exercise real API-server immutable UID validation independently of the
/// resourceVersion condition, after deleting and recreating the named resource.
async fn assert_recreated_resource_rejects_stale_patch(template: &Value, name: &str) {
    use std::io::Write as _;
    let resource = serde_json::json!({
        "apiVersion": template["apiVersion"], "kind": "Sandbox",
        "metadata": {"name": name}, "spec": template["spec"],
    });
    let mut file = tempfile::NamedTempFile::new().expect("test manifest");
    file.write_all(serde_json::to_string(&resource).unwrap().as_bytes())
        .unwrap();
    let path = file.path().to_str().unwrap();
    let create = kubectl_mutation(&["create", "-f", path, "-o", "json"]).await;
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    let original: Value = serde_json::from_slice(&create.stdout).unwrap();
    let delete = kubectl_mutation(&[
        "delete",
        "sandboxes.agents.x-k8s.io",
        name,
        "--wait=true",
        "--timeout=60s",
    ])
    .await;
    assert!(
        delete.status.success(),
        "{}",
        String::from_utf8_lossy(&delete.stderr)
    );
    let create = kubectl_mutation(&["create", "-f", path, "-o", "json"]).await;
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    let replacement: Value = serde_json::from_slice(&create.stdout).unwrap();
    let patch = serde_json::json!({"metadata": {
        "uid": original["metadata"]["uid"],
        "annotations": {"example.com/stale-patch": "must-not-apply"},
    }})
    .to_string();
    let rejected = kubectl_mutation(&[
        "patch",
        "sandboxes.agents.x-k8s.io",
        name,
        "--type=merge",
        "-p",
        &patch,
    ])
    .await;
    let after = kubectl_get("sandboxes.agents.x-k8s.io", &[name]).await;
    let cleanup = kubectl_mutation(&[
        "delete",
        "sandboxes.agents.x-k8s.io",
        name,
        "--wait=true",
        "--timeout=60s",
    ])
    .await;
    assert!(
        cleanup.status.success(),
        "{}",
        String::from_utf8_lossy(&cleanup.stderr)
    );
    assert_ne!(original["metadata"]["uid"], replacement["metadata"]["uid"]);
    assert!(!rejected.status.success(), "stale UID patch must fail");
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("metadata.uid"),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert!(after["metadata"]["annotations"]["example.com/stale-patch"].is_null());
}

async fn kubectl_get(resource: &str, selector: &[&str]) -> Value {
    let namespace = std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE")
        .expect("Kubernetes E2E wrapper must provide the sandbox namespace");
    let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        .expect("Kubernetes E2E wrapper must provide its active context");
    assert!(!namespace.trim().is_empty() && !context.trim().is_empty());
    let output = tokio::process::Command::new("kubectl")
        .args([
            "--context",
            &context,
            "--namespace",
            &namespace,
            "--request-timeout=30s",
            "get",
            resource,
        ])
        .args(selector)
        .args(["--output=json"])
        .kill_on_drop(true)
        .output()
        .await
        .expect("run scoped kubectl get");
    assert!(
        output.status.success(),
        "kubectl get {resource} {selector:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse kubectl JSON")
}

async fn sandbox_resource(id: &str) -> Value {
    let selector = format!("openshell.ai/sandbox-id={id}");
    let list = kubectl_get("sandboxes.agents.x-k8s.io", &["--selector", &selector]).await;
    let [resource] = list["items"].as_array().expect("Sandbox items").as_slice() else {
        panic!("expected exactly one Sandbox resource for {id}: {list}");
    };
    assert_eq!(
        resource["metadata"]["labels"]["openshell.ai/sandbox-id"],
        id
    );
    assert!(
        resource["metadata"]["uid"]
            .as_str()
            .is_some_and(|uid| !uid.is_empty())
    );
    resource.clone()
}

/// Read claims by their exact names from the actual workload Pod. Do not rely
/// on controller-version-dependent PVC names or labels, or inspect other PVCs.
async fn claim_uids(resource: &Value) -> BTreeMap<String, String> {
    let pod_name = resource["metadata"]["annotations"]["agents.x-k8s.io/pod-name"]
        .as_str()
        .unwrap_or_else(|| resource["metadata"]["name"].as_str().expect("Sandbox name"));
    let pod = kubectl_get("pod", &[pod_name]).await;
    assert!(
        pod["metadata"]["ownerReferences"]
            .as_array()
            .expect("workload Pod owners")
            .iter()
            .any(|owner| owner["uid"] == resource["metadata"]["uid"]),
        "workload Pod must belong to this Sandbox resource"
    );
    let agent = pod["spec"]["containers"]
        .as_array()
        .expect("Pod containers")
        .iter()
        .find(|container| container["name"] == "agent")
        .expect("agent container");
    let workspace_volume = agent["volumeMounts"]
        .as_array()
        .expect("agent volume mounts")
        .iter()
        .find(|mount| mount["mountPath"] == "/sandbox")
        .expect("workspace volume mount");
    let volumes = pod["spec"]["volumes"].as_array().expect("Pod volumes");
    assert!(
        volumes.iter().any(|volume| {
            volume["name"] == workspace_volume["name"]
                && volume["persistentVolumeClaim"]["claimName"]
                    .as_str()
                    .is_some()
        }),
        "workspace must be backed by a PVC"
    );
    let mut claims = BTreeMap::new();
    for volume in volumes {
        let Some(name) = volume["persistentVolumeClaim"]["claimName"].as_str() else {
            continue;
        };
        let claim = kubectl_get("persistentvolumeclaim", &[name]).await;
        let uid = claim["metadata"]["uid"]
            .as_str()
            .filter(|uid| !uid.is_empty())
            .expect("PVC UID");
        assert_eq!(claim["status"]["phase"], "Bound");
        claims.insert(name.to_owned(), uid.to_owned());
    }
    assert!(
        !claims.is_empty(),
        "test must exercise PVC-backed workspace storage"
    );
    claims
}

fn assert_resource_retained(before: &Value, after: &Value, image: &str) {
    assert_eq!(after["metadata"]["name"], before["metadata"]["name"]);
    assert_eq!(after["metadata"]["uid"], before["metadata"]["uid"]);
    assert_eq!(
        after["spec"]["volumeClaimTemplates"],
        before["spec"]["volumeClaimTemplates"]
    );
    let agent = after["spec"]["podTemplate"]["spec"]["containers"]
        .as_array()
        .expect("workload containers")
        .iter()
        .find(|container| container["name"] == "agent")
        .expect("agent container");
    assert_eq!(agent["image"], image);
}

fn assert_identity_retained(before: &proto::Sandbox, after: &proto::Sandbox) {
    assert_eq!(
        after.metadata.as_ref().expect("metadata").id,
        before.metadata.as_ref().expect("metadata").id
    );
    assert_eq!(after.host_key_fingerprint, before.host_key_fingerprint);
}

async fn assert_base_release(sandbox: &Sandbox, release: &str) {
    assert!(
        sandbox
            .exec(["cat", "/etc/alpine-release"])
            .await
            .expect("base image release")
            .stdout
            .trim()
            .starts_with(release)
    );
}

fn assert_update_completed(original: &proto::Sandbox, updated: &proto::Sandbox) {
    assert_identity_retained(original, updated);
    let status = updated.status.as_ref().expect("updated status");
    assert_eq!(status.phase, proto::SandboxPhase::Stopped as i32);
    assert!(
        status
            .provisioning
            .as_ref()
            .is_none_or(|record| !record.driver_operation_pending),
        "successful image update must settle the old-understood operation interlock"
    );
    assert_eq!(
        updated
            .spec
            .as_ref()
            .expect("spec")
            .template
            .as_ref()
            .expect("template")
            .image,
        *UPDATED_IMAGE
    );
}

async fn assert_replay(
    client: &mut AuthedSandboxUpdatesClient,
    update: proto::UpdateSandboxRequest,
    updated: &proto::Sandbox,
) {
    // Replay restores current resource state, not a captured transient status.
    // Use retained driver evidence to prove that no new image operation ran.
    let id = &updated.metadata.as_ref().expect("updated metadata").id;
    let before = sandbox_resource(id).await;
    let evidence = before["metadata"]["annotations"]["openshell.ai/sandbox-image-update"].clone();
    let operation: Value =
        serde_json::from_str(evidence.as_str().expect("image operation evidence"))
            .expect("parse image operation evidence");
    assert!(
        operation["revision"]
            .as_u64()
            .is_some_and(|revision| revision > 0)
    );
    assert!(
        operation["operation_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    let replay = client
        .update_sandbox(rpc(update))
        .await
        .expect("request-ID replay");
    assert_eq!(
        replay
            .metadata()
            .get("openshell-replayed")
            .expect("replay metadata"),
        "true"
    );
    let replayed = replay.into_inner().sandbox.expect("replayed Sandbox");
    assert_update_completed(updated, &replayed);
    assert_eq!(replayed.spec, updated.spec);
    let after = sandbox_resource(id).await;
    assert_eq!(after["metadata"]["uid"], before["metadata"]["uid"]);
    assert_eq!(
        after["metadata"]["annotations"]["openshell.ai/sandbox-image-update"], evidence,
        "replay must retain the exact driver operation identity and revision"
    );
    assert!(
        replayed
            .metadata
            .as_ref()
            .expect("replayed metadata")
            .resource_version
            >= updated
                .metadata
                .as_ref()
                .expect("updated metadata")
                .resource_version
    );
}

async fn assert_image_update_supported(client: &mut AuthedGrpcClient) {
    // This test is Kubernetes-only: missing support is a regression, not a skip.
    let info = client
        .get_gateway_info(rpc(proto::GetGatewayInfoRequest {}))
        .await
        .expect("get gateway capabilities")
        .into_inner();
    assert!(info.extensions.iter().any(|extension| {
        extension
            .supported_capabilities
            .iter()
            .any(|capability| capability == "openshell.compute.update-sandbox-configuration")
    }));
}

/// Updating a stopped sandbox retains storage and identity and changes the next workload.
#[testkit::test]
async fn image_update_retains_workspace_and_identity(cx: &mut Context) -> testkit::Result {
    let selected = testkit::Gateway::from_env()?;
    let workspace = selected.workspace.as_str();
    let gateway = selected.connect().await?;
    let mut client = gateway.raw_grpc();
    let mut image_client = gateway.raw_sandbox_updates();
    assert_image_update_supported(&mut client).await;

    let sandbox = cx
        // The testkit's unique prefix leaves five characters of the name limit.
        .sandbox("image")
        .spec(|spec| spec.image = Some(ORIGINAL_IMAGE.to_string()))
        .create()
        .await?;
    sandbox.wait_ready().await?;
    let original = get_sandbox(&mut client, workspace, sandbox.name()).await;
    let id = &original.metadata.as_ref().expect("sandbox metadata").id;
    assert!(!id.is_empty(), "sandbox must have a canonical ID");
    assert!(
        original.host_key_fingerprint.starts_with("SHA256:"),
        "sandbox must have a gateway-managed SSH identity"
    );
    assert_base_release(&sandbox, "3.21.").await;
    let sentinel = request_id();
    sandbox
        .exec([
            "sh",
            "-c",
            &format!("printf '%s' '{sentinel}' > '{SENTINEL_PATH}'"),
        ])
        .await
        .expect("write workspace sentinel");
    let before = sandbox_resource(id).await;
    let original_claims = claim_uids(&before).await;

    let running_update = proto::UpdateSandboxRequest {
        workspace_scope: Some(proto::workspace_selector(workspace)),
        name: sandbox.name().to_owned(),
        image: Some(UPDATED_IMAGE.to_string()),
        expected_resource_version: original
            .metadata
            .as_ref()
            .expect("metadata")
            .resource_version,
        request_id: String::new(),
        ..Default::default()
    };
    let error = image_client
        .update_sandbox(rpc(running_update.clone()))
        .await
        .expect_err("running update must be rejected");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_resource_retained(&before, &sandbox_resource(id).await, &ORIGINAL_IMAGE);

    sandbox.stop().await?;
    let stopped = get_sandbox(&mut client, workspace, sandbox.name()).await;
    let update = proto::UpdateSandboxRequest {
        expected_resource_version: stopped
            .metadata
            .as_ref()
            .expect("metadata")
            .resource_version,
        request_id: request_id(),
        command: Some(proto::SandboxCommandUpdate { argv: vec![
            "/bin/sh".into(), "-c".into(),
            "mkdir -p /sandbox/harness; printf '%s:%s' \"$AGENT_MODE\" \"$1\" > /sandbox/harness/configuration; exec sleep 86400".into(),
            "agent-bootstrap".into(), "new-argument".into(),
        ] }),
        environment: Some(proto::SandboxMapUpdate { values: std::collections::HashMap::from([("AGENT_MODE".into(), "updated".into())]) }),
        labels: Some(proto::SandboxMapUpdate { values: std::collections::HashMap::from([("team".into(), "updated-agent".into())]) }),
        annotations: Some(proto::SandboxMapUpdate { values: std::collections::HashMap::from([("example.com/revision".into(), "2".into())]) }),
        ..running_update
    };
    let (updated, update) =
        update_stopped_sandbox(&mut client, &mut image_client, workspace, update).await;
    assert_update_completed(&original, &updated);
    assert_resource_retained(&before, &sandbox_resource(id).await, &UPDATED_IMAGE);

    assert_replay(&mut image_client, update, &updated).await;
    assert_recreated_resource_rejects_stale_patch(
        &sandbox_resource(id).await,
        &cx.name("uid-race"),
    )
    .await;

    sandbox.start().await?;
    assert_base_release(&sandbox, "3.22.").await;
    assert_eq!(
        sandbox
            .exec(["cat", "/sandbox/harness/configuration"])
            .await
            .expect("updated command and environment ran on start")
            .stdout
            .trim(),
        "updated:new-argument"
    );
    let observed = get_sandbox(&mut client, workspace, sandbox.name()).await;
    assert_eq!(
        observed
            .metadata
            .as_ref()
            .unwrap()
            .labels
            .get("team")
            .map(String::as_str),
        Some("updated-agent")
    );
    assert_eq!(
        observed
            .metadata
            .as_ref()
            .unwrap()
            .annotations
            .get("example.com/revision")
            .map(String::as_str),
        Some("2")
    );
    assert_eq!(
        sandbox
            .exec(["cat", SENTINEL_PATH])
            .await
            .expect("retained workspace sentinel")
            .stdout
            .trim(),
        sentinel
    );
    let current = get_sandbox(&mut client, workspace, sandbox.name()).await;
    assert_identity_retained(&original, &current);
    let after = sandbox_resource(id).await;
    assert_resource_retained(&before, &after, &UPDATED_IMAGE);
    assert_eq!(
        claim_uids(&after).await,
        original_claims,
        "all mounted PVC names and UIDs must survive image replacement"
    );
    sandbox.delete().await?;
    Ok(())
}

/// A terminal command can be stopped and repaired without replacing its storage.
#[testkit::test]
async fn terminal_workload_can_stop_update_and_restart(cx: &mut Context) -> testkit::Result {
    let selected = testkit::Gateway::from_env()?;
    let workspace = selected.workspace.as_str();
    let gateway = selected.connect().await?;
    let mut client = gateway.raw_grpc();
    let mut updates = gateway.raw_sandbox_updates();
    let sandbox = cx
        .sandbox("term")
        .restart_policy(testkit::sdk::SandboxRestartPolicy::Never)
        .spec(|spec| spec.image = Some(ORIGINAL_IMAGE.to_string()))
        .create()
        .await?;
    sandbox.wait_ready().await?;
    let original = get_sandbox(&mut client, workspace, sandbox.name()).await;
    let before = sandbox_resource(sandbox.id()).await;
    let original_claims = claim_uids(&before).await;
    let sentinel = request_id();
    sandbox
        .exec([
            "sh",
            "-c",
            &format!("printf '%s' '{sentinel}' > '{SENTINEL_PATH}'"),
        ])
        .await?;

    for exit_code in [0, 1] {
        sandbox.stop().await?;
        update_stopped_sandbox(
            &mut client,
            &mut updates,
            workspace,
            proto::UpdateSandboxRequest {
                workspace_scope: Some(proto::workspace_selector(workspace)),
                name: sandbox.name().to_owned(),
                command: Some(proto::SandboxCommandUpdate {
                    argv: vec!["/bin/sh".into(), "-c".into(), format!("exit {exit_code}")],
                }),
                ..Default::default()
            },
        )
        .await;
        // Do not wait for Ready: the command may exit before Ready is observed.
        client
            .start_sandbox(rpc(proto::StartSandboxRequest {
                workspace_scope: Some(proto::workspace_selector(workspace)),
                name: sandbox.name().to_owned(),
                ..Default::default()
            }))
            .await
            .expect("start terminal command");
        sandbox.wait_finished().await?;
        let terminal = get_sandbox(&mut client, workspace, sandbox.name()).await;
        let status = terminal.status.as_ref().unwrap();
        assert_eq!(
            status.phase,
            if exit_code == 0 {
                proto::SandboxPhase::Completed
            } else {
                proto::SandboxPhase::Error
            } as i32
        );
        assert_eq!(status.exit_code, Some(exit_code));
        assert!(status.conditions.iter().any(|condition| condition.reason
            == if exit_code == 0 {
                "MainProcessCompleted"
            } else {
                "MainProcessFailed"
            }));

        sandbox.stop().await?;
        let stopped = get_sandbox(&mut client, workspace, sandbox.name()).await;
        assert_eq!(
            stopped.status.as_ref().unwrap().phase,
            proto::SandboxPhase::Stopped as i32
        );
        assert_eq!(stopped.status.as_ref().unwrap().exit_code, Some(exit_code));
        update_stopped_sandbox(
            &mut client,
            &mut updates,
            workspace,
            proto::UpdateSandboxRequest {
                workspace_scope: Some(proto::workspace_selector(workspace)),
                name: sandbox.name().to_owned(),
                command: Some(proto::SandboxCommandUpdate {
                    argv: vec!["sleep".into(), "86400".into()],
                }),
                ..Default::default()
            },
        )
        .await;
        sandbox.start().await?;
        let repaired = get_sandbox(&mut client, workspace, sandbox.name()).await;
        assert_identity_retained(&original, &repaired);
        assert_eq!(repaired.status.as_ref().unwrap().exit_code, None);
        assert_eq!(
            sandbox.exec(["cat", SENTINEL_PATH]).await?.stdout.trim(),
            sentinel
        );
        let after = sandbox_resource(sandbox.id()).await;
        assert_resource_retained(&before, &after, &ORIGINAL_IMAGE);
        assert_eq!(claim_uids(&after).await, original_claims);
    }
    sandbox.delete().await?;
    Ok(())
}
