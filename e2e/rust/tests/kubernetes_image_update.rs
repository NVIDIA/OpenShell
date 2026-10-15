// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

//! Exercise the public image-update RPC in both Agent Sandbox API-version lanes.
//! Kubernetes object checks are read-only and scoped to this test's sandbox.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use openshell_bootstrap::{load_active_gateway, load_gateway_metadata};
use openshell_e2e::harness::cli::{run_cli, wait_for_sandbox_phase};
use openshell_e2e::harness::sandbox::SandboxGuard;
use openshell_sdk::raw::{AuthedGrpcClient, proto};
use openshell_sdk::{ClientConfig, EdgeAuthInterceptor, OpenShellClient};
use serde_json::Value;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

// Multi-platform release manifests; no test-local tags or cluster image loads.
const ORIGINAL_IMAGE: &str = "docker.io/library/alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507";
const UPDATED_IMAGE: &str = "docker.io/library/alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8";
const SENTINEL_PATH: &str = "/sandbox/.image-update-sentinel";

/// Reuse the wrapper's registered endpoint (including its isolated XDG config).
/// The SDK owns plaintext transport; the `OpenShift` wrapper registers an mTLS
/// gateway, for which we attach its existing client bundle to a tonic channel.
async fn gateway_client() -> AuthedGrpcClient {
    let name = std::env::var("OPENSHELL_GATEWAY")
        .ok()
        .filter(|name| !name.trim().is_empty())
        .or_else(load_active_gateway)
        .expect("Kubernetes E2E wrapper must register a gateway");
    let metadata = load_gateway_metadata(&name).expect("load E2E gateway metadata");
    let client = if metadata.gateway_endpoint.starts_with("http://") {
        OpenShellClient::connect(ClientConfig::new(metadata.gateway_endpoint))
            .await
            .expect("connect to E2E gateway")
    } else {
        assert!(
            matches!(metadata.auth_mode.as_deref(), None | Some("mtls")),
            "Kubernetes E2E wrapper must register plaintext or mTLS transport"
        );
        let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(
            || PathBuf::from(std::env::var_os("HOME").expect("HOME")).join(".config"),
            PathBuf::from,
        );
        let bundle = config.join("openshell/gateways").join(&name).join("mtls");
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(
                std::fs::read(bundle.join("ca.crt")).expect("read E2E gateway CA"),
            ))
            .identity(Identity::from_pem(
                std::fs::read(bundle.join("tls.crt")).expect("read E2E client certificate"),
                std::fs::read(bundle.join("tls.key")).expect("read E2E client key"),
            ));
        let channel = Endpoint::from_shared(metadata.gateway_endpoint)
            .expect("E2E gateway endpoint")
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .tls_config(tls)
            .expect("configure E2E gateway mTLS")
            .connect()
            .await
            .expect("connect to E2E gateway over mTLS");
        OpenShellClient::from_parts(channel, EdgeAuthInterceptor::noop())
    };
    client.raw_grpc()
}

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

async fn get_sandbox(client: &mut AuthedGrpcClient, name: &str) -> proto::Sandbox {
    client
        .get_sandbox(rpc(proto::GetSandboxRequest {
            workspace_scope: Some(proto::workspace_selector("default")),
            name: name.to_owned(),
        }))
        .await
        .expect("get test sandbox")
        .into_inner()
        .sandbox
        .expect("Sandbox response")
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

async fn assert_base_release(sandbox: &SandboxGuard, release: &str) {
    assert!(
        sandbox
            .exec(&["cat", "/etc/alpine-release"])
            .await
            .expect("base image release")
            .trim()
            .starts_with(release)
    );
}

fn assert_update_completed(original: &proto::Sandbox, updated: &proto::Sandbox) {
    assert_identity_retained(original, updated);
    let status = updated.status.as_ref().expect("updated status");
    assert_eq!(status.phase, proto::SandboxPhase::Stopped as i32);
    assert!(
        status.image_update.is_none(),
        "successful update must clear pending intent"
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
        UPDATED_IMAGE
    );
}

async fn assert_replay(
    client: &mut AuthedGrpcClient,
    update: proto::UpdateSandboxRequest,
    updated: &proto::Sandbox,
) {
    // Replay the exact old resource-version request. Sandbox replay returns its
    // current state: ordinary watch observations may have advanced metadata and
    // status since the original response, without applying the image again.
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
    assert_eq!(
        replayed
            .status
            .as_ref()
            .expect("replayed status")
            .image_revision,
        updated
            .status
            .as_ref()
            .expect("updated status")
            .image_revision,
        "replay must not admit another image operation"
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

#[tokio::test]
async fn image_update_retains_workspace_and_identity() {
    let mut client = gateway_client().await;
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
            .any(|capability| capability == "openshell.compute.update-sandbox-image")
    }));

    let mut sandbox = SandboxGuard::create(&["--from", ORIGINAL_IMAGE, "--no-auto-providers"])
        .await
        .expect("create original Alpine sandbox");
    let original = get_sandbox(&mut client, &sandbox.name).await;
    let id = &original.metadata.as_ref().expect("sandbox metadata").id;
    assert!(!id.is_empty(), "sandbox must have a canonical ID");
    assert!(
        original.host_key_fingerprint.starts_with("SHA256:"),
        "sandbox must have a gateway-managed SSH identity"
    );
    assert_base_release(&sandbox, "3.21.").await;
    let sentinel = request_id();
    sandbox
        .exec(&[
            "sh",
            "-c",
            &format!("printf '%s' '{sentinel}' > '{SENTINEL_PATH}'"),
        ])
        .await
        .expect("write workspace sentinel");
    let before = sandbox_resource(id).await;
    let original_claims = claim_uids(&before).await;

    let running_update = proto::UpdateSandboxRequest {
        workspace_scope: Some(proto::workspace_selector("default")),
        name: sandbox.name.clone(),
        image: UPDATED_IMAGE.to_owned(),
        expected_resource_version: original
            .metadata
            .as_ref()
            .expect("metadata")
            .resource_version,
        request_id: String::new(),
    };
    let error = client
        .update_sandbox(rpc(running_update.clone()))
        .await
        .expect_err("running update must be rejected");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_resource_retained(&before, &sandbox_resource(id).await, ORIGINAL_IMAGE);

    let (output, code) = run_cli(&["sandbox", "stop", &sandbox.name]).await;
    assert_eq!(code, 0, "sandbox stop: {output}");
    wait_for_sandbox_phase(&sandbox.name, "Stopped", Duration::from_secs(120))
        .await
        .expect("sandbox stopped");
    let stopped = get_sandbox(&mut client, &sandbox.name).await;
    let update = proto::UpdateSandboxRequest {
        expected_resource_version: stopped
            .metadata
            .as_ref()
            .expect("metadata")
            .resource_version,
        request_id: request_id(),
        ..running_update
    };
    let updated = client
        .update_sandbox(rpc(update.clone()))
        .await
        .expect("update stopped sandbox image")
        .into_inner()
        .sandbox
        .expect("updated Sandbox");
    assert_update_completed(&original, &updated);
    assert_resource_retained(&before, &sandbox_resource(id).await, UPDATED_IMAGE);

    assert_replay(&mut client, update, &updated).await;

    let (output, code) = run_cli(&["sandbox", "start", &sandbox.name]).await;
    assert_eq!(code, 0, "sandbox start: {output}");
    wait_for_sandbox_phase(&sandbox.name, "Ready", Duration::from_secs(180))
        .await
        .expect("updated sandbox ready");
    assert_base_release(&sandbox, "3.22.").await;
    assert_eq!(
        sandbox
            .exec(&["cat", SENTINEL_PATH])
            .await
            .expect("retained workspace sentinel")
            .trim(),
        sentinel
    );
    let current = get_sandbox(&mut client, &sandbox.name).await;
    assert_identity_retained(&original, &current);
    let after = sandbox_resource(id).await;
    assert_resource_retained(&before, &after, UPDATED_IMAGE);
    assert_eq!(
        claim_uids(&after).await,
        original_claims,
        "all mounted PVC names and UIDs must survive image replacement"
    );
    sandbox.cleanup().await;
}
