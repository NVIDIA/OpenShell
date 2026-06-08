// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end reconciler test against a real kube apiserver.
//!
//! Drives the full CR lifecycle (apply → reconcile → status=Running →
//! delete → finalizer cleanup → CR gone) without depending on
//! `openshell-server` being deployed. A [`TestGateway`] stub records the
//! reconciler's gateway calls and returns synthetic responses so the test
//! exercises kube-rs wiring, SSA, status patches, finalizers, and the
//! cr-uid idempotency lookup in isolation.
//!
//! Marked `#[ignore]` so `cargo test --workspace` doesn't try to run it
//! without a cluster. Invoke explicitly:
//!
//! ```shell
//! # First: tests/kind/bootstrap.sh writes the kind kubeconfig
//! make -C crates/openshell-controller/tests/kind up
//! # Then:
//! mise exec -- cargo test -p openshell-controller --test e2e_reconciler -- --ignored --nocapture
//! ```
//!
//! CI invokes this through `mise run test:controller-e2e` (see tasks/test.toml).

#![allow(clippy::unwrap_used)] // tests panic on setup failures by design
#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kube::api::{DeleteParams, ListParams, PostParams};
use kube::core::ObjectMeta;
use kube::{Api, Client};
use openshell_controller::types::{OpenShellSandbox, OpenShellSandboxSpec, Phase};
use openshell_controller::{ControllerConfig, GatewayClient};
use openshell_core::proto::openshell::{CreateSandboxRequest, Sandbox};
use openshell_core::proto::datamodel::v1::ObjectMeta as SandboxMeta;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};
use tonic::Status;

/// Gateway stub that records calls and returns synthetic sandboxes.
#[derive(Default)]
struct TestGateway {
    created: Mutex<Vec<CreateSandboxRequest>>,
    deleted: Mutex<Vec<String>>,
}

impl TestGateway {
    async fn created_names(&self) -> Vec<String> {
        self.created
            .lock()
            .await
            .iter()
            .map(|r| r.name.clone())
            .collect()
    }

    async fn deleted_names(&self) -> Vec<String> {
        self.deleted.lock().await.clone()
    }

    async fn created_for_uid(&self, uid: &str) -> Option<String> {
        self.created
            .lock()
            .await
            .iter()
            .find(|r| {
                r.labels.get("openshell.nvidia.com/cr-uid").map(String::as_str) == Some(uid)
            })
            .map(|r| r.name.clone())
    }
}

#[async_trait]
impl GatewayClient for TestGateway {
    async fn create_sandbox(&self, req: CreateSandboxRequest) -> Result<Sandbox, Status> {
        let id = format!("test-sandbox-{}", uuid_lite());
        let name = req.name.clone();
        self.created.lock().await.push(req);
        Ok(Sandbox {
            metadata: Some(SandboxMeta {
                id,
                name,
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            spec: None,
            status: None,
        })
    }

    async fn delete_sandbox(&self, name: &str) -> Result<bool, Status> {
        self.deleted.lock().await.push(name.to_owned());
        Ok(true)
    }

    async fn find_sandbox_by_label(
        &self,
        key: &str,
        value: &str,
    ) -> Result<Option<Sandbox>, Status> {
        // Search the recorded creates for one tagged with this label.
        // This mirrors the gateway's real label-selector behaviour.
        let created = self.created.lock().await;
        Ok(created
            .iter()
            .find(|r| r.labels.get(key).map(String::as_str) == Some(value))
            .map(|r| Sandbox {
                metadata: Some(SandboxMeta {
                    id: format!("found-{}", r.name),
                    name: r.name.clone(),
                    created_at_ms: 0,
                    labels: r.labels.clone(),
                    resource_version: 0,
                }),
                spec: None,
                status: None,
            }))
    }

    async fn get_sandbox(&self, name: &str) -> Result<Sandbox, Status> {
        // Test stub: pretend the sandbox is always Ready. Real gateway
        // reads the driver-observed pod readiness from its store.
        let created = self.created.lock().await;
        let Some(r) = created.iter().find(|r| r.name == name) else {
            return Err(Status::not_found(format!("test gateway has no {name}")));
        };
        let mut sandbox = Sandbox {
            metadata: Some(SandboxMeta {
                id: format!("test-sandbox-{name}"),
                name: r.name.clone(),
                created_at_ms: 0,
                labels: r.labels.clone(),
                resource_version: 0,
            }),
            spec: None,
            status: None,
        };
        sandbox.set_phase(openshell_core::proto::SandboxPhase::Ready as i32);
        Ok(sandbox)
    }
}

fn uuid_lite() -> String {
    // Tests don't need real UUIDs; just enough entropy to avoid collisions
    // across multiple create calls in one test run.
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or_else(|_| "0".to_owned(), |d| d.as_nanos().to_string())
}

fn cr(name: &str, image: &str) -> OpenShellSandbox {
    OpenShellSandbox {
        metadata: ObjectMeta {
            name: Some(name.to_owned()),
            namespace: Some("default".to_owned()),
            ..Default::default()
        },
        spec: OpenShellSandboxSpec {
            image: image.to_owned(),
            policy_yaml: "version: 1\n".to_owned(),
            environment: std::collections::BTreeMap::default(),
            providers: Vec::new(),
            gpu: false,
            gpu_device: None,
            log_level: None,
            runtime_class_name: None,
            labels: std::collections::BTreeMap::default(),
        },
        status: None,
    }
}

async fn wait_for_phase(
    api: &Api<OpenShellSandbox>,
    name: &str,
    expected: Phase,
) -> Result<OpenShellSandbox, String> {
    let deadline = Duration::from_secs(15);
    timeout(deadline, async {
        loop {
            if let Ok(obj) = api.get(name).await
                && obj.status.as_ref().and_then(|s| s.phase).map(phase_label)
                    == Some(phase_label(expected))
            {
                return obj;
            }
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .map_err(|_| format!("timed out waiting for {name} to reach phase={expected:?}"))
}

fn phase_label(p: Phase) -> &'static str {
    match p {
        Phase::Pending => "Pending",
        Phase::Provisioning => "Provisioning",
        Phase::Running => "Running",
        Phase::Terminating => "Terminating",
        Phase::Failed => "Failed",
        Phase::Deleted => "Deleted",
    }
}

async fn wait_for_gone(api: &Api<OpenShellSandbox>, name: &str) -> Result<(), String> {
    let deadline = Duration::from_secs(15);
    timeout(deadline, async {
        loop {
            match api.get(name).await {
                Err(kube::Error::Api(e)) if e.code == 404 => return,
                _ => sleep(Duration::from_millis(200)).await,
            }
        }
    })
    .await
    .map_err(|_| format!("timed out waiting for {name} to be removed"))
}

/// Clean up any CRs left behind by a previous test run. Tests share a
/// namespace so this is best-effort: delete-collection, then wait.
async fn cleanup(api: &Api<OpenShellSandbox>) {
    let _ = api
        .delete_collection(&DeleteParams::default(), &ListParams::default())
        .await;
    // Give the apiserver a moment to process the deletes; we'll create
    // CRs with fresh names anyway, so this is just hygiene.
    sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
#[ignore = "requires a kube cluster; run via `cargo test -- --ignored` after `make up`"]
async fn cr_lifecycle_reaches_running_then_clears_on_delete() {
    let client = Client::try_default()
        .await
        .expect("kube client (set KUBECONFIG or run `make up`)");
    let api: Api<OpenShellSandbox> = Api::namespaced(client.clone(), "default");
    cleanup(&api).await;

    let gateway = Arc::new(TestGateway::default());
    let gw_for_task = gateway.clone();
    let task = tokio::spawn(async move {
        let config = ControllerConfig {
            watch_namespace: "default".to_owned(),
            log_filter: "info,openshell_controller=debug".to_owned(),
        };
        let _ = openshell_controller::run(gw_for_task, config).await;
    });

    // Give the controller a moment to install its watchers.
    sleep(Duration::from_millis(500)).await;

    let body = cr("e2e-running", "ghcr.io/nvidia/openshell/sandbox:latest");
    api.create(&PostParams::default(), &body)
        .await
        .expect("apply CR");

    let final_obj = wait_for_phase(&api, "e2e-running", Phase::Running)
        .await
        .expect("reach Running");
    let status = final_obj.status.expect("status set");
    assert_eq!(status.phase.map(phase_label), Some("Running"));
    assert!(
        status.sandbox_id.as_deref().is_some_and(|id| !id.is_empty()),
        "status.sandboxId populated from gateway response"
    );

    assert_eq!(gateway.created_names().await, vec!["e2e-running"]);

    api.delete("e2e-running", &DeleteParams::default())
        .await
        .expect("delete CR");
    wait_for_gone(&api, "e2e-running")
        .await
        .expect("CR removed after finalizer");
    assert_eq!(gateway.deleted_names().await, vec!["e2e-running"]);

    task.abort();
}

#[tokio::test]
#[ignore = "requires a kube cluster"]
async fn cr_uid_idempotency_skips_duplicate_create_on_spec_edit() {
    let client = Client::try_default().await.expect("kube client");
    let api: Api<OpenShellSandbox> = Api::namespaced(client.clone(), "default");
    cleanup(&api).await;

    let gateway = Arc::new(TestGateway::default());
    let gw_for_task = gateway.clone();
    let task = tokio::spawn(async move {
        let config = ControllerConfig {
            watch_namespace: "default".to_owned(),
            log_filter: "info,openshell_controller=debug".to_owned(),
        };
        let _ = openshell_controller::run(gw_for_task, config).await;
    });
    sleep(Duration::from_millis(500)).await;

    let body = cr("e2e-spec-edit", "ghcr.io/nvidia/openshell/sandbox:v1");
    let created = api
        .create(&PostParams::default(), &body)
        .await
        .expect("apply CR");
    let uid = created.metadata.uid.clone().expect("apiserver set uid");

    wait_for_phase(&api, "e2e-spec-edit", Phase::Running)
        .await
        .expect("reach Running");
    assert_eq!(gateway.created_for_uid(&uid).await.as_deref(), Some("e2e-spec-edit"));

    // Edit .spec.image — this bumps metadata.generation and triggers a
    // fresh reconcile. The cr-uid lookup must find the existing sandbox
    // and skip a duplicate create.
    let mut updated = api.get("e2e-spec-edit").await.expect("re-fetch");
    updated.spec.image = "ghcr.io/nvidia/openshell/sandbox:v2".into();
    api.replace("e2e-spec-edit", &PostParams::default(), &updated)
        .await
        .expect("update CR");

    // Wait a bit for the reconciler to observe the update and run.
    sleep(Duration::from_secs(2)).await;

    let created_count = gateway.created.lock().await.len();
    assert_eq!(
        created_count, 1,
        "spec edit must not trigger a second create (cr-uid lookup found existing)"
    );

    api.delete("e2e-spec-edit", &DeleteParams::default())
        .await
        .ok();
    wait_for_gone(&api, "e2e-spec-edit").await.ok();
    task.abort();
}
