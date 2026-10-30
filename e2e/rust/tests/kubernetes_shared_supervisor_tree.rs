// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-shared-supervisor-tree")]

//! Two gateway replicas sharing a database and a two-member shared supervisor
//! pool. Every pool sandbox's session runs on the replica serving its
//! supervisor at start and after a gateway crash, a gateway rolling restart,
//! and a supervisor crash; exec reaches every sandbox after each step.

mod shared_supervisor;

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::sandbox::SandboxGuard;
use shared_supervisor::{
    EXEC_PROBE_TIMEOUT, GATEWAY_SELECTOR, kubectl, kubectl_command, release_namespace,
    supervisor_pods, wait_until_attached,
};

const SANDBOXES: usize = 4;
const SETTLE_DEADLINE: Duration = Duration::from_mins(3);
const POSTGRES: &str = "deploy/openshell-e2e-postgres";
/// Each granted pool sandbox with its owning member, the replica serving that
/// member's stream, and the replica owning the sandbox's session.
const TREE: &str = "\
WITH io AS (SELECT convert_from(payload, 'UTF8')::json AS p FROM objects
            WHERE object_type = 'supervisor_instance_owner'),
     pm AS (SELECT convert_from(payload, 'UTF8')::json AS p FROM objects
            WHERE object_type = 'supervisor_pool_member'),
     so AS (SELECT substring(id FROM 'supervisor-owner:(.*)') AS sandbox_id,
                   convert_from(payload, 'UTF8')::json AS p FROM objects
            WHERE object_type = 'supervisor_session_owner')
SELECT io.p->>'sandbox_id', io.p->>'member_id', coalesce(pm.p->>'gateway_replica', ''),
       coalesce(so.p->>'owner_replica_id', '')
FROM io LEFT JOIN pm ON pm.p->>'member_id' = io.p->>'member_id'
LEFT JOIN so ON so.sandbox_id = io.p->>'sandbox_id'
WHERE io.p->>'phase' = 'granted'";

#[derive(Debug)]
struct Branch {
    member: String,
    supervisor_gateway: String,
    session_gateway: String,
}

async fn tree() -> Vec<Branch> {
    kubectl(&[
        "-n",
        &release_namespace(),
        "exec",
        POSTGRES,
        "--",
        "psql",
        "-U",
        "openshell",
        "-d",
        "openshell",
        "-XAt",
        "-F",
        "|",
        "-c",
        TREE,
    ])
    .await
    .lines()
    .filter_map(|row| {
        let mut fields = row.split('|').skip(1);
        Some(Branch {
            member: fields.next()?.to_string(),
            supervisor_gateway: fields.next()?.to_string(),
            session_gateway: fields.next()?.to_string(),
        })
    })
    .collect()
}

/// Wait until every sandbox's session runs on its supervisor's replica and no
/// record names a `gone` gateway or supervisor Pod.
async fn assert_tree(step: &str, gone: &[String]) -> Vec<Branch> {
    let mut last = Vec::new();
    let settled = tokio::time::timeout(SETTLE_DEADLINE, async {
        loop {
            last = tree().await;
            if last.len() == SANDBOXES
                && last.iter().all(|branch| {
                    !branch.session_gateway.is_empty()
                        && branch.session_gateway == branch.supervisor_gateway
                        && !gone.contains(&branch.member)
                        && !gone.contains(&branch.session_gateway)
                })
            {
                return;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "{step}: sessions did not settle on their supervisor's gateway within {SETTLE_DEADLINE:?}: {last:#?}"
    );
    last
}

/// Reopens the CLI's port-forward when the gateway Pod behind it is gone.
struct GatewayForward {
    port: u16,
    child: Option<tokio::process::Child>,
}

impl GatewayForward {
    fn new() -> Self {
        let config = std::env::var("XDG_CONFIG_HOME").expect("XDG_CONFIG_HOME");
        let gateway = std::env::var("OPENSHELL_GATEWAY").expect("OPENSHELL_GATEWAY");
        let metadata: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{config}/openshell/gateways/{gateway}/metadata.json"
            ))
            .expect("read gateway metadata"),
        )
        .expect("parse gateway metadata");
        let port = metadata["gateway_port"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .expect("gateway_port");
        Self { port, child: None }
    }

    async fn reachable(&self) -> bool {
        tokio::net::TcpStream::connect(("127.0.0.1", self.port))
            .await
            .is_ok()
    }

    async fn ensure(&mut self) {
        if self.reachable().await {
            return;
        }
        self.child = Some(
            kubectl_command()
                .args([
                    "-n",
                    &release_namespace(),
                    "port-forward",
                    &format!("svc/{}", release()),
                    &format!("{}:8080", self.port),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .expect("spawn kubectl port-forward"),
        );
        let opened = tokio::time::timeout(Duration::from_secs(30), async {
            while !self.reachable().await {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await;
        assert!(opened.is_ok(), "port-forward on {} never opened", self.port);
    }
}

async fn assert_exec(step: &str, forward: &mut GatewayForward, sandboxes: &[SandboxGuard]) {
    for sandbox in sandboxes {
        let mut last = String::new();
        let reached = tokio::time::timeout(SETTLE_DEADLINE, async {
            loop {
                forward.ensure().await;
                match tokio::time::timeout(EXEC_PROBE_TIMEOUT, sandbox.exec(&["true"])).await {
                    Ok(Ok(_)) => return,
                    Ok(Err(error)) => last = error,
                    Err(_) => last = "exec timed out".to_string(),
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        })
        .await;
        assert!(reached.is_ok(), "{step}: exec into {} failed: {last}", sandbox.name);
    }
}

fn release() -> String {
    std::env::var("OPENSHELL_E2E_KUBE_RELEASE").expect("OPENSHELL_E2E_KUBE_RELEASE")
}

async fn gateway_pods() -> Vec<String> {
    kubectl(&[
        "-n",
        &release_namespace(),
        "get",
        "pods",
        "-l",
        GATEWAY_SELECTOR,
        "-o",
        "jsonpath={.items[*].metadata.name}",
    ])
    .await
    .split_whitespace()
    .map(str::to_string)
    .collect()
}

/// The gateway's workload, a Deployment or a `StatefulSet`.
async fn gateway_workload() -> String {
    kubectl(&[
        "-n",
        &release_namespace(),
        "get",
        "deploy,statefulset",
        "--field-selector",
        &format!("metadata.name={}", release()),
        "-o",
        "name",
    ])
    .await
    .trim()
    .to_string()
}

async fn rollout(action: &str, workload: &str) {
    kubectl(&[
        "-n",
        &release_namespace(),
        "rollout",
        action,
        workload,
        "--timeout=300s",
    ])
    .await;
}

async fn force_delete(pod: &str) {
    kubectl(&[
        "-n",
        &release_namespace(),
        "delete",
        "pod",
        pod,
        "--grace-period=0",
        "--force",
    ])
    .await;
}

#[tokio::test]
async fn pool_sessions_follow_their_supervisors_gateway() {
    let gateway = gateway_workload().await;
    let supervisor = format!("deployment.apps/{}-supervisor", release());
    assert_eq!(gateway_pods().await.len(), 2, "the lane runs two gateway replicas");
    wait_until_attached(&supervisor_pods().await).await;

    let mut forward = GatewayForward::new();
    forward.ensure().await;
    let mut sandboxes = Vec::new();
    for _ in 0..SANDBOXES {
        sandboxes.push(
            SandboxGuard::create_detached_main_with_args(&[], &["sleep", "infinity"])
                .await
                .expect("create sandbox"),
        );
    }
    let branches = assert_tree("start", &[]).await;
    assert_exec("start", &mut forward, &sandboxes).await;

    let crashed = vec![branches[0].supervisor_gateway.clone()];
    force_delete(&crashed[0]).await;
    rollout("status", &gateway).await;
    assert_tree("gateway crash", &crashed).await;
    assert_exec("gateway crash", &mut forward, &sandboxes).await;

    let restarted = gateway_pods().await;
    kubectl(&["-n", &release_namespace(), "rollout", "restart", &gateway]).await;
    rollout("status", &gateway).await;
    assert_tree("gateway rolling restart", &restarted).await;
    assert_exec("gateway rolling restart", &mut forward, &sandboxes).await;

    let crashed = vec![supervisor_pods().await.remove(0)];
    force_delete(&crashed[0]).await;
    rollout("status", &supervisor).await;
    assert_tree("supervisor crash", &crashed).await;
    assert_exec("supervisor crash", &mut forward, &sandboxes).await;

    forward.ensure().await;
    drop(sandboxes);
}
