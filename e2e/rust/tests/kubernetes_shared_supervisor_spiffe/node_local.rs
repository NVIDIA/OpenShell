// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Node-local Broker coverage: no Broker Service, gateway relocation, and
//! fresh acquisition with TCP 8443 restricted to the gateway's current node.

use super::shared_supervisor::{
    GATEWAY_SELECTOR, release_namespace, supervisor_pods, wait_until_attached,
};
use super::{call_until, cli, kubectl, kubectl_with_input, replace_broker_agent, spire_fixture};
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::{Value, json};
use std::{collections::BTreeSet, time::Duration};

async fn gateway_pod() -> Value {
    let pods = kubectl(&[
        "-n",
        &release_namespace(),
        "get",
        "pods",
        "-l",
        GATEWAY_SELECTOR,
        "-o",
        "json",
    ])
    .await;
    let pods: Value = serde_json::from_str(&pods).unwrap();
    let active: Vec<_> = pods["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|pod| {
            pod["metadata"]["deletionTimestamp"].is_null() && pod["status"]["phase"] == "Running"
        })
        .collect();
    let [pod] = active.as_slice() else {
        panic!("expected one active gateway Pod");
    };
    (*pod).clone()
}

async fn restrict_broker_to_node(ip: &str) {
    let ip: std::net::IpAddr = ip.parse().expect("gateway node IP");
    let cidr = format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 });
    let policy = json!({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "e2e-node-local-broker", "namespace": release_namespace()},
        "spec": {
            "podSelector": {"matchLabels": {"app.kubernetes.io/name": "openshell"}},
            "policyTypes": ["Egress"],
            "egress": [
                {"to": [{"ipBlock": {"cidr": cidr}}], "ports": [{"protocol": "TCP", "port": 8443}]},
                {"ports": [{"protocol": "TCP", "port": 1, "endPort": 8442}, {"protocol": "TCP", "port": 8444, "endPort": 65535}]},
                {"ports": [{"protocol": "UDP"}]}
            ]
        }
    });
    kubectl_with_input(&["apply", "-f", "-"], Some(&policy.to_string())).await;
}

async fn wait_for_gateway() {
    tokio::time::timeout(Duration::from_mins(2), async {
        while !cli(&["sandbox", "list"]).await.0 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .expect("gateway port-forward did not reconnect after relocation");
    wait_until_attached(&supervisor_pods().await).await;
}

async fn fresh_acquisition(sandbox: &SandboxGuard, port: u16, id: &str) {
    let (ok, output) = cli(&["sandbox", "stop", &sandbox.name]).await;
    assert!(ok, "{output}");
    let (ok, output) = cli(&["sandbox", "start", &sandbox.name]).await;
    assert!(ok, "{output}");
    call_until(sandbox, port, &format!("SAW:{id}")).await;
}

async fn relocate_gateway(deployment: &str, node: &str) {
    let namespace = release_namespace();
    if gateway_pod().await["spec"]["nodeName"] != node {
        let patch = json!({"spec": {"template": {"spec": {"nodeSelector": {"kubernetes.io/hostname": node}}}}});
        kubectl(&[
            "-n",
            &namespace,
            "patch",
            "deployment",
            deployment,
            "--type=merge",
            "-p",
            &patch.to_string(),
        ])
        .await;
        kubectl(&[
            "-n",
            &namespace,
            "rollout",
            "status",
            &format!("deployment/{deployment}"),
            "--timeout=180s",
        ])
        .await;
        wait_for_gateway().await;
    }
}

pub(super) async fn exercise(sandbox: &SandboxGuard, port: u16, id: &str) {
    let namespace = release_namespace();
    let fixture = spire_fixture();
    assert!(
        kubectl(&[
            "-n",
            &fixture,
            "get",
            "service",
            "spire-broker",
            "--ignore-not-found",
            "-o",
            "name"
        ])
        .await
        .trim()
        .is_empty(),
        "node-local mode must not create a Broker Service"
    );
    let pods = kubectl(&[
        "-n",
        &fixture,
        "get",
        "pods",
        "-l",
        "app.kubernetes.io/name=agent,app.kubernetes.io/instance=spire",
        "-o",
        "json",
    ])
    .await;
    let pods: Value = serde_json::from_str(&pods).unwrap();
    let nodes: BTreeSet<String> = pods["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pod| pod["spec"]["nodeName"].as_str().unwrap().to_string())
        .collect();
    let minimum: usize = std::env::var("OPENSHELL_E2E_SPIRE_MIN_AGENTS")
        .unwrap_or_else(|_| "2".into())
        .parse()
        .unwrap();
    assert!(
        nodes.len() >= minimum && nodes.len() >= 2,
        "node-local relocation needs {minimum} Broker nodes"
    );
    let deployments = kubectl(&[
        "-n",
        &namespace,
        "get",
        "deployments",
        "-l",
        GATEWAY_SELECTOR,
        "-o",
        "json",
    ])
    .await;
    let deployments: Value = serde_json::from_str(&deployments).unwrap();
    let gateways: Vec<_> = deployments["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|deployment| {
            deployment["spec"]["selector"]["matchLabels"]["app.kubernetes.io/name"] == "openshell"
        })
        .collect();
    let [deployment] = gateways.as_slice() else {
        panic!("node-local relocation requires an external-database gateway Deployment");
    };
    let deployment = deployment["metadata"]["name"].as_str().unwrap();
    for node in &nodes {
        relocate_gateway(deployment, node).await;
        let gateway = gateway_pod().await;
        assert_eq!(gateway["spec"]["nodeName"], node.as_str());
        assert!(
            gateway["spec"]["containers"][0]["env"]
                .as_array()
                .unwrap()
                .iter()
                .any(|env| env["name"] == "OPENSHELL_NODE_IP"
                    && env["valueFrom"]["fieldRef"]["fieldPath"] == "status.hostIP")
        );
        restrict_broker_to_node(gateway["status"]["hostIP"].as_str().unwrap()).await;
        fresh_acquisition(sandbox, port, id).await;
        eprintln!("Node-local Broker acquisition succeeded with gateway on {node}");
    }
    let gateway = gateway_pod().await;
    let agent = pods["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|pod| pod["spec"]["nodeName"] == gateway["spec"]["nodeName"])
        .unwrap();
    replace_broker_agent(&fixture, agent).await;
    fresh_acquisition(sandbox, port, id).await;
    eprintln!("Node-local Broker acquisition succeeded after local agent replacement");
}
