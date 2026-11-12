// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-shared-supervisor")]

mod shared_supervisor;

use openshell_e2e::harness::cli::{run_cli, wait_for_sandbox_phase};
use openshell_e2e::harness::sandbox::SandboxGuard;
use shared_supervisor::{
    GATEWAY_CONTAINER, GATEWAY_SELECTOR, kubectl, kubectl_json, release_namespace,
};
use std::time::Duration;

async fn generation(name: &str) -> shared_supervisor::Generation {
    let resource = shared_supervisor::sandbox_resource(name).await;
    let annotations = &resource["metadata"]["annotations"];
    shared_supervisor::Generation {
        route: annotations["openshell.ai/sandbox-runtime-supervisor-session"]
            .as_str()
            .or_else(|| annotations["openshell.ai/sandbox-runtime-supervisor-uid"].as_str())
            .expect("supervisor route or Pod identity")
            .to_string(),
        runtime: annotations["openshell.ai/sandbox-runtime-generation"]
            .as_str()
            .unwrap()
            .to_string(),
        workload_pod_uid: annotations["openshell.ai/sandbox-runtime-workload-uid"]
            .as_str()
            .unwrap()
            .to_string(),
    }
}

async fn ready_spare(excluding: Option<&str>) -> serde_json::Value {
    tokio::time::timeout(Duration::from_mins(6), async {
        loop {
            let resources = kubectl_json(&[
                "-n",
                &release_namespace(),
                "get",
                "sandboxes.agents.x-k8s.io",
                "-l",
                "openshell.ai/warm-pool",
                "-o",
                "json",
            ])
            .await;
            let logs = kubectl(&[
                "-n",
                &release_namespace(),
                "logs",
                "-l",
                GATEWAY_SELECTOR,
                "-c",
                GATEWAY_CONTAINER,
                "--tail=2000",
            ])
            .await;
            for resource in resources["items"].as_array().unwrap() {
                let annotations = &resource["metadata"]["annotations"];
                if resource["metadata"]["labels"]["openshell.ai/sandbox-id"].is_string()
                    || resource["metadata"]["deletionTimestamp"].is_string()
                    || annotations["openshell.ai/warm-runtime-released"] != "true"
                {
                    continue;
                }
                let record: serde_json::Value = serde_json::from_str(
                    annotations["openshell.ai/warm-runtime"].as_str().unwrap(),
                )
                .unwrap();
                let session = record["session_id"].as_str().unwrap();
                if Some(session) != excluding
                    && logs.lines().any(|line| {
                        line.contains("warm runtime ready for claim") && line.contains(session)
                    })
                {
                    return resource.clone();
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .expect("pool must produce an authenticated ready spare")
}

#[tokio::test]
#[ignore = "requires e2e/kubernetes/values-warm-pool.yaml and matching branch images"]
async fn claims_existing_pod_refills_pool_and_restarts_with_fresh_identity() {
    let (output, code) = run_cli(&[
        "sandbox",
        "template",
        "create",
        "e2e-warm",
        "--image",
        "nvcr.io/nvidia/base/ubuntu:24.04",
        "--ready-within",
        "5s",
        "--max-burst",
        "1",
    ])
    .await;
    assert_eq!(code, 0, "{output}");
    let spare = ready_spare(None).await;
    let record: serde_json::Value = serde_json::from_str(
        spare["metadata"]["annotations"]["openshell.ai/warm-runtime"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let session = record["session_id"].as_str().unwrap();
    let physical_name = spare["metadata"]["name"].as_str().unwrap();
    let pod = kubectl_json(&[
        "-n",
        &release_namespace(),
        "get",
        "pod",
        physical_name,
        "-o",
        "json",
    ])
    .await;
    let dedicated_uid =
        spare["metadata"]["annotations"]["openshell.ai/sandbox-runtime-supervisor-uid"].as_str();
    let prepared_secret = if let Some(uid) = dedicated_uid {
        let pods = kubectl_json(&["-n", &release_namespace(), "get", "pods", "-o", "json"]).await;
        let supervisor = pods["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|pod| pod["metadata"]["uid"] == uid)
            .unwrap();
        assert_eq!(supervisor["status"]["containerStatuses"][0]["ready"], false);
        let name = supervisor["spec"]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|volume| volume["name"] == "bootstrap")
            .unwrap()["secret"]["secretName"]
            .as_str()
            .unwrap();
        let secret = kubectl_json(&[
            "-n",
            &release_namespace(),
            "get",
            "secret",
            name,
            "-o",
            "json",
        ])
        .await;
        assert!(secret["data"].get("instance.json").is_none());
        // Remain on the same registration stream while the runtime is idle.
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let logs = kubectl(&[
                    "-n",
                    &release_namespace(),
                    "logs",
                    "-l",
                    GATEWAY_SELECTOR,
                    "-c",
                    GATEWAY_CONTAINER,
                    "--tail=2000",
                ])
                .await;
                if logs.lines().any(|line| {
                    line.contains(session)
                        && line.contains("dedicated supervisor registration pending")
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_secs(35)).await;
        Some((
            name.to_string(),
            secret["metadata"]["resourceVersion"].clone(),
        ))
    } else {
        None
    };
    let mut sandbox = SandboxGuard::create_with_gateway_default(&["--template", "e2e-warm"])
        .await
        .expect("claim warm runtime");
    wait_for_sandbox_phase(&sandbox.name, "Ready", Duration::from_mins(2))
        .await
        .unwrap();
    let claimed = generation(&sandbox.name).await;
    assert_eq!(
        claimed.runtime, session,
        "create must claim the ready physical generation"
    );
    assert_eq!(
        claimed.workload_pod_uid,
        pod["metadata"]["uid"].as_str().unwrap()
    );
    assert_eq!(
        claimed.route,
        dedicated_uid.map_or_else(|| format!("rt-{session}"), str::to_string)
    );
    if let Some(uid) = dedicated_uid {
        // Gateway session readiness can precede the kubelet's next probe and
        // Pod status update. Require readiness on the same unrestarted Pod.
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let pods =
                    kubectl_json(&["-n", &release_namespace(), "get", "pods", "-o", "json"]).await;
                let supervisor = pods["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|pod| pod["metadata"]["uid"] == uid)
                    .expect("claim must preserve the original dedicated supervisor Pod");
                let status = &supervisor["status"]["containerStatuses"][0];
                assert_eq!(status["restartCount"], 0);
                if status["ready"] == true {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .expect("claimed supervisor must become ready");
    }
    if let Some((name, version)) = prepared_secret {
        let secret = kubectl_json(&[
            "-n",
            &release_namespace(),
            "get",
            "secret",
            &name,
            "-o",
            "json",
        ])
        .await;
        assert_eq!(
            secret["metadata"]["resourceVersion"], version,
            "claim must not update the mounted Secret"
        );
        let logs = kubectl(&[
            "-n",
            &release_namespace(),
            "logs",
            "-l",
            GATEWAY_SELECTOR,
            "-c",
            GATEWAY_CONTAINER,
            "--tail=2000",
        ])
        .await;
        assert_eq!(
            logs.lines()
                .filter(|line| line.contains(session)
                    && line.contains("dedicated supervisor registration pending"))
                .count(),
            1,
            "unclaimed registration must stay open"
        );
        assert!(
            logs.lines().any(|line| line.contains(session)
                && line.contains("dedicated supervisor claim delivered"))
        );
    }
    assert!(
        sandbox
            .exec(&["sh", "-c", "printf warm-claim-ok"])
            .await
            .unwrap()
            .contains("warm-claim-ok")
    );
    let replacement = ready_spare(Some(session)).await;
    assert_ne!(replacement["metadata"]["uid"], spare["metadata"]["uid"]);
    let (output, code) = run_cli(&["sandbox", "stop", &sandbox.name]).await;
    assert_eq!(code, 0, "{output}");
    if let Some(uid) = dedicated_uid {
        let pods = kubectl_json(&["-n", &release_namespace(), "get", "pods", "-o", "json"]).await;
        assert!(
            pods["items"].as_array().unwrap().iter().all(|pod| {
                pod["metadata"]["uid"] != uid || pod["metadata"]["deletionTimestamp"].is_string()
            }),
            "stop must remove the claimed physical supervisor"
        );
    }
    let (output, code) = run_cli(&["sandbox", "start", &sandbox.name]).await;
    assert_eq!(code, 0, "{output}");
    wait_for_sandbox_phase(&sandbox.name, "Ready", Duration::from_mins(2))
        .await
        .unwrap();
    let restarted = generation(&sandbox.name).await;
    assert_ne!(restarted.runtime, claimed.runtime);
    assert_ne!(restarted.route, claimed.route);
    assert_ne!(restarted.workload_pod_uid, claimed.workload_pod_uid);
    assert!(
        sandbox
            .exec(&["sh", "-c", "printf warm-restart-ok"])
            .await
            .unwrap()
            .contains("warm-restart-ok")
    );
    sandbox.delete().await.unwrap();
    let (output, code) = run_cli(&["sandbox", "template", "delete", "e2e-warm"]).await;
    assert_eq!(code, 0, "{output}");
    tokio::time::timeout(Duration::from_mins(3), async {
        loop {
            let resources = kubectl_json(&[
                "-n",
                &release_namespace(),
                "get",
                "sandboxes.agents.x-k8s.io",
                "-l",
                "openshell.ai/warm-pool",
                "-o",
                "json",
            ])
            .await;
            if resources["items"].as_array().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .expect("deleting the template must drain unclaimed capacity");
}
