// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod lifecycle_reconciliation {
    use super::*;

    // Availability reads run concurrently. Match pending responses by path
    // rather than assuming tokio::join! polls its branches in a fixed order.
    fn read_only_driver(steps: Vec<KubeTestStep>) -> ScriptedDriver {
        let steps = Arc::new(std::sync::Mutex::new(VecDeque::from(steps)));
        let pending = steps.clone();
        let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
            let pending = pending.clone();
            async move {
                assert_eq!(
                    request.method(),
                    http::Method::GET,
                    "reconciliation must preserve the replacement"
                );
                let mut pending = pending.lock().unwrap();
                let index = pending
                    .iter()
                    .position(|(method, path, _)| {
                        request.method() == method && request.uri().path() == *path
                    })
                    .unwrap_or_else(|| panic!("unexpected read {}", request.uri().path()));
                let (_, _, response) = pending.remove(index).unwrap();
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        let client = Client::new(service, "openshell");
        let driver = KubernetesComputeDriver {
            client: client.clone(),
            watch_client: client,
            sandbox_api_version: Arc::new(OnceCell::new()),
            lifecycle_gates: Arc::default(),
            config: KubernetesComputeConfig::default(),
            operator_allowlist: None,
        };
        (driver, steps, Arc::default())
    }

    fn snapshot(version: &str, phase: Option<SandboxRuntimeBootstrapPhase>) -> serde_json::Value {
        let mut object = serde_json::json!({
            "apiVersion": format!("{SANDBOX_GROUP}/{version}"), "kind": "Sandbox",
            "metadata": {
                "name": "sandbox-cr", "namespace": "openshell", "uid": "cr-uid",
                "resourceVersion": "42",
                "labels": {LABEL_SANDBOX_ID: "sandbox-1", LABEL_SANDBOX_WORKSPACE: "team-a"},
                "annotations": {
                    crate::resource_admission::CONFIG_USED: "false",
                    crate::resource_admission::IDENTITIES: "{}",
                    ANNOTATION_SANDBOX_RUNTIME_READINESS: "unavailable"
                }
            },
            "spec": {"podTemplate": {"spec": {
                "automountServiceAccountToken": false,
                "volumes": [{"name": SANDBOX_BOOTSTRAP_VOLUME_NAME,
                    "secret": {"secretName": "os-sandbox-sandbox-1-gen2"}}]
            }}}
        });
        object["spec"][if version == SANDBOX_VERSION_V1ALPHA1 {
            "replicas"
        } else {
            "operatingMode"
        }] = if version == SANDBOX_VERSION_V1ALPHA1 {
            serde_json::json!(0)
        } else {
            serde_json::json!("Suspended")
        };
        if let Some(phase) = phase {
            object["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING] =
                serde_json::json!("true");
            object["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION] =
                serde_json::json!("stop");
            object["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE] =
                serde_json::json!(phase.as_str());
            object["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID] =
                serde_json::json!("old-supervisor-uid");
        }
        object
    }

    fn restarted_snapshot(version: &str) -> serde_json::Value {
        let mut object = snapshot(version, Some(SandboxRuntimeBootstrapPhase::Preparing));
        object["metadata"]["resourceVersion"] = serde_json::json!("43");
        let annotations = &mut object["metadata"]["annotations"];
        annotations[ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION] = serde_json::json!("restart");
        annotations[ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT] =
            serde_json::json!(openshell_core::time::now_ms().to_string());
        annotations[ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID] =
            serde_json::json!("new-supervisor-uid");
        annotations[ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_UID] =
            serde_json::json!("sandbox-workload-fence-uid");
        annotations[ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_GENERATION] = serde_json::json!("1");
        object["spec"][if version == SANDBOX_VERSION_V1ALPHA1 {
            "replicas"
        } else {
            "operatingMode"
        }] = if version == SANDBOX_VERSION_V1ALPHA1 {
            serde_json::json!(1)
        } else {
            serde_json::json!("Running")
        };
        object
    }

    fn listed(version: &str, object: serde_json::Value) -> KubeTestStep {
        (
            http::Method::GET,
            if version == SANDBOX_VERSION_V1ALPHA1 {
                "/apis/agents.x-k8s.io/v1alpha1/namespaces/openshell/sandboxes"
            } else {
                "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes"
            },
            kube_test_response(
                http::StatusCode::OK,
                serde_json::json!({
                    "apiVersion": format!("{SANDBOX_GROUP}/{version}"),
                    "kind": "SandboxList", "items": [object]
                }),
            ),
        )
    }

    fn refreshed(version: &str, object: serde_json::Value) -> KubeTestStep {
        (
            http::Method::GET,
            if version == SANDBOX_VERSION_V1ALPHA1 {
                "/apis/agents.x-k8s.io/v1alpha1/namespaces/openshell/sandboxes/sandbox-cr"
            } else {
                "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr"
            },
            kube_test_response(http::StatusCode::OK, object),
        )
    }

    fn preparing_dependencies() -> Vec<KubeTestStep> {
        let mut fence = workload_fence("openshell", &SandboxRuntimeNames::new("sandbox-1"), 5500);
        for (policy, component) in [
            (&mut fence.workload_policy, "sandbox-workload-fence"),
            (&mut fence.supervisor_policy, "sandbox-supervisor-egress"),
        ] {
            policy.metadata.labels.get_or_insert_default().extend([
                (
                    LABEL_MANAGED_BY.to_string(),
                    LABEL_MANAGED_BY_VALUE.to_string(),
                ),
                ("openshell.ai/component".to_string(), component.to_string()),
            ]);
            policy.metadata.uid = Some(format!("{component}-uid"));
            policy.metadata.generation = Some(1);
        }
        let workload = || {
            (
                http::Method::GET,
                "/apis/networking.k8s.io/v1/namespaces/openshell/networkpolicies/openshell-sandbox-workloads",
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::to_value(&fence.workload_policy).unwrap(),
                ),
            )
        };
        let supervisor = || {
            (
                http::Method::GET,
                "/apis/networking.k8s.io/v1/namespaces/openshell/networkpolicies/openshell-sandbox-supervisors",
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::to_value(&fence.supervisor_policy).unwrap(),
                ),
            )
        };
        vec![
            workload(),
            supervisor(),
            workload(),
            (
                http::Method::GET,
                "/api/v1/namespaces/openshell/pods/os-supervisor-sandbox-1",
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion": "v1", "kind": "Pod",
                        "metadata": {"name": "os-supervisor-sandbox-1", "uid": "new-supervisor-uid"},
                        "spec": {"containers": []}, "status": {"phase": "Pending"}
                    }),
                ),
            ),
            (
                http::Method::GET,
                "/api/v1/namespaces/openshell/services/os-boundary-sandbox-1",
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion": "v1", "kind": "Service", "metadata": {"name": "os-boundary-sandbox-1"}
                    }),
                ),
            ),
            workload(),
            supervisor(),
        ]
    }

    #[tokio::test]
    async fn stale_stop_snapshots_cannot_delete_a_restarted_supervisor() {
        for version in [SANDBOX_VERSION_V1ALPHA1, SANDBOX_VERSION_V1BETA1] {
            for phase in [
                None,
                Some(SandboxRuntimeBootstrapPhase::Releasing),
                Some(SandboxRuntimeBootstrapPhase::Suspending),
            ] {
                // Restart completed its critical section after LIST. The old
                // implementation either deleted the replacement or attempted
                // cleanup using the old stop transition. Every allowed request
                // here is a read; unexpected DELETE/PATCH/Secret access fails.
                let mut steps = vec![
                    listed(version, snapshot(version, phase)),
                    refreshed(version, restarted_snapshot(version)),
                ];
                steps.extend(preparing_dependencies());
                let (driver, steps, _) = read_only_driver(steps);
                driver.sandbox_api_version.set(version).unwrap();
                driver.reconcile_sandbox_runtime_resources().await;
                assert!(steps.lock().unwrap().is_empty());
            }
        }
    }

    #[tokio::test]
    async fn reconciliation_skips_a_busy_restart_and_retries_after_release() {
        let version = SANDBOX_VERSION_V1BETA1;
        let mut steps = vec![
            listed(version, snapshot(version, None)),
            listed(version, snapshot(version, None)),
            refreshed(version, restarted_snapshot(version)),
        ];
        steps.extend(preparing_dependencies());
        let (driver, steps, _) = read_only_driver(steps);
        driver.sandbox_api_version.set(version).unwrap();
        let clone = driver.clone();
        let guard = clone
            .lifecycle_gates
            .gate_for("sandbox-1")
            .lock_owned()
            .await;
        // Restart may already have created its Pod while the CR is still
        // stopped. Reconciliation must skip even reading that companion.
        driver.reconcile_sandbox_runtime_resources().await;
        drop(guard);
        driver.reconcile_sandbox_runtime_resources().await;
        assert!(steps.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn refresh_cannot_adopt_a_replaced_sandbox_cr() {
        let version = SANDBOX_VERSION_V1BETA1;
        let mut replacement = restarted_snapshot(version);
        replacement["metadata"]["uid"] = serde_json::json!("another-cr-uid");
        let (driver, steps, _) = read_only_driver(vec![
            listed(version, snapshot(version, None)),
            refreshed(version, replacement),
        ]);
        driver.sandbox_api_version.set(version).unwrap();
        driver.reconcile_sandbox_runtime_resources().await;
        assert!(steps.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn lifecycle_requests_share_gates_across_clones_without_blocking_other_sandboxes() {
        let driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig::default());
        let clone = driver.clone();
        let guard = clone
            .lifecycle_gates
            .gate_for("sandbox-1")
            .lock_owned()
            .await;
        let sandbox = Sandbox {
            id: "sandbox-1".to_string(),
            ..Default::default()
        };
        let mut create = Box::pin(driver.create_sandbox(&sandbox));
        let mut stop = Box::pin(driver.stop_sandbox("sandbox-1"));
        let mut delete = Box::pin(driver.delete_sandbox("sandbox-1"));
        let mut start = Box::pin(driver.start_sandbox("sandbox-1", "", &[], ""));
        assert!(futures::poll!(&mut create).is_pending());
        assert!(futures::poll!(&mut stop).is_pending());
        assert!(futures::poll!(&mut delete).is_pending());
        assert!(futures::poll!(&mut start).is_pending());
        driver
            .start_sandbox("sandbox-2", "", &[], "")
            .await
            .unwrap_err();
        // Cancel queued mutations, then let start obtain the gate. Its normal
        // generation validation proves release did not leave it deadlocked.
        drop(create);
        drop(stop);
        drop(delete);
        drop(guard);
        assert!(matches!(
            start.await,
            Err(KubernetesDriverError::InvalidArgument(_))
        ));
    }
}
