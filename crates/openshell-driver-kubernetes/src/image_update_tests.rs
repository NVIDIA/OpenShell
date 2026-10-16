// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION, ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE,
    ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING, ANNOTATION_SANDBOX_RUNTIME_LOG_LEVEL,
    ANNOTATION_SANDBOX_RUNTIME_MAIN_PROCESS_SPEC, ANNOTATION_SANDBOX_RUNTIME_READINESS,
    KubernetesComputeConfig, LABEL_SANDBOX_WORKSPACE, OperatorNamespaceAllowlist,
    SANDBOX_BOOTSTRAP_CONTAINER_NAME, SANDBOX_BOOTSTRAP_VOLUME_NAME, SANDBOX_GROUP,
    SANDBOX_VERSION_V1ALPHA1, WORKSPACE_INIT_MOUNT_PATH, WorkspaceMode,
};
use super::*;
use http_body_util::BodyExt as _;
use kube::Client;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::OnceCell;

struct ApiState {
    sandbox: serde_json::Value,
    pvc: serde_json::Value,
    pods: Vec<serde_json::Value>,
    calls: Vec<(http::Method, String)>,
    patches: Vec<serde_json::Value>,
    conflict: bool,
    pods_continue: bool,
}

fn response(
    status: http::StatusCode,
    value: serde_json::Value,
) -> http::Response<kube::client::Body> {
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(kube::client::Body::from(value.to_string().into_bytes()))
        .unwrap()
}

fn merge(target: &mut serde_json::Value, patch: &serde_json::Value) {
    if let Some(patch) = patch.as_object() {
        for (key, value) in patch {
            if value.is_null() {
                target.as_object_mut().unwrap().remove(key);
            } else {
                if target.get(key).is_none() {
                    target[key] = serde_json::Value::Null;
                }
                if value.is_object() && !target[key].is_object() {
                    target[key] = serde_json::json!({});
                }
                merge(&mut target[key], value);
            }
        }
    } else {
        *target = patch.clone();
    }
}

fn snapshot(version: &str) -> serde_json::Value {
    let mut value = serde_json::json!({
        "apiVersion": format!("{SANDBOX_GROUP}/{version}"),
        "kind": "Sandbox",
        "metadata": {
            "name": "sandbox-cr", "namespace": "openshell", "uid": "resource-uid",
            "resourceVersion": "42", "generation": 7,
            "labels": {LABEL_SANDBOX_ID: "sandbox-1", LABEL_SANDBOX_NAME: "sandbox-name", LABEL_SANDBOX_WORKSPACE: "team-a"},
            "annotations": {
                LABEL_SANDBOX_ID: "sandbox-1", LABEL_SANDBOX_NAME: "sandbox-name",
                crate::resource_admission::CONFIG_USED: "true",
                crate::resource_admission::IDENTITIES: "{\"PersistentVolumeClaim/openshell/team-data\":\"data-pvc-uid\"}",
                "operator.example/bootstrap-provenance": "preserve-me",
                ANNOTATION_SANDBOX_RUNTIME_MAIN_PROCESS_SPEC: "stored-launch-spec",
                ANNOTATION_SANDBOX_RUNTIME_LOG_LEVEL: "info",
                ANNOTATION_SANDBOX_RUNTIME_READINESS: "unavailable",
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING: "false",
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION: "restart",
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE: "released",
                SANDBOX_POD_NAME_ANNOTATION: "recorded-workload"
            },
            "ownerReferences": [{"apiVersion":"v1", "kind":"Namespace", "name":"openshell", "uid":"namespace-uid"}]
        },
        "spec": {
            "volumeClaimTemplates": [{"metadata":{"name":"workspace"}, "spec":{"accessModes":["ReadWriteOnce"], "resources":{"requests":{"storage":"10Gi"}}}}],
            "podTemplate": {
                "metadata": {"annotations": {"operator.example/pod-injection": "preserved"}},
                "spec": {
                    "automountServiceAccountToken": false,
                    "serviceAccountName": "openshell-sandbox",
                    "imagePullSecrets": [{"name":"operator-registry"}],
                    "volumes": [
                        {"name": SANDBOX_BOOTSTRAP_VOLUME_NAME, "secret":{"secretName":"old-bootstrap-secret"}},
                        {"name":"data", "persistentVolumeClaim":{"claimName":"team-data", "readOnly":false}}
                    ],
                    "containers": [
                        {"name":"agent", "image":"registry.example/agent:v1", "command":["/.openshell/runtime/openshell-sandbox"], "env":[{"name":"UNCHANGED","value":"yes"}], "volumeMounts":[{"name":"workspace", "mountPath":"/sandbox"}, {"name":"data", "mountPath":"/data", "subPath":"agent"}]},
                        {"name":"operator-sidecar", "image":"registry.example/agent:v1"}
                    ],
                    "initContainers": [
                        {"name":SANDBOX_BOOTSTRAP_CONTAINER_NAME, "image":"trusted-runtime:v3"},
                        {"name":WORKSPACE_INIT_CONTAINER_NAME, "image":"registry.example/agent:v1", "command":["seed-workspace"], "volumeMounts":[{"name":"workspace", "mountPath":WORKSPACE_INIT_MOUNT_PATH}]},
                        {"name":"operator-init", "image":"registry.example/agent:v1"}
                    ]
                }
            }
        },
        "status":{"conditions":[{"type":"Suspended", "status":"True", "observedGeneration":7}]}
    });
    if version == SANDBOX_VERSION_V1BETA1 {
        value["spec"]["operatingMode"] = serde_json::json!("Suspended");
    } else {
        value["spec"]["replicas"] = serde_json::json!(0);
    }
    value
}

fn fixture(
    version: &'static str,
    operator: bool,
) -> (KubernetesComputeDriver, Arc<Mutex<ApiState>>) {
    let state = Arc::new(Mutex::new(ApiState {
        sandbox: snapshot(version),
        pvc: serde_json::json!({
            "apiVersion":"meta.k8s.io/v1", "kind":"PartialObjectMetadata",
            "metadata": {"name":"team-data", "namespace":"openshell", "uid":"data-pvc-uid",
                "labels": {"openshell.ai/sandbox-attachable":"true", "openshell.ai/sandbox-attachable-workspace":"team-a"}}
        }),
        pods: Vec::new(),
        calls: Vec::new(),
        patches: Vec::new(),
        conflict: false,
        pods_continue: false,
    }));
    let service_state = state.clone();
    let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
        let state = service_state.clone();
        async move {
            let path = request.uri().path().to_string();
            let query = request.uri().query().unwrap_or_default().to_string();
            let method = request.method().clone();
            let body = request.into_body().collect().await.unwrap().to_bytes();
            let mut state = state.lock().unwrap();
            state.calls.push((method.clone(), path.clone()));
            let value = match (method, path.as_str()) {
                (http::Method::GET, path) if path.ends_with("/sandboxes") => {
                    serde_json::json!({"apiVersion":format!("{SANDBOX_GROUP}/{version}"), "kind":"SandboxList", "metadata":{}, "items":[state.sandbox]})
                }
                (http::Method::GET, path) if path.ends_with("/sandboxes/sandbox-cr") => {
                    state.sandbox.clone()
                }
                (
                    http::Method::GET,
                    "/api/v1/namespaces/openshell/persistentvolumeclaims/team-data",
                ) => state.pvc.clone(),
                (http::Method::GET, "/api/v1/namespaces/openshell/pods") => {
                    if state.pods_continue && !query.contains("continue=") {
                        serde_json::json!({"apiVersion":"v1", "kind":"PodList", "metadata":{"continue":"page-two"}, "items":[]})
                    } else {
                        serde_json::json!({"apiVersion":"v1", "kind":"PodList", "metadata":{}, "items":state.pods})
                    }
                }
                (http::Method::PATCH, path) if path.ends_with("/sandboxes/sandbox-cr") => {
                    let mutation: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(
                        mutation["metadata"]["uid"],
                        state.sandbox["metadata"]["uid"]
                    );
                    assert_eq!(
                        mutation["metadata"]["resourceVersion"],
                        state.sandbox["metadata"]["resourceVersion"]
                    );
                    state.patches.push(mutation.clone());
                    if state.conflict {
                        return Ok::<_, std::convert::Infallible>(response(
                            http::StatusCode::CONFLICT,
                            serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "reason":"Conflict", "message":"concurrent start or edit", "code":409}),
                        ));
                    }
                    let next_version = state.sandbox["metadata"]["resourceVersion"]
                        .as_str()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap()
                        + 1;
                    let next_generation =
                        state.sandbox["metadata"]["generation"].as_u64().unwrap() + 1;
                    merge(&mut state.sandbox, &mutation);
                    state.sandbox["metadata"]["resourceVersion"] =
                        serde_json::json!(next_version.to_string());
                    state.sandbox["metadata"]["generation"] = serde_json::json!(next_generation);
                    state.sandbox.clone()
                }
                (method, path) => {
                    panic!("unexpected image update Kubernetes request {method} {path}")
                }
            };
            Ok::<_, std::convert::Infallible>(response(http::StatusCode::OK, value))
        }
    });
    let client = Client::new(service, "openshell");
    let api_version = OnceCell::new();
    api_version.set(version).unwrap();
    let driver = KubernetesComputeDriver {
        client: client.clone(),
        watch_client: client,
        sandbox_api_version: Arc::new(api_version),
        lifecycle_gates: Arc::default(),
        config: KubernetesComputeConfig {
            allow_driver_config: true,
            workspace_mode: if operator {
                WorkspaceMode::Operator
            } else {
                WorkspaceMode::Shared
            },
            ..Default::default()
        },
        operator_allowlist: operator.then(|| {
            OperatorNamespaceAllowlist::from_set(std::iter::once("openshell".to_string()).collect())
        }),
    };
    (driver, state)
}

fn request() -> UpdateSandboxImageRequest {
    UpdateSandboxImageRequest {
        sandbox_id: "sandbox-1".into(),
        name: "sandbox-name".into(),
        image: "registry.example/agent:v2".into(),
        expected_image: "registry.example/agent:v1".into(),
        expected_runtime_identity: "kubernetes://openshell/resource-uid/old-supervisor-uid".into(),
        operation_id: "stable-operation-1".into(),
        validate_only: false,
        revision: 1,
    }
}

#[tokio::test]
async fn image_update_preflight_validates_without_writes_and_apply_rechecks() {
    let (driver, state) = fixture(SANDBOX_VERSION_V1BETA1, false);
    let before = state.lock().unwrap().sandbox.clone();
    let mut preflight = request();
    preflight.validate_only = true;
    driver.update_sandbox_image(&preflight).await.unwrap();
    {
        let state = state.lock().unwrap();
        assert!(state.patches.is_empty());
        assert_eq!(state.sandbox, before);
        assert!(
            state
                .calls
                .iter()
                .any(|(_, path)| path.ends_with("/persistentvolumeclaims/team-data"))
        );
        assert!(state.calls.iter().any(|(_, path)| path.ends_with("/pods")));
    }
    // Operator approval can change between preflight and apply. Both requests
    // independently enforce the entire stopped/admission check.
    state.lock().unwrap().pvc["metadata"]["labels"] = serde_json::json!({});
    assert!(matches!(
        driver.update_sandbox_image(&request()).await,
        Err(KubernetesDriverError::Precondition(_))
    ));
    assert!(matches!(
        driver.update_sandbox_image(&preflight).await,
        Err(KubernetesDriverError::Precondition(_))
    ));
    assert!(state.lock().unwrap().patches.is_empty());
}

#[tokio::test]
async fn image_update_capability_is_optional() {
    let (driver, _) = fixture(SANDBOX_VERSION_V1BETA1, false);
    let metadata = driver.capabilities().unwrap().extension.unwrap();
    let capability = openshell_core::extension_protocol::COMPUTE_UPDATE_SANDBOX_IMAGE;
    assert!(
        metadata
            .supported_capabilities
            .iter()
            .any(|value| value == capability)
    );
    assert!(
        !metadata
            .required_capabilities
            .iter()
            .any(|value| value == capability)
    );
}

#[tokio::test]
async fn image_update_preserves_resource_storage_and_operator_bootstrap_annotations() {
    for version in [SANDBOX_VERSION_V1BETA1, SANDBOX_VERSION_V1ALPHA1] {
        for operator in [false, true] {
            let (driver, state) = fixture(version, operator);
            if operator {
                // Operator-mode identity can live in bootstrap annotations
                // rather than a caller-visible workload-name label.
                state.lock().unwrap().sandbox["metadata"]["labels"]
                    .as_object_mut()
                    .unwrap()
                    .remove(LABEL_SANDBOX_NAME);
            }
            let before = state.lock().unwrap().sandbox.clone();
            let pvc_before = state.lock().unwrap().pvc.clone();
            driver.update_sandbox_image(&request()).await.unwrap();
            let state = state.lock().unwrap();
            let mut expected = before;
            expected["metadata"]["resourceVersion"] = serde_json::json!("43");
            expected["metadata"]["generation"] = serde_json::json!(8);
            expected["metadata"]["annotations"][IMAGE_UPDATE_ANNOTATION] = serde_json::json!(
                serde_json::to_string(&ImageUpdateRecord {
                    operation_id: request().operation_id,
                    expected_image: request().expected_image,
                    image: request().image,
                    revision: request().revision,
                })
                .unwrap()
            );
            expected["spec"]["podTemplate"]["spec"]["containers"][0]["image"] =
                serde_json::json!(request().image);
            expected["spec"]["podTemplate"]["spec"]["initContainers"][1]["image"] =
                serde_json::json!(request().image);
            // Whole-object equality proves claim templates, mounts, owner UID,
            // launch state, operator annotations, and trusted/sidecar images
            // were preserved. The API rejects any unexpected DELETE/POST.
            assert_eq!(state.sandbox, expected);
            assert_eq!(state.pvc, pvc_before);
            assert_eq!(state.patches.len(), 1);
            assert_eq!(
                state.patches[0]["metadata"]["annotations"]
                    .as_object()
                    .unwrap()
                    .len(),
                1
            );
            assert!(
                state.patches[0]["spec"]
                    .get("volumeClaimTemplates")
                    .is_none()
            );
            assert!(
                state.patches[0]["spec"]["podTemplate"]["spec"]
                    .get("volumes")
                    .is_none()
            );
        }
    }
}

#[tokio::test]
async fn image_update_retry_is_durable_and_does_not_patch_twice() {
    let (driver, state) = fixture(SANDBOX_VERSION_V1BETA1, false);
    driver.update_sandbox_image(&request()).await.unwrap();
    // Simulate a process restart by dropping the original in-memory gate state.
    let mut restarted = driver.clone();
    restarted.lifecycle_gates = Arc::default();
    restarted.update_sandbox_image(&request()).await.unwrap();
    assert_eq!(state.lock().unwrap().patches.len(), 1);
    let mut other_operation = request();
    other_operation.operation_id = "other-operation".into();
    other_operation.revision += 1;
    assert!(matches!(
        driver.update_sandbox_image(&other_operation).await,
        Err(KubernetesDriverError::Precondition(_))
    ));
    let mut reused_operation = request();
    reused_operation.image = "registry.example/agent:v3".into();
    assert!(matches!(
        driver.update_sandbox_image(&reused_operation).await,
        Err(KubernetesDriverError::Precondition(_))
    ));
    assert_eq!(state.lock().unwrap().patches.len(), 1);
}

#[tokio::test]
async fn image_update_monotonic_revision_rejects_late_replay_after_a_tag_round_trip() {
    let (driver, state) = fixture(SANDBOX_VERSION_V1BETA1, false);
    let a = request();
    driver.update_sandbox_image(&a).await.unwrap();
    let mut b = a.clone();
    b.expected_image = a.image.clone();
    b.image = a.expected_image.clone();
    b.operation_id = "operation-b".into();
    b.revision = 2;
    driver.update_sandbox_image(&b).await.unwrap();
    let before = state.lock().unwrap().sandbox.clone();
    // The current tag again matches A's expected image, but its revision is
    // stale. The latest evidence must reject A rather than reapply it.
    assert!(matches!(driver.update_sandbox_image(&a).await,
        Err(KubernetesDriverError::Precondition(message)) if message.contains("older")));
    let mut conflicting = a.clone();
    conflicting.operation_id = "different-operation-at-revision-2".into();
    conflicting.revision = b.revision;
    assert!(matches!(driver.update_sandbox_image(&conflicting).await,
        Err(KubernetesDriverError::Precondition(message)) if message.contains("revision was already used")));
    assert_eq!(state.lock().unwrap().patches.len(), 2);
    assert_eq!(state.lock().unwrap().sandbox, before);
    driver.update_sandbox_image(&b).await.unwrap();
    assert_eq!(state.lock().unwrap().patches.len(), 2);
    conflicting.revision = 3;
    driver.update_sandbox_image(&conflicting).await.unwrap();
    assert_eq!(state.lock().unwrap().patches.len(), 3);
}

#[tokio::test]
async fn image_update_rejects_zero_revision_before_kubernetes_io() {
    let (driver, state) = fixture(SANDBOX_VERSION_V1BETA1, false);
    let mut request = request();
    request.revision = 0;
    assert!(matches!(
        driver.update_sandbox_image(&request).await,
        Err(KubernetesDriverError::InvalidArgument(_))
    ));
    assert!(state.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn image_update_rejects_running_bootstrapping_and_unspecified_operating_state() {
    for version in [SANDBOX_VERSION_V1BETA1, SANDBOX_VERSION_V1ALPHA1] {
        for scenario in ["running", "bootstrap", "missing", "deleting"] {
            let (driver, state) = fixture(version, false);
            {
                let mut state = state.lock().unwrap();
                match scenario {
                    "running" if version == SANDBOX_VERSION_V1BETA1 => {
                        state.sandbox["spec"]["operatingMode"] = serde_json::json!("Running");
                    }
                    "running" => state.sandbox["spec"]["replicas"] = serde_json::json!(1),
                    "bootstrap" => {
                        state.sandbox["metadata"]["annotations"]
                            [ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING] = serde_json::json!("true");
                    }
                    "missing" => {
                        state.sandbox["spec"].as_object_mut().unwrap().remove(
                            if version == SANDBOX_VERSION_V1BETA1 {
                                "operatingMode"
                            } else {
                                "replicas"
                            },
                        );
                    }
                    "deleting" => {
                        state.sandbox["metadata"]["deletionTimestamp"] =
                            serde_json::json!("2026-10-15T18:00:00Z");
                    }
                    _ => unreachable!(),
                }
            }
            assert!(
                matches!(
                    driver.update_sandbox_image(&request()).await,
                    Err(KubernetesDriverError::Precondition(_))
                ),
                "{scenario} {version}"
            );
            assert!(state.lock().unwrap().patches.is_empty());
        }
    }
}

#[tokio::test]
async fn image_update_checks_actual_workload_and_supervisor_pods_including_later_pages() {
    for metadata in [
        serde_json::json!({"name":"controller-workload", "ownerReferences":[{"apiVersion":"agents.x-k8s.io/v1beta1", "kind":"Sandbox", "name":"sandbox-cr", "uid":"resource-uid"}]}),
        serde_json::json!({"name":"supervisor", "labels":{LABEL_SANDBOX_ID:"sandbox-1"}}),
        serde_json::json!({"name":"recorded-workload", "deletionTimestamp":"2026-10-15T18:00:00Z"}),
        serde_json::json!({"name":"workload-with-annotation", "annotations":{LABEL_SANDBOX_ID:"sandbox-1"}}),
    ] {
        let (driver, state) = fixture(SANDBOX_VERSION_V1BETA1, false);
        {
            let mut state = state.lock().unwrap();
            state
                .pods
                .push(serde_json::json!({"apiVersion":"v1", "kind":"Pod", "metadata":metadata}));
            state.pods_continue = true;
        }
        let result = driver.update_sandbox_image(&request()).await;
        assert!(
            matches!(result, Err(KubernetesDriverError::Precondition(message)) if message.contains("Pods still exist"))
        );
        assert!(state.lock().unwrap().patches.is_empty());
    }
}

#[tokio::test]
async fn image_update_rejects_image_name_and_runtime_identity_conflicts() {
    for scenario in ["image", "name", "runtime", "seed", "missing-provenance"] {
        let (driver, state) = fixture(SANDBOX_VERSION_V1BETA1, false);
        let mut request = request();
        match scenario {
            "image" => request.expected_image = "registry.example/agent:other".into(),
            "name" => request.name = "different-name".into(),
            "runtime" => {
                request.expected_runtime_identity =
                    "kubernetes://openshell/replacement-uid/old-supervisor".into();
            }
            "seed" => {
                state.lock().unwrap().sandbox["spec"]["podTemplate"]["spec"]["initContainers"][1]
                    ["image"] = serde_json::json!("different-seed:v1");
            }
            "missing-provenance" => {
                state.lock().unwrap().sandbox["metadata"]["annotations"]
                    .as_object_mut()
                    .unwrap()
                    .remove(crate::resource_admission::CONFIG_USED);
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(
                driver.update_sandbox_image(&request).await,
                Err(KubernetesDriverError::Precondition(_))
            ),
            "{scenario}"
        );
        assert!(state.lock().unwrap().patches.is_empty());
    }
}

#[tokio::test]
async fn image_update_revalidates_attachment_admission_and_uid_even_on_retry() {
    for retry in [false, true] {
        for scenario in ["labels", "uid", "config-disabled"] {
            let (mut driver, state) = fixture(SANDBOX_VERSION_V1BETA1, false);
            if retry {
                driver.update_sandbox_image(&request()).await.unwrap();
            }
            match scenario {
                "labels" => state.lock().unwrap().pvc["metadata"]["labels"] = serde_json::json!({}),
                "uid" => {
                    state.lock().unwrap().pvc["metadata"]["uid"] =
                        serde_json::json!("replacement-pvc-uid");
                }
                "config-disabled" => driver.config.allow_driver_config = false,
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    driver.update_sandbox_image(&request()).await,
                    Err(KubernetesDriverError::Precondition(_))
                ),
                "{scenario} retry={retry}"
            );
            assert_eq!(state.lock().unwrap().patches.len(), usize::from(retry));
        }
    }
}

#[tokio::test]
async fn image_update_conflict_does_not_blindly_retry_or_recreate() {
    let (driver, state) = fixture(SANDBOX_VERSION_V1BETA1, false);
    state.lock().unwrap().conflict = true;
    let before = state.lock().unwrap().sandbox.clone();
    assert!(
        matches!(driver.update_sandbox_image(&request()).await, Err(KubernetesDriverError::Precondition(message)) if message.contains("changed during image update"))
    );
    let state = state.lock().unwrap();
    assert_eq!(state.patches.len(), 1);
    assert_eq!(state.sandbox, before);
}

#[tokio::test]
async fn image_update_grpc_maps_validation_and_precondition_errors() {
    use openshell_core::proto::compute::v1::compute_driver_image_updates_server::ComputeDriverImageUpdates;
    let (driver, state) = fixture(SANDBOX_VERSION_V1BETA1, false);
    let service = crate::ComputeDriverService::new(driver);
    let mut invalid = request();
    invalid.image = "https://registry.example/image:v2".into();
    let error = service
        .update_sandbox_image(tonic::Request::new(invalid))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(state.lock().unwrap().calls.is_empty());
    let mut conflict = request();
    conflict.expected_image = "other:v1".into();
    let error = service
        .update_sandbox_image(tonic::Request::new(conflict))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn image_update_can_repair_a_legacy_invalid_image_reference() {
    let (driver, state) = fixture(SANDBOX_VERSION_V1BETA1, false);
    let invalid_image = "UpperCaseRepository";
    {
        let mut state = state.lock().unwrap();
        state.sandbox["spec"]["podTemplate"]["spec"]["containers"][0]["image"] =
            serde_json::json!(invalid_image);
        state.sandbox["spec"]["podTemplate"]["spec"]["initContainers"][1]["image"] =
            serde_json::json!(invalid_image);
    }
    let mut update = request();
    update.expected_image = invalid_image.into();
    driver.update_sandbox_image(&update).await.unwrap();
    let state = state.lock().unwrap();
    assert_eq!(state.patches.len(), 1);
    assert_eq!(
        state.sandbox["spec"]["podTemplate"]["spec"]["containers"][0]["image"],
        update.image
    );
    assert_eq!(state.sandbox["metadata"]["uid"], "resource-uid");
}

#[test]
fn image_update_validates_container_references() {
    for image in [
        "agent",
        "registry.example:5000/team/agent:v2",
        "localhost/agent:Tag_1",
        "[::1]:5000/team/agent",
        "team/image__name:v2",
        &format!("registry.example/agent@sha256:{}", "a".repeat(64)),
    ] {
        validate_workload_image(image).unwrap();
    }
    for image in [
        "",
        " image:v2",
        "image:v2\n",
        "https://host/image",
        "host//image",
        "UpperCaseRepository",
        "agent:",
        "agent@sha256:invalid",
        "agent@sha256:abc",
        &format!("agent@sha256:{}", "a".repeat(32)),
        &format!("agent@sha256:{}", "a".repeat(65)),
        &format!("{}:v1", "a".repeat(256)),
        "../agent",
        &"a".repeat(2049),
    ] {
        assert!(validate_workload_image(image).is_err(), "{image:?}");
    }
}

#[tokio::test]
async fn image_update_serializes_with_other_lifecycle_operations() {
    let (driver, state) = fixture(SANDBOX_VERSION_V1BETA1, false);
    let guard = driver
        .lifecycle_gates
        .gate_for("sandbox-1")
        .lock_owned()
        .await;
    let request = request();
    let pending = driver.update_sandbox_image(&request);
    tokio::pin!(pending);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut pending)
            .await
            .is_err()
    );
    assert!(state.lock().unwrap().calls.is_empty());
    drop(guard);
    pending.await.unwrap();
}
