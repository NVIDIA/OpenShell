// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use http_body_util::BodyExt;
use openshell_supervisor_control::{
    ActivationRequest, InstancePlacement, PlacementFuture, PlacementRequest, PreparationRelease,
    PreparationRequest, PreparationRevision, PreparedRuntime, proto::SandboxInstanceAssignment,
};
use serde_json::{Value, json};
use std::sync::Mutex;

const SANDBOXES: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
const PODS: &str = "/api/v1/namespaces/openshell/pods";
const SECRETS: &str = "/api/v1/namespaces/openshell/secrets";

#[derive(Default, Debug)]
#[allow(clippy::struct_excessive_bools)]
struct State {
    token_review: Option<Value>,
    journal: Option<openshell_supervisor_control::warm_pool::WarmPoolSnapshot>,
    public_trust: Option<Value>,
    fail_journal_read: bool,
    objects: BTreeMap<String, Value>,
    events: Vec<String>,
    preparations: Vec<PreparationRequest>,
    refuse_capacity: bool,
    /// Lose the response after committing a write to this collection/resource.
    lose_response: Option<String>,
    fail_read: Option<(String, u16)>,
    replace_pod_on_prepare: bool,
    mutate_pod_on_prepare: bool,
    other_gate: bool,
    conflict: Option<Value>,
    version: u64,
    retirement: Option<Result<PreparationRelease, String>>,
    replace_on_retirement: bool,
    delete_conflict: Option<Value>,
    lose_delete_response: bool,
    activated: BTreeMap<String, SandboxInstanceAssignment>,
    lose_activation_response: bool,
}

#[derive(Debug)]
struct Placement(Arc<Mutex<State>>);

impl InstancePlacement for Placement {
    fn warm_runtime_trust(&self) -> PlacementFuture<WarmRuntimeTrust> {
        let trust =
            serde_json::from_value(self.0.lock().unwrap().public_trust.clone().unwrap()).unwrap();
        Box::pin(async move { Ok(trust) })
    }
    fn warm_pool_targets(
        &self,
        _: Option<String>,
    ) -> PlacementFuture<Vec<openshell_supervisor_control::warm_pool::WarmPoolTarget>> {
        let pool = pool_config();
        Box::pin(async move {
            Ok(vec![
                openshell_supervisor_control::warm_pool::WarmPoolTarget {
                    pool_id: pool.name,
                    workspace: pool.workspace,
                    target: pool.target_size,
                    spec: Some(pool.spec),
                },
            ])
        })
    }
    fn warm_pool_state(
        &self,
        _: String,
        _: String,
    ) -> PlacementFuture<Option<openshell_supervisor_control::warm_pool::WarmPoolSnapshot>> {
        let state = self.0.lock().unwrap();
        let result = if state.fail_journal_read {
            Err("journal unavailable".into())
        } else {
            Ok(state.journal.clone())
        };
        Box::pin(async move { result })
    }
    fn update_warm_pool(
        &self,
        update: openshell_supervisor_control::warm_pool::WarmPoolUpdate,
    ) -> PlacementFuture<bool> {
        let mut state = self.0.lock().unwrap();
        let changed = state
            .journal
            .as_ref()
            .map(|snapshot| snapshot.resource_version)
            == update.expected_version;
        if changed {
            state.events.push("journal".into());
            state.journal = Some(openshell_supervisor_control::warm_pool::WarmPoolSnapshot {
                resource_version: update.expected_version.unwrap_or(0) + 1,
                state: update.state,
            });
        }
        Box::pin(async move { Ok(changed) })
    }
    fn retire_preparation(
        &self,
        request: PreparationRetirement,
    ) -> PlacementFuture<PreparationRelease> {
        let mut state = self.0.lock().unwrap();
        state.events.push("retire".into());
        let Some((_, object)) = state
            .objects
            .iter_mut()
            .find(|(path, _)| *path == &format!("{SANDBOXES}/warm-{}", request.generation))
        else {
            return Box::pin(async { Ok(PreparationRelease::Released) });
        };
        assert_eq!(object["metadata"]["annotations"][RETIRING], "true");
        let record: Record =
            serde_json::from_str(object["metadata"]["annotations"][RECORD].as_str().unwrap())
                .unwrap();
        assert_eq!(request.route, record.route());
        assert_eq!(request.workspace, record.workspace);
        assert_eq!(request.generation.as_str(), record.physical_id());
        assert_eq!(request.auth_epoch, record.trust.auth_epoch);
        if state.replace_on_retirement {
            let (_, object) = state
                .objects
                .iter_mut()
                .find(|(path, _)| path.starts_with(&format!("{SANDBOXES}/")))
                .unwrap();
            object["metadata"]["uid"] = json!("replacement");
        }
        let result = state
            .retirement
            .clone()
            .unwrap_or(Ok(PreparationRelease::Released));
        Box::pin(async move { result })
    }
    fn prepare_runtime(&self, request: PreparationRequest) -> PlacementFuture {
        let mut state = self.0.lock().unwrap();
        let expected_uid =
            &request.registration.runtime_descriptor.resource_claims["kubernetes.workload_pod_uid"];
        assert!(
            state
                .objects
                .iter()
                .any(|(path, object)| path.starts_with(SECRETS)
                    && object["metadata"]["ownerReferences"][0]["uid"].as_str()
                        == Some(expected_uid))
        );
        state.events.push("reserve".into());
        state.preparations.push(request);
        if state.replace_pod_on_prepare {
            let (_, pod) = state
                .objects
                .iter_mut()
                .find(|(path, _)| path.starts_with(PODS))
                .unwrap();
            pod["metadata"]["uid"] = json!("replacement-pod");
            pod["metadata"]["resourceVersion"] = json!("replacement-version");
        }
        if state.mutate_pod_on_prepare {
            let (_, pod) = state
                .objects
                .iter_mut()
                .find(|(path, _)| path.starts_with(PODS))
                .unwrap();
            pod["spec"]["initContainers"][0]["image"] = json!("untrusted-image");
        }
        let result = if state.refuse_capacity {
            Err("no supervisor capacity".into())
        } else {
            Ok(())
        };
        Box::pin(async move { result })
    }

    fn place_launch(&self, _: PlacementRequest) -> PlacementFuture {
        panic!("unexpected active launch")
    }
    fn prepared_runtimes(&self, _: String) -> PlacementFuture<Vec<PreparedRuntime>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn release_preparation(&self, _: PreparationRevision) -> PlacementFuture<PreparationRelease> {
        panic!("unexpected release")
    }
    fn activate_runtime(
        &self,
        request: ActivationRequest,
    ) -> PlacementFuture<SandboxInstanceAssignment> {
        let mut state = self.0.lock().unwrap();
        let assignment = request.assignment;
        let registration = SandboxInstanceRegistration::from_assignment(&assignment).unwrap();
        let cr = state
            .objects
            .get(&format!(
                "{SANDBOXES}/warm-{}",
                registration.runtime_descriptor.session_id
            ))
            .unwrap();
        assert_eq!(
            cr["metadata"]["labels"][LABEL_SANDBOX_ID],
            assignment.sandbox_id
        );
        assert!(
            cr["metadata"]["annotations"][claim::CLAIM].is_string(),
            "claim precedes activation"
        );
        state.events.push("activate".into());
        let committed = state
            .activated
            .entry(assignment.route.clone())
            .or_insert_with(|| {
                let mut registration = registration;
                registration.auth.gateway_token =
                    openshell_core::jwt::SecretJwt::parse("committed-gateway").unwrap();
                registration.auth.sandbox_token =
                    openshell_core::jwt::SecretJwt::parse("committed-sandbox").unwrap();
                registration.to_assignment().unwrap()
            })
            .clone();
        assert_eq!(committed.sandbox_id, assignment.sandbox_id);
        let lost = std::mem::take(&mut state.lose_activation_response);
        Box::pin(async move {
            if lost {
                Err("activation response lost".into())
            } else {
                Ok(committed)
            }
        })
    }
    fn recorded(&self) -> PlacementFuture<BTreeMap<String, i64>> {
        panic!("unexpected recovery")
    }
    fn record_recovered(&self, _: SandboxInstanceAssignment) -> PlacementFuture {
        panic!("unexpected recovery")
    }
}

fn response(code: u16, body: Value) -> http::Response<http_body_util::Full<bytes::Bytes>> {
    http::Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            serde_json::to_vec(&body).unwrap(),
        )))
        .unwrap()
}

fn error(code: u16) -> http::Response<http_body_util::Full<bytes::Bytes>> {
    response(
        code,
        json!({"apiVersion":"v1","kind":"Status","status":"Failure",
            "message":"fixture error","reason": if code == 404 {"NotFound"} else {"fixture"}, "code":code}),
    )
}

fn merge(target: &mut Value, patch: &Value) {
    if let (Some(target), Some(patch)) = (target.as_object_mut(), patch.as_object()) {
        for (key, value) in patch {
            if value.is_null() {
                target.remove(key);
            } else {
                merge(target.entry(key).or_insert(Value::Null), value);
            }
        }
    } else {
        *target = patch.clone();
    }
}

fn fixture(state: Arc<Mutex<State>>) -> KubernetesComputeDriver {
    if state.lock().unwrap().public_trust.is_none() {
        state.lock().unwrap().public_trust = Some(serde_json::to_value(request().trust).unwrap());
    }
    let service_state = state.clone();
    let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
        let state = service_state.clone();
        async move {
            let method = request.method().clone();
            let path = request.uri().path().to_string();
            let selector = request
                .uri()
                .query()
                .unwrap_or_default()
                .split('&')
                .find_map(|part| part.strip_prefix("labelSelector="))
                .unwrap_or_default()
                .replace("%3D", "=")
                .replace("%2C", ",")
                .replace("%2F", "/");
            let bytes = request.into_body().collect().await.unwrap().to_bytes();
            let body = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            let mut state = state.lock().unwrap();
            state.events.push(format!("{method} {path}"));
            let result = match method {
                http::Method::DELETE => {
                    if let Some(change) = state.delete_conflict.take() {
                        state.version += 1;
                        let version = state.version.to_string();
                        let object = state.objects.get_mut(&path).unwrap();
                        merge(object, &change);
                        object["metadata"]["resourceVersion"] = json!(version);
                    }
                    let Some(object) = state.objects.get(&path) else {
                        return Ok(error(404));
                    };
                    assert_eq!(body["propagationPolicy"], "Foreground");
                    if body["preconditions"]["uid"] != object["metadata"]["uid"]
                        || body["preconditions"]["resourceVersion"]
                            != object["metadata"]["resourceVersion"]
                    {
                        return Ok(error(409));
                    }
                    state.objects.remove(&path);
                    if state.lose_delete_response {
                        state.lose_delete_response = false;
                        return Ok(error(504));
                    }
                    response(
                        200,
                        json!({"apiVersion":"v1","kind":"Status","status":"Success"}),
                    )
                }
                http::Method::GET => {
                    if let Some((failed_path, code)) = &state.fail_read
                        && &path == failed_path
                    {
                        return Ok::<_, std::convert::Infallible>(error(*code));
                    }
                    if path == SANDBOXES {
                        let items: Vec<_> = state
                            .objects
                            .iter()
                            .filter(|(key, _)| key.starts_with(&format!("{SANDBOXES}/")))
                            .filter(|(_, value)| {
                                selector.split(',').filter(|clause| !clause.is_empty()).all(
                                    |clause| match clause.split_once('=') {
                                        Some((key, expected)) => {
                                            value["metadata"]["labels"][key] == expected
                                        }
                                        None => value["metadata"]["labels"].get(clause).is_some(),
                                    },
                                )
                            })
                            .map(|(_, value)| value.clone())
                            .collect();
                        response(
                            200,
                            json!({"apiVersion":"agents.x-k8s.io/v1beta1","kind":"SandboxList","metadata":{},"items":items}),
                        )
                    } else if let Some(object) = state.objects.get(&path) {
                        response(200, object.clone())
                    } else {
                        error(404)
                    }
                }
                http::Method::POST => {
                    if path == "/apis/authentication.k8s.io/v1/tokenreviews" {
                        return Ok(response(
                            200,
                            json!({"apiVersion":"authentication.k8s.io/v1", "kind":"TokenReview", "status":state.token_review}),
                        ));
                    }
                    let target = format!("{path}/{}", body["metadata"]["name"].as_str().unwrap());
                    if state.objects.contains_key(&target) {
                        error(409)
                    } else {
                        state.version += 1;
                        let mut object = body;
                        if path.ends_with("/services") {
                            object["spec"]["clusterIP"] = json!("10.42.0.9");
                        }
                        object["metadata"]["uid"] = json!(format!("uid-{}", state.version));
                        object["metadata"]["resourceVersion"] = json!(state.version.to_string());
                        object["metadata"]["generation"] = json!(1);
                        state.objects.insert(target.clone(), object.clone());
                        if state.lose_response.as_deref() == Some(&path)
                            || state.lose_response.as_deref() == Some(&target)
                        {
                            state.lose_response = None;
                            error(504)
                        } else {
                            response(201, object)
                        }
                    }
                }
                http::Method::PATCH => {
                    if path.starts_with(SANDBOXES)
                        && let Some(change) = state.conflict.take()
                    {
                        state.version += 1;
                        let version = state.version.to_string();
                        let object = state.objects.get_mut(&path).unwrap();
                        merge(object, &change);
                        object["metadata"]["resourceVersion"] = json!(version);
                        return Ok(error(409));
                    }
                    if let Some(existing) = state.objects.get(&path) {
                        if body["metadata"]
                            .get("uid")
                            .is_some_and(|uid| uid != &existing["metadata"]["uid"])
                            || body["metadata"]
                                .get("resourceVersion")
                                .is_some_and(|rv| rv != &existing["metadata"]["resourceVersion"])
                        {
                            return Ok(error(409));
                        }
                        let mut object = existing.clone();
                        merge(&mut object, &body);
                        state.version += 1;
                        object["metadata"]["resourceVersion"] = json!(state.version.to_string());
                        state.objects.insert(path.clone(), object.clone());
                        if path.starts_with(SANDBOXES)
                            && object["spec"]["operatingMode"] == "Running"
                        {
                            let pod_path =
                                format!("{PODS}/{}", object["metadata"]["name"].as_str().unwrap());
                            if !state.objects.contains_key(&pod_path) {
                                let mut pod = object["spec"]["podTemplate"].clone();
                                pod["apiVersion"] = json!("v1");
                                pod["kind"] = json!("Pod");
                                pod["metadata"]["name"] = object["metadata"]["name"].clone();
                                pod["metadata"]["namespace"] = json!("openshell");
                                pod["metadata"]["uid"] = json!("workload-pod-uid");
                                pod["metadata"]["resourceVersion"] = json!("pod-version-1");
                                pod["metadata"]["ownerReferences"] = json!([{
                                    "apiVersion":"agents.x-k8s.io/v1beta1","kind":"Sandbox","controller":true,
                                    "name":object["metadata"]["name"],"uid":object["metadata"]["uid"]}]);
                                if state.other_gate {
                                    pod["spec"]["schedulingGates"]
                                        .as_array_mut()
                                        .unwrap()
                                        .push(json!({"name":"other.example/gate"}));
                                }
                                for key in ["containers", "initContainers"] {
                                    for container in pod["spec"][key].as_array_mut().unwrap() {
                                        if let Some(env) =
                                            container.get_mut("env").and_then(Value::as_array_mut)
                                        {
                                            for entry in env {
                                                if entry.get("value").and_then(Value::as_str)
                                                    == Some("")
                                                {
                                                    entry.as_object_mut().unwrap().remove("value");
                                                }
                                            }
                                        }
                                    }
                                }
                                state.objects.insert(pod_path, pod);
                            }
                        }
                        if state.lose_response.as_deref() == Some(&path) {
                            state.lose_response = None;
                            error(504)
                        } else {
                            response(200, object)
                        }
                    } else {
                        error(404)
                    }
                }
                _ => panic!("unexpected {method} {path}"),
            };
            Ok::<_, std::convert::Infallible>(result)
        }
    });
    let shared_config = crate::config::SharedSupervisorConfig {
        service_name: "supervisor".into(),
        service_namespace: "openshell".into(),
        runtime_port: 5500,
        token_secret_name: "token".into(),
    };
    let config = KubernetesComputeConfig {
        namespace: "openshell".into(),
        gateway_id: "gateway".into(),
        sandbox_uid: Some(1000),
        sandbox_gid: Some(1000),
        default_image: "workload-image".into(),
        sandbox_runtime_image: "runtime-image".into(),
        shared_supervisor: Some(shared_config.clone()),
        ..Default::default()
    };
    let mut driver = KubernetesComputeDriver::new_for_test(config);
    driver.client = Client::new(service, "openshell");
    let supervision = SharedSupervision::new();
    supervision
        .controller()
        .install_placement(Arc::new(Placement(state.clone())));
    driver.shared_supervisor = Some(SharedSupervisor::new(shared_config, supervision));
    state.lock().unwrap().objects.extend([
        ("/api/v1/namespaces/openshell".into(), json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"openshell","uid":"namespace-uid"}})),
        ("/api/v1/namespaces/openshell/services/supervisor".into(), json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"supervisor"},
            "spec":{"clusterIP":"10.42.0.8","selector":{"component":"supervisor"}}})),
    ]);
    driver
}

/// A Kubernetes API integration check, separate from shared-supervisor E2E. The
/// capacity authority is in-memory here; this checks real CRD defaulting, Pod
/// admission, Secret ownership and scheduling-gate updates, not activation.
#[derive(Debug, Default)]
struct ApiTestPlacement {
    requests: Mutex<Vec<PreparationRequest>>,
    journal: Mutex<Option<openshell_supervisor_control::warm_pool::WarmPoolSnapshot>>,
    trust: Mutex<Option<Value>>,
}

impl InstancePlacement for ApiTestPlacement {
    fn warm_runtime_trust(&self) -> PlacementFuture<WarmRuntimeTrust> {
        let trust = serde_json::from_value(self.trust.lock().unwrap().clone().unwrap()).unwrap();
        Box::pin(async move { Ok(trust) })
    }
    fn warm_pool_targets(
        &self,
        _: Option<String>,
    ) -> PlacementFuture<Vec<openshell_supervisor_control::warm_pool::WarmPoolTarget>> {
        let pool = pool_config();
        Box::pin(async move {
            Ok(vec![
                openshell_supervisor_control::warm_pool::WarmPoolTarget {
                    pool_id: pool.name,
                    workspace: pool.workspace,
                    target: pool.target_size,
                    spec: Some(pool.spec),
                },
            ])
        })
    }
    fn warm_pool_state(
        &self,
        _: String,
        _: String,
    ) -> PlacementFuture<Option<openshell_supervisor_control::warm_pool::WarmPoolSnapshot>> {
        let snapshot = self.journal.lock().unwrap().clone();
        Box::pin(async move { Ok(snapshot) })
    }
    fn update_warm_pool(
        &self,
        update: openshell_supervisor_control::warm_pool::WarmPoolUpdate,
    ) -> PlacementFuture<bool> {
        let mut journal = self.journal.lock().unwrap();
        let changed =
            journal.as_ref().map(|snapshot| snapshot.resource_version) == update.expected_version;
        if changed {
            *journal = Some(openshell_supervisor_control::warm_pool::WarmPoolSnapshot {
                resource_version: update.expected_version.unwrap_or(0) + 1,
                state: update.state,
            });
        }
        Box::pin(async move { Ok(changed) })
    }
    fn retire_preparation(&self, _: PreparationRetirement) -> PlacementFuture<PreparationRelease> {
        Box::pin(async { Ok(PreparationRelease::Released) })
    }
    fn prepare_runtime(&self, request: PreparationRequest) -> PlacementFuture {
        self.requests.lock().unwrap().push(request);
        Box::pin(async { Ok(()) })
    }
    fn place_launch(&self, _: PlacementRequest) -> PlacementFuture {
        panic!("unexpected launch")
    }
    fn prepared_runtimes(&self, _: String) -> PlacementFuture<Vec<PreparedRuntime>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn release_preparation(&self, _: PreparationRevision) -> PlacementFuture<PreparationRelease> {
        panic!("unexpected release")
    }
    fn activate_runtime(&self, _: ActivationRequest) -> PlacementFuture<SandboxInstanceAssignment> {
        panic!("unexpected activation")
    }
    fn recorded(&self) -> PlacementFuture<BTreeMap<String, i64>> {
        panic!("unexpected recovery")
    }
    fn record_recovered(&self, _: SandboxInstanceAssignment) -> PlacementFuture {
        panic!("unexpected recovery")
    }
}

#[tokio::test]
#[ignore = "requires e2e/with-kube-gateway.sh with the shared-supervisor overlay"]
async fn warm_runtime_resources_on_kubernetes() {
    let namespace =
        std::env::var("OPENSHELL_E2E_KUBE_NAMESPACE").expect("run with the Kubernetes E2E wrapper");
    let release = std::env::var("OPENSHELL_E2E_KUBE_RELEASE").unwrap();
    let client = Client::try_default().await.unwrap();
    let config_map = Api::<ConfigMap>::namespaced(client.clone(), &namespace)
        .get(&format!("{release}-config"))
        .await
        .unwrap();
    let config: toml::Value = toml::from_str(&config_map.data.unwrap()["gateway.toml"]).unwrap();
    let mut config: KubernetesComputeConfig = config["openshell"]["drivers"]["kubernetes"]
        .clone()
        .try_into()
        .unwrap();
    config.namespace.clone_from(&namespace);
    assert_eq!(config.workspace_mode, WorkspaceMode::Shared);
    let shared_config = config
        .shared_supervisor
        .clone()
        .expect("shared supervisor overlay required");
    let supervision = SharedSupervision::new();
    let placement = Arc::new(ApiTestPlacement::default());
    supervision
        .controller()
        .install_placement(placement.clone());
    let mut request = request();
    request.workspace = "default".into();
    request.trust.gateway_id.clone_from(&config.gateway_id);
    let key = openshell_crypto::pki::generate_keypair_for(&rcgen::PKCS_ED25519).unwrap();
    request.trust.verification_keys[0].public_key_pem = key.public_key_pem().into_bytes();
    *placement.trust.lock().unwrap() = Some(serde_json::to_value(&request.trust).unwrap());
    let mut driver = KubernetesComputeDriver::new_for_test(config);
    driver.client = client.clone();
    driver.shared_supervisor = Some(SharedSupervisor::new(shared_config, supervision));
    let name = format!("warm-{}", request.session_id);
    let result = driver.prepare_warm_runtime(&request).await;
    // Always remove only this run's physical CR; its dependents are owned by UID.
    // The wrapper also tears down the ephemeral cluster after any assertion fails.
    let checked = Box::pin(async {
        let prepared = result?;
        let pod = Api::<Pod>::namespaced(client.clone(), &namespace)
            .get(&name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        assert!(!has_gate(&pod));
        assert_eq!(pod.metadata.uid, prepared.resource.pod_uid);
        let secret = Api::<Secret>::namespaced(client.clone(), &namespace)
            .get(
                &SandboxRuntimeNames::for_generation(
                    &request.session_id.to_string(),
                    &request.session_id.to_string(),
                )
                .sandbox_secret,
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        assert_eq!(secret.immutable, Some(true));
        assert_eq!(
            secret.metadata.owner_references.as_ref().unwrap()[0].uid,
            pod.metadata.uid.unwrap()
        );
        let resumed = driver.resume_warm_runtime(&prepared.resource).await?;
        assert_eq!(resumed.registration, prepared.registration);
        assert_eq!(placement.requests.lock().unwrap().len(), 2);
        // Exercise UID/version-preconditioned foreground deletion against the
        // real API as well. Capacity fencing is tested with the durable store.
        for _ in 0..10 {
            match driver.retire_warm_runtime(&prepared.resource).await {
                Ok(WarmRuntimeRetirement::Deleting | WarmRuntimeRetirement::Absent) => break,
                Ok(WarmRuntimeRetirement::Changed) => {}
                outcome => panic!("unexpected real API retirement outcome: {outcome:?}"),
            }
        }
        let api = driver
            .supported_agent_sandbox_api(client.clone(), &namespace)
            .await
            .unwrap();
        let object = api.api.get_opt(&name).await.unwrap();
        assert!(object.is_none_or(|object| object.metadata.deletion_timestamp.is_some()));
        let names = SandboxRuntimeNames::for_generation(
            &request.session_id.to_string(),
            &request.session_id.to_string(),
        );
        tokio::time::timeout(Duration::from_mins(1), async {
            loop {
                let pod = Api::<Pod>::namespaced(client.clone(), &namespace)
                    .get_opt(&name)
                    .await
                    .unwrap();
                let secret = Api::<Secret>::namespaced(client.clone(), &namespace)
                    .get_opt(&names.sandbox_secret)
                    .await
                    .unwrap();
                let policy = Api::<NetworkPolicy>::namespaced(client.clone(), &namespace)
                    .get_opt(&names.shared_control_policy)
                    .await
                    .unwrap();
                if pod.is_none() && secret.is_none() && policy.is_none() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .expect("Kubernetes must collect the retired runtime's owned resources");
        // Drive the actual reconciler against the API: concurrent replicas fill
        // once, then a higher configuration revision drains the physical runtime.
        let mut pool = pool_config();
        pool.workspace = "default".into();
        pool.target_size = 1;
        pool.max_size = 1;
        pool.spec
            .template
            .as_mut()
            .unwrap()
            .image
            .clone_from(&driver.config.default_image);
        let (a, b) = tokio::join!(
            driver.reconcile_warm_pool(&pool),
            driver.reconcile_warm_pool(&pool)
        );
        assert_eq!(a?.failed, 0);
        assert_eq!(b?.failed, 0);
        let resources = driver.warm_runtime_inventory(&pool.workspace).await?;
        assert_eq!(resources.len(), 1);
        assert!(resources[0].released);
        assert_eq!(driver.reconcile_warm_pool(&pool).await?.ready, 0);
        pool.revision += 1;
        pool.target_size = 0;
        tokio::time::timeout(Duration::from_mins(1), async {
            loop {
                for entry in &mut placement
                    .journal
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .state
                    .entries
                {
                    entry.last_attempt_at_ms = None;
                }
                driver.reconcile_warm_pool(&pool).await.unwrap();
                if placement
                    .journal
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .state
                    .entries
                    .is_empty()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .expect("the reconciler must finish the pool drain");
        assert!(
            driver
                .warm_runtime_inventory(&pool.workspace)
                .await?
                .is_empty()
        );
        Ok::<_, KubernetesDriverError>(())
    })
    .await;
    let api = driver
        .supported_agent_sandbox_api(client, &namespace)
        .await
        .unwrap();
    if let Some(object) = api.api.get_opt(&name).await.unwrap() {
        api.api
            .delete(
                &name,
                &DeleteParams {
                    preconditions: Some(Preconditions {
                        uid: object.metadata.uid,
                        resource_version: None,
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
    checked.unwrap();
}

fn request() -> WarmRuntimeRequest {
    let key = openshell_crypto::pki::generate_keypair_for(&rcgen::PKCS_ED25519).unwrap();
    WarmRuntimeRequest {
        workspace: "team-a".into(),
        pool_id: "pool-a".into(),
        session_id: SandboxSessionId::new(),
        spec: SandboxSpec {
            environment: [("TASK_ENV".into(), "value".into())].into(),
            ..Default::default()
        },
        trust: WarmRuntimeTrust {
            gateway_id: "gateway".into(),
            verification_keys: vec![SessionVerificationKey {
                key_id: "key-1".into(),
                public_key_pem: key.public_key_pem().into_bytes(),
            }],
            auth_epoch: CredentialEpoch::new(1).unwrap(),
            session_rotation: SessionRotation::new(1).unwrap(),
        },
    }
}

fn pool_config() -> crate::config::WarmPoolConfig {
    crate::config::WarmPoolConfig {
        name: "pool-a".into(),
        workspace: "team-a".into(),
        revision: 1,
        target_size: 2,
        max_size: 2,
        max_age_secs: 600,
        preparation_timeout_secs: 120,
        spec: SandboxSpec {
            template: Some(SandboxTemplate {
                image: "workload-image".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    }
}

fn claiming_sandbox(request: &WarmRuntimeRequest, id: &str) -> Sandbox {
    let mut spec = request.spec.clone();
    spec.launch_authentication = serde_json::to_vec(&json!({
        "gateway_id": request.trust.gateway_id,
        "verification_keys": request.trust.verification_keys,
        "supervisor": {
            "session_id": SandboxSessionId::new(), "runtime_generation": "proposed-generation",
            "session_rotation": 1, "auth_epoch": 1,
            "gateway_token": "proposed-gateway", "gateway_expires_at": 0,
            "sandbox_token": "proposed-sandbox", "sandbox_expires_at": 0
        }
    }))
    .unwrap();
    Sandbox {
        id: id.into(),
        name: id.into(),
        workspace: request.workspace.clone(),
        spec: Some(spec),
        ..Default::default()
    }
}

async fn claim_object(
    driver: &KubernetesComputeDriver,
    resource: &WarmRuntimeResource,
) -> (AgentSandboxApi, DynamicObject, Record) {
    let api = driver
        .supported_agent_sandbox_api(driver.client.clone(), &resource.namespace)
        .await
        .unwrap();
    let object = api.api.get(&resource.name).await.unwrap();
    let record = read_record(&object, &driver.config.gateway_id).unwrap();
    (api, object, record)
}

fn mark_prepared_ready(driver: &KubernetesComputeDriver, prepared: &WarmRuntimePreparation) {
    use openshell_supervisor_control::{InstanceOwner, PoolView};
    let route = prepared.registration.route.clone();
    driver
        .shared_supervisor
        .as_ref()
        .unwrap()
        .supervision()
        .controller()
        .update_pool(
            PoolView {
                owners: BTreeMap::from([(
                    route.clone(),
                    InstanceOwner {
                        member_id: "member".into(),
                        process_id: "process".into(),
                        auth_epoch: 1,
                        supervisor_instance_id: None,
                        takeover: None,
                    },
                )]),
                desired: [route.clone()].into(),
                assignments: BTreeMap::from([(
                    route.clone(),
                    prepared.registration.to_assignment().unwrap(),
                )]),
                reports: BTreeMap::from([(
                    route.clone(),
                    openshell_supervisor_control::proto::SandboxInstanceStatus {
                        route,
                        phase: openshell_supervisor_control::proto::SandboxInstancePhase::Prepared
                            as i32,
                        ready: true,
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            },
            tokio::time::Instant::now(),
        );
}

#[tokio::test]
async fn create_claims_ready_capacity_and_preserves_physical_resources() {
    let state = Arc::new(Mutex::new(State::default()));
    let mut driver = fixture(state.clone());
    let pool = pool_config();
    driver.config.warm_pool.max_size = pool.max_size;
    driver.config.warm_pool.max_age_secs = pool.max_age_secs;
    driver.config.warm_pool.preparation_timeout_secs = pool.preparation_timeout_secs;
    driver.reconcile_warm_pool(&pool).await.unwrap();
    let resource = driver
        .warm_runtime_inventory("team-a")
        .await
        .unwrap()
        .remove(0);
    let prepared = driver.resume_warm_runtime(&resource).await.unwrap();
    mark_prepared_ready(&driver, &prepared);
    let mut request = request();
    request.spec = reconciler::spec(&pool);
    let sandbox = claiming_sandbox(&request, "logical-one");
    let before = state.lock().unwrap().objects[&format!("{PODS}/{}", resource.name)].clone();
    let identity = driver.create_sandbox(&sandbox).await.unwrap();
    assert_eq!(
        identity,
        kubernetes_runtime_identity(
            &resource.namespace,
            &resource.uid,
            &prepared.registration.route
        )
    );
    let (_, claimed, _) = claim_object(&driver, &resource).await;
    assert_eq!(sandbox_id_from_object(&claimed).unwrap(), sandbox.id);
    assert_eq!(
        physical_resource_id(&claimed, &sandbox.id),
        resource.session_id.to_string()
    );
    assert!(!claim_pending(&claimed));
    assert_eq!(driver.create_sandbox(&sandbox).await.unwrap(), identity);
    let mut changed = sandbox.clone();
    let mut auth: openshell_core::jwt::SandboxLaunchAuthentication =
        serde_json::from_slice(&changed.spec.as_ref().unwrap().launch_authentication).unwrap();
    auth.supervisor.runtime_generation =
        openshell_core::sandbox_generation::SandboxGenerationId::parse("another-launch").unwrap();
    changed.spec.as_mut().unwrap().launch_authentication = serde_json::to_vec(&auth).unwrap();
    assert!(driver.create_sandbox(&changed).await.is_err());
    assert_eq!(
        state.lock().unwrap().objects[&format!("{PODS}/{}", resource.name)],
        before
    );
    assert_eq!(
        driver.retire_warm_runtime(&resource).await.unwrap(),
        WarmRuntimeRetirement::Changed
    );
    let names = SandboxRuntimeNames::for_generation(&sandbox.id, &resource.session_id.to_string());
    let secret: Secret = serde_json::from_value(
        state.lock().unwrap().objects[&format!("{SECRETS}/{}", names.supervisor_secret)].clone(),
    )
    .unwrap();
    let canonical = SandboxInstanceRegistration::from_launch_material(
        &secret.data.unwrap()[SHARED_INSTANCE_KEY].0,
    )
    .unwrap();
    assert_eq!(
        canonical.auth.gateway_token.expose_secret(),
        "committed-gateway"
    );
    assert_eq!(
        canonical.runtime_descriptor.tls,
        prepared.registration.runtime_descriptor.tls
    );
    assert_eq!(canonical.runtime_descriptor.session_id, resource.session_id);
    // Ordinary recovery reads the canonical Secret by logical ID and generation.
    assert!(
        driver
            .read_shared_instance_material(SharedInstanceSecretRecord {
                namespace: resource.namespace.clone(),
                sandbox_id: sandbox.id,
                generation: resource.session_id.to_string(),
            })
            .await
            .unwrap()
            .is_some()
    );
    driver.reconcile_warm_pool(&pool).await.unwrap();
    assert!(
        !state
            .lock()
            .unwrap()
            .journal
            .as_ref()
            .unwrap()
            .state
            .entries
            .iter()
            .any(|entry| entry.session_id == resource.session_id)
    );
}

#[tokio::test]
async fn warm_claim_recovers_lost_activation_and_secret_responses() {
    for lost in ["activation", "intent", "claim", "canonical"] {
        let state = Arc::new(Mutex::new(State::default()));
        let driver = fixture(state.clone());
        let request = request();
        let prepared = driver.prepare_warm_runtime(&request).await.unwrap();
        let sandbox = claiming_sandbox(&request, "logical-one");
        let (api, object, record) = claim_object(&driver, &prepared.resource).await;
        state.lock().unwrap().lose_activation_response = lost == "activation";
        state.lock().unwrap().lose_response = match lost {
            "intent" => Some(SECRETS.into()),
            "claim" => Some(format!("{SANDBOXES}/{}", prepared.resource.name)),
            "canonical" => Some(format!(
                "{SECRETS}/{}",
                SandboxRuntimeNames::for_generation(&sandbox.id, &record.physical_id())
                    .supervisor_secret
            )),
            _ => None,
        };
        assert!(
            driver
                .claim_warm_object(
                    &sandbox,
                    &api,
                    &object,
                    &record,
                    prepared.registration.clone()
                )
                .await
                .is_err()
        );
        let current = api.api.get(&prepared.resource.name).await.unwrap();
        if lost == "intent" {
            // Secret committed before the CR claim: retry adopts that intent.
            driver
                .claim_warm_object(&sandbox, &api, &current, &record, prepared.registration)
                .await
                .unwrap();
        } else {
            assert!(claim_pending(&current));
            driver.finish_warm_claim(&api, &current).await.unwrap();
        }
        assert_eq!(state.lock().unwrap().activated.len(), 1);
        let current = api.api.get(&prepared.resource.name).await.unwrap();
        assert!(!claim_pending(&current));
        driver.finish_warm_claim(&api, &current).await.unwrap();
        assert_eq!(
            driver
                .retire_warm_runtime(&prepared.resource)
                .await
                .unwrap(),
            WarmRuntimeRetirement::Changed
        );
    }
}

#[tokio::test]
async fn two_sandboxes_cannot_claim_the_same_physical_runtime() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = fixture(state.clone());
    let request = request();
    let prepared = driver.prepare_warm_runtime(&request).await.unwrap();
    let a = claiming_sandbox(&request, "logical-a");
    let b = claiming_sandbox(&request, "logical-b");
    let (api, object, record) = claim_object(&driver, &prepared.resource).await;
    let (first, second) = tokio::join!(
        driver.claim_warm_object(&a, &api, &object, &record, prepared.registration.clone()),
        driver.claim_warm_object(&b, &api, &object, &record, prepared.registration),
    );
    assert_ne!(first.is_ok(), second.is_ok());
    assert_eq!(state.lock().unwrap().activated.len(), 1);
    assert_eq!(
        state
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|event| *event == "activate")
            .count(),
        1
    );
}

#[tokio::test]
async fn warm_claim_rejects_retirement_race_and_incompatible_shape() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = fixture(state.clone());
    let request = request();
    let prepared = driver.prepare_warm_runtime(&request).await.unwrap();
    let mut sandbox = claiming_sandbox(&request, "logical-one");
    let (api, object, record) = claim_object(&driver, &prepared.resource).await;
    assert!(driver.warm_shape_matches(&sandbox, &record).unwrap());
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .environment
        .insert("TASK_ENV".into(), "different".into());
    assert!(!driver.warm_shape_matches(&sandbox, &record).unwrap());
    sandbox.spec = Some(request.spec.clone());
    sandbox.spec.as_mut().unwrap().template = Some(SandboxTemplate {
        image: "different-image".into(),
        ..Default::default()
    });
    assert!(!driver.warm_shape_matches(&sandbox, &record).unwrap());
    let sandbox = claiming_sandbox(&request, "logical-one");
    state.lock().unwrap().conflict = Some(json!({"metadata":{"annotations":{RETIRING:"true"}}}));
    assert!(
        driver
            .claim_warm_object(&sandbox, &api, &object, &record, prepared.registration)
            .await
            .is_err()
    );
    assert!(state.lock().unwrap().activated.is_empty());
}

fn permit_next_attempt(state: &Arc<Mutex<State>>) {
    for entry in &mut state
        .lock()
        .unwrap()
        .journal
        .as_mut()
        .unwrap()
        .state
        .entries
    {
        entry.last_attempt_at_ms = None;
    }
}

#[tokio::test]
async fn pool_replicas_provision_one_inventory_then_drain_without_refill() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = fixture(state.clone());
    let replica = driver.clone();
    let mut pool = pool_config();
    let (a, b) = tokio::join!(
        driver.reconcile_warm_pool(&pool),
        replica.reconcile_warm_pool(&pool)
    );
    assert_eq!(a.unwrap().failed, 0);
    assert_eq!(b.unwrap().failed, 0);
    let inventory = driver
        .warm_runtime_inventory(&pool.workspace)
        .await
        .unwrap();
    assert_eq!(inventory.len(), 2);
    assert!(inventory.iter().all(|resource| resource.released));
    let report = replica.reconcile_warm_pool(&pool).await.unwrap();
    assert_eq!((report.pending, report.ready, report.attempted), (2, 0, 0));
    {
        let state = state.lock().unwrap();
        assert_eq!(state.journal.as_ref().unwrap().state.entries.len(), 2);
        let journal = state
            .events
            .iter()
            .position(|event| event == "journal")
            .unwrap();
        let create = state
            .events
            .iter()
            .position(|event| event == &format!("POST {SANDBOXES}"))
            .unwrap();
        assert!(journal < create);
    }
    pool.revision = 2;
    pool.target_size = 0;
    permit_next_attempt(&state);
    let report = driver.reconcile_warm_pool(&pool).await.unwrap();
    assert_eq!((report.retiring, report.failed), (2, 0));
    assert!(
        driver
            .warm_runtime_inventory(&pool.workspace)
            .await
            .unwrap()
            .is_empty()
    );
    // A restart completes the DB fences for now-absent CRs. Parallel completion
    // can race on the journal; a subsequent pass retries the retained entry.
    for _ in 0..3 {
        permit_next_attempt(&state);
        replica.reconcile_warm_pool(&pool).await.unwrap();
    }
    assert!(
        state
            .lock()
            .unwrap()
            .journal
            .as_ref()
            .unwrap()
            .state
            .entries
            .is_empty()
    );
    assert!(driver.reconcile_warm_pool(&pool_config()).await.is_err());
}

#[tokio::test]
async fn pool_preserves_creation_intent_on_lost_response_and_fails_closed_on_inventory_errors() {
    let state = Arc::new(Mutex::new(State {
        lose_response: Some(SANDBOXES.into()),
        ..Default::default()
    }));
    let driver = fixture(state.clone());
    let mut pool = pool_config();
    pool.target_size = 1;
    pool.max_size = 1;
    assert_eq!(driver.reconcile_warm_pool(&pool).await.unwrap().failed, 1);
    let session = state
        .lock()
        .unwrap()
        .journal
        .as_ref()
        .unwrap()
        .state
        .entries[0]
        .session_id;
    permit_next_attempt(&state);
    assert_eq!(driver.reconcile_warm_pool(&pool).await.unwrap().failed, 0);
    let inventory = driver
        .warm_runtime_inventory(&pool.workspace)
        .await
        .unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].session_id, session);
    state.lock().unwrap().fail_journal_read = true;
    let before = state.lock().unwrap().events.len();
    assert!(driver.reconcile_warm_pool(&pool).await.is_err());
    assert_eq!(state.lock().unwrap().events.len(), before);
    state.lock().unwrap().fail_journal_read = false;
    state.lock().unwrap().fail_read = Some((SANDBOXES.into(), 503));
    assert!(driver.reconcile_warm_pool(&pool).await.is_err());
    assert_eq!(
        state
            .lock()
            .unwrap()
            .journal
            .as_ref()
            .unwrap()
            .state
            .entries
            .len(),
        1
    );
}

#[tokio::test]
async fn pool_capacity_refusal_keeps_the_same_gated_runtime_for_retry() {
    let state = Arc::new(Mutex::new(State {
        refuse_capacity: true,
        ..Default::default()
    }));
    let driver = fixture(state.clone());
    let mut pool = pool_config();
    pool.target_size = 1;
    pool.max_size = 1;
    assert_eq!(driver.reconcile_warm_pool(&pool).await.unwrap().failed, 1);
    let before = driver
        .warm_runtime_inventory(&pool.workspace)
        .await
        .unwrap();
    assert!(!before[0].released);
    assert!(has_gate(&pod(&state.lock().unwrap())));
    state.lock().unwrap().refuse_capacity = false;
    permit_next_attempt(&state);
    assert_eq!(driver.reconcile_warm_pool(&pool).await.unwrap().failed, 0);
    let after = driver
        .warm_runtime_inventory(&pool.workspace)
        .await
        .unwrap();
    assert_eq!(before[0].uid, after[0].uid);
    assert_eq!(before[0].session_id, after[0].session_id);
    assert!(after[0].released);
}

fn pod(state: &State) -> Pod {
    serde_json::from_value(
        state
            .objects
            .iter()
            .find(|(path, _)| path.starts_with(PODS))
            .unwrap()
            .1
            .clone(),
    )
    .unwrap()
}

#[tokio::test]
async fn creates_a_unique_gated_runtime_and_reserves_before_releasing() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = fixture(state.clone());
    let request = request();
    let result = driver
        .prepare_warm_runtime(&request)
        .await
        .unwrap_or_else(|error| panic!("{error}: {:?}", state.lock().unwrap().events));
    let inventory = driver.warm_runtime_inventory("team-a").await.unwrap();
    assert_eq!(inventory, std::slice::from_ref(&result.resource));
    let state = state.lock().unwrap();
    assert!(!has_gate(&pod(&state)));
    assert!(result.resource.released);
    assert!(
        result
            .registration
            .runtime_descriptor
            .boundary_id
            .is_empty()
    );
    let object = &state.objects[&format!("{SANDBOXES}/{}", result.resource.name)];
    assert!(object["metadata"]["labels"].get(LABEL_SANDBOX_ID).is_none());
    let secret_path = state
        .objects
        .keys()
        .find(|path| path.starts_with(SECRETS))
        .unwrap();
    let bootstrap = &state.objects[secret_path];
    assert_eq!(bootstrap["immutable"], true);
    assert_eq!(bootstrap["data"].as_object().unwrap().len(), 4);
    assert_eq!(
        bootstrap["metadata"]["ownerReferences"][0]["uid"],
        "workload-pod-uid"
    );
    let reserve = state
        .events
        .iter()
        .position(|event| event == "reserve")
        .unwrap();
    let secret = state
        .events
        .iter()
        .position(|event| event == &format!("POST {SECRETS}"))
        .unwrap();
    let release = state
        .events
        .iter()
        .position(|event| event.starts_with(&format!("PATCH {PODS}/")))
        .unwrap();
    assert!(secret < reserve && reserve < release);
}

#[tokio::test]
async fn capacity_refusal_stays_gated_and_restart_reuses_secret_and_identity() {
    let state = Arc::new(Mutex::new(State {
        refuse_capacity: true,
        ..Default::default()
    }));
    let driver = fixture(state.clone());
    assert!(
        driver
            .prepare_warm_runtime(&request())
            .await
            .unwrap_err()
            .to_string()
            .contains("capacity")
    );
    let inventory = driver.warm_runtime_inventory("team-a").await.unwrap();
    let before = {
        let mut state = state.lock().unwrap();
        assert!(has_gate(&pod(&state)));
        state.refuse_capacity = false;
        state.preparations[0].registration.clone()
    };
    let restarted = fixture(state.clone());
    let resumed = restarted.resume_warm_runtime(&inventory[0]).await.unwrap();
    assert_eq!(resumed.registration, before);
    assert_eq!(
        state
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|event| *event == &format!("POST {SECRETS}"))
            .count(),
        1
    );
}

#[tokio::test]
async fn lost_create_or_secret_or_gate_response_recovers_without_new_identity() {
    for phase in ["sandbox", "secret", "gate"] {
        let request = request();
        let path = match phase {
            "sandbox" => SANDBOXES.into(),
            "secret" => SECRETS.into(),
            _ => format!("{PODS}/warm-{}", request.session_id),
        };
        let state = Arc::new(Mutex::new(State {
            lose_response: Some(path),
            ..Default::default()
        }));
        let driver = fixture(state.clone());
        assert!(
            driver.prepare_warm_runtime(&request).await.is_err(),
            "{phase}"
        );
        let inventory = driver.warm_runtime_inventory("team-a").await.unwrap();
        assert_eq!(inventory.len(), 1);
        let result = driver.resume_warm_runtime(&inventory[0]).await.unwrap();
        assert_eq!(result.resource.uid, inventory[0].uid);
        assert_eq!(result.resource.session_id, request.session_id);
        let again = driver.prepare_warm_runtime(&request).await.unwrap();
        assert_eq!(again.registration, result.registration);
        assert_eq!(
            state
                .lock()
                .unwrap()
                .objects
                .keys()
                .filter(|key| key.starts_with(SECRETS))
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn replacement_or_mutated_pod_is_not_released_after_reservation() {
    for replace in [false, true] {
        let state = Arc::new(Mutex::new(State {
            replace_pod_on_prepare: replace,
            mutate_pod_on_prepare: !replace,
            ..Default::default()
        }));
        let driver = fixture(state.clone());
        assert!(driver.prepare_warm_runtime(&request()).await.is_err());
        let state = state.lock().unwrap();
        assert!(has_gate(&pod(&state)));
        assert!(
            !state
                .events
                .iter()
                .any(|event| event.starts_with(&format!("PATCH {PODS}/")))
        );
    }
}

#[tokio::test]
async fn retries_reject_changed_shape_credentials_and_physical_resource() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = fixture(state.clone());
    let mut request = request();
    let result = driver.prepare_warm_runtime(&request).await.unwrap();
    request
        .spec
        .environment
        .insert("NEW_ENV".into(), "value".into());
    assert!(driver.prepare_warm_runtime(&request).await.is_err());
    request.spec.sandbox_token = "must-not-persist".into();
    assert!(driver.prepare_warm_runtime(&request).await.is_err());
    state
        .lock()
        .unwrap()
        .objects
        .get_mut(&format!("{SANDBOXES}/{}", result.resource.name))
        .unwrap()["metadata"]["uid"] = json!("replacement");
    assert!(driver.resume_warm_runtime(&result.resource).await.is_err());
    assert!(!format!("{:?}", state.lock().unwrap().objects).contains("must-not-persist"));
}

#[tokio::test]
async fn only_openshell_gate_is_removed() {
    let state = Arc::new(Mutex::new(State {
        other_gate: true,
        ..Default::default()
    }));
    let driver = fixture(state.clone());
    driver.prepare_warm_runtime(&request()).await.unwrap();
    let pod = pod(&state.lock().unwrap());
    let gates = pod.spec.unwrap().scheduling_gates.unwrap();
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].name, "other.example/gate");
}

#[tokio::test]
async fn invalid_inventory_and_forbidden_reads_are_not_empty_inventory() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = fixture(state.clone());
    let result = driver.prepare_warm_runtime(&request()).await.unwrap();
    {
        let mut state = state.lock().unwrap();
        let object = state
            .objects
            .get_mut(&format!("{SANDBOXES}/{}", result.resource.name))
            .unwrap();
        object["metadata"]["annotations"][RECORD] = json!("invalid");
    }
    assert!(driver.warm_runtime_inventory("team-a").await.is_err());
    state.lock().unwrap().fail_read = Some((SANDBOXES.into(), 403));
    assert!(driver.warm_runtime_inventory("team-a").await.is_err());
}

#[tokio::test]
async fn premature_gate_removal_is_not_repaired_by_installing_credentials() {
    let state = Arc::new(Mutex::new(State {
        refuse_capacity: true,
        ..Default::default()
    }));
    let driver = fixture(state.clone());
    assert!(driver.prepare_warm_runtime(&request()).await.is_err());
    let inventory = driver.warm_runtime_inventory("team-a").await.unwrap();
    {
        let mut state = state.lock().unwrap();
        let (_, pod) = state
            .objects
            .iter_mut()
            .find(|(path, _)| path.starts_with(PODS))
            .unwrap();
        pod["spec"]["schedulingGates"] = json!([]);
        state.refuse_capacity = false;
    }
    assert!(driver.resume_warm_runtime(&inventory[0]).await.is_err());
    assert_eq!(state.lock().unwrap().preparations.len(), 1);
}

#[tokio::test]
async fn status_conflicts_retry_but_concurrent_claims_do_not() {
    for claim in [false, true] {
        let conflict = if claim {
            json!({"metadata":{"labels":{LABEL_SANDBOX_ID:"claimed"}}})
        } else {
            json!({"status":{"observedGeneration":1}})
        };
        let state = Arc::new(Mutex::new(State {
            conflict: Some(conflict),
            ..Default::default()
        }));
        let driver = fixture(state.clone());
        let result = driver.prepare_warm_runtime(&request()).await;
        if claim {
            assert!(result.is_err());
            assert!(state.lock().unwrap().preparations.is_empty());
        } else {
            assert!(result.unwrap().resource.released);
        }
    }
}

#[tokio::test]
async fn malformed_trust_fails_before_creating_resources() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = fixture(state.clone());
    let mut request = request();
    request.trust.verification_keys[0].public_key_pem = b"invalid-key".to_vec();
    assert!(driver.prepare_warm_runtime(&request).await.is_err());
    assert!(state.lock().unwrap().events.is_empty());
}

#[tokio::test]
async fn retirement_journals_before_fencing_and_deletes_only_after_success() {
    for released in [false, true] {
        let state = Arc::new(Mutex::new(State {
            refuse_capacity: !released,
            ..Default::default()
        }));
        let driver = fixture(state.clone());
        let request = request();
        assert_eq!(
            driver.prepare_warm_runtime(&request).await.is_ok(),
            released
        );
        let resource = driver
            .warm_runtime_inventory("team-a")
            .await
            .unwrap()
            .pop()
            .unwrap();
        state.lock().unwrap().retirement = Some(Err("ambiguous retirement response".into()));
        assert!(driver.retire_warm_runtime(&resource).await.is_err());
        let pending = driver.warm_runtime_inventory("team-a").await.unwrap();
        assert!(pending[0].retiring);
        assert!(driver.resume_warm_runtime(&resource).await.is_err());
        assert!(driver.prepare_warm_runtime(&request).await.is_err());
        assert!(
            !state
                .lock()
                .unwrap()
                .events
                .iter()
                .any(|event| event.starts_with("DELETE"))
        );
        state.lock().unwrap().retirement = None;
        // A fresh driver resumes the journal after the ambiguous result.
        let restarted = fixture(state.clone());
        assert_eq!(
            restarted.retire_warm_runtime(&resource).await.unwrap(),
            WarmRuntimeRetirement::Deleting
        );
        assert_eq!(
            restarted.retire_warm_runtime(&resource).await.unwrap(),
            WarmRuntimeRetirement::Absent
        );
        let state = state.lock().unwrap();
        let delete = state
            .events
            .iter()
            .position(|event| event.starts_with("DELETE"))
            .unwrap();
        let retire = state
            .events
            .iter()
            .rposition(|event| event == "retire")
            .unwrap();
        assert!(retire < delete);
        // Namespace-wide fences and dependents are not removed individually;
        // only the CR deletion invokes garbage collection by ownership UID.
        assert_eq!(
            state
                .events
                .iter()
                .filter(|event| event.starts_with("DELETE"))
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn retirement_does_not_delete_changed_reservations_or_replaced_resources() {
    for mode in ["claimed", "absent", "replaced"] {
        let state = Arc::new(Mutex::new(State::default()));
        let driver = fixture(state.clone());
        let resource = driver
            .prepare_warm_runtime(&request())
            .await
            .unwrap()
            .resource;
        {
            let mut state = state.lock().unwrap();
            match mode {
                "claimed" => state.retirement = Some(Ok(PreparationRelease::Changed)),
                "absent" => state.retirement = Some(Ok(PreparationRelease::Absent)),
                _ => state.replace_on_retirement = true,
            }
        }
        assert_eq!(
            driver.retire_warm_runtime(&resource).await.unwrap(),
            WarmRuntimeRetirement::Changed
        );
        assert!(
            !state
                .lock()
                .unwrap()
                .events
                .iter()
                .any(|event| event.starts_with("DELETE"))
        );
    }
}

#[tokio::test]
async fn concurrent_kubernetes_claim_fences_retirement_before_capacity_release() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = fixture(state.clone());
    let resource = driver
        .prepare_warm_runtime(&request())
        .await
        .unwrap()
        .resource;
    state.lock().unwrap().conflict =
        Some(json!({"metadata":{"labels":{LABEL_SANDBOX_ID:"claimed"}}}));
    assert!(driver.retire_warm_runtime(&resource).await.is_err());
    assert_eq!(
        driver.retire_warm_runtime(&resource).await.unwrap(),
        WarmRuntimeRetirement::Changed
    );
    assert!(
        !state
            .lock()
            .unwrap()
            .events
            .iter()
            .any(|event| event == "retire" || event.starts_with("DELETE"))
    );
}

#[tokio::test]
async fn retirement_delete_is_fenced_and_a_lost_response_is_recoverable() {
    for lost_response in [false, true] {
        let state = Arc::new(Mutex::new(State::default()));
        let driver = fixture(state.clone());
        let resource = driver
            .prepare_warm_runtime(&request())
            .await
            .unwrap()
            .resource;
        let path = format!("{SANDBOXES}/{}", resource.name);
        if lost_response {
            state.lock().unwrap().lose_delete_response = true;
            assert!(driver.retire_warm_runtime(&resource).await.is_err());
            assert_eq!(
                driver.retire_warm_runtime(&resource).await.unwrap(),
                WarmRuntimeRetirement::Absent
            );
        } else {
            state.lock().unwrap().delete_conflict = Some(json!({"metadata":{"uid":"replacement"}}));
            assert_eq!(
                driver.retire_warm_runtime(&resource).await.unwrap(),
                WarmRuntimeRetirement::Changed
            );
            assert_eq!(
                state.lock().unwrap().objects[&path]["metadata"]["uid"],
                "replacement"
            );
            assert_eq!(
                driver.retire_warm_runtime(&resource).await.unwrap(),
                WarmRuntimeRetirement::Changed
            );
        }
    }
}

fn dedicated_fixture(state: Arc<Mutex<State>>) -> KubernetesComputeDriver {
    let mut driver = fixture(state);
    driver.warm_supervision = Some(
        driver
            .shared_supervisor
            .take()
            .unwrap()
            .supervision()
            .clone(),
    );
    driver.config.shared_supervisor = None;
    driver
}

#[tokio::test]
async fn dedicated_warm_claim_persists_credentials_without_projecting_or_replacing_pods() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = dedicated_fixture(state.clone());
    let request = request();
    let prepared = driver.prepare_warm_runtime(&request).await.unwrap();
    let (api, object, record) = claim_object(&driver, &prepared.resource).await;
    let names = record.names();
    let supervisor_path = format!("{PODS}/{}", names.supervisor_pod);
    let before = state.lock().unwrap().objects[&supervisor_path].clone();
    assert_eq!(before["spec"]["volumes"][0]["secret"]["optional"], false);
    assert_eq!(
        before["spec"]["containers"][0]["startupProbe"]["tcpSocket"]["port"],
        5502
    );
    assert!(
        !state
            .lock()
            .unwrap()
            .objects
            .contains_key(&format!("{SECRETS}/{}", names.supervisor_secret))
    );
    assert!(
        !driver
            .warm_connection_ready(&prepared.resource)
            .await
            .unwrap()
    );
    let sandbox = claiming_sandbox(&request, "logical-dedicated");
    let canonical_names = SandboxRuntimeNames::for_generation(&sandbox.id, &record.physical_id());
    // Lose the persistence response after the canonical claim has committed.
    state.lock().unwrap().lose_response =
        Some(format!("{SECRETS}/{}", canonical_names.supervisor_secret));
    assert!(
        driver
            .claim_warm_object(
                &sandbox,
                &api,
                &object,
                &record,
                prepared.registration.clone()
            )
            .await
            .is_err()
    );
    let (_, pending, _) = claim_object(&driver, &prepared.resource).await;
    assert!(claim_pending(&pending));
    assert_eq!(
        supervisor_placement(&pending).unwrap(),
        SupervisorPlacement::Dedicated
    );
    driver.finish_warm_claim(&api, &pending).await.unwrap();
    let (_, claimed, _) = claim_object(&driver, &prepared.resource).await;
    assert!(!claim_pending(&claimed));
    let supervisor: Pod =
        serde_json::from_value(state.lock().unwrap().objects[&supervisor_path].clone()).unwrap();
    assert!(
        KubernetesComputeDriver::resolve_sandbox_owner(&supervisor, &sandbox.id)
            .unwrap()
            .1
    );
    validate_claimed_supervisor(&supervisor, &claimed, &sandbox.id).unwrap();
    let mut replaced = supervisor.clone();
    replaced.metadata.uid = Some("replaced".into());
    assert!(validate_claimed_supervisor(&replaced, &claimed, &sandbox.id).is_err());
    assert!(validate_claimed_supervisor(&supervisor, &object, &sandbox.id).is_err());
    assert_eq!(
        state.lock().unwrap().objects[&supervisor_path]["spec"],
        before["spec"]
    );
    assert_eq!(
        state.lock().unwrap().objects[&supervisor_path]["metadata"]["uid"],
        before["metadata"]["uid"]
    );
    let secret: Secret = serde_json::from_value(
        state.lock().unwrap().objects[&format!("{SECRETS}/{}", canonical_names.supervisor_secret)]
            .clone(),
    )
    .unwrap();
    assert!(
        !state
            .lock()
            .unwrap()
            .objects
            .contains_key(&format!("{SECRETS}/{}", names.supervisor_secret))
    );
    let registration = SandboxInstanceRegistration::from_launch_material(
        &secret.data.unwrap()[SHARED_INSTANCE_KEY].0,
    )
    .unwrap();
    assert_eq!(registration.sandbox_id, sandbox.id);
    assert_eq!(
        registration.auth.gateway_token.expose_secret(),
        "committed-gateway"
    );
    assert_eq!(
        registration.runtime_descriptor.tls,
        prepared.registration.runtime_descriptor.tls
    );
    assert_eq!(
        registration.runtime_descriptor.resource_claims["kubernetes.supervisor_pod_uid"],
        before["metadata"]["uid"].as_str().unwrap()
    );
    assert!(
        driver
            .try_claim_warm_runtime(&sandbox, "openshell")
            .await
            .unwrap()
            .unwrap()
            .ends_with(before["metadata"]["uid"].as_str().unwrap())
    );
}

#[tokio::test]
async fn dedicated_readiness_excludes_terminated_and_restarted_supervisors() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = dedicated_fixture(state.clone());
    let prepared = driver.prepare_warm_runtime(&request()).await.unwrap();
    let (_, _, record) = claim_object(&driver, &prepared.resource).await;
    let supervisor_path = format!("{PODS}/{}", record.names().supervisor_pod);
    {
        let mut state = state.lock().unwrap();
        state
            .objects
            .get_mut(&format!("{PODS}/{}", prepared.resource.name))
            .unwrap()["status"] = json!({"phase": "Running"});
        state.objects.get_mut(&supervisor_path).unwrap()["status"] = json!({
            "phase": "Running",
            "containerStatuses": [{
                "name": "supervisor", "image": "supervisor", "imageID": "supervisor",
                "ready": false, "started": true, "restartCount": 0,
                "state": {"running": {}}
            }]
        });
    }
    assert!(
        driver
            .warm_connection_ready(&prepared.resource)
            .await
            .unwrap()
    );
    // The Pod phase and successful startup verdict can lag a container exit.
    // The warm supervisor exits when its authenticated connection disappears.
    state
        .lock()
        .unwrap()
        .objects
        .get_mut(&supervisor_path)
        .unwrap()["status"]["containerStatuses"][0]["state"] =
        json!({"terminated": {"exitCode": 1}});
    assert!(
        !driver
            .warm_connection_ready(&prepared.resource)
            .await
            .unwrap()
    );
    {
        let mut state = state.lock().unwrap();
        let container =
            &mut state.objects.get_mut(&supervisor_path).unwrap()["status"]["containerStatuses"][0];
        container["state"] = json!({"running": {}});
        container["restartCount"] = json!(1);
    }
    // A restarted process cannot revive the old spare, even if it reconnects
    // and its startup probe succeeds again.
    assert!(
        !driver
            .warm_connection_ready(&prepared.resource)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn dedicated_preparation_rejects_a_replaced_supervisor() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = dedicated_fixture(state.clone());
    let prepared = driver.prepare_warm_runtime(&request()).await.unwrap();
    let (_, _, record) = claim_object(&driver, &prepared.resource).await;
    state
        .lock()
        .unwrap()
        .objects
        .get_mut(&format!("{PODS}/{}", record.names().supervisor_pod))
        .unwrap()["metadata"]["uid"] = json!("replacement");
    assert!(
        driver
            .resume_warm_runtime(&prepared.resource)
            .await
            .is_err()
    );
    assert!(
        !driver
            .warm_connection_ready(&prepared.resource)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn dedicated_registration_authenticates_only_the_original_live_physical_binding() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = dedicated_fixture(state.clone());
    let request = request();
    let prepared = driver.prepare_warm_runtime(&request).await.unwrap();
    let (api, object, record) = claim_object(&driver, &prepared.resource).await;
    let names = record.names();
    let pod_path = format!("{PODS}/{}", names.supervisor_pod);
    let pod = state.lock().unwrap().objects[&pod_path].clone();
    state.lock().unwrap().token_review = Some(json!({
        "authenticated":true, "audiences":[SANDBOX_TOKEN_AUDIENCE],
        "user": {"username":format!("system:serviceaccount:openshell:{}", driver.config.service_account_name),
            "extra": {POD_NAME_EXTRA:[names.supervisor_pod], POD_UID_EXTRA:[pod["metadata"]["uid"]]}}
    }));
    let binding = driver
        .authenticate_warm_supervisor("test-token")
        .await
        .unwrap();
    assert_eq!(binding.route, prepared.registration.route);
    state.lock().unwrap().fail_read =
        Some((format!("{SANDBOXES}/{}", prepared.resource.name), 503));
    assert_eq!(
        driver
            .authenticate_warm_supervisor("test-token")
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    state.lock().unwrap().fail_read = None;
    assert!(driver.authenticate_sandbox("test-token").await.is_err());
    let sandbox = claiming_sandbox(&request, "logical-dedicated");
    driver
        .claim_warm_object(
            &sandbox,
            &api,
            &object,
            &record,
            prepared.registration.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        driver
            .authenticate_warm_supervisor("test-token")
            .await
            .unwrap(),
        binding
    );
    assert_eq!(
        driver.authenticate_sandbox("test-token").await.unwrap().0,
        sandbox.id
    );
    for path in [
        pod_path,
        format!("{PODS}/{}", prepared.resource.name),
        format!("{SANDBOXES}/{}", prepared.resource.name),
        "/api/v1/namespaces/openshell".into(),
    ] {
        let original = state.lock().unwrap().objects[&path].clone();
        state.lock().unwrap().objects.get_mut(&path).unwrap()["metadata"]["uid"] =
            json!("replaced");
        assert!(
            driver
                .authenticate_warm_supervisor("test-token")
                .await
                .is_err(),
            "{path}"
        );
        state
            .lock()
            .unwrap()
            .objects
            .insert(path.clone(), original.clone());
        state.lock().unwrap().objects.get_mut(&path).unwrap()["metadata"]["deletionTimestamp"] =
            json!("2026-11-12T00:00:00Z");
        assert!(
            driver
                .authenticate_warm_supervisor("test-token")
                .await
                .is_err(),
            "{path}"
        );
        state.lock().unwrap().objects.insert(path, original);
    }
}

#[tokio::test]
async fn template_targets_are_capped_and_disable_drains_without_changing_identity() {
    let state = Arc::new(Mutex::new(State::default()));
    let mut driver = fixture(state);
    assert!(driver.config.warm_pool.enabled);
    driver.config.warm_pool.max_size = 1;
    let active = driver.template_warm_pools(None).await.unwrap().remove(0);
    assert_eq!(active.target_size, 1);
    let trust = request().trust;
    let before = reconciler::fingerprint(&driver.config, &active, &trust).unwrap();
    driver.config.warm_pool.enabled = false;
    let disabled = driver.template_warm_pools(None).await.unwrap().remove(0);
    assert_eq!(disabled.target_size, 0);
    assert_eq!(disabled.name, active.name);
    assert_eq!(
        reconciler::fingerprint(&driver.config, &disabled, &trust).unwrap(),
        before
    );
}
