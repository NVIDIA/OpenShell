// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use http_body_util::BodyExt;
use openshell_core::jwt::{CredentialEpoch, SessionRotation};
use openshell_isolation_interface::contract::ResolvedWorkloadIdentity;
use openshell_sandbox_backend::boundary_protocol::{
    GatewayVerificationKey, SandboxTlsServerConfig,
};
use openshell_supervisor_control::{
    ActivationRequest, InstancePlacement, PlacementFuture, PlacementRequest, PreparationRelease,
    PreparationRevision, PreparedRuntime, proto::SandboxInstanceAssignment,
};

use super::*;
use crate::isolation::{
    KubernetesControlPath, KubernetesSandboxRuntimeBoundarySpec, KubernetesSupervisorClaim,
};

fn bootstrap() -> PreparedRuntimeBootstrap {
    PreparedRuntimeBootstrap {
        pool_id: "pool-a".into(),
        workspace: "team-a".into(),
        namespace: "sandbox-ns".into(),
        pod_name: "warm-pod".into(),
        pod_uid: "pod-uid-1".into(),
        secret_name: "warm-bootstrap-1".into(),
        session_id: SandboxSessionId::new(),
    }
}

fn spec(
    bootstrap: &PreparedRuntimeBootstrap,
    tls: SandboxTlsClientConfig,
) -> KubernetesSandboxRuntimeBoundarySpec {
    let route = format!("rt-{}", bootstrap.session_id);
    KubernetesSandboxRuntimeBoundarySpec {
        boundary_id: String::new(),
        generation: "physical-generation-1".into(),
        session_id: bootstrap.session_id,
        session_rotation: SessionRotation::new(1).unwrap(),
        auth_epoch: CredentialEpoch::new(7).unwrap(),
        gateway_id: "gateway-1".into(),
        verification_keys: vec![GatewayVerificationKey {
            key_id: "key-1".into(),
            public_key_pem: "verification-key".into(),
        }],
        namespace_uid: "namespace-uid".into(),
        sandbox_resource_uid: "physical-sandbox-uid".into(),
        workload_pod_uid: bootstrap.pod_uid.clone(),
        workload_pod_uid_path: PathBuf::from("/.openshell/pod-identity/uid"),
        supervisor: KubernetesSupervisorClaim::SandboxInstance(route.clone()),
        egress_policy_uid: "fence-uid".into(),
        egress_policy_resource_version: "123".into(),
        control_path: KubernetesControlPath::RuntimeInitiatedShared {
            control_authority: "shared.gateway.svc:5500".into(),
            supervisor_address: "10.42.0.7:5500".parse().unwrap(),
            supervisor_namespace: "gateway".into(),
            route,
            control_policy_uid: "control-uid".into(),
            control_policy_resource_version: "456".into(),
        },
        sandbox_tls: SandboxTlsServerConfig {
            certificate_chain_path: BOUNDARY_CERTIFICATE_PATH.into(),
            private_key_path: BOUNDARY_PRIVATE_KEY_PATH.into(),
        },
        supervisor_tls: tls,
        host_gateway_ip: None,
        workload_identity: ResolvedWorkloadIdentity::new(
            1000,
            1000,
            Vec::new(),
            "kubernetes-config".into(),
            "sandbox:physical-sandbox-uid".into(),
        )
        .unwrap(),
        child_env: HashMap::new(),
    }
}

#[derive(Default)]
#[allow(clippy::struct_excessive_bools)]
struct State {
    secret: Option<Secret>,
    assignment: Option<SandboxInstanceAssignment>,
    events: Vec<&'static str>,
    refuse: bool,
    read_error: bool,
    ambiguous_create: bool,
    ambiguous_prepare: bool,
}

struct Placement(Arc<Mutex<State>>);
impl std::fmt::Debug for Placement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Placement")
    }
}
impl InstancePlacement for Placement {
    fn runtime_assignment(
        &self,
        _: String,
        _: String,
    ) -> PlacementFuture<Option<SandboxInstanceAssignment>> {
        let state = self.0.lock().unwrap();
        let result = if state.read_error {
            Err("gateway unavailable".into())
        } else {
            Ok(state.assignment.clone())
        };
        Box::pin(async move { result })
    }
    fn prepare_runtime(&self, request: PreparationRequest) -> PlacementFuture {
        let mut state = self.0.lock().unwrap();
        assert!(state.secret.is_some());
        state.events.push("prepare");
        let result = if state.refuse {
            Err("no capacity".into())
        } else {
            state.assignment = Some(request.registration.to_assignment().unwrap());
            if state.ambiguous_prepare {
                Err("response lost".into())
            } else {
                Ok(())
            }
        };
        Box::pin(async move { result })
    }
    fn place_launch(&self, _: PlacementRequest) -> PlacementFuture {
        panic!("active launch")
    }
    fn prepared_runtimes(&self, _: String) -> PlacementFuture<Vec<PreparedRuntime>> {
        panic!("inventory")
    }
    fn retire_preparation(
        &self,
        _: openshell_supervisor_control::PreparationRetirement,
    ) -> PlacementFuture<PreparationRelease> {
        panic!("retirement")
    }
    fn release_preparation(&self, _: PreparationRevision) -> PlacementFuture<PreparationRelease> {
        panic!("release")
    }
    fn activate_runtime(&self, _: ActivationRequest) -> PlacementFuture<SandboxInstanceAssignment> {
        panic!("activation")
    }
    fn recorded(&self) -> PlacementFuture<BTreeMap<String, i64>> {
        panic!("recovery")
    }
    fn record_recovered(&self, _: SandboxInstanceAssignment) -> PlacementFuture {
        panic!("recovery")
    }
}

fn fixture(state: Arc<Mutex<State>>) -> (kube::Client, SharedSupervision) {
    let supervision = SharedSupervision::new();
    supervision
        .controller()
        .install_placement(Arc::new(Placement(state.clone())));
    let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
        let state = state.clone();
        async move {
            // No GET, LIST or WATCH is permitted, even on conflicts or recovery.
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(
                request.uri().path(),
                "/api/v1/namespaces/sandbox-ns/secrets"
            );
            let body = request.into_body().collect().await.unwrap().to_bytes();
            let secret: Secret = serde_json::from_slice(&body).unwrap();
            let mut state = state.lock().unwrap();
            state.events.push("create");
            let code = if state.secret.is_some() {
                409
            } else {
                state.secret = Some(secret.clone());
                if state.ambiguous_create { 504 } else { 201 }
            };
            let value = if code == 201 {
                serde_json::to_value(secret).unwrap()
            } else {
                serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "message":"fixture", "reason":"fixture", "code":code})
            };
            Ok::<_, Infallible>(
                http::Response::builder()
                    .status(code)
                    .header("content-type", "application/json")
                    .body(http_body_util::Full::new(bytes::Bytes::from(
                        serde_json::to_vec(&value).unwrap(),
                    )))
                    .unwrap(),
            )
        }
    });
    (kube::Client::new(service, "default"), supervision)
}

#[tokio::test]
async fn preparation_recovers_public_identity_without_reading_secrets() {
    let bootstrap = bootstrap();
    let state = Arc::new(Mutex::new(State::default()));
    let (client, supervision) = fixture(state.clone());
    let first = bootstrap
        .prepare(
            client,
            &supervision,
            |tls| spec(&bootstrap, tls).provision_prepared(),
            |_| async {
                state.lock().unwrap().events.push("other-bootstrap-writes");
                Ok(())
            },
        )
        .await
        .unwrap();
    let (client, restarted) = fixture(state.clone());
    let recovered = bootstrap
        .prepare(
            client,
            &restarted,
            |tls| spec(&bootstrap, tls).provision_prepared(),
            |_| async { panic!("completed bootstrap must not be recreated") },
        )
        .await
        .unwrap();
    assert_eq!(first, recovered);
    assert_eq!(
        state.lock().unwrap().events,
        ["create", "other-bootstrap-writes", "prepare"]
    );
}

#[tokio::test]
async fn incomplete_preparations_never_adopt_conflicting_or_ambiguous_secrets() {
    for failure in ["create", "other-writes", "capacity"] {
        let bootstrap = bootstrap();
        let state = Arc::new(Mutex::new(State {
            ambiguous_create: failure == "create",
            refuse: failure == "capacity",
            ..Default::default()
        }));
        let (client, supervision) = fixture(state.clone());
        assert!(
            bootstrap
                .prepare(
                    client,
                    &supervision,
                    |tls| spec(&bootstrap, tls).provision_prepared(),
                    |_| async {
                        if failure == "other-writes" {
                            Err(invalid("interrupted bootstrap"))
                        } else {
                            Ok(())
                        }
                    }
                )
                .await
                .is_err()
        );
        let original = state.lock().unwrap().secret.clone().unwrap();
        state.lock().unwrap().refuse = false;
        let (client, restarted) = fixture(state.clone());
        assert!(
            bootstrap
                .prepare(
                    client,
                    &restarted,
                    |tls| spec(&bootstrap, tls).provision_prepared(),
                    |_| async { Ok(()) }
                )
                .await
                .is_err()
        );
        assert_eq!(state.lock().unwrap().secret.as_ref(), Some(&original));
        assert!(state.lock().unwrap().assignment.is_none());
    }
}

#[tokio::test]
async fn lost_preparation_response_recovers_after_the_durable_milestone() {
    let bootstrap = bootstrap();
    let state = Arc::new(Mutex::new(State {
        ambiguous_prepare: true,
        ..Default::default()
    }));
    let (client, supervision) = fixture(state.clone());
    assert!(
        bootstrap
            .prepare(
                client,
                &supervision,
                |tls| spec(&bootstrap, tls).provision_prepared(),
                |_| async { Ok(()) }
            )
            .await
            .is_err()
    );
    let (client, restarted) = fixture(state.clone());
    bootstrap
        .prepare(
            client,
            &restarted,
            |tls| spec(&bootstrap, tls).provision_prepared(),
            |_| async { panic!("no rewrites") },
        )
        .await
        .unwrap();
    assert_eq!(state.lock().unwrap().events, ["create", "prepare"]);
}

#[tokio::test]
async fn recovery_rejects_changed_physical_coordinates_and_failed_gateway_reads() {
    let bootstrap = bootstrap();
    let state = Arc::new(Mutex::new(State::default()));
    let (client, supervision) = fixture(state.clone());
    bootstrap
        .prepare(
            client.clone(),
            &supervision,
            |tls| spec(&bootstrap, tls).provision_prepared(),
            |_| async { Ok(()) },
        )
        .await
        .unwrap();
    let mut replacement = bootstrap.clone();
    replacement.pod_uid = "replacement".into();
    assert!(
        replacement
            .prepare(
                client.clone(),
                &supervision,
                |tls| spec(&replacement, tls).provision_prepared(),
                |_| async { Ok(()) }
            )
            .await
            .is_err()
    );
    state.lock().unwrap().read_error = true;
    assert!(
        bootstrap
            .prepare(
                client,
                &supervision,
                |_| panic!("failed reads must not generate a new identity"),
                |_| async { Ok(()) }
            )
            .await
            .is_err()
    );
    assert_eq!(state.lock().unwrap().events, ["create", "prepare"]);
}
