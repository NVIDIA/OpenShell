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
struct State {
    secret: Option<Secret>,
    events: Vec<&'static str>,
    requests: Vec<PreparationRequest>,
    refuse: bool,
    read_error: Option<u16>,
    ambiguous_create: bool,
    initial_reads: usize,
}

struct Placement(Arc<Mutex<State>>);

impl std::fmt::Debug for Placement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Placement")
    }
}

impl InstancePlacement for Placement {
    fn retire_preparation(
        &self,
        _: openshell_supervisor_control::PreparationRetirement,
    ) -> PlacementFuture<PreparationRelease> {
        panic!("unexpected retirement")
    }
    fn prepare_runtime(&self, request: PreparationRequest) -> PlacementFuture {
        let mut state = self.0.lock().unwrap();
        // Capacity must never be reserved for transient, unpersisted TLS material.
        let secret = state
            .secret
            .as_ref()
            .expect("bootstrap persisted before reservation");
        let registration: PreparedRuntimeRegistration =
            serde_json::from_slice(&secret.data.as_ref().unwrap()[REGISTRATION_KEY].0).unwrap();
        assert_eq!(request.registration, registration);
        assert_eq!(request.auth_epoch.get(), 7);
        state.events.push("prepare");
        state.requests.push(request);
        let result = if state.refuse {
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
        panic!("unexpected inventory")
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

fn response(
    code: u16,
    value: serde_json::Value,
) -> http::Response<http_body_util::Full<bytes::Bytes>> {
    http::Response::builder()
        .status(code)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            serde_json::to_vec(&value).unwrap(),
        )))
        .unwrap()
}

fn api_error(code: u16) -> http::Response<http_body_util::Full<bytes::Bytes>> {
    response(
        code,
        serde_json::json!({
            "apiVersion": "v1", "kind": "Status", "status": "Failure",
            "message": "fixture error", "reason": if code == 404 { "NotFound" } else { "fixture" }, "code": code,
        }),
    )
}

fn fixture(
    bootstrap: &PreparedRuntimeBootstrap,
    state: Arc<Mutex<State>>,
    race: bool,
) -> (kube::Client, SharedSupervision) {
    let supervision = SharedSupervision::new();
    supervision
        .controller()
        .install_placement(Arc::new(Placement(state.clone())));
    let path = format!("/api/v1/namespaces/{}/secrets", bootstrap.namespace);
    let name = bootstrap.secret_name.clone();
    let barrier = race.then(|| Arc::new(tokio::sync::Barrier::new(2)));
    let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
        let state = state.clone();
        let path = path.clone();
        let name = name.clone();
        let barrier = barrier.clone();
        async move {
            let response = match request.method().clone() {
                http::Method::GET => {
                    assert_eq!(request.uri().path(), format!("{path}/{name}"));
                    let (response, wait) = {
                        let mut state = state.lock().unwrap();
                        state.events.push("get");
                        state.initial_reads += 1;
                        let response = state.read_error.map_or_else(
                            || {
                                state.secret.as_ref().map_or_else(
                                    || api_error(404),
                                    |secret| response(200, serde_json::to_value(secret).unwrap()),
                                )
                            },
                            api_error,
                        );
                        (response, state.initial_reads <= 2)
                    };
                    if wait && let Some(barrier) = barrier {
                        barrier.wait().await;
                    }
                    response
                }
                http::Method::POST => {
                    assert_eq!(request.uri().path(), path);
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    let candidate: Secret = serde_json::from_slice(&body).unwrap();
                    let mut state = state.lock().unwrap();
                    state.events.push("create");
                    if state.secret.is_some() {
                        api_error(409)
                    } else {
                        state.secret = Some(candidate.clone());
                        if state.ambiguous_create {
                            api_error(504)
                        } else {
                            response(201, serde_json::to_value(candidate).unwrap())
                        }
                    }
                }
                _ => panic!("bootstrap must not release scheduling gates or delete resources"),
            };
            Ok::<_, Infallible>(response)
        }
    });
    (kube::Client::new(service, "default"), supervision)
}

#[tokio::test]
async fn preparation_recovers_the_same_identity_after_gateway_restart() {
    let bootstrap = bootstrap();
    let state = Arc::new(Mutex::new(State::default()));
    let (client, supervision) = fixture(&bootstrap, state.clone(), false);
    let registration = bootstrap
        .prepare(client, &supervision, |tls| {
            spec(&bootstrap, tls).provision_prepared()
        })
        .await
        .unwrap();
    let secret = state.lock().unwrap().secret.clone().unwrap();
    assert_eq!(secret.immutable, Some(true));
    assert_eq!(
        secret.metadata.owner_references,
        Some(vec![bootstrap.owner()])
    );
    assert!(registration.runtime_descriptor.boundary_id.is_empty());
    let config: BoundaryConfig =
        serde_json::from_slice(secret_value(&secret, BOUNDARY_CONFIG_KEY).unwrap()).unwrap();
    assert!(config.boundary_id.is_empty());
    assert_eq!(
        config.resource_claims["kubernetes.workload_pod_uid"],
        bootstrap.pod_uid
    );
    let public = serde_json::to_string(&registration).unwrap();
    assert!(!public.contains("PRIVATE KEY"));
    assert!(!public.contains("gateway_token"));
    assert!(!public.contains("sandbox_token"));

    let (client, supervision) = fixture(&bootstrap, state.clone(), false);
    let recovered = bootstrap
        .prepare(client, &supervision, |tls| {
            spec(&bootstrap, tls).provision_prepared()
        })
        .await
        .unwrap();
    assert_eq!(registration, recovered);
    let state = state.lock().unwrap();
    assert_eq!(state.secret.as_ref(), Some(&secret));
    assert_eq!(state.events, ["get", "create", "prepare", "get", "prepare"]);
}

#[tokio::test]
async fn competing_replicas_reserve_only_the_winning_tls_identity() {
    let bootstrap = bootstrap();
    let state = Arc::new(Mutex::new(State::default()));
    let (client, supervision) = fixture(&bootstrap, state.clone(), true);
    let (first, second) = tokio::join!(
        bootstrap.prepare(client.clone(), &supervision, |tls| spec(&bootstrap, tls)
            .provision_prepared()),
        bootstrap.prepare(client, &supervision, |tls| spec(&bootstrap, tls)
            .provision_prepared()),
    );
    assert_eq!(first.unwrap(), second.unwrap());
    let state = state.lock().unwrap();
    assert_eq!(state.events.iter().filter(|e| **e == "create").count(), 2);
    assert_eq!(state.requests.len(), 2);
    assert_eq!(
        state.requests[0].registration,
        state.requests[1].registration
    );
}

#[tokio::test]
async fn capacity_refusal_preserves_bootstrap_for_retry() {
    let bootstrap = bootstrap();
    let state = Arc::new(Mutex::new(State {
        refuse: true,
        ..State::default()
    }));
    let (client, supervision) = fixture(&bootstrap, state.clone(), false);
    assert!(
        bootstrap
            .prepare(client.clone(), &supervision, |tls| spec(&bootstrap, tls)
                .provision_prepared())
            .await
            .is_err()
    );
    let secret = {
        let mut state = state.lock().unwrap();
        state.refuse = false;
        state.secret.clone().unwrap()
    };
    bootstrap
        .prepare(client, &supervision, |tls| {
            spec(&bootstrap, tls).provision_prepared()
        })
        .await
        .unwrap();
    let state = state.lock().unwrap();
    assert_eq!(state.secret.as_ref(), Some(&secret));
    assert_eq!(
        state.requests[0].registration,
        state.requests[1].registration
    );
    assert!(supervision.controller().pool_withdrawals().is_empty());
}

#[tokio::test]
async fn ambiguous_secret_creation_is_recovered_without_rekeying() {
    let bootstrap = bootstrap();
    let state = Arc::new(Mutex::new(State {
        ambiguous_create: true,
        ..State::default()
    }));
    let (client, supervision) = fixture(&bootstrap, state.clone(), false);
    assert!(
        bootstrap
            .prepare(client.clone(), &supervision, |tls| spec(&bootstrap, tls)
                .provision_prepared())
            .await
            .is_err()
    );
    let secret = state.lock().unwrap().secret.clone().unwrap();
    assert!(state.lock().unwrap().requests.is_empty());
    bootstrap
        .prepare(client, &supervision, |tls| {
            spec(&bootstrap, tls).provision_prepared()
        })
        .await
        .unwrap();
    let state = state.lock().unwrap();
    assert_eq!(state.secret.as_ref(), Some(&secret));
    assert_eq!(state.events, ["get", "create", "get", "prepare"]);
}

#[tokio::test]
async fn failed_reads_never_create_replacement_material_or_reserve_capacity() {
    for code in [403, 500] {
        let bootstrap = bootstrap();
        let state = Arc::new(Mutex::new(State {
            read_error: Some(code),
            ..State::default()
        }));
        let (client, supervision) = fixture(&bootstrap, state.clone(), false);
        assert!(
            bootstrap
                .prepare(client, &supervision, |_| panic!(
                    "must not generate replacement material"
                ))
                .await
                .is_err()
        );
        assert_eq!(state.lock().unwrap().events, ["get"]);
    }
}

#[tokio::test]
async fn replacement_pod_and_workspace_cannot_adopt_existing_bootstrap() {
    let bootstrap = bootstrap();
    let state = Arc::new(Mutex::new(State::default()));
    let (client, supervision) = fixture(&bootstrap, state.clone(), false);
    bootstrap
        .prepare(client.clone(), &supervision, |tls| {
            spec(&bootstrap, tls).provision_prepared()
        })
        .await
        .unwrap();
    for field in ["pod_uid", "workspace", "session_id"] {
        let mut replacement = bootstrap.clone();
        match field {
            "pod_uid" => replacement.pod_uid = "replacement-pod".into(),
            "workspace" => replacement.workspace = "team-b".into(),
            _ => replacement.session_id = SandboxSessionId::new(),
        }
        assert!(
            replacement
                .prepare(client.clone(), &supervision, |tls| spec(&replacement, tls)
                    .provision_prepared())
                .await
                .is_err()
        );
    }
    assert_eq!(state.lock().unwrap().requests.len(), 1);
}

#[tokio::test]
async fn changed_physical_or_bootstrap_inputs_are_rejected_before_reservation() {
    let bootstrap = bootstrap();
    let state = Arc::new(Mutex::new(State::default()));
    let (client, supervision) = fixture(&bootstrap, state.clone(), false);
    bootstrap
        .prepare(client.clone(), &supervision, |tls| {
            spec(&bootstrap, tls).provision_prepared()
        })
        .await
        .unwrap();
    for field in [
        "generation",
        "resource_uid",
        "fence",
        "epoch",
        "keys",
        "env",
        "address",
    ] {
        let result = bootstrap
            .prepare(client.clone(), &supervision, |tls| {
                let mut spec = spec(&bootstrap, tls);
                match field {
                    "generation" => spec.generation = "other-generation".into(),
                    "resource_uid" => spec.sandbox_resource_uid = "other-resource".into(),
                    "fence" => spec.egress_policy_resource_version = "999".into(),
                    "epoch" => spec.auth_epoch = CredentialEpoch::new(8).unwrap(),
                    "keys" => spec.verification_keys.clear(),
                    "env" => {
                        spec.child_env.insert("OTHER".into(), "value".into());
                    }
                    _ => {
                        if let KubernetesControlPath::RuntimeInitiatedShared {
                            supervisor_address,
                            ..
                        } = &mut spec.control_path
                        {
                            *supervisor_address = "10.42.0.8:5500".parse().unwrap();
                        }
                    }
                }
                spec.provision_prepared()
            })
            .await;
        assert!(result.is_err(), "accepted changed {field}");
    }
    assert_eq!(state.lock().unwrap().requests.len(), 1);
}

#[tokio::test]
async fn malformed_or_mutable_secret_is_never_repaired_in_place() {
    let bootstrap = bootstrap();
    let state = Arc::new(Mutex::new(State::default()));
    let (client, supervision) = fixture(&bootstrap, state.clone(), false);
    bootstrap
        .prepare(client.clone(), &supervision, |tls| {
            spec(&bootstrap, tls).provision_prepared()
        })
        .await
        .unwrap();
    let original = state.lock().unwrap().secret.clone().unwrap();
    for field in [
        "immutable",
        "owner",
        "config",
        "registration",
        "key",
        "extra",
    ] {
        let mut secret = original.clone();
        match field {
            "immutable" => secret.immutable = Some(false),
            "owner" => secret.metadata.owner_references = None,
            "config" => {
                secret.data.as_mut().unwrap().insert(
                    BOUNDARY_CONFIG_KEY.into(),
                    ByteString(b"invalid secret marker".to_vec()),
                );
            }
            "registration" => {
                secret.data.as_mut().unwrap().remove(REGISTRATION_KEY);
            }
            "key" => {
                secret.data.as_mut().unwrap().insert(
                    BOUNDARY_PRIVATE_KEY.into(),
                    ByteString(b"invalid secret marker".to_vec()),
                );
            }
            _ => {
                secret
                    .data
                    .as_mut()
                    .unwrap()
                    .insert("auth.json".into(), ByteString(vec![1]));
            }
        }
        state.lock().unwrap().secret = Some(secret);
        let error = bootstrap
            .prepare(client.clone(), &supervision, |tls| {
                spec(&bootstrap, tls).provision_prepared()
            })
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("invalid secret marker"));
    }
    let state = state.lock().unwrap();
    assert_eq!(state.requests.len(), 1);
    assert_eq!(
        state
            .events
            .iter()
            .filter(|event| **event == "create")
            .count(),
        1
    );
}

#[test]
fn prepared_provisioning_binds_both_topologies_and_rejects_invalid_identity() {
    let bootstrap = bootstrap();
    let material = generate_sandbox_tls_material(bootstrap.session_id).unwrap();
    let mut dedicated = spec(&bootstrap, tls_pin(&material));
    dedicated.supervisor = KubernetesSupervisorClaim::Pod("supervisor-uid".into());
    let prepared = dedicated.provision_prepared().unwrap();
    assert_eq!(
        prepared.runtime_descriptor.resource_claims["kubernetes.supervisor_pod_uid"],
        "supervisor-uid"
    );
    for case in ["assigned", "dedicated", "route", "missing_uid"] {
        let mut spec = spec(&bootstrap, tls_pin(&material));
        match case {
            "assigned" => spec.boundary_id = "logical-sandbox".into(),
            "dedicated" => {
                spec.supervisor = KubernetesSupervisorClaim::Pod(String::new());
            }
            "route" => {
                spec.supervisor =
                    KubernetesSupervisorClaim::SandboxInstance("rt-wrong-0123456789".into());
            }
            _ => spec.workload_pod_uid.clear(),
        }
        assert!(spec.provision_prepared().is_err(), "accepted {case}");
    }
}

#[tokio::test]
async fn prepared_pods_have_independent_tls_identities_and_require_the_expected_name() {
    let first = bootstrap();
    let mut second = bootstrap();
    second.pod_name = "another-pod".into();
    second.pod_uid = "pod-uid-2".into();
    second.secret_name = "warm-bootstrap-2".into();
    let mut identities = Vec::new();
    for bootstrap in [first, second] {
        let state = Arc::new(Mutex::new(State::default()));
        let (client, supervision) = fixture(&bootstrap, state.clone(), false);
        let registration = bootstrap
            .prepare(client, &supervision, |tls| {
                spec(&bootstrap, tls).provision_prepared()
            })
            .await
            .unwrap();
        identities.push((
            state.lock().unwrap().secret.clone().unwrap(),
            registration.runtime_descriptor.tls,
        ));
    }
    let (secret, pin) = &identities[0];
    let (other_secret, other_pin) = &identities[1];
    assert_ne!(
        secret_value(secret, BOUNDARY_PRIVATE_KEY).unwrap(),
        secret_value(other_secret, BOUNDARY_PRIVATE_KEY).unwrap()
    );
    assert_ne!(pin.trust_anchor_pem, other_pin.trust_anchor_pem);
    assert!(tls_connect(secret, pin).await);
    assert!(tls_connect(other_secret, other_pin).await);
    assert!(!tls_connect(secret, other_pin).await);
    let mut wrong_name = pin.clone();
    wrong_name.server_name = "warm-pod.sandbox-ns.svc".into();
    assert!(!tls_connect(secret, &wrong_name).await);
}

async fn tls_connect(secret: &Secret, pin: &SandboxTlsClientConfig) -> bool {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
    let certs =
        CertificateDer::pem_slice_iter(secret_value(secret, BOUNDARY_CERTIFICATE_KEY).unwrap())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(secret_value(secret, BOUNDARY_PRIVATE_KEY).unwrap()).unwrap();
    let server = openshell_crypto::tls::try_server_builder()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(pin.trust_anchor_pem.as_bytes()).unwrap())
        .unwrap();
    let client = openshell_crypto::tls::try_client_builder()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let (server, client) = tokio::io::duplex(64 * 1024);
    let (_, connected) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            acceptor.accept(server),
            connector.connect(
                ServerName::try_from(pin.server_name.clone()).unwrap(),
                client
            )
        )
    })
    .await
    .expect("TLS handshake completes");
    connected.is_ok()
}

#[tokio::test]
async fn provisioning_cannot_substitute_a_different_tls_pin() {
    let bootstrap = bootstrap();
    let state = Arc::new(Mutex::new(State::default()));
    let (client, supervision) = fixture(&bootstrap, state.clone(), false);
    let substituted = generate_sandbox_tls_material(bootstrap.session_id).unwrap();
    assert!(
        bootstrap
            .prepare(client, &supervision, |_| spec(
                &bootstrap,
                tls_pin(&substituted)
            )
            .provision_prepared())
            .await
            .is_err()
    );
    assert_eq!(state.lock().unwrap().events, ["get"]);
}
