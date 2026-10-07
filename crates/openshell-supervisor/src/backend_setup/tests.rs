// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::collections::{BTreeMap, HashMap};
use std::sync::Weak;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use openshell_core::jwt::{CredentialEpoch, SecretJwt, SessionRotation};
use openshell_core::policy::{FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy};
use openshell_core::sandbox_generation::SandboxGenerationId;
use openshell_isolation_interface::contract::{
    BoundaryConfirmation, BoundaryDuplexStream, BoundaryExec, BoundaryExitStatus,
    BoundaryLoopbackConnector, BoundaryProcess, BoundaryProperties, BoundarySignal,
    ConfirmedBoundary, EnforcedProperty, ExecSession, ExecSpec, LoopbackTarget,
    NetworkMediationSource, OuterFenceGuarantee, OuterFenceGuarantees, PendingDnsQuery,
    PendingTcpOpen, ReadyBoundary, RunningBoundary, VerifiedBackendDescriptor,
};
use openshell_supervisor_network::upstream_proxy::UpstreamProxyArgs;

const TEST_BACKEND: &str = "in-process-test";
// Deliberately not JSON or a SandboxRuntimeDescriptor. Only TestSetup accepts it.
const TEST_PAYLOAD: &[u8] = b"in-process-v1\0owned-launch";

#[derive(Default)]
struct Observed {
    events: Mutex<Vec<&'static str>>,
    services: Mutex<Weak<BackendServices>>,
    discovery_unavailable: AtomicBool,
    deny_confirmation: AtomicBool,
    require_networking: AtomicBool,
    active: AtomicBool,
    starts: AtomicUsize,
    releases: AtomicUsize,
}

impl Observed {
    fn record(&self, event: &'static str) {
        self.events.lock().unwrap().push(event);
    }

    fn events(&self) -> Vec<&'static str> {
        self.events.lock().unwrap().clone()
    }
}

struct TestSetup {
    auth: SupervisorAuthBundle,
    sandbox_id: String,
    selected_name: &'static str,
    built_name: &'static str,
    observed: Arc<Observed>,
}

impl TestSetup {
    fn new() -> Self {
        Self {
            auth: SupervisorAuthBundle {
                session_id: SandboxSessionId::new(),
                runtime_generation: SandboxGenerationId::parse("generation-1").unwrap(),
                session_rotation: SessionRotation::new(1).unwrap(),
                auth_epoch: CredentialEpoch::new(1).unwrap(),
                gateway_token: SecretJwt::parse("test-gateway-token").unwrap(),
                gateway_expires_at: 0,
                sandbox_token: SecretJwt::parse("test-sandbox-token").unwrap(),
                sandbox_expires_at: 0,
            },
            sandbox_id: "sandbox-1".to_string(),
            selected_name: TEST_BACKEND,
            built_name: TEST_BACKEND,
            observed: Arc::new(Observed::default()),
        }
    }

    fn descriptor() -> BackendDescriptor {
        BackendDescriptor {
            backend_name: TEST_BACKEND.to_string(),
            payload: TEST_PAYLOAD.to_vec(),
        }
    }

    fn select(&self) -> SelectedBackend {
        SelectedBackend::select(
            self,
            Self::descriptor(),
            Some(TEST_BACKEND),
            Some("sandbox-1"),
            &self.auth,
        )
        .unwrap()
    }

    fn services(&self) -> BackendServices {
        BackendServices {
            ca_file_paths: Arc::new(Mutex::new(None)),
            provider_credentials: ProviderCredentialState::from_child_env_snapshot(
                1,
                HashMap::from([("TEST_CONFIG".into(), "initial".into())]),
            ),
            sandbox_bearer: self.auth.sandbox_bearer_slot().unwrap(),
        }
    }
}

fn identity() -> ResolvedWorkloadIdentity {
    ResolvedWorkloadIdentity::new(1000, 1000, vec![], "test".into(), "test-resource".into())
        .unwrap()
}

fn policy() -> SandboxPolicy {
    SandboxPolicy {
        version: 1,
        filesystem: FilesystemPolicy::default(),
        network: NetworkPolicy::default(),
        landlock: LandlockPolicy::default(),
        process: ProcessPolicy::default(),
    }
}

fn agent() -> AgentSpec {
    AgentSpec {
        program: "test-agent".into(),
        args: vec!["test-argument".into()],
        workdir: Some("/test-workspace".into()),
        timeout_secs: 15,
        interactive: false,
    }
}

impl BackendSetup for TestSetup {
    fn backend_name(&self) -> &str {
        self.selected_name
    }

    fn decode(
        &self,
        payload: &[u8],
    ) -> std::result::Result<(LaunchIdentity, Box<dyn PreparedBackend>), BackendError> {
        self.observed.record("decode");
        if payload != TEST_PAYLOAD {
            return Err(BackendError::Descriptor(
                "invalid in-process launch data".into(),
            ));
        }
        Ok((
            LaunchIdentity {
                sandbox_id: self.sandbox_id.clone(),
                generation: self.auth.runtime_generation.to_string(),
                session_id: self.auth.session_id,
                workload_identity: identity(),
                vm_policy_identity: None,
            },
            Box::new(TestLaunch {
                name: self.built_name,
                observed: self.observed.clone(),
                generation: self.auth.runtime_generation.to_string(),
                expected_session: self.auth.session_id,
            }),
        ))
    }
}

struct TestLaunch {
    name: &'static str,
    observed: Arc<Observed>,
    generation: String,
    expected_session: SandboxSessionId,
}

#[tonic::async_trait]
impl PreparedBackend for TestLaunch {
    async fn discover_policy(
        &self,
        bearer: SessionBearerTokenSlot,
    ) -> std::result::Result<(Option<String>, bool), BackendError> {
        self.observed.record("discover");
        bearer.authorization_metadata().unwrap();
        if self.observed.discovery_unavailable.load(Ordering::SeqCst) {
            return Err(BackendError::Unavailable("discovery unavailable".into()));
        }
        Ok((None, false))
    }

    fn build(
        self: Box<Self>,
        services: BackendServices,
    ) -> std::result::Result<Arc<dyn IsolationBackend>, BackendError> {
        self.observed.record("build");
        let services = Arc::new(services);
        *self.observed.services.lock().unwrap() = Arc::downgrade(&services);
        Ok(Arc::new(TestBackend {
            name: self.name,
            observed: self.observed,
            services,
            generation: self.generation,
            expected_session: self.expected_session,
        }))
    }
}

struct TestBackend {
    name: &'static str,
    observed: Arc<Observed>,
    services: Arc<BackendServices>,
    generation: String,
    expected_session: SandboxSessionId,
}

#[tonic::async_trait]
impl IsolationBackend for TestBackend {
    fn backend_name(&self) -> &str {
        self.name
    }

    async fn attach(
        &self,
        descriptor: VerifiedBackendDescriptor,
        sandbox: SandboxContext,
    ) -> std::result::Result<Box<dyn BoundBoundary>, BackendError> {
        self.observed.record("attach");
        assert_eq!(descriptor.payload(), TEST_PAYLOAD);
        assert_eq!(descriptor.backend_name(), TEST_BACKEND);
        assert_eq!(sandbox.sandbox_id, "sandbox-1");
        assert_eq!(sandbox.session_id, self.expected_session);
        assert_eq!(sandbox.identity, identity());
        assert_eq!(sandbox.agent.program, "test-agent");
        assert_eq!(sandbox.agent.args, ["test-argument"]);
        assert_eq!(sandbox.agent.workdir.as_deref(), Some("/test-workspace"));
        assert_eq!(sandbox.agent.timeout_secs, 15);
        assert_eq!(sandbox.policy.version, 1);
        if self.observed.active.swap(true, Ordering::SeqCst) {
            return Err(BackendError::Denied("resource already owned".into()));
        }
        Ok(Box::new(TestBound {
            lease: Lease(self.observed.clone()),
            services: self.services.clone(),
            generation: self.generation.clone(),
            session_id: sandbox.session_id,
        }))
    }
}

// Models backend ownership only. Dropping a rejected or completed attempt
// releases this in-process resource; these tests make no Linux cleanup claim.
struct Lease(Arc<Observed>);

impl Drop for Lease {
    fn drop(&mut self) {
        self.0.active.store(false, Ordering::SeqCst);
        self.0.releases.fetch_add(1, Ordering::SeqCst);
    }
}

struct TestBound {
    lease: Lease,
    services: Arc<BackendServices>,
    generation: String,
    session_id: SandboxSessionId,
}

#[tonic::async_trait]
impl BoundBoundary for TestBound {
    fn network_mediation_source(&self) -> Arc<dyn NetworkMediationSource> {
        Arc::new(TestIo)
    }

    async fn confirm(self: Box<Self>) -> std::result::Result<ConfirmedBoundary, BackendError> {
        self.lease.0.record("confirm");
        let property = EnforcedProperty::new(true, "in-process-test");
        let confirmation = BoundaryConfirmation {
            generation: self.generation.clone(),
            identity: identity(),
            properties: BoundaryProperties {
                filesystem_confinement: property.clone(),
                egress_interception: property.clone(),
                request_attribution: property.clone(),
                privilege_floor: property,
            },
            authenticated_supervisor: !self.lease.0.deny_confirmation.load(Ordering::SeqCst),
            session_id: self.session_id,
            outer_fence: OuterFenceGuarantees::from_enforcement_evidence(
                &self.generation,
                [
                    OuterFenceGuarantee::DefaultDenyEgress,
                    OuterFenceGuarantee::NoUnmanagedEgressPath,
                    OuterFenceGuarantee::RevocationVerified,
                    OuterFenceGuarantee::ControllerLossFailsClosed,
                ],
                b"in-process-enforcement-evidence",
            )?,
            runtime_exit_terminates_workload: true,
            resource_claims: BTreeMap::new(),
            backend_audit: serde_json::json!({"in_process": true}),
        };
        ConfirmedBoundary::try_new(self, confirmation, &identity())
    }
}

#[tonic::async_trait]
impl ReadyBoundary for TestBound {
    async fn start_agent(
        self: Box<Self>,
    ) -> std::result::Result<Box<dyn RunningBoundary>, BackendError> {
        if self.lease.0.require_networking.load(Ordering::SeqCst) {
            let paths = self.services.ca_file_paths.lock().unwrap();
            let (certificate, bundle) = paths.as_ref().expect("networking published CA paths");
            assert!(certificate.is_file());
            assert!(bundle.is_file());
        }
        self.lease.0.record("start");
        self.lease.0.starts.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(TestRunning {
            _lease: self.lease,
            _services: self.services,
        }))
    }
}

struct TestRunning {
    _lease: Lease,
    _services: Arc<BackendServices>,
}

#[tonic::async_trait]
impl RunningBoundary for TestRunning {
    fn agent(&self) -> Arc<dyn BoundaryProcess> {
        Arc::new(TestIo)
    }
    fn exec(&self) -> Arc<dyn BoundaryExec> {
        Arc::new(TestIo)
    }
    fn loopback_connector(&self) -> Arc<dyn BoundaryLoopbackConnector> {
        Arc::new(TestIo)
    }
    async fn terminate(&self) -> std::result::Result<(), BackendError> {
        Ok(())
    }
}

struct TestIo;

#[tonic::async_trait]
impl NetworkMediationSource for TestIo {
    async fn accept_tcp(&self) -> std::result::Result<PendingTcpOpen, BackendError> {
        std::future::pending().await
    }
    async fn accept_dns(&self) -> std::result::Result<PendingDnsQuery, BackendError> {
        std::future::pending().await
    }
}

#[tonic::async_trait]
impl BoundaryProcess for TestIo {
    async fn wait(&self) -> std::result::Result<BoundaryExitStatus, BackendError> {
        Ok(BoundaryExitStatus::Exited(0))
    }
    async fn signal(&self, _: BoundarySignal) -> std::result::Result<(), BackendError> {
        Ok(())
    }
    async fn terminate(&self) -> std::result::Result<(), BackendError> {
        Ok(())
    }
}

#[tonic::async_trait]
impl BoundaryExec for TestIo {
    async fn exec(&self, _: ExecSpec) -> std::result::Result<ExecSession, BackendError> {
        Err(BackendError::Unsupported("test backend has no exec".into()))
    }
}

#[tonic::async_trait]
impl BoundaryLoopbackConnector for TestIo {
    async fn connect(
        &self,
        _: LoopbackTarget,
    ) -> std::result::Result<BoundaryDuplexStream, BackendError> {
        Err(BackendError::Unsupported(
            "test backend has no connector".into(),
        ))
    }
}

#[test]
fn admission_rejection_never_decodes_or_discovers() {
    let mut setup = TestSetup::new();
    for (descriptor_name, admitted) in [
        (TEST_BACKEND, None),
        ("foreign", Some(TEST_BACKEND)),
        (TEST_BACKEND, Some("foreign")),
    ] {
        let mut descriptor = TestSetup::descriptor();
        descriptor.backend_name = descriptor_name.into();
        descriptor.payload = b"malformed".to_vec();
        assert!(
            SelectedBackend::select(&setup, descriptor, admitted, Some("sandbox-1"), &setup.auth)
                .is_err()
        );
    }
    // Valid data would decode successfully if selection skipped its name check.
    setup.selected_name = "another-selected-backend";
    assert!(
        SelectedBackend::select(
            &setup,
            TestSetup::descriptor(),
            Some(TEST_BACKEND),
            Some("sandbox-1"),
            &setup.auth
        )
        .is_err()
    );
    assert!(setup.observed.events().is_empty());
}

#[test]
fn shared_identity_rejection_stops_before_discovery() {
    let setup = TestSetup::new();
    for sandbox in [None, Some(""), Some("other-sandbox")] {
        assert!(
            SelectedBackend::select(
                &setup,
                TestSetup::descriptor(),
                Some(TEST_BACKEND),
                sandbox,
                &setup.auth
            )
            .is_err()
        );
    }
    let mut auth = setup.auth.clone();
    auth.session_id = SandboxSessionId::new();
    assert!(
        SelectedBackend::select(
            &setup,
            TestSetup::descriptor(),
            Some(TEST_BACKEND),
            Some("sandbox-1"),
            &auth
        )
        .is_err()
    );
    auth = setup.auth.clone();
    auth.runtime_generation = SandboxGenerationId::parse("other-generation").unwrap();
    assert!(
        SelectedBackend::select(
            &setup,
            TestSetup::descriptor(),
            Some(TEST_BACKEND),
            Some("sandbox-1"),
            &auth
        )
        .is_err()
    );
    assert_eq!(setup.observed.events(), vec!["decode"; 5]);
    assert_eq!(setup.observed.starts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn attachment_receives_live_supervisor_services() {
    let setup = TestSetup::new();
    let services = setup.services();
    let ca_paths = services.ca_file_paths.clone();
    let providers = services.provider_credentials.clone();
    let bearer = services.sandbox_bearer.clone();
    let bound = setup
        .select()
        .attach(services, policy(), agent())
        .await
        .unwrap();
    let backend_services = setup.observed.services.lock().unwrap().upgrade().unwrap();
    assert!(Arc::ptr_eq(&ca_paths, &backend_services.ca_file_paths));
    assert!(Arc::ptr_eq(
        &providers.snapshot(),
        &backend_services.provider_credentials.snapshot()
    ));

    // Later updates must reach the handles retained during attachment.
    *ca_paths.lock().unwrap() = Some(("/test/ca".into(), "/test/bundle".into()));
    providers.install_child_env_snapshot(
        2,
        HashMap::from([("TEST_CONFIG".into(), "repaired".into())]),
    );
    bearer
        .update(
            SecretJwt::parse("rotated-test-token").unwrap(),
            0,
            CredentialEpoch::new(2).unwrap(),
        )
        .unwrap();
    assert_eq!(
        *backend_services.ca_file_paths.lock().unwrap(),
        Some(("/test/ca".into(), "/test/bundle".into()))
    );
    assert!(Arc::ptr_eq(
        &providers.snapshot(),
        &backend_services.provider_credentials.snapshot()
    ));
    assert_eq!(
        backend_services.provider_credentials.snapshot().child_env["TEST_CONFIG"],
        "repaired"
    );
    assert_eq!(
        backend_services.sandbox_bearer.credential_epoch(),
        Some(CredentialEpoch::new(2).unwrap())
    );
    bearer.clear();
    assert!(
        backend_services
            .sandbox_bearer
            .authorization_metadata()
            .is_err()
    );
    drop(backend_services);
    drop(bound);
    assert!(setup.observed.services.lock().unwrap().upgrade().is_none());
}

#[tokio::test]
async fn constructed_backend_must_keep_selected_name() {
    let mut setup = TestSetup::new();
    setup.built_name = "wrong-backend";
    assert!(
        setup
            .select()
            .attach(setup.services(), policy(), agent())
            .await
            .is_err()
    );
    assert_eq!(setup.observed.events(), ["decode", "build"]);
    assert_eq!(setup.observed.starts.load(Ordering::SeqCst), 0);
    assert!(setup.observed.services.lock().unwrap().upgrade().is_none());
}

#[test]
fn standard_setup_decodes_native_descriptor_and_preserves_vm_identity() {
    use openshell_sandbox_backend::boundary_protocol::{
        SandboxRuntimeDescriptor, SandboxTlsClientConfig, SandboxTransport,
    };

    assert!(OpenShellBackendSetup.decode(b"{}").is_err());
    let setup = TestSetup::new();
    let mut descriptor = SandboxRuntimeDescriptor {
        boundary_id: setup.sandbox_id.clone(),
        generation: setup.auth.runtime_generation.to_string(),
        session_id: setup.auth.session_id,
        workload_identity: ResolvedWorkloadIdentity::new(
            1000,
            1001,
            vec![],
            "test".into(),
            "test-resource".into(),
        )
        .unwrap(),
        transport: SandboxTransport::Unix {
            socket_path: "/unused-test-runtime".into(),
        },
        tls: SandboxTlsClientConfig {
            server_name: "unused-test-runtime".into(),
            trust_anchor_pem: String::new(),
        },
        host_gateway_ip: None,
        resource_claims: BTreeMap::new(),
        outer_fence: OuterFenceGuarantees::from_enforcement_evidence(
            "generation-1",
            [],
            b"test-evidence",
        )
        .unwrap(),
    };
    for is_vm in [false, true] {
        if is_vm {
            descriptor
                .resource_claims
                .insert("vm.generation".into(), "generation-1".into());
        }
        let selected = SelectedBackend::select(
            &OpenShellBackendSetup,
            descriptor.backend_descriptor().unwrap(),
            Some(openshell_sandbox_backend::BACKEND_NAME),
            Some(&setup.sandbox_id),
            &setup.auth,
        )
        .unwrap();
        let projected = selected.vm_policy_identity();
        assert_eq!(projected.is_some(), is_vm);
        if let Some(projected) = projected {
            assert_eq!((projected.uid, projected.gid), (1000, 1001));
            for (user, group, accepted) in [
                ("1000", "1001", true),
                ("1001", "sandbox", false),
                ("sandbox", "1000", false),
            ] {
                let policy = openshell_core::proto::SandboxPolicy {
                    process: Some(openshell_core::proto::ProcessPolicy {
                        run_as_user: user.into(),
                        run_as_group: group.into(),
                    }),
                    ..Default::default()
                };
                assert_eq!(
                    projected.validate(&policy).is_ok(),
                    accepted,
                    "{user}:{group}"
                );
            }
        }
    }
}

/// Auth slots and shutdown signals are process-wide. Run the real startup in a
/// child so parallel tests cannot replace credentials or consume its SIGTERM.
#[cfg(unix)]
#[tokio::test]
async fn shared_startup_uses_selected_backend_through_readiness_and_shutdown() {
    use std::time::Duration;

    const CHILD_ROOT: &str = "OPENSHELL_TEST_SELECTED_BACKEND_ROOT";
    const TEST: &str =
        "backend_setup::tests::shared_startup_uses_selected_backend_through_readiness_and_shutdown";
    let Ok(root) = std::env::var(CHILD_ROOT) else {
        // Keep Unix socket paths short, including on macOS. The parent owns
        // every fixture file so timeout or child failure still removes them.
        let root = tempfile::Builder::new()
            .prefix("selected-backend-")
            .tempdir_in("/tmp")
            .unwrap();
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap());
        child.args(["--exact", TEST, "--nocapture", "--test-threads=1"]);
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("OPENSHELL_") {
                child.env_remove(name);
            }
        }
        child
            .env(CHILD_ROOT, root.path())
            .env(
                openshell_core::sandbox_env::PROXY_TLS_DIR,
                root.path().join("tls"),
            )
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(30), child.output())
            .await
            .expect("shared startup child exceeded its deadline")
            .expect("run isolated shared startup test");
        assert!(
            output.status.success(),
            "shared startup child failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    };

    // Match the binary's process setup before exercising the shared library.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let root = PathBuf::from(root);
    let rules = root.join("policy.rego");
    let data = root.join("policy.yaml");
    let readiness = root.join("ready.sock");
    let marker = root.join("main-exit");
    std::fs::write(
        &rules,
        include_str!("../../../openshell-supervisor-network/data/sandbox-policy.rego"),
    )
    .unwrap();
    std::fs::write(&data, "network_policies: {}\n").unwrap();
    let reservation = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let health_port = reservation.local_addr().unwrap().port();
    drop(reservation);

    let setup = TestSetup::new();
    setup
        .observed
        .require_networking
        .store(true, Ordering::SeqCst);
    let startup = || {
        Box::pin(crate::run_sandbox_with_backend(
            &setup,
            crate::SandboxRunConfig {
                command: vec!["test-agent".into(), "test-argument".into()],
                workdir: Some("/test-workspace".into()),
                timeout_secs: 15,
                interactive: false,
                await_main_process_attachment: false,
                sandbox_id: Some(setup.sandbox_id.clone()),
                sandbox: None,
                openshell_endpoint: None,
                policy_rules: Some(rules.to_string_lossy().into_owned()),
                policy_data: Some(data.to_string_lossy().into_owned()),
                ssh_socket_path: None,
                health_socket_path: Some(readiness.clone()),
                health_port: Some(health_port),
                ocsf_enabled: Arc::new(AtomicBool::new(false)),
                ocsf_schema_version: Arc::new(Mutex::new(String::new())),
                upstream_proxy_args: UpstreamProxyArgs::default(),
                backend_descriptor: TestSetup::descriptor(),
                auth_bundle: setup.auth.clone(),
                admitted_isolation_backend: Some(TEST_BACKEND.into()),
                main_exit_marker: Some(marker.clone()),
                otlp_endpoint: None,
            },
        ))
    };

    setup
        .observed
        .discovery_unavailable
        .store(true, Ordering::SeqCst);
    let error = tokio::time::timeout(Duration::from_secs(5), startup())
        .await
        .expect("discovery failure must end startup")
        .expect_err("discovery failure must reject startup");
    assert!(error.to_string().contains("discovery unavailable"));
    assert_eq!(setup.observed.events(), ["decode", "discover"]);
    assert_eq!(setup.observed.starts.load(Ordering::SeqCst), 0);
    assert!(!readiness.exists());
    assert!(!marker.exists());
    assert!(
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, health_port))
            .await
            .is_err()
    );
    setup
        .observed
        .discovery_unavailable
        .store(false, Ordering::SeqCst);
    setup
        .observed
        .deny_confirmation
        .store(true, Ordering::SeqCst);
    assert!(startup().await.is_err());
    assert_eq!(
        setup.observed.events(),
        [
            "decode", "discover", "decode", "discover", "build", "attach", "confirm"
        ]
    );
    assert_eq!(setup.observed.starts.load(Ordering::SeqCst), 0);
    assert_eq!(setup.observed.releases.load(Ordering::SeqCst), 1);
    assert!(!setup.observed.active.load(Ordering::SeqCst));
    assert!(setup.observed.services.lock().unwrap().upgrade().is_none());
    assert!(!readiness.exists());
    assert!(!marker.exists());
    assert!(
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, health_port))
            .await
            .is_err()
    );

    setup
        .observed
        .deny_confirmation
        .store(false, Ordering::SeqCst);
    let observe_and_shutdown = async {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if marker.exists()
                    && tokio::net::UnixStream::connect(&readiness).await.is_ok()
                    && tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, health_port))
                        .await
                        .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("selected backend did not reach process completion and readiness");
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "exit_code=0\n");
        assert_eq!(setup.observed.starts.load(Ordering::SeqCst), 1);
        assert!(setup.observed.active.load(Ordering::SeqCst));
        // Exercise the production shutdown future while it retains access
        // after main-process exit; only this isolated child receives the signal.
        nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGTERM)
            .unwrap();
    };
    let (result, ()) = tokio::join!(startup(), observe_and_shutdown);
    assert_eq!(result.unwrap(), 0);
    assert_eq!(
        setup.observed.events(),
        [
            "decode", "discover", "decode", "discover", "build", "attach", "confirm", "decode",
            "discover", "build", "attach", "confirm", "start"
        ]
    );
    assert_eq!(setup.observed.releases.load(Ordering::SeqCst), 2);
    assert!(!setup.observed.active.load(Ordering::SeqCst));
    assert!(setup.observed.services.lock().unwrap().upgrade().is_none());
    assert!(!readiness.exists());
    // Listener tasks are aborted on drop; let the runtime reap their sockets.
    tokio::task::yield_now().await;
    assert!(
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, health_port))
            .await
            .is_err()
    );
}
