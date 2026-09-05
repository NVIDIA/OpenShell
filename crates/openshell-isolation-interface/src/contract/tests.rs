// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Conformance harness for the runtime-selectable contract.
//!
//! Two materially different mock backends (`Primary`, `Secondary`) with
//! distinct concrete state structs (each generic over a marker, so each kind
//! monomorphizes to its own types) prove the registry holds heterogeneous
//! backends behind `dyn` with no enum over concrete state, and that one driver
//! runs both unchanged.

use std::marker::PhantomData;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;

// ---------------------------------------------------------------------------
// Marker kinds: two materially different backends.
// ---------------------------------------------------------------------------

trait MockKind: Send + Sync + 'static {
    const BACKEND_ID: &'static str;
    /// Whether this backend can produce a binary digest (a heterogeneity axis:
    /// one backend resolves a full identity, the other resolves path-only).
    const HAS_DIGEST: bool;
}

struct Primary;
impl MockKind for Primary {
    const BACKEND_ID: &'static str = "mock-primary";
    const HAS_DIGEST: bool = true;
}

struct Secondary;
impl MockKind for Secondary {
    const BACKEND_ID: &'static str = "mock-secondary";
    const HAS_DIGEST: bool = false;
}

// ---------------------------------------------------------------------------
// Runtime interfaces (shared across kinds where behavior is identical).
// ---------------------------------------------------------------------------

struct MockProcess {
    status: BoundaryExitStatus,
    alive: AtomicBool,
    signals: Mutex<Vec<BoundarySignal>>,
}

impl MockProcess {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            status: BoundaryExitStatus::Exited(0),
            alive: AtomicBool::new(true),
            signals: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl BoundaryProcess for MockProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        // Stable across repeated calls.
        self.alive.store(false, Ordering::SeqCst);
        Ok(self.status)
    }
    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        if !self.alive.load(Ordering::SeqCst) {
            return Err(BackendError::Terminated("process has exited".to_string()));
        }
        self.signals.lock().unwrap().push(signal);
        Ok(())
    }
    async fn terminate(&self) -> Result<(), BackendError> {
        self.alive
            .swap(false, Ordering::SeqCst)
            .then_some(())
            .ok_or_else(|| BackendError::Terminated("process has exited".to_string()))
    }
}

/// Mediation source: hands the mediation service a connection carrying its
/// per-connection identity-resolution result.
struct MockSource<K>(PhantomData<K>);

#[async_trait]
impl<K: MockKind> NetworkMediationSource for MockSource<K> {
    async fn accept(&self) -> Result<PendingNetworkOpen, BackendError> {
        let (near, _far) = tokio::io::duplex(64);
        let (result, _result_rx) = oneshot::channel();
        Ok(PendingNetworkOpen {
            stream: Box::new(near),
            binary_identity: Ok(BinaryIdentity {
                binary_path: PathBuf::from("/usr/bin/agent"),
                binary_digest: K::HAS_DIGEST
                    .then(|| "00".repeat(32).parse().expect("valid digest")),
                ancestors: vec![],
                cmdline_paths: vec![],
            }),
            destination: "203.0.113.10:443".parse().unwrap(),
            socket: NetworkSocketMetadata {
                socket_cookie: 7,
                nonblocking: false,
                process_generation: 1,
            },
            policy_generation: 1,
            result,
        })
    }
}

/// An source whose backend cannot attribute the connection: the connection is
/// still delivered, carrying `Err`, so the mediation service denies and audits
/// it. It never authorizes anything.
struct UnattributedSource;

#[async_trait]
impl NetworkMediationSource for UnattributedSource {
    async fn accept(&self) -> Result<PendingNetworkOpen, BackendError> {
        let (near, _far) = tokio::io::duplex(64);
        let (result, _result_rx) = oneshot::channel();
        Ok(PendingNetworkOpen {
            stream: Box::new(near),
            binary_identity: Err(ResolveError::Failed("hash unavailable".to_string())),
            destination: "203.0.113.10:443".parse().unwrap(),
            socket: NetworkSocketMetadata {
                socket_cookie: 8,
                nonblocking: false,
                process_generation: 1,
            },
            policy_generation: 1,
            result,
        })
    }
}

struct MockExec;

struct MockTerminal {
    size: Mutex<Option<(u16, u16)>>,
}

#[async_trait]
impl BoundaryTerminal for MockTerminal {
    async fn resize(&self, cols: u16, rows: u16) -> Result<(), BackendError> {
        *self.size.lock().unwrap() = Some((cols, rows));
        Ok(())
    }
}

#[async_trait]
impl BoundaryExec for MockExec {
    async fn exec(&self, spec: ExecSpec) -> Result<ExecSession, BackendError> {
        let (_near, far) = tokio::io::duplex(64);
        let (out_r, _out_w) = tokio::io::duplex(64);
        let (err_r, _err_w) = tokio::io::duplex(64);
        let stdin: BoundaryInput = Box::new(far);
        let stderr: BoundaryOutput = Box::new(err_r);
        let terminal: Arc<dyn BoundaryTerminal> = Arc::new(MockTerminal {
            size: Mutex::new(None),
        });
        Ok(ExecSession {
            process: MockProcess::new(),
            stdin: (!spec.pty).then_some(stdin),
            stdout: Box::new(out_r),
            stderr: (!spec.pty).then_some(stderr),
            terminal: spec.pty.then_some(terminal),
        })
    }
}

struct MockPortForward;

#[async_trait]
impl BoundaryPortForward for MockPortForward {
    async fn connect(&self, _target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError> {
        let (near, far) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut far = far;
            let mut buf = [0u8; 4];
            if far.read_exact(&mut buf).await.is_ok() {
                let _ = far.write_all(&buf).await;
            }
        });
        Ok(Box::new(near))
    }
}

// ---------------------------------------------------------------------------
// Boxed lifecycle states (distinct concrete struct per kind).
// ---------------------------------------------------------------------------

struct MockBound<K> {
    source: Arc<MockSource<K>>,
}
struct MockReady<K> {
    _k: PhantomData<K>,
}
struct MockRunning<K> {
    process: Arc<MockProcess>,
    exec: Arc<MockExec>,
    port_forward: Arc<MockPortForward>,
    _k: PhantomData<K>,
}

#[async_trait]
impl<K: MockKind> BoundBoundary for MockBound<K> {
    fn network_mediation_source(&self) -> Arc<dyn NetworkMediationSource> {
        self.source.clone()
    }
    async fn confirm(self: Box<Self>) -> Result<ConfirmedBoundary, BackendError> {
        Ok(ConfirmedBoundary::new(
            Box::new(MockReady::<K> { _k: PhantomData }),
            confirmation_evidence(),
        ))
    }
}

#[async_trait]
impl<K: MockKind> ReadyBoundary for MockReady<K> {
    async fn start_agent(self: Box<Self>) -> Result<Box<dyn RunningBoundary>, BackendError> {
        Ok(Box::new(MockRunning::<K> {
            process: MockProcess::new(),
            exec: Arc::new(MockExec),
            port_forward: Arc::new(MockPortForward),
            _k: PhantomData,
        }))
    }
}

impl<K: MockKind> RunningBoundary for MockRunning<K> {
    fn agent(&self) -> Arc<dyn BoundaryProcess> {
        self.process.clone()
    }
    fn exec(&self) -> Arc<dyn BoundaryExec> {
        self.exec.clone()
    }
    fn port_forward(&self) -> Arc<dyn BoundaryPortForward> {
        self.port_forward.clone()
    }
}

/// One backend per boundary resource: `attach` is atomic and never binds a
/// resource that is already bound to an active boundary, so a second attach
/// against the same mock resource is `Denied`.
struct MockBackend<K> {
    attached: AtomicBool,
    _k: PhantomData<K>,
}

impl<K> MockBackend<K> {
    fn new() -> Self {
        Self {
            attached: AtomicBool::new(false),
            _k: PhantomData,
        }
    }
}

#[async_trait]
impl<K: MockKind> IsolationBackend for MockBackend<K> {
    fn backend_name(&self) -> &'static str {
        K::BACKEND_ID
    }
    async fn attach(
        &self,
        descriptor: VerifiedTopologyDescriptor,
        sandbox: SandboxContext,
    ) -> Result<Box<dyn BoundBoundary>, BackendError> {
        assert_eq!(descriptor.backend_name(), K::BACKEND_ID);
        assert!(!sandbox.sandbox_id.is_empty());
        if self.attached.swap(true, Ordering::SeqCst) {
            return Err(BackendError::Denied(
                "resource is already bound to an active boundary".to_string(),
            ));
        }
        Ok(Box::new(MockBound::<K> {
            source: Arc::new(MockSource(PhantomData)),
        }))
    }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn registry() -> BackendRegistry {
    let mut reg = BackendRegistry::new();
    reg.register(Arc::new(MockBackend::<Primary>::new()))
        .expect("register primary");
    reg.register(Arc::new(MockBackend::<Secondary>::new()))
        .expect("register secondary");
    reg
}

fn descriptor(backend_name: &str) -> TopologyDescriptor {
    TopologyDescriptor {
        backend_name: backend_name.to_string(),
        payload: vec![],
    }
}

fn sandbox_ctx() -> SandboxContext {
    SandboxContext {
        sandbox_id: "sb-1".to_string(),
        policy: SandboxPolicy {
            version: 1,
            filesystem: openshell_core::policy::FilesystemPolicy::default(),
            network: openshell_core::policy::NetworkPolicy::default(),
            landlock: openshell_core::policy::LandlockPolicy::default(),
            process: openshell_core::policy::ProcessPolicy::default(),
        },
        agent: AgentSpec {
            program: "/bin/true".to_string(),
            args: vec![],
            workdir: None,
            timeout_secs: 0,
            interactive: false,
        },
        identity: workload_identity(),
    }
}

fn workload_identity() -> ResolvedWorkloadIdentity {
    ResolvedWorkloadIdentity::new(
        1000,
        1000,
        vec![1000],
        "policy".to_string(),
        "sha256:test".to_string(),
    )
    .unwrap()
}

fn confirmation_evidence() -> SandboxConfirmEvidence {
    SandboxConfirmEvidence {
        generation: "generation-1".to_string(),
        identity: workload_identity(),
        capabilities: CapabilityEvidence {
            inheritable: 0,
            permitted: 0,
            effective: 0,
            bounding: 0,
            ambient: 0,
        },
        no_new_privileges: true,
        sandbox_dumpable: false,
        child_dumpable: true,
        core_limit_zero: true,
        native_architecture: std::env::consts::ARCH.to_string(),
        kernel_release: "test".to_string(),
        seccomp: SeccompEvidence {
            new_listener: true,
            notification_round_trip: true,
            id_validation: true,
            addfd_send: true,
            retained_socket_operation: true,
            proc_fd_identity: true,
            task_memory_read: true,
            task_memory_write: true,
            cancellation: true,
        },
        landlock_abi: 1,
        landlock_allow_deny: true,
        udp_dns_round_trip: true,
        tcp_dns_round_trip: true,
        tcp_allow_round_trip: true,
        tcp_deny_round_trip: true,
        authenticated_supervisor: true,
        session_epoch: "epoch-1".to_string(),
        driver_fence: DriverFenceEvidence::Vm {
            generation: "generation-1".to_string(),
            network_device_count: 0,
        },
        resource_claims: BTreeMap::new(),
    }
}

#[test]
fn driver_fence_evidence_is_backend_specific_and_fail_closed() {
    let docker = DriverFenceEvidence::Docker {
        container_id: "sha256:container".to_string(),
        network_mode: "none".to_string(),
        unexpected_networks: Vec::new(),
    };
    let kubernetes = DriverFenceEvidence::Kubernetes {
        network_policy_uid: "policy-uid".to_string(),
        network_policy_resource_version: "42".to_string(),
        ingress_isolated: true,
        egress_isolated: true,
        egress_rule_count: 0,
    };
    let vm = DriverFenceEvidence::Vm {
        generation: "generation-1".to_string(),
        network_device_count: 0,
    };

    assert!(docker.validate_for_backend("docker").is_ok());
    assert!(
        kubernetes
            .validate_for_backend("kubernetes-proxy-pod")
            .is_ok()
    );
    assert!(vm.validate_for_backend("vm").is_ok());
    assert!(docker.validate_for_backend("vm").is_err());

    let drifted = DriverFenceEvidence::Docker {
        container_id: "sha256:container".to_string(),
        network_mode: "bridge".to_string(),
        unexpected_networks: vec!["bridge".to_string()],
    };
    assert!(drifted.validate_for_backend("docker").is_err());
}

/// The backend-independent supervisor sequence. Identical for every backend:
/// this is the proof that adding a backend needs no supervisor lifecycle change.
async fn drive(
    reg: &BackendRegistry,
    descriptor: TopologyDescriptor,
    admitted: &str,
) -> Result<Box<dyn RunningBoundary>, BackendError> {
    let (backend, verified) = reg.resolve(descriptor, admitted)?;
    let bound = backend.attach(verified, sandbox_ctx()).await?;
    // The mediation source is retained before consuming `Bound` and stays
    // usable across the confirm/start transitions.
    let _ingress = bound.network_mediation_source();
    assert_eq!(bound.host_gateway_ip(), None);
    let confirmed = bound.confirm().await?;
    confirmed.evidence.validate(&sandbox_ctx().identity)?;
    confirmed.boundary.start_agent().await
}

// ---------------------------------------------------------------------------
// Registry and descriptor.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registry_selects_correct_backend() {
    let reg = registry();
    let (f, _v) = reg
        .resolve(descriptor("mock-secondary"), "mock-secondary")
        .expect("resolve");
    assert_eq!(f.backend_name(), "mock-secondary");
}

#[test]
fn registry_rejects_duplicate_registration() {
    let mut reg = BackendRegistry::new();
    reg.register(Arc::new(MockBackend::<Primary>::new()))
        .expect("first");
    let err = reg
        .register(Arc::new(MockBackend::<Primary>::new()))
        .expect_err("duplicate must fail");
    assert!(matches!(err, BackendError::Descriptor(_)));
}

#[test]
fn registry_rejects_unknown_backend() {
    let reg = registry();
    let err = reg
        .resolve(descriptor("nope"), "nope")
        .map(|_| ())
        .expect_err("unknown must fail");
    assert!(matches!(err, BackendError::NotRegistered(_)));
}

#[test]
fn registry_rejects_descriptor_admission_mismatch_without_fallback() {
    let reg = registry();
    // Descriptor names primary, admission says secondary: must fail, and must
    // not silently fall back to either backend.
    let err = reg
        .resolve(descriptor("mock-primary"), "mock-secondary")
        .map(|_| ())
        .expect_err("mismatch must fail");
    assert!(matches!(err, BackendError::Descriptor(_)));
}

// ---------------------------------------------------------------------------
// Lifecycle: one driver, two heterogeneous backends, no consumer change.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn one_driver_runs_both_backends() {
    let reg = registry();
    // The exact same driver code runs a backend with distinct concrete state
    // structs; the registry holds them behind `dyn`, no enum.
    let primary = drive(&reg, descriptor("mock-primary"), "mock-primary")
        .await
        .expect("primary lifecycle");
    let secondary = drive(&reg, descriptor("mock-secondary"), "mock-secondary")
        .await
        .expect("secondary lifecycle");

    // Both expose a usable agent process handle past start_agent.
    assert_eq!(
        primary.agent().wait().await.expect("wait"),
        BoundaryExitStatus::Exited(0)
    );
    assert_eq!(
        secondary.agent().wait().await.expect("wait"),
        BoundaryExitStatus::Exited(0)
    );
}

#[tokio::test]
async fn one_boundary_termination_does_not_change_another_boundary() {
    let reg = registry();
    let primary = drive(&reg, descriptor("mock-primary"), "mock-primary")
        .await
        .expect("primary lifecycle");
    let secondary = drive(&reg, descriptor("mock-secondary"), "mock-secondary")
        .await
        .expect("secondary lifecycle");

    primary
        .agent()
        .terminate()
        .await
        .expect("terminate primary");
    secondary
        .agent()
        .signal(BoundarySignal::Term)
        .await
        .expect("secondary remains active");
}

#[tokio::test]
async fn attach_never_binds_an_already_bound_resource() {
    let reg = registry();
    // First attach binds the mock resource.
    drive(&reg, descriptor("mock-primary"), "mock-primary")
        .await
        .expect("first lifecycle");
    // A second attach against the same active boundary must be denied, not
    // silently create a second binding.
    let err = drive(&reg, descriptor("mock-primary"), "mock-primary")
        .await
        .map(|_| ())
        .expect_err("second attach must fail");
    assert_eq!(err.kind(), BackendErrorKind::Denied);
}

#[tokio::test]
async fn runtime_interfaces_survive_lifecycle_consumption() {
    let reg = registry();
    let (backend, verified) = reg
        .resolve(descriptor("mock-primary"), "mock-primary")
        .expect("resolve");
    let bound = backend
        .attach(verified, sandbox_ctx())
        .await
        .expect("attach");

    // Retain the source at Bound, then consume the bound state with confirm.
    // The retained Arc must remain usable afterward.
    let source = bound.network_mediation_source();
    let confirmed = bound.confirm().await.expect("confirm");
    let _running = confirmed.boundary.start_agent().await.expect("start");

    let conn = source.accept().await.expect("accept after consumption");
    let identity = conn.binary_identity.expect("identity resolves");
    assert_eq!(identity.binary_path, PathBuf::from("/usr/bin/agent"));
}

// ---------------------------------------------------------------------------
// Process and I/O.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agent_process_survives_and_wait_is_stable() {
    let reg = registry();
    let running = drive(&reg, descriptor("mock-primary"), "mock-primary")
        .await
        .expect("lifecycle");
    let agent = running.agent();
    // Survives start_agent returning; wait is stable across repeated calls.
    assert_eq!(
        agent.wait().await.expect("wait 1"),
        BoundaryExitStatus::Exited(0)
    );
    assert_eq!(
        agent.wait().await.expect("wait 2"),
        BoundaryExitStatus::Exited(0)
    );
    assert!(matches!(
        agent.signal(BoundarySignal::Term).await,
        Err(BackendError::Terminated(_))
    ));
}

#[tokio::test]
async fn every_signal_reaches_the_backend_unchanged() {
    let process = MockProcess::new();
    for signal in [
        BoundarySignal::Term,
        BoundarySignal::Kill,
        BoundarySignal::Int,
        BoundarySignal::Hup,
    ] {
        process.signal(signal).await.expect("signal");
    }
    assert_eq!(
        *process.signals.lock().unwrap(),
        vec![
            BoundarySignal::Term,
            BoundarySignal::Kill,
            BoundarySignal::Int,
            BoundarySignal::Hup,
        ]
    );
}

#[tokio::test]
async fn normal_and_signaled_exit_are_distinct_and_stable() {
    let signaled = MockProcess {
        status: BoundaryExitStatus::Signaled(9),
        alive: AtomicBool::new(false),
        signals: Mutex::new(Vec::new()),
    };
    assert_eq!(
        signaled.wait().await.expect("first wait"),
        BoundaryExitStatus::Signaled(9)
    );
    assert_eq!(
        signaled.wait().await.expect("second wait"),
        BoundaryExitStatus::Signaled(9)
    );
    assert_ne!(
        signaled.wait().await.expect("third wait"),
        BoundaryExitStatus::Exited(137)
    );
}

#[tokio::test]
async fn exec_session_owns_its_process_and_streams() {
    let reg = registry();
    let running = drive(&reg, descriptor("mock-primary"), "mock-primary")
        .await
        .expect("lifecycle");
    let session = running
        .exec()
        .exec(ExecSpec {
            program: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), "true".to_string()],
            env: vec![],
            workdir: None,
            pty: false,
        })
        .await
        .expect("exec");
    // The exec'd process survives `exec` returning, and stdout/stderr are distinct.
    assert!(session.stderr.is_some());
    assert!(session.stdin.is_some());
    assert_eq!(
        session.process.wait().await.expect("exec wait"),
        BoundaryExitStatus::Exited(0)
    );
}

#[tokio::test]
async fn pty_exec_merges_output_and_supports_resize() {
    let session = MockExec
        .exec(ExecSpec {
            program: "/bin/sh".to_string(),
            args: vec![],
            env: vec![],
            workdir: None,
            pty: true,
        })
        .await
        .expect("pty exec");
    assert!(session.stdin.is_none());
    assert!(session.stderr.is_none());
    session
        .terminal
        .expect("terminal")
        .resize(120, 40)
        .await
        .expect("resize");
}

#[tokio::test]
async fn port_forward_rejects_non_loopback() {
    let target = LoopbackTarget::new("8.8.8.8".parse().unwrap(), 53);
    assert!(target.is_err());
    let loopback = LoopbackTarget::new("127.0.0.1".parse().unwrap(), 8080).expect("loopback ok");
    assert_eq!(loopback.port(), 8080);
}

#[tokio::test]
async fn validated_port_forward_stream_remains_usable() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let target = LoopbackTarget::new("127.0.0.1".parse().unwrap(), 8080).unwrap();
    let mut stream = MockPortForward.connect(target).await.expect("connect");
    stream.write_all(b"ping").await.expect("write");
    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await.expect("read");
    assert_eq!(&response, b"ping");
}

// ---------------------------------------------------------------------------
// Mediation and binary identity.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pending_network_open_carries_socket_bound_identity() {
    let reg = registry();
    let (backend, verified) = reg
        .resolve(descriptor("mock-primary"), "mock-primary")
        .expect("resolve");
    let bound = backend
        .attach(verified, sandbox_ctx())
        .await
        .expect("attach");
    let conn = bound
        .network_mediation_source()
        .accept()
        .await
        .expect("accept");
    let identity = conn.binary_identity.expect("identity resolves");
    assert_eq!(identity.binary_path, PathBuf::from("/usr/bin/agent"));
    // A missing digest is `None`, never an empty value.
    assert_eq!(
        identity.binary_digest.expect("digest").to_string(),
        "00".repeat(32)
    );
    assert_eq!(conn.destination, "203.0.113.10:443".parse().unwrap());
    assert_eq!(conn.socket.socket_cookie, 7);
}

#[tokio::test]
async fn missing_digest_is_none_never_empty() {
    // The secondary backend resolves path-only identity: the digest is `None`,
    // so policy that requires a digest cannot authorize the connection.
    let source = MockSource::<Secondary>(PhantomData);
    let conn = source.accept().await.expect("accept");
    let identity = conn.binary_identity.expect("identity resolves");
    assert!(identity.binary_digest.is_none());
}

#[test]
fn sha256_digest_rejects_signed_hex_chunks() {
    let signed = format!("+0{}", "00".repeat(31));
    assert!(signed.parse::<Sha256Digest>().is_err());
    assert!("00".repeat(32).parse::<Sha256Digest>().is_ok());
}

#[tokio::test]
async fn unresolved_identity_travels_with_the_pending_open_and_fails_closed() {
    // Attribution failure does not tear down the source: the connection is
    // delivered carrying `Err`, and the mediation service denies it.
    let source = UnattributedSource;
    let conn = source.accept().await.expect("accept");
    assert!(conn.binary_identity.is_err());
}

#[test]
fn workload_identity_rejects_root_and_normalizes_groups() {
    assert!(
        ResolvedWorkloadIdentity::new(0, 1000, vec![], "policy".into(), "digest".into()).is_err()
    );
    let identity = ResolvedWorkloadIdentity::new(
        1000,
        1001,
        vec![1003, 1001, 1002, 1003],
        "policy".into(),
        "digest".into(),
    )
    .unwrap();
    assert_eq!(identity.supplementary_gids, vec![1002, 1003]);
}

#[test]
fn confirmation_evidence_rejects_identity_or_posture_drift() {
    let expected = workload_identity();
    let evidence = confirmation_evidence();
    evidence.validate(&expected).unwrap();

    let mut drifted = confirmation_evidence();
    drifted.capabilities.effective = 1;
    assert!(drifted.validate(&expected).is_err());

    let different = ResolvedWorkloadIdentity::new(
        1002,
        1000,
        vec![1000],
        "policy".into(),
        "sha256:test".into(),
    )
    .unwrap();
    assert!(evidence.validate(&different).is_err());
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

#[test]
fn error_kinds_map_to_supervisor_status_classes() {
    assert_eq!(
        BackendError::Descriptor("x".into()).kind(),
        BackendErrorKind::Invalid
    );
    assert_eq!(
        BackendError::NotRegistered("x".into()).kind(),
        BackendErrorKind::Invalid
    );
    assert_eq!(
        BackendError::Denied("x".into()).kind(),
        BackendErrorKind::Denied
    );
    assert_eq!(
        BackendError::Unavailable("x".into()).kind(),
        BackendErrorKind::Unavailable
    );
    assert_eq!(
        BackendError::Unsupported("x".into()).kind(),
        BackendErrorKind::Unsupported
    );
    assert_eq!(
        BackendError::Attach("x".into()).kind(),
        BackendErrorKind::Failed
    );
    assert_eq!(
        BackendError::Confirm("x".into()).kind(),
        BackendErrorKind::Failed
    );
    assert_eq!(
        BackendError::Terminated("x".into()).kind(),
        BackendErrorKind::Terminated
    );
}
