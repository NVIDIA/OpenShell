// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Conformance harness for the runtime-selectable contract.
//!
//! Two materially different mock factories (`Primary`, `Secondary`) with
//! distinct concrete state structs (each generic over a marker, so each kind
//! monomorphizes to its own types) prove the registry holds heterogeneous
//! factories behind `dyn` with no enum over concrete state, and that one driver
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
        Ok(self.status)
    }
    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        self.signals.lock().unwrap().push(signal);
        Ok(())
    }
    async fn terminate(&self) -> Result<(), BackendError> {
        self.alive.store(false, Ordering::SeqCst);
        Ok(())
    }
    fn diagnostic_pid(&self) -> Option<u32> {
        Some(4242)
    }
}

/// Mediation ingress: hands the mediation service a connection carrying its
/// per-connection identity-resolution result.
struct MockIngress<K>(PhantomData<K>);

#[async_trait]
impl<K: MockKind> MediationIngress for MockIngress<K> {
    async fn accept(&self) -> Result<MediatedConnection, BackendError> {
        let (near, _far) = tokio::io::duplex(64);
        Ok(MediatedConnection {
            stream: Box::new(near),
            binary_identity: Ok(BinaryIdentity {
                binary_path: PathBuf::from("/usr/bin/agent"),
                binary_sha256: K::HAS_DIGEST.then(|| "deadbeef".to_string()),
                ancestors: vec![],
                cmdline_paths: vec![],
            }),
        })
    }
}

/// An ingress whose backend cannot attribute the connection: the connection is
/// still delivered, carrying `Err`, so the mediation service denies and audits
/// it. It never authorizes anything.
struct UnattributedIngress;

#[async_trait]
impl MediationIngress for UnattributedIngress {
    async fn accept(&self) -> Result<MediatedConnection, BackendError> {
        let (near, _far) = tokio::io::duplex(64);
        Ok(MediatedConnection {
            stream: Box::new(near),
            binary_identity: Err(ResolveError::Failed("hash unavailable".to_string())),
        })
    }
}

struct MockExec;

#[async_trait]
impl BoundaryExec for MockExec {
    async fn exec(&self, _spec: ExecSpec) -> Result<ExecSession, BackendError> {
        let (_near, far) = tokio::io::duplex(64);
        let (out_r, _out_w) = tokio::io::duplex(64);
        let (err_r, _err_w) = tokio::io::duplex(64);
        Ok(ExecSession {
            process: MockProcess::new(),
            stdin: Some(Box::new(far)),
            stdout: Box::new(out_r),
            stderr: Some(Box::new(err_r)),
            terminal: None,
        })
    }
}

struct MockPortForward;

#[async_trait]
impl BoundaryPortForward for MockPortForward {
    async fn connect(&self, _target: LoopbackTarget) -> Result<BoundaryConn, BackendError> {
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
    ingress: Arc<MockIngress<K>>,
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
    fn mediation_ingress(&self) -> Arc<dyn MediationIngress> {
        self.ingress.clone()
    }
    async fn confirm(self: Box<Self>) -> Result<Box<dyn ReadyBoundary>, BackendError> {
        Ok(Box::new(MockReady::<K> { _k: PhantomData }))
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

/// One factory per boundary resource: `attach` is atomic and never binds a
/// resource that is already bound to an active boundary, so a second attach
/// against the same mock resource is `Denied`.
struct MockFactory<K> {
    attached: AtomicBool,
    _k: PhantomData<K>,
}

impl<K> MockFactory<K> {
    fn new() -> Self {
        Self {
            attached: AtomicBool::new(false),
            _k: PhantomData,
        }
    }
}

#[async_trait]
impl<K: MockKind> IsolationBackendFactory for MockFactory<K> {
    fn backend_id(&self) -> &'static str {
        K::BACKEND_ID
    }
    fn contract_version(&self) -> u32 {
        CONTRACT_VERSION
    }
    async fn attach(
        &self,
        descriptor: VerifiedTopologyDescriptor,
        sandbox: SandboxContext,
    ) -> Result<Box<dyn BoundBoundary>, BackendError> {
        assert_eq!(descriptor.backend_id(), K::BACKEND_ID);
        assert!(!sandbox.sandbox_id.is_empty());
        if self.attached.swap(true, Ordering::SeqCst) {
            return Err(BackendError::Denied(
                "resource is already bound to an active boundary".to_string(),
            ));
        }
        Ok(Box::new(MockBound::<K> {
            ingress: Arc::new(MockIngress(PhantomData)),
        }))
    }
}

/// A factory that speaks the wrong contract version; registration must reject it.
struct WrongVersionFactory;

#[async_trait]
impl IsolationBackendFactory for WrongVersionFactory {
    fn backend_id(&self) -> &'static str {
        "mock-wrong-version"
    }
    fn contract_version(&self) -> u32 {
        CONTRACT_VERSION + 1
    }
    async fn attach(
        &self,
        _descriptor: VerifiedTopologyDescriptor,
        _sandbox: SandboxContext,
    ) -> Result<Box<dyn BoundBoundary>, BackendError> {
        unreachable!("must never be resolved")
    }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn registry() -> BackendRegistry {
    let mut reg = BackendRegistry::new();
    reg.register(Arc::new(MockFactory::<Primary>::new()))
        .expect("register primary");
    reg.register(Arc::new(MockFactory::<Secondary>::new()))
        .expect("register secondary");
    reg
}

fn descriptor(backend_id: &str) -> TopologyDescriptor {
    TopologyDescriptor {
        contract_version: CONTRACT_VERSION,
        backend_id: backend_id.to_string(),
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
    }
}

/// The backend-independent supervisor sequence. Identical for every backend:
/// this is the proof that adding a backend needs no supervisor lifecycle change.
async fn drive(
    reg: &BackendRegistry,
    descriptor: TopologyDescriptor,
    admitted: &str,
) -> Result<Box<dyn RunningBoundary>, BackendError> {
    let (factory, verified) = reg.resolve(descriptor, admitted)?;
    let bound = factory.attach(verified, sandbox_ctx()).await?;
    // The mediation ingress is retained before consuming `Bound` and stays
    // usable across the confirm/start transitions.
    let _ingress = bound.mediation_ingress();
    let ready = bound.confirm().await?;
    ready.start_agent().await
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
    assert_eq!(f.backend_id(), "mock-secondary");
}

#[test]
fn registry_rejects_duplicate_registration() {
    let mut reg = BackendRegistry::new();
    reg.register(Arc::new(MockFactory::<Primary>::new()))
        .expect("first");
    let err = reg
        .register(Arc::new(MockFactory::<Primary>::new()))
        .expect_err("duplicate must fail");
    assert!(matches!(err, BackendError::Descriptor(_)));
}

#[test]
fn registry_rejects_wrong_factory_version() {
    let mut reg = BackendRegistry::new();
    let err = reg
        .register(Arc::new(WrongVersionFactory))
        .expect_err("wrong version must fail");
    assert_eq!(err.kind(), BackendErrorKind::Invalid);
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

#[test]
fn registry_rejects_unsupported_version() {
    let reg = registry();
    let mut d = descriptor("mock-primary");
    d.contract_version = CONTRACT_VERSION + 1;
    let err = reg
        .resolve(d, "mock-primary")
        .map(|_| ())
        .expect_err("bad version must fail");
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
    let (factory, verified) = reg
        .resolve(descriptor("mock-primary"), "mock-primary")
        .expect("resolve");
    let bound = factory
        .attach(verified, sandbox_ctx())
        .await
        .expect("attach");

    // Retain the ingress at Bound, then consume the bound state with confirm.
    // The retained Arc must remain usable afterward.
    let ingress = bound.mediation_ingress();
    let ready = bound.confirm().await.expect("confirm");
    let _running = ready.start_agent().await.expect("start");

    let conn = ingress.accept().await.expect("accept after consumption");
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
    agent.signal(BoundarySignal::Term).await.expect("signal");
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
async fn port_forward_rejects_non_loopback() {
    let target = LoopbackTarget::new("8.8.8.8".parse().unwrap(), 53);
    assert!(target.is_err());
    let loopback = LoopbackTarget::new("127.0.0.1".parse().unwrap(), 8080).expect("loopback ok");
    assert_eq!(loopback.port(), 8080);
}

// ---------------------------------------------------------------------------
// Mediation and binary identity.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mediated_connection_carries_identity_for_that_connection() {
    let reg = registry();
    let (factory, verified) = reg
        .resolve(descriptor("mock-primary"), "mock-primary")
        .expect("resolve");
    let bound = factory
        .attach(verified, sandbox_ctx())
        .await
        .expect("attach");
    let conn = bound.mediation_ingress().accept().await.expect("accept");
    let identity = conn.binary_identity.expect("identity resolves");
    assert_eq!(identity.binary_path, PathBuf::from("/usr/bin/agent"));
    // A missing digest is `None`, never an empty value.
    assert_eq!(identity.binary_sha256.as_deref(), Some("deadbeef"));
}

#[tokio::test]
async fn missing_digest_is_none_never_empty() {
    // The secondary backend resolves path-only identity: the digest is `None`,
    // so policy that requires a digest cannot authorize the connection.
    let ingress = MockIngress::<Secondary>(PhantomData);
    let conn = ingress.accept().await.expect("accept");
    let identity = conn.binary_identity.expect("identity resolves");
    assert!(identity.binary_sha256.is_none());
}

#[tokio::test]
async fn unresolved_identity_travels_with_the_connection_and_fails_closed() {
    // Attribution failure does not tear down the ingress: the connection is
    // delivered carrying `Err`, and the mediation service denies it.
    let ingress = UnattributedIngress;
    let conn = ingress.accept().await.expect("accept");
    assert!(conn.binary_identity.is_err());
}

// ---------------------------------------------------------------------------
// Descriptor environment transport.
// ---------------------------------------------------------------------------

#[test]
fn descriptor_env_value_round_trips() {
    let original = TopologyDescriptor {
        contract_version: CONTRACT_VERSION,
        backend_id: "mock-primary".to_string(),
        payload: vec![0x00, 0x7f, 0xff],
    };
    let parsed = TopologyDescriptor::from_env_value(&original.to_env_value()).expect("parse");
    assert_eq!(parsed.contract_version, original.contract_version);
    assert_eq!(parsed.backend_id, original.backend_id);
    assert_eq!(parsed.payload, original.payload);
}

#[test]
fn in_pod_descriptor_env_value_round_trips_with_empty_payload() {
    let parsed = TopologyDescriptor::from_env_value(&TopologyDescriptor::in_pod().to_env_value())
        .expect("parse");
    assert_eq!(parsed.backend_id, IN_POD_BACKEND_ID);
    assert_eq!(parsed.contract_version, CONTRACT_VERSION);
    assert!(parsed.payload.is_empty());
}

#[test]
fn malformed_descriptor_env_values_fail_closed() {
    for bad in [
        "",
        "1",
        "1:in-pod",
        "x:in-pod:",
        "1::",
        "1:in-pod:zz",
        "1:in-pod:abc",
        "1:in-pod:aa:bb",
    ] {
        assert!(
            TopologyDescriptor::from_env_value(bad).is_err(),
            "{bad:?} must fail closed"
        );
    }
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

#[test]
fn error_kinds_map_and_only_unavailable_retries() {
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
    assert!(BackendError::Unavailable("x".into()).is_retryable());
    assert!(!BackendError::Confirm("x".into()).is_retryable());
}
