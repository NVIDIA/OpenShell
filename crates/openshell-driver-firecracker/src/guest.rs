// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Private guest mode for the Firecracker driver.
//!
//! This is transport and lifecycle glue, not another supervisor model. When
//! the host authorizes `start_agent`, it invokes the existing
//! `openshell-supervisor-process` implementation inside the VM.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use openshell_core::proposals::AgentProposals;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_supervisor_process::boundary_io::BoundaryRuntimeState;
use openshell_supervisor_process::process::{
    ProcessEnforcementMode, ProcessStatus, ResolvedProcessIdentity,
};
use openshell_supervisor_process::run::{AgentSignaler, spawn_workload};
use serde::{Deserialize, Serialize};

use crate::protocol::{
    AgentSpecWire, ExitStatusWire, Request, RequestEnvelope, Response, ResponseEnvelope,
    SandboxPolicyWire, SignalWire, read_frame, write_frame,
};

pub const DEFAULT_GUEST_CONFIG_PATH: &str = "/etc/openshell/firecracker.json";
const DEFAULT_CONTROL_PORT: u32 = 5500;
const DEFAULT_AGENT_UID: u32 = 10_001;
const DEFAULT_AGENT_GID: u32 = 10_001;
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Driver-private configuration injected into the guest image at provision time.
#[derive(Clone, Serialize, Deserialize)]
pub struct GuestConfig {
    pub boundary_id: String,
    pub bootstrap_token: String,
    #[serde(default = "default_control_port")]
    pub control_port: u32,
    #[serde(default = "default_agent_uid")]
    pub agent_uid: u32,
    #[serde(default = "default_agent_gid")]
    pub agent_gid: u32,
}

impl std::fmt::Debug for GuestConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuestConfig")
            .field("boundary_id", &self.boundary_id)
            .field("bootstrap_token", &"<redacted>")
            .field("control_port", &self.control_port)
            .field("agent_uid", &self.agent_uid)
            .field("agent_gid", &self.agent_gid)
            .finish()
    }
}

const fn default_control_port() -> u32 {
    DEFAULT_CONTROL_PORT
}

const fn default_agent_uid() -> u32 {
    DEFAULT_AGENT_UID
}

const fn default_agent_gid() -> u32 {
    DEFAULT_AGENT_GID
}

pub fn run_guest(config_path: &Path) -> Result<(), String> {
    if std::process::id() == 1 {
        prepare_pid1_filesystems()?;
    }
    let bytes = std::fs::read(config_path)
        .map_err(|error| format!("read guest config {}: {error}", config_path.display()))?;
    let config: GuestConfig = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode guest config {}: {error}", config_path.display()))?;
    validate_config(&config)?;
    let process_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("create guest process runtime: {error}"))?;
    let runtime = Arc::new(GuestRuntime::new(
        config.clone(),
        process_runtime.handle().clone(),
    ));
    serve(config.control_port, runtime)
}

fn validate_config(config: &GuestConfig) -> Result<(), String> {
    if config.boundary_id.is_empty() {
        return Err("guest boundary ID must not be empty".to_string());
    }
    if config.bootstrap_token.len() < 32 {
        return Err("guest bootstrap token must contain at least 32 bytes".to_string());
    }
    if config.control_port == 0 {
        return Err("guest control port must be nonzero".to_string());
    }
    if config.agent_uid == 0 || config.agent_gid == 0 {
        return Err("guest agent UID and GID must be nonzero".to_string());
    }
    Ok(())
}

fn prepare_pid1_filesystems() -> Result<(), String> {
    for path in ["/proc", "/sys", "/dev", "/run", "/tmp", "/sandbox"] {
        std::fs::create_dir_all(path).map_err(|error| format!("create {path}: {error}"))?;
    }
    mount_if_needed("proc", "/proc", "proc")?;
    mount_if_needed("sysfs", "/sys", "sysfs")?;
    mount_if_needed("devtmpfs", "/dev", "devtmpfs")?;
    std::fs::create_dir_all("/dev/pts").map_err(|error| format!("create /dev/pts: {error}"))?;
    mount_if_needed("devpts", "/dev/pts", "devpts")?;
    Ok(())
}

fn mount_if_needed(source: &str, target: &str, file_system: &str) -> Result<(), String> {
    let source = CString::new(source).map_err(|error| error.to_string())?;
    let target_c = CString::new(target).map_err(|error| error.to_string())?;
    let file_system = CString::new(file_system).map_err(|error| error.to_string())?;
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            file_system.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EBUSY) {
        Ok(())
    } else {
        Err(format!("mount {file_system:?} on {target}: {error}"))
    }
}

fn serve(port: u32, runtime: Arc<GuestRuntime>) -> Result<(), String> {
    let listener = VsockListener::bind(port)
        .map_err(|error| format!("bind guest control vsock port {port}: {error}"))?;
    eprintln!("Firecracker process supervisor leaf listening on vsock port {port}");
    loop {
        match listener.accept() {
            Ok(stream) => {
                let runtime = runtime.clone();
                std::thread::spawn(move || {
                    if let Err(error) = serve_one(stream, &runtime) {
                        eprintln!("Firecracker guest control request failed: {error}");
                    }
                });
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("accept guest control connection: {error}")),
        }
    }
}

fn serve_one(mut stream: VsockStream, runtime: &GuestRuntime) -> Result<(), String> {
    stream
        .set_timeout(CONTROL_IO_TIMEOUT)
        .map_err(|error| format!("set control timeout: {error}"))?;
    let request: RequestEnvelope =
        read_frame(&mut stream).map_err(|error| format!("read control frame: {error}"))?;
    let response = ResponseEnvelope {
        request_id: request.request_id,
        response: runtime.dispatch(request),
    };
    write_frame(&mut stream, &response).map_err(|error| format!("write control frame: {error}"))
}

struct GuestRuntime {
    config: GuestConfig,
    process_runtime: tokio::runtime::Handle,
    state: Mutex<RuntimeState>,
}

enum RuntimeState {
    AwaitingAttach,
    Bound,
    Ready,
    Running(Arc<ManagedProcess>),
}

impl GuestRuntime {
    fn new(config: GuestConfig, process_runtime: tokio::runtime::Handle) -> Self {
        Self {
            config,
            process_runtime,
            state: Mutex::new(RuntimeState::AwaitingAttach),
        }
    }

    fn dispatch(&self, envelope: RequestEnvelope) -> Response {
        if !constant_time_eq(
            envelope.boundary_id.as_bytes(),
            self.config.boundary_id.as_bytes(),
        ) || !constant_time_eq(
            envelope.bootstrap_token.as_bytes(),
            self.config.bootstrap_token.as_bytes(),
        ) {
            return guest_error("denied", "control authentication failed");
        }
        match envelope.request {
            Request::Attach => self.attach(),
            Request::Confirm => self.confirm(),
            Request::StartAgent {
                sandbox_id,
                spec,
                policy,
            } => self.start_agent(sandbox_id, spec, *policy),
            Request::Wait { process_id } => self.wait(&process_id),
            Request::Signal { process_id, signal } => self.signal(&process_id, signal),
            Request::Terminate { process_id } => self.terminate(&process_id),
        }
    }

    fn attach(&self) -> Response {
        let mut state = lock(&self.state);
        match *state {
            RuntimeState::AwaitingAttach => {
                *state = RuntimeState::Bound;
                Response::Attached
            }
            RuntimeState::Bound => Response::Attached,
            _ => guest_error("invalid", "boundary has already advanced past attach"),
        }
    }

    fn confirm(&self) -> Response {
        let mut state = lock(&self.state);
        match *state {
            RuntimeState::Bound => {
                *state = RuntimeState::Ready;
                Response::Confirmed
            }
            RuntimeState::Ready => Response::Confirmed,
            RuntimeState::AwaitingAttach => {
                guest_error("invalid", "boundary must be attached before confirm")
            }
            RuntimeState::Running(_) => {
                guest_error("invalid", "boundary has already started its agent")
            }
        }
    }

    fn start_agent(
        &self,
        sandbox_id: String,
        spec: AgentSpecWire,
        policy: SandboxPolicyWire,
    ) -> Response {
        let mut state = lock(&self.state);
        if !matches!(*state, RuntimeState::Ready) {
            return guest_error("invalid", "boundary must be confirmed before start_agent");
        }
        let process = match ManagedProcess::spawn(
            &self.process_runtime,
            sandbox_id,
            spec,
            policy.into(),
            ResolvedProcessIdentity::new(Some(self.config.agent_uid), Some(self.config.agent_gid)),
        ) {
            Ok(process) => Arc::new(process),
            Err(error) => return guest_error("failed", error),
        };
        let process_id = process.process_id();
        *state = RuntimeState::Running(process);
        Response::Started { process_id }
    }

    fn wait(&self, process_id: &str) -> Response {
        let process = match self.running_process(process_id) {
            Ok(process) => process,
            Err(response) => return response,
        };
        match process.wait() {
            Ok(status) => Response::Exited { status },
            Err(error) => guest_error("failed", error),
        }
    }

    fn signal(&self, process_id: &str, signal: SignalWire) -> Response {
        let process = match self.running_process(process_id) {
            Ok(process) => process,
            Err(response) => return response,
        };
        match process.signal(signal) {
            Ok(()) => Response::Signaled,
            Err(error) => guest_error("terminated", error),
        }
    }

    fn terminate(&self, process_id: &str) -> Response {
        let process = match self.running_process(process_id) {
            Ok(process) => process,
            Err(response) => return response,
        };
        match process.signal(SignalWire::Kill) {
            Ok(()) => Response::Terminated,
            Err(_) if process.has_exited() => Response::Terminated,
            Err(error) => guest_error("failed", error),
        }
    }

    fn running_process(&self, process_id: &str) -> Result<Arc<ManagedProcess>, Response> {
        let state = lock(&self.state);
        let RuntimeState::Running(process) = &*state else {
            return Err(guest_error("invalid", "agent process has not been started"));
        };
        if process.process_id() != process_id {
            return Err(guest_error("invalid", "unknown process ID"));
        }
        Ok(process.clone())
    }
}

type ProcessExit = Result<ExitStatusWire, String>;
type SharedProcessExit = Arc<(Mutex<Option<ProcessExit>>, Condvar)>;

struct ManagedProcess {
    pid: i32,
    signaler: AgentSignaler,
    exit: SharedProcessExit,
}

impl ManagedProcess {
    fn spawn(
        runtime: &tokio::runtime::Handle,
        sandbox_id: String,
        spec: AgentSpecWire,
        policy: openshell_core::policy::SandboxPolicy,
        resolved_identity: ResolvedProcessIdentity,
    ) -> Result<Self, String> {
        if spec.program.is_empty() {
            return Err("agent program must not be empty".to_string());
        }
        let boundary_runtime = BoundaryRuntimeState::new();
        let mut spawned = runtime
            .block_on(spawn_workload(
                &spec.program,
                &spec.args,
                spec.workdir.as_deref(),
                spec.timeout_secs,
                spec.interactive,
                Some(&sandbox_id),
                None,
                None,
                false,
                &policy,
                resolved_identity,
                ProcessEnforcementMode::Full,
                Arc::new(AtomicU32::new(0)),
                None,
                ProviderCredentialState::from_child_env_snapshot(
                    0,
                    std::collections::HashMap::new(),
                ),
                std::collections::HashMap::new(),
                None,
                AgentProposals::default(),
                None,
                None,
                None,
                Some(boundary_runtime),
            ))
            .map_err(|error| format!("start process supervisor leaf: {error}"))?;
        let pid = i32::try_from(spawned.pid())
            .map_err(|_| "process supervisor PID does not fit i32".to_string())?;
        let signaler = spawned.signaler();
        let exit = Arc::new((Mutex::new(None), Condvar::new()));
        let reaper_exit = exit.clone();
        runtime.spawn(async move {
            let result = spawned
                .wait()
                .await
                .map(process_status)
                .map_err(|error| format!("wait for process supervisor leaf: {error}"));
            let (state, changed) = &*reaper_exit;
            *lock(state) = Some(result);
            changed.notify_all();
        });
        Ok(Self {
            pid,
            signaler,
            exit,
        })
    }

    fn process_id(&self) -> String {
        self.pid.to_string()
    }

    fn wait(&self) -> ProcessExit {
        let (state, changed) = &*self.exit;
        let mut exit = lock(state);
        while exit.is_none() {
            exit = changed
                .wait(exit)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        exit.as_ref().expect("exit checked above").clone()
    }

    fn signal(&self, signal: SignalWire) -> Result<(), String> {
        if self.has_exited() {
            return Err("agent process has already exited".to_string());
        }
        let result = match signal {
            SignalWire::Term => self.signaler.term(),
            SignalWire::Kill => self.signaler.kill(),
            SignalWire::Int => self.signaler.interrupt(),
            SignalWire::Hup => self.signaler.hangup(),
        };
        result.map_err(|error| format!("signal process supervisor group: {error}"))
    }

    fn has_exited(&self) -> bool {
        let (state, _) = &*self.exit;
        lock(state).is_some()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn process_status(status: ProcessStatus) -> ExitStatusWire {
    status.signal().map_or_else(
        || ExitStatusWire::Exited(status.code()),
        ExitStatusWire::Signaled,
    )
}

fn guest_error(kind: &str, message: impl Into<String>) -> Response {
    Response::Error {
        kind: kind.to_string(),
        message: message.into(),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or_default();
        let right_byte = right.get(index).copied().unwrap_or_default();
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

struct VsockListener {
    fd: OwnedFd,
}

impl VsockListener {
    fn bind(port: u32) -> io::Result<Self> {
        let family = libc::sa_family_t::try_from(libc::AF_VSOCK).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "AF_VSOCK exceeds sa_family_t")
        })?;
        let address_length =
            libc::socklen_t::try_from(size_of::<libc::sockaddr_vm>()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "sockaddr_vm exceeds socklen_t")
            })?;
        let raw_fd =
            unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let address = libc::sockaddr_vm {
            svm_family: family,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: libc::VMADDR_CID_ANY,
            svm_zero: [0; 4],
        };
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const address).cast::<libc::sockaddr>(),
                address_length,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::listen(fd.as_raw_fd(), 16) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    fn accept(&self) -> io::Result<VsockStream> {
        let raw_fd = unsafe {
            libc::accept4(
                self.fd.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if raw_fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(VsockStream {
                file: unsafe { File::from_raw_fd(raw_fd) },
            })
        }
    }
}

struct VsockStream {
    file: File,
}

impl VsockStream {
    fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
        let option_length =
            libc::socklen_t::try_from(size_of::<libc::timeval>()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "timeval exceeds socklen_t")
            })?;
        let timeout = libc::timeval {
            tv_sec: timeout.as_secs().try_into().unwrap_or(libc::time_t::MAX),
            tv_usec: timeout.subsec_micros().into(),
        };
        for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            let result = unsafe {
                libc::setsockopt(
                    self.file.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&raw const timeout).cast(),
                    option_length,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

impl Read for VsockStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Write for VsockStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.file.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_config_debug_redacts_token() {
        let config = GuestConfig {
            boundary_id: "sandbox-1".to_string(),
            bootstrap_token: "never-log-this-never-log-this".to_string(),
            control_port: 5500,
            agent_uid: DEFAULT_AGENT_UID,
            agent_gid: DEFAULT_AGENT_GID,
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("never-log-this"));
    }

    #[test]
    fn constant_time_comparison_checks_length_and_content() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"different"));
        assert!(!constant_time_eq(b"same", b"sam"));
    }
}
