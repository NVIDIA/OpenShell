// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox-local [`BoundaryLoopbackConnector`] implementation.

use async_trait::async_trait;
use openshell_isolation_interface::contract::{
    BackendError, BoundaryDuplexStream, BoundaryLoopbackConnector, LoopbackTarget,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

const RUNTIME_ACTIVE: u8 = 0;
const RUNTIME_FROZEN: u8 = 1;
const RUNTIME_TERMINATED: u8 = 2;
const RUNTIME_ENFORCEMENT_LOST: u8 = 3;

/// Shared liveness and child-process ownership for one active boundary.
pub struct BoundaryRuntimeState {
    state: AtomicU8,
    process_groups: Mutex<HashMap<u32, RegisteredProcessGroup>>,
    exclusive_pid_namespace: bool,
}

impl BoundaryRuntimeState {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(RUNTIME_ACTIVE),
            process_groups: Mutex::new(HashMap::new()),
            exclusive_pid_namespace: false,
        })
    }

    /// Construct state for a boundary that exclusively owns its PID namespace.
    #[must_use]
    pub fn new_exclusive_pid_namespace() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(RUNTIME_ACTIVE),
            process_groups: Mutex::new(HashMap::new()),
            exclusive_pid_namespace: true,
        })
    }

    #[must_use]
    pub const fn requires_dedicated_process_group(&self) -> bool {
        self.exclusive_pid_namespace
    }

    pub fn ensure_active(&self) -> Result<(), BackendError> {
        match self.state.load(Ordering::Acquire) {
            RUNTIME_ACTIVE => Ok(()),
            RUNTIME_FROZEN => Err(BackendError::Unavailable(
                "boundary is frozen while supervisor control recovers".to_string(),
            )),
            _ => Err(BackendError::Terminated("boundary has ended".to_string())),
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state.load(Ordering::Acquire) == RUNTIME_ACTIVE
    }

    #[must_use]
    pub fn enforcement_was_lost(&self) -> bool {
        self.state.load(Ordering::Acquire) == RUNTIME_ENFORCEMENT_LOST
    }

    pub fn register_process_group(
        &self,
        pid: u32,
        terminal: Arc<std::sync::atomic::AtomicBool>,
        signal_lock: Arc<Mutex<()>>,
    ) -> Result<(), BackendError> {
        let mut groups = self
            .process_groups
            .lock()
            .map_err(|_| BackendError::Process("boundary process registry poisoned".to_string()))?;
        self.ensure_active()?;
        groups.insert(
            pid,
            RegisteredProcessGroup {
                pid,
                terminal,
                signal_lock,
            },
        );
        Ok(())
    }

    pub fn unregister_process_group(
        &self,
        pid: u32,
        terminal: &Arc<std::sync::atomic::AtomicBool>,
    ) {
        if let Ok(mut groups) = self.process_groups.lock()
            && groups
                .get(&pid)
                .is_some_and(|group| Arc::ptr_eq(&group.terminal, terminal))
        {
            groups.remove(&pid);
        }
    }

    #[cfg(test)]
    pub fn registered_process_group_count(&self) -> usize {
        self.process_groups.lock().map_or(0, |groups| groups.len())
    }

    /// End the boundary and terminate every registered workload process group.
    pub fn deactivate(&self) {
        let previous = self.state.swap(RUNTIME_TERMINATED, Ordering::AcqRel);
        if matches!(previous, RUNTIME_ACTIVE | RUNTIME_FROZEN) {
            self.signal_registered_processes(nix::sys::signal::Signal::SIGCONT);
            self.signal_registered_processes(nix::sys::signal::Signal::SIGKILL);
        }
    }

    /// Stop every owned workload process while the supervisor reconnects.
    ///
    /// New process and loopback operations fail while frozen. The registered
    /// process groups include the canonical workload and every sandbox exec.
    #[must_use]
    pub fn freeze(&self) -> bool {
        if self
            .state
            .compare_exchange(
                RUNTIME_ACTIVE,
                RUNTIME_FROZEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        self.signal_registered_processes(nix::sys::signal::Signal::SIGSTOP);
        true
    }

    /// Resume a workload only after the replacement supervisor connection has
    /// authenticated, attached, and reconfirmed the boundary.
    #[must_use]
    pub fn resume(&self) -> bool {
        if self
            .state
            .compare_exchange(
                RUNTIME_FROZEN,
                RUNTIME_ACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        self.signal_registered_processes(nix::sys::signal::Signal::SIGCONT);
        true
    }

    /// Begin fail-closed termination after authenticated recovery times out.
    /// Frozen tasks are continued before `SIGTERM` so they can run their
    /// ordinary shutdown handlers.
    #[must_use]
    pub fn begin_enforcement_loss_termination(&self) -> bool {
        if self
            .state
            .compare_exchange(
                RUNTIME_FROZEN,
                RUNTIME_ENFORCEMENT_LOST,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        self.signal_registered_processes(nix::sys::signal::Signal::SIGCONT);
        self.signal_registered_processes(nix::sys::signal::Signal::SIGTERM);
        true
    }

    /// Begin an authenticated, graceful boundary shutdown.
    #[must_use]
    pub fn begin_termination(&self) -> bool {
        loop {
            let state = self.state.load(Ordering::Acquire);
            if !matches!(state, RUNTIME_ACTIVE | RUNTIME_FROZEN) {
                return false;
            }
            if self
                .state
                .compare_exchange(
                    state,
                    RUNTIME_TERMINATED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                self.signal_registered_processes(nix::sys::signal::Signal::SIGCONT);
                self.signal_registered_processes(nix::sys::signal::Signal::SIGTERM);
                return true;
            }
        }
    }

    /// Force all remaining owned process groups to exit.
    pub fn force_kill(&self) {
        self.signal_registered_processes(nix::sys::signal::Signal::SIGCONT);
        self.signal_registered_processes(nix::sys::signal::Signal::SIGKILL);
    }

    #[must_use]
    pub fn has_registered_processes(&self) -> bool {
        self.process_groups
            .lock()
            .is_ok_and(|groups| !groups.is_empty())
    }

    /// End the boundary because required standing enforcement was lost.
    ///
    /// Returns `true` only to the caller that won the active-to-terminated
    /// transition. A concurrent normal teardown cannot later be reclassified
    /// as enforcement loss.
    pub fn deactivate_for_enforcement_loss(&self) -> bool {
        loop {
            let state = self.state.load(Ordering::Acquire);
            if !matches!(state, RUNTIME_ACTIVE | RUNTIME_FROZEN) {
                return false;
            }
            if self
                .state
                .compare_exchange(
                    state,
                    RUNTIME_ENFORCEMENT_LOST,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                self.force_kill();
                return true;
            }
        }
    }

    fn signal_registered_processes(&self, signal: nix::sys::signal::Signal) {
        let groups = self
            .process_groups
            .lock()
            .map(|groups| groups.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for group in &groups {
            group.signal(signal);
        }
        #[cfg(target_os = "linux")]
        {
            let roots = groups.iter().map(|group| group.pid).collect::<Vec<_>>();
            // A workload may create another process group or session. Once its
            // registered roots are stopped they cannot fork again, so bounded
            // repeated descendant scans close the signal-to-scan race without
            // requiring ptrace or a capability.
            let mut previous = Vec::new();
            for _ in 0..4 {
                let owned = owned_process_ids(&roots, self.exclusive_pid_namespace);
                for pid in &owned {
                    if roots.contains(pid) {
                        continue;
                    }
                    if let Ok(pid) = i32::try_from(*pid) {
                        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), signal);
                    }
                }
                if owned == previous {
                    break;
                }
                previous = owned;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn owned_process_ids(roots: &[u32], exclusive_pid_namespace: bool) -> Vec<u32> {
    let mut parents = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return roots.to_vec();
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(after_name) = stat.rsplit_once(") ").map(|(_, fields)| fields) else {
            continue;
        };
        let Some(parent) = after_name
            .split_whitespace()
            .nth(1)
            .and_then(|field| field.parse::<u32>().ok())
        else {
            continue;
        };
        parents.insert(pid, parent);
    }

    // When openshell-sandbox is PID 1, every other process in its exclusive
    // namespace is workload-owned, including an orphan reparented during the
    // scan. Outside that deployment shape, restrict the walk to registered
    // roots so unit tests and development runs cannot affect sibling tasks.
    if exclusive_pid_namespace && std::process::id() == 1 {
        let mut owned = parents
            .keys()
            .copied()
            .filter(|pid| *pid != 1)
            .collect::<Vec<_>>();
        owned.sort_unstable();
        return owned;
    }

    let mut owned = roots.to_vec();
    loop {
        let mut changed = false;
        for (&pid, &parent) in &parents {
            if !owned.contains(&pid) && owned.contains(&parent) {
                owned.push(pid);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    owned.sort_unstable();
    owned.dedup();
    owned
}

#[derive(Clone)]
struct RegisteredProcessGroup {
    pid: u32,
    terminal: Arc<std::sync::atomic::AtomicBool>,
    signal_lock: Arc<Mutex<()>>,
}

impl RegisteredProcessGroup {
    fn signal(&self, signal: nix::sys::signal::Signal) {
        let _signal_guard = self
            .signal_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.terminal.load(Ordering::Acquire) {
            return;
        }
        if let Ok(pid) = i32::try_from(self.pid) {
            let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), signal);
        }
    }
}

/// Loopback port-forward owned by the sandbox process.
pub struct LocalLoopbackConnector {
    runtime: Option<Arc<BoundaryRuntimeState>>,
}

impl LocalLoopbackConnector {
    #[must_use]
    pub fn new(runtime: Option<Arc<BoundaryRuntimeState>>) -> Self {
        Self { runtime }
    }
}

#[async_trait]
impl BoundaryLoopbackConnector for LocalLoopbackConnector {
    async fn connect(&self, target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError> {
        if let Some(runtime) = &self.runtime {
            runtime.ensure_active()?;
        }
        let addr = std::net::SocketAddr::new(target.host(), target.port());
        let stream = openshell_core::net::connect_tcp_nodelay_best_effort(&[addr])
            .await
            .map_err(|e| BackendError::Process(format!("port-forward connect to {addr}: {e}")))?;
        if let Some(runtime) = &self.runtime {
            runtime.ensure_active()?;
        }
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Stands in for the SSH server's port-forward path: connect through the
    /// interface, write, and read the echo.
    #[tokio::test]
    async fn loopback_connector_connects_and_round_trips() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).await.unwrap();
            sock.write_all(&buf).await.unwrap();
        });

        let pf = LocalLoopbackConnector::new(None);
        let target =
            LoopbackTarget::new(Ipv4Addr::LOCALHOST.into(), addr.port()).expect("loopback target");
        let mut conn = pf.connect(target).await.expect("connect through interface");
        conn.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    /// Drive the port-forward interface through a generic `&dyn` consumer, proving a
    /// kernel-separated backend (tunneling into a guest) would use the same call.
    #[tokio::test]
    async fn loopback_connector_is_driven_via_dyn() {
        async fn forward_one(pf: &dyn BoundaryLoopbackConnector, target: LoopbackTarget) -> bool {
            pf.connect(target).await.is_ok()
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let pf = LocalLoopbackConnector::new(None);
        let target = LoopbackTarget::new(Ipv4Addr::LOCALHOST.into(), addr.port()).unwrap();
        assert!(forward_one(&pf, target).await);
    }

    #[tokio::test]
    async fn loopback_connector_rejects_after_boundary_end() {
        let runtime = BoundaryRuntimeState::new();
        let pf = LocalLoopbackConnector::new(Some(runtime.clone()));
        runtime.deactivate();
        let target = LoopbackTarget::new(Ipv4Addr::LOCALHOST.into(), 1).unwrap();
        assert!(matches!(
            pf.connect(target).await,
            Err(BackendError::Terminated(_))
        ));
    }

    #[tokio::test]
    async fn failed_loopback_connector_keeps_boundary_active() {
        let runtime = BoundaryRuntimeState::new();
        let pf = LocalLoopbackConnector::new(Some(runtime.clone()));
        // Port zero is never a connectable TCP destination. Reserving an ephemeral
        // port and dropping its listener races other parallel tests that may bind it.
        let target = LoopbackTarget::new(Ipv4Addr::LOCALHOST.into(), 0).unwrap();
        assert!(matches!(
            pf.connect(target).await,
            Err(BackendError::Process(_))
        ));
        runtime.ensure_active().expect("boundary remains active");
    }

    #[test]
    fn stale_unregister_preserves_reused_process_group_registration() {
        let runtime = BoundaryRuntimeState::new();
        let first_terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second_terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pid = 42;
        runtime
            .register_process_group(pid, first_terminal.clone(), Arc::new(Mutex::new(())))
            .expect("first registration");
        runtime
            .register_process_group(pid, second_terminal.clone(), Arc::new(Mutex::new(())))
            .expect("replacement registration");

        runtime.unregister_process_group(pid, &first_terminal);
        assert_eq!(runtime.registered_process_group_count(), 1);

        runtime.unregister_process_group(pid, &second_terminal);
        assert_eq!(runtime.registered_process_group_count(), 0);
    }

    #[test]
    fn canonical_process_completion_does_not_end_boundary_runtime() {
        let runtime = BoundaryRuntimeState::new_exclusive_pid_namespace();
        let terminal = Arc::new(std::sync::atomic::AtomicBool::new(true));
        runtime
            .register_process_group(42, terminal.clone(), Arc::new(Mutex::new(())))
            .expect("register canonical process");

        runtime.unregister_process_group(42, &terminal);

        runtime
            .ensure_active()
            .expect("canonical completion must preserve exec and forwarding");
        assert_eq!(runtime.registered_process_group_count(), 0);
        runtime.deactivate();
        assert!(matches!(
            runtime.ensure_active(),
            Err(BackendError::Terminated(_))
        ));
    }

    #[test]
    fn freeze_blocks_new_operations_until_explicit_resume() {
        let runtime = BoundaryRuntimeState::new_exclusive_pid_namespace();

        assert!(runtime.freeze());
        assert!(matches!(
            runtime.ensure_active(),
            Err(BackendError::Unavailable(_))
        ));
        assert!(!runtime.freeze());
        assert!(runtime.resume());
        runtime.ensure_active().expect("runtime resumed");
    }

    #[test]
    fn enforcement_loss_is_terminal_after_freeze() {
        let runtime = BoundaryRuntimeState::new_exclusive_pid_namespace();

        assert!(runtime.freeze());
        assert!(runtime.begin_enforcement_loss_termination());
        assert!(runtime.enforcement_was_lost());
        assert!(!runtime.resume());
        assert!(matches!(
            runtime.ensure_active(),
            Err(BackendError::Terminated(_))
        ));
    }
}
