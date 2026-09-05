// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox-local [`BoundaryPortForward`] implementation.

use async_trait::async_trait;
use openshell_isolation_interface::contract::{
    BackendError, BoundaryDuplexStream, BoundaryPortForward, LoopbackTarget,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

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
            state: AtomicU8::new(0),
            process_groups: Mutex::new(HashMap::new()),
            exclusive_pid_namespace: false,
        })
    }

    /// Construct state for a boundary that exclusively owns its PID namespace.
    #[must_use]
    pub fn new_exclusive_pid_namespace() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(0),
            process_groups: Mutex::new(HashMap::new()),
            exclusive_pid_namespace: true,
        })
    }

    #[must_use]
    pub const fn requires_dedicated_process_group(&self) -> bool {
        self.exclusive_pid_namespace
    }

    pub fn ensure_active(&self) -> Result<(), BackendError> {
        if self.state.load(Ordering::Acquire) == 0 {
            Ok(())
        } else {
            Err(BackendError::Terminated("boundary has ended".to_string()))
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state.load(Ordering::Acquire) == 0
    }

    #[must_use]
    pub fn enforcement_was_lost(&self) -> bool {
        self.state.load(Ordering::Acquire) == 2
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
        if self
            .state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.terminate_registered_processes();
        }
    }

    /// End the boundary because required standing enforcement was lost.
    ///
    /// Returns `true` only to the caller that won the active-to-terminated
    /// transition. A concurrent normal teardown cannot later be reclassified
    /// as enforcement loss.
    pub fn deactivate_for_enforcement_loss(&self) -> bool {
        if self
            .state
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        self.terminate_registered_processes();
        true
    }

    fn terminate_registered_processes(&self) {
        let groups = self
            .process_groups
            .lock()
            .map(|groups| groups.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for group in groups {
            group.terminate();
        }
    }
}

#[derive(Clone)]
struct RegisteredProcessGroup {
    pid: u32,
    terminal: Arc<std::sync::atomic::AtomicBool>,
    signal_lock: Arc<Mutex<()>>,
}

impl RegisteredProcessGroup {
    fn terminate(&self) {
        let _signal_guard = self
            .signal_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.terminal.load(Ordering::Acquire) {
            return;
        }
        if let Ok(pid) = i32::try_from(self.pid) {
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }
}

/// Loopback port-forward owned by the sandbox process.
pub struct LocalPortForward {
    runtime: Option<Arc<BoundaryRuntimeState>>,
}

impl LocalPortForward {
    #[must_use]
    pub fn new(runtime: Option<Arc<BoundaryRuntimeState>>) -> Self {
        Self { runtime }
    }
}

#[async_trait]
impl BoundaryPortForward for LocalPortForward {
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
    async fn port_forward_connects_and_round_trips() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).await.unwrap();
            sock.write_all(&buf).await.unwrap();
        });

        let pf = LocalPortForward::new(None);
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
    async fn port_forward_is_driven_via_dyn() {
        async fn forward_one(pf: &dyn BoundaryPortForward, target: LoopbackTarget) -> bool {
            pf.connect(target).await.is_ok()
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let pf = LocalPortForward::new(None);
        let target = LoopbackTarget::new(Ipv4Addr::LOCALHOST.into(), addr.port()).unwrap();
        assert!(forward_one(&pf, target).await);
    }

    #[tokio::test]
    async fn port_forward_rejects_after_boundary_end() {
        let runtime = BoundaryRuntimeState::new();
        let pf = LocalPortForward::new(Some(runtime.clone()));
        runtime.deactivate();
        let target = LoopbackTarget::new(Ipv4Addr::LOCALHOST.into(), 1).unwrap();
        assert!(matches!(
            pf.connect(target).await,
            Err(BackendError::Terminated(_))
        ));
    }

    #[tokio::test]
    async fn failed_port_forward_keeps_boundary_active() {
        let runtime = BoundaryRuntimeState::new();
        let pf = LocalPortForward::new(Some(runtime.clone()));
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
}
