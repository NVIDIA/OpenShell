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

    /// Whether any workload process remains, registered or not.
    ///
    /// A registered root is unregistered once it is reaped, but descendants
    /// that ignored `SIGTERM` may outlive it. When the sandbox owns the
    /// process tree (PID 1 or a child subreaper), every live descendant is
    /// counted so termination is not reported complete while one survives.
    #[must_use]
    pub fn has_owned_processes(&self) -> bool {
        if self.has_registered_processes() {
            return true;
        }
        #[cfg(target_os = "linux")]
        if self.exclusive_pid_namespace && sandbox_owns_process_tree() {
            return !owned_processes(&[], true).is_empty();
        }
        false
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
                let owned = owned_processes(&roots, self.exclusive_pid_namespace);
                for process in &owned {
                    if !roots.contains(&process.pid) {
                        signal_owned_process(*process, signal);
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

/// One scanned workload process, identified by PID and kernel start time so a
/// reused PID is never mistaken for it.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct OwnedProcess {
    pid: u32,
    start_time: u64,
}

#[cfg(target_os = "linux")]
struct ProcStat {
    parent: u32,
    start_time: u64,
    live: bool,
}

#[cfg(target_os = "linux")]
fn read_proc_stat(pid: u32) -> Option<ProcStat> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name may contain spaces or parentheses; fields resume after
    // the final ") ". Field 3 is the state, 4 the parent, 22 the start time.
    let fields = stat
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    Some(ProcStat {
        parent: fields.get(1)?.parse().ok()?,
        start_time: fields.get(19)?.parse().ok()?,
        live: !matches!(*fields.first()?, "Z" | "X" | "x"),
    })
}

/// Whether orphaned descendants are reparented to this sandbox process.
#[cfg(target_os = "linux")]
fn sandbox_owns_process_tree() -> bool {
    std::process::id() == 1
        || rustix::process::child_subreaper().is_ok_and(|subreaper| subreaper.is_some())
}

#[cfg(target_os = "linux")]
fn owned_processes(roots: &[u32], exclusive_pid_namespace: bool) -> Vec<OwnedProcess> {
    let mut stats = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some(stat) = read_proc_stat(pid) {
            stats.insert(pid, stat);
        }
    }

    // When the sandbox is PID 1 of its exclusive namespace or a child
    // subreaper, orphans are reparented to it, so its descendants are exactly
    // the workload tree, including an orphan reparented during the scan.
    // Otherwise restrict the walk to registered roots so unit tests and
    // development runs cannot affect sibling tasks.
    let mut owned = if exclusive_pid_namespace && sandbox_owns_process_tree() {
        vec![std::process::id()]
    } else {
        roots.to_vec()
    };
    loop {
        let mut changed = false;
        for (&pid, stat) in &stats {
            if !owned.contains(&pid) && owned.contains(&stat.parent) {
                owned.push(pid);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let sandbox = std::process::id();
    let mut owned = owned
        .into_iter()
        .filter(|pid| *pid != sandbox)
        .filter_map(|pid| {
            let stat = stats.get(&pid)?;
            stat.live.then_some(OwnedProcess {
                pid,
                start_time: stat.start_time,
            })
        })
        .collect::<Vec<_>>();
    owned.sort_unstable();
    owned.dedup();
    owned
}

/// Signal one scanned process through a pidfd, after confirming the pidfd
/// refers to the scanned process rather than a later process with its PID.
#[cfg(target_os = "linux")]
fn signal_owned_process(process: OwnedProcess, signal: nix::sys::signal::Signal) {
    let Some(pid) = i32::try_from(process.pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return;
    };
    let Some(signal) = rustix::process::Signal::from_named_raw(signal as i32) else {
        return;
    };
    let Ok(pidfd) = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) else {
        return;
    };
    if read_proc_stat(process.pid).map(|stat| stat.start_time) != Some(process.start_time) {
        return;
    }
    let _ = rustix::process::pidfd_send_signal(&pidfd, signal);
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

    #[cfg(target_os = "linux")]
    #[test]
    fn termination_waits_for_descendants_that_outlive_their_root() {
        use std::io::BufRead as _;
        use std::os::unix::process::CommandExt as _;

        // Becoming a subreaper changes this whole process, so run the
        // scenario in a fresh copy of the test binary.
        const CHILD_MARKER: &str = "OPENSHELL_SUBREAPER_TEARDOWN_CHILD";
        if std::env::var_os(CHILD_MARKER).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "boundary_io::tests::termination_waits_for_descendants_that_outlive_their_root",
                    "--nocapture",
                ])
                .env(CHILD_MARKER, "1")
                .status()
                .expect("run isolated teardown test");
            assert!(status.success(), "isolated teardown test failed");
            return;
        }
        rustix::process::set_child_subreaper(Some(rustix::process::getpid()))
            .expect("become child subreaper");
        let runtime = BoundaryRuntimeState::new_exclusive_pid_namespace();
        // The grandchild inherits an ignored SIGTERM; the root restores the
        // default disposition and exits on SIGTERM.
        let mut root = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                "trap '' TERM; sleep 600 & trap - TERM; echo ready; wait",
            ])
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn root");
        let mut line = String::new();
        std::io::BufReader::new(root.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "ready");
        let terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        runtime
            .register_process_group(root.id(), terminal.clone(), Arc::new(Mutex::new(())))
            .expect("register root");

        assert!(runtime.begin_termination());
        root.wait().expect("root exits on SIGTERM");
        terminal.store(true, Ordering::Release);
        runtime.unregister_process_group(root.id(), &terminal);
        assert!(!runtime.has_registered_processes());
        assert!(
            runtime.has_owned_processes(),
            "a SIGTERM-ignoring grandchild must keep termination incomplete"
        );

        runtime.force_kill();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while runtime.has_owned_processes() {
            assert!(
                std::time::Instant::now() < deadline,
                "forced termination left a descendant alive"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
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
