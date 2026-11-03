// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox-local [`BoundaryLoopbackConnector`] implementation.

use crate::native_api::BoundaryLoopbackConnector;

use async_trait::async_trait;
use openshell_isolation_interface::contract::{BackendError, BoundaryDuplexStream, LoopbackTarget};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const RUNTIME_ACTIVE: u8 = 0;
const RUNTIME_FROZEN: u8 = 1;
const RUNTIME_TERMINATED: u8 = 2;
const RUNTIME_ENFORCEMENT_LOST: u8 = 3;

/// A test hook that parks one transition's deferred descendant batch: the
/// generation the hook targets and the closure to run when it fires.
#[cfg(test)]
type DeferredBatchHook = (u64, Box<dyn FnOnce() + Send>);

/// Shared liveness and child-process ownership for one active boundary.
pub struct BoundaryRuntimeState {
    state: AtomicU8,
    process_groups: Mutex<HashMap<u32, RegisteredProcessGroup>>,
    exclusive_pid_namespace: bool,
    /// Serializes every signal application. The multi-iteration `/proc`
    /// collection scans run outside this mutex; a locked section signals the
    /// registered process groups and re-validates each already-collected
    /// descendant through its pidfd (`pidfd_open`, one `/proc/<pid>/stat`
    /// read, and the send), bounded by the descendant count.
    signal_order: Mutex<()>,
    /// Bumped under `signal_order` by every transition that applies signals.
    /// A deferred descendant batch applies its signal only while the
    /// generation it captured is still current, so a batch from an older
    /// transition can never land after a newer transition's signals.
    transition_generation: AtomicU64,
    #[cfg(test)]
    deferred_batch_hook: Mutex<Option<DeferredBatchHook>>,
    /// A test hook that parks the next `/proc` descendant collect.
    #[cfg(test)]
    collect_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl BoundaryRuntimeState {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(RUNTIME_ACTIVE),
            process_groups: Mutex::new(HashMap::new()),
            exclusive_pid_namespace: false,
            signal_order: Mutex::new(()),
            transition_generation: AtomicU64::new(0),
            #[cfg(test)]
            deferred_batch_hook: Mutex::new(None),
            #[cfg(test)]
            collect_hook: Mutex::new(None),
        })
    }

    /// Construct state for a boundary that exclusively owns its PID namespace.
    #[must_use]
    pub fn new_exclusive_pid_namespace() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(RUNTIME_ACTIVE),
            process_groups: Mutex::new(HashMap::new()),
            exclusive_pid_namespace: true,
            signal_order: Mutex::new(()),
            transition_generation: AtomicU64::new(0),
            #[cfg(test)]
            deferred_batch_hook: Mutex::new(None),
            #[cfg(test)]
            collect_hook: Mutex::new(None),
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
    /// Their roots are stopped synchronously; the `/proc` descendant sweep is
    /// deferred to `executor`, so it runs under neither the caller's locks
    /// nor `signal_order`. `recovery_id` names the recovery the freeze
    /// belongs to in sweep-failure events.
    #[must_use]
    pub fn freeze(self: &Arc<Self>, executor: &tokio::runtime::Handle, recovery_id: u64) -> bool {
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
        self.defer_descendant_signal(executor, nix::sys::signal::Signal::SIGSTOP, recovery_id);
        true
    }

    /// Resume a workload only after the replacement supervisor connection has
    /// authenticated, attached, and reconfirmed the boundary. Roots are
    /// continued synchronously; the descendant sweep is deferred to
    /// `executor` exactly as [`Self::freeze`] defers its own, because
    /// `commit_confirm` runs on a runtime worker that a synchronous scan
    /// would stall.
    #[must_use]
    pub fn resume(self: &Arc<Self>, executor: &tokio::runtime::Handle, recovery_id: u64) -> bool {
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
        self.defer_descendant_signal(executor, nix::sys::signal::Signal::SIGCONT, recovery_id);
        true
    }

    /// Signal the registered groups synchronously — so a freeze stops and a
    /// resume continues the roots before the caller returns — and defer the
    /// descendant sweep to `executor` as a detached task.
    fn defer_descendant_signal(
        self: &Arc<Self>,
        executor: &tokio::runtime::Handle,
        signal: nix::sys::signal::Signal,
        recovery_id: u64,
    ) {
        let generation = {
            let _order = self
                .signal_order
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let generation = self.transition_generation.fetch_add(1, Ordering::AcqRel) + 1;
            self.signal_registered_groups(signal);
            generation
        };
        #[cfg(target_os = "linux")]
        {
            let runtime = Arc::clone(self);
            // Detached on purpose: if the runtime shuts down with the batch
            // queued it never runs, and terminal paths signal synchronously.
            executor.spawn_blocking(move || {
                runtime.deferred_descendant_sweep(generation, signal, recovery_id);
            });
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = executor;
            let _ = recovery_id;
            let _ = generation;
        }
    }

    /// Apply `signal` to the descendants of the registered groups for the
    /// transition that captured `generation`.
    ///
    /// Each pass collects the owned set without holding `signal_order`, then
    /// applies the signal under it only while that generation is still
    /// current, so a batch deferred by an older transition is dropped rather
    /// than landing after a newer transition's signals. The locked apply
    /// section re-validates every collected descendant through its pidfd
    /// (`pidfd_open`, one `/proc/<pid>/stat` read, and the send) over the
    /// already-collected set — bounded by the descendant count, not by a
    /// `/proc` walk — plus the killpg on the registered groups. Collecting
    /// before locking stays PID-reuse-safe because [`signal_owned_process`]
    /// re-validates each pid through its pidfd before signaling.
    #[cfg(target_os = "linux")]
    fn deferred_descendant_sweep(
        &self,
        generation: u64,
        signal: nix::sys::signal::Signal,
        recovery_id: u64,
    ) {
        #[cfg(test)]
        if let Some(park) = self.take_deferred_batch_hook(generation) {
            park();
        }
        // Best-effort staleness avoidance, not the ordering check: a batch
        // whose generation was already superseded returns without paying the
        // `/proc` walk. The authoritative check stays in the locked apply
        // section below.
        if self.transition_generation.load(Ordering::Acquire) != generation {
            return;
        }
        let roots = self.registered_roots();
        let mut previous: Option<Vec<OwnedProcess>> = None;
        let mut delivered = true;
        for attempt in 0..4 {
            let owned = match self.collect_descendants(&roots) {
                Ok(owned) => owned,
                // A collection error with attempts left is retried by the
                // next pass; the last one is reported below.
                Err(_) if attempt < 3 => continue,
                Err(_) => {
                    delivered = false;
                    break;
                }
            };
            if previous.as_ref() == Some(&owned) {
                break;
            }
            let applied = {
                let _order = self
                    .signal_order
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if self.transition_generation.load(Ordering::Acquire) != generation {
                    // A newer transition applied its own signals; dropping
                    // this batch is the correct ordering behavior.
                    return;
                }
                apply_signal(&owned, &roots, signal)
            };
            delivered = delivered && applied;
            previous = Some(owned);
        }
        if !delivered {
            // A descendant that escaped the signal is an observable
            // enforcement gap while the boundary is frozen.
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ProcessActivityBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(openshell_ocsf::ActivityId::Close)
                    .severity(openshell_ocsf::SeverityId::Low)
                    .status(openshell_ocsf::StatusId::Failure)
                    .actor_process(crate::process::ocsf_launcher_process())
                    .message(format!(
                        "deferred descendant sweep failed to apply {signal} [recovery_id:{recovery_id}]"
                    ))
                    .build()
            );
            // Dual-emitted as a detection finding, as every security
            // finding is: Medium like the connection-lost finding, because
            // the gap sits inside a frozen boundary whose recovery is still
            // pending.
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(openshell_ocsf::ActivityId::Open)
                    .severity(openshell_ocsf::SeverityId::Medium)
                    .confidence(openshell_ocsf::ConfidenceId::High)
                    .is_alert(true)
                    .finding_info(openshell_ocsf::FindingInfo::new(
                        "sandbox-deferred-sweep-enforcement-gap",
                        "Sandbox Deferred Sweep Enforcement Gap",
                    ))
                    .message(format!(
                        "deferred descendant sweep enforcement gap: {signal} not applied [recovery_id:{recovery_id}]"
                    ))
                    .build()
            );
        }
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
        // An unreadable /proc fails closed: processes may remain.
        #[cfg(target_os = "linux")]
        return owned_processes(&[], self.exclusive_pid_namespace)
            .map_or(true, |owned| !owned.is_empty());
        #[cfg(not(target_os = "linux"))]
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

    /// Apply `signal` to every registered group and every scanned descendant,
    /// synchronously.
    ///
    /// Terminal and enforcement-loss paths only: the registered groups are
    /// signaled — and the transition generation bumped — under `signal_order`
    /// before the first scan, so a stale deferred batch is dropped ahead of
    /// the terminal signals and the roots react without waiting behind a
    /// `/proc` walk. The descendant scans then run outside `signal_order`, so
    /// a `supervisor_connection` holder waits at most one apply section.
    /// Terminal signals are authoritative, so unlike the deferred sweeps
    /// nothing is dropped on a generation change. Freeze and resume defer
    /// their descendant sweeps instead (see
    /// [`Self::defer_descendant_signal`]).
    fn signal_registered_processes(&self, signal: nix::sys::signal::Signal) {
        // The registry is cloned once and the roots derive from that
        // snapshot, so no locked section takes the registry lock.
        let groups = self.registered_groups();
        // Signal the registered groups before the first `/proc` collect, as
        // `defer_descendant_signal` does for freeze and resume: the bump
        // stays under `signal_order` ahead of the group signals, so any
        // stale deferred batch is dropped rather than landing after them.
        {
            let _order = self
                .signal_order
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.transition_generation.fetch_add(1, Ordering::AcqRel);
            for group in &groups {
                group.signal(signal);
            }
        }
        #[cfg(target_os = "linux")]
        {
            let roots: Vec<u32> = groups.iter().map(|group| group.pid).collect();
            let mut previous = Vec::new();
            let mut delivered = true;
            // A workload may create another process group or session. Once
            // the registered roots are stopped they cannot fork again, so
            // bounded repeated descendant scans close the signal-to-scan race
            // without requiring ptrace or a capability. Applies stay
            // generation-unchecked: terminal signals are authoritative and
            // are never dropped.
            for attempt in 0..4 {
                let owned = match self.collect_descendants(&roots) {
                    Ok(owned) => owned,
                    // A collection error with attempts left is retried by
                    // the next pass; the last one is reported below.
                    Err(_) if attempt < 3 => continue,
                    Err(_) => {
                        delivered = false;
                        break;
                    }
                };
                let applied = {
                    let _order = self
                        .signal_order
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    apply_signal(&owned, &roots, signal)
                };
                delivered = delivered && applied;
                if owned == previous {
                    break;
                }
                previous = owned;
            }
            if !delivered {
                // A descendant that escaped the terminal signal is an
                // observable enforcement gap.
                openshell_ocsf::ocsf_emit!(
                    openshell_ocsf::ProcessActivityBuilder::new(openshell_ocsf::ctx::ctx())
                        .activity(openshell_ocsf::ActivityId::Close)
                        .severity(openshell_ocsf::SeverityId::Low)
                        .status(openshell_ocsf::StatusId::Failure)
                        .actor_process(crate::process::ocsf_launcher_process())
                        .message(format!(
                            "terminal descendant signaling failed to apply {signal}"
                        ))
                        .build()
                );
                // Dual-emitted as a detection finding, as every security
                // finding is: High like the recovery-expired finding,
                // because the terminal path does not retry and nothing
                // else will enforce against the escaped descendant.
                openshell_ocsf::ocsf_emit!(
                    openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                        .activity(openshell_ocsf::ActivityId::Open)
                        .severity(openshell_ocsf::SeverityId::High)
                        .confidence(openshell_ocsf::ConfidenceId::High)
                        .is_alert(true)
                        .finding_info(openshell_ocsf::FindingInfo::new(
                            "sandbox-terminal-signal-enforcement-gap",
                            "Sandbox Terminal Signal Enforcement Gap",
                        ))
                        .message(format!(
                            "terminal descendant signaling enforcement gap: {signal} not applied"
                        ))
                        .build()
                );
            }
        }
    }

    fn signal_registered_groups(&self, signal: nix::sys::signal::Signal) {
        for group in &self.registered_groups() {
            group.signal(signal);
        }
    }

    fn registered_groups(&self) -> Vec<RegisteredProcessGroup> {
        self.process_groups
            .lock()
            .map(|groups| groups.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    }

    #[cfg(target_os = "linux")]
    fn registered_roots(&self) -> Vec<u32> {
        self.registered_groups()
            .iter()
            .map(|group| group.pid)
            .collect()
    }

    /// The owned descendants of `roots`, without applying anything. Collection
    /// never takes `signal_order`.
    #[cfg(target_os = "linux")]
    fn collect_descendants(&self, roots: &[u32]) -> std::io::Result<Vec<OwnedProcess>> {
        #[cfg(test)]
        if let Some(park) = self.take_collect_hook() {
            park();
        }
        owned_processes(roots, self.exclusive_pid_namespace)
    }

    /// Park the deferred batch of one transition before its first
    /// `signal_order` acquisition (parking it while holding the mutex would
    /// deadlock the next transition). Arming names the generation the hook
    /// targets, so a batch from another transition — both freeze and resume
    /// defer one — leaves it armed.
    #[cfg(test)]
    fn arm_deferred_batch_hook(&self, generation: u64, park: Box<dyn FnOnce() + Send>) {
        *self
            .deferred_batch_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((generation, park));
    }

    #[cfg(test)]
    fn take_deferred_batch_hook(&self, generation: u64) -> Option<Box<dyn FnOnce() + Send>> {
        let mut hook = self
            .deferred_batch_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if hook.as_ref().is_some_and(|(armed, _)| *armed == generation) {
            hook.take().map(|(_, park)| park)
        } else {
            None
        }
    }

    /// Park the next `/proc` descendant collect, so a test can observe what
    /// has already happened before the collect returns.
    #[cfg(test)]
    fn arm_collect_hook(&self, park: Box<dyn FnOnce() + Send>) {
        *self
            .collect_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(park);
    }

    #[cfg(test)]
    fn take_collect_hook(&self) -> Option<Box<dyn FnOnce() + Send>> {
        self.collect_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
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
fn read_proc_stat(pid: u32) -> std::io::Result<ProcStat> {
    let malformed = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed /proc/<pid>/stat",
        )
    };
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // The command name may contain spaces or parentheses; fields resume after
    // the final ") ". Field 3 is the state, 4 the parent, 22 the start time.
    let fields = stat
        .rsplit_once(") ")
        .ok_or_else(malformed)?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    Ok(ProcStat {
        parent: fields
            .get(1)
            .and_then(|field| field.parse().ok())
            .ok_or_else(malformed)?,
        start_time: fields
            .get(19)
            .and_then(|field| field.parse().ok())
            .ok_or_else(malformed)?,
        live: !matches!(*fields.first().ok_or_else(malformed)?, "Z" | "X" | "x"),
    })
}

/// Whether orphaned descendants are reparented to this sandbox process.
#[cfg(target_os = "linux")]
fn sandbox_owns_process_tree() -> bool {
    std::process::id() == 1
        || rustix::process::child_subreaper().is_ok_and(|subreaper| subreaper.is_some())
}

#[cfg(target_os = "linux")]
fn owned_processes(
    roots: &[u32],
    exclusive_pid_namespace: bool,
) -> std::io::Result<Vec<OwnedProcess>> {
    let mut stats = HashMap::new();
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for entry in std::fs::read_dir("/proc")?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if let Ok(stat) = read_proc_stat(pid) {
            children.entry(stat.parent).or_default().push(pid);
            stats.insert(pid, stat);
        }
    }

    // When the sandbox is PID 1 of its exclusive namespace or a child
    // subreaper, orphans are reparented to it, so its descendants are exactly
    // the workload tree. Otherwise walk only from registered roots so unit
    // tests and development runs cannot affect sibling tasks.
    let sandbox = std::process::id();
    let mut pending = if exclusive_pid_namespace && sandbox_owns_process_tree() {
        vec![sandbox]
    } else {
        roots.to_vec()
    };
    let mut visited = std::collections::HashSet::new();
    let mut owned = Vec::new();
    while let Some(pid) = pending.pop() {
        if !visited.insert(pid) {
            continue;
        }
        if let Some(descendants) = children.get(&pid) {
            pending.extend(descendants);
        }
        if let Some(stat) = stats.get(&pid)
            && pid != sandbox
            && stat.live
        {
            owned.push(OwnedProcess {
                pid,
                start_time: stat.start_time,
            });
        }
    }
    owned.sort_unstable();
    Ok(owned)
}

/// Signal an already-collected set under the caller's `signal_order` guard.
/// Returns whether the signal reached every live descendant.
#[cfg(target_os = "linux")]
fn apply_signal(
    processes: &[OwnedProcess],
    roots: &[u32],
    signal: nix::sys::signal::Signal,
) -> bool {
    let mut delivered = true;
    for process in processes {
        if !roots.contains(&process.pid) && !signal_owned_process(*process, signal) {
            delivered = false;
        }
    }
    delivered
}

/// Signal one scanned process through a pidfd, after confirming the pidfd
/// refers to the scanned process rather than a later process with its PID.
/// Returns whether the signal was delivered: a process that is already gone
/// counts as delivered, because there is nothing left to enforce, while an
/// attempt that could not be made — a pidfd that could not be opened for any
/// reason other than the process being gone, a stat that could not be read,
/// or a signal the kernel does not know — does not, so the enforcement gap
/// stays observable instead of being folded into "already gone".
#[cfg(target_os = "linux")]
fn signal_owned_process(process: OwnedProcess, signal: nix::sys::signal::Signal) -> bool {
    let Some(pid) = i32::try_from(process.pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return true;
    };
    let Some(signal) = rustix::process::Signal::from_named_raw(signal as i32) else {
        // A signal the kernel does not know is a programming error, not a
        // gone process.
        return false;
    };
    let pidfd = match rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) {
        Ok(pidfd) => pidfd,
        // ESRCH alone means the process is already gone; any other failure
        // (EMFILE, ENOMEM, ...) means the signal could not be attempted.
        Err(err) => return err.raw_os_error() == libc::ESRCH,
    };
    match read_proc_stat(process.pid) {
        // The pid now belongs to a different process; the replacement must
        // not be signaled.
        Ok(stat) if stat.start_time != process.start_time => true,
        Ok(_) => pidfd_send_counts_delivered(rustix::process::pidfd_send_signal(&pidfd, signal)),
        // An unreadable stat is a could-not-try unless the process is
        // already gone.
        Err(err) => err.kind() == std::io::ErrorKind::NotFound,
    }
}

/// Whether a pidfd send result counts as delivered. `ESRCH` means the
/// process exited and was reaped between the stat re-read and the send, so
/// there is nothing left to enforce; the send went through the pinned
/// pidfd, so the error cannot refer to a different process. Any other
/// failure is a real enforcement gap.
#[cfg(target_os = "linux")]
fn pidfd_send_counts_delivered(result: Result<(), rustix::io::Errno>) -> bool {
    match result {
        Ok(()) => true,
        Err(err) => err.raw_os_error() == libc::ESRCH,
    }
}

/// Test helpers shared by this crate's test modules: the comm-skipping
/// `/proc/<pid>/stat` parse lives in exactly one place, and the kill-on-drop
/// guard keeps long-lived fixtures from outliving a failed assertion.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod test_proc_stat {
    /// The `/proc/<pid>/stat` fields after the command name, which may
    /// contain spaces or parentheses. A malformed stat yields no fields.
    fn stat_fields(stat: &str) -> std::str::SplitWhitespace<'_> {
        stat.rsplit_once(") ").map_or_else(
            || "".split_whitespace(),
            |(_, fields)| fields.split_whitespace(),
        )
    }

    /// Whether the process is stopped, as a frozen workload is.
    pub fn process_stopped(pid: u32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .is_some_and(|stat| {
                stat_fields(&stat)
                    .next()
                    .is_some_and(|state| state.starts_with('T'))
            })
    }

    /// The parent of a pid, to find a workload's descendants.
    pub fn process_parent(pid: u32) -> Option<u32> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat_fields(&stat)
            .nth(1)
            .and_then(|parent| parent.parse().ok())
    }

    /// The process group of a pid, to prove a fixture keeps a descendant
    /// off its root's group.
    pub fn process_group_of(pid: u32) -> Option<u32> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat_fields(&stat)
            .nth(2)
            .and_then(|group| group.parse().ok())
    }

    /// Kills a whole process group on drop unless disarmed, so a failed
    /// assertion cannot orphan a test's long-lived sleep fixtures. Arm it
    /// with a group leader's pid — a root spawned with `process_group(0)`
    /// or a `setsid` descendant is its own group leader — and disarm it
    /// where the normal cleanup path handles the group itself.
    pub struct ProcessGroupKillGuard {
        pid: Option<u32>,
    }

    impl ProcessGroupKillGuard {
        #[must_use]
        pub fn new(pid: u32) -> Self {
            Self { pid: Some(pid) }
        }

        /// Disarm the guard: the normal cleanup path handles the group.
        pub fn disarm(&mut self) {
            self.pid = None;
        }
    }

    impl Drop for ProcessGroupKillGuard {
        fn drop(&mut self) {
            if let Some(pid) = self.pid
                && let Ok(pid) = i32::try_from(pid)
            {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
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
    #[cfg(target_os = "linux")]
    use super::test_proc_stat::{ProcessGroupKillGuard, process_group_of, process_stopped};
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
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test executor");

        assert!(runtime.freeze(executor.handle(), 1));
        assert!(matches!(
            runtime.ensure_active(),
            Err(BackendError::Unavailable(_))
        ));
        assert!(!runtime.freeze(executor.handle(), 1));
        assert!(runtime.resume(executor.handle(), 1));
        runtime.ensure_active().expect("runtime resumed");
    }

    #[test]
    fn enforcement_loss_is_terminal_after_freeze() {
        let runtime = BoundaryRuntimeState::new_exclusive_pid_namespace();
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test executor");

        assert!(runtime.freeze(executor.handle(), 1));
        assert!(runtime.begin_enforcement_loss_termination());
        assert!(runtime.enforcement_was_lost());
        assert!(!runtime.resume(executor.handle(), 1));
        assert!(matches!(
            runtime.ensure_active(),
            Err(BackendError::Terminated(_))
        ));
    }

    /// A deferred freeze sweep must not land after a resume: the batch a
    /// freeze captured is dropped once a newer transition has applied its own
    /// signals, so a descendant that was already continued stays running.
    /// This is the SIGSTOP-after-SIGCONT race a naive deferral that only
    /// spawns the sweep would introduce.
    #[cfg(target_os = "linux")]
    #[test]
    fn deferred_freeze_batch_cannot_stop_a_resumed_descendant() {
        use std::io::BufRead as _;
        use std::os::unix::process::CommandExt as _;

        let runtime = BoundaryRuntimeState::new();
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test executor");
        // The root gets its own process group, as a registered workload
        // does, and the descendant leaves it via setsid, so only the
        // deferred sweep — not the synchronous killpg — can reach it.
        let mut root = std::process::Command::new("/bin/sh")
            .args(["-c", "echo $$; setsid sleep 600 & echo $!; wait"])
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn root");
        let mut stdout = std::io::BufReader::new(root.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read root pid");
        let root_pid: u32 = line.trim().parse().expect("root pid");
        line.clear();
        stdout.read_line(&mut line).expect("read descendant pid");
        let descendant_pid: u32 = line.trim().parse().expect("descendant pid");
        assert_eq!(root_pid, root.id());
        // A failed assertion must not orphan the sleep fixtures: each guard
        // kills its whole group on drop unless disarmed for the normal
        // cleanup below.
        let mut descendant_guard = ProcessGroupKillGuard::new(descendant_pid);
        let mut root_guard = ProcessGroupKillGuard::new(root_pid);
        // The descendant separates asynchronously: `setsid` runs after the
        // fork, so wait for the split before freezing.
        let separated_by = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while process_group_of(descendant_pid) == process_group_of(root_pid) {
            assert!(
                std::time::Instant::now() < separated_by,
                "the fixture must keep the descendant off the root's process group"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        runtime
            .register_process_group(root_pid, terminal.clone(), Arc::new(Mutex::new(())))
            .expect("register root");

        // Park the freeze's deferred batch before it first acquires
        // signal_order, then resume and release it: the stale batch must be
        // dropped rather than stop the resumed descendant.
        let (release, released) = std::sync::mpsc::channel::<()>();
        let (parked_tx, parked) = std::sync::mpsc::channel::<()>();
        let freeze_generation = runtime.transition_generation.load(Ordering::Acquire) + 1;
        runtime.arm_deferred_batch_hook(
            freeze_generation,
            Box::new(move || {
                let _ = parked_tx.send(());
                let _ = released.recv_timeout(std::time::Duration::from_secs(10));
            }),
        );
        assert!(runtime.freeze(executor.handle(), 1));
        parked
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the freeze deferred its descendant batch");
        assert!(runtime.resume(executor.handle(), 1));
        release.send(()).expect("release the parked batch");

        let resumed_by = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while process_stopped(descendant_pid) {
            assert!(
                std::time::Instant::now() < resumed_by,
                "a stale freeze batch stopped the resumed descendant"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            !process_stopped(descendant_pid),
            "the resumed descendant must stay running"
        );

        // Cleanup: kill the descendant before its root so nothing outlives
        // the test.
        descendant_guard.disarm();
        root_guard.disarm();
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(descendant_pid).unwrap()),
            nix::sys::signal::SIGKILL,
        );
        terminal.store(true, Ordering::Release);
        let _ = root.kill();
        let _ = root.wait();
    }

    /// A deferred freeze batch must also be dropped after a terminal
    /// transition: `begin_termination` bumps the transition generation while
    /// it applies SIGCONT then SIGTERM, so a stale SIGSTOP cannot land on a
    /// descendant that survived the terminal signals. Both the root and the
    /// descendant ignore SIGTERM so they survive termination; SIGSTOP cannot
    /// be ignored, so a batch that leaked through would still be observable.
    #[cfg(target_os = "linux")]
    #[test]
    fn deferred_freeze_batch_cannot_stop_a_descendant_after_termination() {
        use std::io::BufRead as _;
        use std::os::unix::process::CommandExt as _;

        let runtime = BoundaryRuntimeState::new();
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test executor");
        let armed = tempfile::tempdir().expect("trap marker directory");
        let armed_path = armed.path().join("trap-armed");
        let mut root = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                &format!(
                    "trap '' TERM; echo $$; setsid sh -c 'trap \"\" TERM; touch {armed}; \
                     while :; do sleep 3600; done' & echo $!; wait",
                    armed = armed_path.display(),
                ),
            ])
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn root");
        let mut stdout = std::io::BufReader::new(root.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read root pid");
        let root_pid: u32 = line.trim().parse().expect("root pid");
        line.clear();
        stdout.read_line(&mut line).expect("read descendant pid");
        let descendant_pid: u32 = line.trim().parse().expect("descendant pid");
        assert_eq!(root_pid, root.id());
        // A failed assertion must not orphan the sleep fixtures: each guard
        // kills its whole group on drop unless disarmed for the normal
        // cleanup below.
        let mut descendant_guard = ProcessGroupKillGuard::new(descendant_pid);
        let mut root_guard = ProcessGroupKillGuard::new(root_pid);
        // The descendant must have its trap armed and its own process group
        // before the terminal transition runs, so it survives SIGTERM and
        // only the deferred sweep — not the synchronous killpg — can stop it.
        let ready_by = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !armed_path.exists() || process_group_of(descendant_pid) == process_group_of(root_pid)
        {
            assert!(
                std::time::Instant::now() < ready_by,
                "the fixture must arm the descendant's trap and split its process group"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        runtime
            .register_process_group(root_pid, terminal.clone(), Arc::new(Mutex::new(())))
            .expect("register root");

        // Park the freeze's deferred batch before it first acquires
        // signal_order, run the terminal transition, then release it: the
        // stale batch must be dropped rather than stop a descendant that
        // survived the terminal signals.
        let (release, released) = std::sync::mpsc::channel::<()>();
        let (parked_tx, parked) = std::sync::mpsc::channel::<()>();
        let freeze_generation = runtime.transition_generation.load(Ordering::Acquire) + 1;
        runtime.arm_deferred_batch_hook(
            freeze_generation,
            Box::new(move || {
                let _ = parked_tx.send(());
                let _ = released.recv_timeout(std::time::Duration::from_secs(10));
            }),
        );
        assert!(runtime.freeze(executor.handle(), 1));
        parked
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the freeze deferred its descendant batch");
        assert!(runtime.begin_termination());
        release.send(()).expect("release the parked batch");

        let running_by = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while process_stopped(descendant_pid) {
            assert!(
                std::time::Instant::now() < running_by,
                "a stale freeze batch stopped a descendant that survived termination"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            !process_stopped(descendant_pid),
            "the surviving descendant must stay running"
        );

        // Cleanup: kill the descendant's whole group before its root so
        // nothing outlives the test.
        descendant_guard.disarm();
        root_guard.disarm();
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(i32::try_from(descendant_pid).unwrap()),
            nix::sys::signal::Signal::SIGKILL,
        );
        terminal.store(true, Ordering::Release);
        let _ = root.kill();
        let _ = root.wait();
    }

    /// A terminal signal must reach the registered groups before the first
    /// `/proc` descendant collect, not behind it: the canonical workload
    /// processes would otherwise keep running for the length of a scan on
    /// every teardown. This parks the first collect and asserts the
    /// registered root is already stopped while the scan has not returned.
    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_group_signal_precedes_the_first_descendant_collect() {
        use std::io::BufRead as _;
        use std::os::unix::process::CommandExt as _;

        let runtime = BoundaryRuntimeState::new();
        let mut root = std::process::Command::new("/bin/sh")
            .args(["-c", "echo ready; sleep 600"])
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn root");
        let mut line = String::new();
        std::io::BufReader::new(root.stdout.take().unwrap())
            .read_line(&mut line)
            .expect("read root ready line");
        assert_eq!(line.trim(), "ready");
        let terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        runtime
            .register_process_group(root.id(), terminal.clone(), Arc::new(Mutex::new(())))
            .expect("register root");

        let (parked_tx, parked) = std::sync::mpsc::channel::<()>();
        let (release, released) = std::sync::mpsc::channel::<()>();
        runtime.arm_collect_hook(Box::new(move || {
            let _ = parked_tx.send(());
            let _ = released.recv_timeout(std::time::Duration::from_secs(10));
        }));
        let signaler = {
            let runtime = Arc::clone(&runtime);
            std::thread::spawn(move || {
                runtime.signal_registered_processes(nix::sys::signal::Signal::SIGSTOP);
            })
        };
        parked
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the terminal path reached its first descendant collect");

        let stopped_by = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !process_stopped(root.id()) {
            assert!(
                std::time::Instant::now() < stopped_by,
                "the registered group must be signaled before the first descendant collect returns"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        release.send(()).expect("release the parked collect");
        signaler.join().expect("terminal signaling finished");

        // Cleanup: continue then kill the root so nothing outlives the test.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(root.id()).unwrap()),
            nix::sys::signal::Signal::SIGCONT,
        );
        terminal.store(true, Ordering::Release);
        let _ = root.kill();
        let _ = root.wait();
    }

    /// `kthreadd` and its kernel-thread children, when `/proc` shows them
    /// and we do not own them: the subtree is live, scannable, and refuses
    /// our signals with `EPERM`, the one real send failure reachable
    /// without a fault-injection seam. Returns `None` when running as root
    /// or inside a PID namespace that hides kernel threads, where the
    /// failure cannot be reproduced.
    #[cfg(target_os = "linux")]
    fn kernel_thread_root() -> Option<u32> {
        if rustix::process::geteuid().is_root() {
            return None;
        }
        let stat = std::fs::read_to_string("/proc/2/stat").ok()?;
        let comm = stat.split_once('(')?.1.split_once(')')?.0;
        if comm != "kthreadd" {
            return None;
        }
        // A live descendant must exist for a sweep to attempt a signal.
        let live_descendants = std::fs::read_dir("/proc")
            .ok()?
            .flatten()
            .filter_map(|entry| {
                let pid = entry.file_name().to_str()?.parse::<u32>().ok()?;
                let stat = read_proc_stat(pid).ok()?;
                (stat.parent == 2 && stat.live).then_some(pid)
            })
            .count();
        (live_descendants > 0).then_some(2)
    }

    /// A deferred sweep that cannot signal a live descendant must report the
    /// failure as a low-severity OCSF process event naming the recovery the
    /// sweep belongs to, dual-emitted as a Medium detection finding. The
    /// sweep runs on the test thread because the OCSF
    /// capture is a thread-local subscriber; its inputs are the ones the
    /// freeze path passes. Every send against the kernel-thread subtree
    /// fails with `EPERM` before any signal is queued, so nothing on the
    /// machine is affected.
    #[cfg(target_os = "linux")]
    #[test]
    fn failed_deferred_sweep_reports_the_recovery_id() {
        const RECOVERY_ID: u64 = 4242;
        let Some(root) = kernel_thread_root() else {
            return;
        };
        let runtime = BoundaryRuntimeState::new();
        let terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        runtime
            .register_process_group(root, terminal.clone(), Arc::new(Mutex::new(())))
            .expect("register kernel-thread root");
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _capture = capture.install();
        let generation = runtime.transition_generation.load(Ordering::Acquire);
        runtime.deferred_descendant_sweep(
            generation,
            nix::sys::signal::Signal::SIGWINCH,
            RECOVERY_ID,
        );

        let events = capture.events();
        let failures = events
            .iter()
            .filter(|event| {
                event.base().message.as_deref().is_some_and(|message| {
                    message.starts_with("deferred descendant sweep failed to apply")
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(failures.len(), 1, "one failure event: {events:?}");
        let failure = failures[0];
        assert_eq!(failure.class_uid(), 1007, "a process activity event");
        assert_eq!(failure.base().severity, openshell_ocsf::SeverityId::Low);
        assert_eq!(
            failure.base().status,
            Some(openshell_ocsf::StatusId::Failure)
        );
        let message = failure.base().message.as_deref().expect("message");
        assert!(
            message.contains("[recovery_id:4242]"),
            "the failure must name its recovery: {message}"
        );
        // The same gap is dual-emitted as a detection finding, as every
        // security finding is.
        let findings = events
            .iter()
            .filter(|event| {
                event.base().message.as_deref().is_some_and(|message| {
                    message.starts_with("deferred descendant sweep enforcement gap")
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(findings.len(), 1, "one detection finding: {events:?}");
        let finding = findings[0];
        assert_eq!(finding.class_uid(), 2004, "a detection finding event");
        assert_eq!(finding.base().severity, openshell_ocsf::SeverityId::Medium);
        let finding_message = finding.base().message.as_deref().expect("finding message");
        assert!(
            finding_message.contains("[recovery_id:4242]"),
            "the finding must name its recovery: {finding_message}"
        );
        runtime.unregister_process_group(root, &terminal);
    }

    /// A sweep whose descendant vanished before it applied must not report a
    /// failure: a process that is already gone counts as delivered, because
    /// there is nothing left to enforce. The kept in-group descendant proves
    /// the sweep really applied its signal.
    #[cfg(target_os = "linux")]
    #[test]
    fn deferred_sweep_of_a_vanished_descendant_reports_no_failure() {
        use std::io::BufRead as _;
        use std::os::unix::process::CommandExt as _;

        let runtime = BoundaryRuntimeState::new();
        // One descendant leaves the root's process group and is killed before
        // the sweep runs; one stays in it and must be stopped by the sweep.
        let mut root = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                "echo $$; setsid sleep 600 & echo $!; sleep 900 & echo $!; wait",
            ])
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn root");
        let mut stdout = std::io::BufReader::new(root.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read root pid");
        let root_pid: u32 = line.trim().parse().expect("root pid");
        line.clear();
        stdout.read_line(&mut line).expect("read detached pid");
        let detached_pid: u32 = line.trim().parse().expect("detached pid");
        line.clear();
        stdout.read_line(&mut line).expect("read kept pid");
        let kept_pid: u32 = line.trim().parse().expect("kept pid");
        assert_eq!(root_pid, root.id());
        // A failed assertion must not orphan the sleep fixtures: the root
        // guard covers the kept in-group descendant, the detached guard the
        // setsid one, and each is disarmed where the normal cleanup path
        // handles its group.
        let mut detached_guard = ProcessGroupKillGuard::new(detached_pid);
        let mut root_guard = ProcessGroupKillGuard::new(root_pid);
        let separated_by = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while process_group_of(detached_pid) == process_group_of(root_pid) {
            assert!(
                std::time::Instant::now() < separated_by,
                "the fixture must keep the detached descendant off the root's process group"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        runtime
            .register_process_group(root_pid, terminal.clone(), Arc::new(Mutex::new(())))
            .expect("register root");

        detached_guard.disarm();
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(detached_pid).unwrap()),
            nix::sys::signal::Signal::SIGKILL,
        );
        // The root reaps it through `wait`; a lingering zombie is equally
        // unenforceable and must not count as a failure either.
        let reaped_by = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while read_proc_stat(detached_pid).is_ok_and(|stat| stat.live) {
            assert!(
                std::time::Instant::now() < reaped_by,
                "the killed descendant must not stay live"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _capture = capture.install();
        let generation = runtime.transition_generation.load(Ordering::Acquire);
        runtime.deferred_descendant_sweep(generation, nix::sys::signal::Signal::SIGSTOP, 7);
        assert!(
            capture.events().iter().all(|event| {
                !event.base().message.as_deref().is_some_and(|message| {
                    message.starts_with("deferred descendant sweep failed to apply")
                })
            }),
            "a vanished descendant must not report a sweep failure"
        );
        assert!(
            process_stopped(kept_pid),
            "the sweep must have stopped the kept descendant"
        );

        // Cleanup: the stopped in-group descendant dies with its root's group.
        root_guard.disarm();
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(i32::try_from(root_pid).unwrap()),
            nix::sys::signal::Signal::SIGKILL,
        );
        terminal.store(true, Ordering::Release);
        let _ = root.kill();
        let _ = root.wait();
    }

    /// A process that is already gone when the sweep applies its signal
    /// counts as delivered — a pid that no longer resolves, a pid reused by
    /// a different process, and a pid that cannot be parsed — because there
    /// is nothing left to enforce, so no failure may be reported.
    #[cfg(target_os = "linux")]
    #[test]
    fn signal_accounting_counts_a_gone_process_as_delivered() {
        let mut gone = std::process::Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .expect("spawn gone process");
        let gone_pid = gone.id();
        let gone_start = read_proc_stat(gone_pid)
            .expect("read gone process stat")
            .start_time;
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(gone_pid).unwrap()),
            nix::sys::signal::Signal::SIGKILL,
        );
        gone.wait().expect("reap gone process");
        let vanished_by = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while read_proc_stat(gone_pid).is_ok_and(|stat| stat.live) {
            assert!(
                std::time::Instant::now() < vanished_by,
                "the killed process must leave /proc"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // The pid no longer resolves to a live process.
        assert!(signal_owned_process(
            OwnedProcess {
                pid: gone_pid,
                start_time: gone_start,
            },
            nix::sys::signal::Signal::SIGSTOP
        ));
        // A pid that cannot be represented is vacuously delivered.
        assert!(signal_owned_process(
            OwnedProcess {
                pid: u32::MAX,
                start_time: gone_start,
            },
            nix::sys::signal::Signal::SIGSTOP
        ));
        // The whole collected set counts as delivered through apply_signal.
        assert!(apply_signal(
            &[OwnedProcess {
                pid: gone_pid,
                start_time: gone_start,
            }],
            &[],
            nix::sys::signal::Signal::SIGSTOP
        ));

        // A reused pid keeps its own start time; the stale identity must not
        // be signaled, so the live replacement is unaffected.
        let mut replacement = std::process::Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .expect("spawn replacement");
        let replacement_start = read_proc_stat(replacement.id())
            .expect("read replacement stat")
            .start_time;
        assert!(signal_owned_process(
            OwnedProcess {
                pid: replacement.id(),
                start_time: replacement_start.wrapping_add(1),
            },
            nix::sys::signal::Signal::SIGSTOP
        ));
        assert!(
            !process_stopped(replacement.id()),
            "a stale identity must not be signaled"
        );
        let _ = replacement.kill();
        let _ = replacement.wait();
    }

    /// Only a failed send against a validated live process counts as
    /// undelivered: a harmless signal to our own live process is delivered,
    /// and the `EPERM` the kernel-thread subtree returns for our signal is
    /// not, which is what feeds the sweep's failure event.
    #[cfg(target_os = "linux")]
    #[test]
    fn signal_accounting_counts_only_a_failed_send_as_undelivered() {
        let mut live = std::process::Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .expect("spawn live process");
        let live_stat = read_proc_stat(live.id()).expect("read live stat");
        // SIGWINCH is ignored by default: a real, harmless delivery.
        assert!(signal_owned_process(
            OwnedProcess {
                pid: live.id(),
                start_time: live_stat.start_time,
            },
            nix::sys::signal::Signal::SIGWINCH
        ));
        assert!(
            live.try_wait().expect("check live process").is_none(),
            "the delivered signal must have been harmless"
        );
        let _ = live.kill();
        let _ = live.wait();

        let Some(root) = kernel_thread_root() else {
            return;
        };
        let root_stat = read_proc_stat(root).expect("read kthreadd stat");
        let kernel_thread = OwnedProcess {
            pid: root,
            start_time: root_stat.start_time,
        };
        assert!(
            !signal_owned_process(kernel_thread, nix::sys::signal::Signal::SIGWINCH),
            "an EPERM send against a live process is undelivered"
        );
        assert!(
            !apply_signal(&[kernel_thread], &[], nix::sys::signal::Signal::SIGWINCH),
            "the failed send must fail the whole collected set"
        );
    }

    /// A send that returns `ESRCH` means the process was reaped between the
    /// stat re-read and the send, so it counts as delivered: the window
    /// cannot be hit deterministically through `signal_owned_process` (a
    /// reaped process's stat re-read is `NotFound` first), so the send-error
    /// classification is asserted directly.
    #[cfg(target_os = "linux")]
    #[test]
    fn signal_accounting_counts_a_reaped_process_send_as_delivered() {
        assert!(pidfd_send_counts_delivered(Ok(())));
        assert!(pidfd_send_counts_delivered(Err(rustix::io::Errno::SRCH)));
        assert!(!pidfd_send_counts_delivered(Err(rustix::io::Errno::PERM)));
        assert!(!pidfd_send_counts_delivered(Err(rustix::io::Errno::MFILE)));
    }

    /// A terminal collect error must not be swallowed as an empty scan: with
    /// the file-descriptor limit lowered to zero, `/proc` cannot be read
    /// (`EMFILE`), so every collect attempt fails and the terminal path must
    /// report the failure instead of treating the descendant set as
    /// converged-empty. The limit is process-wide, so the scenario runs in a
    /// fresh copy of the test binary, as the subreaper teardown test does.
    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_collect_error_is_reported_not_swallowed() {
        use nix::sys::resource::{Resource, getrlimit, setrlimit};
        use std::os::unix::process::CommandExt as _;

        const CHILD_MARKER: &str = "OPENSHELL_TERMINAL_COLLECT_EMFILE_CHILD";
        if std::env::var_os(CHILD_MARKER).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "boundary_io::tests::terminal_collect_error_is_reported_not_swallowed",
                    "--nocapture",
                ])
                .env(CHILD_MARKER, "1")
                .status()
                .expect("run isolated terminal collect test");
            assert!(status.success(), "isolated terminal collect test failed");
            return;
        }

        let runtime = BoundaryRuntimeState::new();
        let mut root = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 600"])
            .process_group(0)
            .spawn()
            .expect("spawn root");
        let _root_guard = ProcessGroupKillGuard::new(root.id());
        runtime
            .register_process_group(
                root.id(),
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
                Arc::new(Mutex::new(())),
            )
            .expect("register root");

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _capture = capture.install();
        let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).expect("read descriptor limit");
        setrlimit(Resource::RLIMIT_NOFILE, 0, hard).expect("lower descriptor limit");
        runtime.deactivate();
        setrlimit(Resource::RLIMIT_NOFILE, soft, hard).expect("restore descriptor limit");
        assert!(
            capture.events().iter().any(|event| {
                event.base().message.as_deref().is_some_and(|message| {
                    message.starts_with("terminal descendant signaling failed to apply")
                })
            }),
            "a terminal collect error must be reported, not swallowed as an empty scan"
        );
        let _ = root.wait();
    }

    /// A signal that could not even be attempted must not be folded into the
    /// "already gone" classification: with the file-descriptor limit lowered
    /// to zero, the pidfd for a live process cannot be opened (`EMFILE`), so
    /// the attempt counts as undelivered and the gap stays observable. The
    /// limit is process-wide, so the scenario runs in a fresh copy of the
    /// test binary, as the subreaper teardown test does.
    #[cfg(target_os = "linux")]
    #[test]
    fn signal_accounting_counts_a_could_not_try_as_undelivered() {
        use nix::sys::resource::{Resource, getrlimit, setrlimit};

        const CHILD_MARKER: &str = "OPENSHELL_SIGNAL_EMFILE_CHILD";
        if std::env::var_os(CHILD_MARKER).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "boundary_io::tests::signal_accounting_counts_a_could_not_try_as_undelivered",
                    "--nocapture",
                ])
                .env(CHILD_MARKER, "1")
                .status()
                .expect("run isolated emfile test");
            assert!(status.success(), "isolated emfile test failed");
            return;
        }

        let mut live = std::process::Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .expect("spawn live process");
        let stat = read_proc_stat(live.id()).expect("read live stat");
        let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).expect("read descriptor limit");
        setrlimit(Resource::RLIMIT_NOFILE, 0, hard).expect("lower descriptor limit");
        let delivered = signal_owned_process(
            OwnedProcess {
                pid: live.id(),
                start_time: stat.start_time,
            },
            nix::sys::signal::Signal::SIGWINCH,
        );
        setrlimit(Resource::RLIMIT_NOFILE, soft, hard).expect("restore descriptor limit");
        assert!(
            !delivered,
            "a pidfd that could not be opened must count as undelivered"
        );
        let _ = live.kill();
        let _ = live.wait();
    }
}
