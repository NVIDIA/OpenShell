// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded log of launch and exit events for the workload processes this
//! runtime starts, and of execs in the workload when the supervisor asks for
//! them, read by the supervisor with a sequence cursor.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::linux::seccomp_notify::{Notification, NotificationListener};
use openshell_isolation_interface::contract::ProcessInstance;
use openshell_sandbox_backend::boundary_protocol::{
    ExitStatusWire, ProcessEventKindWire, ProcessEventWire,
};

const CAPACITY: usize = 4096;
/// Most events in one response.
pub const MAX_READ: usize = 256;
/// Encoded size one response stays under, half the control message limit.
const MAX_READ_BYTES: usize = 512 * 1024;
/// How long a read with nothing to return waits for an event.
pub const READ_WAIT: Duration = Duration::from_secs(30);
/// Execs recorded back to back before the rate applies.
const EXEC_BURST: u64 = 500;
/// Execs recorded per second once the burst is spent.
const EXEC_RATE_PER_SECOND: u64 = 200;
/// Shortest time between two reports of suppressed execs.
const SUPPRESSED_REPORT_INTERVAL: Duration = Duration::from_secs(1);
/// Execs waiting for their files to be looked up.
const EXEC_QUEUE: usize = 256;

static LOG: LazyLock<ProcessEventLog> =
    LazyLock::new(|| ProcessEventLog::with_exec_rate(CAPACITY, EXEC_BURST, EXEC_RATE_PER_SECOND));
static RECORD_EXECUTIONS: AtomicBool = AtomicBool::new(false);

/// The runtime's process event log.
pub fn log() -> &'static ProcessEventLog {
    &LOG
}

/// A launch recorded in the log, kept until the runtime reaps the process.
pub struct Launched {
    process: ProcessInstance,
    executable: String,
}

/// Record the launch of a process the runtime just spawned from `program`.
/// `None` when procfs no longer reports it.
pub fn record_launch(pid: u32, program: &str) -> Option<Launched> {
    let Some(process) = openshell_binary_identity::observe_process(pid) else {
        tracing::warn!(
            pid,
            "process not visible in procfs; launch and exit not recorded"
        );
        return None;
    };
    // A process that already exited has no readable executable link.
    let executable = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map_or_else(|_| program.to_string(), |path| path.display().to_string());
    log().record(process, &executable, ProcessEventKindWire::Launched);
    Some(Launched {
        process,
        executable,
    })
}

impl Launched {
    pub fn record_exit(&self, status: ExitStatusWire) {
        log().record(
            self.process,
            &self.executable,
            ProcessEventKindWire::Exited(status),
        );
    }
}

/// Whether the supervisor asked for each exec in the workload.
pub fn records_executions() -> bool {
    RECORD_EXECUTIONS.load(Ordering::Acquire)
}

/// Apply the supervisor's latest choice of recording each exec.
pub fn set_record_executions(record: bool) {
    RECORD_EXECUTIONS.store(record, Ordering::Release);
}

/// Record the exec a workload thread is about to make, then let it proceed.
///
/// Recording is best effort and never changes the outcome of the exec. The
/// file lookups run on their own thread so a slow filesystem cannot stall
/// the broker; an exec that finds that thread behind is counted as
/// suppressed.
pub fn observe_exec(
    listener: &Arc<NotificationListener>,
    notification: Notification,
) -> io::Result<()> {
    if !records_executions() {
        return listener.respond_continue(notification.id);
    }
    let queued = exec_observer().is_some_and(|observer| {
        observer
            .try_send((Arc::clone(listener), notification))
            .is_ok()
    });
    if queued {
        return Ok(());
    }
    log().suppress_exec();
    listener.respond_continue(notification.id)
}

type PendingExec = (Arc<NotificationListener>, Notification);

fn exec_observer() -> Option<&'static SyncSender<PendingExec>> {
    static OBSERVER: LazyLock<Option<SyncSender<PendingExec>>> = LazyLock::new(|| {
        let (sender, pending) = mpsc::sync_channel::<PendingExec>(EXEC_QUEUE);
        std::thread::Builder::new()
            .name("openshell-exec-observer".to_string())
            .spawn(move || {
                for (listener, notification) in pending {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        record_requested_exec(&listener, notification);
                    }));
                    let _ = listener.respond_continue(notification.id);
                }
            })
            .inspect_err(|error| tracing::warn!(%error, "exec observer did not start"))
            .ok()?;
        Some(sender)
    });
    OBSERVER.as_ref()
}

fn record_requested_exec(listener: &NotificationListener, notification: Notification) {
    let Some(exec) = requested_exec(&notification) else {
        return;
    };
    let pidfd = rustix::process::Pid::from_raw(exec.process.pid.cast_signed()).and_then(|pid| {
        rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).ok()
    });
    // The procfs reads and the pidfd describe this caller only if it is still
    // blocked in the same notification.
    if listener.validate_id(notification.id).is_err() || is_runtime_spawn(&exec) {
        return;
    }
    let recorded = log().record_exec(
        exec.process,
        &exec.executable,
        ProcessEventKindWire::Executed {
            previous_executable: exec.previous_executable,
            parent_executable: exec.parent_executable,
        },
    );
    if !recorded {
        return;
    }
    match pidfd {
        Some(pidfd) => crate::process_exits::watch(log(), exec.process, exec.executable, pidfd),
        // No exit can be recorded without a descriptor.
        None => log().suppress_exec(),
    }
}

struct RequestedExec {
    process: ProcessInstance,
    executable: String,
    previous_executable: String,
    parent_executable: String,
}

/// The process making an exec and the file it names. `None` when the file
/// does not exist or is not executable, so the exec will fail, or when
/// procfs no longer reports the caller. A file that cannot be resolved is
/// named as the caller gave it.
fn requested_exec(notification: &Notification) -> Option<RequestedExec> {
    let tid = notification.tid;
    let (dirfd, path_address, flags) = if i64::from(notification.syscall) == libc::SYS_execveat {
        (
            u32::try_from(notification.args[0] & u64::from(u32::MAX))
                .ok()?
                .cast_signed(),
            notification.args[1],
            notification.args[4],
        )
    } else {
        (libc::AT_FDCWD, notification.args[0], 0)
    };
    let path = crate::provider_files::read_path_bytes(tid, path_address).ok()?;
    let process = openshell_binary_identity::observe_process(tid)?;
    let executable = if path.is_empty()
        && flags & u64::from(libc::AT_EMPTY_PATH.unsigned_abs()) != 0
    {
        // An exec of an open descriptor, which can name a deleted or memory
        // file that has no path to resolve.
        std::fs::read_link(format!("/proc/{tid}/fd/{dirfd}")).ok()?
    } else {
        let lookup = lookup_path(tid, process.pid, dirfd, &path);
        match std::fs::metadata(&lookup) {
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => {
                return None;
            }
            Ok(metadata) if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 => {
                return None;
            }
            _ => {}
        }
        std::fs::canonicalize(&lookup)
            .or_else(|_| std::fs::read_link(&lookup))
            .unwrap_or_else(|_| PathBuf::from(OsString::from_vec(path)))
    };
    Some(RequestedExec {
        executable: executable.display().to_string(),
        previous_executable: executable_of(process.pid),
        parent_executable: executable_of(process.parent_pid),
        process,
    })
}

/// Where the runtime finds the file `tid` names, with the caller's own
/// procfs entries in place of the runtime's.
fn lookup_path(tid: u32, pid: u32, dirfd: i32, path: &[u8]) -> PathBuf {
    let own = (
        path.strip_prefix(b"/proc/self/"),
        path.strip_prefix(b"/proc/thread-self/"),
    );
    let (base, rest) = match own {
        (Some(rest), _) => (format!("/proc/{tid}/root/proc/{pid}/"), rest),
        (_, Some(rest)) => (format!("/proc/{tid}/root/proc/{pid}/task/{tid}/"), rest),
        _ if path.starts_with(b"/") => (format!("/proc/{tid}/root"), path),
        _ if dirfd == libc::AT_FDCWD => (format!("/proc/{tid}/cwd/"), path),
        _ => (format!("/proc/{tid}/fd/{dirfd}/"), path),
    };
    let mut lookup = base.into_bytes();
    lookup.extend_from_slice(rest);
    PathBuf::from(OsString::from_vec(lookup))
}

fn executable_of(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .map(|path| path.display().to_string())
        .unwrap_or_default()
}

/// This runtime process and its executable.
fn runtime() -> &'static (ProcessInstance, String) {
    static RUNTIME: LazyLock<(ProcessInstance, String)> = LazyLock::new(|| {
        let pid = std::process::id();
        let process = openshell_binary_identity::observe_process(pid).unwrap_or(ProcessInstance {
            pid,
            parent_pid: 0,
            start_time_ms: 0,
        });
        (process, executable_of(pid))
    });
    &RUNTIME
}

static RUNTIME_SPAWNS: AtomicUsize = AtomicUsize::new(0);

/// Run `spawn`, during which the runtime's own children are not recorded
/// as workload execs.
pub fn runtime_spawn<T>(spawn: impl FnOnce() -> T) -> T {
    struct Spawning;
    impl Drop for Spawning {
        fn drop(&mut self) {
            RUNTIME_SPAWNS.fetch_sub(1, Ordering::AcqRel);
        }
    }
    RUNTIME_SPAWNS.fetch_add(1, Ordering::AcqRel);
    let _spawning = Spawning;
    spawn()
}

/// A child the runtime forked to start a session, before its exec. The
/// session's launch is recorded when the spawn returns.
fn is_runtime_spawn(exec: &RequestedExec) -> bool {
    let (runtime, executable) = runtime();
    RUNTIME_SPAWNS.load(Ordering::Acquire) > 0
        && exec.process.parent_pid == runtime.pid
        && exec.previous_executable == *executable
}

pub struct ProcessEventLog {
    capacity: usize,
    exec_rate_per_second: u64,
    suppressed_report_interval: Duration,
    state: Mutex<State>,
    changed: Condvar,
}

struct State {
    events: VecDeque<ProcessEventWire>,
    next_sequence: u64,
    exec_tokens: ExecTokens,
    suppressed: u64,
    suppressed_reported: Option<Instant>,
}

/// Token bucket bounding how many execs the log records.
struct ExecTokens {
    available: u64,
    burst: u64,
    refilled: Instant,
}

impl ExecTokens {
    fn take(&mut self, rate_per_second: u64) -> bool {
        let now = Instant::now();
        let earned = u64::try_from(
            now.duration_since(self.refilled).as_millis() * u128::from(rate_per_second) / 1000,
        )
        .unwrap_or(u64::MAX);
        if earned > 0 {
            self.available = self.available.saturating_add(earned).min(self.burst);
            self.refilled = now;
        }
        let available = self.available > 0;
        if available {
            self.available -= 1;
        }
        available
    }
}

impl ProcessEventLog {
    #[cfg(test)]
    pub fn new(capacity: usize) -> Self {
        Self::with_exec_rate(capacity, EXEC_BURST, EXEC_RATE_PER_SECOND)
    }

    fn with_exec_rate(capacity: usize, burst: u64, rate_per_second: u64) -> Self {
        Self {
            capacity,
            exec_rate_per_second: rate_per_second,
            suppressed_report_interval: SUPPRESSED_REPORT_INTERVAL,
            state: Mutex::new(State {
                events: VecDeque::new(),
                next_sequence: 1,
                exec_tokens: ExecTokens {
                    available: burst,
                    burst,
                    refilled: Instant::now(),
                },
                suppressed: 0,
                suppressed_reported: None,
            }),
            changed: Condvar::new(),
        }
    }

    #[cfg(test)]
    fn reporting_suppressed_every(mut self, interval: Duration) -> Self {
        self.suppressed_report_interval = interval;
        self
    }

    pub fn record(&self, process: ProcessInstance, executable: &str, kind: ProcessEventKindWire) {
        let mut state = self.lock();
        self.push(&mut state, process, executable.to_string(), kind);
        drop(state);
        self.changed.notify_all();
    }

    /// Record an exec unless execs exceed the log's rate, in which case it is
    /// counted and reported as suppressed on a later read. Whether it was
    /// recorded.
    pub fn record_exec(
        &self,
        process: ProcessInstance,
        executable: &str,
        kind: ProcessEventKindWire,
    ) -> bool {
        let mut state = self.lock();
        if state.exec_tokens.take(self.exec_rate_per_second) {
            self.push(&mut state, process, executable.to_string(), kind);
            drop(state);
            self.changed.notify_all();
            true
        } else {
            self.count_suppressed(state);
            false
        }
    }

    /// Count an exec that goes unrecorded.
    pub fn suppress_exec(&self) {
        self.count_suppressed(self.lock());
    }

    fn count_suppressed(&self, mut state: std::sync::MutexGuard<'_, State>) {
        state.suppressed = state.suppressed.saturating_add(1);
        let first = state.suppressed == 1;
        drop(state);
        // A waiting read only needs to learn when its report is due.
        if first {
            self.changed.notify_all();
        }
    }

    fn push(
        &self,
        state: &mut State,
        process: ProcessInstance,
        executable: String,
        kind: ProcessEventKindWire,
    ) {
        let time_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
            .unwrap_or_default();
        let sequence = state.next_sequence;
        state.next_sequence += 1;
        if state.events.len() == self.capacity {
            state.events.pop_front();
        }
        state.events.push_back(ProcessEventWire {
            sequence,
            process,
            executable,
            kind,
            time_ms,
        });
    }

    /// Up to `max` events after `after` that fit the response budget, and how
    /// many events after `after` were evicted. Waits up to `wait` when there
    /// is nothing to return.
    pub fn read(&self, after: u64, max: usize, wait: Duration) -> (Vec<ProcessEventWire>, u64) {
        let started = Instant::now();
        let mut state = self.lock();
        loop {
            let now = Instant::now();
            let report_in = self.suppressed_report_in(&state, now);
            if report_in == Some(Duration::ZERO) {
                self.report_suppressed(&mut state, now);
            }
            let remaining = wait.saturating_sub(now.duration_since(started));
            if state.next_sequence > after.saturating_add(1) || remaining.is_zero() {
                break;
            }
            let timeout = report_in
                .filter(|report_in| !report_in.is_zero())
                .map_or(remaining, |report_in| report_in.min(remaining));
            state = self
                .changed
                .wait_timeout(state, timeout)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        let first = state
            .events
            .front()
            .map_or(state.next_sequence, |event| event.sequence);
        let lost = first.saturating_sub(after.saturating_add(1));
        let mut budget = MAX_READ_BYTES;
        let events = state
            .events
            .iter()
            .filter(|event| event.sequence > after)
            .take(max)
            .enumerate()
            .take_while(|(index, event)| {
                let size = encoded_size(event);
                let fits = *index == 0 || size <= budget;
                budget = budget.saturating_sub(size);
                fits
            })
            .map(|(_, event)| event.clone())
            .collect();
        (events, lost)
    }

    /// How long until suppressed execs are due to be reported, `None` when
    /// there are none.
    fn suppressed_report_in(&self, state: &State, now: Instant) -> Option<Duration> {
        (state.suppressed > 0).then(|| {
            state
                .suppressed_reported
                .map_or(Duration::ZERO, |reported| {
                    self.suppressed_report_interval
                        .saturating_sub(now.duration_since(reported))
                })
        })
    }

    fn report_suppressed(&self, state: &mut State, now: Instant) {
        let count = std::mem::take(&mut state.suppressed);
        state.suppressed_reported = Some(now);
        let (runtime, executable) = runtime();
        self.push(
            state,
            *runtime,
            executable.clone(),
            ProcessEventKindWire::Suppressed { count },
        );
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// An upper bound on one event's encoded size.
fn encoded_size(event: &ProcessEventWire) -> usize {
    let previous = match &event.kind {
        ProcessEventKindWire::Executed {
            previous_executable,
            parent_executable,
        } => previous_executable.len() + parent_executable.len(),
        _ => 0,
    };
    event.executable.len() + previous + 128
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn process(pid: u32) -> ProcessInstance {
        ProcessInstance {
            pid,
            parent_pid: 1,
            start_time_ms: 1_000,
        }
    }

    #[test]
    fn read_returns_events_after_the_cursor_in_order() {
        let log = ProcessEventLog::new(8);
        log.record(process(10), "/bin/sh", ProcessEventKindWire::Launched);
        log.record(
            process(10),
            "/bin/sh",
            ProcessEventKindWire::Exited(ExitStatusWire::Exited(3)),
        );
        log.record(process(11), "/bin/true", ProcessEventKindWire::Launched);

        let (events, lost) = log.read(1, MAX_READ, Duration::ZERO);
        assert_eq!(lost, 0);
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            [2, 3]
        );
        assert_eq!(
            events[0].kind,
            ProcessEventKindWire::Exited(ExitStatusWire::Exited(3))
        );
        assert_eq!(events[1].process.pid, 11);

        let (events, _) = log.read(0, 1, Duration::ZERO);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sequence, 1);
    }

    #[test]
    fn evicted_events_after_the_cursor_are_counted_as_lost() {
        let log = ProcessEventLog::new(2);
        for pid in 1..=5 {
            log.record(process(pid), "/bin/true", ProcessEventKindWire::Launched);
        }

        let (events, lost) = log.read(1, MAX_READ, Duration::ZERO);
        assert_eq!(lost, 2);
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            [4, 5]
        );
        let (_, lost) = log.read(4, MAX_READ, Duration::ZERO);
        assert_eq!(lost, 0);
    }

    #[test]
    fn a_read_stops_before_the_response_byte_budget() {
        let log = ProcessEventLog::new(MAX_READ);
        let path = format!("/{}", "a".repeat(4095));
        for pid in 1..=u32::try_from(MAX_READ).unwrap() {
            log.record(process(pid), &path, ProcessEventKindWire::Launched);
        }

        let (events, _) = log.read(0, MAX_READ, Duration::ZERO);
        assert!(!events.is_empty());
        assert!(events.len() < MAX_READ);
        let bytes: usize = events.iter().map(encoded_size).sum();
        assert!(bytes <= MAX_READ_BYTES);

        let mut read = events.len();
        let mut after = events.last().unwrap().sequence;
        loop {
            let (events, _) = log.read(after, MAX_READ, Duration::ZERO);
            let Some(last) = events.last() else { break };
            after = last.sequence;
            read += events.len();
        }
        assert_eq!(read, MAX_READ);
    }

    #[test]
    fn an_event_records_when_it_happened() {
        let log = ProcessEventLog::new(8);
        let before = now_ms();
        log.record(process(7), "/bin/sh", ProcessEventKindWire::Launched);
        let (events, _) = log.read(0, MAX_READ, Duration::ZERO);
        assert!(events[0].time_ms >= before);
        assert!(events[0].time_ms <= now_ms());
    }

    fn now_ms() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
    }

    fn executed() -> ProcessEventKindWire {
        ProcessEventKindWire::Executed {
            previous_executable: "/bin/sh".to_string(),
            parent_executable: "/bin/sh".to_string(),
        }
    }

    #[test]
    fn execs_over_the_rate_are_reported_as_one_suppressed_count() {
        let log = ProcessEventLog::with_exec_rate(8, 2, 1);
        for pid in 1..=5 {
            log.record_exec(process(pid), "/bin/true", executed());
        }
        log.record(process(9), "/bin/sh", ProcessEventKindWire::Launched);

        let (events, _) = log.read(0, MAX_READ, Duration::ZERO);
        let kinds: Vec<_> = events.iter().map(|event| event.kind.clone()).collect();
        assert_eq!(
            kinds,
            [
                executed(),
                executed(),
                ProcessEventKindWire::Launched,
                ProcessEventKindWire::Suppressed { count: 3 },
            ]
        );
        assert_eq!(events[3].process.pid, std::process::id());

        let (events, _) = log.read(events[3].sequence, MAX_READ, Duration::ZERO);
        assert!(events.is_empty());
    }

    #[test]
    fn suppressed_execs_are_reported_at_most_once_per_interval() {
        let log = ProcessEventLog::with_exec_rate(16, 0, 1)
            .reporting_suppressed_every(Duration::from_millis(200));
        log.record_exec(process(1), "/bin/true", executed());
        let (first, _) = log.read(0, MAX_READ, Duration::ZERO);
        assert_eq!(first[0].kind, ProcessEventKindWire::Suppressed { count: 1 });

        for pid in 2..=4 {
            log.record_exec(process(pid), "/bin/true", executed());
        }
        let after = first[0].sequence;
        let (events, _) = log.read(after, MAX_READ, Duration::ZERO);
        assert!(events.is_empty(), "{events:?}");

        // A waiting read returns the count once the interval has passed.
        let started = Instant::now();
        let (events, _) = log.read(after, MAX_READ, Duration::from_secs(10));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(
            events
                .iter()
                .map(|event| event.kind.clone())
                .collect::<Vec<_>>(),
            [ProcessEventKindWire::Suppressed { count: 3 }]
        );
    }

    #[test]
    fn a_waiting_read_wakes_for_suppressed_execs() {
        let log = Arc::new(ProcessEventLog::with_exec_rate(8, 0, 1));
        let writer = log.clone();
        let recorder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            writer.record_exec(process(7), "/bin/true", executed());
        });
        let (events, _) = log.read(0, MAX_READ, Duration::from_secs(10));
        recorder.join().unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| event.kind.clone())
                .collect::<Vec<_>>(),
            [ProcessEventKindWire::Suppressed { count: 1 }]
        );
    }

    #[test]
    fn an_exec_left_unobserved_is_reported_as_suppressed() {
        let log = ProcessEventLog::new(8);
        log.suppress_exec();
        let (events, _) = log.read(0, MAX_READ, Duration::ZERO);
        assert_eq!(
            events
                .iter()
                .map(|event| event.kind.clone())
                .collect::<Vec<_>>(),
            [ProcessEventKindWire::Suppressed { count: 1 }]
        );
    }

    #[test]
    fn the_exec_rate_refills_over_time() {
        let log = ProcessEventLog::with_exec_rate(8, 1, 1_000);
        log.record_exec(process(1), "/bin/true", executed());
        log.record_exec(process(2), "/bin/true", executed());
        std::thread::sleep(Duration::from_millis(20));
        log.record_exec(process(3), "/bin/true", executed());

        let (events, _) = log.read(0, MAX_READ, Duration::ZERO);
        let pids: Vec<_> = events
            .iter()
            .filter(|event| event.kind == executed())
            .map(|event| event.process.pid)
            .collect();
        assert_eq!(pids, [1, 3]);
    }

    /// The workload's execs are recorded under the pid that makes them,
    /// with the parent of that pid, and the runtime's own spawns and execs
    /// that cannot run are not.
    #[test]
    fn workload_execs_are_recorded_with_their_parent() {
        use std::os::unix::ffi::OsStrExt as _;

        const CHILD_MARKER: &str = "OPENSHELL_TEST_EXEC_EVENTS_CHILD";
        struct Recording;
        impl Drop for Recording {
            fn drop(&mut self) {
                set_record_executions(false);
            }
        }
        if std::env::var_os(CHILD_MARKER).is_some() {
            let dir = tempfile::tempdir().expect("tempdir");
            let link = dir.path().join(std::ffi::OsStr::from_bytes(b"tr\xffue"));
            std::os::unix::fs::symlink("/bin/true", &link).expect("link");
            let status = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(
                    "/nonexistent-exec 2>/dev/null; /etc/passwd 2>/dev/null; \"$1\"; \
                     exec /proc/self/exe -c 'exec /bin/true'",
                )
                .arg("sh")
                .arg(&link)
                .status()
                .expect("run shell");
            assert!(status.success());
            return;
        }

        set_record_executions(true);
        let _recording = Recording;
        let first = log().lock().next_sequence;
        let (launcher, listener) = crate::linux::workload_launcher::start().expect("launcher");
        let listener = Arc::new(listener);
        let done = Arc::new(AtomicBool::new(false));
        let broker = {
            let done = done.clone();
            std::thread::spawn(move || serve_notifications(&listener, &done))
        };
        let executable = std::env::current_exe().expect("test executable");
        let mut child = launcher
            .execute(move || {
                std::process::Command::new(executable)
                    .args([
                        "--exact",
                        "process_events::tests::workload_execs_are_recorded_with_their_parent",
                        "--nocapture",
                    ])
                    .env(CHILD_MARKER, "1")
                    .spawn()
            })
            .expect("launcher result")
            .expect("spawn child");
        let child_pid = child.id();
        assert!(child.wait().expect("wait child").success());
        done.store(true, Ordering::Release);
        broker.join().expect("broker");

        let (events, _) = log().read(first - 1, usize::MAX, Duration::ZERO);
        let execs: Vec<_> = events
            .iter()
            .filter(|event| matches!(event.kind, ProcessEventKindWire::Executed { .. }))
            .collect();
        assert!(
            !events.iter().any(|event| event.process.pid == child_pid),
            "the runtime's own spawn is not an exec event"
        );
        assert_eq!(execs.len(), 4, "{execs:#?}");
        let (shell, linked, reexec, replaced) = (execs[0], execs[1], execs[2], execs[3]);
        let shell_exe = shell.executable.clone();
        assert!(shell_exe.contains("sh"), "{shell_exe}");
        assert_eq!(shell.process.parent_pid, child_pid);
        let test_binary = std::fs::canonicalize(std::env::current_exe().unwrap())
            .unwrap()
            .display()
            .to_string();
        assert_eq!(
            shell.kind,
            ProcessEventKindWire::Executed {
                previous_executable: test_binary.clone(),
                parent_executable: test_binary.clone(),
            }
        );
        // A file named by bytes that are not UTF-8 is still recorded.
        assert!(
            linked.executable.ends_with("/true"),
            "{}",
            linked.executable
        );
        assert_eq!(linked.process.parent_pid, shell.process.pid);
        // `/proc/self` names the caller, not the runtime.
        assert_eq!(reexec.process, shell.process);
        assert_eq!(reexec.executable, shell_exe);
        assert_eq!(replaced.process, shell.process);
        assert!(
            replaced.executable.ends_with("/true"),
            "{}",
            replaced.executable
        );
        assert_eq!(
            replaced.kind,
            ProcessEventKindWire::Executed {
                previous_executable: shell_exe,
                parent_executable: test_binary,
            }
        );

        // Each recorded process's exit is recorded under its last executable,
        // with the status when the runtime read it before its parent reaped it.
        let deadline = Instant::now() + Duration::from_secs(10);
        let ended = loop {
            let (events, _) = log().read(first - 1, usize::MAX, Duration::from_millis(50));
            let ended: Vec<_> = events
                .into_iter()
                .filter(|event| matches!(event.kind, ProcessEventKindWire::Ended(_)))
                .collect();
            if ended.len() >= 2 || Instant::now() > deadline {
                break ended;
            }
        };
        let mut ended_pids: Vec<_> = ended.iter().map(|event| event.process).collect();
        ended_pids.sort_by_key(|process| process.pid);
        let mut expected = vec![shell.process, linked.process];
        expected.sort_by_key(|process| process.pid);
        assert_eq!(ended_pids, expected, "{ended:#?}");
        for event in &ended {
            assert!(event.executable.ends_with("/true"), "{event:#?}");
            assert!(
                matches!(
                    event.kind,
                    ProcessEventKindWire::Ended(None | Some(ExitStatusWire::Exited(0)))
                ),
                "{event:#?}"
            );
        }
    }

    #[allow(unsafe_code)]
    fn serve_notifications(listener: &Arc<NotificationListener>, done: &AtomicBool) {
        use std::os::fd::BorrowedFd;
        while !done.load(Ordering::Acquire) {
            // SAFETY: the listener outlives this borrow.
            let fd = unsafe { BorrowedFd::borrow_raw(listener.as_raw_fd()) };
            let mut descriptors = [nix::poll::PollFd::new(fd, nix::poll::PollFlags::POLLIN)];
            if nix::poll::poll(&mut descriptors, nix::poll::PollTimeout::from(50_u16)).unwrap_or(0)
                == 0
            {
                continue;
            }
            let Ok(notification) = listener.receive() else {
                continue;
            };
            let syscall = i64::from(notification.syscall);
            if syscall == libc::SYS_execve || syscall == libc::SYS_execveat {
                observe_exec(listener, notification).expect("continue exec");
            } else {
                let _ = listener.respond_continue(notification.id);
            }
        }
    }

    #[test]
    fn an_empty_read_waits_for_the_next_event() {
        let log = Arc::new(ProcessEventLog::new(8));
        let started = Instant::now();
        let (events, lost) = log.read(0, MAX_READ, Duration::from_millis(50));
        assert!(events.is_empty());
        assert_eq!(lost, 0);
        assert!(started.elapsed() >= Duration::from_millis(50));

        let writer = log.clone();
        let recorder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            writer.record(process(7), "/bin/sh", ProcessEventKindWire::Launched);
        });
        let (events, _) = log.read(0, MAX_READ, Duration::from_secs(10));
        recorder.join().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].process.pid, 7);
    }
}
