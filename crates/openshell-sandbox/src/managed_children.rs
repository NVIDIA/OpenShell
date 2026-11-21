// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide tracker for sandbox-managed child PIDs.
//!
//! The supervisor spawns several long-lived children (the entrypoint, SSH
//! sessions). Each registers its PID here on spawn and removes it on exit so
//! the orchestrator's `SIGCHLD` reaper can distinguish supervised processes
//! from incidental zombies.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::Duration;

static MANAGED_CHILDREN: LazyLock<Mutex<HashMap<i32, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static REAPER_EVENT_FD: AtomicI32 = AtomicI32::new(-1);
static PROC_CHILDREN_SUPPORT_REPORTED: AtomicBool = AtomicBool::new(false);
const REAPER_RECOVERY_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(test)]
static REAPER_SCAN_COUNT: AtomicU64 = AtomicU64::new(0);

extern "C" fn notify_reaper_on_sigchld(_: libc::c_int) {
    let fd = REAPER_EVENT_FD.load(Ordering::Acquire);
    if fd >= 0 {
        let wakeup = 1_u64;
        // SAFETY: write is async-signal-safe; the process-lifetime eventfd is
        // nonblocking, so a full counter cannot stall the signal handler.
        unsafe {
            libc::write(fd, (&raw const wakeup).cast(), size_of::<u64>());
        }
    }
}

/// Identity of one registry entry. The generation prevents an old waiter from
/// removing a newer child that reused the same numeric PID after reap.
#[derive(Clone, Copy)]
pub struct ManagedChild {
    pid: i32,
    generation: u64,
}

/// Exclusive access to the managed-child registry.
///
/// A process spawner holds this guard from immediately before `spawn` or
/// `fork` until the returned PID is registered. The orphan reaper holds the
/// same guard while deciding whether to reap an exited child. This closes the
/// otherwise unavoidable window in which a fast-exiting managed child exists
/// but its PID has not yet been published.
pub struct RegistryGuard(MutexGuard<'static, HashMap<i32, u64>>);

impl RegistryGuard {
    /// Add a newly spawned managed child.
    pub fn register(&mut self, pid: u32) -> Option<ManagedChild> {
        let Ok(pid) = i32::try_from(pid) else {
            return None;
        };
        if pid <= 0 {
            return None;
        }
        let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        self.0.insert(pid, generation);
        Some(ManagedChild { pid, generation })
    }

    /// Return whether the PID belongs to an explicit waiter.
    #[must_use]
    pub fn contains(&self, pid: i32) -> bool {
        self.0.contains_key(&pid)
    }

    /// Remove exactly this supervised-child registration. A newer
    /// registration for a reused PID is preserved.
    pub fn unregister(&mut self, child: ManagedChild) {
        if self.0.get(&child.pid) == Some(&child.generation) {
            self.0.remove(&child.pid);
        }
    }
}

/// Lock the registry for an atomic spawn-and-register or inspect-and-reap
/// operation.
pub fn lock() -> RegistryGuard {
    RegistryGuard(
        MANAGED_CHILDREN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

/// Register a child and return the generation-bearing removal token.
pub fn register(pid: u32) -> Option<ManagedChild> {
    lock().register(pid)
}

/// Remove exactly this supervised-child registration. A newer registration
/// for a reused PID is preserved.
pub fn unregister(child: ManagedChild) {
    lock().unregister(child);
}

/// Return `true` if `pid` is currently in the supervised-child set.
#[must_use]
pub fn is_managed(pid: i32) -> bool {
    lock().contains(pid)
}

/// Wait until a managed child is terminal without reaping it.
///
/// Keeping the child as a zombie prevents PID/process-group reuse until the
/// owner publishes terminal state and performs the final wait.
pub fn wait_until_terminal(pid: u32) -> io::Result<()> {
    use nix::sys::wait::{Id, WaitPidFlag, waitid};
    let pid = i32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "PID out of range"))?;
    waitid(
        Id::Pid(nix::unistd::Pid::from_raw(pid)),
        WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT,
    )
    .map(|_| ())
    .map_err(io::Error::other)
}

/// Start the background reaper used when `openshell-sandbox` owns PID 1.
///
/// Explicitly managed children remain owned by their normal waiters. Only
/// unregistered children adopted from the workload process tree are reaped.
pub fn start_orphan_reaper() -> io::Result<()> {
    // This is installed before the boundary starts its runtime threads or
    // workload children. The descriptor and handler live until process exit.
    // SAFETY: eventfd has scalar arguments and returns a new descriptor.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    REAPER_EVENT_FD.store(fd, Ordering::Release);
    let action = nix::sys::signal::SigAction::new(
        nix::sys::signal::SigHandler::Handler(notify_reaper_on_sigchld),
        nix::sys::signal::SaFlags::SA_RESTART | nix::sys::signal::SaFlags::SA_NOCLDSTOP,
        nix::sys::signal::SigSet::empty(),
    );
    // SAFETY: the handler only reads a lock-free atomic and writes to the
    // nonblocking eventfd, both valid for the remaining process lifetime.
    unsafe { nix::sys::signal::sigaction(nix::sys::signal::Signal::SIGCHLD, &action) }
        .map_err(io::Error::other)?;
    std::thread::Builder::new()
        .name("openshell-orphan-reaper".to_string())
        .spawn(move || {
            loop {
                if let Err(error) = reap_unmanaged_children_once() {
                    tracing::debug!(%error, "orphan reaper scan failed");
                }
                if let Err(error) = wait_for_reaper_event(fd) {
                    tracing::debug!(%error, "orphan reaper notification failed");
                    std::thread::sleep(REAPER_RECOVERY_INTERVAL);
                }
            }
        })
        .map(|_| ())
}

fn wait_for_reaper_event(fd: libc::c_int) -> io::Result<()> {
    let mut notification = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll receives one valid pollfd for the process-lifetime eventfd.
    let ready = unsafe {
        libc::poll(
            &raw mut notification,
            1,
            i32::try_from(REAPER_RECOVERY_INTERVAL.as_millis()).unwrap(),
        )
    };
    if ready < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(());
        }
        return Err(error);
    }
    if ready == 0 {
        return Ok(());
    }
    if notification.revents & libc::POLLIN == 0 {
        return Err(io::Error::other("orphan reaper eventfd is not readable"));
    }
    let mut count = 0_u64;
    // Drain before scanning: a SIGCHLD arriving during the next scan remains
    // queued and triggers another pass. A single read drains coalesced writes.
    // SAFETY: read writes one u64 into valid storage; the fd is nonblocking.
    let read = unsafe { libc::read(fd, (&raw mut count).cast(), size_of::<u64>()) };
    if read == isize::try_from(size_of::<u64>()).expect("u64 size fits isize")
        || (read < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock)
    {
        Ok(())
    } else if read < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::other("short orphan reaper eventfd read"))
    }
}

fn reap_unmanaged_children_once() -> io::Result<usize> {
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};

    #[cfg(test)]
    REAPER_SCAN_COUNT.fetch_add(1, Ordering::Relaxed);
    let children = direct_child_pids()?;
    let registry = lock();
    let mut reaped = 0;
    for pid in children {
        if registry.contains(pid) {
            continue;
        }
        match waitpid(nix::unistd::Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive)
            | Err(nix::errno::Errno::ECHILD | nix::errno::Errno::ESRCH) => {}
            Ok(_) => reaped += 1,
            Err(error) => return Err(io::Error::other(error)),
        }
    }
    Ok(reaped)
}

fn direct_child_pids() -> io::Result<HashSet<i32>> {
    scan_task_children(
        std::path::Path::new("/proc/self/task"),
        &PROC_CHILDREN_SUPPORT_REPORTED,
    )
}

/// Collect the child PIDs listed by every task directory below `task_root`.
///
/// Missing children support is reported through `reported` (see
/// [`report_missing_support_once`]).
fn scan_task_children(
    task_root: &std::path::Path,
    reported: &AtomicBool,
) -> io::Result<HashSet<i32>> {
    let mut children = HashSet::new();
    let mut saw_children_file = false;
    let mut saw_task_without_children = false;
    for task in std::fs::read_dir(task_root)? {
        let task = task?;
        match read_task_children(&task.path())? {
            TaskChildren::Pids(pids) => {
                saw_children_file = true;
                children.extend(pids);
            }
            TaskChildren::VanishedTask => {}
            TaskChildren::UnsupportedKernel => saw_task_without_children = true,
        }
    }
    // Corroborate before reporting: an environment without children-file
    // support exposes no children file for any task, while a teardown or
    // TID-reuse race on a supported kernel strands at most one task
    // directory without its file while the rest still list theirs.
    if saw_task_without_children && !saw_children_file {
        report_missing_support_once(reported);
    }
    Ok(children)
}

/// The `children` entries of one task directory.
#[derive(Debug, PartialEq, Eq)]
enum TaskChildren {
    /// Positive child PIDs listed by the kernel.
    Pids(Vec<i32>),
    /// The task exited while the directory listing was being walked.
    VanishedTask,
    /// No `children` file is exposed for a task directory that still exists,
    /// so children cannot be discovered from procfs.
    UnsupportedKernel,
}

fn read_task_children(task_dir: &std::path::Path) -> io::Result<TaskChildren> {
    match std::fs::read_to_string(task_dir.join("children")) {
        Ok(contents) => Ok(TaskChildren::Pids(
            contents
                .split_ascii_whitespace()
                .filter_map(|value| value.parse::<i32>().ok())
                .filter(|pid| *pid > 0)
                .collect(),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if task_dir.try_exists()? {
                Ok(TaskChildren::UnsupportedKernel)
            } else {
                Ok(TaskChildren::VanishedTask)
            }
        }
        Err(error) => Err(error),
    }
}

/// Emit the missing-support warning and detection finding the first time
/// `reported` flips from false to true, and do nothing afterwards.
fn report_missing_support_once(reported: &AtomicBool) {
    if reported
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    tracing::warn!(
        "no /proc/self/task/*/children: the orphan reaper cannot discover \
         children (kernel built without CONFIG_PROC_CHILDREN, or restricted \
         procfs such as gVisor or a subset=pid mount)"
    );
    openshell_ocsf::ocsf_emit!(
        openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(openshell_ocsf::ActivityId::Open)
            .severity(openshell_ocsf::SeverityId::Medium)
            .confidence(openshell_ocsf::ConfidenceId::High)
            .is_alert(true)
            .finding_info(
                openshell_ocsf::FindingInfo::new(
                    "proc-children-unavailable",
                    "Sandbox Orphan Reaper Unavailable",
                )
                .with_desc(
                    "No task under /proc/self/task exposes a children file, so \
                     the sandbox orphan reaper cannot discover unmanaged \
                     children, and exited descendants accumulate as zombies \
                     until the process limit. The likely causes are a kernel \
                     built without CONFIG_PROC_CHILDREN or restricted procfs \
                     (for example gVisor or a subset=pid mount).",
                )
            )
            .message("orphan reaper unavailable: no /proc/self/task/*/children")
            .build()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid, waitpid};
    use nix::unistd::Pid;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    use tracing_subscriber::layer::SubscriberExt;

    /// Sink for the plain `tracing` events emitted alongside OCSF events.
    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedLogs {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl CapturedLogs {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("log buffer")).into_owned()
        }
    }

    fn fork_exiting_child() -> i32 {
        // SAFETY: the child does not run Rust code after fork; it exits through
        // libc immediately, avoiding inherited test-harness locks.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: terminate without unwinding or touching Rust state.
            unsafe { libc::_exit(0) };
        }
        assert!(pid > 0, "fork failed: {}", io::Error::last_os_error());
        pid
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "condition did not become true");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn orphan_reaper_waits_while_idle_and_reaps_only_unmanaged_children() {
        const HELPER_ENV: &str = "OPENSHELL_ORPHAN_REAPER_TEST_HELPER";
        if std::env::var_os(HELPER_ENV).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "managed_children::tests::orphan_reaper_waits_while_idle_and_reaps_only_unmanaged_children",
                    "--nocapture",
                ])
                .env(HELPER_ENV, "1")
                .output()
                .expect("start isolated reaper test process");
            assert!(
                output.status.success(),
                "reaper test failed: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            return;
        }

        start_orphan_reaper().expect("start orphan reaper");
        wait_until(|| REAPER_SCAN_COUNT.load(Ordering::Relaxed) > 0);
        let idle_scan_count = REAPER_SCAN_COUNT.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(REAPER_SCAN_COUNT.load(Ordering::Relaxed), idle_scan_count);

        let mut registry = lock();
        let managed_pid = fork_exiting_child();
        let managed = registry
            .register(u32::try_from(managed_pid).unwrap())
            .unwrap();
        drop(registry);
        wait_until(|| {
            matches!(
                waitid(
                    Id::Pid(Pid::from_raw(managed_pid)),
                    WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT
                ),
                Ok(WaitStatus::Exited(..))
            )
        });
        wait_until(|| REAPER_SCAN_COUNT.load(Ordering::Relaxed) > idle_scan_count);
        assert!(matches!(
            waitpid(Pid::from_raw(managed_pid), None),
            Ok(WaitStatus::Exited(..))
        ));
        unregister(managed);

        let orphan_pids: Vec<i32> = (0..8).map(|_| fork_exiting_child()).collect();
        wait_until(|| {
            let children = direct_child_pids().expect("inspect direct children");
            orphan_pids.iter().all(|pid| !children.contains(pid))
        });
        for pid in orphan_pids {
            assert_eq!(
                waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG)),
                Err(nix::errno::Errno::ECHILD)
            );
        }
    }

    #[test]
    fn fast_child_remains_waitable_after_orphan_reap_attempt() {
        let mut registry = lock();
        let mut child = Command::new("sh")
            .args(["-c", "exit 11"])
            .spawn()
            .expect("spawn fast child");
        let child_pid = child.id();
        let managed_child = registry.register(child_pid).expect("register fast child");
        drop(registry);
        let pid = Pid::from_raw(i32::try_from(child_pid).unwrap());

        // Observe the completed child without consuming its status, exactly
        // as the orphan reaper does before its managed-PID check.
        loop {
            match waitid(
                Id::Pid(pid),
                WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
            ) {
                Ok(WaitStatus::StillAlive) => std::thread::yield_now(),
                Ok(_) => break,
                Err(error) => panic!("observe fast child: {error}"),
            }
        }

        let registry = lock();
        let reaped = if registry.contains(pid.as_raw()) {
            None
        } else {
            Some(waitpid(pid, Some(WaitPidFlag::WNOHANG)))
        };
        drop(registry);
        assert!(
            reaped.is_none(),
            "the orphan reaper must leave a registered child to its explicit waiter"
        );

        let wait = child.wait();
        unregister(managed_child);
        assert!(
            wait.is_ok(),
            "the explicit child waiter must retain the exit status"
        );
    }

    #[test]
    fn reaper_cannot_steal_child_while_registration_is_in_progress() {
        // Keep the logical spawn paused before its PID is registered. This is
        // the exact window that previously let the orphan reaper consume a
        // fast child's status.
        let pid = 1_000_002_u32;
        let (spawn_entered_tx, spawn_entered_rx) = mpsc::channel();
        let (complete_spawn_tx, complete_spawn_rx) = mpsc::channel();
        let (registered_tx, registered_rx) = mpsc::channel();
        let (reap_attempted_tx, reap_attempted_rx) = mpsc::channel();
        let (reap_result_tx, reap_result_rx) = mpsc::channel();

        let spawn = std::thread::spawn(move || {
            let mut registry = lock();
            spawn_entered_tx.send(()).unwrap();
            complete_spawn_rx.recv().unwrap();
            let managed_child = registry.register(pid).expect("register child");
            assert!(registered_tx.send(managed_child).is_ok());
        });
        spawn_entered_rx.recv().unwrap();

        let reaper = std::thread::spawn(move || {
            reap_attempted_tx.send(()).unwrap();
            let registry = lock();
            reap_result_tx
                .send(registry.contains(i32::try_from(pid).unwrap()))
                .unwrap();
        });
        reap_attempted_rx.recv().unwrap();

        assert!(
            reap_result_rx
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "the reaper must wait until the child is registered"
        );

        complete_spawn_tx.send(()).unwrap();
        let managed_child = registered_rx.recv().unwrap();
        spawn.join().unwrap();
        assert!(reap_result_rx.recv().unwrap());
        reaper.join().unwrap();
        unregister(managed_child);
    }

    #[test]
    fn stale_unregister_preserves_reused_pid_registration() {
        let pid = i32::MAX as u32;
        let first = lock().register(pid).expect("first registration");
        let second = lock().register(pid).expect("replacement registration");

        unregister(first);
        assert!(is_managed(i32::try_from(pid).expect("test pid")));

        unregister(second);
        assert!(!is_managed(i32::try_from(pid).expect("test pid")));
    }

    #[test]
    fn unregister_recovers_from_a_poisoned_registry() {
        let pid = 1_000_003_u32;
        let child = lock().register(pid).expect("register child");

        // Poison the registry mutex exactly as a panicking holder would. The
        // deliberate panic prints through the default hook; swapping the
        // process-global hook here would swallow the diagnostics of a
        // sibling test that fails at the same moment.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _registry = lock();
            panic!("poison the managed-children registry");
        }));

        unregister(child);
        assert!(!is_managed(i32::try_from(pid).expect("test pid")));
    }

    #[test]
    fn task_children_classification_distinguishes_missing_support() {
        let dir = tempfile::tempdir().expect("create procfs stand-in");

        // A task directory without a children file: the kernel was built
        // without CONFIG_PROC_CHILDREN.
        let unsupported = dir.path().join("1234");
        std::fs::create_dir_all(&unsupported).expect("create task directory");
        assert_eq!(
            read_task_children(&unsupported).expect("read unsupported task"),
            TaskChildren::UnsupportedKernel
        );

        // A live task directory with parseable and unparseable entries.
        std::fs::write(unsupported.join("children"), "123 456 0 -7 not-a-pid\n")
            .expect("write children file");
        assert_eq!(
            read_task_children(&unsupported).expect("read children"),
            TaskChildren::Pids(vec![123, 456])
        );

        // A task directory that vanished mid-scan.
        let vanished = dir.path().join("5678");
        assert_eq!(
            read_task_children(&vanished).expect("read vanished task"),
            TaskChildren::VanishedTask
        );
    }

    #[test]
    fn child_pid_parser_observes_a_live_child() {
        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn child");
        assert!(
            direct_child_pids()
                .expect("read direct children")
                .contains(&i32::try_from(child.id()).expect("child PID"))
        );
        child.kill().expect("kill child");
        child.wait().expect("wait for child");
    }

    #[test]
    fn missing_proc_children_support_is_reported_once() {
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let logs = CapturedLogs::default();
        let writer = logs.clone();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(capture.clone()).with(
                tracing_subscriber::fmt::layer()
                    .with_writer(move || writer.clone())
                    .with_ansi(false),
            ),
        );

        // A private latch: the process-wide one is shared with every other
        // test that scans the real /proc/self/task, so asserting on it would
        // depend on parallel test ordering.
        let reported = AtomicBool::new(false);
        report_missing_support_once(&reported);
        report_missing_support_once(&reported);

        let events = capture.json_events();
        assert_eq!(
            events.len(),
            1,
            "the kernel condition must be reported exactly once: {events:?}"
        );
        let event = &events[0];
        assert_eq!(event["class_uid"], 2004);
        assert_eq!(event["activity_id"], 1);
        assert_eq!(event["severity_id"], 3);
        assert_eq!(event["severity"], "Medium");
        assert_eq!(event["confidence_id"], 3);
        assert_eq!(event["confidence"], "High");
        assert_eq!(event["is_alert"].as_bool(), Some(true));
        assert_eq!(event["finding_info"]["uid"], "proc-children-unavailable");
        assert_eq!(
            event["finding_info"]["title"],
            "Sandbox Orphan Reaper Unavailable"
        );
        assert!(
            event["finding_info"]["desc"]
                .as_str()
                .is_some_and(|desc| desc.contains("CONFIG_PROC_CHILDREN")),
            "finding description: {event:?}"
        );
        assert!(
            event["message"]
                .as_str()
                .is_some_and(|message| message.contains("/proc/self/task/*/children")),
            "finding message: {event:?}"
        );

        let warnings = logs.text().matches("CONFIG_PROC_CHILDREN").count();
        assert_eq!(
            warnings,
            1,
            "the warning must also be emitted once: {}",
            logs.text()
        );
    }

    #[test]
    fn scan_reports_missing_support_only_when_no_task_lists_children() {
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let logs = CapturedLogs::default();
        let writer = logs.clone();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(capture.clone()).with(
                tracing_subscriber::fmt::layer()
                    .with_writer(move || writer.clone())
                    .with_ansi(false),
            ),
        );

        let dir = tempfile::tempdir().expect("create procfs stand-in");

        // A task tree where no task exposes a children file: the whole
        // environment lacks children-file support, so the scan reports it.
        for tid in ["1234", "5678"] {
            std::fs::create_dir(dir.path().join(tid)).expect("create task directory");
        }
        let reported = AtomicBool::new(false);
        let pids = scan_task_children(dir.path(), &reported).expect("scan unsupported tree");
        assert!(pids.is_empty(), "no children can be listed: {pids:?}");
        assert_eq!(
            capture.json_events().len(),
            1,
            "a fully unsupported task tree must be reported"
        );

        // A tree where some task still lists its children is a supported
        // environment that lost a task mid-scan: no report.
        std::fs::write(dir.path().join("1234").join("children"), "42\n")
            .expect("write children file");
        let reported = AtomicBool::new(false);
        let pids = scan_task_children(dir.path(), &reported).expect("scan mixed tree");
        assert_eq!(pids, HashSet::from([42]));
        assert_eq!(
            capture.json_events().len(),
            1,
            "a mixed task tree must not be reported as unsupported"
        );

        let warnings = logs.text().matches("/proc/self/task/*/children").count();
        assert_eq!(warnings, 1, "exactly one warning: {}", logs.text());
    }

    #[test]
    fn unreadable_task_directory_surfaces_its_error() {
        // Root bypasses directory permissions, so the read cannot be made to
        // fail.
        if rustix::process::geteuid().is_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("create procfs stand-in");
        let task = dir.path().join("9012");
        std::fs::create_dir(&task).expect("create task directory");
        std::fs::set_permissions(&task, std::fs::Permissions::from_mode(0o000))
            .expect("make task directory unreadable");

        let outcome = read_task_children(&task);
        // Restore search permission first so the stand-in directory can be
        // removed even when the assertions below fail.
        std::fs::set_permissions(&task, std::fs::Permissions::from_mode(0o700))
            .expect("restore task directory permissions");

        let error = outcome
            .expect_err("an unreadable task directory must surface its error, not classify it");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
