// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exits of the workload processes whose execs the runtime recorded.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::LazyLock;
use std::sync::mpsc;

use openshell_isolation_interface::contract::ProcessInstance;
use openshell_sandbox_backend::boundary_protocol::{ExitStatusWire, ProcessEventKindWire};
use rustix::event::{PollFd, PollFlags};

use crate::process_events::ProcessEventLog;

/// Most processes watched at once. A process recorded beyond the cap has no
/// exit record and is counted as suppressed.
const MAX_WATCHED: usize = 1024;

/// A process to watch: its pidfd names the instance even after its pid is
/// reused.
struct Watch {
    process: ProcessInstance,
    executable: String,
    pidfd: OwnedFd,
    log: &'static ProcessEventLog,
}

struct Watcher {
    watches: mpsc::Sender<Watch>,
    wake: UnixStream,
}

/// Record in `log` when `process` exits under the name `executable`. A
/// second watch of the same process updates the name it exits under.
pub fn watch(
    log: &'static ProcessEventLog,
    process: ProcessInstance,
    executable: String,
    pidfd: OwnedFd,
) {
    let Some(watcher) = watcher() else {
        return;
    };
    let watch = Watch {
        process,
        executable,
        pidfd,
        log,
    };
    if watcher.watches.send(watch).is_ok() {
        // A full buffer already holds a wakeup.
        let _ = (&watcher.wake).write(&[0]);
    }
}

fn watcher() -> Option<&'static Watcher> {
    static WATCHER: LazyLock<Option<Watcher>> = LazyLock::new(|| {
        let (wake, woken) = UnixStream::pair()
            .and_then(|(wake, woken)| {
                wake.set_nonblocking(true)?;
                woken.set_nonblocking(true)?;
                Ok((wake, woken))
            })
            .inspect_err(|error| tracing::warn!(%error, "exit observer did not start"))
            .ok()?;
        let (watches, pending) = mpsc::channel();
        std::thread::Builder::new()
            .name("openshell-exit-observer".to_string())
            .spawn(move || observe_exits(&pending, &woken))
            .inspect_err(|error| tracing::warn!(%error, "exit observer did not start"))
            .ok()?;
        Some(Watcher { watches, wake })
    });
    WATCHER.as_ref()
}

fn observe_exits(pending: &mpsc::Receiver<Watch>, mut woken: &UnixStream) {
    let cap = max_watched(rustix::process::getrlimit(rustix::process::Resource::Nofile).current);
    let mut watched: HashMap<u32, Watch> = HashMap::new();
    loop {
        let mut wakeups = [0; 64];
        while woken.read(&mut wakeups).is_ok_and(|read| read > 0) {}
        for watch in pending.try_iter() {
            add_watch(&mut watched, watch, cap);
        }
        let pids: Vec<u32> = watched.keys().copied().collect();
        let mut descriptors: Vec<PollFd<'_>> = std::iter::once(PollFd::new(woken, PollFlags::IN))
            .chain(
                pids.iter()
                    .map(|pid| PollFd::new(&watched[pid].pidfd, PollFlags::IN)),
            )
            .collect();
        match rustix::event::poll(&mut descriptors, None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => {
                tracing::warn!(%error, "waiting for workload exits failed; retrying");
                drop(descriptors);
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
        }
        let exited: Vec<u32> = descriptors[1..]
            .iter()
            .zip(&pids)
            .filter(|(descriptor, _)| !descriptor.revents().is_empty())
            .map(|(_, pid)| *pid)
            .collect();
        drop(descriptors);
        for pid in exited {
            if let Some(watch) = watched.remove(&pid) {
                record_exit(&watch);
            }
        }
    }
}

/// A quarter of the runtime's descriptor limit, so watches never starve the
/// sockets and procfs reads it mediates with.
fn max_watched(descriptor_limit: Option<u64>) -> usize {
    descriptor_limit
        .and_then(|limit| usize::try_from(limit / 4).ok())
        .map_or(MAX_WATCHED, |quarter| quarter.min(MAX_WATCHED))
}

fn add_watch(watched: &mut HashMap<u32, Watch>, watch: Watch, cap: usize) {
    let pid = watch.process.pid;
    if let Some(current) = watched.get_mut(&pid) {
        if current.process.start_time_ms == watch.process.start_time_ms {
            current.executable = watch.executable;
            return;
        }
        // The watched process exited and its pid was reused before the exit
        // was read.
        if let Some(exited) = watched.remove(&pid) {
            record_exit(&exited);
        }
    }
    // The runtime records the exits of the children it waits for. Spawns
    // register under this lock, so a child is registered by the time it is
    // seen here.
    if crate::managed_children::is_managed(pid.cast_signed()) {
        return;
    }
    if watched.len() < cap {
        watched.insert(pid, watch);
    } else {
        watch.log.suppress_exec();
    }
}

fn record_exit(watch: &Watch) {
    // The kernel keeps the status with the pidfd once the parent reaps the
    // process, and procfs shows it until then.
    let status = pidfd_exit_status(&watch.pidfd)
        .or_else(|| zombie_exit_status(&watch.process))
        .or_else(|| pidfd_exit_status(&watch.pidfd))
        .map(exit_status);
    watch.log.record(
        watch.process,
        &watch.executable,
        ProcessEventKindWire::Ended(status),
    );
}

fn exit_status(status: i32) -> ExitStatusWire {
    if libc::WIFEXITED(status) {
        ExitStatusWire::Exited(libc::WEXITSTATUS(status))
    } else {
        ExitStatusWire::Signaled(libc::WTERMSIG(status))
    }
}

/// The wait status the kernel keeps with a reaped process's pidfd, on
/// kernels that keep it.
#[allow(unsafe_code)]
fn pidfd_exit_status(pidfd: &OwnedFd) -> Option<i32> {
    // SAFETY: all zeros is a valid pidfd_info.
    let mut info: libc::pidfd_info = unsafe { std::mem::zeroed() };
    info.mask = u64::from(libc::PIDFD_INFO_EXIT);
    // SAFETY: PIDFD_GET_INFO writes at most a pidfd_info into `info`.
    let result = unsafe { libc::ioctl(pidfd.as_raw_fd(), libc::PIDFD_GET_INFO, &raw mut info) };
    (result == 0 && info.mask & u64::from(libc::PIDFD_INFO_EXIT) != 0).then_some(info.exit_code)
}

/// The wait status of `process` while it is a zombie. `None` once its parent
/// has reaped it, or when procfs would hide it from the runtime. Field 52 is
/// the thread-group leader's exit code, and procfs also reports zero when an
/// LSM denies the runtime access; neither is detected here.
fn zombie_exit_status(process: &ProcessInstance) -> Option<i32> {
    let pid = process.pid;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The instance read above still exists, so the reads described it.
    if openshell_binary_identity::observe_process(pid)?.start_time_ms != process.start_time_ms
        || !same_credentials(&status)
    {
        return None;
    }
    let fields: Vec<&str> = stat.rsplit_once(") ")?.1.split_whitespace().collect();
    if fields.first() != Some(&"Z") {
        return None;
    }
    // Field 52, exit_code, counting from the state in field 3.
    fields.get(49)?.parse().ok()
}

/// Whether procfs shows the runtime the exit code of the process `status`
/// describes, which it reports as zero to a caller whose credentials differ.
fn same_credentials(status: &str) -> bool {
    let ids = |prefix: &str| -> Option<Vec<u32>> {
        let line = status.lines().find_map(|line| line.strip_prefix(prefix))?;
        line.split_whitespace().map(|id| id.parse().ok()).collect()
    };
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    ids("Uid:").is_some_and(|ids| ids.iter().all(|id| *id == uid))
        && ids("Gid:").is_some_and(|ids| ids.iter().all(|id| *id == gid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn pidfd(pid: u32) -> OwnedFd {
        let pid = rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap();
        rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap()
    }

    fn ended(log: &ProcessEventLog, pid: u32) -> ProcessEventKindWire {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let (events, _) = log.read(0, usize::MAX, Duration::from_millis(50));
            if let Some(event) = events.iter().find(|event| {
                event.process.pid == pid && matches!(event.kind, ProcessEventKindWire::Ended(_))
            }) {
                return event.kind.clone();
            }
            assert!(Instant::now() < deadline, "no exit recorded for {pid}");
        }
    }

    fn live_child() -> (std::process::Child, ProcessInstance) {
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "read _"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let process = openshell_binary_identity::observe_process(child.id()).unwrap();
        (child, process)
    }

    fn watch_of(log: &'static ProcessEventLog, process: ProcessInstance) -> Watch {
        Watch {
            process,
            executable: "/bin/sh".to_string(),
            pidfd: pidfd(process.pid),
            log,
        }
    }

    #[test]
    fn watches_beyond_the_cap_are_counted_as_suppressed() {
        let log: &'static ProcessEventLog = Box::leak(Box::new(ProcessEventLog::new(8)));
        let (mut first, first_process) = live_child();
        let (mut second, second_process) = live_child();
        let mut watched = HashMap::new();
        add_watch(&mut watched, watch_of(log, first_process), 1);
        add_watch(&mut watched, watch_of(log, second_process), 1);
        assert_eq!(
            watched.keys().copied().collect::<Vec<_>>(),
            [first_process.pid]
        );
        let (events, _) = log.read(0, usize::MAX, Duration::ZERO);
        assert_eq!(
            events
                .iter()
                .map(|event| event.kind.clone())
                .collect::<Vec<_>>(),
            [ProcessEventKindWire::Suppressed { count: 1 }]
        );
        for child in [&mut first, &mut second] {
            drop(child.stdin.take());
            child.wait().unwrap();
        }
    }

    /// The runtime records the exits of the children it waits for itself;
    /// other children, such as orphans it adopted, are watched.
    #[test]
    fn a_managed_child_is_not_watched() {
        let log: &'static ProcessEventLog = Box::leak(Box::new(ProcessEventLog::new(8)));
        let (mut child, process) = live_child();
        let mut watched = HashMap::new();
        let registration = crate::managed_children::register(process.pid).unwrap();
        add_watch(&mut watched, watch_of(log, process), 4);
        assert!(watched.is_empty());
        crate::managed_children::unregister(registration);
        add_watch(&mut watched, watch_of(log, process), 4);
        assert_eq!(watched.len(), 1);
        drop(child.stdin.take());
        child.wait().unwrap();
    }

    #[test]
    fn the_cap_leaves_most_descriptors_to_the_runtime() {
        assert_eq!(max_watched(Some(1024)), 256);
        assert_eq!(max_watched(Some(1 << 20)), MAX_WATCHED);
        assert_eq!(max_watched(None), MAX_WATCHED);
    }

    #[test]
    fn an_exit_is_recorded_with_the_status_its_zombie_reports() {
        let log: &'static ProcessEventLog = Box::leak(Box::new(ProcessEventLog::new(8)));
        let mut exits_3 = std::process::Command::new("/bin/sh")
            .args(["-c", "read _; exit 3"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = exits_3.id();
        let process = openshell_binary_identity::observe_process(pid).unwrap();
        watch(log, process, "/bin/sh".to_string(), pidfd(pid));
        watch(log, process, "/usr/bin/renamed".to_string(), pidfd(pid));
        drop(exits_3.stdin.take());

        assert_eq!(
            ended(log, pid),
            ProcessEventKindWire::Ended(Some(ExitStatusWire::Exited(3)))
        );
        let (events, _) = log.read(0, usize::MAX, Duration::ZERO);
        assert_eq!(events.len(), 1, "{events:#?}");
        assert_eq!(events[0].executable, "/usr/bin/renamed");
        assert_eq!(events[0].process, process);
        exits_3.wait().unwrap();
    }

    #[test]
    fn an_exit_reaped_before_it_is_read_has_a_status_only_where_the_kernel_keeps_it() {
        let log: &'static ProcessEventLog = Box::leak(Box::new(ProcessEventLog::new(8)));
        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
        let pid = child.id();
        let process = openshell_binary_identity::observe_process(pid).unwrap();
        let descriptor = pidfd(pid);
        child.wait().unwrap();
        watch(log, process, "/bin/true".to_string(), descriptor);

        // Kernels that keep the status with the pidfd still report it.
        assert!(matches!(
            ended(log, pid),
            ProcessEventKindWire::Ended(None | Some(ExitStatusWire::Exited(0)))
        ));
    }
}
