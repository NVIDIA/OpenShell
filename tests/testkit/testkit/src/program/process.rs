// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! One test process: started in its own process group, waited for with a
//! timeout, and stopped with `SIGTERM`, a grace period, then `SIGKILL`.
//!
//! The process group is killed whenever the test process ends, so a test's
//! helpers, such as CLI processes, cannot outlive it.

use std::io;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// How the test process ended.
#[derive(Debug)]
pub enum Ended {
    Exited(ExitStatus),
    /// Stopped after the timeout.
    TimedOut,
    /// Stopped because the supervisor was asked to stop.
    Interrupted,
}

/// Start `command` in its own process group.
pub fn spawn(command: &mut Command) -> io::Result<Child> {
    command.process_group(0).spawn()
}

/// Wait for `child`, stopping it after `timeout` or once the supervisor has
/// been asked to stop (see [`install_stop_handlers`]). The child is reaped
/// and its group killed on every path, including errors.
pub fn wait(child: &mut Child, timeout: Duration, grace: Duration) -> io::Result<Ended> {
    let result = wait_or_stop(child, timeout, grace);
    if result.is_err() {
        let _ = reap(child);
    }
    result
}

fn wait_or_stop(child: &mut Child, timeout: Duration, grace: Duration) -> io::Result<Ended> {
    let deadline = Instant::now() + timeout;
    loop {
        if has_exited(child)? {
            return Ok(Ended::Exited(reap(child)?));
        }
        if stop_requested() {
            stop(child, grace)?;
            return Ok(Ended::Interrupted);
        }
        if Instant::now() >= deadline {
            stop(child, grace)?;
            return Ok(Ended::TimedOut);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// `SIGTERM` the group, wait up to `grace`, then `SIGKILL` it. A stop signal
/// during the grace period, or a second one in all, cuts it short.
fn stop(child: &mut Child, grace: Duration) -> io::Result<ExitStatus> {
    signal_group(child, libc::SIGTERM);
    let deadline = Instant::now() + grace;
    let before = stop_requests();
    let cut_short = || {
        let now = stop_requests();
        now > before || now >= 2
    };
    while Instant::now() < deadline && !cut_short() && !has_exited(child)? {
        std::thread::sleep(POLL_INTERVAL);
    }
    reap(child)
}

/// Kill whatever is left of the group, then collect the exit status.
fn reap(child: &mut Child) -> io::Result<ExitStatus> {
    signal_group(child, libc::SIGKILL);
    child.wait()
}

static STOP_REQUESTS: AtomicUsize = AtomicUsize::new(0);

fn stop_requests() -> usize {
    STOP_REQUESTS.load(Ordering::SeqCst)
}

/// Whether the supervisor has been asked to stop since it started.
pub fn stop_requested() -> bool {
    stop_requests() > 0
}

fn pid(child: &Child) -> libc::pid_t {
    libc::pid_t::try_from(child.id()).expect("pid fits in pid_t")
}

/// Whether the child has exited, without reaping it. While it is unreaped
/// its PID, and so its process group ID, cannot be reused, so signalling the
/// group cannot reach an unrelated process.
#[cfg(target_os = "linux")]
fn has_exited(child: &mut Child) -> io::Result<bool> {
    // SAFETY: `info` is a valid out-pointer, and `WNOWAIT` leaves the child
    // for `Child::wait` to reap.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let result = libc::waitid(
            libc::P_PID,
            child.id(),
            &raw mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        );
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(info.si_pid() != 0)
    }
}

/// Whether the child has exited, reaping it. `waitid` with `WNOWAIT` is not
/// reliable outside Linux (see golang/go#19314), so the group is killed just
/// after the leader is reaped. Its ID could in principle be reused in that
/// window, though a new process would have to get the same PID and lead a
/// group.
#[cfg(not(target_os = "linux"))]
fn has_exited(child: &mut Child) -> io::Result<bool> {
    Ok(child.try_wait()?.is_some())
}

fn signal_group(child: &Child, signal: libc::c_int) {
    // SAFETY: plain syscall to the child's own group (see `spawn`). ESRCH, an
    // empty group, is fine.
    unsafe {
        libc::kill(-pid(child), signal);
    }
}

extern "C" fn on_stop(_signal: libc::c_int) {
    STOP_REQUESTS.fetch_add(1, Ordering::SeqCst);
}

/// Count `SIGINT`, `SIGTERM`, and `SIGHUP` as stop requests instead of dying.
/// Tests run in their own process group, so a Ctrl-C at the terminal reaches
/// only the supervisor, which must stop the test.
pub fn install_stop_handlers() -> io::Result<()> {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: the handler only touches an atomic, which is
        // async-signal-safe.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_stop as *const () as libc::sighandler_t;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&raw mut action.sa_mask);
            if libc::sigaction(signal, &raw const action, std::ptr::null_mut()) == -1 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use super::{Ended, spawn, wait};

    fn sh(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]).stdin(Stdio::null());
        command
    }

    #[test]
    fn exit_status_is_kept() {
        let mut child = spawn(&mut sh("exit 3")).unwrap();
        let ended = wait(&mut child, Duration::from_secs(10), Duration::from_secs(1)).unwrap();
        assert!(
            matches!(ended, Ended::Exited(status) if status.code() == Some(3)),
            "{ended:?}"
        );
    }

    #[test]
    fn timeout_terminates_the_test() {
        let started = Instant::now();
        let mut child = spawn(&mut sh("sleep 30")).unwrap();
        let ended = wait(
            &mut child,
            Duration::from_millis(200),
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(matches!(ended, Ended::TimedOut), "{ended:?}");
        // `sleep` dies on SIGTERM, well inside the grace period.
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_test_ignoring_sigterm_is_killed_after_the_grace_period() {
        let started = Instant::now();
        let mut child = spawn(&mut sh("trap '' TERM; sleep 30")).unwrap();
        let ended = wait(
            &mut child,
            Duration::from_millis(200),
            Duration::from_millis(500),
        )
        .unwrap();
        assert!(matches!(ended, Ended::TimedOut), "{ended:?}");
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(700), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    }
}
