// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cross-platform "die when my parent dies" primitive.
//!
//! The VM driver spawns a chain of subprocesses (compute driver → `--internal-run-vm`
//! launcher → gvproxy + libkrun fork). If any link in that chain is killed
//! with SIGKILL — or simply crashes — the children are reparented to init
//! and survive indefinitely, leaking libkrun workers and gvproxy
//! instances.
//!
//! This module exposes two functions:
//! * [`die_with_parent`] — configure the kernel (Linux) or a helper
//!   thread (BSDs, incl. macOS) to SIGKILL the current process when its
//!   parent dies. Call it from `main` in every subprocess we spawn
//!   along the chain. Idempotent-ish (each call is a full setup — see
//!   the runtime.rs comment at the single call site).
//! * [`die_with_parent_cleanup`] — same as above, but on the BSD path a
//!   best-effort cleanup callback runs *before* this process exits.
//!   This matters when we own a non-Rust child (e.g. gvproxy) that
//!   cannot arm its own procguard; the callback lets us SIGTERM it
//!   first.
//!
//! The Linux path uses `nix::sys::prctl::set_pdeathsig(SIGKILL)`, and
//! the BSD path uses `smol-rs/polling` with its `kqueue::Process` +
//! `ProcessOps::Exit` filter. Both are well-tested library surfaces;
//! we keep only the glue code and the pre-arming parent-liveness
//! re-check.

/// Arrange for the current process to receive SIGKILL if its parent dies.
///
/// On Linux this sets `PR_SET_PDEATHSIG` to SIGKILL (via
/// `nix::sys::prctl`). The kernel delivers SIGKILL the moment
/// `getppid()` changes away from the original parent.
///
/// On the BSD family (macOS, FreeBSD, etc.) this spawns a detached
/// helper thread that uses `kqueue` with `EVFILT_PROC | NOTE_EXIT` on
/// the parent PID. When the parent exits the thread calls `exit(1)`,
/// which is sufficient for our use case — we are not a critical daemon
/// that needs to drain state; we are a VM launcher / gRPC driver whose
/// entire job is tied to the parent's lifetime.
pub fn die_with_parent() -> Result<(), String> {
    die_with_parent_cleanup(|| ())
}

/// Like [`die_with_parent`], but run `cleanup` (best-effort,
/// async-signal-unsafe — it runs on the helper thread) immediately
/// before terminating the process. Use this when we own children that
/// cannot arm their own procguard; the cleanup hook is the only chance
/// we get to send them SIGTERM after the kernel reparents us.
///
/// On Linux the cleanup is a no-op: `PR_SET_PDEATHSIG` delivers SIGKILL
/// directly to us, there is no Rust-controlled moment between "parent
/// died" and "we die" in which we could run a callback.
pub fn die_with_parent_cleanup<F>(cleanup: F) -> Result<(), String>
where
    F: FnOnce() + Send + 'static,
{
    #[cfg(target_os = "linux")]
    {
        // Linux has no opportunity for a cleanup hook — the kernel
        // delivers SIGKILL directly. Callers that need pre-exit cleanup
        // must combine this with a `pre_exec` PR_SET_PDEATHSIG on their
        // children (so the kernel cascades) or rely on process-group
        // killpg from a signal handler in the parent.
        let _ = cleanup; // intentionally dropped
        install_linux_pdeathsig()
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    {
        install_bsd_kqueue_watcher(cleanup)
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    )))]
    {
        let _ = cleanup;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn install_linux_pdeathsig() -> Result<(), String> {
    use nix::sys::signal::Signal;
    use nix::unistd::getppid;

    // Race: if the parent already died between fork/exec and this call,
    // `getppid()` now returns 1 and PR_SET_PDEATHSIG will never fire.
    // Read the current parent first so we can detect that case and exit.
    let original_ppid = getppid();
    if original_ppid == nix::unistd::Pid::from_raw(1) {
        return Err("process was already orphaned before procguard armed".to_string());
    }

    nix::sys::prctl::set_pdeathsig(Signal::SIGKILL)
        .map_err(|err| format!("prctl(PR_SET_PDEATHSIG) failed: {err}"))?;

    // Re-check after arming: the parent may have died between getppid()
    // and prctl(). If so, PR_SET_PDEATHSIG missed its window.
    if getppid() != original_ppid {
        return Err("parent exited before procguard could arm".to_string());
    }

    Ok(())
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
fn install_bsd_kqueue_watcher<F>(cleanup: F) -> Result<(), String>
where
    F: FnOnce() + Send + 'static,
{
    use nix::unistd::getppid;
    use polling::os::kqueue::{PollerKqueueExt, Process, ProcessOps};
    use polling::{Events, PollMode, Poller};

    let parent_pid = getppid();
    if parent_pid == nix::unistd::Pid::from_raw(1) {
        return Err("process was already orphaned before procguard armed".to_string());
    }
    let parent_pid_nz = std::num::NonZeroI32::new(parent_pid.as_raw())
        .ok_or_else(|| "getppid returned 0 unexpectedly".to_string())?;

    // Build the poller on the caller's thread so any setup error
    // surfaces synchronously. `EVFILT_PROC | NOTE_EXIT` is a one-shot
    // filter, so `PollMode::Oneshot` matches the kernel semantics.
    //
    // SAFETY: `Process::from_pid` requires the PID to "be tied to an
    // actual child process". Our parent is alive at this point — we
    // re-check `getppid()` immediately after registration to close the
    // race where the parent dies between the read above and the
    // `add_filter` call. The BSD kqueue implementation accepts any
    // live PID, not just our own children; the "child" wording in the
    // polling docs is carried over from historical terminology in the
    // kqueue(2) manpage. The kernel guarantees NOTE_EXIT fires if the
    // PID is valid at registration.
    let poller = Poller::new().map_err(|err| format!("polling: Poller::new failed: {err}"))?;
    let key = 1;
    #[allow(unsafe_code)]
    // SAFETY requirement is documented on the enclosing function: the
    // PID was just read from `getppid()` and re-checked below, so it
    // points at a live process. `Process::from_pid` is an
    // entry-in-the-kernel-table registration — the kernel validates
    // the PID when the filter is added.
    let filter = unsafe { Process::from_pid(parent_pid_nz, ProcessOps::Exit) };
    poller
        .add_filter(filter, key, PollMode::Oneshot)
        .map_err(|err| format!("polling: add_filter(NOTE_EXIT, {parent_pid_nz}) failed: {err}"))?;

    // Between getppid() and the registered filter the parent may
    // already have died. Detect that and abort so the caller can bail.
    if getppid() != parent_pid {
        return Err("parent exited before procguard could arm".to_string());
    }

    // Hand off to a dedicated OS thread. Block in `poller.wait()`
    // until the single NOTE_EXIT event fires, run the cleanup, then
    // exit. We prefer `exit(1)` over `kill(getpid, SIGKILL)` so the
    // callback gets to complete — SIGKILL would race it. Our children
    // have their own procguards armed and will notice `getppid() ==
    // 1` shortly after, so we do not need Linux-semantics exactness.
    std::thread::Builder::new()
        .name("procguard".to_string())
        .spawn(move || {
            let mut events = Events::new();
            // Block indefinitely; the filter is Oneshot so we expect
            // exactly one event (parent's NOTE_EXIT) or a spurious
            // wakeup we treat the same way.
            let _ = poller.wait(&mut events, None);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(cleanup));
            std::process::exit(1);
        })
        .map(|_| ())
        .map_err(|e| format!("failed to spawn procguard thread: {e}"))
}
