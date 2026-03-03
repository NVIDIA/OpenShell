#![allow(unsafe_code)]
//! Hardware-isolated microVM gateway using libkrun.
//!
//! This crate provides a safe Rust interface over the [libkrun](https://github.com/containers/libkrun)
//! C library for running processes inside lightweight microVMs. On macOS ARM64,
//! libkrun uses Apple's Hypervisor.framework (HVF); on Linux it uses KVM.
//!
//! # Architecture
//!
//! libkrun bundles a VMM (Virtual Machine Monitor) in a dynamic library with a
//! simple C API. Combined with libkrunfw (which bundles a Linux kernel), it can
//! boot a microVM in milliseconds with minimal resource overhead.
//!
//! The guest's root filesystem is mapped from a host directory via virtio-fs.
//! Networking uses TSI (Transparent Socket Impersonation) by default, allowing
//! the guest to transparently access host network endpoints without explicit
//! network configuration.
//!
//! # Usage
//!
//! ```no_run
//! use navigator_gateway::KrunContext;
//!
//! let ctx = KrunContext::builder()
//!     .vcpus(1)
//!     .memory_mib(128)
//!     .rootfs("./my-alpine-rootfs")
//!     .workdir("/")
//!     .exec("/bin/echo", &["Hello from a hardware-isolated microVM!"])
//!     .build()
//!     .expect("failed to configure microVM");
//!
//! // Boots the VM and never returns on success.
//! // The process exits with the guest workload's exit code.
//! ctx.start_enter().expect("failed to start microVM");
//! ```
//!
//! # Prerequisites
//!
//! - **macOS ARM64**: Install via Homebrew: `brew tap slp/krun && brew install libkrun`
//! - **Linux**: Build and install libkrunfw + libkrun from source
//! - A root filesystem directory containing an aarch64 Linux userspace
//!   (e.g., [Alpine minirootfs](https://alpinelinux.org/downloads/))

mod context;
mod error;
mod ffi;

pub use context::{KrunContext, KrunContextBuilder, PortMapping, VirtiofsMount};
pub use error::GatewayError;

/// Wait for a child process to exit and return its exit status.
///
/// This is a thin wrapper over `waitpid(2)` for use after [`KrunContext::fork_start`].
pub fn wait_for_pid(pid: u32) -> Result<i32, GatewayError> {
    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid.cast_signed(), &raw mut status, 0) };
    if ret < 0 {
        return Err(GatewayError::Fork(std::io::Error::last_os_error()));
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Ok(128 + libc::WTERMSIG(status))
    } else {
        Ok(status)
    }
}

/// Check if a child process is still alive (non-blocking).
///
/// Uses `waitpid(WNOHANG)` to check if the child has exited without blocking.
/// This correctly detects zombie processes (which `kill(pid, 0)` does not —
/// zombies are still signalable). If the child has exited, it is reaped.
///
/// Returns `true` if the process is still running, `false` if it has exited
/// or the PID is invalid.
///
/// **Warning**: If the child has exited, this function reaps it. A subsequent
/// call to [`wait_for_pid`] on the same PID will fail with ECHILD.
pub fn is_pid_alive(pid: u32) -> bool {
    let mut status: libc::c_int = 0;
    // waitpid with WNOHANG returns:
    //   0        — child still running
    //   pid      — child has exited (reaped)
    //   -1       — error (e.g., not our child, invalid pid)
    let ret = unsafe { libc::waitpid(pid.cast_signed(), &raw mut status, libc::WNOHANG) };
    ret == 0
}
