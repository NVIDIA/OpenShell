// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Guest PID 1: minimal system setup, then run `serve` as a child and reap
//! every orphan. PID 1 runs from a root that holds only the shim (a
//! Firecracker initramfs or a minimal gVisor OCI root); the workload rootfs
//! is mounted at [`crate::launch::WORKLOAD_ROOT`]. When `serve` exits the guest stops (Firecracker powers off,
//! gVisor's container exits).
use crate::launch::Substrate;
use anyhow::{Context, Result};
use std::{
    ffi::CString,
    sync::atomic::{AtomicI32, Ordering},
};

/// Firecracker config disk holding `launch.json`.
pub const CONFIG_DEVICE: &str = "/dev/vdb";
/// Firecracker disk holding the workload rootfs.
pub const WORKLOAD_DEVICE: &str = "/dev/vda";
pub const CONFIG_MOUNT: &str = "/run/openshell/config";
/// gVisor bind mount holding the backend socket.
pub const CHANNEL_DIR: &str = "/run/openshell/chan";
/// gVisor launch file, copied into the container-private rootfs by the driver.
pub const GVISOR_LAUNCH: &str = "/run/openshell/launch.json";

fn mount(source: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: &str) -> Result<()> {
    std::fs::create_dir_all(target).ok();
    let (source, target, fstype, data) = (
        CString::new(source)?,
        CString::new(target)?,
        CString::new(fstype)?,
        CString::new(data)?,
    );
    // SAFETY: all pointers are valid NUL-terminated strings for the call.
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            data.as_ptr().cast(),
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EBUSY) {
            return Err(error).with_context(|| format!("mount {}", target.to_string_lossy()));
        }
    }
    Ok(())
}

pub fn unmount(target: &str) -> Result<()> {
    let target = CString::new(target)?;
    // SAFETY: valid NUL-terminated path.
    if unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn loopback_up() -> Result<()> {
    // SAFETY: an AF_INET datagram socket used only for interface ioctls.
    unsafe {
        let socket = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if socket < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut request: libc::ifreq = std::mem::zeroed();
        for (slot, byte) in request.ifr_name.iter_mut().zip(b"lo\0") {
            *slot = *byte as libc::c_char;
        }
        let mut result = libc::ioctl(socket, libc::SIOCGIFFLAGS, &mut request);
        if result == 0 {
            request.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            result = libc::ioctl(socket, libc::SIOCSIFFLAGS, &request);
        }
        let error = std::io::Error::last_os_error();
        libc::close(socket);
        if result != 0 {
            return Err(error.into());
        }
    }
    Ok(())
}

fn firecracker_setup() -> Result<()> {
    let nosuid = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    mount("proc", "/proc", "proc", nosuid, "")?;
    mount("sysfs", "/sys", "sysfs", nosuid, "")?;
    mount("devtmpfs", "/dev", "devtmpfs", libc::MS_NOSUID, "mode=0755")?;
    mount(
        "devpts",
        "/dev/pts",
        "devpts",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "mode=0620,ptmxmode=0666",
    )?;
    let _ = std::os::unix::fs::symlink("pts/ptmx", "/dev/ptmx");
    mount(
        "tmpfs",
        "/dev/shm",
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        "mode=1777",
    )?;
    mount(
        "tmpfs",
        "/tmp",
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        "mode=1777",
    )?;
    mount(
        "tmpfs",
        "/run",
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        "mode=0755",
    )?;
    if let Err(error) = mount("cgroup2", "/sys/fs/cgroup", "cgroup2", nosuid, "") {
        eprintln!("sandbox-shim init: cgroup2 unavailable: {error:#}");
    }
    loopback_up().context("bring up loopback")?;
    // SAFETY: valid buffer and length.
    unsafe { libc::sethostname(c"openshell".as_ptr(), 9) };
    mount(
        CONFIG_DEVICE,
        CONFIG_MOUNT,
        "ext4",
        libc::MS_RDONLY | nosuid,
        "",
    )
    .context("mount launch config disk")?;
    // The workload rootfs is a separate disk; the shim's own root is the
    // initramfs, which no workload process can reach.
    mount(WORKLOAD_DEVICE, crate::launch::WORKLOAD_ROOT, "ext4", 0, "")
        .context("mount workload rootfs disk")?;
    Ok(())
}

fn power_off() -> ! {
    // SAFETY: final system calls of guest init.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
        libc::_exit(1)
    }
}

const SWITCHED: &str = "OPENSHELL_SHIM_SWITCHED_ROOT";

/// Move PID 1 off the initramfs onto a tmpfs root, as switch_root does on a
/// normal boot. The kernel never lets `rootfs` itself be pivoted away, and
/// workload processes enter their rootfs with pivot_root.
fn switch_root() -> Result<()> {
    use std::os::unix::process::CommandExt;
    let new_root = "/newroot";
    mount(
        "tmpfs",
        new_root,
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        "mode=0755",
    )?;
    std::fs::copy("/init", format!("{new_root}/init")).context("copy shim to new root")?;
    for dir in ["dev", "proc", "sys", "run", "tmp"] {
        std::fs::create_dir_all(format!("{new_root}/{dir}"))?;
    }
    std::env::set_current_dir(new_root)?;
    // SAFETY: plain mount/chroot syscalls with valid NUL-terminated paths.
    unsafe {
        if libc::mount(
            c".".as_ptr(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_MOVE,
            std::ptr::null(),
        ) != 0
            || libc::chroot(c".".as_ptr()) != 0
        {
            return Err(std::io::Error::last_os_error()).context("switch root");
        }
    }
    std::env::set_current_dir("/")?;
    let error = std::process::Command::new("/init")
        .args(std::env::args_os().skip(1))
        .env(SWITCHED, "1")
        .exec();
    Err(error).context("re-exec init on the new root")
}

pub fn run(substrate: Substrate) -> Result<()> {
    if substrate == Substrate::Firecracker
        && std::env::var_os(SWITCHED).is_none()
        && let Err(error) = switch_root()
    {
        eprintln!("sandbox-shim init: {error:#}");
        power_off();
    }
    if substrate == Substrate::Firecracker
        && let Err(error) = firecracker_setup()
    {
        eprintln!("sandbox-shim init: {error:#}");
        power_off();
    }
    let me = std::env::current_exe()?;
    let child = std::process::Command::new(me)
        .args(["serve", "--substrate", substrate.as_str()])
        .spawn()
        .context("start serve")?;
    let serve = child.id() as i32;
    SERVE_PID.store(serve, Ordering::Relaxed);
    // SAFETY: the handler only performs an async-signal-safe kill.
    unsafe {
        libc::signal(libc::SIGTERM, forward as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, forward as *const () as libc::sighandler_t);
    }
    let code = loop {
        let mut status = 0;
        // SAFETY: plain wait for any child.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid == serve {
            break if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                1
            };
        }
        if pid < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
            break 1;
        }
    };
    println!("sandbox-shim init: serve exited with {code}");
    match substrate {
        Substrate::Firecracker => power_off(),
        Substrate::Gvisor => std::process::exit(code),
    }
}

static SERVE_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward(signal: libc::c_int) {
    let pid = SERVE_PID.load(Ordering::Relaxed);
    if pid > 0 {
        // SAFETY: kill is async-signal-safe.
        unsafe { libc::kill(pid, signal) };
    }
}
