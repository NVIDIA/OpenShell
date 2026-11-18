// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native socket and DNS mediation inside a Firecracker guest, built on the
//! production `openshell-sandbox` mechanisms: one launcher thread owns a
//! networking-only seccomp user-notification listener that every workload
//! process inherits, and the production `NetworkBroker` injects loopback-bound
//! sockets, serves the DNS relay on `127.0.0.53:53`, and queues external TCP
//! opens for the supervisor. Workloads need no proxy settings.
use crate::launch::WORKLOAD_ROOT;
use anyhow::{Context, Result, ensure};
use openshell_binary_identity::{ExecutablePathView, ProcfsIdentityResolver};
use openshell_isolation_interface::contract::ResolveError;
use openshell_sandbox::{
    binary_pins::BinaryIdentityPins,
    linux::{child_seccomp, seccomp_notify, workload_launcher::WorkloadLauncher},
    network_broker::NetworkBroker,
};
use std::{
    os::{fd::OwnedFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    sync::Arc,
};

/// Executables whose root is neither the workload rootfs nor the shim's root,
/// such as processes in a nested container, are reported under this prefix
/// with their path inside their own root. Policy must name them explicitly.
pub const NESTED_ROOT_PREFIX: &str = "/.openshell/nested-root";
/// The shim's own executables (ancestors of every workload process).
pub const SHIM_ROOT_PREFIX: &str = "/.openshell/shim";

pub struct NativeNetwork {
    pub broker: NetworkBroker,
    pub launcher: WorkloadLauncher,
    pub pins: BinaryIdentityPins,
}

impl NativeNetwork {
    /// Qualify the guest kernel and start the launcher and broker. Any
    /// failure is fatal: the shim never falls back to an unmediated or
    /// proxy-only network.
    pub fn start() -> Result<Arc<Self>> {
        let probe = seccomp_notify::probe_notification_api()
            .context("seccomp user notification is unavailable")?;
        ensure!(
            probe.notification_round_trip() && probe.addfd_send(),
            "seccomp user notification lacks ADDFD-SEND"
        );
        // The child filter must build here; installing it per launch would
        // otherwise fail only once a workload starts.
        child_seccomp::prepare_namespaced().context("prepare workload hardening")?;
        let view = WorkloadPathView::new().context("measure workload and shim roots")?;
        let (launcher, listener) = openshell_sandbox::linux::workload_launcher::start_networking()
            .context("start the workload launcher")?;
        let broker = NetworkBroker::start_networking(
            listener,
            ProcfsIdentityResolver::for_pid_namespace().with_path_view(Arc::new(view)),
        )
        .context("start the network broker")?;
        broker.confirm_healthy().context("network broker")?;
        Ok(Arc::new(Self {
            broker,
            launcher,
            pins: BinaryIdentityPins::default(),
        }))
    }

    /// Whether every mediation component still runs.
    pub fn healthy(&self) -> Result<()> {
        self.broker.confirm_healthy()?;
        ensure!(self.launcher.is_alive(), "workload launcher stopped");
        Ok(())
    }
}

/// Reports each executable by the path its own root resolves to the same
/// file, never by string shape alone.
#[derive(Debug)]
pub struct WorkloadPathView {
    workload_root: (u64, u64),
    shim_root: (u64, u64),
}

fn identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

impl WorkloadPathView {
    pub fn new() -> Result<Self> {
        Ok(Self {
            workload_root: identity(&std::fs::metadata(WORKLOAD_ROOT)?),
            shim_root: identity(&std::fs::metadata("/")?),
        })
    }

    fn failed(pid: u32, message: impl std::fmt::Display) -> ResolveError {
        ResolveError::Failed(format!("executable path of {pid}: {message}"))
    }
}

/// Candidate paths of `procfs_path` inside the process's own root. Procfs may
/// render a workload executable relative to the workload root or, if the
/// observer can reach it, through the shim's mount of that root.
pub fn candidates(procfs_path: &Path) -> Vec<PathBuf> {
    let mut paths = vec![procfs_path.to_path_buf()];
    if let Ok(inner) = procfs_path.strip_prefix(WORKLOAD_ROOT) {
        paths.push(Path::new("/").join(inner));
    }
    paths
}

/// Classify a process root and form the reported path.
pub fn report(
    root: (u64, u64),
    workload_root: (u64, u64),
    shim_root: (u64, u64),
    path: &Path,
) -> PathBuf {
    let relative = path.strip_prefix("/").unwrap_or(path);
    if root == workload_root {
        Path::new("/").join(relative)
    } else if root == shim_root {
        Path::new(SHIM_ROOT_PREFIX).join(relative)
    } else {
        Path::new(NESTED_ROOT_PREFIX).join(relative)
    }
}

impl ExecutablePathView for WorkloadPathView {
    fn report_path(&self, pid: u32, procfs_path: &Path) -> Result<PathBuf, ResolveError> {
        use rustix::fs::{Mode, OFlags, ResolveFlags};
        let root: OwnedFd = std::fs::File::open(format!("/proc/{pid}/root"))
            .map_err(|error| Self::failed(pid, format!("open root: {error}")))?
            .into();
        let root_identity = rustix::fs::fstat(&root)
            .map(|stat| (stat.st_dev, stat.st_ino))
            .map_err(|error| Self::failed(pid, format!("stat root: {error}")))?;
        let executable = std::fs::metadata(format!("/proc/{pid}/exe"))
            .map_err(|error| Self::failed(pid, format!("stat executable: {error}")))?;
        for candidate in candidates(procfs_path) {
            // Resolve inside the process's root: absolute symlinks and `..`
            // cannot leave it, and no magic link is followed.
            let Ok(file) = rustix::fs::openat2(
                &root,
                &candidate,
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
            ) else {
                continue;
            };
            let Ok(stat) = rustix::fs::fstat(&file) else {
                continue;
            };
            if (stat.st_dev, stat.st_ino) == identity(&executable) {
                return Ok(report(
                    root_identity,
                    self.workload_root,
                    self.shim_root,
                    &candidate,
                ));
            }
        }
        Err(Self::failed(
            pid,
            format!(
                "{} does not name the running executable in its root",
                procfs_path.display()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_cover_workload_mount_paths() {
        assert_eq!(
            candidates(Path::new("/run/openshell/workload/usr/bin/curl")),
            vec![
                PathBuf::from("/run/openshell/workload/usr/bin/curl"),
                PathBuf::from("/usr/bin/curl")
            ]
        );
        assert_eq!(
            candidates(Path::new("/usr/bin/curl")),
            vec![PathBuf::from("/usr/bin/curl")]
        );
    }

    #[test]
    fn report_qualifies_paths_outside_the_workload_root() {
        let (workload, shim, nested) = ((1, 2), (3, 4), (5, 6));
        let path = Path::new("/usr/bin/curl");
        assert_eq!(report(workload, workload, shim, path), path);
        assert_eq!(
            report(shim, workload, shim, Path::new("/init")),
            Path::new("/.openshell/shim/init")
        );
        assert_eq!(
            report(nested, workload, shim, Path::new("/bin/busybox")),
            Path::new("/.openshell/nested-root/bin/busybox")
        );
    }

    #[test]
    fn view_verifies_the_running_executable() {
        // In this test the "workload root" is the host root itself.
        let view = WorkloadPathView {
            workload_root: identity(&std::fs::metadata("/").unwrap()),
            shim_root: (u64::MAX, u64::MAX),
        };
        let pid = std::process::id();
        let exe = std::fs::read_link("/proc/self/exe").unwrap();
        assert_eq!(view.report_path(pid, &exe).unwrap(), exe);
        // A path that names another file is refused rather than reported.
        assert!(view.report_path(pid, Path::new("/bin/sh")).is_err());
        assert!(view.report_path(pid, Path::new("/nonexistent")).is_err());
    }
}
