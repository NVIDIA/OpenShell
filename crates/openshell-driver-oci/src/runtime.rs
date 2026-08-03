// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Direct invocation of the configured low-level OCI runtime (`runc`,
//! `crun`, ...) as a child process of this driver.
//!
//! This is the mechanism that makes `OpenShell` — not containerd — the
//! process that spawns the sandbox's root process. containerd is used
//! only for image pull/unpack and snapshot management, behind the
//! `openshell-rootfs` provider boundary; it is never asked to create or
//! run a container or task. This module builds a standard OCI bundle
//! directory (`config.json` + a mounted `rootfs/`) from the provider's
//! prepared mounts, and drives it through the runtime's standard
//! `create`/`start`/`state`/`kill`/`delete` CLI contract — the same
//! integration pattern containerd's own shim, CRI-O, and Podman use,
//! just invoked directly by this driver instead of by containerd.
//!
//! Verified end to end against a real `runc` and `crun` install: pull a
//! snapshot from containerd, mount it into a bundle directory ourselves,
//! `create`/`start`/`state`/`delete` against both runtimes successfully,
//! and confirmed a bogus `runtime_binary` surfaces a clear "no such file or
//! directory" error rather than being silently ignored.
//!
//! Because we no longer register a containerd `Container`/`Task` object,
//! the snapshot this bundle mounts has nothing else protecting it from
//! containerd's background garbage collector — the rootfs provider
//! protects it with a containerd lease for the sandbox's lifetime (see
//! `openshell_rootfs::ContainerdRootfsProvider`).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use openshell_rootfs::RootfsMount;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("failed to run {command}: {reason}")]
    CommandFailed { command: String, reason: String },
    #[error("failed to parse `{runtime_binary} state` output: {reason}")]
    MalformedState {
        runtime_binary: String,
        reason: String,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Coarse lifecycle status reported by `runtime state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeStatus {
    Creating,
    Created,
    Running,
    Stopped,
    Paused,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct RuntimeState {
    pub status: RuntimeStatus,
    pub pid: u32,
}

/// Directory this driver stores a sandbox's OCI bundle (`config.json` plus
/// the mounted `rootfs/`) under.
#[must_use]
pub fn bundle_dir(state_dir: &Path, sandbox_id: &str) -> PathBuf {
    state_dir.join("bundles").join(sandbox_id)
}

/// Mount the rootfs provider's prepared mount at `<bundle_dir>/rootfs`.
///
/// This driver performs this mount itself (rather than delegating it to
/// containerd's task service, which normally does this as part of task
/// creation) because it never creates a containerd task.
pub fn mount_rootfs(bundle_dir: &Path, mount: &RootfsMount) -> Result<(), RuntimeError> {
    let rootfs = bundle_dir.join("rootfs");
    std::fs::create_dir_all(&rootfs)?;

    let mut args: Vec<String> = vec![
        "-t".to_string(),
        mount.fs_type.clone(),
        mount.source.clone(),
    ];
    args.push(rootfs.to_string_lossy().to_string());
    if !mount.options.is_empty() {
        args.push("-o".to_string());
        args.push(mount.options.join(","));
    }
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    run("mount", &args_ref)
}

/// Best-effort unmount of a bundle's rootfs. Never fails the caller: a
/// bundle that was never fully mounted (e.g. an error before
/// `mount_rootfs` ran) is not an error condition during cleanup.
pub fn unmount_rootfs(bundle_dir: &Path) {
    let rootfs = bundle_dir.join("rootfs");
    let _ = run("umount", &[rootfs.to_string_lossy().as_ref()]);
}

/// Write the OCI runtime spec into the bundle directory.
pub fn write_config(bundle_dir: &Path, spec: &oci_spec::runtime::Spec) -> Result<(), RuntimeError> {
    std::fs::create_dir_all(bundle_dir)?;
    let json = serde_json::to_vec_pretty(spec).map_err(|err| RuntimeError::CommandFailed {
        command: "serialize OCI spec".to_string(),
        reason: err.to_string(),
    })?;
    std::fs::write(bundle_dir.join("config.json"), json)?;
    Ok(())
}

/// Directory this driver points the low-level runtime's own `--root`
/// (state root) at.
///
/// Scoping this under the driver's own `state_dir` means `runc
/// state`/`kill`/`delete` for a given container ID can never collide with
/// an unrelated `runc`/`crun` consumer on the same host sharing the
/// runtime's compiled-in global default root (e.g. another containerd
/// shim, or a manual `runc` invocation).
#[must_use]
pub fn runtime_root(state_dir: &Path) -> PathBuf {
    state_dir.join("runtime-root")
}

/// `runc create --bundle <dir> --pid-file <dir>/pid <id>`, with the
/// container's own stdio redirected to log files inside the bundle.
///
/// Deliberately does not use a piped/captured-output `Command` for this
/// call: the container's init process inherits this command's stdio fds,
/// and (unlike `state`/`delete`, whose own process exits immediately) it
/// stays alive after `create` returns, holding those fds open. Capturing
/// output via a pipe here would hang forever waiting for EOF that never
/// comes. Real log files avoid that without losing the container's
/// output.
pub fn create(
    runtime_binary: &str,
    runtime_root: &Path,
    bundle_dir: &Path,
    container_id: &str,
) -> Result<(), RuntimeError> {
    std::fs::create_dir_all(runtime_root)?;
    let stdout_log = bundle_dir.join("stdout.log");
    let stderr_log = bundle_dir.join("stderr.log");
    let stdout = std::fs::File::create(&stdout_log)?;
    let stderr = std::fs::File::create(&stderr_log)?;

    let status = Command::new(runtime_binary)
        .args([
            "--root",
            &runtime_root.to_string_lossy(),
            "create",
            "--bundle",
            &bundle_dir.to_string_lossy(),
            container_id,
        ])
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .status()
        .map_err(|err| RuntimeError::CommandFailed {
            command: format!("{runtime_binary} create {container_id}"),
            reason: err.to_string(),
        })?;

    if status.success() {
        Ok(())
    } else {
        let stderr_contents = std::fs::read_to_string(&stderr_log).unwrap_or_default();
        Err(RuntimeError::CommandFailed {
            command: format!("{runtime_binary} create {container_id}"),
            reason: stderr_contents,
        })
    }
}

/// `runc start <id>`.
pub fn start(
    runtime_binary: &str,
    runtime_root: &Path,
    container_id: &str,
) -> Result<(), RuntimeError> {
    let root = runtime_root.to_string_lossy();
    run(runtime_binary, &["--root", &root, "start", container_id])
}

/// `runc kill <id> <signal>`. Errors are the caller's to decide whether to
/// ignore (e.g. the process may have already exited).
pub fn kill(
    runtime_binary: &str,
    runtime_root: &Path,
    container_id: &str,
    signal: u32,
) -> Result<(), RuntimeError> {
    let root = runtime_root.to_string_lossy();
    let signal_str = signal.to_string();
    run(
        runtime_binary,
        &["--root", &root, "kill", container_id, &signal_str],
    )
}

/// `runc delete -f <id>` (force: also removes a still-running container).
pub fn delete(
    runtime_binary: &str,
    runtime_root: &Path,
    container_id: &str,
) -> Result<(), RuntimeError> {
    let root = runtime_root.to_string_lossy();
    run(
        runtime_binary,
        &["--root", &root, "delete", "-f", container_id],
    )
}

/// `runc state <id>`, parsed into a [`RuntimeState`].
pub fn state(
    runtime_binary: &str,
    runtime_root: &Path,
    container_id: &str,
) -> Result<RuntimeState, RuntimeError> {
    let output = Command::new(runtime_binary)
        .args([
            "--root",
            &runtime_root.to_string_lossy(),
            "state",
            container_id,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|err| RuntimeError::CommandFailed {
            command: format!("{runtime_binary} state {container_id}"),
            reason: err.to_string(),
        })?;
    if !output.status.success() {
        return Err(RuntimeError::CommandFailed {
            command: format!("{runtime_binary} state {container_id}"),
            reason: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|err| RuntimeError::MalformedState {
            runtime_binary: runtime_binary.to_string(),
            reason: err.to_string(),
        })?;
    let status_str = json["status"].as_str().unwrap_or("unknown");
    let status = match status_str {
        "creating" => RuntimeStatus::Creating,
        "created" => RuntimeStatus::Created,
        "running" => RuntimeStatus::Running,
        "stopped" => RuntimeStatus::Stopped,
        "paused" => RuntimeStatus::Paused,
        _ => RuntimeStatus::Unknown,
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let pid = json["pid"].as_u64().unwrap_or(0) as u32;
    Ok(RuntimeState { status, pid })
}

/// List sandbox IDs this driver currently has a bundle directory for.
///
/// This driver tracks its own sandboxes by scanning its state directory
/// (the same pattern the VM driver uses to rediscover accepted sandboxes
/// on restart) rather than asking containerd or the runtime for a global
/// list — containerd has no record of these containers at all, and
/// `runc list` would return every container under the runtime's
/// configured root, not just this driver's.
pub fn list_sandbox_ids(state_dir: &Path) -> Vec<String> {
    let bundles_root = state_dir.join("bundles");
    let Ok(entries) = std::fs::read_dir(&bundles_root) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect()
}

fn run(cmd: &str, args: &[&str]) -> Result<(), RuntimeError> {
    let output = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| RuntimeError::CommandFailed {
            command: format!("{cmd} {}", args.join(" ")),
            reason: err.to_string(),
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(RuntimeError::CommandFailed {
            command: format!("{cmd} {}", args.join(" ")),
            reason: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_dir_is_scoped_under_bundles_subdir() {
        let path = bundle_dir(Path::new("/var/lib/openshell/driver-oci"), "sandbox-1");
        assert_eq!(
            path,
            PathBuf::from("/var/lib/openshell/driver-oci/bundles/sandbox-1")
        );
    }

    #[test]
    fn runtime_root_is_scoped_under_state_dir() {
        let path = runtime_root(Path::new("/var/lib/openshell/driver-oci"));
        assert_eq!(
            path,
            PathBuf::from("/var/lib/openshell/driver-oci/runtime-root")
        );
    }

    #[test]
    fn list_sandbox_ids_returns_empty_for_missing_state_dir() {
        let ids = list_sandbox_ids(Path::new("/nonexistent/state/dir/that/does/not/exist"));
        assert!(ids.is_empty());
    }

    #[test]
    fn list_sandbox_ids_discovers_bundle_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundles = dir.path().join("bundles");
        std::fs::create_dir_all(bundles.join("sandbox-a")).unwrap();
        std::fs::create_dir_all(bundles.join("sandbox-b")).unwrap();
        std::fs::write(bundles.join("not-a-dir"), b"").unwrap();

        let mut ids = list_sandbox_ids(dir.path());
        ids.sort();
        assert_eq!(ids, vec!["sandbox-a".to_string(), "sandbox-b".to_string()]);
    }

    #[test]
    fn parses_runc_state_json() {
        // Shape matches real `runc state`/`crun state` output observed
        // during development against both runtimes.
        let json = br#"{"ociVersion":"1.2.1","id":"x","pid":1234,"status":"running"}"#;
        let value: serde_json::Value = serde_json::from_slice(json).unwrap();
        assert_eq!(value["status"].as_str(), Some("running"));
        assert_eq!(value["pid"].as_u64(), Some(1234));
    }
}
