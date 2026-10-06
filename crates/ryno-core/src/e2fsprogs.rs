// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host filesystem tools shared by VM image operations and gateway preflight.
//!
//! The gateway launches the VM driver with its environment unchanged. Resolve
//! tools here so both binaries select the same installation without linking the
//! driver runtime into the gateway or starting it during preflight.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tokio::sync::watch;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const INSTALL_GUIDANCE: &str = "Install e2fsprogs 1.43 or newer, or repair the selected installation and the gateway service PATH; rerun config preflight with the service account and environment";

/// Resolve a tool using the VM driver's inherited PATH and existing package prefixes.
///
/// Names are ordered alternatives: the formatter tries `mke2fs` before
/// `mkfs.ext4`. A present but broken installation returns an error and stops
/// lookup. The returned absolute path is also used for
/// image operations; the caller's environment is not changed.
pub fn resolve(names: &[&str]) -> Result<PathBuf, String> {
    resolve_in(names, &search_dirs(std::env::var_os("PATH").as_deref()))
}

fn search_dirs(path: Option<&OsStr>) -> Vec<PathBuf> {
    let mut dirs: Vec<_> = path
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
        .collect();
    // Preserve the VM driver's existing package-prefix fallbacks. Additional
    // installations, including Linux sbin directories, belong on service PATH.
    for root in ["/opt/homebrew/opt/e2fsprogs", "/usr/local/opt/e2fsprogs"] {
        dirs.push(Path::new(root).join("sbin"));
        dirs.push(Path::new(root).join("bin"));
    }
    dirs
}

fn resolve_in(names: &[&str], dirs: &[PathBuf]) -> Result<PathBuf, String> {
    for name in names {
        for directory in dirs {
            let candidate = directory.join(name);
            let metadata = match fs::metadata(&candidate) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!(
                        "inspect {}: {error}. {INSTALL_GUIDANCE}",
                        candidate.display()
                    ));
                }
            };
            if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
                return Err(format!(
                    "{} is not an executable file. {INSTALL_GUIDANCE}",
                    candidate.display()
                ));
            }
            // Canonicalization makes relative PATH entries unambiguous in the
            // report and ensures execution cannot redo PATH lookup differently.
            return candidate.canonicalize().map_err(|error| {
                format!(
                    "resolve {}: {error}. {INSTALL_GUIDANCE}",
                    candidate.display()
                )
            });
        }
    }
    Err(format!(
        "{} not found in the VM driver's search directories: {}. {INSTALL_GUIDANCE}",
        names.join(" or "),
        dirs.iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(":")
    ))
}

/// Check a formatter, `debugfs`, and `e2fsck` without creating images or driver state.
///
/// Each selected executable receives only `-V`, with null stdin, a five-second
/// deadline, and at most 8 KiB captured per stream. Errors retain the selected
/// path and the tool's diagnostics. Image health requires a separate check.
pub async fn preflight(cancellation: watch::Receiver<bool>) -> Result<Vec<String>, String> {
    preflight_in_with_cancellation(
        &search_dirs(std::env::var_os("PATH").as_deref()),
        cancellation,
    )
    .await
}

#[cfg(test)]
async fn preflight_in(dirs: &[PathBuf]) -> Result<Vec<String>, String> {
    let (_sender, cancellation) = watch::channel(false);
    preflight_in_with_cancellation(dirs, cancellation).await
}

async fn preflight_in_with_cancellation(
    dirs: &[PathBuf],
    mut cancellation: watch::Receiver<bool>,
) -> Result<Vec<String>, String> {
    let mut reports = Vec::new();
    for (names, identity) in [
        (&["mke2fs", "mkfs.ext4"][..], "mke2fs"),
        (&["debugfs"][..], "debugfs"),
        (&["e2fsck"][..], "e2fsck"),
    ] {
        let result = async {
            let path = resolve_in(names, dirs)?;
            let label = path.display();
            let output = run_version_probe(Command::new(&path), &mut cancellation)
                .await
                .map_err(|error| format!("run {label} -V: {error}. {INSTALL_GUIDANCE}"))?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !output.status.success() {
                return Err(format!(
                    "{label} -V failed with status {}\nstdout: {stdout}\nstderr: {stderr}\n{INSTALL_GUIDANCE}",
                    output.status
                ));
            }
            let version = supported_version(identity, &stdout)
                .or_else(|| supported_version(identity, &stderr))
                .ok_or_else(|| format!(
                    "{label} is not a supported {identity} executable\nstdout: {stdout}\nstderr: {stderr}\n{INSTALL_GUIDANCE}"
                ))?;
            Ok(format!("VM host tool {identity}: {label} ({version})"))
        }.await;
        match result {
            Ok(report) => reports.push(report),
            Err(error) => {
                // Retain earlier selected paths even when a later tool fails.
                reports.push(error);
                return Err(reports.join("\n"));
            }
        }
    }
    Ok(reports)
}

// Keep the group leader unreaped until group cleanup so its PID cannot be
// reused while a descendant still holds a captured output pipe open.
struct ProbeProcess {
    child: tokio::process::Child,
    group: Option<nix::unistd::Pid>,
}

impl ProbeProcess {
    fn stop_group(&mut self) -> Result<Option<nix::unistd::Pid>, String> {
        let Some(group) = self.group.take() else {
            return Ok(None);
        };
        match nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(None),
            // Darwin can return EPERM for a group containing only our exited,
            // unreaped leader. Defer judgment until after its owned reap.
            #[cfg(target_os = "macos")]
            Err(nix::errno::Errno::EPERM) => Ok(Some(group)),
            Err(error) => Err(format!("terminate version probe process group: {error}")),
        }
    }
}

impl Drop for ProbeProcess {
    fn drop(&mut self) {
        let _ = self.stop_group();
        // kill_on_drop schedules the direct child for reaping if the caller
        // aborts its future. CLI signal cancellation instead awaits cleanup.
    }
}

async fn cancelled(cancellation: &mut watch::Receiver<bool>) {
    loop {
        if *cancellation.borrow_and_update() {
            return;
        }
        if cancellation.changed().await.is_err() {
            // A closed sender does not request cancellation.
            std::future::pending::<()>().await;
        }
    }
}

async fn observe_exit(group: nix::unistd::Pid) -> Result<(), String> {
    use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

    let pid = Pid::from_raw(group.as_raw()).ok_or("invalid version probe process ID")?;
    loop {
        let exited = waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        )
        .map(|status| status.is_some());
        match exited {
            Ok(false) | Err(rustix::io::Errno::INTR) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(true) => return Ok(()),
            Err(error) => return Err(format!("observe version probe exit: {error}")),
        }
    }
}

async fn run_version_probe(
    command: Command,
    cancellation: &mut watch::Receiver<bool>,
) -> Result<std::process::Output, String> {
    use std::process::Stdio;

    if *cancellation.borrow() {
        return Err("host tool checks cancelled".to_string());
    }
    let child = tokio::process::Command::from(command)
        .arg("-V")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| error.to_string())?;
    let group = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .map(nix::unistd::Pid::from_raw)
        .ok_or_else(|| "version probe has no valid process ID".to_string())?;
    let mut probe = ProbeProcess {
        child,
        group: Some(group),
    };
    let stdout = probe
        .child
        .stdout
        .take()
        .ok_or("version probe stdout is unavailable")?;
    let stderr = probe
        .child
        .stderr
        .take()
        .ok_or("version probe stderr is unavailable")?;
    let output = tokio::select! {
        biased;
        () = cancelled(cancellation) => Err("host tool checks cancelled".to_string()),
        result = tokio::time::timeout(PROBE_TIMEOUT, async {
            let (stdout, stderr, ()) = tokio::try_join!(
                read_probe_output(stdout, "stdout"),
                read_probe_output(stderr, "stderr"),
                observe_exit(group),
            )?;
            Ok((stdout, stderr))
        }) => result.unwrap_or_else(|_| Err("timed out after 5 seconds".to_string())),
    };
    // Signal the group before reaping its leader, then retire the stored group
    // ID before awaiting anything else. No later drop can signal a reused PID.
    let group_cleanup = probe.stop_group();
    let status = tokio::time::timeout(Duration::from_secs(1), probe.child.wait())
        .await
        .map_err(|_| "version probe cleanup exceeded one second".to_string())
        .and_then(|result| result.map_err(|error| format!("reap version probe: {error}")));
    let status = match (group_cleanup, status) {
        (Ok(Some(group)), Ok(status)) => {
            // Signal 0 only queries existence; it never signals a process.
            // ESRCH after the owned reap proves no group members remain. If
            // the ID was reused, this check can only fail conservatively.
            match nix::sys::signal::killpg(group, None) {
                Err(nix::errno::Errno::ESRCH) => Ok(status),
                result => Err(format!(
                    "version probe process group remains after cleanup: {result:?}"
                )),
            }
        }
        (Ok(None), status) | (Err(_), status @ Err(_)) => status,
        (Err(error), Ok(_)) | (Ok(Some(_)), Err(error)) => Err(error),
    };
    match (output, status) {
        (Ok((stdout, stderr)), Ok(status)) => Ok(std::process::Output {
            status,
            stdout,
            stderr,
        }),
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
    }
}

async fn read_probe_output(
    reader: impl tokio::io::AsyncRead + Unpin,
    stream: &str,
) -> Result<Vec<u8>, String> {
    use tokio::io::AsyncReadExt as _;
    // Read one extra byte to distinguish complete output from overflow. Stop
    // on overflow instead of draining an unbounded writer until the deadline.
    const MAX_BYTES: usize = 8 * 1024;
    let mut output = Vec::new();
    reader
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut output)
        .await
        .map_err(|error| format!("read version probe {stream}: {error}"))?;
    if output.len() > MAX_BYTES {
        output.truncate(MAX_BYTES);
        return Err(format!(
            "version probe {stream} exceeded {MAX_BYTES} bytes: {} [truncated]",
            String::from_utf8_lossy(&output)
        ));
    }
    Ok(output)
}

fn supported_version<'a>(identity: &str, output: &'a str) -> Option<&'a str> {
    output.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        if words.next() != Some(identity) {
            return None;
        }
        let version = words.next()?;
        let mut parts = version.split('.');
        let major = parts.next()?.parse::<u32>().ok()?;
        let minor = parts.next()?.parse::<u32>().ok()?;
        // Reject malformed version tokens rather than accepting an arbitrary
        // suffix after an otherwise valid major/minor pair.
        if let Some(patch) = parts.next()
            && (patch.parse::<u32>().is_err() || parts.next().is_some())
        {
            return None;
        }
        // VM image preparation uses mke2fs -d and ext4 filesystem features.
        // Keep all host tools on the supported e2fsprogs release baseline.
        ((major, minor) >= (1, 43)).then_some(version)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_e2fs_tool(directory: &Path, name: &str, body: &str) {
        let path = directory.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write tool");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("make executable");
    }

    fn fake_e2fs_installation(directory: &Path) {
        for name in ["mke2fs", "debugfs", "e2fsck"] {
            fake_e2fs_tool(
                directory,
                name,
                &format!("test \"$1\" = -V || exit 64\necho '{name} 1.47.4' >&2"),
            );
        }
    }

    #[tokio::test]
    async fn filesystem_preflight_accepts_private_prefix_and_formatter_alias() {
        let temp = tempfile::tempdir().expect("private prefix");
        fake_e2fs_installation(temp.path());
        fs::rename(temp.path().join("mke2fs"), temp.path().join("mkfs.ext4"))
            .expect("use formatter alias");
        preflight_in(&[temp.path().to_path_buf()])
            .await
            .expect("all required tools available");
        let selected = resolve_in(&["debugfs"], &[temp.path().to_path_buf()])
            .expect("execution uses same resolver");
        let expected = temp
            .path()
            .join("debugfs")
            .canonicalize()
            .expect("tool path");
        assert_eq!(selected, expected);
    }

    #[tokio::test]
    async fn filesystem_preflight_rejects_missing_tools() {
        let temp = tempfile::tempdir().expect("clean host search path");
        let error = preflight_in(&[temp.path().to_path_buf()])
            .await
            .expect_err("missing formatter must reject preparation");
        assert!(error.contains("mke2fs or mkfs.ext4 not found"), "{error}");
        assert!(error.contains("gateway service PATH"), "{error}");
    }

    #[tokio::test]
    async fn filesystem_preflight_requires_debugfs_and_recovery_tool() {
        for missing in ["debugfs", "e2fsck"] {
            let temp = tempfile::tempdir().expect("partial installation");
            fake_e2fs_installation(temp.path());
            fs::remove_file(temp.path().join(missing)).expect("remove required tool");
            let error = preflight_in(&[temp.path().to_path_buf()])
                .await
                .expect_err("missing tool");
            assert!(error.contains(&format!("{missing} not found")), "{error}");
            assert!(
                error.contains("VM host tool mke2fs:"),
                "earlier path lost: {error}"
            );
        }
    }

    #[tokio::test]
    async fn filesystem_preflight_retains_missing_interpreter_error() {
        let temp = tempfile::tempdir().expect("broken installation");
        let path = temp.path().join("mke2fs");
        fs::write(&path, "#!/nonexistent/e2fsprogs-interpreter\n").expect("broken executable");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("executable bit");
        fake_e2fs_tool(temp.path(), "mkfs.ext4", "echo 'mke2fs 1.47.4' >&2");
        let error = preflight_in(&[temp.path().to_path_buf()])
            .await
            .expect_err("loader error");
        assert!(error.contains("mke2fs -V:"), "{error}");
        assert!(error.contains("No such file or directory"), "{error}");
        assert!(!error.contains("mke2fs or mkfs.ext4 not found"), "{error}");
    }

    #[tokio::test]
    async fn filesystem_preflight_rejects_nonexecutable_before_another_installation() {
        let first = tempfile::tempdir().expect("first installation");
        let second = tempfile::tempdir().expect("second installation");
        fs::write(first.path().join("mke2fs"), b"not executable").expect("write broken tool");
        fake_e2fs_installation(second.path());
        let path = std::env::join_paths([first.path(), second.path()]).expect("search path");
        let error = preflight_in(&std::env::split_paths(&path).collect::<Vec<_>>())
            .await
            .expect_err("broken installation must not fall back");
        assert!(error.contains("is not an executable file"), "{error}");
        assert!(
            error.contains(&first.path().display().to_string()),
            "{error}"
        );
    }

    #[tokio::test]
    async fn filesystem_preflight_preserves_failed_tool_output() {
        let first = tempfile::tempdir().expect("first installation");
        let second = tempfile::tempdir().expect("second installation");
        fake_e2fs_tool(first.path(), "mke2fs", "echo 'loader failed' >&2\nexit 42");
        fake_e2fs_installation(second.path());
        let path = std::env::join_paths([first.path(), second.path()]).expect("search path");
        let error = preflight_in(&std::env::split_paths(&path).collect::<Vec<_>>())
            .await
            .expect_err("real execution failure must not fall back");
        assert!(error.contains("42"), "{error}");
        assert!(error.contains("loader failed"), "{error}");
        assert!(
            error.contains(&first.path().display().to_string()),
            "{error}"
        );
    }

    #[tokio::test]
    async fn filesystem_preflight_rejects_incompatible_tool() {
        let temp = tempfile::tempdir().expect("old installation");
        fake_e2fs_installation(temp.path());
        fake_e2fs_tool(temp.path(), "debugfs", "echo 'debugfs 1.42.13' >&2");
        let error = preflight_in(&[temp.path().to_path_buf()])
            .await
            .expect_err("old tool must reject preparation");
        assert!(
            error.contains("not a supported debugfs executable"),
            "{error}"
        );
        assert!(error.contains("debugfs 1.42.13"), "{error}");
    }

    #[tokio::test]
    async fn filesystem_preflight_stops_a_hung_version_probe() {
        let temp = tempfile::tempdir().expect("hung installation");
        fake_e2fs_tool(temp.path(), "mke2fs", "exec /bin/sleep 30");
        let error = preflight_in(&[temp.path().to_path_buf()])
            .await
            .expect_err("preflight must finish even if a tool hangs");
        assert!(error.contains("timed out after 5 seconds"), "{error}");
    }

    #[tokio::test]
    async fn filesystem_preflight_bounds_each_output_stream() {
        let temp = tempfile::tempdir().expect("noisy installation");
        for (redirect, stream) in [("", "stdout"), (">&2", "stderr")] {
            fake_e2fs_tool(
                temp.path(),
                "mke2fs",
                &format!("/bin/dd if=/dev/zero bs=16384 count=4 {redirect} 2>/dev/null\nexit 42"),
            );
            let error = preflight_in(&[temp.path().to_path_buf()])
                .await
                .expect_err("oversized probe output must fail early");
            assert!(error.contains(&format!("{stream} exceeded 8192 bytes")));
            assert!(
                error.len() < 9000,
                "diagnostic grew to {} bytes",
                error.len()
            );
        }
    }

    #[tokio::test]
    async fn filesystem_preflight_timeout_terminates_wrapper_descendants() {
        let temp = tempfile::tempdir().expect("wrapper installation");
        let marker = temp.path().join("survived-timeout");
        fake_e2fs_tool(
            temp.path(),
            "mke2fs",
            &format!(
                "(/bin/sleep 6; echo survived > '{}') &\nwait",
                marker.display()
            ),
        );
        let error = preflight_in(&[temp.path().to_path_buf()])
            .await
            .expect_err("wrapper must time out");
        assert!(error.contains("timed out after 5 seconds"), "{error}");
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert!(
            !marker.exists(),
            "wrapper descendant survived its probe timeout"
        );
    }

    #[tokio::test]
    async fn filesystem_preflight_retains_exited_leader_until_held_pipe_cleanup() {
        let temp = tempfile::tempdir().expect("wrapper installation");
        let marker = temp.path().join("survived-exited-leader");
        fake_e2fs_tool(
            temp.path(),
            "mke2fs",
            &format!(
                "(/bin/sleep 6; echo survived > '{}') &\necho 'mke2fs 1.47.4'\nexit 0",
                marker.display()
            ),
        );
        let error = preflight_in(&[temp.path().to_path_buf()])
            .await
            .expect_err("descendant holds output pipe");
        assert!(error.contains("timed out after 5 seconds"), "{error}");
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert!(
            !marker.exists(),
            "descendant of exited probe leader survived cleanup"
        );
    }

    #[tokio::test]
    async fn filesystem_preflight_cancellation_terminates_wrapper_descendants() {
        let temp = tempfile::tempdir().expect("wrapper installation");
        let ready = temp.path().join("child-ready");
        let marker = temp.path().join("survived-cancellation");
        fake_e2fs_tool(
            temp.path(),
            "mke2fs",
            &format!(
                "(echo ready > '{}'; /bin/sleep 6; echo survived > '{}') &\nwait",
                ready.display(),
                marker.display()
            ),
        );
        let path = temp.path().to_path_buf();
        let probe = tokio::spawn(async move { preflight_in(&[path]).await });
        for _ in 0..400 {
            if ready.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if !ready.exists() {
            probe.abort();
            let result = probe.await;
            panic!("probe descendant did not start: {result:?}");
        }
        probe.abort();
        assert!(probe.await.expect_err("cancelled task").is_cancelled());
        tokio::time::sleep(Duration::from_millis(6300)).await;
        assert!(!marker.exists(), "wrapper descendant survived cancellation");
    }

    #[test]
    fn filesystem_preflight_requires_expected_identity_and_version() {
        assert_eq!(
            supported_version("mke2fs", "mke2fs 1.43 (test)"),
            Some("1.43")
        );
        for output in [
            "other 1.47.4",
            "mke2fs unknown",
            "mke2fs 1.42.13",
            "mke2fs 1.47.garbage",
            "mke2fs 1.47.4.5",
            "",
        ] {
            assert_eq!(supported_version("mke2fs", output), None, "{output}");
        }
    }
}
