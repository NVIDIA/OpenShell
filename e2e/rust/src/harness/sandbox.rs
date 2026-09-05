// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox lifecycle management with automatic cleanup.
//!
//! [`SandboxGuard`] creates a sandbox and ensures it is deleted when the guard
//! is dropped, replacing the `trap cleanup EXIT` pattern from the bash tests.

use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::timeout;

use super::binary::openshell_cmd;
use super::output::{extract_field, strip_ansi};

/// Extract the sandbox name from CLI create output.
///
/// The CLI prints `Created sandbox: <name>` (current format). Falls back to
/// `Name: <name>` for compatibility with older output formats.
fn extract_sandbox_name(output: &str) -> Option<String> {
    extract_field(output, "Created sandbox").or_else(|| extract_field(output, "Name"))
}

/// Default timeout for waiting for a sandbox to become ready.
/// In VM mode, the overlayfs snapshotter re-extracts all image layers
/// from the content store on every boot (~250s for the 1GB sandbox
/// base image), so 600s accommodates extraction + workspace-init + pod
/// startup.
const SANDBOX_READY_TIMEOUT: Duration = Duration::from_secs(600);

/// RAII guard that deletes a sandbox on drop.
///
/// For sandboxes created with `--keep` (long-running background command), the
/// guard also holds the child process handle and kills it during cleanup.
pub struct SandboxGuard {
    /// The sandbox name, parsed from CLI output.
    pub name: String,

    /// The full captured stdout from the create command (for short-lived
    /// sandboxes). Empty for `--keep` sandboxes where output is streamed.
    pub create_output: String,

    /// Background child process for `--keep` sandboxes.
    child: Option<tokio::process::Child>,

    /// Whether cleanup has already been performed.
    cleaned_up: bool,
}

impl SandboxGuard {
    /// Manage the cleanup of a sandbox created outside this helper.
    pub fn manage_existing(name: String) -> Self {
        Self {
            name,
            create_output: String::new(),
            child: None,
            cleaned_up: false,
        }
    }

    /// Create a persistent scratch sandbox and optionally run a command in it.
    ///
    /// Arguments before `--` are forwarded to `sandbox create`; arguments after
    /// `--` are run with `sandbox exec`. This keeps generic E2E tests focused on
    /// the behavior of their one-shot payload now that a trailing create command
    /// is the sandbox's canonical main process and its exit is terminal.
    ///
    /// # Arguments
    ///
    /// * `args` — Extra arguments to `openshell sandbox create`, including
    ///   `-- <command>` if needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the CLI exits with a non-zero status or the sandbox
    /// name cannot be parsed from the output.
    pub async fn create(args: &[&str]) -> Result<Self, String> {
        let separator = args.iter().position(|arg| *arg == "--");
        let (create_args, command) = separator.map_or((args, &[][..]), |index| {
            (&args[..index], &args[index + 1..])
        });

        if create_args.contains(&"--no-keep") {
            return Err(
                "SandboxGuard::create makes a persistent scratch sandbox; use the CLI directly to test --no-keep semantics"
                    .to_string(),
            );
        }

        let mut cmd = openshell_cmd();
        cmd.arg("sandbox").arg("create").arg("--detach");
        for arg in create_args {
            cmd.arg(arg);
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = timeout(SANDBOX_READY_TIMEOUT, cmd.output())
            .await
            .map_err(|_| format!("sandbox create timed out after {SANDBOX_READY_TIMEOUT:?}"))?
            .map_err(|e| format!("failed to spawn openshell: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{stdout}{stderr}");

        if !output.status.success() {
            return Err(format!(
                "sandbox create failed (exit {:?}):\n{combined}",
                output.status.code()
            ));
        }

        let name = extract_sandbox_name(&combined).ok_or_else(|| {
            format!("could not parse sandbox name from create output:\n{combined}")
        })?;

        let mut guard = Self {
            name,
            create_output: combined,
            child: None,
            cleaned_up: false,
        };

        if !command.is_empty() {
            match guard.exec(command).await {
                Ok(exec_output) => guard.create_output.push_str(&exec_output),
                Err(err) => {
                    guard.cleanup().await;
                    return Err(err);
                }
            }
        }

        Ok(guard)
    }

    /// Create a sandbox with a long-lived canonical main command and connect
    /// to it in the background.
    ///
    /// Creation is detached because the harness captures output. This method
    /// then runs `sandbox connect` and polls the retained main-process output
    /// for `ready_marker`.
    ///
    /// # Arguments
    ///
    /// * `command` — The command and arguments to run inside the sandbox
    ///   (passed after `--`).
    /// * `ready_marker` — A string to wait for in the combined output that
    ///   signals readiness.
    ///
    /// # Errors
    ///
    /// Returns an error if the process exits prematurely, the ready marker is
    /// not seen within [`SANDBOX_READY_TIMEOUT`], or the sandbox name cannot
    /// be parsed.
    pub async fn create_keep(command: &[&str], ready_marker: &str) -> Result<Self, String> {
        Self::create_keep_with_args(&[], command, ready_marker).await
    }

    /// Create a sandbox with a detached canonical main command.
    ///
    /// Unlike [`SandboxGuard::create_keep`], this does not open an attachment,
    /// which lets tests control competing and reconnecting clients directly.
    pub async fn create_detached_main(command: &[&str]) -> Result<Self, String> {
        let mut cmd = openshell_cmd();
        cmd.arg("sandbox")
            .arg("create")
            .arg("--detach")
            .arg("--")
            .args(command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = timeout(SANDBOX_READY_TIMEOUT, cmd.output())
            .await
            .map_err(|_| format!("sandbox create timed out after {SANDBOX_READY_TIMEOUT:?}"))?
            .map_err(|e| format!("failed to spawn openshell: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{stdout}{stderr}");

        if !output.status.success() {
            return Err(format!(
                "sandbox create failed (exit {:?}):\n{combined}",
                output.status.code()
            ));
        }

        let name = extract_sandbox_name(&combined).ok_or_else(|| {
            format!("could not parse sandbox name from create output:\n{combined}")
        })?;
        Ok(Self {
            name,
            create_output: combined,
            child: None,
            cleaned_up: false,
        })
    }

    /// Like [`SandboxGuard::create_keep`], but forwards extra flags to
    /// `sandbox create` (e.g. `--policy <file>`, `--name <n>`) before the
    /// `-- <command>` separator.
    ///
    /// # Errors
    ///
    /// Returns an error if the process exits prematurely, the ready marker is
    /// not seen within [`SANDBOX_READY_TIMEOUT`], or the sandbox name cannot
    /// be parsed.
    pub async fn create_keep_with_args(
        create_args: &[&str],
        command: &[&str],
        ready_marker: &str,
    ) -> Result<Self, String> {
        let mut create_cmd = openshell_cmd();
        create_cmd.arg("sandbox").arg("create").arg("--detach");
        for arg in create_args {
            create_cmd.arg(arg);
        }
        create_cmd.arg("--").args(command);
        create_cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let create_output = timeout(SANDBOX_READY_TIMEOUT, create_cmd.output())
            .await
            .map_err(|_| format!("sandbox create timed out after {SANDBOX_READY_TIMEOUT:?}"))?
            .map_err(|e| format!("failed to spawn openshell: {e}"))?;
        let create_stdout = String::from_utf8_lossy(&create_output.stdout).to_string();
        let create_stderr = String::from_utf8_lossy(&create_output.stderr).to_string();
        let create_combined = format!("{create_stdout}{create_stderr}");

        if !create_output.status.success() {
            return Err(format!(
                "sandbox create failed (exit {:?}):\n{create_combined}",
                create_output.status.code()
            ));
        }

        let sandbox_name = extract_sandbox_name(&create_combined).ok_or_else(|| {
            format!("could not parse sandbox name from create output:\n{create_combined}")
        })?;

        let mut connect_cmd = openshell_cmd();
        connect_cmd
            .arg("sandbox")
            .arg("connect")
            .arg(&sandbox_name)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = connect_cmd
            .spawn()
            .map_err(|e| format!("failed to spawn openshell connect: {e}"))?;

        let stdout = child.stdout.take().expect("stdout must be piped");
        let mut reader = BufReader::new(stdout).lines();

        let stderr_handle = child.stderr.take().expect("stderr must be piped");
        let stderr_buf = Arc::new(Mutex::new(String::new()));
        let stderr_buf_clone = Arc::clone(&stderr_buf);
        let stderr_task = tokio::spawn(async move {
            let mut reader = BufReader::new(stderr_handle).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let clean = strip_ansi(&line);
                let mut buf = stderr_buf_clone.lock().unwrap();
                buf.push_str(&clean);
                buf.push('\n');
            }
        });

        let mut accumulated = create_combined;
        let mut ready = false;

        let poll_result = timeout(SANDBOX_READY_TIMEOUT, async {
            while let Ok(Some(line)) = reader.next_line().await {
                let clean = strip_ansi(&line);
                accumulated.push_str(&clean);
                accumulated.push('\n');

                // Check for the ready marker.
                if clean.contains(ready_marker) {
                    ready = true;
                    break;
                }
            }
        })
        .await;

        let collect_stderr = || {
            stderr_task.abort();
            let buf = stderr_buf.lock().unwrap();
            buf.clone()
        };

        if poll_result.is_err() {
            // Timeout — kill the child and report.
            let _ = child.kill().await;
            let stderr_output = collect_stderr();
            return Err(format!(
                "sandbox did not become ready within {SANDBOX_READY_TIMEOUT:?}.\n\
                 Stdout:\n{accumulated}\nStderr:\n{stderr_output}"
            ));
        }

        if !ready {
            // The line reader ended before seeing the marker (process exited).
            let _ = child.kill().await;
            let stderr_output = collect_stderr();
            return Err(format!(
                "sandbox connect exited before ready marker '{ready_marker}' was seen.\n\
                 Stdout:\n{accumulated}\nStderr:\n{stderr_output}"
            ));
        }

        Ok(Self {
            name: sandbox_name,
            create_output: accumulated,
            child: Some(child),
            cleaned_up: false,
        })
    }

    /// Create a detached scratch sandbox with pre-loaded files, then exec a
    /// command in it.
    ///
    /// Equivalent to:
    /// ```text
    /// openshell sandbox create --detach --upload <local>:<dest> [extra_args...]
    /// openshell sandbox exec <name> -- <command>
    /// ```
    ///
    /// The `--no-git-ignore` flag is passed to avoid needing a git repository.
    ///
    /// # Errors
    ///
    /// Returns an error if the CLI exits with a non-zero status or the sandbox
    /// name cannot be parsed.
    pub async fn create_with_upload(
        upload_local: &str,
        upload_dest: &str,
        command: &[&str],
    ) -> Result<Self, String> {
        Self::create_with_uploads(&[(upload_local, upload_dest)], command).await
    }

    /// Create a sandbox with multiple `--upload` specs.
    ///
    /// Each element of `uploads` is a `(local_path, sandbox_dest)` pair.
    /// `--no-git-ignore` is applied to all uploads.
    pub async fn create_with_uploads(
        uploads: &[(&str, &str)],
        command: &[&str],
    ) -> Result<Self, String> {
        let mut cmd = openshell_cmd();
        cmd.arg("sandbox").arg("create").arg("--detach");
        for (local, dest) in uploads {
            cmd.arg("--upload").arg(format!("{local}:{dest}"));
        }
        cmd.arg("--no-git-ignore");
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = timeout(SANDBOX_READY_TIMEOUT, cmd.output())
            .await
            .map_err(|_| {
                format!("sandbox create --upload timed out after {SANDBOX_READY_TIMEOUT:?}")
            })?
            .map_err(|e| format!("failed to spawn openshell: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{stdout}{stderr}");

        if !output.status.success() {
            return Err(format!(
                "sandbox create --upload failed (exit {:?}):\n{combined}",
                output.status.code()
            ));
        }

        let name = extract_sandbox_name(&combined).ok_or_else(|| {
            format!("could not parse sandbox name from create output:\n{combined}")
        })?;

        let mut guard = Self {
            name,
            create_output: combined,
            child: None,
            cleaned_up: false,
        };

        match guard.exec(command).await {
            Ok(exec_output) => guard.create_output.push_str(&exec_output),
            Err(err) => {
                guard.cleanup().await;
                return Err(err);
            }
        }

        Ok(guard)
    }

    /// Upload local files to the sandbox via `openshell sandbox upload`.
    ///
    /// # Arguments
    ///
    /// * `local_path` — Local file or directory to upload.
    /// * `dest` — Destination path in the sandbox (e.g. `/sandbox/uploaded`).
    ///
    /// # Errors
    ///
    /// Returns an error if the upload command fails.
    pub async fn upload(&self, local_path: &str, dest: &str) -> Result<String, String> {
        let mut cmd = openshell_cmd();
        cmd.arg("sandbox")
            .arg("upload")
            .arg(&self.name)
            .arg(local_path)
            .arg(dest)
            .arg("--no-git-ignore");
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = cmd
            .output()
            .await
            .map_err(|e| format!("failed to spawn openshell upload: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{stdout}{stderr}");

        if !output.status.success() {
            return Err(format!(
                "sandbox upload failed (exit {:?}):\n{combined}",
                output.status.code()
            ));
        }

        Ok(combined)
    }

    /// Upload local files to the sandbox's discovered working directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the upload command fails.
    pub async fn upload_to_workdir(&self, local_path: &str) -> Result<String, String> {
        let mut cmd = openshell_cmd();
        cmd.arg("sandbox")
            .arg("upload")
            .arg(&self.name)
            .arg(local_path)
            .arg("--no-git-ignore");
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = cmd
            .output()
            .await
            .map_err(|e| format!("failed to spawn openshell upload: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{stdout}{stderr}");

        if !output.status.success() {
            return Err(format!(
                "sandbox upload failed (exit {:?}):\n{combined}",
                output.status.code()
            ));
        }

        Ok(combined)
    }

    /// Upload local files with `.gitignore` filtering (default behavior).
    ///
    /// Unlike [`upload`], this does NOT pass `--no-git-ignore`, so the CLI
    /// will filter out gitignored files. The `cwd` is set to the given
    /// directory so that `git_repo_root()` inside the CLI resolves correctly.
    ///
    /// # Arguments
    ///
    /// * `local_path` — Local file or directory to upload.
    /// * `dest` — Destination path in the sandbox.
    /// * `cwd` — Working directory for the CLI process (should be inside a git
    ///   repo).
    ///
    /// # Errors
    ///
    /// Returns an error if the upload command fails.
    pub async fn upload_with_gitignore(
        &self,
        local_path: &str,
        dest: &str,
        cwd: &std::path::Path,
    ) -> Result<String, String> {
        let mut cmd = openshell_cmd();
        cmd.arg("sandbox")
            .arg("upload")
            .arg(&self.name)
            .arg(local_path)
            .arg(dest)
            .current_dir(cwd);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = cmd
            .output()
            .await
            .map_err(|e| format!("failed to spawn openshell upload: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{stdout}{stderr}");

        if !output.status.success() {
            return Err(format!(
                "sandbox upload (with gitignore) failed (exit {:?}):\n{combined}",
                output.status.code()
            ));
        }

        Ok(combined)
    }

    /// Run a one-shot command inside the sandbox via `openshell sandbox exec`.
    ///
    /// Used by tests that need to pre-populate sandbox-side state (create
    /// files, symlinks, directories) without going through the upload flow.
    /// Stdout and stderr are captured and returned together; PTY allocation
    /// is disabled so the call is suitable for non-interactive setups.
    ///
    /// # Arguments
    ///
    /// * `argv` — Command and arguments to execute (passed after `--`).
    ///
    /// # Errors
    ///
    /// Returns an error if the CLI exits non-zero.
    pub async fn exec(&self, argv: &[&str]) -> Result<String, String> {
        let mut cmd = openshell_cmd();
        cmd.arg("sandbox")
            .arg("exec")
            .arg("--name")
            .arg(&self.name)
            .arg("--no-tty")
            .arg("--");
        for arg in argv {
            cmd.arg(arg);
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = cmd
            .output()
            .await
            .map_err(|e| format!("failed to spawn openshell exec: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{stdout}{stderr}");

        if !output.status.success() {
            return Err(format!(
                "sandbox exec failed (exit {:?}):\n{combined}",
                output.status.code()
            ));
        }

        Ok(combined)
    }

    /// Download files from the sandbox via `openshell sandbox download`.
    ///
    /// # Arguments
    ///
    /// * `sandbox_path` — Path inside the sandbox to download.
    /// * `local_dest` — Local destination directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the download command fails.
    pub async fn download(&self, sandbox_path: &str, local_dest: &str) -> Result<String, String> {
        let mut cmd = openshell_cmd();
        cmd.arg("sandbox")
            .arg("download")
            .arg(&self.name)
            .arg(sandbox_path)
            .arg(local_dest);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = cmd
            .output()
            .await
            .map_err(|e| format!("failed to spawn openshell download: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{stdout}{stderr}");

        if !output.status.success() {
            return Err(format!(
                "sandbox download failed (exit {:?}):\n{combined}",
                output.status.code()
            ));
        }

        Ok(combined)
    }

    /// Spawn `openshell forward start` as a background process.
    ///
    /// Returns the child process handle. The caller is responsible for killing
    /// it (or it will be killed on drop since `kill_on_drop(true)` is set).
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be spawned.
    pub fn spawn_forward(&self, port: u16) -> Result<tokio::process::Child, String> {
        let mut cmd = openshell_cmd();
        cmd.arg("forward")
            .arg("start")
            .arg(port.to_string())
            .arg(&self.name);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        cmd.spawn()
            .map_err(|e| format!("failed to spawn port forward: {e}"))
    }

    /// Delete the sandbox explicitly.
    ///
    /// Also kills the background child process if one exists. This is called
    /// automatically by [`Drop`], but can be called manually for clarity.
    pub async fn cleanup(&mut self) {
        if self.cleaned_up {
            return;
        }
        self.cleaned_up = true;

        // Kill the background child process if present.
        if let Some(ref mut child) = self.child {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }

        // Delete the sandbox.
        let mut cmd = openshell_cmd();
        cmd.arg("sandbox").arg("delete").arg(&self.name);
        cmd.stdout(Stdio::null()).stderr(Stdio::null());

        let _ = cmd.status().await;
    }
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        if self.cleaned_up {
            return;
        }

        // We need to run async cleanup in a sync Drop. Use block_in_place to
        // avoid blocking the tokio runtime. This is acceptable for test code.
        let name = self.name.clone();
        let mut child = self.child.take();

        // Attempt cleanup with a new runtime if we're not inside one, or
        // block_in_place if we are.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("create cleanup runtime");
            rt.block_on(async {
                if let Some(ref mut child) = child {
                    let _: Result<(), _> = child.kill().await;
                    let _ = child.wait().await;
                }

                let mut cmd = openshell_cmd();
                cmd.arg("sandbox").arg("delete").arg(&name);
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
                let _ = cmd.status().await;
            });
        });
    }
}
