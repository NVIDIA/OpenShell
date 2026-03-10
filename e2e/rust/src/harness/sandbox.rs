// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox lifecycle management with automatic cleanup.
//!
//! [`SandboxGuard`] creates a sandbox and ensures it is deleted when the guard
//! is dropped, replacing the `trap cleanup EXIT` pattern from the bash tests.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::timeout;

use super::binary::nemoclaw_cmd;
use super::output::{extract_field, strip_ansi};

/// Extract the sandbox name from CLI create output.
///
/// The CLI prints `Created sandbox: <name>` (current format). Falls back to
/// `Name: <name>` for compatibility with older output formats.
fn extract_sandbox_name(output: &str) -> Option<String> {
    extract_field(output, "Created sandbox")
        .or_else(|| extract_field(output, "Name"))
}

/// Default timeout for waiting for a sandbox to become ready.
const SANDBOX_READY_TIMEOUT: Duration = Duration::from_secs(120);

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
    /// Create a sandbox that runs a command to completion (no `--keep`).
    ///
    /// Captures the full CLI output and parses the sandbox name from it.
    /// The sandbox is created synchronously (the CLI blocks until the command
    /// finishes).
    ///
    /// # Arguments
    ///
    /// * `args` — Extra arguments to `nemoclaw sandbox create`, including
    ///   `-- <command>` if needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the CLI exits with a non-zero status or the sandbox
    /// name cannot be parsed from the output.
    pub async fn create(args: &[&str]) -> Result<Self, String> {
        let mut cmd = nemoclaw_cmd();
        cmd.arg("sandbox").arg("create");
        for arg in args {
            cmd.arg(arg);
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = cmd
            .output()
            .await
            .map_err(|e| format!("failed to spawn nemoclaw: {e}"))?;

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

    /// Create a sandbox with `--keep` that runs a long-lived background
    /// command.
    ///
    /// The CLI process runs in the background. This method polls its stdout
    /// for `ready_marker` (a string the background command prints when it is
    /// ready to accept work). Sandbox name is parsed from the output header.
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
    pub async fn create_keep(
        command: &[&str],
        ready_marker: &str,
    ) -> Result<Self, String> {
        let mut cmd = nemoclaw_cmd();
        cmd.arg("sandbox")
            .arg("create")
            .arg("--keep")
            .arg("--")
            .args(command);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn nemoclaw: {e}"))?;

        let stdout = child.stdout.take().expect("stdout must be piped");
        let mut reader = BufReader::new(stdout).lines();

        let mut accumulated = String::new();
        let mut name: Option<String> = None;
        let mut ready = false;

        let poll_result = timeout(SANDBOX_READY_TIMEOUT, async {
            while let Ok(Some(line)) = reader.next_line().await {
                let clean = strip_ansi(&line);
                accumulated.push_str(&clean);
                accumulated.push('\n');

                // Try to extract the sandbox name from the header.
                if name.is_none() {
                    if let Some(n) = extract_sandbox_name(&accumulated) {
                        name = Some(n);
                    }
                }

                // Check for the ready marker.
                if clean.contains(ready_marker) {
                    ready = true;
                    break;
                }
            }
        })
        .await;

        if poll_result.is_err() {
            // Timeout — kill the child and report.
            let _ = child.kill().await;
            return Err(format!(
                "sandbox did not become ready within {SANDBOX_READY_TIMEOUT:?}.\n\
                 Output so far:\n{accumulated}"
            ));
        }

        if !ready {
            // The line reader ended before seeing the marker (process exited).
            let _ = child.kill().await;
            return Err(format!(
                "sandbox create exited before ready marker '{ready_marker}' was seen.\n\
                 Output:\n{accumulated}"
            ));
        }

        let sandbox_name = name.ok_or_else(|| {
            format!("could not parse sandbox name from create output:\n{accumulated}")
        })?;

        Ok(Self {
            name: sandbox_name,
            create_output: accumulated,
            child: Some(child),
            cleaned_up: false,
        })
    }

    /// Create a sandbox that runs a command, with `--upload` to pre-load files.
    ///
    /// Equivalent to:
    /// ```text
    /// nemoclaw sandbox create --upload <local>:<dest> [extra_args...] -- <command>
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
        let upload_spec = format!("{upload_local}:{upload_dest}");

        let mut cmd = nemoclaw_cmd();
        cmd.arg("sandbox")
            .arg("create")
            .arg("--upload")
            .arg(&upload_spec)
            .arg("--no-git-ignore")
            .arg("--")
            .args(command);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = cmd
            .output()
            .await
            .map_err(|e| format!("failed to spawn nemoclaw: {e}"))?;

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

        Ok(Self {
            name,
            create_output: combined,
            child: None,
            cleaned_up: false,
        })
    }

    /// Upload local files to the sandbox via `nemoclaw sandbox upload`.
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
        let mut cmd = nemoclaw_cmd();
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
            .map_err(|e| format!("failed to spawn nemoclaw upload: {e}"))?;

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
        let mut cmd = nemoclaw_cmd();
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
            .map_err(|e| format!("failed to spawn nemoclaw upload: {e}"))?;

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

    /// Download files from the sandbox via `nemoclaw sandbox download`.
    ///
    /// # Arguments
    ///
    /// * `sandbox_path` — Path inside the sandbox to download.
    /// * `local_dest` — Local destination directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the download command fails.
    pub async fn download(
        &self,
        sandbox_path: &str,
        local_dest: &str,
    ) -> Result<String, String> {
        let mut cmd = nemoclaw_cmd();
        cmd.arg("sandbox")
            .arg("download")
            .arg(&self.name)
            .arg(sandbox_path)
            .arg(local_dest);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = cmd
            .output()
            .await
            .map_err(|e| format!("failed to spawn nemoclaw download: {e}"))?;

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

    /// Spawn `nemoclaw forward start` as a background process.
    ///
    /// Returns the child process handle. The caller is responsible for killing
    /// it (or it will be killed on drop since `kill_on_drop(true)` is set).
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be spawned.
    pub fn spawn_forward(&self, port: u16) -> Result<tokio::process::Child, String> {
        let mut cmd = nemoclaw_cmd();
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
        let mut cmd = nemoclaw_cmd();
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

                let mut cmd = nemoclaw_cmd();
                cmd.arg("sandbox").arg("delete").arg(&name);
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
                let _ = cmd.status().await;
            });
        });
    }
}
