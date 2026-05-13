// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SSH connection and proxy utilities.

use crate::tls::{TlsOptions, grpc_client};
use miette::{IntoDiagnostic, Result, WrapErr};
#[cfg(unix)]
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
use openshell_core::ObjectId;
use openshell_core::forward::{
    build_proxy_command, find_ssh_forward_pid, format_gateway_url, resolve_ssh_gateway,
    shell_escape, validate_ssh_session_response, write_forward_pid,
};
use openshell_core::proto::{
    CreateSshSessionRequest, GetSandboxRequest, SshRelayTarget, TcpForwardFrame, TcpForwardInit,
    tcp_forward_init,
};
use owo_colors::OwoColorize;
use std::fs;
use std::io::{IsTerminal, Write};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command as TokioCommand;
use tokio_stream::wrappers::ReceiverStream;

const FOREGROUND_FORWARD_STARTUP_GRACE_PERIOD: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug)]
pub enum Editor {
    Vscode,
    Cursor,
}

impl Editor {
    fn binary(self) -> &'static str {
        match self {
            Self::Vscode => "code",
            Self::Cursor => "cursor",
        }
    }

    fn remote_target(host_alias: &str) -> String {
        format!("ssh-remote+{host_alias}")
    }

    fn label(self) -> &'static str {
        match self {
            Self::Vscode => "VS Code",
            Self::Cursor => "Cursor",
        }
    }
}

struct SshSessionConfig {
    proxy_command: String,
    sandbox_id: String,
    gateway_url: String,
    token: String,
}

async fn ssh_session_config(
    server: &str,
    name: &str,
    tls: &TlsOptions,
) -> Result<SshSessionConfig> {
    let mut client = grpc_client(server, tls).await?;

    // Resolve sandbox name to id.
    let sandbox = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox not found"))?;

    let response = client
        .create_ssh_session(CreateSshSessionRequest {
            sandbox_id: sandbox.object_id().to_string(),
        })
        .await
        .into_diagnostic()?;
    let session = response.into_inner();
    validate_ssh_session_response(&session)
        .map_err(|err| miette::miette!("gateway returned invalid SSH session response: {err}"))?;

    let exe = std::env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to resolve OpenShell executable")?;
    let exe_command = exe.to_string_lossy().into_owned();

    // When using Cloudflare bearer auth, the SSH CONNECT must go through the
    // external tunnel endpoint (the cluster URL), not the server's internal
    // scheme/host/port which may be plaintext HTTP on 127.0.0.1.
    let gateway_url = if tls.is_bearer_auth() {
        server.trim_end_matches('/').to_string()
    } else {
        // If the server returned a loopback gateway address, override it with the
        // cluster endpoint's host. This handles the case where the server defaults
        // to 127.0.0.1 but the cluster is actually running on a remote host.
        #[allow(clippy::cast_possible_truncation)]
        let gateway_port_u16 = session.gateway_port as u16;
        let (gateway_host, gateway_port) =
            resolve_ssh_gateway(&session.gateway_host, gateway_port_u16, server);
        format_gateway_url(&session.gateway_scheme, &gateway_host, gateway_port)
    };
    let gateway_name = tls
        .gateway_name()
        .ok_or_else(|| miette::miette!("gateway name is required to build SSH proxy command"))?;
    let proxy_command = build_proxy_command(
        &exe_command,
        &gateway_url,
        &session.sandbox_id,
        &session.token,
        gateway_name,
    );

    Ok(SshSessionConfig {
        proxy_command,
        sandbox_id: session.sandbox_id.clone(),
        gateway_url,
        token: session.token,
    })
}

fn ssh_base_command(proxy_command: &str) -> Command {
    // SSH log level follows the program's verbosity.  main() maps the `-v`
    // count to OPENSHELL_SSH_LOG_LEVEL; an explicit env-var override wins.
    let ssh_log_level =
        std::env::var("OPENSHELL_SSH_LOG_LEVEL").unwrap_or_else(|_| "ERROR".to_string());

    let mut command = Command::new("ssh");
    command
        .arg("-o")
        .arg(format!("ProxyCommand={proxy_command}"))
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg(format!("LogLevel={ssh_log_level}"))
        // Detect a dead relay within ~45s. The relay rides on a TCP connection
        // that the client has no way to observe silently dropping (gateway
        // restart, supervisor restart, cluster failover), so fall back to
        // SSH-level keepalives instead of hanging forever.
        .arg("-o")
        .arg("ServerAliveInterval=15")
        .arg("-o")
        .arg("ServerAliveCountMax=3");
    command
}

#[cfg(unix)]
const TRANSIENT_TTY_SIGNALS: &[Signal] = &[Signal::SIGINT, Signal::SIGQUIT, Signal::SIGTERM];

#[cfg(unix)]
struct ParentSignalGuard {
    previous: Vec<(Signal, SigAction)>,
}

#[cfg(unix)]
impl ParentSignalGuard {
    #[allow(unsafe_code)]
    fn ignore_transient_tty_signals() -> Result<Self> {
        let mut previous = Vec::with_capacity(TRANSIENT_TTY_SIGNALS.len());
        for &signal in TRANSIENT_TTY_SIGNALS {
            let action = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
            // SAFETY: `sigaction` is the POSIX API for updating process signal
            // dispositions. We install `SIG_IGN` for a small fixed set of
            // terminal signals and store the previous handlers for restoration.
            let old = unsafe { sigaction(signal, &action) }.into_diagnostic()?;
            previous.push((signal, old));
        }
        Ok(Self { previous })
    }
}

#[cfg(unix)]
impl Drop for ParentSignalGuard {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        for &(signal, previous) in self.previous.iter().rev() {
            // SAFETY: these `SigAction` values were returned by `sigaction`
            // above for this process, so restoring them here returns the parent
            // signal handlers to their original state.
            let _ = unsafe { sigaction(signal, &previous) };
        }
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn reset_transient_tty_signals(command: &mut Command) {
    // SAFETY: `pre_exec` runs in the forked child immediately before `exec`.
    // We only reset a small fixed set of signal handlers to `SIG_DFL`, which is
    // required so SSH receives terminal signals normally even though the parent
    // process temporarily ignores them to preserve cleanup.
    unsafe {
        command.pre_exec(|| {
            for &signal in TRANSIENT_TTY_SIGNALS {
                let action = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());
                sigaction(signal, &action).map_err(|err| std::io::Error::other(err.to_string()))?;
            }
            Ok(())
        });
    }
}

fn exec_or_wait(mut command: Command, replace_process: bool) -> Result<()> {
    if replace_process && std::io::stdin().is_terminal() {
        #[cfg(unix)]
        {
            let err = command.exec();
            return Err(miette::miette!("failed to exec ssh: {err}"));
        }
    }

    #[cfg(unix)]
    let _signal_guard = if !replace_process && std::io::stdin().is_terminal() {
        reset_transient_tty_signals(&mut command);
        Some(ParentSignalGuard::ignore_transient_tty_signals()?)
    } else {
        None
    };

    let status = command.status().into_diagnostic()?;

    if !status.success() {
        return Err(miette::miette!("ssh exited with status {status}"));
    }

    Ok(())
}

async fn sandbox_connect_with_mode(
    server: &str,
    name: &str,
    tls: &TlsOptions,
    replace_process: bool,
) -> Result<()> {
    let session = ssh_session_config(server, name, tls).await?;

    let mut command = ssh_base_command(&session.proxy_command);
    command
        .arg("-tt")
        .arg("-o")
        .arg("RequestTTY=force")
        .arg("-o")
        .arg("SetEnv=TERM=xterm-256color")
        .arg("sandbox")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    tokio::task::spawn_blocking(move || exec_or_wait(command, replace_process))
        .await
        .into_diagnostic()??;

    Ok(())
}

/// Connect to a sandbox via SSH.
pub async fn sandbox_connect(server: &str, name: &str, tls: &TlsOptions) -> Result<()> {
    sandbox_connect_with_mode(server, name, tls, true).await
}

pub(crate) async fn sandbox_connect_without_exec(
    server: &str,
    name: &str,
    tls: &TlsOptions,
) -> Result<()> {
    sandbox_connect_with_mode(server, name, tls, false).await
}

pub async fn sandbox_connect_editor(
    server: &str,
    gateway: &str,
    name: &str,
    editor: Editor,
    tls: &TlsOptions,
) -> Result<()> {
    // Verify the sandbox exists before writing SSH config / launching the editor.
    let mut client = grpc_client(server, tls).await?;
    client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox not found: {name}"))?;

    let host_alias = host_alias(name);
    install_ssh_config(gateway, name)?;
    launch_editor(editor, &host_alias)?;
    eprintln!(
        "{} Opened {} for sandbox {}",
        "✓".green().bold(),
        editor.label(),
        name
    );
    Ok(())
}

/// Forward a local port to a sandbox via SSH.
///
/// When `background` is `true` the SSH process is forked into the background
/// (using `-f`) and its PID is written to a state file so it can be managed
/// later via [`stop_forward`] or [`list_forwards`].
pub async fn sandbox_forward(
    server: &str,
    name: &str,
    spec: &openshell_core::forward::ForwardSpec,
    background: bool,
    tls: &TlsOptions,
) -> Result<()> {
    openshell_core::forward::check_port_available(spec)?;

    let session = ssh_session_config(server, name, tls).await?;

    let mut command = TokioCommand::from(ssh_base_command(&session.proxy_command));
    command
        .arg("-N")
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-L")
        .arg(spec.ssh_forward_arg());

    if background {
        // SSH -f: fork to background after authentication.
        command.arg("-f");
    }

    command
        .arg("sandbox")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let port = spec.port;

    let status = if background {
        command.status().await.into_diagnostic()?
    } else {
        let mut child = command.spawn().into_diagnostic()?;
        if let Ok(status) =
            tokio::time::timeout(FOREGROUND_FORWARD_STARTUP_GRACE_PERIOD, child.wait()).await
        {
            status.into_diagnostic()?
        } else {
            eprintln!("{}", foreground_forward_started_message(name, spec));
            child.wait().await.into_diagnostic()?
        }
    };

    if !status.success() {
        return Err(miette::miette!("ssh exited with status {status}"));
    }

    if background {
        // SSH has forked — find its PID and record it.
        if let Some(pid) = find_ssh_forward_pid(&session.sandbox_id, port) {
            write_forward_pid(name, port, pid, &session.sandbox_id, &spec.bind_addr)?;
        } else {
            eprintln!(
                "{} Could not discover backgrounded SSH process; \
                 forward may be running but is not tracked",
                "!".yellow(),
            );
        }
    }

    Ok(())
}

fn foreground_forward_started_message(
    name: &str,
    spec: &openshell_core::forward::ForwardSpec,
) -> String {
    format!(
        "{} Forwarding port {} to sandbox {name}\n  Access at: {}\n  Press Ctrl+C to stop\n  {}",
        "✓".green().bold(),
        spec.port,
        spec.access_url(),
        "Hint: pass --background to start forwarding without blocking your terminal".dimmed(),
    )
}

async fn sandbox_exec_with_mode(
    server: &str,
    name: &str,
    command: &[String],
    tty: bool,
    tls: &TlsOptions,
    replace_process: bool,
) -> Result<()> {
    if command.is_empty() {
        return Err(miette::miette!("no command provided"));
    }

    let session = ssh_session_config(server, name, tls).await?;
    let mut ssh = ssh_base_command(&session.proxy_command);

    if tty {
        ssh.arg("-tt")
            .arg("-o")
            .arg("RequestTTY=force")
            .arg("-o")
            .arg("SetEnv=TERM=xterm-256color");
    } else {
        ssh.arg("-T").arg("-o").arg("RequestTTY=no");
    }

    let command_str = command
        .iter()
        .map(|arg| shell_escape(arg))
        .collect::<Vec<_>>()
        .join(" ");

    ssh.arg("sandbox")
        .arg(command_str)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    tokio::task::spawn_blocking(move || exec_or_wait(ssh, tty && replace_process))
        .await
        .into_diagnostic()??;

    Ok(())
}

/// Execute a command in a sandbox via SSH.
pub async fn sandbox_exec(
    server: &str,
    name: &str,
    command: &[String],
    tty: bool,
    tls: &TlsOptions,
) -> Result<()> {
    sandbox_exec_with_mode(server, name, command, tty, tls, true).await
}

pub(crate) async fn sandbox_exec_without_exec(
    server: &str,
    name: &str,
    command: &[String],
    tty: bool,
    tls: &TlsOptions,
) -> Result<()> {
    sandbox_exec_with_mode(server, name, command, tty, tls, false).await
}

/// What to pack into the tar archive streamed to the sandbox.
enum UploadSource {
    /// A single local file or directory.  `tar_name` controls the entry name
    /// inside the archive (e.g. the target basename for file-to-file uploads).
    SinglePath {
        local_path: PathBuf,
        tar_name: std::ffi::OsString,
    },
    /// A set of files relative to a base directory (git-filtered uploads).
    FileList {
        base_dir: PathBuf,
        files: Vec<String>,
        archive_prefix: Option<PathBuf>,
    },
}

fn write_upload_archive<W: Write>(writer: W, source: UploadSource) -> Result<()> {
    let mut archive = tar::Builder::new(writer);
    match source {
        UploadSource::SinglePath {
            local_path,
            tar_name,
        } => {
            if local_path.is_file() {
                archive
                    .append_path_with_name(&local_path, &tar_name)
                    .into_diagnostic()?;
            } else if local_path.is_dir() {
                archive
                    .append_dir_all(&tar_name, &local_path)
                    .into_diagnostic()?;
            } else {
                return Err(miette::miette!(
                    "local path does not exist: {}",
                    local_path.display()
                ));
            }
        }
        UploadSource::FileList {
            base_dir,
            files,
            archive_prefix,
        } => {
            for file in &files {
                let full_path = base_dir.join(file);
                let archive_path = archive_prefix
                    .as_ref()
                    .map_or_else(|| PathBuf::from(file), |prefix| prefix.join(file));
                if full_path.is_file() {
                    archive
                        .append_path_with_name(&full_path, &archive_path)
                        .into_diagnostic()
                        .wrap_err_with(|| {
                            format!("failed to add {} to tar archive", archive_path.display())
                        })?;
                } else if full_path.is_dir() {
                    archive
                        .append_dir_all(&archive_path, &full_path)
                        .into_diagnostic()
                        .wrap_err_with(|| {
                            format!(
                                "failed to add directory {} to tar archive",
                                archive_path.display()
                            )
                        })?;
                }
            }
        }
    }
    archive.finish().into_diagnostic()?;
    Ok(())
}

/// Core tar-over-SSH upload: streams a tar archive into `dest_dir` on the
/// sandbox.  Callers are responsible for splitting the destination path so
/// that `dest_dir` is always a directory.
///
/// When `dest_dir` is `None`, the sandbox user's home directory (`$HOME`) is
/// used as the extraction target.  This avoids hard-coding any particular
/// path and works for custom container images with non-default `WORKDIR`.
async fn ssh_tar_upload(
    server: &str,
    name: &str,
    dest_dir: Option<&str>,
    source: UploadSource,
    tls: &TlsOptions,
) -> Result<()> {
    let session = ssh_session_config(server, name, tls).await?;

    // When no explicit destination is given, use the unescaped `$HOME` shell
    // variable so the remote shell resolves it at runtime.
    let escaped_dest = dest_dir.map_or_else(|| "$HOME".to_string(), shell_escape);

    let mut ssh = ssh_base_command(&session.proxy_command);
    ssh.arg("-T")
        .arg("-o")
        .arg("RequestTTY=no")
        .arg("sandbox")
        .arg(format!(
            "mkdir -p {escaped_dest} && cat | tar xf - -C {escaped_dest}",
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = ssh.spawn().into_diagnostic()?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| miette::miette!("failed to open stdin for ssh process"))?;

    // Build the tar archive in a blocking task since the tar crate is synchronous.
    tokio::task::spawn_blocking(move || -> Result<()> { write_upload_archive(stdin, source) })
        .await
        .into_diagnostic()??;

    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .into_diagnostic()?
        .into_diagnostic()?;

    if !status.success() {
        return Err(miette::miette!(
            "ssh tar extract exited with status {status}"
        ));
    }

    Ok(())
}

/// Split a sandbox path into (`parent_directory`, basename).
///
/// Examples:
///   `"/sandbox/.bashrc"`  -> `("/sandbox", ".bashrc")`
///   `"/sandbox/sub/file"` -> `("/sandbox/sub", "file")`
///   `"file.txt"`          -> `(".", "file.txt")`
fn split_sandbox_path(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(0) => ("/", &path[1..]),
        Some(pos) => (&path[..pos], &path[pos + 1..]),
        None => (".", path),
    }
}

/// Writable root inside every sandbox. Used as the boundary for path-traversal
/// checks on sandbox-side source paths in download flows.
const SANDBOX_WORKSPACE_ROOT: &str = "/sandbox";

/// Lexically clean a POSIX-style absolute path by resolving `.` and `..`
/// components, collapsing repeated separators, and stripping any trailing
/// slash. Returns `None` if the input is empty or relative — the caller is
/// expected to reject those before reaching this helper.
///
/// This is *lexical* only: it does not consult the filesystem and so cannot
/// follow symlinks. That trade-off is intentional — the function is used
/// client-side to refuse obvious path-traversal attempts before issuing the
/// SSH command. Symlink-based escapes inside the sandbox must be addressed
/// server-side.
fn lexical_clean_absolute_path(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }
    let mut stack: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    if stack.is_empty() {
        return Some("/".to_string());
    }
    let mut out = String::with_capacity(path.len());
    for component in stack {
        out.push('/');
        out.push_str(component);
    }
    Some(out)
}

/// Validate that a sandbox-side source path passed to `sandbox download`
/// resolves under the sandbox writable root.
///
/// Returns the cleaned, traversal-resolved path on success. Refuses any
/// path that lexically escapes `/sandbox` (e.g. `/etc/passwd`,
/// `/sandbox/../etc/passwd`) with a user-facing error.
///
/// This is a lexical guard only — it does not follow symlinks. Call
/// `resolve_sandbox_source_path` after this on any path that will be passed
/// to a subsequent SSH I/O operation, so a symlink such as
/// `/sandbox/etc-link -> /etc` cannot leak files outside the workspace.
fn validate_sandbox_source_path(path: &str) -> Result<String> {
    if path.is_empty() {
        return Err(miette::miette!("sandbox source path is empty"));
    }
    let cleaned = lexical_clean_absolute_path(path)
        .ok_or_else(|| miette::miette!("sandbox source path must be absolute (got '{path}')"))?;
    if !is_under_sandbox_workspace(&cleaned) {
        return Err(miette::miette!(
            "sandbox source path '{path}' is outside the sandbox workspace ({SANDBOX_WORKSPACE_ROOT})"
        ));
    }
    Ok(cleaned)
}

/// Pure helper: is `path` equal to `/sandbox` or a descendant of it?
fn is_under_sandbox_workspace(path: &str) -> bool {
    path == SANDBOX_WORKSPACE_ROOT || path.starts_with(&format!("{SANDBOX_WORKSPACE_ROOT}/"))
}

/// Resolve every symlink in `sandbox_path` on the sandbox side and refuse the
/// result if it lands outside `/sandbox`.
///
/// The lexical guard in `validate_sandbox_source_path` cannot see symlinks; a
/// path such as `/sandbox/etc-link/passwd` (where `etc-link -> /etc`) clears
/// the lexical check but would still leak `/etc/passwd` once `tar -C` follows
/// the link. Resolving symlinks on the remote side and re-validating closes
/// that gap. The returned fully-resolved path is what the caller should hand
/// to probe and tar invocations.
async fn resolve_sandbox_source_path(
    session: &SshSessionConfig,
    sandbox_path: &str,
) -> Result<String> {
    let resolve_cmd = format!("realpath -e -- {path}", path = shell_escape(sandbox_path));
    let resolved = ssh_run_capture_stdout(session, &resolve_cmd)
        .await
        .wrap_err_with(|| format!("failed to resolve sandbox source path '{sandbox_path}'"))?;
    if resolved.is_empty() {
        return Err(miette::miette!(
            "sandbox source path '{sandbox_path}' does not exist"
        ));
    }
    if !is_under_sandbox_workspace(&resolved) {
        return Err(miette::miette!(
            "sandbox source path '{sandbox_path}' resolves to '{resolved}', outside the sandbox workspace ({SANDBOX_WORKSPACE_ROOT})"
        ));
    }
    Ok(resolved)
}

/// Resolve the host-side target path for a downloaded *file*, following
/// `cp`-style semantics.
///
/// - If `dest_str` ends with `/` or already exists as a directory, the file is
///   placed inside it as `<dest>/<source_basename>`.
/// - Otherwise `dest_str` is treated as the exact file path to write.
///
/// `dest_exists_as_dir` is taken as a parameter (rather than queried inside)
/// so this function stays pure and unit-testable; the caller performs the
/// filesystem check.
fn resolve_file_download_target(
    dest_str: &str,
    source_basename: &str,
    dest_exists_as_dir: bool,
) -> PathBuf {
    let trailing_slash = dest_str.ends_with('/');
    let dest_path = Path::new(dest_str);
    if trailing_slash || dest_exists_as_dir {
        dest_path.join(source_basename)
    } else {
        dest_path.to_path_buf()
    }
}

/// Push a list of files from a local directory into a sandbox using tar-over-SSH.
///
/// Files are streamed as a tar archive to `ssh ... tar xf - -C <dest>` on
/// the sandbox side.  When `dest` is `None`, files are uploaded to the
/// sandbox user's home directory.
pub async fn sandbox_sync_up_files(
    server: &str,
    name: &str,
    base_dir: &Path,
    files: &[String],
    local_path: &Path,
    dest: Option<&str>,
    tls: &TlsOptions,
) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    ssh_tar_upload(
        server,
        name,
        dest,
        UploadSource::FileList {
            base_dir: base_dir.to_path_buf(),
            files: files.to_vec(),
            archive_prefix: file_list_archive_prefix(local_path),
        },
        tls,
    )
    .await
}

/// Push a local path (file or directory) into a sandbox using tar-over-SSH.
///
/// When `sandbox_path` is `None`, files are uploaded to the sandbox user's
/// home directory.  When uploading a single file to an explicit destination
/// that does not end with `/`, the destination is treated as a file path:
/// the parent directory is created and the file is written with the
/// destination's basename.  This matches `cp` / `scp` semantics.
pub async fn sandbox_sync_up(
    server: &str,
    name: &str,
    local_path: &Path,
    sandbox_path: Option<&str>,
    tls: &TlsOptions,
) -> Result<()> {
    // When an explicit destination is given and looks like a file path (does
    // not end with '/'), split into parent directory + target basename so that
    // `mkdir -p` creates the parent and tar extracts the file with the right
    // name.
    //
    // Exception: if splitting would yield "/" as the parent (e.g. the user
    // passed "/sandbox"), fall through to directory semantics instead.  The
    // sandbox user cannot write to "/" and the intent is almost certainly
    // "put the file inside /sandbox", not "create a file named sandbox in /".
    if let Some(path) = sandbox_path
        && local_path.is_file()
        && !path.ends_with('/')
    {
        let (parent, target_name) = split_sandbox_path(path);
        if parent != "/" {
            return ssh_tar_upload(
                server,
                name,
                Some(parent),
                UploadSource::SinglePath {
                    local_path: local_path.to_path_buf(),
                    tar_name: target_name.into(),
                },
                tls,
            )
            .await;
        }
    }

    let tar_name = if local_path.is_file() {
        local_path
            .file_name()
            .ok_or_else(|| miette::miette!("path has no file name"))?
            .to_os_string()
    } else {
        // For directories, wrap contents under the source basename so uploads
        // land at `<dest>/<dirname>/...` — matches `scp -r` and `cp -r`. Falls
        // back to "." for paths with no meaningful basename (`.`, `/`), which
        // preserves the legacy flatten behavior in those edge cases.
        directory_upload_prefix(local_path)
    };

    ssh_tar_upload(
        server,
        name,
        sandbox_path,
        UploadSource::SinglePath {
            local_path: local_path.to_path_buf(),
            tar_name,
        },
        tls,
    )
    .await
}

/// Compute the tar entry prefix for a directory upload.
///
/// Returns the directory's basename for any path with a meaningful basename;
/// callers extracting at `<dest>` will see contents wrapped under
/// `<dest>/<basename>/...`. Returns `"."` for paths without a basename
/// (e.g. `.` or `/`), which produces flat extraction at `<dest>`.
fn directory_upload_prefix(local_path: &Path) -> std::ffi::OsString {
    local_path
        .file_name()
        .map_or_else(|| ".".into(), std::ffi::OsStr::to_os_string)
}

fn file_list_archive_prefix(local_path: &Path) -> Option<PathBuf> {
    if !local_path.is_dir() {
        return None;
    }

    let prefix = directory_upload_prefix(local_path);
    if prefix == "." {
        None
    } else {
        Some(PathBuf::from(prefix))
    }
}

/// Run a small command on the sandbox over SSH and capture its stdout.
///
/// Used by the download flow to probe whether the source path is a regular
/// file or a directory before streaming the tar archive. Stderr is inherited
/// so the user still sees any diagnostic output from ssh itself.
async fn ssh_run_capture_stdout(session: &SshSessionConfig, command: &str) -> Result<String> {
    let mut ssh = ssh_base_command(&session.proxy_command);
    ssh.arg("-T")
        .arg("-o")
        .arg("RequestTTY=no")
        .arg("sandbox")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let output = tokio::task::spawn_blocking(move || ssh.output())
        .await
        .into_diagnostic()?
        .into_diagnostic()?;
    if !output.status.success() {
        return Err(miette::miette!(
            "ssh probe exited with status {}",
            output.status
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SandboxSourceKind {
    File,
    Directory,
}

/// Probe the sandbox-side source path. The path is assumed to have already
/// been validated by `validate_sandbox_source_path`.
async fn probe_sandbox_source_kind(
    session: &SshSessionConfig,
    sandbox_path: &str,
) -> Result<SandboxSourceKind> {
    let probe_cmd = format!(
        "if [ -d {path} ]; then printf dir; elif [ -e {path} ]; then printf file; else printf missing; fi",
        path = shell_escape(sandbox_path),
    );
    let kind = ssh_run_capture_stdout(session, &probe_cmd).await?;
    match kind.as_str() {
        "dir" => Ok(SandboxSourceKind::Directory),
        "file" => Ok(SandboxSourceKind::File),
        "missing" => Err(miette::miette!(
            "sandbox source path '{sandbox_path}' does not exist"
        )),
        other => Err(miette::miette!(
            "unexpected probe output for sandbox source path '{sandbox_path}': '{other}'"
        )),
    }
}

/// Pull a path from a sandbox to a local destination using tar-over-SSH.
///
/// Follows `cp`-style semantics for the destination:
///
/// - If the source is a single file:
///   - When `dest` ends with `/` or already exists as a directory on the host,
///     the file lands at `<dest>/<source-basename>`.
///   - Otherwise `dest` is taken to be the exact file path to write.
/// - If the source is a directory, its contents are extracted into `dest`
///   (creating `dest` if it does not yet exist). This preserves prior
///   behaviour for the directory-source case.
///
/// The sandbox source path is also subjected to a workspace-boundary check
/// before any SSH command is issued; paths that lexically resolve outside
/// `/sandbox` are refused.
pub async fn sandbox_sync_down(
    server: &str,
    name: &str,
    sandbox_path: &str,
    dest: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let sandbox_path = validate_sandbox_source_path(sandbox_path)?;
    let session = ssh_session_config(server, name, tls).await?;
    let sandbox_path = resolve_sandbox_source_path(&session, &sandbox_path).await?;
    let kind = probe_sandbox_source_kind(&session, &sandbox_path).await?;

    match kind {
        SandboxSourceKind::File => sandbox_sync_down_file(&session, &sandbox_path, dest).await,
        SandboxSourceKind::Directory => {
            sandbox_sync_down_directory(&session, &sandbox_path, dest).await
        }
    }
}

/// Stream a tar archive from the sandbox and extract it into a fresh
/// destination directory. The source is always wrapped on the sandbox side so
/// the host can pick a basename when needed.
async fn stream_sandbox_tar(
    session: &SshSessionConfig,
    tar_cmd: String,
    extract_into: &Path,
) -> Result<()> {
    let mut ssh = ssh_base_command(&session.proxy_command);
    ssh.arg("-T")
        .arg("-o")
        .arg("RequestTTY=no")
        .arg("sandbox")
        .arg(tar_cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = ssh.spawn().into_diagnostic()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| miette::miette!("failed to open stdout for ssh process"))?;

    let extract_into = extract_into.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut archive = tar::Archive::new(stdout);
        archive
            .unpack(&extract_into)
            .into_diagnostic()
            .wrap_err("failed to extract tar archive from sandbox")?;
        Ok(())
    })
    .await
    .into_diagnostic()??;

    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .into_diagnostic()?
        .into_diagnostic()?;

    if !status.success() {
        return Err(miette::miette!(
            "ssh tar create exited with status {status}"
        ));
    }
    Ok(())
}

/// Build the `tar cf - -C <parent> -- <basename>` command used to wrap a
/// single sandbox-side file for download.
///
/// The trailing `--` is required: a sandbox-side file whose basename starts
/// with `-` (e.g. `--checkpoint-action=...`) would otherwise be parsed by GNU
/// tar as an option rather than a member to archive.
fn build_single_file_tar_cmd(parent: &str, basename: &str) -> String {
    format!(
        "tar cf - -C {parent} -- {name}",
        parent = shell_escape(parent),
        name = shell_escape(basename),
    )
}

async fn sandbox_sync_down_file(
    session: &SshSessionConfig,
    sandbox_path: &str,
    dest: &str,
) -> Result<()> {
    let (parent, basename) = split_sandbox_path(sandbox_path);
    let dest_exists_as_dir = fs::symlink_metadata(Path::new(dest)).is_ok_and(|m| m.is_dir());
    let final_path = resolve_file_download_target(dest, basename, dest_exists_as_dir);

    let staging_parent = final_path
        .parent()
        .ok_or_else(|| miette::miette!("destination '{}' has no parent directory", dest))?;
    fs::create_dir_all(staging_parent)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create local destination directory '{}'",
                staging_parent.display()
            )
        })?;

    let staging = tempfile::TempDir::new_in(staging_parent)
        .into_diagnostic()
        .wrap_err("failed to create download staging directory")?;

    let tar_cmd = build_single_file_tar_cmd(parent, basename);
    stream_sandbox_tar(session, tar_cmd, staging.path()).await?;

    place_downloaded_file(staging.path(), basename, &final_path).wrap_err_with(|| {
        format!(
            "failed to place downloaded file at '{}'",
            final_path.display()
        )
    })?;
    Ok(())
}

/// Move a single file extracted by `stream_sandbox_tar` into its final
/// position on the host.
///
/// `staging_dir` must contain a single regular-file entry named
/// `source_basename` (the wrapper produced by `tar cf - -C <parent> <name>`).
/// The entry is renamed onto `final_path`, atomically when `staging_dir` is
/// on the same filesystem. Refuses to overwrite an existing directory at
/// `final_path` to match `cp` behaviour.
fn place_downloaded_file(
    staging_dir: &Path,
    source_basename: &str,
    final_path: &Path,
) -> Result<()> {
    let staged_file = staging_dir.join(source_basename);
    let staged_meta = fs::symlink_metadata(&staged_file)
        .into_diagnostic()
        .wrap_err("downloaded archive did not contain the expected entry")?;
    if !staged_meta.is_file() {
        return Err(miette::miette!(
            "downloaded entry '{source_basename}' is not a regular file"
        ));
    }

    if let Ok(existing) = fs::symlink_metadata(final_path)
        && existing.is_dir()
    {
        return Err(miette::miette!(
            "cannot overwrite directory '{}' with downloaded file",
            final_path.display()
        ));
    }

    fs::rename(&staged_file, final_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to rename into '{}'", final_path.display()))?;
    Ok(())
}

async fn sandbox_sync_down_directory(
    session: &SshSessionConfig,
    sandbox_path: &str,
    dest: &str,
) -> Result<()> {
    let dest_path = Path::new(dest);
    if let Ok(existing) = fs::symlink_metadata(dest_path)
        && !existing.is_dir()
    {
        return Err(miette::miette!(
            "cannot extract directory '{sandbox_path}' over non-directory destination '{}'",
            dest_path.display()
        ));
    }
    fs::create_dir_all(dest_path)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create local destination directory '{}'",
                dest_path.display()
            )
        })?;

    let tar_cmd = format!("tar cf - -C {path} .", path = shell_escape(sandbox_path));
    stream_sandbox_tar(session, tar_cmd, dest_path).await
}

/// Run the SSH proxy, connecting stdin/stdout to the gateway.
pub async fn sandbox_ssh_proxy(
    gateway_url: &str,
    sandbox_id: &str,
    token: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let server = grpc_server_from_ssh_gateway_url(gateway_url)?;
    let mut client = grpc_client(&server, tls).await?;

    let (tx, rx) = tokio::sync::mpsc::channel::<TcpForwardFrame>(16);
    tx.send(TcpForwardFrame {
        payload: Some(openshell_core::proto::tcp_forward_frame::Payload::Init(
            TcpForwardInit {
                sandbox_id: sandbox_id.to_string(),
                service_id: format!("ssh-proxy:{sandbox_id}"),
                target: Some(tcp_forward_init::Target::Ssh(SshRelayTarget {})),
                authorization_token: token.to_string(),
            },
        )),
    })
    .await
    .map_err(|_| miette::miette!("failed to initialize SSH forward stream"))?;

    let mut response = client
        .forward_tcp(ReceiverStream::new(rx))
        .await
        .into_diagnostic()?
        .into_inner();

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let to_remote = tokio::spawn(async move {
        let mut stdin = stdin;
        let mut buf = vec![0u8; 64 * 1024];
        while let Ok(n) = stdin.read(&mut buf).await {
            if n == 0 {
                break;
            }
            if tx
                .send(TcpForwardFrame {
                    payload: Some(openshell_core::proto::tcp_forward_frame::Payload::Data(
                        buf[..n].to_vec(),
                    )),
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let from_remote = tokio::spawn(async move {
        let mut stdout = stdout;
        loop {
            let Ok(Some(frame)) = response.message().await else {
                break;
            };
            let Some(openshell_core::proto::tcp_forward_frame::Payload::Data(data)) = frame.payload
            else {
                continue;
            };
            if data.is_empty() {
                continue;
            }
            if stdout.write_all(&data).await.is_err() {
                break;
            }
            let _ = stdout.flush().await;
        }
    });
    let _ = from_remote.await;
    to_remote.abort();

    Ok(())
}

fn grpc_server_from_ssh_gateway_url(gateway_url: &str) -> Result<String> {
    let url: url::Url = gateway_url
        .parse()
        .into_diagnostic()
        .wrap_err("invalid gateway URL")?;
    let scheme = url.scheme();
    let gateway_host = url
        .host_str()
        .ok_or_else(|| miette::miette!("gateway URL missing host"))?;
    let gateway_port = url
        .port_or_known_default()
        .ok_or_else(|| miette::miette!("gateway URL missing port"))?;
    Ok(format_gateway_url(scheme, gateway_host, gateway_port))
}

/// Run the SSH proxy in "name mode": create a session on the fly, then proxy.
///
/// This is equivalent to [`sandbox_ssh_proxy`] but accepts a cluster endpoint
/// and sandbox name instead of pre-created gateway/token credentials.  It is
/// suitable for use as an SSH `ProxyCommand` in `~/.ssh/config` because it
/// creates a fresh session on every invocation.
pub async fn sandbox_ssh_proxy_by_name(server: &str, name: &str, tls: &TlsOptions) -> Result<()> {
    let session = ssh_session_config(server, name, tls).await?;
    sandbox_ssh_proxy(
        &session.gateway_url,
        &session.sandbox_id,
        &session.token,
        tls,
    )
    .await
}

fn host_alias(name: &str) -> String {
    format!("openshell-{name}")
}

fn render_ssh_config(gateway: &str, name: &str) -> String {
    let exe = std::env::current_exe().expect("failed to resolve OpenShell executable");
    let exe = shell_escape(&exe.to_string_lossy());

    let proxy_cmd = format!(
        "{exe} ssh-proxy --gateway-name {} --name {}",
        shell_escape(gateway),
        shell_escape(name),
    );
    let host_alias = host_alias(name);
    format!(
        "Host {host_alias}\n    User sandbox\n    StrictHostKeyChecking no\n    UserKnownHostsFile /dev/null\n    GlobalKnownHostsFile /dev/null\n    LogLevel ERROR\n    ServerAliveInterval 15\n    ServerAliveCountMax 3\n    ProxyCommand {proxy_cmd}\n"
    )
}

fn openshell_ssh_config_path() -> Result<PathBuf> {
    Ok(openshell_core::paths::xdg_config_dir()?
        .join("openshell")
        .join("ssh_config"))
}

fn user_ssh_config_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .into_diagnostic()
        .wrap_err("HOME is not set")?;
    Ok(PathBuf::from(home).join(".ssh").join("config"))
}

fn render_include_line(path: &Path) -> String {
    format!("Include \"{}\"", path.display())
}

fn ssh_config_includes_path(contents: &str, path: &Path) -> bool {
    let quoted = format!("\"{}\"", path.display());
    let plain = path.display().to_string();
    contents.lines().any(|line| {
        let trimmed = line.trim();
        if !trimmed.starts_with("Include ") {
            return false;
        }
        trimmed["Include ".len()..]
            .split_whitespace()
            .any(|token| token == quoted || token == plain)
    })
}

fn ensure_openshell_include(main_config: &Path, managed_config: &Path) -> Result<()> {
    if let Some(parent) = main_config.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create ~/.ssh directory")?;
    }

    let include_line = render_include_line(managed_config);
    let contents = fs::read_to_string(main_config).unwrap_or_default();
    let mut lines: Vec<&str> = contents.lines().collect();
    lines.retain(|line| !ssh_config_includes_path(line, managed_config));

    let insert_at = lines
        .iter()
        .position(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("Host ") || trimmed.starts_with("Match ")
        })
        .unwrap_or(lines.len());

    let mut out = Vec::new();
    out.extend_from_slice(&lines[..insert_at]);
    if !out.is_empty() && !out.last().is_some_and(|line| line.is_empty()) {
        out.push("");
    }
    out.push(&include_line);
    if insert_at < lines.len() && !lines[insert_at].is_empty() {
        out.push("");
    }
    out.extend_from_slice(&lines[insert_at..]);

    let mut rendered = out.join("\n");
    if !rendered.is_empty() {
        rendered.push('\n');
    }

    fs::write(main_config, rendered)
        .into_diagnostic()
        .wrap_err("failed to update ~/.ssh/config")?;
    Ok(())
}

fn host_line_matches(line: &str, alias: &str) -> bool {
    let trimmed = line.trim_start();
    if !trimmed.starts_with("Host ") {
        return false;
    }
    trimmed["Host ".len()..]
        .split_whitespace()
        .any(|token| token == alias)
}

fn upsert_host_block(contents: &str, alias: &str, block: &str) -> String {
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.iter().position(|line| host_line_matches(line, alias));

    let mut out = Vec::new();
    if let Some(start) = start {
        let end = lines
            .iter()
            .enumerate()
            .skip(start + 1)
            .find(|(_, line)| line.trim_start().starts_with("Host "))
            .map_or(lines.len(), |(idx, _)| idx);

        out.extend_from_slice(&lines[..start]);
        if !out.is_empty() && !out.last().is_some_and(|line| line.is_empty()) {
            out.push("");
        }
        out.extend(block.lines());
        if end < lines.len() && !lines[end..].first().is_some_and(|line| line.is_empty()) {
            out.push("");
        }
        out.extend_from_slice(&lines[end..]);
    } else {
        out.extend_from_slice(&lines);
        if !out.is_empty() && !out.last().is_some_and(|line| line.is_empty()) {
            out.push("");
        }
        out.extend(block.lines());
    }

    let mut rendered = out.join("\n");
    if !rendered.is_empty() {
        rendered.push('\n');
    }
    rendered
}

pub fn install_ssh_config(gateway: &str, name: &str) -> Result<PathBuf> {
    let managed_config = openshell_ssh_config_path()?;
    let main_config = user_ssh_config_path()?;
    ensure_openshell_include(&main_config, &managed_config)?;

    if let Some(parent) = managed_config.parent() {
        openshell_core::paths::create_dir_restricted(parent)?;
    }

    let alias = host_alias(name);
    let block = render_ssh_config(gateway, name);
    let contents = fs::read_to_string(&managed_config).unwrap_or_default();
    let updated = upsert_host_block(&contents, &alias, &block);
    fs::write(&managed_config, updated)
        .into_diagnostic()
        .wrap_err("failed to write OpenShell SSH config")?;
    Ok(managed_config)
}

fn launch_editor(editor: Editor, host_alias: &str) -> Result<()> {
    launch_editor_command(
        editor.binary(),
        editor.label(),
        &Editor::remote_target(host_alias),
    )
}

fn launch_editor_command(binary: &str, label: &str, remote_target: &str) -> Result<()> {
    let status = Command::new(binary)
        .arg("--remote")
        .arg(remote_target)
        .arg("/sandbox")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    match status {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(miette::miette!(
            "{} is not installed or not on PATH",
            binary
        )),
        Err(err) => Err(err)
            .into_diagnostic()
            .wrap_err(format!("failed to launch {label}")),
    }
}

/// Print an SSH config `Host` block for a sandbox to stdout.
///
/// The output is suitable for appending to `~/.ssh/config` so that tools like
/// `VSCode` Remote-SSH can connect to the sandbox by host alias.
///
/// The `ProxyCommand` uses `--gateway-name` so that `ssh-proxy` resolves the
/// gateway endpoint and TLS certificates from the gateway metadata directory
/// (`~/.config/openshell/gateways/<name>/mtls/`).
pub fn print_ssh_config(gateway: &str, name: &str) {
    print!("{}", render_ssh_config(gateway, name));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TEST_ENV_LOCK;

    #[test]
    fn upsert_host_block_appends_when_missing() {
        let input = "Host existing\n  HostName example.com\n";
        let block = "Host openshell-demo\n    User sandbox\n";
        let output = upsert_host_block(input, "openshell-demo", block);
        assert!(output.contains("Host existing"));
        assert!(output.contains("Host openshell-demo"));
        assert_eq!(output.matches("Host openshell-demo").count(), 1);
    }

    #[test]
    fn upsert_host_block_replaces_existing_without_duplicates() {
        let input = "Host openshell-demo\n    User old\n\nHost other\n    HostName other.example\n";
        let block = "Host openshell-demo\n    User sandbox\n    LogLevel ERROR\n";
        let output = upsert_host_block(input, "openshell-demo", block);
        assert!(!output.contains("User old"));
        assert!(output.contains("LogLevel ERROR"));
        assert!(output.contains("Host other"));
        assert_eq!(output.matches("Host openshell-demo").count(), 1);
    }

    #[test]
    #[allow(unsafe_code)] // Test-only: env vars require unsafe in Rust 2024.
    fn install_ssh_config_adds_include_once_and_updates_managed_file() {
        let _guard = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = tempfile::tempdir().unwrap();
        let xdg = tempfile::tempdir().unwrap();
        let old_home = std::env::var("HOME").ok();
        let old_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::set_var("XDG_CONFIG_HOME", xdg.path());
        }

        let ssh_dir = home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        let user_config = ssh_dir.join("config");
        fs::write(&user_config, "Host personal\n    HostName example.com\n").unwrap();

        let managed_path = install_ssh_config("openshell", "demo").unwrap();
        install_ssh_config("openshell", "demo").unwrap();

        let main_contents = fs::read_to_string(&user_config).unwrap();
        assert!(main_contents.contains("Host personal"));
        assert_eq!(main_contents.matches("Include ").count(), 1);
        assert!(main_contents.contains(&render_include_line(&managed_path)));
        let include_idx = main_contents.find("Include ").unwrap();
        let host_idx = main_contents.find("Host personal").unwrap();
        assert!(include_idx < host_idx);

        let managed_contents = fs::read_to_string(&managed_path).unwrap();
        assert_eq!(managed_contents.matches("Host openshell-demo").count(), 1);
        assert!(managed_contents.contains("ProxyCommand"));

        unsafe {
            match old_home {
                Some(val) => std::env::set_var("HOME", val),
                None => std::env::remove_var("HOME"),
            }
            match old_xdg {
                Some(val) => std::env::set_var("XDG_CONFIG_HOME", val),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }

    #[test]
    fn launch_editor_returns_friendly_error_when_binary_missing() {
        let err = launch_editor_command(
            "openshell-test-missing-binary",
            "Test Editor",
            "ssh-remote+openshell-demo",
        )
        .unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("openshell-test-missing-binary is not installed or not on PATH"));
    }

    #[test]
    fn foreground_forward_started_message_includes_port_and_stop_hint() {
        let spec = openshell_core::forward::ForwardSpec::new(8080);
        let message = foreground_forward_started_message("demo", &spec);
        assert!(message.contains("Forwarding port 8080 to sandbox demo"));
        assert!(message.contains("Access at: http://127.0.0.1:8080/"));
        assert!(message.contains("sandbox demo"));
        assert!(message.contains("Press Ctrl+C to stop"));
        assert!(message.contains(
            "Hint: pass --background to start forwarding without blocking your terminal"
        ));
    }

    #[test]
    fn foreground_forward_started_message_custom_bind_addr() {
        let spec = openshell_core::forward::ForwardSpec::parse("0.0.0.0:3000").unwrap();
        let message = foreground_forward_started_message("demo", &spec);
        assert!(message.contains("Forwarding port 3000 to sandbox demo"));
        assert!(message.contains("Access at: http://localhost:3000/"));
    }

    #[test]
    fn split_sandbox_path_separates_parent_and_basename() {
        assert_eq!(
            split_sandbox_path("/sandbox/.bashrc"),
            ("/sandbox", ".bashrc")
        );
        assert_eq!(
            split_sandbox_path("/sandbox/sub/file"),
            ("/sandbox/sub", "file")
        );
        assert_eq!(split_sandbox_path("/a/b/c/d.txt"), ("/a/b/c", "d.txt"));
    }

    #[test]
    fn lexical_clean_resolves_dot_and_dotdot_segments() {
        assert_eq!(
            lexical_clean_absolute_path("/sandbox/./a"),
            Some("/sandbox/a".to_string())
        );
        assert_eq!(
            lexical_clean_absolute_path("/sandbox/sub/../a"),
            Some("/sandbox/a".to_string())
        );
        assert_eq!(
            lexical_clean_absolute_path("/sandbox/../etc/passwd"),
            Some("/etc/passwd".to_string())
        );
        assert_eq!(
            lexical_clean_absolute_path("//sandbox///foo//"),
            Some("/sandbox/foo".to_string())
        );
        assert_eq!(lexical_clean_absolute_path("/"), Some("/".to_string()));
    }

    #[test]
    fn lexical_clean_refuses_relative_paths() {
        assert_eq!(lexical_clean_absolute_path(""), None);
        assert_eq!(lexical_clean_absolute_path("sandbox/a"), None);
        assert_eq!(lexical_clean_absolute_path("./a"), None);
    }

    #[test]
    fn validate_sandbox_source_path_accepts_workspace_paths() {
        assert_eq!(
            validate_sandbox_source_path("/sandbox/file.txt").unwrap(),
            "/sandbox/file.txt"
        );
        assert_eq!(
            validate_sandbox_source_path("/sandbox/.openclaw/workspace/hello.txt").unwrap(),
            "/sandbox/.openclaw/workspace/hello.txt"
        );
        assert_eq!(
            validate_sandbox_source_path("/sandbox").unwrap(),
            "/sandbox"
        );
        assert_eq!(
            validate_sandbox_source_path("/sandbox/").unwrap(),
            "/sandbox"
        );
        assert_eq!(
            validate_sandbox_source_path("/sandbox/sub/../file").unwrap(),
            "/sandbox/file"
        );
    }

    #[test]
    fn validate_sandbox_source_path_rejects_traversal_and_escapes() {
        let traversal = validate_sandbox_source_path("/etc/passwd").unwrap_err();
        assert!(
            format!("{traversal}").contains("outside the sandbox workspace"),
            "unexpected error: {traversal}"
        );

        let parent_escape = validate_sandbox_source_path("/sandbox/../etc/passwd").unwrap_err();
        assert!(
            format!("{parent_escape}").contains("outside the sandbox workspace"),
            "unexpected error: {parent_escape}"
        );

        let prefix_only = validate_sandbox_source_path("/sandboxed/secrets").unwrap_err();
        assert!(
            format!("{prefix_only}").contains("outside the sandbox workspace"),
            "unexpected error: {prefix_only}"
        );

        let empty = validate_sandbox_source_path("").unwrap_err();
        assert!(format!("{empty}").contains("empty"));

        let relative = validate_sandbox_source_path("sandbox/file").unwrap_err();
        assert!(format!("{relative}").contains("must be absolute"));
    }

    #[test]
    fn is_under_sandbox_workspace_accepts_root_and_descendants() {
        assert!(is_under_sandbox_workspace("/sandbox"));
        assert!(is_under_sandbox_workspace("/sandbox/file"));
        assert!(is_under_sandbox_workspace("/sandbox/sub/nested"));
    }

    #[test]
    fn is_under_sandbox_workspace_rejects_outside_paths_and_prefix_collisions() {
        assert!(!is_under_sandbox_workspace("/etc/passwd"));
        assert!(!is_under_sandbox_workspace("/sandboxed/secrets"));
        assert!(!is_under_sandbox_workspace("/"));
        assert!(!is_under_sandbox_workspace(""));
    }

    #[test]
    fn build_single_file_tar_cmd_inserts_double_dash_before_basename() {
        // Without `--`, a basename such as `--checkpoint-action=...` would be
        // parsed by GNU tar as an option. Guard the wire format against this
        // regression.
        let cmd = build_single_file_tar_cmd("/sandbox", "--checkpoint-action=exec=id");
        assert!(
            cmd.contains(" -- "),
            "expected `--` separator in tar command, got: {cmd}"
        );
        assert!(
            cmd.ends_with(&shell_escape("--checkpoint-action=exec=id")),
            "expected basename at end of tar command, got: {cmd}"
        );
    }

    #[test]
    fn build_single_file_tar_cmd_escapes_parent_and_basename() {
        let cmd = build_single_file_tar_cmd("/sandbox/with space", "name with space");
        assert!(cmd.contains(" -- "), "missing `--` separator: {cmd}");
        assert!(
            cmd.contains(&shell_escape("/sandbox/with space")),
            "parent not shell-escaped: {cmd}"
        );
        assert!(
            cmd.contains(&shell_escape("name with space")),
            "basename not shell-escaped: {cmd}"
        );
    }

    #[test]
    fn resolve_file_download_target_writes_to_dest_when_not_a_directory() {
        assert_eq!(
            resolve_file_download_target("/tmp/out.txt", "hello.txt", false),
            PathBuf::from("/tmp/out.txt")
        );
    }

    #[test]
    fn resolve_file_download_target_places_inside_existing_directory() {
        assert_eq!(
            resolve_file_download_target("/tmp", "hello.txt", true),
            PathBuf::from("/tmp/hello.txt")
        );
    }

    #[test]
    fn resolve_file_download_target_honors_trailing_slash() {
        assert_eq!(
            resolve_file_download_target("/tmp/newdir/", "hello.txt", false),
            PathBuf::from("/tmp/newdir/hello.txt")
        );
    }

    fn build_single_file_archive(entry_path: &str, bytes: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_gnu();
            header.set_path(entry_path).expect("set tar entry path");
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append(&header, bytes).expect("append tar entry");
            builder.finish().expect("finish tar archive");
        }
        buf
    }

    fn unpack_into(archive_bytes: &[u8], staging: &Path) {
        let mut archive = tar::Archive::new(std::io::Cursor::new(archive_bytes));
        archive.unpack(staging).expect("unpack archive");
    }

    #[test]
    fn place_downloaded_file_writes_regular_file_at_dest() {
        let workdir = tempfile::tempdir().expect("create workdir");
        let staging = workdir.path().join("staging");
        fs::create_dir_all(&staging).expect("create staging");
        let archive = build_single_file_archive("hello.txt", b"trust me");
        unpack_into(&archive, &staging);

        let dest = workdir.path().join("out.txt");
        place_downloaded_file(&staging, "hello.txt", &dest).expect("place file");

        let meta = fs::symlink_metadata(&dest).expect("stat dest");
        assert!(meta.is_file(), "dest must be a regular file, got {meta:?}");
        assert_eq!(fs::read(&dest).expect("read dest"), b"trust me");
    }

    #[test]
    fn place_downloaded_file_refuses_to_clobber_existing_directory() {
        let workdir = tempfile::tempdir().expect("create workdir");
        let staging = workdir.path().join("staging");
        fs::create_dir_all(&staging).expect("create staging");
        let archive = build_single_file_archive("hello.txt", b"trust me");
        unpack_into(&archive, &staging);

        let dest = workdir.path().join("conflict-dir");
        fs::create_dir(&dest).expect("create conflict dir");

        let err = place_downloaded_file(&staging, "hello.txt", &dest)
            .expect_err("expected directory-clobber refusal");
        assert!(
            format!("{err}").contains("cannot overwrite directory"),
            "unexpected error: {err}"
        );
        assert!(
            fs::symlink_metadata(&dest).expect("stat dest").is_dir(),
            "dest should remain a directory after refusal"
        );
    }

    #[test]
    fn download_full_pipeline_lands_file_at_exact_dest_path() {
        let workdir = tempfile::tempdir().expect("create workdir");
        let staging_parent = workdir.path();
        let archive = build_single_file_archive("hello.txt", b"trust me");

        let dest_str = staging_parent.join("out.txt");
        let dest_str = dest_str.to_str().unwrap();
        let final_path = resolve_file_download_target(dest_str, "hello.txt", false);
        assert_eq!(final_path, Path::new(dest_str));

        let staging = tempfile::TempDir::new_in(staging_parent).expect("staging dir");
        unpack_into(&archive, staging.path());
        place_downloaded_file(staging.path(), "hello.txt", &final_path).expect("place");

        let meta = fs::symlink_metadata(&final_path).expect("stat final");
        assert!(meta.is_file(), "expected regular file, got {meta:?}");
        assert_eq!(fs::read(&final_path).expect("read final"), b"trust me");
    }

    #[test]
    fn download_full_pipeline_places_inside_existing_directory_destination() {
        let workdir = tempfile::tempdir().expect("create workdir");
        let archive = build_single_file_archive("hello.txt", b"trust me");

        let dest_dir = workdir.path().join("out-dir");
        fs::create_dir(&dest_dir).expect("create dest dir");
        let dest_str = dest_dir.to_str().unwrap();
        let final_path = resolve_file_download_target(dest_str, "hello.txt", true);
        assert_eq!(final_path, dest_dir.join("hello.txt"));

        let staging = tempfile::TempDir::new_in(workdir.path()).expect("staging dir");
        unpack_into(&archive, staging.path());
        place_downloaded_file(staging.path(), "hello.txt", &final_path).expect("place");

        let meta = fs::symlink_metadata(&final_path).expect("stat final");
        assert!(meta.is_file());
        assert_eq!(fs::read(&final_path).expect("read final"), b"trust me");
    }

    #[test]
    fn directory_upload_prefix_uses_basename_for_named_directories() {
        assert_eq!(
            directory_upload_prefix(Path::new("/tmp/upload-test")),
            std::ffi::OsString::from("upload-test")
        );
        assert_eq!(
            directory_upload_prefix(Path::new("foo")),
            std::ffi::OsString::from("foo")
        );
        assert_eq!(
            directory_upload_prefix(Path::new("./parent/nested")),
            std::ffi::OsString::from("nested")
        );
    }

    #[test]
    fn directory_upload_prefix_falls_back_to_dot_for_basename_less_paths() {
        assert_eq!(
            directory_upload_prefix(Path::new(".")),
            std::ffi::OsString::from(".")
        );
        assert_eq!(
            directory_upload_prefix(Path::new("/")),
            std::ffi::OsString::from(".")
        );
    }

    #[test]
    fn file_list_archive_prefix_uses_named_directory_basename() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let source = tmpdir.path().join("source-dir");
        let file = tmpdir.path().join("file.txt");
        fs::create_dir_all(&source).expect("create source dir");
        fs::write(&file, "file").expect("write file");

        assert_eq!(
            file_list_archive_prefix(&source),
            Some(PathBuf::from("source-dir"))
        );
        assert_eq!(file_list_archive_prefix(Path::new(".")), None);
        assert_eq!(file_list_archive_prefix(&file), None);
    }

    fn upload_archive_paths(source: UploadSource) -> Vec<String> {
        let mut bytes = Vec::new();
        write_upload_archive(&mut bytes, source).expect("write upload archive");
        let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
        let entries = archive.entries().expect("read archive entries");
        let mut paths = entries
            .map(|entry| {
                entry
                    .expect("read archive entry")
                    .path()
                    .expect("read archive path")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }

    #[test]
    fn file_list_archive_preserves_directory_prefix_when_requested() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let base_dir = tmpdir.path().join("nested");
        fs::create_dir_all(base_dir.join("inner")).expect("create dirs");
        fs::write(base_dir.join("file.txt"), "file").expect("write file");
        fs::write(base_dir.join("inner/child.txt"), "child").expect("write child");

        let paths = upload_archive_paths(UploadSource::FileList {
            base_dir,
            files: vec!["file.txt".into(), "inner/child.txt".into()],
            archive_prefix: Some(PathBuf::from("nested")),
        });

        assert_eq!(paths, vec!["nested/file.txt", "nested/inner/child.txt"]);
    }

    #[test]
    fn file_list_archive_stays_flat_without_directory_prefix() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let base_dir = tmpdir.path().join("nested");
        fs::create_dir_all(base_dir.join("inner")).expect("create dirs");
        fs::write(base_dir.join("file.txt"), "file").expect("write file");
        fs::write(base_dir.join("inner/child.txt"), "child").expect("write child");

        let paths = upload_archive_paths(UploadSource::FileList {
            base_dir,
            files: vec!["file.txt".into(), "inner/child.txt".into()],
            archive_prefix: None,
        });

        assert_eq!(paths, vec!["file.txt", "inner/child.txt"]);
    }

    #[test]
    fn single_directory_archive_preserves_directory_basename() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let source = tmpdir.path().join("source-dir");
        fs::create_dir_all(source.join("inner")).expect("create dirs");
        fs::write(source.join("file.txt"), "file").expect("write file");
        fs::write(source.join("inner/child.txt"), "child").expect("write child");

        let paths = upload_archive_paths(UploadSource::SinglePath {
            local_path: source,
            tar_name: "source-dir".into(),
        });

        assert!(paths.contains(&"source-dir/file.txt".to_string()));
        assert!(paths.contains(&"source-dir/inner/child.txt".to_string()));
        assert!(paths.iter().all(|path| path.starts_with("source-dir/")));
    }

    #[test]
    fn split_sandbox_path_handles_root_and_bare_names() {
        // File directly under root
        assert_eq!(split_sandbox_path("/.bashrc"), ("/", ".bashrc"));
        // No directory component at all
        assert_eq!(split_sandbox_path("file.txt"), (".", "file.txt"));
    }
}
