// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SSH connection and proxy utilities.

use crate::tls::{TlsOptions, build_rustls_config, grpc_client, require_tls_materials};
use miette::{IntoDiagnostic, Result, WrapErr};
#[cfg(unix)]
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
use openshell_core::forward::{
    build_proxy_command, find_ssh_forward_pid, resolve_ssh_gateway, shell_escape,
    validate_ssh_session_response, write_forward_pid,
};
use openshell_core::proto::{CreateSshSessionRequest, GetSandboxRequest};
use owo_colors::OwoColorize;
use rustls::pki_types::ServerName;
use std::fs;
use std::io::IsTerminal;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::Command as TokioCommand;
use tokio_rustls::TlsConnector;

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

    fn remote_target(self, host_alias: &str) -> String {
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
            sandbox_id: sandbox.id,
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
        let base = server.trim_end_matches('/');
        format!("{base}{}", session.connect_path)
    } else {
        // If the server returned a loopback gateway address, override it with the
        // cluster endpoint's host. This handles the case where the server defaults
        // to 127.0.0.1 but the cluster is actually running on a remote host.
        #[allow(clippy::cast_possible_truncation)]
        let gateway_port_u16 = session.gateway_port as u16;
        let (gateway_host, gateway_port) =
            resolve_ssh_gateway(&session.gateway_host, gateway_port_u16, server);
        format!(
            "{}://{}:{}{}",
            session.gateway_scheme, gateway_host, gateway_port, session.connect_path
        )
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
        match tokio::time::timeout(FOREGROUND_FORWARD_STARTUP_GRACE_PERIOD, child.wait()).await {
            Ok(status) => status.into_diagnostic()?,
            Err(_) => {
                eprintln!("{}", foreground_forward_started_message(name, spec));
                child.wait().await.into_diagnostic()?
            }
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
    },
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
    let escaped_dest = match dest_dir {
        Some(d) => shell_escape(d),
        None => "$HOME".to_string(),
    };

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
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut archive = tar::Builder::new(stdin);
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
            UploadSource::FileList { base_dir, files } => {
                for file in &files {
                    let full_path = base_dir.join(file);
                    if full_path.is_file() {
                        archive
                            .append_path_with_name(&full_path, file)
                            .into_diagnostic()
                            .wrap_err_with(|| format!("failed to add {file} to tar archive"))?;
                    } else if full_path.is_dir() {
                        archive
                            .append_dir_all(file, &full_path)
                            .into_diagnostic()
                            .wrap_err_with(|| {
                                format!("failed to add directory {file} to tar archive")
                            })?;
                    }
                }
            }
        }
        archive.finish().into_diagnostic()?;
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
            "ssh tar extract exited with status {status}"
        ));
    }

    Ok(())
}

/// Split a sandbox path into (parent_directory, basename).
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
    if let Some(path) = sandbox_path {
        if local_path.is_file() && !path.ends_with('/') {
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
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| ".".into())
}

/// Pull a path from a sandbox to a local destination using tar-over-SSH.
pub async fn sandbox_sync_down(
    server: &str,
    name: &str,
    sandbox_path: &str,
    local_path: &Path,
    tls: &TlsOptions,
) -> Result<()> {
    let session = ssh_session_config(server, name, tls).await?;

    // Build tar command.  When the sandbox path is a directory we tar its
    // *contents* (using `-C <path> .`) so the caller gets the files directly
    // without an extra wrapper directory.  For a single file we split into
    // the parent directory and the filename.
    let sandbox_path_clean = sandbox_path.trim_end_matches('/');

    let tar_cmd = format!(
        "if [ -d {path} ]; then tar cf - -C {path} .; else tar cf - -C {parent} {name}; fi",
        path = shell_escape(sandbox_path_clean),
        parent = shell_escape(
            sandbox_path_clean
                .rfind('/')
                .map_or(".", |pos| if pos == 0 {
                    "/"
                } else {
                    &sandbox_path_clean[..pos]
                })
        ),
        name = shell_escape(
            sandbox_path_clean
                .rfind('/')
                .map_or(sandbox_path_clean, |pos| &sandbox_path_clean[pos + 1..])
        ),
    );

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

    let local_path = local_path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        fs::create_dir_all(&local_path)
            .into_diagnostic()
            .wrap_err("failed to create local destination directory")?;
        let mut archive = tar::Archive::new(stdout);
        archive
            .unpack(&local_path)
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

/// Run the SSH proxy, connecting stdin/stdout to the gateway.
pub async fn sandbox_ssh_proxy(
    gateway_url: &str,
    sandbox_id: &str,
    token: &str,
    tls: &TlsOptions,
) -> Result<()> {
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
    let connect_path = url.path();

    let request = format!(
        "CONNECT {connect_path} HTTP/1.1\r\nHost: {gateway_host}\r\nX-Sandbox-Id: {sandbox_id}\r\nX-Sandbox-Token: {token}\r\n\r\n"
    );

    // The gateway returns 412 (Precondition Failed) when the sandbox pod
    // exists but hasn't reached Ready phase yet. This is a transient state
    // after sandbox allocation — retry with backoff instead of failing
    // immediately.
    const MAX_CONNECT_WAIT: Duration = Duration::from_secs(60);
    const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

    let start = std::time::Instant::now();
    let mut backoff = INITIAL_BACKOFF;
    let mut buf_stream;

    loop {
        let mut stream: Box<dyn ProxyStream> =
            connect_gateway(scheme, gateway_host, gateway_port, tls).await?;
        stream
            .write_all(request.as_bytes())
            .await
            .into_diagnostic()?;

        // Wrap in a BufReader **before** reading the HTTP response.  The gateway
        // may send the 200 OK response and the first SSH protocol bytes in the
        // same TCP segment / WebSocket frame.  A plain `read()` would consume
        // those SSH bytes into our buffer and discard them, causing SSH to see a
        // truncated protocol banner and exit with code 255.  BufReader ensures
        // any bytes read past the `\r\n\r\n` header boundary stay buffered and
        // are returned by subsequent reads during the bidirectional copy phase.
        buf_stream = BufReader::new(stream);
        let status = read_connect_status(&mut buf_stream).await?;
        if status == 200 {
            break;
        }
        if status == 412 && start.elapsed() < MAX_CONNECT_WAIT {
            tracing::debug!(
                elapsed = ?start.elapsed(),
                "sandbox not yet ready (HTTP 412), retrying in {backoff:?}"
            );
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(8));
            continue;
        }
        return Err(miette::miette!(
            "gateway CONNECT failed with status {status}"
        ));
    }

    let (reader, writer) = tokio::io::split(buf_stream);
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    // Spawn both copy directions as independent tasks.  Using separate spawned
    // tasks (instead of try_join!/select!) ensures that when one direction
    // completes or errors, the other continues independently until it also
    // finishes.  This is critical: when the remote side closes the connection,
    // we must keep the stdin→gateway copy alive so SSH can finish sending its
    // protocol-close packets, and vice-versa.
    let to_remote = tokio::spawn(copy_ignoring_errors(stdin, writer));
    let from_remote = tokio::spawn(copy_ignoring_errors(reader, stdout));
    let _ = from_remote.await;
    // Once the remote→stdout direction is done, SSH has received all the data
    // it needs.  Drop the stdin→gateway task – SSH will close its pipe when
    // it's done regardless.
    to_remote.abort();

    Ok(())
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
            .map(|(idx, _)| idx)
            .unwrap_or(lines.len());

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
        &editor.remote_target(host_alias),
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

/// Copy all bytes from `reader` to `writer`, flushing on completion.
/// Errors are intentionally discarded – connection teardown errors are
/// expected during normal SSH session shutdown.
async fn copy_ignoring_errors<R, W>(mut reader: R, mut writer: W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let _ = tokio::io::copy(&mut reader, &mut writer).await;
    let _ = AsyncWriteExt::flush(&mut writer).await;
    let _ = AsyncWriteExt::shutdown(&mut writer).await;
}

async fn connect_gateway(
    scheme: &str,
    host: &str,
    port: u16,
    tls: &TlsOptions,
) -> Result<Box<dyn ProxyStream>> {
    // When using edge bearer auth, route through the WebSocket tunnel proxy
    // regardless of the origin scheme. The proxy handles edge auth headers
    // and TLS termination at the edge; the origin may be plaintext HTTP
    // behind the tunnel.
    if tls.is_bearer_auth() {
        let token = tls
            .edge_token
            .as_deref()
            .ok_or_else(|| miette::miette!("edge token required for tunnel"))?;
        let gateway_url = format!("https://{host}:{port}");
        let proxy = crate::edge_tunnel::start_tunnel_proxy(&gateway_url, token).await?;
        let tcp = TcpStream::connect(proxy.local_addr)
            .await
            .into_diagnostic()?;
        tcp.set_nodelay(true).into_diagnostic()?;
        return Ok(Box::new(tcp));
    }

    let tcp = TcpStream::connect((host, port)).await.into_diagnostic()?;
    tcp.set_nodelay(true).into_diagnostic()?;
    if scheme.eq_ignore_ascii_case("https") {
        let materials = require_tls_materials(&format!("https://{host}:{port}"), tls)?;
        let config = build_rustls_config(&materials)?;
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| miette::miette!("invalid server name: {host}"))?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .into_diagnostic()?;
        Ok(Box::new(tls))
    } else {
        Ok(Box::new(tcp))
    }
}

/// Read exactly the HTTP response status line and headers up to `\r\n\r\n`.
///
/// Uses byte-at-a-time reads so that the caller's `BufReader` retains any
/// bytes that arrived after the header boundary (e.g. the SSH protocol
/// banner that the gateway may send in the same TCP segment).
async fn read_connect_status<R: AsyncRead + Unpin>(stream: &mut R) -> Result<u16> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.into_diagnostic()?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 8192 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let line = text.lines().next().unwrap_or("");
    let status = line
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse::<u16>()
        .unwrap_or(0);
    Ok(status)
}

trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

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
    fn split_sandbox_path_handles_root_and_bare_names() {
        // File directly under root
        assert_eq!(split_sandbox_path("/.bashrc"), ("/", ".bashrc"));
        // No directory component at all
        assert_eq!(split_sandbox_path("file.txt"), (".", "file.txt"));
    }
}
