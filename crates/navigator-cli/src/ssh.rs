// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SSH connection and proxy utilities.

use crate::tls::{TlsOptions, build_rustls_config, grpc_client, require_tls_materials};
use miette::{IntoDiagnostic, Result, WrapErr};
use navigator_core::forward::{
    find_ssh_forward_pid, resolve_ssh_gateway, shell_escape, write_forward_pid,
};
use navigator_core::proto::{CreateSshSessionRequest, GetSandboxRequest};
use owo_colors::OwoColorize;
use rustls::pki_types::ServerName;
use std::io::IsTerminal;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

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

    let exe = std::env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to resolve NemoClaw executable")?;
    let exe_command = shell_escape(&exe.to_string_lossy());

    // If the server returned a loopback gateway address, override it with the
    // cluster endpoint's host. This handles the case where the server defaults
    // to 127.0.0.1 but the cluster is actually running on a remote host.
    #[allow(clippy::cast_possible_truncation)]
    let gateway_port_u16 = session.gateway_port as u16;
    let (gateway_host, gateway_port) =
        resolve_ssh_gateway(&session.gateway_host, gateway_port_u16, server);

    let gateway_url = format!(
        "{}://{}:{}{}",
        session.gateway_scheme, gateway_host, gateway_port, session.connect_path
    );
    let cluster_name = tls
        .cluster_name()
        .ok_or_else(|| miette::miette!("cluster name is required to build SSH proxy command"))?;
    let proxy_command = format!(
        "{exe_command} ssh-proxy --gateway {} --sandbox-id {} --token {} --cluster {}",
        gateway_url,
        session.sandbox_id,
        session.token,
        shell_escape(cluster_name),
    );

    Ok(SshSessionConfig {
        proxy_command,
        sandbox_id: session.sandbox_id.clone(),
        gateway_url,
        token: session.token,
    })
}

fn ssh_base_command(proxy_command: &str) -> Command {
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
        .arg("LogLevel=ERROR");
    command
}

/// Connect to a sandbox via SSH.
pub async fn sandbox_connect(server: &str, name: &str, tls: &TlsOptions) -> Result<()> {
    let session = ssh_session_config(server, name, tls).await?;

    let mut command = ssh_base_command(&session.proxy_command);
    command
        .arg("-tt")
        .arg("-o")
        .arg("RequestTTY=force")
        .arg("-o")
        .arg("SetEnv=TERM=xterm-256color")
        .arg("sandbox")
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    if std::io::stdin().is_terminal() {
        #[cfg(unix)]
        {
            let err = command.exec();
            return Err(miette::miette!("failed to exec ssh: {err}"));
        }
    }

    let status = tokio::task::spawn_blocking(move || command.status())
        .await
        .into_diagnostic()?
        .into_diagnostic()?;

    if !status.success() {
        return Err(miette::miette!("ssh exited with status {status}"));
    }

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
    port: u16,
    background: bool,
    tls: &TlsOptions,
) -> Result<()> {
    let session = ssh_session_config(server, name, tls).await?;

    let mut command = ssh_base_command(&session.proxy_command);
    command
        .arg("-N")
        .arg("-L")
        .arg(format!("{port}:127.0.0.1:{port}"));

    if background {
        // SSH -f: fork to background after authentication.
        command.arg("-f");
    }

    command
        .arg("sandbox")
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    let status = tokio::task::spawn_blocking(move || command.status())
        .await
        .into_diagnostic()?
        .into_diagnostic()?;

    if !status.success() {
        return Err(miette::miette!("ssh exited with status {status}"));
    }

    if background {
        // SSH has forked — find its PID and record it.
        if let Some(pid) = find_ssh_forward_pid(&session.sandbox_id, port) {
            write_forward_pid(name, port, pid, &session.sandbox_id)?;
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

/// Execute a command in a sandbox via SSH.
pub async fn sandbox_exec(
    server: &str,
    name: &str,
    command: &[String],
    tty: bool,
    tls: &TlsOptions,
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
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    // For interactive TTY sessions, replace this process with SSH via exec()
    // to avoid signal handling issues (e.g. Ctrl+C killing the parent nemoclaw
    // process and orphaning the SSH child).
    if tty && std::io::stdin().is_terminal() {
        #[cfg(unix)]
        {
            let err = ssh.exec();
            return Err(miette::miette!("failed to exec ssh: {err}"));
        }
    }

    let status = tokio::task::spawn_blocking(move || ssh.status())
        .await
        .into_diagnostic()?
        .into_diagnostic()?;

    if !status.success() {
        return Err(miette::miette!("ssh exited with status {status}"));
    }

    Ok(())
}

/// Push a list of files from a local directory into a sandbox using tar-over-SSH.
///
/// This replaces the old rsync-based sync. Files are streamed as a tar archive
/// to `ssh ... tar xf - -C <dest>` on the sandbox side.
pub async fn sandbox_sync_up_files(
    server: &str,
    name: &str,
    base_dir: &Path,
    files: &[String],
    dest: &str,
    tls: &TlsOptions,
) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }

    let session = ssh_session_config(server, name, tls).await?;

    let mut ssh = ssh_base_command(&session.proxy_command);
    ssh.arg("-T")
        .arg("-o")
        .arg("RequestTTY=no")
        .arg("sandbox")
        .arg(format!(
            "mkdir -p {} && cat | tar xf - -C {}",
            shell_escape(dest),
            shell_escape(dest)
        ))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    let mut child = ssh.spawn().into_diagnostic()?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| miette::miette!("failed to open stdin for ssh process"))?;

    // Build the tar archive in a blocking task since the tar crate is synchronous.
    let base_dir = base_dir.to_path_buf();
    let files = files.to_vec();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut archive = tar::Builder::new(stdin);
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
                    .wrap_err_with(|| format!("failed to add directory {file} to tar archive"))?;
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

/// Push a local path (file or directory) into a sandbox using tar-over-SSH.
pub async fn sandbox_sync_up(
    server: &str,
    name: &str,
    local_path: &Path,
    sandbox_path: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let session = ssh_session_config(server, name, tls).await?;

    let mut ssh = ssh_base_command(&session.proxy_command);
    ssh.arg("-T")
        .arg("-o")
        .arg("RequestTTY=no")
        .arg("sandbox")
        .arg(format!(
            "mkdir -p {} && cat | tar xf - -C {}",
            shell_escape(sandbox_path),
            shell_escape(sandbox_path)
        ))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    let mut child = ssh.spawn().into_diagnostic()?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| miette::miette!("failed to open stdin for ssh process"))?;

    let local_path = local_path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut archive = tar::Builder::new(stdin);
        if local_path.is_file() {
            let file_name = local_path
                .file_name()
                .ok_or_else(|| miette::miette!("path has no file name"))?;
            archive
                .append_path_with_name(&local_path, file_name)
                .into_diagnostic()?;
        } else if local_path.is_dir() {
            archive.append_dir_all(".", &local_path).into_diagnostic()?;
        } else {
            return Err(miette::miette!(
                "local path does not exist: {}",
                local_path.display()
            ));
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
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());

    let mut child = ssh.spawn().into_diagnostic()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| miette::miette!("failed to open stdout for ssh process"))?;

    let local_path = local_path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        std::fs::create_dir_all(&local_path)
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

    let mut stream: Box<dyn ProxyStream> =
        connect_gateway(scheme, gateway_host, gateway_port, tls).await?;

    let request = format!(
        "CONNECT {connect_path} HTTP/1.1\r\nHost: {gateway_host}\r\nX-Sandbox-Id: {sandbox_id}\r\nX-Sandbox-Token: {token}\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .into_diagnostic()?;

    let status = read_connect_status(&mut stream).await?;
    if status != 200 {
        return Err(miette::miette!(
            "gateway CONNECT failed with status {status}"
        ));
    }

    let (reader, writer) = tokio::io::split(stream);
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

/// Print an SSH config `Host` block for a sandbox to stdout.
///
/// The output is suitable for appending to `~/.ssh/config` so that tools like
/// `VSCode` Remote-SSH can connect to the sandbox by host alias.
///
/// The `ProxyCommand` uses `--cluster` so that `ssh-proxy` resolves the
/// gateway endpoint and TLS certificates from the cluster metadata directory
/// (`~/.config/nemoclaw/clusters/<name>/mtls/`).
pub fn print_ssh_config(cluster: &str, name: &str) {
    let exe = std::env::current_exe().expect("failed to resolve NemoClaw executable");
    let exe = shell_escape(&exe.to_string_lossy());

    let proxy_cmd = format!("{exe} ssh-proxy --cluster {cluster} --name {name}");

    println!("Host nemoclaw-{name}");
    println!("    User sandbox");
    println!("    StrictHostKeyChecking no");
    println!("    UserKnownHostsFile /dev/null");
    println!("    GlobalKnownHostsFile /dev/null");
    println!("    LogLevel ERROR");
    println!("    ProxyCommand {proxy_cmd}");
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

async fn read_connect_status(stream: &mut dyn ProxyStream) -> Result<u16> {
    let mut buf = Vec::new();
    let mut temp = [0u8; 1024];
    loop {
        let n = stream.read(&mut temp).await.into_diagnostic()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&temp[..n]);
        if buf.windows(4).any(|win| win == b"\r\n\r\n") {
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
