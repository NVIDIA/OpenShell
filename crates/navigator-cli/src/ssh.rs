//! SSH connection and proxy utilities.

use crate::tls::{TlsOptions, build_rustls_config, grpc_client, require_tls_materials};
use miette::{IntoDiagnostic, Result, WrapErr};
use navigator_core::proto::{CreateSshSessionRequest, GetSandboxRequest};
use owo_colors::OwoColorize;
use rustls::pki_types::ServerName;
use std::io::IsTerminal;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

struct SshSessionConfig {
    proxy_command: String,
    sandbox_id: String,
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
        .wrap_err("failed to resolve navigator executable")?;
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
    let proxy_command = format!(
        "{exe_command} ssh-proxy --gateway {} --sandbox-id {} --token {}",
        gateway_url, session.sandbox_id, session.token,
    );

    Ok(SshSessionConfig {
        proxy_command,
        sandbox_id: session.sandbox_id,
    })
}

/// If the server-provided gateway host is a loopback address, use the host
/// from the cluster endpoint instead so the CLI connects to the right machine.
fn resolve_ssh_gateway(gateway_host: &str, gateway_port: u16, cluster_url: &str) -> (String, u16) {
    let is_loopback = gateway_host == "127.0.0.1"
        || gateway_host == "0.0.0.0"
        || gateway_host == "localhost"
        || gateway_host == "::1";

    if !is_loopback {
        return (gateway_host.to_string(), gateway_port);
    }

    // Try to extract the host from the cluster URL
    if let Ok(url) = url::Url::parse(cluster_url)
        && let Some(host) = url.host_str()
    {
        // Only override if the cluster endpoint is not also a loopback address
        let cluster_is_loopback =
            host == "127.0.0.1" || host == "0.0.0.0" || host == "localhost" || host == "::1";
        if !cluster_is_loopback {
            return (host.to_string(), gateway_port);
        }
    }

    (gateway_host.to_string(), gateway_port)
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

// ---------------------------------------------------------------------------
// Forward PID file management
// ---------------------------------------------------------------------------

/// Base directory for forward PID files.
fn forward_pid_dir() -> Result<PathBuf> {
    let base = if let Ok(path) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(path)
    } else {
        let home = std::env::var("HOME")
            .into_diagnostic()
            .wrap_err("HOME is not set")?;
        PathBuf::from(home).join(".config")
    };
    Ok(base.join("navigator").join("forwards"))
}

/// PID file path for a specific sandbox + port forward.
fn forward_pid_path(name: &str, port: u16) -> Result<PathBuf> {
    Ok(forward_pid_dir()?.join(format!("{name}-{port}.pid")))
}

/// Write a PID file for a background forward.
fn write_forward_pid(name: &str, port: u16, pid: u32, sandbox_id: &str) -> Result<()> {
    let dir = forward_pid_dir()?;
    std::fs::create_dir_all(&dir)
        .into_diagnostic()
        .wrap_err("failed to create forwards directory")?;
    let path = forward_pid_path(name, port)?;
    std::fs::write(&path, format!("{pid}\t{sandbox_id}"))
        .into_diagnostic()
        .wrap_err("failed to write forward PID file")?;
    Ok(())
}

/// Find the PID of a backgrounded SSH forward by searching for the matching
/// SSH process.  Falls back to `pgrep` since SSH `-f` forks a new process
/// whose PID we cannot capture directly.
fn find_ssh_forward_pid(sandbox_id: &str, port: u16) -> Option<u32> {
    // Match the ProxyCommand argument which contains the sandbox ID, plus
    // the -L port forwarding spec. The ProxyCommand (with --sandbox-id)
    // appears before -L in the SSH command line.
    let pattern = format!("ssh.*sandbox-id.*{sandbox_id}.*-L.*{port}:127.0.0.1:{port}");
    let output = Command::new("pgrep")
        .arg("-f")
        .arg(&pattern)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // pgrep may return multiple PIDs (e.g., parent + child). Take the last
    // one, which is typically the backgrounded SSH process.
    stdout
        .lines()
        .rev()
        .find_map(|l| l.trim().parse::<u32>().ok())
}

/// Read the PID from a forward PID file.  Returns `None` if the file does not
/// exist or cannot be parsed.
struct ForwardPidRecord {
    pid: u32,
    sandbox_id: Option<String>,
}

fn read_forward_pid(name: &str, port: u16) -> Option<ForwardPidRecord> {
    let path = forward_pid_path(name, port).ok()?;
    let contents = std::fs::read_to_string(path).ok()?;
    let mut parts = contents.split_whitespace();
    let pid = parts.next()?.parse().ok()?;
    let sandbox_id = parts.next().map(str::to_string);
    Some(ForwardPidRecord { pid, sandbox_id })
}

/// Check whether a process is alive.
fn pid_is_alive(pid: u32) -> bool {
    // `kill -0 <pid>` checks if we can signal the process without actually
    // sending a signal.
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn pid_matches_forward(pid: u32, port: u16, sandbox_id: Option<&str>) -> bool {
    let output = match Command::new("ps")
        .arg("-ww")
        .arg("-o")
        .arg("command=")
        .arg("-p")
        .arg(pid.to_string())
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return false,
    };

    let cmd = String::from_utf8_lossy(&output.stdout);
    let forward_spec = format!("{port}:127.0.0.1:{port}");
    if !cmd.contains("ssh") || !cmd.contains("ssh-proxy") || !cmd.contains(&forward_spec) {
        return false;
    }

    sandbox_id.is_none_or(|id| cmd.contains(id))
}

/// Stop a background port forward.
pub fn stop_forward(name: &str, port: u16) -> Result<bool> {
    let pid_path = forward_pid_path(name, port)?;
    let Some(record) = read_forward_pid(name, port) else {
        return Ok(false);
    };
    let pid = record.pid;

    if pid_is_alive(pid) {
        if !pid_matches_forward(pid, port, record.sandbox_id.as_deref()) {
            let _ = std::fs::remove_file(&pid_path);
            return Ok(false);
        }
        let _ = Command::new("kill")
            .arg(pid.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        // Give the process a moment to exit.
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    let _ = std::fs::remove_file(&pid_path);
    Ok(true)
}

/// Stop all forwards for a given sandbox name.
pub fn stop_forwards_for_sandbox(name: &str) -> Result<Vec<u16>> {
    let Ok(dir) = forward_pid_dir() else {
        return Ok(Vec::new());
    };
    let prefix = format!("{name}-");
    let mut stopped = Vec::new();

    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if let Some(rest) = file_name.strip_prefix(&prefix)
            && let Some(port_str) = rest.strip_suffix(".pid")
            && let Ok(port) = port_str.parse::<u16>()
            && stop_forward(name, port)?
        {
            stopped.push(port);
        }
    }

    Ok(stopped)
}

/// Information about a tracked forward.
pub struct ForwardInfo {
    pub sandbox: String,
    pub port: u16,
    pub pid: u32,
    pub alive: bool,
}

/// List all tracked forwards.
pub fn list_forwards() -> Result<Vec<ForwardInfo>> {
    let Ok(dir) = forward_pid_dir() else {
        return Ok(Vec::new());
    };

    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };

    let mut forwards = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy().to_string();
        if let Some(stem) = file_name.strip_suffix(".pid")
            // Parse "<sandbox>-<port>" — the port is the last segment after '-'.
            && let Some(dash_pos) = stem.rfind('-')
            && let Ok(port) = stem[dash_pos + 1..].parse::<u16>()
            && let Some(record) = read_forward_pid(&stem[..dash_pos], port)
        {
            forwards.push(ForwardInfo {
                sandbox: stem[..dash_pos].to_string(),
                port,
                pid: record.pid,
                alive: pid_is_alive(record.pid),
            });
        }
    }

    forwards.sort_by(|a, b| a.sandbox.cmp(&b.sandbox).then(a.port.cmp(&b.port)));
    Ok(forwards)
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

fn shell_escape(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    let safe = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'-' | b'_'));
    if safe {
        return value.to_string();
    }

    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_ssh_gateway_keeps_non_loopback() {
        let (host, port) = resolve_ssh_gateway("10.0.0.5", 8080, "https://spark.local");
        assert_eq!(host, "10.0.0.5");
        assert_eq!(port, 8080);
    }

    #[test]
    fn resolve_ssh_gateway_overrides_loopback_with_cluster_host() {
        let (host, port) = resolve_ssh_gateway("127.0.0.1", 8080, "https://spark.local");
        assert_eq!(host, "spark.local");
        assert_eq!(port, 8080);
    }

    #[test]
    fn resolve_ssh_gateway_overrides_zeros_with_cluster_host() {
        let (host, port) = resolve_ssh_gateway("0.0.0.0", 8080, "https://10.0.0.5:443");
        assert_eq!(host, "10.0.0.5");
        assert_eq!(port, 8080);
    }

    #[test]
    fn resolve_ssh_gateway_overrides_localhost() {
        let (host, port) = resolve_ssh_gateway("localhost", 8080, "https://remote-host:443");
        assert_eq!(host, "remote-host");
        assert_eq!(port, 8080);
    }

    #[test]
    fn resolve_ssh_gateway_no_override_when_cluster_is_also_loopback() {
        let (host, port) = resolve_ssh_gateway("127.0.0.1", 8080, "https://127.0.0.1:443");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn resolve_ssh_gateway_handles_invalid_cluster_url() {
        let (host, port) = resolve_ssh_gateway("127.0.0.1", 8080, "not-a-url");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);
    }
}
