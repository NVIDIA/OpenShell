//! SSH connection and proxy utilities.

use crate::tls::{TlsOptions, build_rustls_config, grpc_client, require_tls_materials};
use miette::{IntoDiagnostic, Result, WrapErr};
use navigator_core::proto::CreateSshSessionRequest;
use rustls::pki_types::ServerName;
use std::io::{IsTerminal, Write};
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
}

async fn ssh_session_config(server: &str, id: &str, tls: &TlsOptions) -> Result<SshSessionConfig> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .create_ssh_session(CreateSshSessionRequest {
            sandbox_id: id.to_string(),
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

    Ok(SshSessionConfig { proxy_command })
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
        .arg("GlobalKnownHostsFile=/dev/null");
    command
}

/// Connect to a sandbox via SSH.
pub async fn sandbox_connect(server: &str, id: &str, tls: &TlsOptions) -> Result<()> {
    let session = ssh_session_config(server, id, tls).await?;

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

/// Execute a command in a sandbox via SSH.
pub async fn sandbox_exec(
    server: &str,
    id: &str,
    command: &[String],
    tty: bool,
    tls: &TlsOptions,
) -> Result<()> {
    if command.is_empty() {
        return Err(miette::miette!("no command provided"));
    }

    let session = ssh_session_config(server, id, tls).await?;
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

/// Sync local files into the sandbox using rsync over SSH.
pub async fn sandbox_rsync(
    server: &str,
    id: &str,
    repo_root: &Path,
    files: &[String],
    tls: &TlsOptions,
) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }

    let session = ssh_session_config(server, id, tls).await?;

    let ssh_command = format!(
        "ssh -o {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null",
        shell_escape(&format!("ProxyCommand={}", session.proxy_command))
    );

    let mut rsync = Command::new("rsync");
    rsync
        .arg("-az")
        .arg("--from0")
        .arg("--files-from=-")
        .arg("--relative")
        .arg("-e")
        .arg(ssh_command)
        .arg(".")
        .arg("sandbox:/sandbox")
        .current_dir(repo_root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    let mut child = rsync.spawn().into_diagnostic()?;
    if let Some(mut stdin) = child.stdin.take() {
        for path in files {
            let entry = format!("./{path}");
            stdin.write_all(entry.as_bytes()).into_diagnostic()?;
            stdin.write_all(&[0]).into_diagnostic()?;
        }
    }

    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .into_diagnostic()?
        .into_diagnostic()?;

    if !status.success() {
        return Err(miette::miette!("rsync exited with status {status}"));
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
