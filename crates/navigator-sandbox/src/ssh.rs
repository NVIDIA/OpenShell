//! Embedded SSH server for sandbox access.

use crate::policy::SandboxPolicy;
use crate::process::drop_privileges;
use crate::sandbox;
#[cfg(target_os = "linux")]
use crate::{register_managed_child, unregister_managed_child};
use miette::{IntoDiagnostic, Result};
use nix::pty::{Winsize, openpty};
use nix::unistd::setsid;
use rand_core::OsRng;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, Handle, Session};
use russh::{ChannelId, CryptoVec};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

const PREFACE_MAGIC: &str = "NSSH1";

#[allow(clippy::too_many_arguments)]
pub async fn run_ssh_server(
    listen_addr: SocketAddr,
    policy: SandboxPolicy,
    workdir: Option<String>,
    handshake_secret: String,
    handshake_skew_secs: u64,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
    ca_file_paths: Option<(PathBuf, PathBuf)>,
    provider_env: HashMap<String, String>,
) -> Result<()> {
    let mut rng = OsRng;
    let host_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).into_diagnostic()?;

    let mut config = russh::server::Config {
        auth_rejection_time: Duration::from_secs(1),
        ..Default::default()
    };
    config.keys.push(host_key);

    let config = Arc::new(config);
    let ca_paths = ca_file_paths.map(Arc::new);
    let listener = TcpListener::bind(listen_addr).await.into_diagnostic()?;
    info!(addr = %listen_addr, "SSH server listening");

    loop {
        let (stream, peer) = listener.accept().await.into_diagnostic()?;
        stream.set_nodelay(true).into_diagnostic()?;
        let config = config.clone();
        let policy = policy.clone();
        let workdir = workdir.clone();
        let secret = handshake_secret.clone();
        let proxy_url = proxy_url.clone();
        let ca_paths = ca_paths.clone();
        let provider_env = provider_env.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_connection(
                stream,
                peer,
                config,
                policy,
                workdir,
                &secret,
                handshake_skew_secs,
                netns_fd,
                proxy_url,
                ca_paths,
                provider_env,
            )
            .await
            {
                warn!(error = %err, "SSH connection failed");
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    config: Arc<russh::server::Config>,
    policy: SandboxPolicy,
    workdir: Option<String>,
    secret: &str,
    handshake_skew_secs: u64,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
    ca_file_paths: Option<Arc<(PathBuf, PathBuf)>>,
    provider_env: HashMap<String, String>,
) -> Result<()> {
    let mut line = String::new();
    read_line(&mut stream, &mut line).await?;
    if !verify_preface(&line, secret, handshake_skew_secs)? {
        let _ = stream.write_all(b"ERR\n").await;
        return Ok(());
    }
    stream.write_all(b"OK\n").await.into_diagnostic()?;
    info!(peer = %peer, "SSH handshake accepted");

    let handler = SshHandler::new(
        policy,
        workdir,
        netns_fd,
        proxy_url,
        ca_file_paths,
        provider_env,
    );
    russh::server::run_stream(config, stream, handler)
        .await
        .map_err(|err| miette::miette!("ssh stream error: {err}"))?;
    Ok(())
}

async fn read_line(stream: &mut tokio::net::TcpStream, buf: &mut String) -> Result<()> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = stream.read(&mut byte).await.into_diagnostic()?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
        if bytes.len() > 1024 {
            break;
        }
    }
    *buf = String::from_utf8_lossy(&bytes).to_string();
    Ok(())
}

fn verify_preface(line: &str, secret: &str, handshake_skew_secs: u64) -> Result<bool> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 5 || parts[0] != PREFACE_MAGIC {
        return Ok(false);
    }
    let token = parts[1];
    let timestamp: i64 = parts[2].parse().unwrap_or(0);
    let nonce = parts[3];
    let signature = parts[4];

    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .into_diagnostic()?
            .as_secs(),
    )
    .into_diagnostic()?;
    let skew = (now - timestamp).unsigned_abs();
    if skew > handshake_skew_secs {
        return Ok(false);
    }

    let payload = format!("{token}|{timestamp}|{nonce}");
    let expected = hmac_sha256(secret.as_bytes(), payload.as_bytes());
    Ok(signature == expected)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

struct SshHandler {
    policy: SandboxPolicy,
    workdir: Option<String>,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
    ca_file_paths: Option<Arc<(PathBuf, PathBuf)>>,
    provider_env: HashMap<String, String>,
    input_sender: Option<mpsc::Sender<Vec<u8>>>,
    pty_master: Option<std::fs::File>,
    pty_request: Option<PtyRequest>,
}

impl SshHandler {
    fn new(
        policy: SandboxPolicy,
        workdir: Option<String>,
        netns_fd: Option<RawFd>,
        proxy_url: Option<String>,
        ca_file_paths: Option<Arc<(PathBuf, PathBuf)>>,
        provider_env: HashMap<String, String>,
    ) -> Self {
        Self {
            policy,
            workdir,
            netns_fd,
            proxy_url,
            ca_file_paths,
            provider_env,
            input_sender: None,
            pty_master: None,
            pty_request: None,
        }
    }
}

impl russh::server::Handler for SshHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Only allow forwarding to loopback destinations to prevent the
        // sandbox SSH server from being used as a generic proxy.
        let is_loopback = host_to_connect == "127.0.0.1"
            || host_to_connect == "localhost"
            || host_to_connect == "::1";
        if !is_loopback {
            warn!(
                host = host_to_connect,
                port = port_to_connect,
                "direct-tcpip rejected: non-loopback destination"
            );
            return Ok(false);
        }

        let host = host_to_connect.to_string();
        #[allow(clippy::cast_possible_truncation)]
        let port = port_to_connect as u16;
        let netns_fd = self.netns_fd;

        tokio::spawn(async move {
            let addr = format!("{host}:{port}");
            let tcp = match connect_in_netns(&addr, netns_fd).await {
                Ok(stream) => stream,
                Err(err) => {
                    warn!(addr = %addr, error = %err, "direct-tcpip: failed to connect");
                    let _ = channel.close().await;
                    return;
                }
            };

            let mut channel_stream = channel.into_stream();
            let mut tcp_stream = tcp;

            let _ = tokio::io::copy_bidirectional(&mut channel_stream, &mut tcp_stream).await;
        });

        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pty_request = Some(PtyRequest {
            term: term.to_string(),
            col_width,
            row_height,
            pixel_width: 0,
            pixel_height: 0,
        });
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pixel_width: u32,
        pixel_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(master) = self.pty_master.as_ref() {
            let winsize = Winsize {
                ws_row: to_u16(row_height.max(1)),
                ws_col: to_u16(col_width.max(1)),
                ws_xpixel: to_u16(pixel_width),
                ws_ypixel: to_u16(pixel_height),
            };
            let _ = unsafe_pty::set_winsize(master.as_raw_fd(), winsize);
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.start_shell(channel, session.handle(), None)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let command = String::from_utf8_lossy(data).trim().to_string();
        if command.is_empty() {
            return Ok(());
        }
        self.start_shell(channel, session.handle(), Some(command))?;
        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(sender) = self.input_sender.as_ref() {
            let _ = sender.send(data.to_vec());
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Drop the input sender so the writer thread exits and the child's
        // stdin pipe is closed.  Without this, commands like `tar xf -` that
        // read until EOF on stdin would hang forever in pipe-based sessions.
        self.input_sender.take();
        Ok(())
    }
}

impl SshHandler {
    fn start_shell(
        &mut self,
        channel: ChannelId,
        handle: Handle,
        command: Option<String>,
    ) -> anyhow::Result<()> {
        if let Some(pty) = self.pty_request.take() {
            let (pty_master, input_sender) = spawn_pty_shell(
                &self.policy,
                self.workdir.clone(),
                command,
                &pty,
                handle,
                channel,
                self.netns_fd,
                self.proxy_url.clone(),
                self.ca_file_paths.clone(),
                &self.provider_env,
            )?;
            self.pty_master = Some(pty_master);
            self.input_sender = Some(input_sender);
        } else {
            let input_sender = spawn_pipe_shell(
                &self.policy,
                self.workdir.clone(),
                command,
                handle,
                channel,
                self.netns_fd,
                self.proxy_url.clone(),
                self.ca_file_paths.clone(),
                &self.provider_env,
            )?;
            self.input_sender = Some(input_sender);
        }
        Ok(())
    }
}

/// Connect a TCP stream to `addr` inside the sandbox network namespace.
///
/// The SSH supervisor runs in the host network namespace while sandbox child
/// processes run in an isolated network namespace (with their own loopback).
/// A plain `TcpStream::connect("127.0.0.1:port")` from the supervisor would
/// hit the host loopback, not the sandbox loopback where services are listening.
///
/// On Linux, we spawn a dedicated OS thread, call `setns` to enter the sandbox
/// namespace, create the socket there, then convert it to a tokio `TcpStream`.
/// We use `std::thread::spawn` (not `spawn_blocking`) because `setns` changes
/// the calling thread's network namespace permanently — a tokio blocking-pool
/// thread could be reused for unrelated tasks and must not be contaminated.
/// On non-Linux platforms (no network namespace support), we connect directly.
async fn connect_in_netns(
    addr: &str,
    netns_fd: Option<RawFd>,
) -> std::io::Result<tokio::net::TcpStream> {
    #[cfg(target_os = "linux")]
    if let Some(fd) = netns_fd {
        let addr = addr.to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let result = (|| -> std::io::Result<std::net::TcpStream> {
                // Enter the sandbox network namespace on this dedicated thread.
                // SAFETY: setns is safe to call; this is a dedicated thread that
                // will exit after the connection is established.
                #[allow(unsafe_code)]
                let rc = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                std::net::TcpStream::connect(&addr)
            })();
            let _ = tx.send(result);
        });

        let std_stream = rx
            .await
            .map_err(|_| std::io::Error::other("netns connect thread panicked"))??;
        std_stream.set_nonblocking(true)?;
        return tokio::net::TcpStream::from_std(std_stream);
    }

    #[cfg(not(target_os = "linux"))]
    let _ = netns_fd;

    tokio::net::TcpStream::connect(addr).await
}

#[derive(Clone)]
struct PtyRequest {
    term: String,
    col_width: u32,
    row_height: u32,
    pixel_width: u32,
    pixel_height: u32,
}

impl Default for PtyRequest {
    fn default() -> Self {
        Self {
            term: "xterm-256color".to_string(),
            col_width: 80,
            row_height: 24,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_pty_shell(
    policy: &SandboxPolicy,
    workdir: Option<String>,
    command: Option<String>,
    pty: &PtyRequest,
    handle: Handle,
    channel: ChannelId,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
    ca_file_paths: Option<Arc<(PathBuf, PathBuf)>>,
    provider_env: &HashMap<String, String>,
) -> anyhow::Result<(std::fs::File, mpsc::Sender<Vec<u8>>)> {
    let winsize = Winsize {
        ws_row: to_u16(pty.row_height.max(1)),
        ws_col: to_u16(pty.col_width.max(1)),
        ws_xpixel: to_u16(pty.pixel_width),
        ws_ypixel: to_u16(pty.pixel_height),
    };
    let openpty = openpty(Some(&winsize), None)?;
    let master = std::fs::File::from(openpty.master);
    let slave = std::fs::File::from(openpty.slave);
    let slave_fd = slave.as_raw_fd();

    let stdin = slave.try_clone()?;
    let stdout = slave.try_clone()?;
    let stderr = slave;
    let mut reader = master.try_clone()?;
    let mut writer = master.try_clone()?;

    let mut cmd = command.map_or_else(
        || {
            let mut c = Command::new("/bin/bash");
            c.arg("-i");
            c
        },
        |command| {
            let mut c = Command::new("/bin/bash");
            c.arg("-lc").arg(command);
            c
        },
    );

    let term = if pty.term.is_empty() {
        "xterm-256color"
    } else {
        pty.term.as_str()
    };

    cmd.stdin(stdin)
        .stdout(stdout)
        .stderr(stderr)
        .env("NAVIGATOR_SANDBOX", "1")
        .env("HOME", "/sandbox")
        .env("USER", "sandbox")
        .env("TERM", term);

    // Set proxy environment variables so cooperative tools (curl, wget, etc.)
    // route traffic through the CONNECT proxy for OPA policy evaluation.
    // Both uppercase and lowercase variants are needed: curl/wget use uppercase,
    // gRPC C-core (libgrpc) checks lowercase http_proxy/https_proxy first.
    if let Some(ref url) = proxy_url {
        cmd.env("HTTP_PROXY", url)
            .env("HTTPS_PROXY", url)
            .env("ALL_PROXY", url)
            .env("http_proxy", url)
            .env("https_proxy", url)
            .env("grpc_proxy", url);
    }

    // Set TLS trust store env vars so SSH shell processes trust the ephemeral CA
    if let Some(ref paths) = ca_file_paths {
        let (ca_cert_path, combined_bundle_path) = paths.as_ref();
        cmd.env("NODE_EXTRA_CA_CERTS", ca_cert_path)
            .env("SSL_CERT_FILE", combined_bundle_path)
            .env("REQUESTS_CA_BUNDLE", combined_bundle_path)
            .env("CURL_CA_BUNDLE", combined_bundle_path);
    }

    // Set provider environment variables (credentials fetched at runtime).
    for (key, value) in provider_env {
        cmd.env(key, value);
    }

    if let Some(dir) = workdir.as_deref() {
        cmd.current_dir(dir);
    }

    #[cfg(unix)]
    {
        unsafe_pty::install_pre_exec(
            &mut cmd,
            policy.clone(),
            workdir.clone(),
            slave_fd,
            netns_fd,
        );
    }

    let mut child = cmd.spawn()?;
    #[cfg(target_os = "linux")]
    let child_pid = child.id();
    #[cfg(target_os = "linux")]
    register_managed_child(child_pid);
    let master_file = master;

    let (sender, receiver) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        while let Ok(bytes) = receiver.recv() {
            if writer.write_all(&bytes).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });

    let runtime = tokio::runtime::Handle::current();
    let runtime_reader = runtime.clone();
    let handle_clone = handle.clone();
    // Signal from the reader thread to the exit thread that all output has
    // been forwarded.  The exit thread waits for this before sending the
    // exit-status and closing the channel, ensuring the correct SSH protocol
    // ordering: data → EOF → exit-status → close.
    let (reader_done_tx, reader_done_rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = CryptoVec::from_slice(&buf[..n]);
                    let handle_clone = handle_clone.clone();
                    drop(runtime_reader.spawn(async move {
                        let _ = handle_clone.data(channel, data).await;
                    }));
                }
            }
        }
        // Send EOF to indicate no more data will be sent on this channel.
        let eof_handle = handle_clone.clone();
        drop(runtime_reader.spawn(async move {
            let _ = eof_handle.eof(channel).await;
        }));
        // Notify the exit thread that all output has been forwarded.
        let _ = reader_done_tx.send(());
    });

    let handle_exit = handle;
    let runtime_exit = runtime;
    std::thread::spawn(move || {
        let status = child.wait().ok();
        #[cfg(target_os = "linux")]
        unregister_managed_child(child_pid);
        let code = status.and_then(|s| s.code()).unwrap_or(1).unsigned_abs();
        // Wait for the reader thread to finish forwarding all output before
        // sending exit-status and closing the channel.  This prevents the
        // race where close() was called before exit_status_request().
        //
        // Use a timeout because a backgrounded grandchild process (e.g.
        // `nohup daemon &`) may hold the PTY slave open indefinitely,
        // preventing the reader from reaching EOF.  Two seconds is enough
        // for any remaining buffered data to drain.
        let _ = reader_done_rx.recv_timeout(Duration::from_secs(2));
        drop(runtime_exit.spawn(async move {
            let _ = handle_exit.exit_status_request(channel, code).await;
            let _ = handle_exit.close(channel).await;
        }));
    });

    Ok((master_file, sender))
}

/// Spawn a shell process with plain pipes (no PTY) for non-interactive sessions.
///
/// This is used when the SSH client did not request a PTY (e.g. `ssh -T`).
/// Unlike [`spawn_pty_shell`], stdout and stderr are separate streams and no
/// terminal output processing (LF→CRLF) is applied, making this safe for
/// binary data transfer (e.g. tar archives).
#[allow(clippy::too_many_arguments)]
fn spawn_pipe_shell(
    policy: &SandboxPolicy,
    workdir: Option<String>,
    command: Option<String>,
    handle: Handle,
    channel: ChannelId,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
    ca_file_paths: Option<Arc<(PathBuf, PathBuf)>>,
    provider_env: &HashMap<String, String>,
) -> anyhow::Result<mpsc::Sender<Vec<u8>>> {
    let mut cmd = command.map_or_else(
        || {
            let mut c = Command::new("/bin/bash");
            c.arg("-i");
            c
        },
        |command| {
            let mut c = Command::new("/bin/bash");
            c.arg("-lc").arg(command);
            c
        },
    );

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("NAVIGATOR_SANDBOX", "1")
        .env("HOME", "/sandbox")
        .env("USER", "sandbox")
        .env("TERM", "dumb");

    if let Some(ref url) = proxy_url {
        cmd.env("HTTP_PROXY", url)
            .env("HTTPS_PROXY", url)
            .env("ALL_PROXY", url)
            .env("http_proxy", url)
            .env("https_proxy", url)
            .env("grpc_proxy", url);
    }

    if let Some(ref paths) = ca_file_paths {
        let (ca_cert_path, combined_bundle_path) = paths.as_ref();
        cmd.env("NODE_EXTRA_CA_CERTS", ca_cert_path)
            .env("SSL_CERT_FILE", combined_bundle_path)
            .env("REQUESTS_CA_BUNDLE", combined_bundle_path)
            .env("CURL_CA_BUNDLE", combined_bundle_path);
    }

    for (key, value) in provider_env {
        cmd.env(key, value);
    }

    if let Some(dir) = workdir.as_deref() {
        cmd.current_dir(dir);
    }

    #[cfg(unix)]
    {
        unsafe_pipe::install_pre_exec(&mut cmd, policy.clone(), workdir.clone(), netns_fd);
    }

    let mut child = cmd.spawn()?;
    #[cfg(target_os = "linux")]
    let child_pid = child.id();
    #[cfg(target_os = "linux")]
    register_managed_child(child_pid);

    let child_stdin = child.stdin.take().expect("stdin was piped");
    let child_stdout = child.stdout.take().expect("stdout was piped");
    let child_stderr = child.stderr.take().expect("stderr was piped");

    // Writer thread: forwards SSH channel data to the child's stdin.
    let (sender, receiver) = mpsc::channel::<Vec<u8>>();
    let mut writer = child_stdin;
    std::thread::spawn(move || {
        while let Ok(bytes) = receiver.recv() {
            if writer.write_all(&bytes).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });

    let runtime = tokio::runtime::Handle::current();

    // We need both stdout and stderr readers to finish before sending EOF.
    // Use an Arc<AtomicUsize> to count completions.
    let readers_remaining = Arc::new(std::sync::atomic::AtomicUsize::new(2));
    let (reader_done_tx, reader_done_rx) = mpsc::channel::<()>();

    // Stdout reader thread: forwards child stdout to the SSH channel.
    let handle_stdout = handle.clone();
    let runtime_stdout = runtime.clone();
    let readers_remaining_stdout = readers_remaining.clone();
    let reader_done_tx_stdout = reader_done_tx.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut reader = child_stdout;
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = CryptoVec::from_slice(&buf[..n]);
                    let h = handle_stdout.clone();
                    drop(runtime_stdout.spawn(async move {
                        let _ = h.data(channel, data).await;
                    }));
                }
            }
        }
        if readers_remaining_stdout.fetch_sub(1, std::sync::atomic::Ordering::AcqRel) == 1 {
            let eof_handle = handle_stdout.clone();
            drop(runtime_stdout.spawn(async move {
                let _ = eof_handle.eof(channel).await;
            }));
            let _ = reader_done_tx_stdout.send(());
        }
    });

    // Stderr reader thread: forwards child stderr to the SSH channel as
    // extended data (type 1 = stderr).
    let handle_stderr = handle.clone();
    let runtime_stderr = runtime.clone();
    let readers_remaining_stderr = readers_remaining;
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut reader = child_stderr;
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = CryptoVec::from_slice(&buf[..n]);
                    let h = handle_stderr.clone();
                    drop(runtime_stderr.spawn(async move {
                        let _ = h.extended_data(channel, 1, data).await;
                    }));
                }
            }
        }
        if readers_remaining_stderr.fetch_sub(1, std::sync::atomic::Ordering::AcqRel) == 1 {
            let eof_handle = handle_stderr.clone();
            drop(runtime_stderr.spawn(async move {
                let _ = eof_handle.eof(channel).await;
            }));
            let _ = reader_done_tx.send(());
        }
    });

    // Exit thread: waits for process exit, then sends exit-status and close.
    let handle_exit = handle;
    let runtime_exit = runtime;
    std::thread::spawn(move || {
        let status = child.wait().ok();
        #[cfg(target_os = "linux")]
        unregister_managed_child(child_pid);
        let code = status.and_then(|s| s.code()).unwrap_or(1).unsigned_abs();
        // Wait for reader threads to finish forwarding output before sending
        // exit-status and close.
        let _ = reader_done_rx.recv_timeout(Duration::from_secs(2));
        drop(runtime_exit.spawn(async move {
            let _ = handle_exit.exit_status_request(channel, code).await;
            let _ = handle_exit.close(channel).await;
        }));
    });

    Ok(sender)
}

mod unsafe_pipe {
    use super::{Command, RawFd, SandboxPolicy, drop_privileges, sandbox};
    #[cfg(unix)]
    use std::os::unix::process::CommandExt;

    #[allow(unsafe_code)]
    pub fn install_pre_exec(
        cmd: &mut Command,
        policy: SandboxPolicy,
        workdir: Option<String>,
        netns_fd: Option<RawFd>,
    ) {
        unsafe {
            cmd.pre_exec(move || {
                // Enter network namespace before dropping privileges.
                #[cfg(target_os = "linux")]
                if let Some(fd) = netns_fd {
                    let result = libc::setns(fd, libc::CLONE_NEWNET);
                    if result != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }

                #[cfg(not(target_os = "linux"))]
                let _ = netns_fd;

                drop_privileges(&policy).map_err(|err| std::io::Error::other(err.to_string()))?;
                sandbox::apply(&policy, workdir.as_deref())
                    .map_err(|err| std::io::Error::other(err.to_string()))?;
                Ok(())
            });
        }
    }
}

mod unsafe_pty {
    use super::{Command, RawFd, SandboxPolicy, Winsize, drop_privileges, sandbox, setsid};
    #[cfg(unix)]
    use std::os::unix::process::CommandExt;

    #[allow(unsafe_code)]
    pub fn set_winsize(fd: RawFd, winsize: Winsize) -> std::io::Result<()> {
        let rc = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, winsize) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn set_controlling_tty(fd: RawFd) -> std::io::Result<()> {
        let rc = unsafe { libc::ioctl(fd, libc::TIOCSCTTY.into(), 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    pub fn install_pre_exec(
        cmd: &mut Command,
        policy: SandboxPolicy,
        workdir: Option<String>,
        slave_fd: RawFd,
        netns_fd: Option<RawFd>,
    ) {
        unsafe {
            cmd.pre_exec(move || {
                setsid().map_err(|err| std::io::Error::other(err.to_string()))?;
                set_controlling_tty(slave_fd)?;

                // Enter network namespace before dropping privileges.
                // This ensures SSH shell processes are isolated to the same
                // network namespace as the entrypoint, forcing all traffic
                // through the veth pair and CONNECT proxy.
                #[cfg(target_os = "linux")]
                if let Some(fd) = netns_fd {
                    let result = libc::setns(fd, libc::CLONE_NEWNET);
                    if result != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }

                #[cfg(not(target_os = "linux"))]
                let _ = netns_fd;

                // Drop privileges before applying sandbox restrictions.
                // initgroups/setgid/setuid need access to /etc/group and /etc/passwd
                // which may be blocked by Landlock.
                drop_privileges(&policy).map_err(|err| std::io::Error::other(err.to_string()))?;
                sandbox::apply(&policy, workdir.as_deref())
                    .map_err(|err| std::io::Error::other(err.to_string()))?;
                Ok(())
            });
        }
    }
}

fn to_u16(value: u32) -> u16 {
    u16::try_from(value.min(u32::from(u16::MAX))).unwrap_or(u16::MAX)
}
