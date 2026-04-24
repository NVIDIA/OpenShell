// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Embedded SSH server for sandbox access.

use crate::child_env;
use crate::policy::SandboxPolicy;
use crate::process::drop_privileges;
use crate::sandbox;
#[cfg(target_os = "linux")]
use crate::{register_managed_child, unregister_managed_child};
use miette::{IntoDiagnostic, Result};
use nix::pty::{Winsize, openpty};
use nix::unistd::setsid;
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, SeverityId, SshActivityBuilder, StatusId, ocsf_emit,
};
use rand_core::OsRng;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, Handle, Session};
use russh::{ChannelId, CryptoVec};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, mpsc};
use std::time::Duration;
use tokio::net::UnixListener;
use tracing::warn;

/// Perform SSH server initialization: generate a host key, build the config,
/// and bind the Unix socket listener. Extracted so that startup errors can be
/// forwarded through the readiness channel rather than being silently logged.
async fn ssh_server_init(
    listen_path: &Path,
    ca_file_paths: &Option<(PathBuf, PathBuf)>,
) -> Result<(
    UnixListener,
    Arc<russh::server::Config>,
    Option<Arc<(PathBuf, PathBuf)>>,
)> {
    let mut rng = OsRng;
    let host_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).into_diagnostic()?;

    let mut config = russh::server::Config {
        auth_rejection_time: Duration::from_secs(1),
        ..Default::default()
    };
    config.keys.push(host_key);

    let config = Arc::new(config);
    let ca_paths = ca_file_paths.as_ref().map(|p| Arc::new(p.clone()));

    // Ensure the parent directory exists and is root-owned with 0700
    // permissions. The sandbox entrypoint runs as an unprivileged user; it
    // must not be able to enter this directory and connect to the socket.
    if let Some(parent) = listen_path.parent() {
        std::fs::create_dir_all(parent).into_diagnostic()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(parent, perms).into_diagnostic()?;
        }
    }

    // Remove any stale socket from a previous run before binding.
    if listen_path.exists() {
        std::fs::remove_file(listen_path).into_diagnostic()?;
    }
    let listener = UnixListener::bind(listen_path).into_diagnostic()?;

    // Tighten permissions so only the supervisor (root) can connect. The
    // sandbox entrypoint runs as an unprivileged user and must not be able to
    // dial the SSH daemon directly — all access goes through the relay from
    // the gateway.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(listen_path, perms).into_diagnostic()?;
    }

    ocsf_emit!(
        SshActivityBuilder::new(crate::ocsf_ctx())
            .activity(ActivityId::Listen)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .message(format!("SSH server listening on {}", listen_path.display()))
            .build()
    );

    Ok((listener, config, ca_paths))
}

#[allow(clippy::too_many_arguments)]
pub async fn run_ssh_server(
    listen_path: PathBuf,
    ready_tx: tokio::sync::oneshot::Sender<Result<()>>,
    policy: SandboxPolicy,
    workdir: Option<String>,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
    ca_file_paths: Option<(PathBuf, PathBuf)>,
    provider_env: HashMap<String, String>,
) -> Result<()> {
    let (listener, config, ca_paths) = match ssh_server_init(&listen_path, &ca_file_paths).await {
        Ok(v) => {
            // Signal that the SSH server has bound the socket and is ready to
            // accept connections. The parent task awaits this before spawning
            // the entrypoint process, ensuring exec requests won't race
            // against server startup.
            let _ = ready_tx.send(Ok(()));
            v
        }
        Err(err) => {
            let _ = ready_tx.send(Err(err));
            return Ok(());
        }
    };

    loop {
        let (stream, _peer) = listener.accept().await.into_diagnostic()?;
        let config = config.clone();
        let policy = policy.clone();
        let workdir = workdir.clone();
        let proxy_url = proxy_url.clone();
        let ca_paths = ca_paths.clone();
        let provider_env = provider_env.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_connection(
                stream,
                config,
                policy,
                workdir,
                netns_fd,
                proxy_url,
                ca_paths,
                provider_env,
            )
            .await
            {
                ocsf_emit!(
                    SshActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Fail)
                        .severity(SeverityId::Low)
                        .status(StatusId::Failure)
                        .message(format!("SSH connection failed: {err}"))
                        .build()
                );
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: tokio::net::UnixStream,
    config: Arc<russh::server::Config>,
    policy: SandboxPolicy,
    workdir: Option<String>,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
    ca_file_paths: Option<Arc<(PathBuf, PathBuf)>>,
    provider_env: HashMap<String, String>,
) -> Result<()> {
    // Access is gated by the Unix-socket filesystem permissions (root-only),
    // not by an application-level preface. The supervisor bridges the
    // gateway's RelayStream directly into this socket.
    ocsf_emit!(
        SshActivityBuilder::new(crate::ocsf_ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .message("SSH connection accepted on supervisor Unix socket")
            .build()
    );

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

/// Per-channel state for tracking PTY resources and I/O senders.
///
/// Each SSH channel gets its own PTY master (if a PTY was requested) and input
/// sender.  This allows `window_change_request` to resize the correct PTY when
/// multiple channels are open simultaneously (e.g. parallel shells, shell +
/// sftp, etc.).
#[derive(Default)]
struct ChannelState {
    input_sender: Option<mpsc::Sender<Vec<u8>>>,
    pty_master: Option<std::fs::File>,
    pty_request: Option<PtyRequest>,
}

struct SshHandler {
    policy: SandboxPolicy,
    workdir: Option<String>,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
    ca_file_paths: Option<Arc<(PathBuf, PathBuf)>>,
    provider_env: HashMap<String, String>,
    channels: HashMap<ChannelId, ChannelState>,
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
            channels: HashMap::new(),
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
        channel: russh::Channel<russh::server::Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.channels.insert(channel.id(), ChannelState::default());
        Ok(true)
    }

    /// Clean up per-channel state when the channel is closed.
    ///
    /// This is the final cleanup and subsumes `channel_eof` — if `channel_close`
    /// fires without a preceding `channel_eof`, all resources (pty_master File,
    /// input_sender) are dropped here.
    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
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
        // Validate port range before truncating u32 -> u16.  The SSH protocol
        // uses u32 for ports, but valid TCP ports are 0-65535.  Without this
        // check, port 65537 truncates to port 1 (privileged).
        if port_to_connect > u32::from(u16::MAX) {
            ocsf_emit!(SshActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Refuse)
                .action(ActionId::Denied)
                .disposition(DispositionId::Blocked)
                .severity(SeverityId::Medium)
                .message(format!(
                    "direct-tcpip rejected: port {port_to_connect} exceeds valid TCP range for host {host_to_connect}"
                ))
                .build());
            return Ok(false);
        }

        // Only allow forwarding to loopback destinations to prevent the
        // sandbox SSH server from being used as a generic proxy.
        if !is_loopback_host(host_to_connect) {
            ocsf_emit!(SshActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Refuse)
                .action(ActionId::Denied)
                .disposition(DispositionId::Blocked)
                .severity(SeverityId::Medium)
                .message(format!(
                    "direct-tcpip rejected: non-loopback destination {host_to_connect}:{port_to_connect}"
                ))
                .build());
            return Ok(false);
        }

        let host = host_to_connect.to_string();
        let port = port_to_connect as u16;
        let netns_fd = self.netns_fd;

        tokio::spawn(async move {
            let addr = format!("{host}:{port}");
            let tcp = match connect_in_netns(&addr, netns_fd).await {
                Ok(stream) => stream,
                Err(err) => {
                    ocsf_emit!(
                        SshActivityBuilder::new(crate::ocsf_ctx())
                            .activity(ActivityId::Fail)
                            .severity(SeverityId::Low)
                            .status(StatusId::Failure)
                            .message(format!("direct-tcpip: failed to connect to {addr}: {err}"))
                            .build()
                    );
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
        let state = self
            .channels
            .get_mut(&channel)
            .ok_or_else(|| anyhow::anyhow!("pty_request on unknown channel {channel:?}"))?;
        state.pty_request = Some(PtyRequest {
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
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pixel_width: u32,
        pixel_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(state) = self.channels.get(&channel) else {
            warn!("window_change_request on unknown channel {channel:?}");
            return Ok(());
        };
        if let Some(master) = state.pty_master.as_ref() {
            let winsize = Winsize {
                ws_row: to_u16(row_height.max(1)),
                ws_col: to_u16(col_width.max(1)),
                ws_xpixel: to_u16(pixel_width),
                ws_ypixel: to_u16(pixel_height),
            };
            if let Err(e) = unsafe_pty::set_winsize(master.as_raw_fd(), winsize) {
                warn!("failed to resize PTY for channel {channel:?}: {e}");
            }
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        // Only allocate a PTY when the client explicitly requested one via
        // pty_request.  VS Code Remote-SSH sends shell_request *without* a
        // preceding pty_request and expects pipe-based I/O with clean LF line
        // endings.  Forcing a PTY here caused CRLF translation which made
        // VS Code misdetect the platform as Windows (and then try to run
        // `powershell`).
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

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp" {
            session.channel_success(channel)?;
            // sftp-server speaks the SFTP binary protocol over stdin/stdout,
            // which is exactly what spawn_pipe_exec wires up.  This enables
            // modern scp (SFTP-based, OpenSSH 9.0+) and SFTP clients to
            // transfer files into and out of the sandbox.
            let input_sender = spawn_pipe_exec(
                &self.policy,
                self.workdir.clone(),
                Some("/usr/lib/openssh/sftp-server".to_string()),
                session.handle(),
                channel,
                self.netns_fd,
                self.proxy_url.clone(),
                self.ca_file_paths.clone(),
                &self.provider_env,
            )?;
            let state = self.channels.get_mut(&channel).ok_or_else(|| {
                anyhow::anyhow!("subsystem_request on unknown channel {channel:?}")
            })?;
            state.input_sender = Some(input_sender);
        } else {
            ocsf_emit!(
                SshActivityBuilder::new(crate::ocsf_ctx())
                    .activity(ActivityId::Refuse)
                    .action(ActionId::Denied)
                    .disposition(DispositionId::Rejected)
                    .severity(SeverityId::Medium)
                    .message(format!("unsupported subsystem requested: {name}"))
                    .build()
            );
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Accept the env request so the client knows we handled it, but we
        // don't actually propagate the variables — the sandbox environment is
        // controlled via policy.  We must reply so VSCode doesn't stall.
        let _ = (variable_name, variable_value);
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(state) = self.channels.get(&channel) else {
            warn!("data on unknown channel {channel:?}");
            return Ok(());
        };
        if let Some(sender) = state.input_sender.as_ref() {
            let _ = sender.send(data.to_vec());
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Drop the input sender so the stdin writer thread sees a
        // disconnected channel and closes the child's stdin pipe.  This
        // is essential for commands like `cat | tar xf -` which need
        // stdin EOF to know the input stream is complete.
        if let Some(state) = self.channels.get_mut(&channel) {
            state.input_sender.take();
        } else {
            warn!("channel_eof on unknown channel {channel:?}");
        }
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
        let state = self
            .channels
            .get_mut(&channel)
            .ok_or_else(|| anyhow::anyhow!("start_shell on unknown channel {channel:?}"))?;
        if let Some(pty) = state.pty_request.take() {
            // PTY was requested — allocate a real PTY (interactive shell or
            // exec that explicitly asked for a terminal).
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
            state.pty_master = Some(pty_master);
            state.input_sender = Some(input_sender);
        } else {
            // No PTY requested — use plain pipes so stdout/stderr are
            // separate and output has clean LF line endings.  This is the
            // path VSCode Remote-SSH exec commands take.
            let input_sender = spawn_pipe_exec(
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
            state.input_sender = Some(input_sender);
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

/// Derive the session USER and HOME from the policy's `run_as_user`.
///
/// Falls back to `("sandbox", "/sandbox")` when the policy has no explicit user,
/// preserving backward compatibility with images that use the default layout.
fn session_user_and_home(policy: &SandboxPolicy) -> (String, String) {
    match policy.process.run_as_user.as_deref() {
        Some(user) if !user.is_empty() => {
            // Look up the user's home directory from /etc/passwd.
            let home = nix::unistd::User::from_name(user)
                .ok()
                .flatten()
                .map(|u| u.dir.to_string_lossy().into_owned())
                .unwrap_or_else(|| format!("/home/{user}"));
            (user.to_string(), home)
        }
        _ => ("sandbox".to_string(), "/sandbox".to_string()),
    }
}

fn apply_child_env(
    cmd: &mut Command,
    session_home: &str,
    session_user: &str,
    term: &str,
    proxy_url: Option<&str>,
    ca_file_paths: Option<&(PathBuf, PathBuf)>,
    provider_env: &HashMap<String, String>,
) {
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into());

    cmd.env_clear()
        .env("OPENSHELL_SANDBOX", "1")
        .env("HOME", session_home)
        .env("USER", session_user)
        .env("SHELL", "/bin/bash")
        .env("PATH", &path)
        .env("TERM", term);

    if let Some(url) = proxy_url {
        for (key, value) in child_env::proxy_env_vars(url) {
            cmd.env(key, value);
        }
    }

    if let Some((ca_cert_path, combined_bundle_path)) = ca_file_paths {
        for (key, value) in child_env::tls_env_vars(ca_cert_path, combined_bundle_path) {
            cmd.env(key, value);
        }
    }

    for (key, value) in provider_env {
        cmd.env(key, value);
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

    // Derive USER and HOME from the policy's run_as_user when available,
    // falling back to "sandbox" / "/sandbox" for backward compatibility.
    let (session_user, session_home) = session_user_and_home(policy);
    apply_child_env(
        &mut cmd,
        &session_home,
        &session_user,
        term,
        proxy_url.as_deref(),
        ca_file_paths.as_deref(),
        provider_env,
    );
    cmd.stdin(stdin).stdout(stdout).stderr(stderr);

    if let Some(dir) = workdir.as_deref() {
        cmd.current_dir(dir);
    }

    // Probe Landlock availability from the parent process where tracing works.
    #[cfg(target_os = "linux")]
    sandbox::linux::log_sandbox_readiness(policy, workdir.as_deref());

    // Phase 1 (as root): Prepare Landlock ruleset before drop_privileges.
    #[cfg(target_os = "linux")]
    let prepared_sandbox = sandbox::linux::prepare(policy, workdir.as_deref())
        .map_err(|err| anyhow::anyhow!("Failed to prepare sandbox: {err}"))?;

    #[cfg(unix)]
    {
        unsafe_pty::install_pre_exec(
            &mut cmd,
            policy.clone(),
            workdir.clone(),
            slave_fd,
            netns_fd,
            #[cfg(target_os = "linux")]
            prepared_sandbox,
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
                    let _ = runtime_reader
                        .block_on(async move { handle_clone.data(channel, data).await });
                }
            }
        }
        // Send EOF to indicate no more data will be sent on this channel.
        let eof_handle = handle_clone.clone();
        let _ = runtime_reader.block_on(async move { eof_handle.eof(channel).await });
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

/// Spawn a command using plain pipes (no PTY).
///
/// stdout is forwarded as SSH channel data and stderr as SSH extended data
/// (type 1), preserving the separation that clients like `VSCode` Remote-SSH
/// expect.  Output retains clean LF line endings (no CRLF translation).
#[allow(clippy::too_many_arguments)]
fn spawn_pipe_exec(
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
            // No command — read from stdin.  Do *not* pass `-i`; interactive
            // mode reads .bashrc, writes prompts to stderr, and can introduce
            // just enough latency for VS Code Remote-SSH's platform detection
            // to time out and fall back to "windows".  Plain `bash` with piped
            // stdin already reads commands line-by-line (script mode), which is
            // exactly what VS Code's local server expects.
            Command::new("/bin/bash")
        },
        |command| {
            let mut c = Command::new("/bin/bash");
            // Use login shell (-l) so that .profile/.bashrc are sourced and
            // tool-specific env vars (VIRTUAL_ENV, UV_PYTHON_INSTALL_DIR, etc.)
            // are available without hardcoding them here.
            c.arg("-lc").arg(command);
            c
        },
    );

    let (session_user, session_home) = session_user_and_home(policy);
    apply_child_env(
        &mut cmd,
        &session_home,
        &session_user,
        "dumb",
        proxy_url.as_deref(),
        ca_file_paths.as_deref(),
        provider_env,
    );
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(dir) = workdir.as_deref() {
        cmd.current_dir(dir);
    }

    // Probe Landlock availability from the parent process where tracing works.
    #[cfg(target_os = "linux")]
    sandbox::linux::log_sandbox_readiness(policy, workdir.as_deref());

    // Phase 1 (as root): Prepare Landlock ruleset before drop_privileges.
    #[cfg(target_os = "linux")]
    let prepared_sandbox = sandbox::linux::prepare(policy, workdir.as_deref())
        .map_err(|err| anyhow::anyhow!("Failed to prepare sandbox: {err}"))?;

    #[cfg(unix)]
    {
        unsafe_pty::install_pre_exec_no_pty(
            &mut cmd,
            policy.clone(),
            workdir.clone(),
            netns_fd,
            #[cfg(target_os = "linux")]
            prepared_sandbox,
        );
    }

    let mut child = cmd.spawn()?;
    #[cfg(target_os = "linux")]
    let child_pid = child.id();
    #[cfg(target_os = "linux")]
    register_managed_child(child_pid);

    let child_stdin = child.stdin.take();
    let child_stdout = child.stdout.take().expect("stdout must be piped");
    let child_stderr = child.stderr.take().expect("stderr must be piped");

    // stdin writer thread
    let (sender, receiver) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let Some(mut stdin) = child_stdin else {
            return;
        };
        while let Ok(bytes) = receiver.recv() {
            if stdin.write_all(&bytes).is_err() {
                break;
            }
            let _ = stdin.flush();
        }
    });

    let runtime = tokio::runtime::Handle::current();

    // Signal from the reader threads to the exit thread that all output has
    // been forwarded.
    let (reader_done_tx, reader_done_rx) = mpsc::channel::<()>();

    // stdout reader
    let stdout_handle = handle.clone();
    let stdout_runtime = runtime.clone();
    let reader_done_stdout = reader_done_tx.clone();
    std::thread::spawn(move || {
        let mut reader = child_stdout;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = CryptoVec::from_slice(&buf[..n]);
                    let h = stdout_handle.clone();
                    let _ = stdout_runtime.block_on(async move { h.data(channel, data).await });
                }
            }
        }
        let _ = reader_done_stdout.send(());
    });

    // stderr reader — sends as extended data (type 1)
    let stderr_handle = handle.clone();
    let stderr_runtime = runtime.clone();
    std::thread::spawn(move || {
        let mut reader = child_stderr;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = CryptoVec::from_slice(&buf[..n]);
                    let h = stderr_handle.clone();
                    let _ = stderr_runtime
                        .block_on(async move { h.extended_data(channel, 1, data).await });
                }
            }
        }
        let _ = reader_done_tx.send(());
    });

    // Exit waiter thread
    let handle_exit = handle;
    let runtime_exit = runtime;
    std::thread::spawn(move || {
        let status = child.wait().ok();
        #[cfg(target_os = "linux")]
        unregister_managed_child(child_pid);
        let code = status.and_then(|s| s.code()).unwrap_or(1).unsigned_abs();
        // Wait for both reader threads.
        let _ = reader_done_rx.recv_timeout(Duration::from_secs(2));
        let _ = reader_done_rx.recv_timeout(Duration::from_secs(1));
        drop(runtime_exit.spawn(async move {
            let _ = handle_exit.eof(channel).await;
            let _ = handle_exit.exit_status_request(channel, code).await;
            let _ = handle_exit.close(channel).await;
        }));
    });

    Ok(sender)
}

mod unsafe_pty {
    #[cfg(not(target_os = "linux"))]
    use super::sandbox;
    use super::{Command, RawFd, SandboxPolicy, Winsize, drop_privileges, setsid};
    #[cfg(unix)]
    use std::os::unix::process::CommandExt;

    #[allow(unsafe_code)]
    pub fn set_winsize(fd: RawFd, winsize: Winsize) -> std::io::Result<()> {
        let rc = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &winsize) };
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
        _workdir: Option<String>,
        slave_fd: RawFd,
        netns_fd: Option<RawFd>,
        #[cfg(target_os = "linux")] prepared: crate::sandbox::linux::PreparedSandbox,
    ) {
        // Wrap in Option so we can .take() it out of the FnMut closure.
        // pre_exec is only called once (after fork, before exec).
        #[cfg(target_os = "linux")]
        let mut prepared = Some(prepared);
        unsafe {
            cmd.pre_exec(move || {
                setsid().map_err(|err| std::io::Error::other(err.to_string()))?;
                set_controlling_tty(slave_fd)?;

                enter_netns_and_sandbox(
                    netns_fd,
                    &policy,
                    #[cfg(target_os = "linux")]
                    prepared.take(),
                )
            });
        }
    }

    /// Pre-exec hook for pipe-based (non-PTY) exec.
    ///
    /// Skips `setsid` and `TIOCSCTTY` since there is no controlling terminal.
    #[allow(unsafe_code)]
    pub fn install_pre_exec_no_pty(
        cmd: &mut Command,
        policy: SandboxPolicy,
        _workdir: Option<String>,
        netns_fd: Option<RawFd>,
        #[cfg(target_os = "linux")] prepared: crate::sandbox::linux::PreparedSandbox,
    ) {
        #[cfg(target_os = "linux")]
        let mut prepared = Some(prepared);
        unsafe {
            cmd.pre_exec(move || {
                enter_netns_and_sandbox(
                    netns_fd,
                    &policy,
                    #[cfg(target_os = "linux")]
                    prepared.take(),
                )
            });
        }
    }

    fn enter_netns_and_sandbox(
        netns_fd: Option<RawFd>,
        policy: &SandboxPolicy,
        #[cfg(target_os = "linux")] prepared: Option<crate::sandbox::linux::PreparedSandbox>,
    ) -> std::io::Result<()> {
        // Enter network namespace before dropping privileges.
        // This ensures SSH shell processes are isolated to the same
        // network namespace as the entrypoint, forcing all traffic
        // through the veth pair and CONNECT proxy.
        #[cfg(target_os = "linux")]
        if let Some(fd) = netns_fd {
            #[allow(unsafe_code)]
            let result = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
            if result != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        #[cfg(not(target_os = "linux"))]
        let _ = netns_fd;

        // Drop privileges. initgroups/setgid/setuid need /etc/group and
        // /etc/passwd which would be blocked if Landlock were already enforced.
        drop_privileges(policy).map_err(|err| std::io::Error::other(err.to_string()))?;
        crate::process::harden_child_process()
            .map_err(|err| std::io::Error::other(err.to_string()))?;

        // Phase 2: Enforce the prepared Landlock ruleset + seccomp.
        // restrict_self() does not require root.
        #[cfg(target_os = "linux")]
        if let Some(prepared) = prepared {
            crate::sandbox::linux::enforce(prepared)
                .map_err(|err| std::io::Error::other(err.to_string()))?;
        }

        #[cfg(not(target_os = "linux"))]
        sandbox::apply(policy, None).map_err(|err| std::io::Error::other(err.to_string()))?;

        Ok(())
    }
}

fn to_u16(value: u32) -> u16 {
    u16::try_from(value.min(u32::from(u16::MAX))).unwrap_or(u16::MAX)
}

/// Check whether a host string refers to a loopback address.
///
/// Covers all representations that resolve to loopback:
/// - `127.0.0.0/8` (the entire IPv4 loopback range, not just `127.0.0.1`)
/// - `localhost`
/// - `::1` and long-form IPv6 loopback (`0:0:0:0:0:0:0:1`)
/// - `::ffff:127.x.x.x` (IPv4-mapped IPv6 loopback)
/// - Bracketed forms like `[::1]`
fn is_loopback_host(host: &str) -> bool {
    // Strip brackets for IPv6 addresses like [::1]
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback(), // covers all 127.x.x.x
        Ok(std::net::IpAddr::V6(v6)) => {
            if v6.is_loopback() {
                return true; // covers ::1 and long form
            }
            // Check IPv4-mapped IPv6 addresses like ::ffff:127.0.0.1
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback();
            }
            false
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    /// Verify that dropping the input sender (the operation `channel_eof`
    /// performs) causes the stdin writer loop to exit and close the child's
    /// stdin pipe.  Without this, commands like `cat | tar xf -` used by
    /// `sync --up` hang forever waiting for EOF on stdin.
    #[test]
    fn dropping_input_sender_closes_child_stdin() {
        let (sender, receiver) = mpsc::channel::<Vec<u8>>();

        let mut child = Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn cat");

        let child_stdin = child.stdin.take().expect("stdin must be piped");

        // Replicate the stdin writer loop from spawn_pipe_exec.
        std::thread::spawn(move || {
            let mut stdin = child_stdin;
            while let Ok(bytes) = receiver.recv() {
                if stdin.write_all(&bytes).is_err() {
                    break;
                }
                let _ = stdin.flush();
            }
        });

        sender.send(b"hello".to_vec()).unwrap();

        // Simulate what channel_eof does: drop the sender.
        drop(sender);

        // cat should see EOF on stdin and exit.  Use a timeout so the test
        // fails fast instead of hanging if the mechanism is broken.
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = done_tx.send(child.wait_with_output());
        });
        let output = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("cat hung for 5s — stdin was not closed (channel_eof bug)")
            .expect("failed to wait for cat");

        assert!(
            output.status.success(),
            "cat exited with {:?}",
            output.status
        );
        assert_eq!(output.stdout, b"hello");
    }

    /// Verify that the stdin writer delivers all buffered data before exiting
    /// when the sender is dropped.  This ensures channel_eof doesn't cause
    /// data loss — only signals "no more data after this".
    #[test]
    fn stdin_writer_delivers_buffered_data_before_eof() {
        let (sender, receiver) = mpsc::channel::<Vec<u8>>();

        let mut child = Command::new("wc")
            .arg("-c")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn wc");

        let child_stdin = child.stdin.take().expect("stdin must be piped");

        std::thread::spawn(move || {
            let mut stdin = child_stdin;
            while let Ok(bytes) = receiver.recv() {
                if stdin.write_all(&bytes).is_err() {
                    break;
                }
                let _ = stdin.flush();
            }
        });

        // Send multiple chunks, then drop the sender.
        for _ in 0..100 {
            sender.send(vec![0u8; 1024]).unwrap();
        }
        drop(sender);

        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = done_tx.send(child.wait_with_output());
        });
        let output = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("wc hung for 5s — stdin was not closed")
            .expect("failed to wait for wc");

        let count: usize = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .expect("wc output was not a number");
        assert_eq!(
            count,
            100 * 1024,
            "expected all 100 KiB delivered before EOF"
        );
    }

    // -----------------------------------------------------------------------
    // SEC-007: is_loopback_host tests
    // -----------------------------------------------------------------------

    #[test]
    fn loopback_host_accepts_standard_ipv4() {
        assert!(is_loopback_host("127.0.0.1"));
    }

    #[test]
    fn loopback_host_accepts_full_ipv4_range() {
        assert!(is_loopback_host("127.0.0.2"));
        assert!(is_loopback_host("127.255.255.255"));
    }

    #[test]
    fn loopback_host_accepts_localhost() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LOCALHOST"));
        assert!(is_loopback_host("Localhost"));
    }

    #[test]
    fn loopback_host_accepts_ipv6_loopback() {
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("0:0:0:0:0:0:0:1"));
    }

    #[test]
    fn loopback_host_accepts_ipv4_mapped_ipv6() {
        assert!(is_loopback_host("::ffff:127.0.0.1"));
    }

    #[test]
    fn loopback_host_rejects_non_loopback() {
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host("192.168.1.1"));
        assert!(!is_loopback_host("8.8.8.8"));
        assert!(!is_loopback_host("example.com"));
        assert!(!is_loopback_host("::ffff:10.0.0.1"));
    }

    #[test]
    fn loopback_host_rejects_empty_and_garbage() {
        assert!(!is_loopback_host(""));
        assert!(!is_loopback_host("not-an-ip"));
        assert!(!is_loopback_host("[]"));
    }

    // -----------------------------------------------------------------------
    // Per-channel PTY state tests (#543)
    // -----------------------------------------------------------------------

    #[test]
    fn set_winsize_applies_to_correct_pty() {
        // Verify that set_winsize applies to a specific PTY master FD,
        // which is the mechanism that per-channel tracking relies on.
        // With the old single-pty_master design, a window_change_request
        // for channel N would resize whatever PTY was stored last —
        // potentially belonging to a different channel.
        let pty_a = openpty(None, None).expect("openpty a");
        let pty_b = openpty(None, None).expect("openpty b");
        let master_a = std::fs::File::from(pty_a.master);
        let master_b = std::fs::File::from(pty_b.master);
        let fd_a = master_a.as_raw_fd();
        let fd_b = master_b.as_raw_fd();
        assert_ne!(fd_a, fd_b, "two PTYs must have distinct FDs");

        // Close the slave ends to avoid leaking FDs in the test.
        drop(std::fs::File::from(pty_a.slave));
        drop(std::fs::File::from(pty_b.slave));

        // Resize only PTY B.
        let winsize_b = Winsize {
            ws_row: 50,
            ws_col: 120,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        unsafe_pty::set_winsize(fd_b, winsize_b).expect("set_winsize on PTY B");

        // Resize PTY A to a different size.
        let winsize_a = Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        unsafe_pty::set_winsize(fd_a, winsize_a).expect("set_winsize on PTY A");

        // Read back sizes via ioctl to verify independence.
        let mut actual_a: libc::winsize = unsafe { std::mem::zeroed() };
        let mut actual_b: libc::winsize = unsafe { std::mem::zeroed() };
        #[allow(unsafe_code)]
        unsafe {
            libc::ioctl(fd_a, libc::TIOCGWINSZ, &mut actual_a);
            libc::ioctl(fd_b, libc::TIOCGWINSZ, &mut actual_b);
        }

        assert_eq!(actual_a.ws_row, 24, "PTY A should be 24 rows");
        assert_eq!(actual_a.ws_col, 80, "PTY A should be 80 cols");
        assert_eq!(actual_b.ws_row, 50, "PTY B should be 50 rows");
        assert_eq!(actual_b.ws_col, 120, "PTY B should be 120 cols");
    }

    #[test]
    fn channel_state_independent_input_senders() {
        // Verify that each channel gets its own input sender so that
        // data() and channel_eof() affect only the targeted channel.
        let (tx_a, rx_a) = mpsc::channel::<Vec<u8>>();
        let (tx_b, rx_b) = mpsc::channel::<Vec<u8>>();

        let mut state_a = ChannelState {
            input_sender: Some(tx_a),
            ..Default::default()
        };
        let state_b = ChannelState {
            input_sender: Some(tx_b),
            ..Default::default()
        };

        // Send data to channel A only.
        state_a
            .input_sender
            .as_ref()
            .unwrap()
            .send(b"hello-a".to_vec())
            .unwrap();
        // Send data to channel B only.
        state_b
            .input_sender
            .as_ref()
            .unwrap()
            .send(b"hello-b".to_vec())
            .unwrap();

        assert_eq!(rx_a.recv().unwrap(), b"hello-a");
        assert_eq!(rx_b.recv().unwrap(), b"hello-b");

        // EOF on channel A (drop sender) should not affect channel B.
        state_a.input_sender.take();
        assert!(
            rx_a.recv().is_err(),
            "channel A sender dropped, recv should fail"
        );

        // Channel B should still be functional.
        state_b
            .input_sender
            .as_ref()
            .unwrap()
            .send(b"still-alive".to_vec())
            .unwrap();
        assert_eq!(rx_b.recv().unwrap(), b"still-alive");
    }

    /// `install_pre_exec_no_pty` runs drop_privileges and succeeds when the
    /// current user/group is already the configured one (no actual uid change).
    ///
    /// This exercises the pre_exec hook end-to-end without needing root: a policy
    /// with no run_as_user/group is a no-op when the process is already unprivileged.
    #[cfg(unix)]
    #[test]
    fn pre_exec_always_calls_drop_privileges() {
        use crate::policy::{
            FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy, SandboxPolicy,
        };

        // No user/group configured and not running as root → drop_privileges is
        // a no-op, so spawn succeeds regardless of the effective UID.
        let policy = SandboxPolicy {
            version: 0,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy {
                run_as_user: None,
                run_as_group: None,
            },
        };

        // Skip if running as root: drop_privileges would try to switch to
        // "sandbox" which may not exist in the test environment.
        if nix::unistd::geteuid().is_root() {
            return;
        }

        let mut cmd = Command::new("echo");
        cmd.arg("drop-privileges-ok");
        cmd.stdout(Stdio::piped());

        unsafe_pty::install_pre_exec_no_pty(
            &mut cmd,
            policy,
            None,
            None, // no netns fd
            #[cfg(target_os = "linux")]
            crate::sandbox::linux::prepare(
                &SandboxPolicy {
                    version: 0,
                    filesystem: FilesystemPolicy::default(),
                    network: NetworkPolicy::default(),
                    landlock: LandlockPolicy::default(),
                    process: ProcessPolicy {
                        run_as_user: None,
                        run_as_group: None,
                    },
                },
                None,
            )
            .expect("prepare should succeed in test environment"),
        );

        let output = cmd
            .spawn()
            .expect("spawn must succeed")
            .wait_with_output()
            .expect("wait_with_output");
        assert!(output.status.success(), "echo should exit 0");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("drop-privileges-ok"),
            "echo output should contain 'drop-privileges-ok'"
        );
    }
}
