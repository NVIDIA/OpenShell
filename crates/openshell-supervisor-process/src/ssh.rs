// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Embedded SSH server for sandbox access.

use crate::child_env;
use crate::main_session::{MainOutput, MainSession};
#[cfg(target_os = "linux")]
use crate::managed_children;
use crate::process::{
    ProcessEnforcementMode, ResolvedProcessIdentity, ResolvedWorkspace,
    drop_privileges_with_identity, is_supervisor_only_env_var, session_user_and_home,
};
use crate::sandbox;
#[cfg(unix)]
use libc;
use miette::{IntoDiagnostic, Result};
use nix::pty::{Winsize, openpty};
use nix::unistd::setsid;
use openshell_core::VERSION;
use openshell_core::net::set_tcp_nodelay_best_effort;
use openshell_core::policy::SandboxPolicy;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, SeverityId, SshActivityBuilder, StatusId, ocsf_emit,
};
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Handle, Session};
use russh::{ChannelId, ChannelOpenFailure, Sig};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, mpsc};
use std::time::Duration;
use tokio::net::UnixListener;
use tracing::warn;

const NO_LOGIN_SHELL_ENV: (&str, &str) = ("OPENSHELL_NO_LOGIN_SHELL", "1");

/// Perform SSH server initialization: generate a host key, build the config,
/// and bind the Unix socket listener. Extracted so that startup errors can be
/// forwarded through the readiness channel rather than being silently logged.
type SshServerInit = (
    UnixListener,
    Arc<russh::server::Config>,
    Option<Arc<(PathBuf, PathBuf)>>,
);

fn ssh_server_init(
    listen_path: &Path,
    ca_file_paths: &Option<(PathBuf, PathBuf)>,
    enforcement_mode: ProcessEnforcementMode,
    shared_socket: bool,
) -> Result<SshServerInit> {
    let mut rng = rand::rng();
    let host_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).into_diagnostic()?;

    // TODO: while building the SSH config, refactor the server_id to be "SSH-2.0-OpenShell_<version>" from `openshell_core::VERSION`
    let mut config = russh::server::Config {
        server_id: russh::SshId::Standard(Cow::Owned(format!("SSH-2.0-OpenShell_{VERSION}"))),
        auth_rejection_time: Duration::from_secs(1),
        ..Default::default()
    };
    config.keys.push(host_key);

    let config = Arc::new(config);
    let ca_paths = ca_file_paths.as_ref().map(|p| Arc::new(p.clone()));

    // In full enforcement mode the supervisor normally starts as root and can
    // isolate the SSH socket in a root-only directory before spawning
    // unprivileged children. Sidecar topology is different: the gateway relay
    // runs in the network sidecar as a different UID, so the shared sidecar
    // state directory must stay group-accessible. Sidecar mode uses a Linux
    // abstract socket instead, so the workload cannot unlink the relay target.
    let abstract_socket = crate::unix_socket::is_abstract(listen_path);
    if !abstract_socket && let Some(parent) = listen_path.parent() {
        std::fs::create_dir_all(parent).into_diagnostic()?;
        #[cfg(unix)]
        if enforcement_mode.uses_privileged_process_setup() && !shared_socket {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(parent, perms).into_diagnostic()?;
        }
    }

    // Remove any stale socket from a previous run before binding.
    if !abstract_socket && listen_path.exists() {
        std::fs::remove_file(listen_path).into_diagnostic()?;
    }
    let runtime_path = crate::unix_socket::runtime_path(listen_path);
    let listener = UnixListener::bind(runtime_path.as_ref()).into_diagnostic()?;

    // Tighten filesystem-socket permissions. Abstract sockets have no inode;
    // sidecar relay connections authenticate the listener with SO_PEERCRED.
    #[cfg(unix)]
    if !abstract_socket {
        use std::os::unix::fs::PermissionsExt;
        let mode = if shared_socket { 0o660 } else { 0o600 };
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(listen_path, perms).into_diagnostic()?;
    }

    ocsf_emit!(
        SshActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Listen)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .message(format!("SSH server listening on {}", listen_path.display()))
            .build()
    );

    Ok((listener, config, ca_paths))
}

#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub async fn run_ssh_server(
    listen_path: PathBuf,
    ready_tx: tokio::sync::oneshot::Sender<Result<()>>,
    policy: SandboxPolicy,
    workspace: ResolvedWorkspace,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
    ca_file_paths: Option<(PathBuf, PathBuf)>,
    provider_credentials: ProviderCredentialState,
    user_environment: HashMap<String, String>,
    resolved_identity: ResolvedProcessIdentity,
    enforcement_mode: ProcessEnforcementMode,
    shared_socket: bool,
    main_session: Arc<MainSession>,
) -> Result<()> {
    let (listener, config, ca_paths) = match ssh_server_init(
        &listen_path,
        &ca_file_paths,
        enforcement_mode,
        shared_socket,
    ) {
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

    let mut consecutive_resource_errors: u32 = 0;
    let mut consecutive_unknown_errors: u32 = 0;

    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                consecutive_resource_errors = 0;
                consecutive_unknown_errors = 0;
                let config = config.clone();
                let policy = policy.clone();
                let workspace = workspace.clone();
                let proxy_url = proxy_url.clone();
                let ca_paths = ca_paths.clone();
                let provider_credentials = provider_credentials.clone();
                let user_environment = user_environment.clone();
                let main_session = Arc::clone(&main_session);

                tokio::spawn(async move {
                    if let Err(err) = handle_connection(
                        stream,
                        config,
                        policy,
                        workspace,
                        netns_fd,
                        proxy_url,
                        ca_paths,
                        provider_credentials,
                        user_environment,
                        resolved_identity,
                        enforcement_mode,
                        main_session,
                    )
                    .await
                    {
                        ocsf_emit!(
                            SshActivityBuilder::new(openshell_ocsf::ctx::ctx())
                                .activity(ActivityId::Fail)
                                .severity(SeverityId::Low)
                                .status(StatusId::Failure)
                                .message(format!("SSH connection failed: {err}"))
                                .build()
                        );
                    }
                });
            }
            Err(err) => {
                match classify_ssh_accept_error(
                    &err,
                    &mut consecutive_resource_errors,
                    &mut consecutive_unknown_errors,
                ) {
                    SshAcceptAction::Terminal => {
                        ocsf_emit!(
                            SshActivityBuilder::new(openshell_ocsf::ctx::ctx())
                                .activity(ActivityId::Fail)
                                .severity(SeverityId::High)
                                .status(StatusId::Failure)
                                .message(format!(
                                    "SSH accept loop exiting on terminal error: {err}"
                                ))
                                .build()
                        );
                        break;
                    }
                    SshAcceptAction::Retry { backoff, severity } => {
                        ocsf_emit!(
                            SshActivityBuilder::new(openshell_ocsf::ctx::ctx())
                                .activity(ActivityId::Fail)
                                .severity(severity)
                                .status(StatusId::Failure)
                                .message(format!(
                                    "SSH accept error (retrying in {}ms): {err}",
                                    backoff.as_millis(),
                                ))
                                .build()
                        );
                        tokio::time::sleep(backoff).await;
                    }
                }
            }
        }
    }

    Ok(())
}

const MAX_CONSECUTIVE_UNKNOWN_SSH_ACCEPT_ERRORS: u32 = 10;

#[derive(Debug, PartialEq)]
enum SshAcceptAction {
    Terminal,
    Retry {
        backoff: Duration,
        severity: SeverityId,
    },
}

fn classify_ssh_accept_error(
    err: &std::io::Error,
    consecutive_resource_errors: &mut u32,
    consecutive_unknown_errors: &mut u32,
) -> SshAcceptAction {
    #[cfg(unix)]
    if matches!(
        err.raw_os_error(),
        Some(libc::EBADF | libc::EINVAL | libc::ENOTSOCK)
    ) {
        return SshAcceptAction::Terminal;
    }

    #[cfg(unix)]
    if matches!(
        err.raw_os_error(),
        Some(
            libc::EMFILE
                | libc::ENFILE
                | libc::ENOBUFS
                | libc::ENOMEM
                | libc::ECONNABORTED
                | libc::ECONNRESET
                | libc::EINTR
                | libc::ENETDOWN
                | libc::EPROTO
                | libc::ENOPROTOOPT
                | libc::EHOSTDOWN
                | libc::EHOSTUNREACH
                | libc::EOPNOTSUPP
                | libc::ENETUNREACH
                | libc::ENOSR
                | libc::ESOCKTNOSUPPORT
                | libc::EPROTONOSUPPORT
                | libc::ETIMEDOUT
        )
    ) {
        *consecutive_unknown_errors = 0;

        #[cfg(unix)]
        let is_resource_pressure = matches!(
            err.raw_os_error(),
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM | libc::ENOSR)
        );
        #[cfg(not(unix))]
        let is_resource_pressure = false;

        if is_resource_pressure {
            *consecutive_resource_errors = consecutive_resource_errors.saturating_add(1);
            let backoff_ms = 100u64
                .saturating_mul(1u64 << (*consecutive_resource_errors).min(7).saturating_sub(1))
                .min(5_000);
            return SshAcceptAction::Retry {
                backoff: Duration::from_millis(backoff_ms),
                severity: SeverityId::Medium,
            };
        }

        *consecutive_resource_errors = 0;
        return SshAcceptAction::Retry {
            backoff: Duration::from_millis(100),
            severity: SeverityId::Low,
        };
    }

    #[cfg(unix)]
    #[cfg(target_os = "linux")]
    if matches!(err.raw_os_error(), Some(libc::ENONET)) {
        *consecutive_unknown_errors = 0;
        *consecutive_resource_errors = 0;
        return SshAcceptAction::Retry {
            backoff: Duration::from_millis(100),
            severity: SeverityId::Low,
        };
    }

    *consecutive_unknown_errors = consecutive_unknown_errors.saturating_add(1);
    if *consecutive_unknown_errors >= MAX_CONSECUTIVE_UNKNOWN_SSH_ACCEPT_ERRORS {
        return SshAcceptAction::Terminal;
    }
    SshAcceptAction::Retry {
        backoff: Duration::from_millis(100),
        severity: SeverityId::Low,
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: tokio::net::UnixStream,
    config: Arc<russh::server::Config>,
    policy: SandboxPolicy,
    workspace: ResolvedWorkspace,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
    ca_file_paths: Option<Arc<(PathBuf, PathBuf)>>,
    provider_credentials: ProviderCredentialState,
    user_environment: HashMap<String, String>,
    resolved_identity: ResolvedProcessIdentity,
    enforcement_mode: ProcessEnforcementMode,
    main_session: Arc<MainSession>,
) -> Result<()> {
    // Access is gated by the Unix-socket filesystem permissions (root-only),
    // not by an application-level preface. The supervisor bridges the
    // gateway's RelayStream directly into this socket.
    ocsf_emit!(
        SshActivityBuilder::new(openshell_ocsf::ctx::ctx())
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
        workspace,
        netns_fd,
        proxy_url,
        ca_file_paths,
        provider_credentials,
        user_environment,
        resolved_identity,
        enforcement_mode,
        main_session,
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
// Several independent per-channel boolean flags (login-shell opt-out and the
// main-attachment state bits) legitimately live side by side here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct ChannelState {
    input_sender: Option<InputSender>,
    pty_master: Option<std::fs::File>,
    pty_request: Option<PtyRequest>,
    no_login_shell: bool,
    main_input_owner: Option<u64>,
    main_attached: bool,
    main_read_only: bool,
    main_detach_prefix_pending: bool,
    main_output_task: Option<tokio::task::AbortHandle>,
}

const MAIN_DETACH_PREFIX: u8 = 0x10; // Ctrl-P
const MAIN_DETACH_KEY: u8 = 0x11; // Ctrl-Q

/// Remove the `OpenShell` detach sequence from canonical-main input.
///
/// A trailing Ctrl-P remains pending across SSH data frames. If the following
/// byte is not Ctrl-Q, both bytes are forwarded unchanged. Bytes after a
/// completed detach sequence are discarded because the attachment is closing.
fn filter_main_detach_sequence(prefix_pending: &mut bool, data: &[u8]) -> (Vec<u8>, bool) {
    let mut forward = Vec::with_capacity(data.len() + usize::from(*prefix_pending));

    for &byte in data {
        if *prefix_pending {
            if byte == MAIN_DETACH_KEY {
                *prefix_pending = false;
                return (forward, true);
            }
            forward.push(MAIN_DETACH_PREFIX);
            *prefix_pending = false;
        }

        if byte == MAIN_DETACH_PREFIX {
            *prefix_pending = true;
        } else {
            forward.push(byte);
        }
    }

    (forward, false)
}

enum InputSender {
    Process(mpsc::Sender<Vec<u8>>),
    Main(tokio::sync::mpsc::Sender<Vec<u8>>),
}

impl InputSender {
    fn send(&self, data: Vec<u8>) -> Result<(), &'static str> {
        match self {
            Self::Process(sender) => sender.send(data).map_err(|_| "process stdin closed"),
            Self::Main(sender) => sender.try_send(data).map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(_) => "canonical stdin buffer is full",
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    "canonical process stdin closed"
                }
            }),
        }
    }
}

struct SshHandler {
    policy: SandboxPolicy,
    workspace: ResolvedWorkspace,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
    ca_file_paths: Option<Arc<(PathBuf, PathBuf)>>,
    provider_credentials: ProviderCredentialState,
    user_environment: HashMap<String, String>,
    resolved_identity: ResolvedProcessIdentity,
    enforcement_mode: ProcessEnforcementMode,
    main_session: Arc<MainSession>,
    channels: HashMap<ChannelId, ChannelState>,
}

impl Drop for SshHandler {
    fn drop(&mut self) {
        for state in self.channels.values_mut() {
            if state.main_attached {
                self.main_session.end_terminal_attachment();
                state.main_attached = false;
            }
            if let Some(owner) = state.main_input_owner.take() {
                self.main_session.release_input(owner);
            }
            if let Some(task) = state.main_output_task.take() {
                task.abort();
            }
        }
    }
}

impl SshHandler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        policy: SandboxPolicy,
        workspace: ResolvedWorkspace,
        netns_fd: Option<RawFd>,
        proxy_url: Option<String>,
        ca_file_paths: Option<Arc<(PathBuf, PathBuf)>>,
        provider_credentials: ProviderCredentialState,
        user_environment: HashMap<String, String>,
        resolved_identity: ResolvedProcessIdentity,
        enforcement_mode: ProcessEnforcementMode,
        main_session: Arc<MainSession>,
    ) -> Self {
        Self {
            policy,
            workspace,
            netns_fd,
            proxy_url,
            ca_file_paths,
            provider_credentials,
            user_environment,
            resolved_identity,
            enforcement_mode,
            main_session,
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
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), ChannelState::default());
        reply.accept().await;
        Ok(())
    }

    /// Clean up per-channel state when the channel is closed.
    ///
    /// This is the final cleanup and subsumes `channel_eof` — if `channel_close`
    /// fires without a preceding `channel_eof`, all resources (`pty_master` File,
    /// `input_sender`) are dropped here.
    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.remove(&channel) {
            if state.main_attached {
                self.main_session.end_terminal_attachment();
            }
            if let Some(owner) = state.main_input_owner {
                self.main_session.release_input(owner);
            }
            if let Some(task) = state.main_output_task {
                task.abort();
            }
        }
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.main_session.finished() {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        // Validate port range before truncating u32 -> u16.  The SSH protocol
        // uses u32 for ports, but valid TCP ports are 0-65535.  Without this
        // check, port 65537 truncates to port 1 (privileged).
        if port_to_connect > u32::from(u16::MAX) {
            ocsf_emit!(SshActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Refuse)
                .action(ActionId::Denied)
                .disposition(DispositionId::Blocked)
                .severity(SeverityId::Medium)
                .message(format!(
                    "direct-tcpip rejected: port {port_to_connect} exceeds valid TCP range for host {host_to_connect}"
                ))
                .build());
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }

        // Only allow forwarding to loopback destinations to prevent the
        // sandbox SSH server from being used as a generic proxy.
        if !is_loopback_host(host_to_connect) {
            ocsf_emit!(SshActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Refuse)
                .action(ActionId::Denied)
                .disposition(DispositionId::Blocked)
                .severity(SeverityId::Medium)
                .message(format!(
                    "direct-tcpip rejected: non-loopback destination {host_to_connect}:{port_to_connect}"
                ))
                .build());
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }

        let host = host_to_connect.to_string();
        // SSH protocol port is bounded by u32 but only u16 is meaningful;
        // saturate as a guard for malformed clients.
        let port = u16::try_from(port_to_connect).unwrap_or(u16::MAX);
        let netns_fd = self.netns_fd;

        // Confirm the channel before spawning: the task below writes to it, and
        // the peer must see the open-confirmation first.
        reply.accept().await;

        tokio::spawn(async move {
            let addr = format!("{host}:{port}");
            let tcp = match connect_in_netns(&addr, netns_fd).await {
                Ok(stream) => stream,
                Err(err) => {
                    ocsf_emit!(
                        SshActivityBuilder::new(openshell_ocsf::ctx::ctx())
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

        Ok(())
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
        if state.main_attached {
            self.main_session
                .resize(col_width, row_height, pixel_width, pixel_height);
        } else if let Some(master) = state.pty_master.as_ref() {
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
        if self.main_session.finished() {
            session.channel_failure(channel)?;
            return Ok(());
        }
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
        if self.main_session.finished() {
            session.channel_failure(channel)?;
            return Ok(());
        }
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
        if name == "openshell-main" {
            if !self.channels.contains_key(&channel) {
                return Err(anyhow::anyhow!(
                    "subsystem_request on unknown channel {channel:?}"
                ));
            }
            if self.main_session.begin_terminal_attachment().is_err() {
                session.channel_failure(channel)?;
                return Ok(());
            }
            let state = self
                .channels
                .get_mut(&channel)
                .expect("main channel existence checked above");
            state.main_attached = true;
            if let Some(pty) = state.pty_request.take() {
                self.main_session.resize(
                    pty.col_width,
                    pty.row_height,
                    pty.pixel_width,
                    pty.pixel_height,
                );
            }
            let (input, input_warning) = if state.main_read_only {
                (None, None)
            } else {
                match self.main_session.acquire_input() {
                    Ok((owner, input)) => {
                        state.main_input_owner = Some(owner);
                        (Some(InputSender::Main(input)), None)
                    }
                    Err(error) => {
                        warn!(%error, "main process input lease unavailable; attaching read-only");
                        (None, Some(error))
                    }
                }
            };
            state.main_detach_prefix_pending = false;
            state.input_sender = input;
            let mut output = self.main_session.subscribe();
            let terminal_delivery = Arc::clone(&self.main_session);
            let handle = session.handle();
            session.channel_success(channel)?;
            if let Some(error) = input_warning {
                let _ = handle
                    .extended_data(
                        channel,
                        1,
                        format!("openshell: {error}; attached read-only\n").into_bytes(),
                    )
                    .await;
            }
            let output_task = tokio::spawn(async move {
                loop {
                    match output.recv().await {
                        Ok(event) => {
                            if let MainOutput::Exit(code) = event {
                                terminal_delivery.wait_for_terminal_reported().await;
                                let _ = send_main_output(&handle, channel, MainOutput::Exit(code))
                                    .await;
                                break;
                            }
                            let _ = send_main_output(&handle, channel, event).await;
                        }
                        Err(error) => {
                            let _ = handle
                                .extended_data(
                                    channel,
                                    1,
                                    format!(
                                        "openshell: attachment fell behind by {} output chunks; reconnect for buffered output\n",
                                        error.skipped
                                    )
                                    .into_bytes(),
                                )
                                .await;
                            let _ = handle.close(channel).await;
                            break;
                        }
                    }
                }
            });
            if let Some(state) = self.channels.get_mut(&channel) {
                state.main_output_task = Some(output_task.abort_handle());
            }
        } else if name == "sftp" && !self.main_session.finished() {
            session.channel_success(channel)?;
            // sftp-server speaks the SFTP binary protocol over stdin/stdout,
            // which is exactly what spawn_pipe_exec wires up.  This enables
            // modern scp (SFTP-based, OpenSSH 9.0+) and SFTP clients to
            // transfer files into and out of the sandbox.
            let input_sender = spawn_pipe_exec(
                &self.policy,
                &self.workspace,
                Some("/usr/lib/openssh/sftp-server".to_string()),
                false,
                session.handle(),
                channel,
                self.netns_fd,
                self.proxy_url.clone(),
                self.ca_file_paths.clone(),
                &self.provider_credentials.child_env_with_gcp_resolved(),
                &self.user_environment,
                self.resolved_identity,
                self.enforcement_mode,
            )?;
            let state = self.channels.get_mut(&channel).ok_or_else(|| {
                anyhow::anyhow!("subsystem_request on unknown channel {channel:?}")
            })?;
            state.input_sender = Some(InputSender::Process(input_sender));
        } else {
            ocsf_emit!(
                SshActivityBuilder::new(openshell_ocsf::ctx::ctx())
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
        // don't actually propagate arbitrary variables — the sandbox
        // environment is controlled via policy. We must reply so VSCode
        // doesn't stall. Two exceptions carry supervisor signals the SSH
        // protocol has no native field for:
        // - OPENSHELL_NO_LOGIN_SHELL: gateway login-shell opt-out.
        // - OPENSHELL_MAIN_READ_ONLY: read-only main attachment.
        if variable_name == NO_LOGIN_SHELL_ENV.0
            && let Some(state) = self.channels.get_mut(&channel)
        {
            state.no_login_shell = variable_value == NO_LOGIN_SHELL_ENV.1;
        }
        if variable_name == "OPENSHELL_MAIN_READ_ONLY"
            && variable_value == "1"
            && let Some(state) = self.channels.get_mut(&channel)
        {
            state.main_read_only = true;
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(state) = self.channels.get_mut(&channel) else {
            warn!("data on unknown channel {channel:?}");
            return Ok(());
        };

        let main_attached = state.main_attached;
        let (forward, detach) = if main_attached {
            filter_main_detach_sequence(&mut state.main_detach_prefix_pending, data)
        } else {
            (data.to_vec(), false)
        };
        let send_error = (!forward.is_empty())
            .then(|| state.input_sender.as_ref()?.send(forward).err())
            .flatten();

        if let Some(error) = send_error {
            let handle = session.handle();
            if main_attached {
                self.close_main_attachment(channel, handle, Some(error))
                    .await;
            } else {
                let _ = handle
                    .extended_data(
                        channel,
                        1,
                        format!("openshell: {error}; closing attachment\n").into_bytes(),
                    )
                    .await;
                let _ = handle.close(channel).await;
            }
            return Ok(());
        }
        if detach {
            self.close_main_attachment(channel, session.handle(), None)
                .await;
            return Ok(());
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
            if state.main_attached
                && let Some(owner) = state.main_input_owner.take()
            {
                self.main_session.release_input(owner);
            }
            state.input_sender.take();
            state.main_detach_prefix_pending = false;
        } else {
            warn!("channel_eof on unknown channel {channel:?}");
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self
            .channels
            .get(&channel)
            .is_some_and(|state| state.main_attached)
        {
            return Ok(());
        }
        let signal = match signal {
            Sig::HUP => Some(nix::sys::signal::Signal::SIGHUP),
            Sig::INT => Some(nix::sys::signal::Signal::SIGINT),
            Sig::KILL => Some(nix::sys::signal::Signal::SIGKILL),
            Sig::QUIT => Some(nix::sys::signal::Signal::SIGQUIT),
            Sig::TERM => Some(nix::sys::signal::Signal::SIGTERM),
            _ => None,
        };
        if let Some(signal) = signal
            && let Err(error) = self.main_session.signal_group(signal)
        {
            warn!(%error, ?signal, "failed to signal canonical main process group");
        }
        Ok(())
    }
}

async fn send_main_output(handle: &Handle, channel: ChannelId, event: MainOutput) -> bool {
    match event {
        MainOutput::Stdout(data) => handle.data(channel, data).await.is_ok(),
        MainOutput::Stderr(data) => handle.extended_data(channel, 1, data).await.is_ok(),
        MainOutput::Exit(code) => {
            let eof_sent = handle.eof(channel).await.is_ok();
            let status_sent = handle
                .exit_status_request(channel, code.max(0).unsigned_abs())
                .await
                .is_ok();
            let close_sent = handle.close(channel).await.is_ok();
            eof_sent && status_sent && close_sent
        }
    }
}

impl SshHandler {
    async fn close_main_attachment(
        &mut self,
        channel: ChannelId,
        handle: Handle,
        error: Option<&str>,
    ) {
        if let Some(state) = self.channels.get_mut(&channel) {
            if state.main_attached {
                self.main_session.end_terminal_attachment();
                state.main_attached = false;
            }
            if let Some(owner) = state.main_input_owner.take() {
                self.main_session.release_input(owner);
            }
            state.input_sender.take();
            state.main_detach_prefix_pending = false;
            if let Some(task) = state.main_output_task.take() {
                task.abort();
            }
        }
        if let Some(error) = error {
            let _ = handle
                .extended_data(
                    channel,
                    1,
                    format!("openshell: {error}; closing attachment\n").into_bytes(),
                )
                .await;
        }
        let _ = handle.eof(channel).await;
        let _ = handle.exit_status_request(channel, 0).await;
        let _ = handle.close(channel).await;
    }

    fn start_shell(
        &mut self,
        channel: ChannelId,
        handle: Handle,
        command: Option<String>,
    ) -> anyhow::Result<()> {
        let provider_env = self.provider_credentials.child_env_with_gcp_resolved();
        let state = self
            .channels
            .get_mut(&channel)
            .ok_or_else(|| anyhow::anyhow!("start_shell on unknown channel {channel:?}"))?;
        let no_login_shell = state.no_login_shell;
        if let Some(pty) = state.pty_request.take() {
            // PTY was requested — allocate a real PTY (interactive shell or
            // exec that explicitly asked for a terminal).
            let (pty_master, input_sender) = spawn_pty_shell(
                &self.policy,
                &self.workspace,
                command,
                no_login_shell,
                &pty,
                handle,
                channel,
                self.netns_fd,
                self.proxy_url.clone(),
                self.ca_file_paths.clone(),
                &provider_env,
                &self.user_environment,
                self.resolved_identity,
                self.enforcement_mode,
            )?;
            state.pty_master = Some(pty_master);
            state.input_sender = Some(InputSender::Process(input_sender));
        } else {
            // No PTY requested — use plain pipes so stdout/stderr are
            // separate and output has clean LF line endings.  This is the
            // path VSCode Remote-SSH exec commands take.
            let input_sender = spawn_pipe_exec(
                &self.policy,
                &self.workspace,
                command,
                no_login_shell,
                handle,
                channel,
                self.netns_fd,
                self.proxy_url.clone(),
                self.ca_file_paths.clone(),
                &provider_env,
                &self.user_environment,
                self.resolved_identity,
                self.enforcement_mode,
            )?;
            state.input_sender = Some(InputSender::Process(input_sender));
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
pub async fn connect_in_netns(
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
        let stream = tokio::net::TcpStream::from_std(std_stream)?;
        set_tcp_nodelay_best_effort(&stream);
        return Ok(stream);
    }

    #[cfg(not(target_os = "linux"))]
    let _ = netns_fd;

    let stream = tokio::net::TcpStream::connect(addr).await?;
    set_tcp_nodelay_best_effort(&stream);
    Ok(stream)
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
fn apply_child_env(
    cmd: &mut Command,
    session_home: &str,
    session_user: &str,
    term: &str,
    proxy_url: Option<&str>,
    ca_file_paths: Option<&(PathBuf, PathBuf)>,
    provider_env: &HashMap<String, String>,
    user_environment: &HashMap<String, String>,
) {
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into());

    cmd.env_clear()
        .env(openshell_core::sandbox_env::SANDBOX, "1")
        .env("HOME", session_home)
        .env("USER", session_user)
        .env("SHELL", openshell_core::shell::detect_login_shell())
        .env("PATH", &path)
        .env("TERM", term);

    for (key, value) in user_environment {
        if !key.starts_with("OPENSHELL_") {
            cmd.env(key, value);
        }
    }

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
        if is_supervisor_only_env_var(key) {
            continue;
        }
        cmd.env(key, value);
    }
}

const fn login_shell_flag(no_login_shell: bool) -> &'static str {
    if no_login_shell { "-c" } else { "-lc" }
}

/// Build the shell command for an SSH session using a shell that exists in the
/// sandbox image (minimal images such as Alpine ship only `/bin/sh`, not bash).
///
/// `no_command_arg` is appended only when no explicit command is given: `-i`
/// for an interactive PTY session, or `None` for the non-PTY stdin path (a
/// bare shell already reads piped stdin line-by-line). With an explicit
/// command the login-shell flag is used per `no_login_shell`.
fn build_ssh_shell_command(
    shell: &str,
    command: Option<String>,
    no_login_shell: bool,
    no_command_arg: Option<&str>,
) -> Command {
    let mut cmd = Command::new(shell);
    match command {
        None => {
            if let Some(arg) = no_command_arg {
                cmd.arg(arg);
            }
        }
        Some(command) => {
            cmd.arg(login_shell_flag(no_login_shell)).arg(command);
        }
    }
    cmd
}

#[allow(clippy::too_many_arguments)]
fn spawn_pty_shell(
    policy: &SandboxPolicy,
    workspace: &ResolvedWorkspace,
    command: Option<String>,
    no_login_shell: bool,
    pty: &PtyRequest,
    handle: Handle,
    channel: ChannelId,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
    ca_file_paths: Option<Arc<(PathBuf, PathBuf)>>,
    provider_env: &HashMap<String, String>,
    user_environment: &HashMap<String, String>,
    resolved_identity: ResolvedProcessIdentity,
    enforcement_mode: ProcessEnforcementMode,
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

    // Resolve a shell present in the sandbox image; interactive PTY sessions
    // pass `-i` when no command is given. Runs in the supervisor, so it
    // inspects the sandbox filesystem.
    let shell = openshell_core::shell::detect_login_shell();
    let mut cmd = build_ssh_shell_command(&shell, command, no_login_shell, Some("-i"));

    let term = if pty.term.is_empty() {
        "xterm-256color"
    } else {
        pty.term.as_str()
    };

    // Derive USER and HOME from the policy's run_as_user when available,
    // falling back to "sandbox" / "/sandbox" for backward compatibility.
    let (session_user, session_home) = session_user_and_home(policy, workspace.home());
    apply_child_env(
        &mut cmd,
        &session_home,
        &session_user,
        term,
        proxy_url.as_deref(),
        ca_file_paths.as_deref(),
        provider_env,
        user_environment,
    );
    cmd.stdin(stdin).stdout(stdout).stderr(stderr);

    if let Some(dir) = workspace.root() {
        cmd.current_dir(dir);
    }

    // Probe Landlock availability from the parent process where tracing works.
    #[cfg(target_os = "linux")]
    if enforcement_mode.enforces_child_sandbox() {
        sandbox::linux::log_sandbox_readiness(policy, workspace.root());
    }

    // Phase 1: Prepare Landlock ruleset before the child applies it.
    #[cfg(target_os = "linux")]
    let prepared_sandbox =
        crate::process::prepare_child_sandbox(policy, workspace.root(), enforcement_mode)
            .map_err(|err| anyhow::anyhow!("Failed to prepare sandbox: {err}"))?;

    #[cfg(unix)]
    {
        unsafe_pty::install_pre_exec(
            &mut cmd,
            policy.clone(),
            workspace.owned_root(),
            slave_fd,
            netns_fd,
            resolved_identity,
            enforcement_mode,
            #[cfg(target_os = "linux")]
            prepared_sandbox,
        );
    }

    #[cfg(target_os = "linux")]
    let mut child = crate::process::spawn_std_command_with_supervisor_identity_namespace(cmd)?;
    #[cfg(not(target_os = "linux"))]
    let mut child = cmd.spawn()?;
    #[cfg(target_os = "linux")]
    let child_pid = child.id();
    #[cfg(target_os = "linux")]
    managed_children::register(child_pid);
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
                    let data = buf[..n].to_vec();
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
        managed_children::unregister(child_pid);
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
    workspace: &ResolvedWorkspace,
    command: Option<String>,
    no_login_shell: bool,
    handle: Handle,
    channel: ChannelId,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
    ca_file_paths: Option<Arc<(PathBuf, PathBuf)>>,
    provider_env: &HashMap<String, String>,
    user_environment: &HashMap<String, String>,
    resolved_identity: ResolvedProcessIdentity,
    enforcement_mode: ProcessEnforcementMode,
) -> anyhow::Result<mpsc::Sender<Vec<u8>>> {
    // Resolve a shell present in the sandbox image; minimal images (e.g. Alpine)
    // don't ship bash, only `/bin/sh`. Runs in the supervisor, so it inspects
    // the sandbox filesystem. No command → read from stdin with no `-i`:
    // interactive mode reads .bashrc, writes prompts to stderr, and can add
    // just enough latency for VS Code Remote-SSH's platform detection to time
    // out and fall back to "windows". A plain shell with piped stdin already
    // reads commands line-by-line (script mode), which is what VS Code expects.
    let shell = openshell_core::shell::detect_login_shell();
    let mut cmd = build_ssh_shell_command(&shell, command, no_login_shell, None);

    let (session_user, session_home) = session_user_and_home(policy, workspace.home());
    apply_child_env(
        &mut cmd,
        &session_home,
        &session_user,
        "dumb",
        proxy_url.as_deref(),
        ca_file_paths.as_deref(),
        provider_env,
        user_environment,
    );
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(dir) = workspace.root() {
        cmd.current_dir(dir);
    }

    // Probe Landlock availability from the parent process where tracing works.
    #[cfg(target_os = "linux")]
    if enforcement_mode.enforces_child_sandbox() {
        sandbox::linux::log_sandbox_readiness(policy, workspace.root());
    }

    // Phase 1: Prepare Landlock ruleset before the child applies it.
    #[cfg(target_os = "linux")]
    let prepared_sandbox =
        crate::process::prepare_child_sandbox(policy, workspace.root(), enforcement_mode)
            .map_err(|err| anyhow::anyhow!("Failed to prepare sandbox: {err}"))?;

    #[cfg(unix)]
    {
        unsafe_pty::install_pre_exec_no_pty(
            &mut cmd,
            policy.clone(),
            workspace.owned_root(),
            netns_fd,
            resolved_identity,
            enforcement_mode,
            #[cfg(target_os = "linux")]
            prepared_sandbox,
        );
    }

    #[cfg(target_os = "linux")]
    let mut child = crate::process::spawn_std_command_with_supervisor_identity_namespace(cmd)?;
    #[cfg(not(target_os = "linux"))]
    let mut child = cmd.spawn()?;
    #[cfg(target_os = "linux")]
    let child_pid = child.id();
    #[cfg(target_os = "linux")]
    managed_children::register(child_pid);

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
                    let data = buf[..n].to_vec();
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
                    let data = buf[..n].to_vec();
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
        managed_children::unregister(child_pid);
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
    use super::{
        Command, ProcessEnforcementMode, RawFd, ResolvedProcessIdentity, SandboxPolicy, Winsize,
        drop_privileges_with_identity, setsid,
    };
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
    // `libc::TIOCSCTTY` is `u32` on macOS/BSD and `u64` on Linux; allow the
    // cross-platform conversion so the same expression compiles everywhere.
    #[allow(clippy::useless_conversion)]
    fn set_controlling_tty(fd: RawFd) -> std::io::Result<()> {
        let rc = unsafe { libc::ioctl(fd, libc::TIOCSCTTY.into(), 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(
            clippy::unnecessary_wraps,
            reason = "Linux pre_exec setup can fail while non-Linux setup cannot."
        )
    )]
    pub fn install_pre_exec(
        cmd: &mut Command,
        policy: SandboxPolicy,
        _workdir: Option<String>,
        slave_fd: RawFd,
        netns_fd: Option<RawFd>,
        resolved_identity: ResolvedProcessIdentity,
        enforcement_mode: ProcessEnforcementMode,
        #[cfg(target_os = "linux")] prepared: Option<crate::sandbox::linux::PreparedSandbox>,
    ) {
        // Wrap in Option so we can .take() it out of the FnMut closure.
        // pre_exec is only called once (after fork, before exec).
        #[cfg(target_os = "linux")]
        let mut prepared = prepared;
        unsafe {
            cmd.pre_exec(move || {
                setsid().map_err(|err| std::io::Error::other(err.to_string()))?;
                set_controlling_tty(slave_fd)?;

                enter_netns_and_sandbox(
                    netns_fd,
                    &policy,
                    resolved_identity,
                    enforcement_mode,
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
    #[cfg_attr(
        not(target_os = "linux"),
        allow(
            clippy::unnecessary_wraps,
            reason = "Linux pre_exec setup can fail while non-Linux setup cannot."
        )
    )]
    pub fn install_pre_exec_no_pty(
        cmd: &mut Command,
        policy: SandboxPolicy,
        _workdir: Option<String>,
        netns_fd: Option<RawFd>,
        resolved_identity: ResolvedProcessIdentity,
        enforcement_mode: ProcessEnforcementMode,
        #[cfg(target_os = "linux")] prepared: Option<crate::sandbox::linux::PreparedSandbox>,
    ) {
        #[cfg(target_os = "linux")]
        let mut prepared = prepared;
        unsafe {
            cmd.pre_exec(move || {
                enter_netns_and_sandbox(
                    netns_fd,
                    &policy,
                    resolved_identity,
                    enforcement_mode,
                    #[cfg(target_os = "linux")]
                    prepared.take(),
                )
            });
        }
    }

    fn enter_netns_and_sandbox(
        netns_fd: Option<RawFd>,
        policy: &SandboxPolicy,
        resolved_identity: ResolvedProcessIdentity,
        enforcement_mode: ProcessEnforcementMode,
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
        if enforcement_mode.uses_privileged_process_setup() {
            drop_privileges_with_identity(policy, resolved_identity)
                .map_err(|err| std::io::Error::other(err.to_string()))?;
        }
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
        if enforcement_mode.enforces_child_sandbox() {
            sandbox::apply(policy, None).map_err(|err| std::io::Error::other(err.to_string()))?;
        }

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
#[allow(
    clippy::doc_markdown,
    unsafe_code,
    reason = "Test code: doc text references identifiers and uses libc::winsize zero-init."
)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::process::Stdio;

    /// Regression test: SSH sessions run the shell they are given, never a
    /// hardcoded bash, so sh-only images (e.g. Alpine) work. Covers both the
    /// interactive PTY path (`-i` when no command) and the non-PTY path.
    #[test]
    fn build_ssh_shell_command_uses_given_shell() {
        // PTY, no command → given shell + interactive flag.
        let cmd = build_ssh_shell_command("/bin/sh", None, false, Some("-i"));
        assert_eq!(cmd.get_program(), OsStr::new("/bin/sh"));
        assert_eq!(cmd.get_args().collect::<Vec<_>>(), vec![OsStr::new("-i")]);

        // Non-PTY, no command → bare shell, no args (reads piped stdin).
        let cmd = build_ssh_shell_command("/bin/sh", None, false, None);
        assert_eq!(cmd.get_program(), OsStr::new("/bin/sh"));
        assert_eq!(cmd.get_args().count(), 0);

        // Explicit command → login-shell flag + command, still on the given shell.
        let cmd = build_ssh_shell_command("/bin/sh", Some("echo hi".into()), false, Some("-i"));
        assert_eq!(cmd.get_program(), OsStr::new("/bin/sh"));
        assert_eq!(
            cmd.get_args().collect::<Vec<_>>(),
            vec![OsStr::new("-lc"), OsStr::new("echo hi")]
        );

        // OPENSHELL_NO_LOGIN_SHELL → plain -c.
        let cmd = build_ssh_shell_command("/bin/sh", Some("echo hi".into()), true, None);
        assert_eq!(
            cmd.get_args().collect::<Vec<_>>(),
            vec![OsStr::new("-c"), OsStr::new("echo hi")]
        );
    }

    /// Regression test: the direct-tcpip connect path sets `TCP_NODELAY`.
    #[tokio::test]
    async fn connect_in_netns_sets_tcp_nodelay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let stream = connect_in_netns(&addr.to_string(), None)
            .await
            .expect("connect");
        assert!(stream.nodelay().expect("query TCP_NODELAY"));
    }

    #[cfg(unix)]
    fn file_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    fn set_file_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ssh_server_init_full_enforcement_keeps_private_socket() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("ssh");
        std::fs::create_dir_all(&parent).unwrap();
        set_file_mode(&parent, 0o775);
        let socket = parent.join("ssh.sock");

        let (listener, _, _) =
            ssh_server_init(&socket, &None, ProcessEnforcementMode::Full, false).unwrap();
        drop(listener);

        assert_eq!(file_mode(&parent), 0o700);
        assert_eq!(file_mode(&socket), 0o600);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ssh_server_init_shared_socket_keeps_group_access() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("ssh");
        std::fs::create_dir_all(&parent).unwrap();
        set_file_mode(&parent, 0o775);
        let socket = parent.join("ssh.sock");

        let (listener, _, _) =
            ssh_server_init(&socket, &None, ProcessEnforcementMode::Full, true).unwrap();
        drop(listener);

        assert_eq!(file_mode(&parent), 0o775);
        assert_eq!(file_mode(&socket), 0o660);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ssh_server_abstract_socket_cannot_be_replaced_while_bound() {
        let socket = PathBuf::from(format!("@openshell-ssh-test-{}", uuid::Uuid::new_v4()));
        let (listener, _, _) =
            ssh_server_init(&socket, &None, ProcessEnforcementMode::NetworkOnly, true).unwrap();

        assert!(
            !socket.exists(),
            "abstract socket must not create a filesystem inode"
        );
        let runtime_path = crate::unix_socket::runtime_path(&socket);
        let err = UnixListener::bind(runtime_path.as_ref())
            .expect_err("a workload must not be able to replace the bound abstract socket");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);

        drop(listener);
    }

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

    /// Command execution selects a login shell by default and a non-login shell
    /// under `--no-login-shell`, so user startup files are sourced only in the
    /// default case.
    #[cfg(unix)]
    #[test]
    fn login_shell_flag_controls_profile_sourcing() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(".bash_profile"), "echo LOGIN_MARKER\n").unwrap();

        let run = |flag: &str| -> String {
            let out = Command::new("bash")
                .arg(flag)
                .arg("true")
                .env("HOME", home.path())
                .env_remove("BASH_ENV") // isolate: -c still reads BASH_ENV if set
                .output()
                .expect("spawn bash");
            String::from_utf8_lossy(&out.stdout).into_owned()
        };

        assert_eq!(login_shell_flag(true), "-c");
        assert_eq!(login_shell_flag(false), "-lc");
        assert!(
            run("-lc").contains("LOGIN_MARKER"),
            "login shell must source .bash_profile"
        );
        assert!(
            !run("-c").contains("LOGIN_MARKER"),
            "non-login shell must not source it"
        );
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
            input_sender: Some(InputSender::Process(tx_a)),
            ..Default::default()
        };
        let state_b = ChannelState {
            input_sender: Some(InputSender::Process(tx_b)),
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

    #[test]
    fn main_detach_filter_forwards_ctrl_c_unchanged() {
        let mut prefix_pending = false;
        let (forward, detach) =
            filter_main_detach_sequence(&mut prefix_pending, b"before\x03after");

        assert_eq!(forward, b"before\x03after");
        assert!(!detach);
        assert!(!prefix_pending);
    }

    #[test]
    fn main_detach_filter_removes_sequence_and_trailing_input() {
        let mut prefix_pending = false;
        let (forward, detach) =
            filter_main_detach_sequence(&mut prefix_pending, b"before\x10\x11after");

        assert_eq!(forward, b"before");
        assert!(detach);
        assert!(!prefix_pending);
    }

    #[test]
    fn main_detach_filter_recognizes_sequence_across_frames() {
        let mut prefix_pending = false;
        let (forward, detach) = filter_main_detach_sequence(&mut prefix_pending, b"before\x10");
        assert_eq!(forward, b"before");
        assert!(!detach);
        assert!(prefix_pending);

        let (forward, detach) = filter_main_detach_sequence(&mut prefix_pending, b"\x11");
        assert!(forward.is_empty());
        assert!(detach);
        assert!(!prefix_pending);
    }

    #[test]
    fn main_detach_filter_forwards_unmatched_prefix() {
        let mut prefix_pending = false;
        let (forward, detach) = filter_main_detach_sequence(&mut prefix_pending, b"\x10");
        assert!(forward.is_empty());
        assert!(!detach);
        assert!(prefix_pending);

        let (forward, detach) = filter_main_detach_sequence(&mut prefix_pending, b"x");
        assert_eq!(forward, b"\x10x");
        assert!(!detach);
        assert!(!prefix_pending);
    }

    // -----------------------------------------------------------------------
    // session_user_and_home tests (Phase 2: numeric UID support)
    // -----------------------------------------------------------------------

    #[test]
    fn session_user_and_home_returns_numeric_uid_as_user() {
        use openshell_core::policy::{
            FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy,
        };
        let policy = SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy {
                run_as_user: Some("1000".into()),
                run_as_group: None,
            },
        };
        let (user, home) = session_user_and_home(&policy, None);
        assert_eq!(user, "1000");
        // Numeric UID has no passwd entry — defaults to /sandbox.
        assert_eq!(home, "/sandbox");
    }

    #[test]
    fn session_user_and_home_uses_driver_workspace_when_supplied() {
        use openshell_core::policy::{
            FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy,
        };
        let policy = SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy {
                run_as_user: Some("1234".into()),
                run_as_group: Some("1235".into()),
            },
        };

        let (user, home) = session_user_and_home(&policy, Some("/workspace/project"));
        assert_eq!(user, "1234");
        assert_eq!(home, "/workspace/project");
    }

    #[test]
    fn session_user_and_home_returns_name_from_passwd() {
        use openshell_core::policy::{
            FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy,
        };
        let policy = SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy {
                run_as_user: Some("sandbox".into()),
                run_as_group: None,
            },
        };
        let (user, home) = session_user_and_home(&policy, None);
        assert_eq!(user, "sandbox");
        // Name-based — should resolve via passwd (or /home/{user}).
        assert!(!home.is_empty());
    }

    #[test]
    fn session_user_and_home_defaults_to_sandbox_when_empty() {
        use openshell_core::policy::{
            FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy,
        };
        let policy = SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy {
                run_as_user: Some(String::new()),
                run_as_group: None,
            },
        };
        let (user, home) = session_user_and_home(&policy, None);
        assert_eq!(user, "sandbox");
        assert_eq!(home, "/sandbox");
    }

    #[test]
    fn session_user_and_home_defaults_to_sandbox_when_none() {
        use openshell_core::policy::{
            FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy,
        };
        let policy = SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy {
                run_as_user: None,
                run_as_group: None,
            },
        };
        let (user, home) = session_user_and_home(&policy, None);
        assert_eq!(user, "sandbox");
        assert_eq!(home, "/sandbox");
    }

    #[test]
    fn session_user_and_home_handles_large_numeric_uid() {
        use openshell_core::policy::{
            FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy,
        };
        let policy = SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy {
                run_as_user: Some("1000660000".into()),
                run_as_group: None,
            },
        };
        let (user, home) = session_user_and_home(&policy, None);
        assert_eq!(user, "1000660000");
        assert_eq!(home, "/sandbox");
    }

    /// `install_pre_exec_no_pty` runs drop_privileges and succeeds when the
    /// current user/group is already the configured one (no actual uid change).
    ///
    /// This exercises the pre_exec hook end-to-end without needing root: a policy
    /// with no run_as_user/group is a no-op when the process is already unprivileged.
    #[cfg(unix)]
    #[test]
    fn pre_exec_always_calls_drop_privileges() {
        use openshell_core::policy::{
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
        if rustix::process::geteuid().is_root() {
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
            ResolvedProcessIdentity::default(),
            ProcessEnforcementMode::Full,
            #[cfg(target_os = "linux")]
            Some(
                sandbox::linux::prepare(
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
            ),
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

    /// SSH pre-exec uses the numeric identity resolved from OCI metadata rather
    /// than looking the preserved declaration up through host NSS.
    #[cfg(unix)]
    #[test]
    fn pre_exec_uses_resolved_oci_identity() {
        use openshell_core::policy::{
            FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy, SandboxPolicy,
        };

        if rustix::process::geteuid().is_root() {
            return;
        }

        let policy = SandboxPolicy {
            version: 0,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy {
                run_as_user: Some("__oci_user_not_in_host_nss__".into()),
                run_as_group: Some("__oci_group_not_in_host_nss__".into()),
            },
        };
        let resolved = ResolvedProcessIdentity::new(
            Some(rustix::process::geteuid().as_raw()),
            Some(rustix::process::getegid().as_raw()),
        );

        let mut cmd = Command::new("echo");
        cmd.arg("resolved-identity-ok");
        cmd.stdout(Stdio::piped());

        unsafe_pty::install_pre_exec_no_pty(
            &mut cmd,
            policy,
            None,
            None,
            resolved,
            ProcessEnforcementMode::Full,
            #[cfg(target_os = "linux")]
            None,
        );

        let output = cmd
            .spawn()
            .expect("spawn should use resolved numeric identity")
            .wait_with_output()
            .expect("wait should succeed");
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "resolved-identity-ok"
        );
    }

    // -----------------------------------------------------------------------
    // direct-tcpip authorization wiring (SEC-007)
    //
    // The `loopback_host_*` tests above cover the predicate in isolation.
    // These drive the real `russh::server::Handler` over an in-memory duplex
    // so the deny path itself is covered: channel-open authorization travels
    // through a reply handle rather than the handler's return value, so a
    // handler that never rejects anything still type-checks and still passes
    // every predicate test.
    // -----------------------------------------------------------------------

    struct AcceptAnyServerKey;

    impl russh::client::Handler for AcceptAnyServerKey {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &russh::keys::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    fn forwarding_test_policy() -> SandboxPolicy {
        use openshell_core::policy::{
            FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy,
        };

        SandboxPolicy {
            version: 0,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy {
                run_as_user: None,
                run_as_group: None,
            },
        }
    }

    /// Serve `SshHandler` on one end of an in-memory duplex and return an
    /// authenticated client handle for the other end.
    ///
    /// The handler gets `netns_fd: None` so `connect_in_netns` performs a plain
    /// TCP connect, making the forwarding path reachable without a network
    /// namespace.
    async fn authenticated_test_client_with_main(
        main_session: Arc<MainSession>,
    ) -> russh::client::Handle<AcceptAnyServerKey> {
        // Scoped so the `!Send` ThreadRng is dropped before the first await.
        let host_key = {
            let mut rng = rand::rng();
            PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("host key")
        };
        let mut server_config = russh::server::Config {
            auth_rejection_time: Duration::from_millis(1),
            ..Default::default()
        };
        server_config.keys.push(host_key);

        let handler = SshHandler::new(
            forwarding_test_policy(),
            ResolvedWorkspace::default(),
            None,
            None,
            None,
            ProviderCredentialState::from_child_env_snapshot(0, HashMap::new()),
            HashMap::new(),
            ResolvedProcessIdentity::default(),
            ProcessEnforcementMode::NetworkOnly,
            main_session,
        );

        let (server_stream, client_stream) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            if let Ok(session) =
                russh::server::run_stream(Arc::new(server_config), server_stream, handler).await
            {
                let _ = session.await;
            }
        });

        let mut client = russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            client_stream,
            AcceptAnyServerKey,
        )
        .await
        .expect("SSH handshake should complete over the duplex");

        let auth = client
            .authenticate_none("sandbox")
            .await
            .expect("auth_none should not error");
        assert!(
            matches!(auth, russh::client::AuthResult::Success),
            "sandbox SSH server accepts the none auth method"
        );

        client
    }

    async fn authenticated_test_client() -> russh::client::Handle<AcceptAnyServerKey> {
        authenticated_test_client_with_main(MainSession::inert()).await
    }

    #[tokio::test]
    async fn abrupt_transport_drop_releases_main_input_lease() {
        let main_session = MainSession::inert();
        let client = authenticated_test_client_with_main(Arc::clone(&main_session)).await;
        let channel = client.channel_open_session().await.expect("open session");
        channel
            .request_subsystem(true, "openshell-main")
            .await
            .expect("attach main subsystem");
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match main_session.acquire_input() {
                    Err(_) => break,
                    Ok((owner, _)) => main_session.release_input(owner),
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("main subsystem should acquire canonical input lease");

        drop(channel);
        drop(client);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if main_session.acquire_input().is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("handler drop should release canonical input lease");
    }

    #[tokio::test]
    async fn main_attachment_closes_naturally_after_terminal_delivery() {
        let main_session = MainSession::inert();
        let client = authenticated_test_client_with_main(Arc::clone(&main_session)).await;
        let mut channel = client.channel_open_session().await.expect("open session");
        channel
            .request_subsystem(true, "openshell-main")
            .await
            .expect("attach main subsystem");
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match main_session.acquire_input() {
                    Err(_) => break,
                    Ok((owner, _)) => main_session.release_input(owner),
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("main subsystem should register its attachment");

        assert!(main_session.finish(7, false).await);
        main_session.mark_terminal_reported();

        let exit_status = tokio::time::timeout(Duration::from_secs(1), async {
            let mut exit_status = None;
            loop {
                match channel.wait().await {
                    Some(russh::ChannelMsg::ExitStatus {
                        exit_status: status,
                    }) => {
                        exit_status = Some(status);
                    }
                    Some(russh::ChannelMsg::Close) => break exit_status,
                    None => panic!("main channel ended without a close message"),
                    Some(_) => {}
                }
            }
        })
        .await
        .expect("main channel should deliver its exit status");
        assert_eq!(exit_status, Some(7));
        drop(channel);
        drop(client);

        tokio::time::timeout(
            Duration::from_secs(1),
            main_session.wait_for_terminal_attachments(),
        )
        .await
        .expect("peer channel close should release terminal delivery");
    }

    #[tokio::test]
    async fn main_subsystem_applies_initial_pty_dimensions() {
        let (main_session, _slave) = MainSession::terminal_for_test();
        let client = authenticated_test_client_with_main(Arc::clone(&main_session)).await;
        let channel = client.channel_open_session().await.expect("open session");
        channel
            .request_pty(true, "xterm-256color", 200, 60, 1600, 900, &[])
            .await
            .expect("request PTY");
        channel
            .request_subsystem(true, "openshell-main")
            .await
            .expect("attach main subsystem");

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if main_session.terminal_size_for_test() == (200, 60) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("main subsystem should apply the initial PTY dimensions");
    }

    #[tokio::test]
    async fn direct_tcpip_rejects_non_loopback_destination() {
        let client = authenticated_test_client().await;

        let err = client
            .channel_open_direct_tcpip("10.0.0.1", 80, "127.0.0.1", 0)
            .await
            .expect_err("forwarding to a non-loopback host must be refused");

        assert!(
            matches!(
                err,
                russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited)
            ),
            "expected AdministrativelyProhibited, got {err:?}"
        );
    }

    #[tokio::test]
    async fn direct_tcpip_rejects_port_above_tcp_range() {
        let client = authenticated_test_client().await;

        // 65_537 truncates to port 1 when cast to u16, so the guard has to
        // reject it before the cast rather than forward to a privileged port.
        let err = client
            .channel_open_direct_tcpip("127.0.0.1", 65_537, "127.0.0.1", 0)
            .await
            .expect_err("a port outside the TCP range must be refused");

        assert!(
            matches!(
                err,
                russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited)
            ),
            "expected AdministrativelyProhibited, got {err:?}"
        );
    }

    #[tokio::test]
    async fn direct_tcpip_forwards_to_loopback_listener() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback echo listener");
        let port = listener.local_addr().expect("listener address").port();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = socket.read(&mut buf).await
                    && n > 0
                {
                    let _ = socket.write_all(&buf[..n]).await;
                }
            }
        });

        let client = authenticated_test_client().await;
        let channel = client
            .channel_open_direct_tcpip("127.0.0.1", u32::from(port), "127.0.0.1", 0)
            .await
            .expect("forwarding to a loopback listener must be allowed");

        let mut stream = channel.into_stream();
        stream.write_all(b"ping").await.expect("write to channel");

        let mut echoed = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
            .await
            .expect("relayed response should arrive before the timeout")
            .expect("read from channel");
        assert_eq!(&echoed, b"ping", "bytes round-trip through the tunnel");
    }
}
