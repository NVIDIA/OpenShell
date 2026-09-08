// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Embedded SSH server for sandbox access.

use crate::main_session::{MainOutput, MainSession};
#[cfg(unix)]
use libc;
use miette::{IntoDiagnostic, Result};
use openshell_core::VERSION;
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, SeverityId, SshActivityBuilder, StatusId, ocsf_emit,
};
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Handle, Session};
use russh::{ChannelId, ChannelOpenFailure, Sig};
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::Duration;
use tokio::net::UnixListener;
use tracing::warn;

const NO_LOGIN_SHELL_ENV: (&str, &str) = ("OPENSHELL_NO_LOGIN_SHELL", "1");
const MAIN_DETACH_PREFIX: u8 = 0x10;
const MAIN_DETACH_KEY: u8 = 0x11;

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
    shared_socket: bool,
) -> Result<SshServerInit> {
    let mut rng = rand::rng();
    let host_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).into_diagnostic()?;

    let mut config = russh::server::Config {
        server_id: russh::SshId::Standard(Cow::Owned(format!("SSH-2.0-OpenShell_{VERSION}"))),
        auth_rejection_time: Duration::from_secs(1),
        ..Default::default()
    };
    config.keys.push(host_key);

    let config = Arc::new(config);
    let ca_paths = ca_file_paths.as_ref().map(|p| Arc::new(p.clone()));

    // A driver may place the supervisor in another container, so an explicitly
    // shared socket retains group access. Linux abstract sockets avoid a
    // workload-replaceable filesystem inode.
    let abstract_socket = crate::unix_socket::is_abstract(listen_path);
    if !abstract_socket && let Some(parent) = listen_path.parent() {
        std::fs::create_dir_all(parent).into_diagnostic()?;
        #[cfg(unix)]
        if !shared_socket {
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
    // local relay connections authenticate the listener with SO_PEERCRED.
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
    ca_file_paths: Option<(PathBuf, PathBuf)>,
    shared_socket: bool,
    port_forward: Arc<dyn openshell_isolation_interface::contract::BoundaryPortForward>,
    boundary_exec: Arc<dyn openshell_isolation_interface::contract::BoundaryExec>,
    main_session: Option<Arc<MainSession>>,
) -> Result<()> {
    let (listener, config, _ca_paths) =
        match ssh_server_init(&listen_path, &ca_file_paths, shared_socket) {
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

    let mut consecutive_resource_errors = 0;
    let mut consecutive_unknown_errors = 0;
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                consecutive_resource_errors = 0;
                consecutive_unknown_errors = 0;
                let config = config.clone();
                let port_forward = port_forward.clone();
                let boundary_exec = boundary_exec.clone();
                let main_session = main_session.clone();

                tokio::spawn(async move {
                    if let Err(err) =
                        handle_connection(stream, config, port_forward, boundary_exec, main_session)
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
            Err(error) => match classify_ssh_accept_error(
                &error,
                &mut consecutive_resource_errors,
                &mut consecutive_unknown_errors,
            ) {
                SshAcceptAction::Terminal => {
                    return Err(error).into_diagnostic();
                }
                SshAcceptAction::Retry { backoff, severity } => {
                    ocsf_emit!(
                        SshActivityBuilder::new(openshell_ocsf::ctx::ctx())
                            .activity(ActivityId::Fail)
                            .severity(severity)
                            .status(StatusId::Failure)
                            .message(format!(
                                "SSH accept error (retrying in {}ms): {error}",
                                backoff.as_millis()
                            ))
                            .build()
                    );
                    tokio::time::sleep(backoff).await;
                }
            },
        }
    }
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
    error: &std::io::Error,
    consecutive_resource_errors: &mut u32,
    consecutive_unknown_errors: &mut u32,
) -> SshAcceptAction {
    #[cfg(unix)]
    if matches!(
        error.raw_os_error(),
        Some(libc::EBADF | libc::EINVAL | libc::ENOTSOCK)
    ) {
        return SshAcceptAction::Terminal;
    }

    #[cfg(unix)]
    if matches!(
        error.raw_os_error(),
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
        let resource_pressure = matches!(
            error.raw_os_error(),
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM | libc::ENOSR)
        );
        if resource_pressure {
            *consecutive_resource_errors = consecutive_resource_errors.saturating_add(1);
            let backoff_ms = 100_u64
                .saturating_mul(1_u64 << (*consecutive_resource_errors).min(7).saturating_sub(1))
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

    #[cfg(target_os = "linux")]
    if error.raw_os_error() == Some(libc::ENONET) {
        *consecutive_resource_errors = 0;
        *consecutive_unknown_errors = 0;
        return SshAcceptAction::Retry {
            backoff: Duration::from_millis(100),
            severity: SeverityId::Low,
        };
    }

    *consecutive_resource_errors = 0;
    *consecutive_unknown_errors = consecutive_unknown_errors.saturating_add(1);
    if *consecutive_unknown_errors >= MAX_CONSECUTIVE_UNKNOWN_SSH_ACCEPT_ERRORS {
        SshAcceptAction::Terminal
    } else {
        SshAcceptAction::Retry {
            backoff: Duration::from_millis(100),
            severity: SeverityId::Low,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: tokio::net::UnixStream,
    config: Arc<russh::server::Config>,
    port_forward: Arc<dyn openshell_isolation_interface::contract::BoundaryPortForward>,
    boundary_exec: Arc<dyn openshell_isolation_interface::contract::BoundaryExec>,
    main_session: Option<Arc<MainSession>>,
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

    let handler = SshHandler::new(port_forward, boundary_exec, main_session);
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
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct ChannelState {
    input_sender: Option<InputSender>,
    process: Option<Arc<dyn openshell_isolation_interface::contract::BoundaryProcess>>,
    terminal: Option<Arc<dyn openshell_isolation_interface::contract::BoundaryTerminal>>,
    pty_request: Option<PtyRequest>,
    no_login_shell: bool,
    main_input_owner: Option<u64>,
    main_attached: bool,
    main_read_only: bool,
    main_detach_prefix_pending: bool,
    main_output_task: Option<tokio::task::AbortHandle>,
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
    /// Loopback port-forward, injected by the orchestrator (RFC 0012). In-pod
    /// this connects from inside the workload netns; a delegated backend
    /// tunnels into its guest. The handler does not know which.
    port_forward: Arc<dyn openshell_isolation_interface::contract::BoundaryPortForward>,
    boundary_exec: Arc<dyn openshell_isolation_interface::contract::BoundaryExec>,
    main_session: Option<Arc<MainSession>>,
    channels: HashMap<ChannelId, ChannelState>,
}

impl Drop for SshHandler {
    fn drop(&mut self) {
        let Some(main_session) = self.main_session.as_ref() else {
            return;
        };
        for state in self.channels.values_mut() {
            if state.main_attached {
                main_session.end_terminal_attachment();
            }
            if let Some(owner) = state.main_input_owner.take() {
                main_session.release_input(owner);
            }
            if let Some(task) = state.main_output_task.take() {
                task.abort();
            }
        }
    }
}

impl SshHandler {
    fn new(
        port_forward: Arc<dyn openshell_isolation_interface::contract::BoundaryPortForward>,
        boundary_exec: Arc<dyn openshell_isolation_interface::contract::BoundaryExec>,
        main_session: Option<Arc<MainSession>>,
    ) -> Self {
        Self {
            port_forward,
            boundary_exec,
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
        if let Some(mut state) = self.channels.remove(&channel) {
            if state.main_attached
                && let Some(main_session) = self.main_session.as_ref()
            {
                main_session.end_terminal_attachment();
                if let Some(owner) = state.main_input_owner.take() {
                    main_session.release_input(owner);
                }
                if let Some(task) = state.main_output_task.take() {
                    task.abort();
                }
                return Ok(());
            }
            if let Some(process) = state.process {
                // Channel ownership defines the exec lifetime. Closing an SSH
                // channel must not strand an in-boundary process.
                let _ = process.terminate().await;
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

        let target = direct_tcpip_target(host_to_connect, port_to_connect);
        if target.is_none() {
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
        let port = u16::try_from(port_to_connect).expect("port range checked above");
        let target = target.expect("loopback target checked above");
        let port_forward = self.port_forward.clone();
        reply.accept().await;

        tokio::spawn(async move {
            let mut tcp_stream = match port_forward.connect(target).await {
                Ok(stream) => stream,
                Err(err) => {
                    ocsf_emit!(
                        SshActivityBuilder::new(openshell_ocsf::ctx::ctx())
                            .activity(ActivityId::Fail)
                            .severity(SeverityId::Low)
                            .status(StatusId::Failure)
                            .message(format!(
                                "direct-tcpip: failed to connect to {host}:{port}: {err}"
                            ))
                            .build()
                    );
                    let _ = channel.close().await;
                    return;
                }
            };

            let mut channel_stream = channel.into_stream();

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
            if let Some(main_session) = self.main_session.as_ref() {
                main_session
                    .resize(col_width, row_height, pixel_width, pixel_height)
                    .await;
            }
        } else if let Some(terminal) = state.terminal.as_ref()
            && let Err(e) = terminal
                .resize(to_u16(col_width.max(1)), to_u16(row_height.max(1)))
                .await
        {
            warn!("failed to resize PTY for channel {channel:?}: {e}");
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
        self.start_shell(channel, session.handle(), None).await?;
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
        self.start_shell(channel, session.handle(), Some(command))
            .await?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "openshell-main" {
            let Some(main_session) = self.main_session.clone() else {
                session.channel_failure(channel)?;
                return Ok(());
            };
            if !begin_main_attachment(&main_session, self.channels.contains_key(&channel)) {
                session.channel_failure(channel)?;
                return Ok(());
            }
            let state = self
                .channels
                .get_mut(&channel)
                .expect("main channel existence checked above");
            state.main_attached = true;
            if let Some(pty) = state.pty_request.take() {
                main_session
                    .resize(
                        pty.col_width,
                        pty.row_height,
                        pty.pixel_width,
                        pty.pixel_height,
                    )
                    .await;
            }
            let (input, warning) = if state.main_read_only {
                (None, None)
            } else {
                match main_session.acquire_input() {
                    Ok((owner, input)) => {
                        state.main_input_owner = Some(owner);
                        (Some(InputSender::Main(input)), None)
                    }
                    Err(error) => (None, Some(error)),
                }
            };
            state.input_sender = input;
            state.main_detach_prefix_pending = false;
            let mut output = main_session.subscribe();
            let terminal_delivery = main_session.clone();
            let handle = session.handle();
            session.channel_success(channel)?;
            if let Some(error) = warning {
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
                        Ok(MainOutput::Exit(code)) => {
                            terminal_delivery.wait_for_terminal_reported().await;
                            let _ =
                                send_main_output(&handle, channel, MainOutput::Exit(code)).await;
                            break;
                        }
                        Ok(event) => {
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
        } else if name == "sftp" {
            session.channel_success(channel)?;
            // sftp-server speaks the SFTP binary protocol over stdin/stdout,
            // which the boundary executor preserves as separate pipes. This enables
            // modern scp (SFTP-based, OpenSSH 9.0+) and SFTP clients to
            // transfer files into and out of the sandbox.
            self.start_exec_spec(
                channel,
                session.handle(),
                openshell_isolation_interface::contract::ExecSpec {
                    program: "/usr/lib/openssh/sftp-server".to_string(),
                    args: vec![],
                    env: vec![],
                    workdir: None,
                    pty: false,
                },
            )
            .await?;
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
        // environment is controlled via policy. The login-shell opt-out is a
        // supervisor signal carried over SSH because the protocol has no
        // native field for it.
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
        let (forward, detach) = if state.main_attached {
            filter_main_detach_sequence(&mut state.main_detach_prefix_pending, data)
        } else {
            (data.to_vec(), false)
        };
        let error = (!forward.is_empty())
            .then(|| state.input_sender.as_ref()?.send(forward).err())
            .flatten();
        if state.main_attached && (detach || error.is_some()) {
            self.close_main_attachment(channel, session.handle(), error)
                .await;
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
                && let Some(main_session) = self.main_session.as_ref()
            {
                // A canonical process outlives one SSH attachment. Release
                // this channel's lease without closing process stdin so a
                // replacement attachment can become the input owner.
                main_session.release_input(owner);
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
        if self
            .channels
            .get(&channel)
            .is_some_and(|state| state.main_attached)
        {
            let signal = match signal {
                Sig::HUP => Some(nix::sys::signal::Signal::SIGHUP),
                Sig::INT => Some(nix::sys::signal::Signal::SIGINT),
                Sig::KILL => Some(nix::sys::signal::Signal::SIGKILL),
                Sig::QUIT => Some(nix::sys::signal::Signal::SIGQUIT),
                Sig::TERM => Some(nix::sys::signal::Signal::SIGTERM),
                _ => None,
            };
            if let (Some(signal), Some(main_session)) = (signal, self.main_session.as_ref())
                && let Err(error) = main_session.signal_group(signal).await
            {
                warn!(%error, ?signal, "failed to signal canonical main process group");
            }
            return Ok(());
        }
        let Some(process) = self
            .channels
            .get(&channel)
            .and_then(|state| state.process.clone())
        else {
            return Ok(());
        };
        let signal = match signal {
            Sig::HUP => Some(openshell_isolation_interface::contract::BoundarySignal::Hup),
            Sig::INT => Some(openshell_isolation_interface::contract::BoundarySignal::Int),
            Sig::KILL => Some(openshell_isolation_interface::contract::BoundarySignal::Kill),
            Sig::TERM => Some(openshell_isolation_interface::contract::BoundarySignal::Term),
            _ => None,
        };
        if let Some(signal) = signal
            && let Err(error) = process.signal(signal).await
        {
            warn!(%error, ?signal, "failed to signal boundary exec process");
        }
        Ok(())
    }
}

impl SshHandler {
    async fn start_shell(
        &mut self,
        channel: ChannelId,
        handle: Handle,
        command: Option<String>,
    ) -> anyhow::Result<()> {
        let state = self
            .channels
            .get_mut(&channel)
            .ok_or_else(|| anyhow::anyhow!("start_shell on unknown channel {channel:?}"))?;
        let no_login_shell = state.no_login_shell;
        let pty = state.pty_request.take();
        let pty_requested = pty.is_some();
        let (program, args) = command.map_or_else(
            || {
                if pty_requested {
                    ("/bin/bash".to_string(), vec!["-i".to_string()])
                } else {
                    ("/bin/bash".to_string(), vec![])
                }
            },
            |command| {
                (
                    "/bin/bash".to_string(),
                    vec![login_shell_flag(no_login_shell).to_string(), command],
                )
            },
        );
        let env = pty
            .as_ref()
            .map(|request| vec![("TERM".to_string(), request.term.clone())])
            .unwrap_or_default();
        self.start_exec_spec(
            channel,
            handle,
            openshell_isolation_interface::contract::ExecSpec {
                program,
                args,
                env,
                workdir: None,
                pty: pty_requested,
            },
        )
        .await?;
        if let (Some(pty), Some(terminal)) = (
            pty,
            self.channels
                .get(&channel)
                .and_then(|state| state.terminal.as_ref()),
        ) {
            terminal
                .resize(to_u16(pty.col_width.max(1)), to_u16(pty.row_height.max(1)))
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        }
        Ok(())
    }

    async fn start_exec_spec(
        &mut self,
        channel: ChannelId,
        handle: Handle,
        spec: openshell_isolation_interface::contract::ExecSpec,
    ) -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut exec = self
            .boundary_exec
            .exec(spec)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let state = self
            .channels
            .get_mut(&channel)
            .ok_or_else(|| anyhow::anyhow!("exec on unknown channel {channel:?}"))?;
        state.process = Some(exec.process.clone());
        state.terminal = exec.terminal.take();

        if let Some(mut stdin) = exec.stdin.take() {
            let (sender, receiver) = mpsc::channel::<Vec<u8>>();
            let runtime = tokio::runtime::Handle::current();
            std::thread::spawn(move || {
                while let Ok(bytes) = receiver.recv() {
                    if runtime.block_on(stdin.write_all(&bytes)).is_err() {
                        break;
                    }
                }
            });
            state.input_sender = Some(InputSender::Process(sender));
        }

        let mut stdout = exec.stdout;
        let stdout_handle = handle.clone();
        let stdout_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 4096];
            loop {
                match stdout.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(size) => {
                        let _ = stdout_handle.data(channel, buffer[..size].to_vec()).await;
                    }
                }
            }
        });
        let stderr_task = exec.stderr.map(|mut stderr| {
            let stderr_handle = handle.clone();
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                loop {
                    match stderr.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(size) => {
                            let _ = stderr_handle
                                .extended_data(channel, 1, buffer[..size].to_vec())
                                .await;
                        }
                    }
                }
            })
        });
        tokio::spawn(async move {
            let status = exec.process.wait().await;
            let _ = stdout_task.await;
            if let Some(task) = stderr_task {
                let _ = task.await;
            }
            let code = match status {
                Ok(openshell_isolation_interface::contract::BoundaryExitStatus::Exited(code)) => {
                    code.max(0).cast_unsigned()
                }
                Ok(openshell_isolation_interface::contract::BoundaryExitStatus::Signaled(
                    signal,
                )) => (128_i32.saturating_add(signal)).max(0).cast_unsigned(),
                Err(_) => 1,
            };
            let _ = handle.eof(channel).await;
            let _ = handle.exit_status_request(channel, code).await;
            let _ = handle.close(channel).await;
        });
        Ok(())
    }

    async fn close_main_attachment(
        &mut self,
        channel: ChannelId,
        handle: Handle,
        error: Option<&str>,
    ) {
        if let Some(state) = self.channels.get_mut(&channel) {
            if state.main_attached {
                if let Some(main_session) = self.main_session.as_ref() {
                    main_session.end_terminal_attachment();
                }
                state.main_attached = false;
            }
            if let Some(owner) = state.main_input_owner.take()
                && let Some(main_session) = self.main_session.as_ref()
            {
                main_session.release_input(owner);
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
}

fn begin_main_attachment(main_session: &MainSession, channel_exists: bool) -> bool {
    channel_exists && main_session.begin_terminal_attachment().is_ok()
}

async fn send_main_output(handle: &Handle, channel: ChannelId, event: MainOutput) -> bool {
    match event {
        MainOutput::Stdout(data) => handle.data(channel, data).await.is_ok(),
        MainOutput::Stderr(data) => handle.extended_data(channel, 1, data).await.is_ok(),
        MainOutput::Exit(code) => {
            let eof = handle.eof(channel).await.is_ok();
            let status = handle
                .exit_status_request(channel, code.max(0).unsigned_abs())
                .await
                .is_ok();
            let close = handle.close(channel).await.is_ok();
            eof && status && close
        }
    }
}

const fn login_shell_flag(no_login_shell: bool) -> &'static str {
    if no_login_shell { "-c" } else { "-lc" }
}

#[allow(dead_code)]
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

/// Resolve a (loopback-validated) destination host string to an `IpAddr`,
/// mapping `localhost` to `127.0.0.1`.
///
/// Returns `None` for anything that does not parse to an IP, so
/// [`LoopbackTarget::new`] never sees a hostname.
fn loopback_ip(host: &str) -> Option<std::net::IpAddr> {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if host.eq_ignore_ascii_case("localhost") {
        return Some(std::net::Ipv4Addr::LOCALHOST.into());
    }
    host.parse().ok()
}

fn direct_tcpip_target(
    host: &str,
    port: u32,
) -> Option<openshell_isolation_interface::contract::LoopbackTarget> {
    if !is_loopback_host(host) {
        return None;
    }
    let port = u16::try_from(port).ok()?;
    let ip = loopback_ip(host)?;
    openshell_isolation_interface::contract::LoopbackTarget::new(ip, port).ok()
}

#[cfg(test)]
#[allow(
    clippy::doc_markdown,
    reason = "Test documentation references protocol and API identifiers."
)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::process::{Command, Stdio};

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

    struct TestPortForward;

    #[async_trait::async_trait]
    impl openshell_isolation_interface::contract::BoundaryPortForward for TestPortForward {
        async fn connect(
            &self,
            target: openshell_isolation_interface::contract::LoopbackTarget,
        ) -> std::result::Result<
            openshell_isolation_interface::contract::BoundaryDuplexStream,
            openshell_isolation_interface::contract::BackendError,
        > {
            let stream = tokio::net::TcpStream::connect((target.host(), target.port()))
                .await
                .map_err(|error| {
                    openshell_isolation_interface::contract::BackendError::Process(
                        error.to_string(),
                    )
                })?;
            Ok(Box::new(stream))
        }
    }

    struct RejectingExec;

    #[async_trait::async_trait]
    impl openshell_isolation_interface::contract::BoundaryExec for RejectingExec {
        async fn exec(
            &self,
            _spec: openshell_isolation_interface::contract::ExecSpec,
        ) -> std::result::Result<
            openshell_isolation_interface::contract::ExecSession,
            openshell_isolation_interface::contract::BackendError,
        > {
            Err(
                openshell_isolation_interface::contract::BackendError::Unsupported(
                    "exec is not used by direct-tcpip tests".into(),
                ),
            )
        }
    }

    async fn authenticated_test_client() -> russh::client::Handle<AcceptAnyServerKey> {
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
            Arc::new(TestPortForward),
            Arc::new(RejectingExec),
            Some(MainSession::inert()),
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
        assert!(matches!(auth, russh::client::AuthResult::Success));
        client
    }

    #[cfg(unix)]
    #[test]
    fn transient_accept_errors_retry_with_bounded_backoff() {
        let mut resource_errors = 0;
        let mut unknown_errors = 0;
        let aborted = std::io::Error::from_raw_os_error(libc::ECONNABORTED);
        assert_eq!(
            classify_ssh_accept_error(&aborted, &mut resource_errors, &mut unknown_errors),
            SshAcceptAction::Retry {
                backoff: Duration::from_millis(100),
                severity: SeverityId::Low,
            }
        );

        let exhausted = std::io::Error::from_raw_os_error(libc::EMFILE);
        let first =
            classify_ssh_accept_error(&exhausted, &mut resource_errors, &mut unknown_errors);
        let second =
            classify_ssh_accept_error(&exhausted, &mut resource_errors, &mut unknown_errors);
        assert_eq!(
            first,
            SshAcceptAction::Retry {
                backoff: Duration::from_millis(100),
                severity: SeverityId::Medium,
            }
        );
        assert_eq!(
            second,
            SshAcceptAction::Retry {
                backoff: Duration::from_millis(200),
                severity: SeverityId::Medium,
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn invalid_listener_accept_error_is_terminal() {
        let mut resource_errors = 0;
        let mut unknown_errors = 0;
        let error = std::io::Error::from_raw_os_error(libc::EBADF);
        assert_eq!(
            classify_ssh_accept_error(&error, &mut resource_errors, &mut unknown_errors),
            SshAcceptAction::Terminal
        );
    }

    #[test]
    fn direct_tcpip_target_rejects_non_loopback_and_out_of_range_ports() {
        assert!(direct_tcpip_target("10.0.0.1", 80).is_none());
        assert!(direct_tcpip_target("127.0.0.1", 65_537).is_none());
    }

    #[test]
    fn direct_tcpip_target_accepts_loopback_destinations() {
        let target = direct_tcpip_target("localhost", 8_080).expect("loopback target");
        assert_eq!(
            target.host(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(target.port(), 8_080);
    }

    #[tokio::test]
    async fn direct_tcpip_handler_rejects_invalid_destinations() {
        for (host, port) in [("10.0.0.1", 80), ("127.0.0.1", 65_537)] {
            let client = authenticated_test_client().await;
            let error = client
                .channel_open_direct_tcpip(host, port, "127.0.0.1", 0)
                .await
                .expect_err("invalid forwarding destination must be refused");
            assert!(matches!(
                error,
                russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited)
            ));
        }
    }

    #[tokio::test]
    async fn direct_tcpip_handler_relays_loopback_bytes() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback echo listener");
        let port = listener.local_addr().expect("listener address").port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept forwarded stream");
            let mut payload = [0_u8; 4];
            socket.read_exact(&mut payload).await.expect("read payload");
            socket.write_all(&payload).await.expect("echo payload");
        });

        let client = authenticated_test_client().await;
        let channel = client
            .channel_open_direct_tcpip("127.0.0.1", u32::from(port), "127.0.0.1", 0)
            .await
            .expect("loopback forwarding must be allowed");
        let mut stream = channel.into_stream();
        stream.write_all(b"ping").await.expect("write channel");
        let mut echoed = [0_u8; 4];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
            .await
            .expect("forwarded response timeout")
            .expect("read channel");
        assert_eq!(&echoed, b"ping");
    }

    #[tokio::test]
    async fn main_attachment_accepts_declared_session_after_process_exit() {
        let main_session = MainSession::inert();
        assert!(main_session.finish(23, true).await);
        assert!(main_session.finished());

        assert!(begin_main_attachment(&main_session, true));
        let mut output = main_session.subscribe();
        assert!(matches!(
            output.recv().await.expect("retained terminal status"),
            MainOutput::Exit(23)
        ));
        main_session.end_terminal_attachment();
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
    async fn ssh_server_init_keeps_private_socket() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("ssh");
        std::fs::create_dir_all(&parent).unwrap();
        set_file_mode(&parent, 0o775);
        let socket = parent.join("ssh.sock");

        let (listener, _, _) = ssh_server_init(&socket, &None, false).unwrap();
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

        let (listener, _, _) = ssh_server_init(&socket, &None, true).unwrap();
        drop(listener);

        assert_eq!(file_mode(&parent), 0o775);
        assert_eq!(file_mode(&socket), 0o660);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ssh_server_abstract_socket_cannot_be_replaced_while_bound() {
        let socket = PathBuf::from(format!("@openshell-ssh-test-{}", uuid::Uuid::new_v4()));
        let (listener, _, _) = ssh_server_init(&socket, &None, true).unwrap();

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
}
