// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! WebSocket relay for opt-in credential placeholder rewriting and message policy.
//!
//! The relay parses only client-to-server frames. Server-to-client bytes stay
//! raw passthrough so inspection and rewriting cannot expose response payloads.

use crate::l7::relay::{L7EvalContext, evaluate_l7_request};
use crate::l7::{EnforcementMode, L7RequestInfo};
use crate::opa::{PolicyGenerationGuard, TunnelPolicyEngine};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use miette::{IntoDiagnostic, Result, miette};
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_core::secrets::{SecretResolver, contains_reserved_credential_marker};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, NetworkActivityBuilder, SeverityId, StatusId,
    ocsf_emit,
};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_TEXT_MESSAGE_BYTES: usize = openshell_supervisor_middleware::MAX_MIDDLEWARE_PAYLOAD_BYTES;
pub const MAX_CONCURRENT_WEBSOCKET_ASSEMBLIES: usize = 32;
pub const MAX_QUEUED_WEBSOCKET_ASSEMBLIES: usize = MAX_CONCURRENT_WEBSOCKET_ASSEMBLIES * 2;
const MAX_RAW_FRAME_PAYLOAD_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MESSAGE_FRAGMENTS: usize = 4096;
const TEXT_MESSAGE_ASSEMBLY_IDLE_TIMEOUT: StdDuration = StdDuration::from_secs(30);
const TEXT_MESSAGE_ASSEMBLY_TOTAL_TIMEOUT: StdDuration = StdDuration::from_secs(120);
const TEXT_MESSAGE_FORWARD_TOTAL_TIMEOUT: StdDuration = StdDuration::from_secs(120);
const COPY_BUF_SIZE: usize = 8192;
const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;
const CREDENTIAL_ENDPOINT_MISMATCH: &str = "websocket credential endpoint mismatch";

#[derive(Clone, Debug)]
pub struct WebSocketAssemblyBudget {
    active: Arc<Semaphore>,
    waiters: Arc<Semaphore>,
}

impl Default for WebSocketAssemblyBudget {
    fn default() -> Self {
        Self::new(
            MAX_CONCURRENT_WEBSOCKET_ASSEMBLIES,
            MAX_QUEUED_WEBSOCKET_ASSEMBLIES,
        )
    }
}

impl WebSocketAssemblyBudget {
    pub fn new(active: usize, waiters: usize) -> Self {
        Self {
            active: Arc::new(Semaphore::new(active)),
            waiters: Arc::new(Semaphore::new(waiters)),
        }
    }

    pub async fn reserve(&self) -> Result<WebSocketAssemblyAdmissionOutcome> {
        if let Ok(active) = Arc::clone(&self.active).try_acquire_owned() {
            return Ok(WebSocketAssemblyAdmissionOutcome::Admitted(
                WebSocketAssemblyAdmission { _active: active },
            ));
        }
        let Ok(waiter) = Arc::clone(&self.waiters).try_acquire_owned() else {
            return Ok(WebSocketAssemblyAdmissionOutcome::QueueExhausted);
        };
        let active = Arc::clone(&self.active)
            .acquire_owned()
            .await
            .map_err(|_| miette!("websocket assembly admission semaphore closed"))?;
        drop(waiter);
        Ok(WebSocketAssemblyAdmissionOutcome::Admitted(
            WebSocketAssemblyAdmission { _active: active },
        ))
    }
}

#[derive(Debug)]
pub struct WebSocketAssemblyAdmission {
    _active: OwnedSemaphorePermit,
}

#[derive(Debug)]
pub enum WebSocketAssemblyAdmissionOutcome {
    Admitted(WebSocketAssemblyAdmission),
    QueueExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebSocketTerminationCause {
    PeerDisconnect,
    PolicyReload,
    CapacityExhausted,
    MiddlewareDenial,
    MiddlewareFailure,
    PolicyDenial,
    InvalidUtf8,
    ProtocolError,
    MessageTooBig,
}

impl WebSocketTerminationCause {
    fn close_code(self) -> Option<u16> {
        match self {
            Self::PeerDisconnect => None,
            Self::PolicyReload => Some(1012),
            Self::CapacityExhausted => Some(1013),
            Self::MiddlewareDenial | Self::MiddlewareFailure | Self::PolicyDenial => Some(1008),
            Self::InvalidUtf8 => Some(1007),
            Self::ProtocolError => Some(1002),
            Self::MessageTooBig => Some(1009),
        }
    }

    fn session_end_reason(self) -> openshell_core::proto::WebSocketSessionEndReason {
        match self {
            Self::PeerDisconnect => {
                openshell_core::proto::WebSocketSessionEndReason::PeerDisconnect
            }
            Self::PolicyReload => openshell_core::proto::WebSocketSessionEndReason::PolicyReload,
            Self::MiddlewareDenial => {
                openshell_core::proto::WebSocketSessionEndReason::MiddlewareDenial
            }
            Self::PolicyDenial => openshell_core::proto::WebSocketSessionEndReason::PolicyDenial,
            Self::CapacityExhausted | Self::MiddlewareFailure => {
                openshell_core::proto::WebSocketSessionEndReason::MiddlewareFailure
            }
            Self::InvalidUtf8 | Self::ProtocolError | Self::MessageTooBig => {
                openshell_core::proto::WebSocketSessionEndReason::ProtocolError
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameFailureClass {
    MessageAssemblyIdleTimeout,
    MessageAssemblyTotalTimeout,
    InvalidUtf8,
    InvalidFragmentation,
    InvalidCloseFrame,
    InvalidControlFrame,
    InvalidLength,
    ReservedOpcode,
    UnmaskedClientFrame,
    RsvBits,
    ProtocolError,
}

impl FrameFailureClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::MessageAssemblyIdleTimeout => "message_assembly_idle_timeout",
            Self::MessageAssemblyTotalTimeout => "message_assembly_total_timeout",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::InvalidFragmentation => "invalid_fragmentation",
            Self::InvalidCloseFrame => "invalid_close_frame",
            Self::InvalidControlFrame => "invalid_control_frame",
            Self::InvalidLength => "invalid_length",
            Self::ReservedOpcode => "reserved_opcode",
            Self::UnmaskedClientFrame => "unmasked_client_frame",
            Self::RsvBits => "rsv_bits",
            Self::ProtocolError => "protocol_error",
        }
    }
}

#[derive(Debug)]
struct WebSocketTermination {
    cause: WebSocketTerminationCause,
    failure_class: Option<FrameFailureClass>,
    error: miette::Report,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssemblyTimeoutKind {
    Idle,
    Total,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameErrorKind {
    PeerDisconnect,
    Protocol(FrameFailureClass),
    InvalidUtf8,
    MessageTooBig,
    AssemblyTimeout(AssemblyTimeoutKind),
}

#[derive(Debug)]
struct FrameError {
    kind: FrameErrorKind,
    error: miette::Report,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl FrameError {
    fn peer_io(context: &str, error: std::io::Error) -> Self {
        Self {
            kind: FrameErrorKind::PeerDisconnect,
            error: miette!("{context}: {error}"),
        }
    }

    fn peer_disconnect(error: miette::Report) -> Self {
        Self {
            kind: FrameErrorKind::PeerDisconnect,
            error,
        }
    }

    fn protocol(failure_class: FrameFailureClass, error: miette::Report) -> Self {
        Self {
            kind: FrameErrorKind::Protocol(failure_class),
            error,
        }
    }

    fn invalid_utf8(error: miette::Report) -> Self {
        Self {
            kind: FrameErrorKind::InvalidUtf8,
            error,
        }
    }

    fn message_too_big(error: miette::Report) -> Self {
        Self {
            kind: FrameErrorKind::MessageTooBig,
            error,
        }
    }

    fn assembly_timeout(kind: AssemblyTimeoutKind) -> Self {
        let error = match kind {
            AssemblyTimeoutKind::Idle => {
                miette!("websocket text message assembly idle timeout")
            }
            AssemblyTimeoutKind::Total => {
                miette!("websocket text message assembly total timeout")
            }
        };
        Self {
            kind: FrameErrorKind::AssemblyTimeout(kind),
            error,
        }
    }
}

impl From<FrameError> for WebSocketTermination {
    fn from(frame_error: FrameError) -> Self {
        let (cause, failure_class) = match frame_error.kind {
            FrameErrorKind::PeerDisconnect => (WebSocketTerminationCause::PeerDisconnect, None),
            FrameErrorKind::Protocol(failure_class) => (
                WebSocketTerminationCause::ProtocolError,
                Some(failure_class),
            ),
            FrameErrorKind::InvalidUtf8 => (
                WebSocketTerminationCause::InvalidUtf8,
                Some(FrameFailureClass::InvalidUtf8),
            ),
            FrameErrorKind::MessageTooBig => (
                WebSocketTerminationCause::MessageTooBig,
                Some(FrameFailureClass::InvalidLength),
            ),
            FrameErrorKind::AssemblyTimeout(kind) => (
                WebSocketTerminationCause::ProtocolError,
                Some(match kind {
                    AssemblyTimeoutKind::Idle => FrameFailureClass::MessageAssemblyIdleTimeout,
                    AssemblyTimeoutKind::Total => FrameFailureClass::MessageAssemblyTotalTimeout,
                }),
            ),
        };
        Self {
            cause,
            failure_class,
            error: frame_error.error,
        }
    }
}

#[derive(Debug)]
enum WebSocketDecompressionError {
    MessageTooBig(miette::Report),
    Protocol(miette::Report),
}

type WebSocketRelayResult<T> = std::result::Result<T, WebSocketTermination>;
type FrameResult<T> = std::result::Result<T, FrameError>;

fn terminate(cause: WebSocketTerminationCause, error: miette::Report) -> WebSocketTermination {
    WebSocketTermination {
        cause,
        failure_class: None,
        error,
    }
}

#[derive(Debug)]
struct FrameHeader {
    fin: bool,
    rsv: u8,
    opcode: u8,
    masked: bool,
    payload_len: u64,
    mask_key: Option<[u8; 4]>,
    raw_header: Vec<u8>,
}

#[derive(Debug)]
enum FragmentState {
    None,
    Text(TextMessageAssembly),
    Binary {
        fragment_count: usize,
        coverage: Vec<openshell_supervisor_middleware::WebSocketCoverage>,
    },
}

/// One admitted client text message while its complete logical payload is
/// being assembled.
///
/// Keeping the admission permit with the buffer and deadlines makes every
/// timeout and terminal parser error release shared middleware capacity through
/// ordinary ownership. The total deadline includes interleaved control frames;
/// the idle deadline resets only when a client read makes progress.
#[derive(Debug)]
struct TextMessageAssembly {
    payload: Vec<u8>,
    compressed: bool,
    fragment_count: usize,
    assembly_admission: WebSocketAssemblyAdmission,
    admission: Option<openshell_supervisor_middleware::MiddlewareWorkAdmission>,
    total_deadline: tokio::time::Instant,
}

impl TextMessageAssembly {
    fn new(
        compressed: bool,
        assembly_admission: WebSocketAssemblyAdmission,
        admission: Option<openshell_supervisor_middleware::MiddlewareWorkAdmission>,
    ) -> Self {
        Self {
            payload: Vec::new(),
            compressed,
            fragment_count: 1,
            assembly_admission,
            admission,
            total_deadline: tokio::time::Instant::now() + TEXT_MESSAGE_ASSEMBLY_TOTAL_TIMEOUT,
        }
    }

    async fn read_some<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        buffer: &mut [u8],
    ) -> FrameResult<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let idle_deadline = tokio::time::Instant::now() + TEXT_MESSAGE_ASSEMBLY_IDLE_TIMEOUT;
        tokio::select! {
            biased;
            () = tokio::time::sleep_until(self.total_deadline) => {
                Err(FrameError::assembly_timeout(AssemblyTimeoutKind::Total))
            }
            () = tokio::time::sleep_until(idle_deadline) => {
                Err(FrameError::assembly_timeout(AssemblyTimeoutKind::Idle))
            }
            result = reader.read(buffer) => {
                result.map_err(|error| FrameError::peer_io("websocket client read failed", error))
            },
        }
    }

    async fn read_exact<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        buffer: &mut [u8],
    ) -> FrameResult<()> {
        let mut filled = 0;
        while filled < buffer.len() {
            let read = self.read_some(reader, &mut buffer[filled..]).await?;
            if read == 0 {
                return Err(FrameError::peer_disconnect(miette!(
                    "websocket payload ended before declared length"
                )));
            }
            filled += read;
        }
        Ok(())
    }

    async fn read_payload<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        frame: &FrameHeader,
    ) -> FrameResult<()> {
        let next = read_masked_payload(reader, frame, Some(self)).await?;
        append_text_fragment(&mut self.payload, next)
    }

    fn ensure_payload_fits(&self, frame: &FrameHeader) -> FrameResult<()> {
        let frame_len = usize::try_from(frame.payload_len).map_err(|_| {
            FrameError::message_too_big(miette!("websocket text frame is too large to buffer"))
        })?;
        let complete_len = self.payload.len().checked_add(frame_len).ok_or_else(|| {
            FrameError::message_too_big(miette!("websocket text message length overflow"))
        })?;
        if complete_len > MAX_TEXT_MESSAGE_BYTES {
            return Err(FrameError::message_too_big(miette!(
                "websocket text message exceeds {MAX_TEXT_MESSAGE_BYTES} byte limit"
            )));
        }
        Ok(())
    }

    fn add_fragment(&mut self) -> FrameResult<()> {
        self.fragment_count = self.fragment_count.saturating_add(1);
        if self.fragment_count > MAX_MESSAGE_FRAGMENTS {
            return Err(FrameError::protocol(
                FrameFailureClass::InvalidFragmentation,
                miette!("websocket message exceeds {MAX_MESSAGE_FRAGMENTS} fragment limit"),
            ));
        }
        Ok(())
    }

    async fn within_total<T>(
        &self,
        future: impl Future<Output = FrameResult<T>>,
    ) -> FrameResult<T> {
        tokio::time::timeout_at(self.total_deadline, future)
            .await
            .map_err(|_| FrameError::assembly_timeout(AssemblyTimeoutKind::Total))?
    }

    fn into_parts(
        self,
    ) -> (
        Vec<u8>,
        bool,
        WebSocketAssemblyAdmission,
        Option<openshell_supervisor_middleware::MiddlewareWorkAdmission>,
    ) {
        (
            self.payload,
            self.compressed,
            self.assembly_admission,
            self.admission,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WebSocketCompression {
    None,
    PermessageDeflate,
}

pub(super) struct InspectionOptions<'a> {
    pub(super) engine: &'a TunnelPolicyEngine,
    pub(super) ctx: &'a L7EvalContext,
    pub(super) enforcement: EnforcementMode,
    pub(super) target: String,
    pub(super) query_params: HashMap<String, Vec<String>>,
    pub(super) graphql_policy: bool,
}

pub(super) struct RelayOptions<'a> {
    pub(super) policy_name: &'a str,
    pub(super) assembly_budget: WebSocketAssemblyBudget,
    pub(super) resolver: Option<&'a SecretResolver>,
    pub(super) generation_guard: Option<&'a PolicyGenerationGuard>,
    pub(super) provider_credentials: Option<&'a ProviderCredentialState>,
    pub(super) target: &'a str,
    pub(super) inspector: Option<InspectionOptions<'a>>,
    pub(super) compression: WebSocketCompression,
    pub(super) middleware_session: Option<openshell_supervisor_middleware::WebSocketSession>,
    pub(super) middleware_context: Option<&'a L7EvalContext>,
    pub(super) deny_uninspected_credentials: bool,
}

/// Relay an upgraded WebSocket connection with optional client text inspection,
/// credential rewriting, and strict permessage-deflate handling.
pub(super) async fn relay_with_options<C, U>(
    client: &mut C,
    upstream: &mut U,
    overflow: Vec<u8>,
    host: &str,
    port: u16,
    mut options: RelayOptions<'_>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    if !overflow.is_empty() {
        client_write.write_all(&overflow).await.into_diagnostic()?;
        client_write.flush().await.into_diagnostic()?;
    }

    let client_to_server = relay_client_to_server(
        &mut client_read,
        &mut upstream_write,
        host,
        port,
        &mut options,
    );
    let server_to_client = async {
        tokio::io::copy(&mut upstream_read, &mut client_write)
            .await
            .map_err(|error| {
                terminate(
                    WebSocketTerminationCause::PeerDisconnect,
                    miette!("websocket upstream relay ended: {error}"),
                )
            })?;
        client_write.flush().await.map_err(|error| {
            terminate(
                WebSocketTerminationCause::PeerDisconnect,
                miette!("websocket client relay ended: {error}"),
            )
        })?;
        Ok::<_, WebSocketTermination>(
            openshell_core::proto::WebSocketSessionEndReason::PeerDisconnect,
        )
    };

    let result = tokio::select! {
        result = client_to_server => result,
        result = server_to_client => result,
    };
    if let Err(termination) = &result {
        observe_termination(host, port, options.policy_name, termination);
    }
    if let Err(termination) = &result {
        let error = termination.error.to_string();
        if error.contains(CREDENTIAL_ENDPOINT_MISMATCH) {
            emit_credential_endpoint_mismatch(host, port, options.policy_name);
            let _ = write_policy_violation_close(&mut client_write).await;
        } else if error.contains("credential") {
            if let Some(code) = termination.cause.close_code() {
                let payload = code.to_be_bytes();
                let _ = write_unmasked_close(&mut client_write, &payload).await;
            }
        } else if let Some(code) = termination.cause.close_code() {
            let payload = code.to_be_bytes();
            let _ = write_masked_close(&mut upstream_write, &payload).await;
            let _ = write_unmasked_close(&mut client_write, &payload).await;
        }
    }
    if let Some(session) = options.middleware_session.take() {
        let reason = match &result {
            Ok(reason) => *reason,
            Err(termination) => termination.cause.session_end_reason(),
        };
        session.end(reason).await;
    }
    let _ = upstream_write.shutdown().await;
    let _ = client_write.shutdown().await;
    result.map(|_| ()).map_err(|termination| termination.error)
}

async fn write_policy_violation_close<W: AsyncWrite + Unpin>(writer: &mut W) -> Result<()> {
    let reason = b"credential endpoint mismatch";
    let mut frame = Vec::with_capacity(reason.len() + 4);
    frame.push(0x80 | OPCODE_CLOSE);
    frame.push(u8::try_from(reason.len() + 2).expect("close reason fits one-byte length"));
    frame.extend_from_slice(&1008u16.to_be_bytes());
    frame.extend_from_slice(reason);
    writer.write_all(&frame).await.into_diagnostic()?;
    writer.flush().await.into_diagnostic()
}

fn emit_credential_endpoint_mismatch(host: &str, port: u16, policy_name: &str) {
    ocsf_emit!(
        NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Fail)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::High)
            .status(StatusId::Failure)
            .dst_endpoint(Endpoint::from_domain(host, port))
            .firewall_rule(policy_name, "credential-binding")
            .message(format!(
                "WebSocket credential use denied: credential is not authorized for {host}:{port}"
            ))
            .status_detail("credential_endpoint_mismatch")
            .build()
    );
    ocsf_emit!(crate::l7::build_credential_endpoint_mismatch_finding(
        policy_name,
        host,
        Some("websocket"),
        "Provider credential endpoint binding mismatch; WebSocket closed",
    ));
}

async fn relay_client_to_server<R, W>(
    reader: &mut R,
    writer: &mut W,
    host: &str,
    port: u16,
    options: &mut RelayOptions<'_>,
) -> WebSocketRelayResult<openshell_core::proto::WebSocketSessionEndReason>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut fragments = FragmentState::None;
    let mut close_seen = false;
    loop {
        let assembly = match &fragments {
            FragmentState::Text(assembly) => Some(assembly),
            FragmentState::None | FragmentState::Binary { .. } => None,
        };
        let Some(frame) = read_frame_header(reader, assembly)
            .await
            .map_err(WebSocketTermination::from)?
        else {
            let _ = writer.shutdown().await;
            return Ok(if close_seen {
                openshell_core::proto::WebSocketSessionEndReason::NormalClose
            } else {
                openshell_core::proto::WebSocketSessionEndReason::PeerDisconnect
            });
        };

        if close_seen {
            return Err(FrameError::protocol(
                FrameFailureClass::InvalidCloseFrame,
                miette!("websocket frame received after close frame"),
            )
            .into());
        }

        validate_frame_header(&frame, &fragments, options.compression)
            .map_err(WebSocketTermination::from)?;

        if matches!(
            frame.opcode,
            OPCODE_TEXT | OPCODE_BINARY | OPCODE_CONTINUATION
        ) {
            ensure_generation_current(host, port, options)?;
        }

        match frame.opcode {
            OPCODE_TEXT => {
                if frame.payload_len > MAX_TEXT_MESSAGE_BYTES as u64 {
                    return Err(FrameError::message_too_big(miette!(
                        "websocket text message exceeds {MAX_TEXT_MESSAGE_BYTES} byte limit"
                    ))
                    .into());
                }
                let assembly_outcome =
                    options.assembly_budget.reserve().await.map_err(|error| {
                        terminate(WebSocketTerminationCause::CapacityExhausted, error)
                    })?;
                let assembly_admission = match assembly_outcome {
                    WebSocketAssemblyAdmissionOutcome::Admitted(admission) => admission,
                    WebSocketAssemblyAdmissionOutcome::QueueExhausted => {
                        return Err(terminate(
                            WebSocketTerminationCause::CapacityExhausted,
                            miette!(
                                "websocket assembly admission queue is full; refusing additional buffered work"
                            ),
                        ));
                    }
                };
                ensure_generation_current(host, port, options)?;
                let admission = if let Some(session) = options.middleware_session.as_mut() {
                    let message_admission = session.admit_message().await.map_err(|error| {
                        terminate(WebSocketTerminationCause::MiddlewareFailure, error)
                    })?;
                    match message_admission {
                        openshell_supervisor_middleware::WebSocketMessageAdmission::Bypass => {
                            options.middleware_session.take();
                            None
                        }
                        openshell_supervisor_middleware::WebSocketMessageAdmission::Inspect(
                            admission,
                        ) => Some(admission),
                    }
                } else {
                    None
                };
                ensure_generation_current(host, port, options)?;
                let compressed = frame.rsv == 0x40;
                let mut assembly =
                    TextMessageAssembly::new(compressed, assembly_admission, admission);
                assembly
                    .read_payload(reader, &frame)
                    .await
                    .map_err(WebSocketTermination::from)?;
                ensure_generation_current(host, port, options)?;
                if frame.fin {
                    let (payload, compressed, assembly_admission, admission) =
                        assembly.into_parts();
                    relay_text_payload(
                        writer,
                        &frame,
                        payload,
                        assembly_admission,
                        admission,
                        false,
                        compressed,
                        host,
                        port,
                        options,
                    )
                    .await?;
                } else {
                    fragments = FragmentState::Text(assembly);
                }
            }
            OPCODE_CONTINUATION => {
                if let FragmentState::Text(assembly) = &mut fragments {
                    assembly
                        .add_fragment()
                        .map_err(WebSocketTermination::from)?;
                    if frame.payload_len > MAX_TEXT_MESSAGE_BYTES as u64 {
                        return Err(FrameError::message_too_big(miette!(
                            "websocket text message exceeds {MAX_TEXT_MESSAGE_BYTES} byte limit"
                        ))
                        .into());
                    }
                    assembly
                        .ensure_payload_fits(&frame)
                        .map_err(WebSocketTermination::from)?;
                    assembly
                        .read_payload(reader, &frame)
                        .await
                        .map_err(WebSocketTermination::from)?;
                    ensure_generation_current(host, port, options)?;
                    if frame.fin {
                        let FragmentState::Text(assembly) =
                            std::mem::replace(&mut fragments, FragmentState::None)
                        else {
                            unreachable!("validated text continuation state")
                        };
                        let (complete, was_compressed, assembly_admission, admission) =
                            assembly.into_parts();
                        relay_text_payload(
                            writer,
                            &frame,
                            complete,
                            assembly_admission,
                            admission,
                            true,
                            was_compressed,
                            host,
                            port,
                            options,
                        )
                        .await?;
                    }
                } else if let FragmentState::Binary {
                    fragment_count,
                    coverage,
                } = &mut fragments
                {
                    *fragment_count = fragment_count.saturating_add(1);
                    if *fragment_count > MAX_MESSAGE_FRAGMENTS {
                        return Err(FrameError::protocol(
                            FrameFailureClass::InvalidFragmentation,
                            miette!(
                                "websocket message exceeds {MAX_MESSAGE_FRAGMENTS} fragment limit"
                            ),
                        )
                        .into());
                    }
                    copy_raw_frame_payload(reader, writer, &frame)
                        .await
                        .map_err(WebSocketTermination::from)?;
                    let fragment_size = usize::try_from(frame.payload_len).unwrap_or(usize::MAX);
                    for record in coverage.iter_mut() {
                        record.original_size = record.original_size.saturating_add(fragment_size);
                    }
                    if frame.fin {
                        let FragmentState::Binary { coverage, .. } =
                            std::mem::replace(&mut fragments, FragmentState::None)
                        else {
                            unreachable!("validated binary continuation state")
                        };
                        if let Some(ctx) = options.middleware_context {
                            crate::l7::middleware::emit_websocket_coverage(ctx, &coverage);
                        }
                    }
                } else {
                    return Err(FrameError::protocol(
                        FrameFailureClass::InvalidFragmentation,
                        miette!("websocket continuation frame without active fragmented message"),
                    )
                    .into());
                }
            }
            OPCODE_BINARY => {
                if options.deny_uninspected_credentials {
                    emit_uninspected_credential_denial(
                        host,
                        port,
                        options.policy_name,
                        "websocket-binary",
                    );
                    return Err(terminate(
                        WebSocketTerminationCause::PolicyDenial,
                        miette!("websocket binary frame denied for credentialed endpoint"),
                    ));
                }
                let initial_size = usize::try_from(frame.payload_len).unwrap_or(usize::MAX);
                let coverage = options
                    .middleware_session
                    .as_mut()
                    .map(|session| {
                        session.observe_unsupported_message(
                            openshell_supervisor_middleware::WebSocketMessageType::Binary,
                            initial_size,
                        )
                    })
                    .unwrap_or_default();
                copy_raw_frame_payload(reader, writer, &frame)
                    .await
                    .map_err(WebSocketTermination::from)?;
                if frame.fin
                    && let Some(ctx) = options.middleware_context
                {
                    crate::l7::middleware::emit_websocket_coverage(ctx, &coverage);
                } else if !frame.fin {
                    fragments = FragmentState::Binary {
                        fragment_count: 1,
                        coverage,
                    };
                }
            }
            OPCODE_CLOSE | OPCODE_PING | OPCODE_PONG => {
                let control_result = match &fragments {
                    FragmentState::Text(assembly) => {
                        assembly
                            .within_total(relay_control_frame(
                                reader,
                                writer,
                                &frame,
                                Some(assembly),
                            ))
                            .await
                    }
                    FragmentState::None | FragmentState::Binary { .. } => {
                        relay_control_frame(reader, writer, &frame, None).await
                    }
                };
                control_result.map_err(WebSocketTermination::from)?;
                if frame.opcode == OPCODE_CLOSE {
                    close_seen = true;
                }
            }
            _ => unreachable!("validated opcode"),
        }
    }
}

async fn read_exact_for_assembly<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
    assembly: Option<&TextMessageAssembly>,
) -> FrameResult<()> {
    match assembly {
        Some(assembly) => assembly.read_exact(reader, buffer).await,
        None => reader
            .read_exact(buffer)
            .await
            .map(|_| ())
            .map_err(|error| FrameError::peer_io("websocket client read failed", error)),
    }
}

async fn read_frame_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    assembly: Option<&TextMessageAssembly>,
) -> FrameResult<Option<FrameHeader>> {
    let mut first = [0u8; 1];
    let first_read = match assembly {
        Some(assembly) => assembly.read_some(reader, &mut first).await,
        None => reader
            .read(&mut first)
            .await
            .map_err(|error| FrameError::peer_io("websocket client read failed", error)),
    };
    let first = match first_read {
        Ok(0) => return Ok(None),
        Ok(_) => first[0],
        Err(error) => return Err(error),
    };
    let mut second = [0u8; 1];
    read_exact_for_assembly(reader, &mut second, assembly).await?;
    let second = second[0];

    let mut raw_header = vec![first, second];
    let len_code = second & 0x7F;
    let payload_len = match len_code {
        0..=125 => u64::from(len_code),
        126 => {
            let mut bytes = [0u8; 2];
            read_exact_for_assembly(reader, &mut bytes, assembly).await?;
            raw_header.extend_from_slice(&bytes);
            let len = u64::from(u16::from_be_bytes(bytes));
            if len < 126 {
                return Err(FrameError::protocol(
                    FrameFailureClass::InvalidLength,
                    miette!("websocket frame uses non-minimal 16-bit extended length"),
                ));
            }
            len
        }
        127 => {
            let mut bytes = [0u8; 8];
            read_exact_for_assembly(reader, &mut bytes, assembly).await?;
            if bytes[0] & 0x80 != 0 {
                return Err(FrameError::protocol(
                    FrameFailureClass::InvalidLength,
                    miette!("websocket frame uses non-canonical 64-bit length"),
                ));
            }
            raw_header.extend_from_slice(&bytes);
            let len = u64::from_be_bytes(bytes);
            if u16::try_from(len).is_ok() {
                return Err(FrameError::protocol(
                    FrameFailureClass::InvalidLength,
                    miette!("websocket frame uses non-minimal 64-bit extended length"),
                ));
            }
            len
        }
        _ => unreachable!("7-bit length code"),
    };

    let masked = second & 0x80 != 0;
    let mask_key = if masked {
        let mut key = [0u8; 4];
        read_exact_for_assembly(reader, &mut key, assembly).await?;
        raw_header.extend_from_slice(&key);
        Some(key)
    } else {
        None
    };

    Ok(Some(FrameHeader {
        fin: first & 0x80 != 0,
        rsv: first & 0x70,
        opcode: first & 0x0F,
        masked,
        payload_len,
        mask_key,
        raw_header,
    }))
}

fn validate_frame_header(
    frame: &FrameHeader,
    fragments: &FragmentState,
    compression: WebSocketCompression,
) -> FrameResult<()> {
    if !valid_rsv_bits(frame, fragments, compression) {
        return Err(FrameError::protocol(
            FrameFailureClass::RsvBits,
            miette!("websocket frame has unsupported RSV bits or extension state"),
        ));
    }
    if !frame.masked {
        return Err(FrameError::protocol(
            FrameFailureClass::UnmaskedClientFrame,
            miette!("websocket client frame is not masked"),
        ));
    }
    if !matches!(
        frame.opcode,
        OPCODE_CONTINUATION
            | OPCODE_TEXT
            | OPCODE_BINARY
            | OPCODE_CLOSE
            | OPCODE_PING
            | OPCODE_PONG
    ) {
        return Err(FrameError::protocol(
            FrameFailureClass::ReservedOpcode,
            miette!("websocket frame uses reserved opcode"),
        ));
    }
    if matches!(frame.opcode, OPCODE_CLOSE | OPCODE_PING | OPCODE_PONG) {
        if !frame.fin {
            return Err(FrameError::protocol(
                FrameFailureClass::InvalidControlFrame,
                miette!("websocket control frame is fragmented"),
            ));
        }
        if frame.payload_len > 125 {
            return Err(FrameError::protocol(
                FrameFailureClass::InvalidControlFrame,
                miette!("websocket control frame exceeds 125 bytes"),
            ));
        }
    }
    if matches!(frame.opcode, OPCODE_TEXT | OPCODE_BINARY)
        && !matches!(fragments, FragmentState::None)
    {
        return Err(FrameError::protocol(
            FrameFailureClass::InvalidFragmentation,
            miette!("websocket data frame started before previous fragmented message completed"),
        ));
    }
    if matches!(frame.opcode, OPCODE_CONTINUATION) && matches!(fragments, FragmentState::None) {
        return Err(FrameError::protocol(
            FrameFailureClass::InvalidFragmentation,
            miette!("websocket continuation frame without active fragmented message"),
        ));
    }
    if (frame.opcode == OPCODE_BINARY
        || (frame.opcode == OPCODE_CONTINUATION
            && matches!(fragments, FragmentState::Binary { .. })))
        && frame.payload_len > MAX_RAW_FRAME_PAYLOAD_BYTES
    {
        return Err(FrameError::protocol(
            FrameFailureClass::InvalidLength,
            miette!(
                "websocket binary frame exceeds {MAX_RAW_FRAME_PAYLOAD_BYTES} byte relay limit"
            ),
        ));
    }
    Ok(())
}

fn valid_rsv_bits(
    frame: &FrameHeader,
    fragments: &FragmentState,
    compression: WebSocketCompression,
) -> bool {
    if frame.rsv == 0 {
        return true;
    }
    if compression != WebSocketCompression::PermessageDeflate || frame.rsv != 0x40 {
        return false;
    }
    matches!(fragments, FragmentState::None) && matches!(frame.opcode, OPCODE_TEXT | OPCODE_BINARY)
}

async fn read_masked_payload<R: AsyncRead + Unpin>(
    reader: &mut R,
    frame: &FrameHeader,
    assembly: Option<&TextMessageAssembly>,
) -> FrameResult<Vec<u8>> {
    let payload_len = usize::try_from(frame.payload_len).map_err(|_| {
        FrameError::message_too_big(miette!("websocket text frame is too large to buffer"))
    })?;
    if payload_len > MAX_TEXT_MESSAGE_BYTES {
        return Err(FrameError::message_too_big(miette!(
            "websocket text message exceeds {MAX_TEXT_MESSAGE_BYTES} byte limit"
        )));
    }
    let mut payload = vec![0u8; payload_len];
    read_exact_for_assembly(reader, &mut payload, assembly).await?;
    let mask_key = frame.mask_key.ok_or_else(|| {
        FrameError::protocol(
            FrameFailureClass::UnmaskedClientFrame,
            miette!("websocket client frame is not masked"),
        )
    })?;
    apply_mask(&mut payload, mask_key);
    Ok(payload)
}

fn append_text_fragment(buffer: &mut Vec<u8>, next: Vec<u8>) -> FrameResult<()> {
    let new_len = buffer.len().checked_add(next.len()).ok_or_else(|| {
        FrameError::message_too_big(miette!("websocket text message length overflow"))
    })?;
    if new_len > MAX_TEXT_MESSAGE_BYTES {
        return Err(FrameError::message_too_big(miette!(
            "websocket text message exceeds {MAX_TEXT_MESSAGE_BYTES} byte limit"
        )));
    }
    buffer.extend_from_slice(&next);
    Ok(())
}

fn ensure_generation_current(
    host: &str,
    port: u16,
    options: &RelayOptions<'_>,
) -> WebSocketRelayResult<()> {
    ensure_generation_guard_current(host, port, options.policy_name, options.generation_guard)
}

fn ensure_generation_guard_current(
    host: &str,
    port: u16,
    policy_name: &str,
    generation_guard: Option<&PolicyGenerationGuard>,
) -> WebSocketRelayResult<()> {
    let Some(guard) = generation_guard else {
        return Ok(());
    };
    guard.ensure_current().map_err(|error| {
        crate::l7::relay::emit_policy_reload(guard, host, port, policy_name);
        terminate(WebSocketTerminationCause::PolicyReload, error)
    })
}

#[allow(clippy::too_many_arguments)]
async fn relay_text_payload<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &FrameHeader,
    payload: Vec<u8>,
    assembly_admission: WebSocketAssemblyAdmission,
    admission: Option<openshell_supervisor_middleware::MiddlewareWorkAdmission>,
    force_reframe: bool,
    compressed: bool,
    host: &str,
    port: u16,
    options: &mut RelayOptions<'_>,
) -> WebSocketRelayResult<()> {
    relay_text_payload_with_before_credential_write(
        writer,
        frame,
        payload,
        assembly_admission,
        admission,
        force_reframe,
        compressed,
        host,
        port,
        options,
        std::future::ready(()),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn relay_text_payload_with_before_credential_write<W, F>(
    writer: &mut W,
    frame: &FrameHeader,
    payload: Vec<u8>,
    _assembly_admission: WebSocketAssemblyAdmission,
    admission: Option<openshell_supervisor_middleware::MiddlewareWorkAdmission>,
    force_reframe: bool,
    compressed: bool,
    host: &str,
    port: u16,
    options: &mut RelayOptions<'_>,
    before_credential_write: F,
) -> WebSocketRelayResult<()>
where
    W: AsyncWrite + Unpin,
    F: Future<Output = ()>,
{
    ensure_generation_current(host, port, options)?;
    let message_payload = if compressed {
        decompress_permessage_deflate(&payload).map_err(|error| match error {
            WebSocketDecompressionError::MessageTooBig(error) => {
                WebSocketTermination::from(FrameError::message_too_big(error))
            }
            WebSocketDecompressionError::Protocol(error) => WebSocketTermination::from(
                FrameError::protocol(FrameFailureClass::ProtocolError, error),
            ),
        })?
    } else {
        payload
    };
    let mut text = String::from_utf8(message_payload).map_err(|_| {
        WebSocketTermination::from(FrameError::invalid_utf8(miette!(
            "websocket text message is not valid UTF-8"
        )))
    })?;
    let live_resolver = options.provider_credentials.map(|credentials| {
        let (resolver, revision) =
            credentials.resolver_for_endpoint_with_revision(host, port, options.target);
        (
            resolver,
            crate::l7::rest::CredentialGenerationGuard::new(credentials, revision),
        )
    });
    let resolver = live_resolver
        .as_ref()
        .map_or(options.resolver, |(resolver, _)| resolver.as_deref());
    if options.deny_uninspected_credentials
        && resolver.is_none()
        && contains_reserved_credential_marker(&text)
    {
        emit_uninspected_credential_denial(host, port, options.policy_name, "websocket-text");
        return Err(terminate(
            WebSocketTerminationCause::PolicyDenial,
            miette!("websocket credential placeholder denied because rewrite is disabled"),
        ));
    }

    // Built-in transport/GraphQL inspection sees the original unresolved
    // message. External transformations run next, then policy is re-evaluated
    // before credential material is introduced.
    if let Some(inspector) = options.inspector.as_ref() {
        inspect_websocket_text_message(host, port, options.policy_name, inspector, &text)?;
    }
    ensure_generation_current(host, port, options)?;

    let mut middleware_transformed = false;
    if let Some(session) = options.middleware_session.as_mut() {
        let admission = admission.ok_or_else(|| {
            terminate(
                WebSocketTerminationCause::MiddlewareFailure,
                miette!("websocket middleware message missing work admission"),
            )
        })?;
        let outcome = session.evaluate_text_admitted(text, admission).await;
        ensure_generation_current(host, port, options)?;
        if let Some(ctx) = options.middleware_context {
            crate::l7::middleware::emit_websocket_message_events(ctx, &outcome);
        }
        if !outcome.allowed {
            if outcome.platform_oversize {
                return Err(FrameError::message_too_big(miette!(
                    "websocket message over middleware platform capacity"
                ))
                .into());
            }
            let cause = if outcome.denial.is_some() {
                WebSocketTerminationCause::MiddlewareDenial
            } else {
                WebSocketTerminationCause::MiddlewareFailure
            };
            return Err(terminate(
                cause,
                miette!("websocket middleware denied message: {}", outcome.reason),
            ));
        }
        middleware_transformed = outcome
            .invocations
            .iter()
            .any(|invocation| invocation.transformed);
        text = outcome.payload;
    }

    if middleware_transformed && let Some(inspector) = options.inspector.as_ref() {
        inspect_websocket_text_message(host, port, options.policy_name, inspector, &text)?;
    }
    ensure_generation_current(host, port, options)?;

    let replacements = if let Some(resolver) = resolver {
        resolver
            .rewrite_websocket_text_placeholders(&mut text)
            .map_err(|error| {
                if error.is_endpoint_mismatch() {
                    terminate(
                        WebSocketTerminationCause::PolicyDenial,
                        miette!(CREDENTIAL_ENDPOINT_MISMATCH),
                    )
                } else {
                    terminate(
                        WebSocketTerminationCause::MiddlewareFailure,
                        miette!("websocket credential placeholder resolution failed"),
                    )
                }
            })?
    } else if contains_reserved_credential_marker(&text) {
        return Err(terminate(
            WebSocketTerminationCause::MiddlewareFailure,
            miette!("websocket credential placeholder resolution failed"),
        ));
    } else {
        0
    };
    ensure_generation_current(host, port, options)?;

    if replacements == 0 && !middleware_transformed && !force_reframe && !compressed {
        let mut payload = text.into_bytes();
        let mask_key = frame.mask_key.ok_or_else(|| {
            WebSocketTermination::from(FrameError::protocol(
                FrameFailureClass::UnmaskedClientFrame,
                miette!("websocket client frame is not masked"),
            ))
        })?;
        apply_mask(&mut payload, mask_key);
        return write_text_frame_guarded(
            writer,
            &frame.raw_header,
            &payload,
            host,
            port,
            options.policy_name,
            options.generation_guard,
        )
        .await;
    }

    if replacements > 0 {
        emit_rewrite_event(host, port, options.policy_name, replacements);
    }
    if replacements > 0 {
        before_credential_write.await;
        if let Some((_, guard)) = live_resolver {
            guard
                .ensure_current()
                .map_err(|error| terminate(WebSocketTerminationCause::PolicyDenial, error))?;
        }
        ensure_generation_current(host, port, options)?;
    }
    if compressed {
        let compressed_payload = compress_permessage_deflate(text.as_bytes()).map_err(|error| {
            WebSocketTermination::from(FrameError::protocol(
                FrameFailureClass::ProtocolError,
                error,
            ))
        })?;
        return write_masked_text_frame_guarded(
            writer,
            0x40,
            &compressed_payload,
            host,
            port,
            options.policy_name,
            options.generation_guard,
        )
        .await;
    }
    write_masked_text_frame_guarded(
        writer,
        0,
        text.as_bytes(),
        host,
        port,
        options.policy_name,
        options.generation_guard,
    )
    .await
}

fn emit_uninspected_credential_denial(host: &str, port: u16, policy_name: &str, surface: &str) {
    let event = NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Traffic)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::High)
        .status(StatusId::Failure)
        .dst_endpoint(Endpoint::from_domain(host, port))
        .firewall_rule(policy_name, "l7-websocket")
        .message(format!(
            "WebSocket credential traffic denied for {host}:{port}"
        ))
        .build();
    ocsf_emit!(event);
    crate::l7::emit_uninspected_credential_finding(host, policy_name, surface);
}

fn inspect_websocket_text_message(
    host: &str,
    port: u16,
    policy_name: &str,
    inspector: &InspectionOptions<'_>,
    text: &str,
) -> WebSocketRelayResult<()> {
    if inspector.graphql_policy {
        return inspect_graphql_websocket_message(host, port, policy_name, inspector, text);
    }

    let request_info = L7RequestInfo {
        action: "WEBSOCKET_TEXT".to_string(),
        target: inspector.target.clone(),
        query_params: inspector.query_params.clone(),
        graphql: None,
        jsonrpc: None,
    };
    let (allowed, reason) = evaluate_l7_request(inspector.engine, inspector.ctx, &request_info)
        .map_err(|error| terminate(WebSocketTerminationCause::PolicyReload, error))?;
    let decision = match (allowed, inspector.enforcement) {
        (true, _) => "allow",
        (false, EnforcementMode::Audit) => "audit",
        (false, EnforcementMode::Enforce) => "deny",
    };
    emit_websocket_l7_event(
        host,
        port,
        policy_name,
        &request_info,
        decision,
        &reason,
        None,
    );
    if !allowed && inspector.enforcement == EnforcementMode::Enforce {
        return Err(terminate(
            WebSocketTerminationCause::PolicyDenial,
            miette!("websocket text message denied by policy"),
        ));
    }
    Ok(())
}

fn inspect_graphql_websocket_message(
    host: &str,
    port: u16,
    policy_name: &str,
    inspector: &InspectionOptions<'_>,
    text: &str,
) -> WebSocketRelayResult<()> {
    match classify_graphql_websocket_message(text) {
        GraphqlWebSocketMessage::Control { message_type } => {
            let request_info = L7RequestInfo {
                action: "WEBSOCKET_CONTROL".to_string(),
                target: inspector.target.clone(),
                query_params: inspector.query_params.clone(),
                graphql: None,
                jsonrpc: None,
            };
            emit_websocket_l7_event(
                host,
                port,
                policy_name,
                &request_info,
                "allow",
                &format!("GraphQL WebSocket control message {message_type}"),
                None,
            );
            Ok(())
        }
        GraphqlWebSocketMessage::Operation {
            message_type,
            graphql,
        } => {
            let request_info = L7RequestInfo {
                action: "WEBSOCKET_TEXT".to_string(),
                target: inspector.target.clone(),
                query_params: inspector.query_params.clone(),
                graphql: Some(graphql.clone()),
                jsonrpc: None,
            };
            let parse_error_reason = graphql
                .error
                .as_deref()
                .map(|error| format!("GraphQL WebSocket message rejected: {error}"));
            let force_deny = parse_error_reason.is_some();
            let (allowed, reason) = if let Some(reason) = parse_error_reason {
                (false, reason)
            } else {
                evaluate_l7_request(inspector.engine, inspector.ctx, &request_info)
                    .map_err(|error| terminate(WebSocketTerminationCause::PolicyReload, error))?
            };
            let decision = match (allowed, inspector.enforcement) {
                (_, _) if force_deny => "deny",
                (true, _) => "allow",
                (false, EnforcementMode::Audit) => "audit",
                (false, EnforcementMode::Enforce) => "deny",
            };
            let reason = format!("graphql_ws_type={message_type} {reason}");
            emit_websocket_l7_event(
                host,
                port,
                policy_name,
                &request_info,
                decision,
                &reason,
                Some(&graphql),
            );
            if (!allowed && inspector.enforcement == EnforcementMode::Enforce) || force_deny {
                return Err(terminate(
                    WebSocketTerminationCause::PolicyDenial,
                    miette!("websocket GraphQL message denied by policy"),
                ));
            }
            Ok(())
        }
    }
}

#[derive(Debug)]
enum GraphqlWebSocketMessage {
    Control {
        message_type: String,
    },
    Operation {
        message_type: String,
        graphql: crate::l7::graphql::GraphqlRequestInfo,
    },
}

fn classify_graphql_websocket_message(text: &str) -> GraphqlWebSocketMessage {
    let value = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(value) => value,
        Err(err) => {
            return GraphqlWebSocketMessage::Operation {
                message_type: "unknown".to_string(),
                graphql: graphql_error(format!(
                    "GraphQL WebSocket message is not valid JSON: {err}"
                )),
            };
        }
    };
    let Some(obj) = value.as_object() else {
        return GraphqlWebSocketMessage::Operation {
            message_type: "unknown".to_string(),
            graphql: graphql_error("GraphQL WebSocket message must be a JSON object"),
        };
    };
    let Some(message_type) = obj.get("type").and_then(serde_json::Value::as_str) else {
        return GraphqlWebSocketMessage::Operation {
            message_type: "unknown".to_string(),
            graphql: graphql_error("GraphQL WebSocket message missing string type"),
        };
    };

    match message_type {
        "subscribe" | "start" => {
            if obj
                .get("id")
                .and_then(serde_json::Value::as_str)
                .is_none_or(str::is_empty)
            {
                return GraphqlWebSocketMessage::Operation {
                    message_type: message_type.to_string(),
                    graphql: graphql_error(
                        "GraphQL WebSocket operation message missing non-empty id",
                    ),
                };
            }
            let Some(payload) = obj.get("payload").filter(|value| value.is_object()) else {
                return GraphqlWebSocketMessage::Operation {
                    message_type: message_type.to_string(),
                    graphql: graphql_error(
                        "GraphQL WebSocket operation message missing object payload",
                    ),
                };
            };
            GraphqlWebSocketMessage::Operation {
                message_type: message_type.to_string(),
                graphql: crate::l7::graphql::classify_json_envelope_value(payload),
            }
        }
        "connection_init" | "connection_terminate" | "ping" | "pong" | "complete" | "stop" => {
            GraphqlWebSocketMessage::Control {
                message_type: message_type.to_string(),
            }
        }
        _ => GraphqlWebSocketMessage::Operation {
            message_type: message_type.to_string(),
            graphql: graphql_error(format!(
                "unsupported GraphQL WebSocket client message type {message_type:?}"
            )),
        },
    }
}

fn graphql_error(message: impl Into<String>) -> crate::l7::graphql::GraphqlRequestInfo {
    crate::l7::graphql::GraphqlRequestInfo {
        operations: Vec::new(),
        error: Some(message.into()),
    }
}

async fn relay_control_frame<R, W>(
    reader: &mut R,
    writer: &mut W,
    frame: &FrameHeader,
    assembly: Option<&TextMessageAssembly>,
) -> FrameResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let raw_payload_len = usize::try_from(frame.payload_len).map_err(|_| {
        FrameError::protocol(
            FrameFailureClass::InvalidControlFrame,
            miette!("websocket control frame payload length overflow"),
        )
    })?;
    let mut raw_payload = vec![0u8; raw_payload_len];
    read_exact_for_assembly(reader, &mut raw_payload, assembly).await?;

    if frame.opcode == OPCODE_CLOSE {
        let mut payload = raw_payload.clone();
        let mask_key = frame.mask_key.ok_or_else(|| {
            FrameError::protocol(
                FrameFailureClass::UnmaskedClientFrame,
                miette!("websocket client frame is not masked"),
            )
        })?;
        apply_mask(&mut payload, mask_key);
        validate_close_payload(&payload)?;
    }

    writer
        .write_all(&frame.raw_header)
        .await
        .map_err(|error| FrameError::peer_io("websocket upstream write failed", error))?;
    writer
        .write_all(&raw_payload)
        .await
        .map_err(|error| FrameError::peer_io("websocket upstream write failed", error))?;
    writer
        .flush()
        .await
        .map_err(|error| FrameError::peer_io("websocket upstream flush failed", error))?;
    Ok(())
}

fn validate_close_payload(payload: &[u8]) -> FrameResult<()> {
    if payload.len() == 1 {
        return Err(FrameError::protocol(
            FrameFailureClass::InvalidCloseFrame,
            miette!("websocket close frame payload cannot be exactly one byte"),
        ));
    }
    if payload.len() < 2 {
        return Ok(());
    }

    let code = u16::from_be_bytes([payload[0], payload[1]]);
    if !valid_close_code(code) {
        return Err(FrameError::protocol(
            FrameFailureClass::InvalidCloseFrame,
            miette!("websocket close frame uses invalid close code"),
        ));
    }
    if std::str::from_utf8(&payload[2..]).is_err() {
        return Err(FrameError::invalid_utf8(miette!(
            "websocket close frame reason is not valid UTF-8"
        )));
    }
    Ok(())
}

fn valid_close_code(code: u16) -> bool {
    (matches!(code, 1000..=1014) && !matches!(code, 1004..=1006)) || (3000..=4999).contains(&code)
}

async fn copy_raw_frame_payload<R, W>(
    reader: &mut R,
    writer: &mut W,
    frame: &FrameHeader,
) -> FrameResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&frame.raw_header)
        .await
        .map_err(|error| FrameError::peer_io("websocket upstream write failed", error))?;
    let mut remaining = frame.payload_len;
    let mut buf = [0u8; COPY_BUF_SIZE];
    while remaining > 0 {
        let to_read = usize::try_from(remaining)
            .unwrap_or(buf.len())
            .min(buf.len());
        let n = reader
            .read(&mut buf[..to_read])
            .await
            .map_err(|error| FrameError::peer_io("websocket client read failed", error))?;
        if n == 0 {
            return Err(FrameError::peer_disconnect(miette!(
                "websocket payload ended before declared length"
            )));
        }
        writer
            .write_all(&buf[..n])
            .await
            .map_err(|error| FrameError::peer_io("websocket upstream write failed", error))?;
        remaining -= n as u64;
    }
    writer
        .flush()
        .await
        .map_err(|error| FrameError::peer_io("websocket upstream flush failed", error))?;
    Ok(())
}

async fn write_masked_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    opcode: u8,
    payload: &[u8],
) -> Result<()> {
    write_masked_frame_with_rsv(writer, opcode, 0, payload).await
}

pub(super) async fn write_masked_close<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<()> {
    write_masked_frame(writer, OPCODE_CLOSE, payload).await
}

pub(super) async fn write_unmasked_close<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<()> {
    let payload_len = u8::try_from(payload.len())
        .map_err(|_| miette!("websocket close payload exceeds 125 bytes"))?;
    writer
        .write_all(&[0x80 | OPCODE_CLOSE, payload_len])
        .await
        .into_diagnostic()?;
    writer.write_all(payload).await.into_diagnostic()?;
    writer.flush().await.into_diagnostic()?;
    Ok(())
}

async fn write_masked_frame_with_rsv<W: AsyncWrite + Unpin>(
    writer: &mut W,
    opcode: u8,
    rsv: u8,
    payload: &[u8],
) -> Result<()> {
    let (header, masked) = masked_frame_parts(opcode, rsv, payload);
    writer.write_all(&header).await.into_diagnostic()?;
    writer.write_all(&masked).await.into_diagnostic()?;
    writer.flush().await.into_diagnostic()?;
    Ok(())
}

async fn write_masked_text_frame_guarded<W: AsyncWrite + Unpin>(
    writer: &mut W,
    rsv: u8,
    payload: &[u8],
    host: &str,
    port: u16,
    policy_name: &str,
    generation_guard: Option<&PolicyGenerationGuard>,
) -> WebSocketRelayResult<()> {
    let (header, masked) = masked_frame_parts(OPCODE_TEXT, rsv, payload);
    write_text_frame_guarded(
        writer,
        &header,
        &masked,
        host,
        port,
        policy_name,
        generation_guard,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn write_text_frame_guarded<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &[u8],
    payload: &[u8],
    host: &str,
    port: u16,
    policy_name: &str,
    generation_guard: Option<&PolicyGenerationGuard>,
) -> WebSocketRelayResult<()> {
    ensure_generation_guard_current(host, port, policy_name, generation_guard)?;
    tokio::time::timeout(TEXT_MESSAGE_FORWARD_TOTAL_TIMEOUT, async {
        writer.write_all(header).await.map_err(|error| {
            terminate(
                WebSocketTerminationCause::PeerDisconnect,
                miette!("websocket upstream write failed: {error}"),
            )
        })?;
        writer.write_all(payload).await.map_err(|error| {
            terminate(
                WebSocketTerminationCause::PeerDisconnect,
                miette!("websocket upstream write failed: {error}"),
            )
        })?;
        writer.flush().await.map_err(|error| {
            terminate(
                WebSocketTerminationCause::PeerDisconnect,
                miette!("websocket upstream flush failed: {error}"),
            )
        })
    })
    .await
    .map_err(|_| {
        terminate(
            WebSocketTerminationCause::PeerDisconnect,
            miette!("websocket upstream forwarding total timeout"),
        )
    })??;
    ensure_generation_guard_current(host, port, policy_name, generation_guard)
}

fn masked_frame_parts(opcode: u8, rsv: u8, payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut header = Vec::with_capacity(14);
    header.push(0x80 | rsv | opcode);
    match payload.len() {
        0..=125 => header.push(0x80 | u8::try_from(payload.len()).expect("payload <= 125")),
        126..=65_535 => {
            header.push(0x80 | 0x7e);
            header.extend_from_slice(
                &u16::try_from(payload.len())
                    .expect("payload <= 65535")
                    .to_be_bytes(),
            );
        }
        _ => {
            header.push(0x80 | 127);
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    let mask_key = new_mask_key();
    header.extend_from_slice(&mask_key);

    let mut masked = payload.to_vec();
    apply_mask(&mut masked, mask_key);
    (header, masked)
}

fn decompress_permessage_deflate(
    payload: &[u8],
) -> std::result::Result<Vec<u8>, WebSocketDecompressionError> {
    let mut decoder = Decompress::new(false);
    let mut input = Vec::with_capacity(payload.len() + 4);
    input.extend_from_slice(payload);
    input.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
    let mut out = Vec::with_capacity(payload.len().saturating_mul(2).min(MAX_TEXT_MESSAGE_BYTES));
    let mut input_pos = 0usize;
    let mut scratch = [0u8; COPY_BUF_SIZE];
    loop {
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder
            .decompress(&input[input_pos..], &mut scratch, FlushDecompress::Sync)
            .map_err(|e| {
                WebSocketDecompressionError::Protocol(miette!(
                    "websocket permessage-deflate decompression failed: {e}"
                ))
            })?;
        let read = usize::try_from(decoder.total_in() - before_in).map_err(|_| {
            WebSocketDecompressionError::Protocol(miette!(
                "websocket permessage-deflate input length overflow"
            ))
        })?;
        let written = usize::try_from(decoder.total_out() - before_out).map_err(|_| {
            WebSocketDecompressionError::Protocol(miette!(
                "websocket permessage-deflate output length overflow"
            ))
        })?;
        input_pos = input_pos.checked_add(read).ok_or_else(|| {
            WebSocketDecompressionError::Protocol(miette!(
                "websocket permessage-deflate input length overflow"
            ))
        })?;
        if out.len().saturating_add(written) > MAX_TEXT_MESSAGE_BYTES {
            return Err(WebSocketDecompressionError::MessageTooBig(miette!(
                "websocket text message exceeds {MAX_TEXT_MESSAGE_BYTES} byte limit"
            )));
        }
        out.extend_from_slice(&scratch[..written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if input_pos >= input.len() && written < scratch.len() {
            break;
        }
        if read == 0 && written == 0 {
            return Err(WebSocketDecompressionError::Protocol(miette!(
                "websocket permessage-deflate decompression did not make progress"
            )));
        }
    }
    Ok(out)
}

fn compress_permessage_deflate(payload: &[u8]) -> Result<Vec<u8>> {
    let mut compressor = Compress::new(Compression::fast(), false);
    let expansion = payload.len() / 16;
    let mut out = Vec::with_capacity(payload.len().saturating_add(expansion).saturating_add(128));
    loop {
        let consumed = usize::try_from(compressor.total_in())
            .map_err(|_| miette!("websocket permessage-deflate input length overflow"))?;
        if consumed >= payload.len() {
            break;
        }
        let before_in = compressor.total_in();
        let before_out = compressor.total_out();
        let status = compressor
            .compress_vec(&payload[consumed..], &mut out, FlushCompress::None)
            .map_err(|e| miette!("websocket permessage-deflate compression failed: {e}"))?;
        if matches!(status, Status::BufError)
            || (compressor.total_in() == before_in && compressor.total_out() == before_out)
        {
            out.reserve(out.capacity().max(1024));
        }
    }
    loop {
        out.reserve(64);
        let before_out = compressor.total_out();
        compressor
            .compress_vec(&[], &mut out, FlushCompress::Sync)
            .map_err(|e| miette!("websocket permessage-deflate compression failed: {e}"))?;
        if out.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
            break;
        }
        if compressor.total_out() == before_out {
            out.reserve(out.capacity().max(1024));
        }
    }
    if !out.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
        return Err(miette!(
            "websocket permessage-deflate compression missing sync marker"
        ));
    }
    out.truncate(out.len() - 4);
    Ok(out)
}

#[cfg(test)]
pub fn compressed_masked_text_frame_for_test(payload: &[u8]) -> Vec<u8> {
    let compressed = compress_permessage_deflate(payload).expect("compress test WebSocket frame");
    let (mut frame, masked) = masked_frame_parts(OPCODE_TEXT, 0x40, &compressed);
    frame.extend_from_slice(&masked);
    frame
}

#[cfg(test)]
pub fn decode_compressed_masked_text_frame_for_test(frame: &[u8]) -> String {
    assert_eq!(frame[0] & 0x0f, OPCODE_TEXT);
    assert_eq!(frame[0] & 0x40, 0x40);
    let header = parse_test_frame_layout(frame);
    assert!(header.masked, "client-to-upstream frame must be masked");
    let mut payload =
        frame[header.payload_offset..header.payload_offset + header.payload_len].to_vec();
    apply_mask(&mut payload, header.mask_key.expect("masked test frame"));
    String::from_utf8(
        decompress_permessage_deflate(&payload).expect("decompress test WebSocket frame"),
    )
    .expect("UTF-8 test WebSocket text")
}

#[cfg(test)]
pub async fn read_frame_for_test<R: AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
    let mut frame = vec![0u8; 2];
    reader
        .read_exact(&mut frame)
        .await
        .expect("read test WebSocket frame header");
    let extended_len_bytes = match frame[1] & 0x7f {
        0..=125 => 0,
        126 => 2,
        127 => 8,
        _ => unreachable!(),
    };
    let header_len = extended_len_bytes + if frame[1] & 0x80 != 0 { 4 } else { 0 };
    frame.resize(2 + header_len, 0);
    reader
        .read_exact(&mut frame[2..])
        .await
        .expect("read test WebSocket frame metadata");
    let payload_len = match frame[1] & 0x7f {
        0..=125 => usize::from(frame[1] & 0x7f),
        126 => usize::from(u16::from_be_bytes([frame[2], frame[3]])),
        127 => usize::try_from(u64::from_be_bytes(frame[2..10].try_into().unwrap())).unwrap(),
        _ => unreachable!(),
    };
    let frame_len = frame.len();
    frame.resize(frame_len + payload_len, 0);
    reader
        .read_exact(&mut frame[frame_len..])
        .await
        .expect("read test WebSocket frame payload");
    frame
}

#[cfg(test)]
struct TestFrameLayout {
    masked: bool,
    mask_key: Option<[u8; 4]>,
    payload_offset: usize,
    payload_len: usize,
}

#[cfg(test)]
fn parse_test_frame_layout(frame: &[u8]) -> TestFrameLayout {
    let masked = frame[1] & 0x80 != 0;
    let len_code = frame[1] & 0x7f;
    let (payload_len, mut payload_offset) = match len_code {
        0..=125 => (usize::from(len_code), 2),
        126 => (usize::from(u16::from_be_bytes([frame[2], frame[3]])), 4),
        127 => (
            usize::try_from(u64::from_be_bytes(frame[2..10].try_into().unwrap())).unwrap(),
            10,
        ),
        _ => unreachable!(),
    };
    let mask_key = masked.then(|| {
        let key = frame[payload_offset..payload_offset + 4]
            .try_into()
            .expect("test frame mask");
        payload_offset += 4;
        key
    });
    TestFrameLayout {
        masked,
        mask_key,
        payload_offset,
        payload_len,
    }
}

fn new_mask_key() -> [u8; 4] {
    let bytes = uuid::Uuid::new_v4().into_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

fn apply_mask(payload: &mut [u8], mask_key: [u8; 4]) {
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask_key[i % 4];
    }
}

fn emit_rewrite_event(host: &str, port: u16, policy_name: &str, replacements: usize) {
    let policy_name = if policy_name.is_empty() {
        "-"
    } else {
        policy_name
    };
    let event = NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Other)
        .action(ActionId::Allowed)
        .disposition(DispositionId::Allowed)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .dst_endpoint(Endpoint::from_domain(host, port))
        .firewall_rule(policy_name, "l7-websocket")
        .message(rewrite_event_message(host, port, replacements))
        .build();
    ocsf_emit!(event);
}

fn rewrite_event_message(host: &str, port: u16, replacements: usize) -> String {
    format!(
        "WEBSOCKET_CREDENTIAL_REWRITE rewrote client text message [host:{host} port:{port} replacements:{replacements}]"
    )
}

fn emit_websocket_l7_event(
    host: &str,
    port: u16,
    policy_name: &str,
    request_info: &L7RequestInfo,
    decision: &str,
    reason: &str,
    graphql: Option<&crate::l7::graphql::GraphqlRequestInfo>,
) {
    let policy_name = if policy_name.is_empty() {
        "-"
    } else {
        policy_name
    };
    let (action_id, disposition_id, severity) = match decision {
        "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
        "allow" | "audit" => (
            ActionId::Allowed,
            DispositionId::Allowed,
            SeverityId::Informational,
        ),
        _ => (
            ActionId::Other,
            DispositionId::Other,
            SeverityId::Informational,
        ),
    };
    let summary = graphql
        .map(crate::l7::graphql::log_summary)
        .map(|summary| format!(" {summary}"))
        .unwrap_or_default();
    let event = NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Other)
        .action(action_id)
        .disposition(disposition_id)
        .severity(severity)
        .status(StatusId::Success)
        .dst_endpoint(Endpoint::from_domain(host, port))
        .firewall_rule(policy_name, "l7-websocket")
        .message(format!(
            "WEBSOCKET_L7_REQUEST {decision} {} {host}:{port}{}{} reason={reason}",
            request_info.action, request_info.target, summary
        ))
        .build();
    ocsf_emit!(event);
}

fn observe_termination(
    host: &str,
    port: u16,
    policy_name: &str,
    termination: &WebSocketTermination,
) {
    if let Some(failure_class) = termination.failure_class {
        emit_protocol_failure(host, port, policy_name, failure_class);
    }
    if termination.cause == WebSocketTerminationCause::CapacityExhausted {
        ocsf_emit!(
            NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Open)
                .action(ActionId::Denied)
                .disposition(DispositionId::Blocked)
                .severity(SeverityId::Medium)
                .status(StatusId::Failure)
                .dst_endpoint(Endpoint::from_domain(host, port))
                .firewall_rule(policy_name, "l7-websocket")
                .status_detail("assembly_capacity_exhausted")
                .message(format!(
                    "WebSocket text assembly capacity exhausted [host:{host} port:{port}]"
                ))
                .build()
        );
    }
}

fn emit_protocol_failure(
    host: &str,
    port: u16,
    policy_name: &str,
    failure_class: FrameFailureClass,
) {
    ocsf_emit!(protocol_failure_event(
        host,
        port,
        policy_name,
        failure_class
    ));
}

fn protocol_failure_event(
    host: &str,
    port: u16,
    policy_name: &str,
    failure_class: FrameFailureClass,
) -> openshell_ocsf::OcsfEvent {
    let policy_name = if policy_name.is_empty() {
        "-"
    } else {
        policy_name
    };
    NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Medium)
        .status(StatusId::Failure)
        .dst_endpoint(Endpoint::from_domain(host, port))
        .firewall_rule(policy_name, "l7-websocket")
        .message(protocol_failure_message(host, port))
        .status_detail(failure_class.as_str())
        .build()
}

fn protocol_failure_message(host: &str, port: u16) -> String {
    format!("WEBSOCKET_CREDENTIAL_REWRITE closed ambiguous client frame [host:{host} port:{port}]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7::relay::L7EvalContext;
    use crate::opa::{NetworkInput, OpaEngine};
    use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
        SupervisorMiddleware, SupervisorMiddlewareServer,
    };
    use openshell_core::proto::{StaticCredentialBinding, StaticCredentialEndpointBinding};
    use openshell_core::provider_credentials::ProviderCredentialState;
    use openshell_core::secrets::SecretResolver;
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
    use tonic::{Request, Response, Status};

    async fn test_assembly_admission() -> WebSocketAssemblyAdmission {
        match WebSocketAssemblyBudget::new(1, 0)
            .reserve()
            .await
            .expect("reserve test assembly")
        {
            WebSocketAssemblyAdmissionOutcome::Admitted(admission) => admission,
            WebSocketAssemblyAdmissionOutcome::QueueExhausted => {
                panic!("fresh test assembly budget must admit")
            }
        }
    }

    const TEST_POLICY: &str = include_str!("../../data/sandbox-policy.rego");
    const GRAPHQL_WS_POLICY: &str = r#"
network_policies:
  graphql_ws:
    name: graphql_ws
    endpoints:
      - host: realtime.graphql.test
        port: 443
        path: "/graphql"
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/graphql"
          - allow:
              operation_type: query
              fields: [viewer]
          - allow:
              operation_type: subscription
              fields: [messageAdded]
    binaries:
      - { path: /usr/bin/node }
"#;

    #[test]
    fn termination_causes_map_to_protocol_close_codes_and_session_reasons() {
        use openshell_core::proto::WebSocketSessionEndReason as EndReason;

        assert_eq!(
            WebSocketTerminationCause::InvalidUtf8.close_code(),
            Some(1007)
        );
        assert_eq!(
            WebSocketTerminationCause::ProtocolError.close_code(),
            Some(1002)
        );
        assert_eq!(
            WebSocketTerminationCause::MessageTooBig.close_code(),
            Some(1009)
        );
        assert_eq!(
            WebSocketTerminationCause::MiddlewareDenial.close_code(),
            Some(1008)
        );
        assert_eq!(
            WebSocketTerminationCause::PolicyReload.close_code(),
            Some(1012)
        );
        assert_eq!(WebSocketTerminationCause::PeerDisconnect.close_code(), None);

        assert_eq!(
            WebSocketTerminationCause::InvalidUtf8.session_end_reason(),
            EndReason::ProtocolError
        );
        assert_eq!(
            WebSocketTerminationCause::MiddlewareDenial.session_end_reason(),
            EndReason::MiddlewareDenial
        );
        assert_eq!(
            WebSocketTerminationCause::PolicyDenial.session_end_reason(),
            EndReason::PolicyDenial
        );
        assert_eq!(
            WebSocketTerminationCause::MiddlewareFailure.session_end_reason(),
            EndReason::MiddlewareFailure
        );
        assert_eq!(
            WebSocketTerminationCause::PolicyReload.session_end_reason(),
            EndReason::PolicyReload
        );
    }

    fn resolver() -> (HashMap<String, String>, SecretResolver) {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            std::iter::once(("DISCORD_BOT_TOKEN".to_string(), "real-token".to_string())).collect(),
        );
        (child_env, resolver.expect("resolver"))
    }

    fn masked_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        masked_frame_with_rsv(fin, opcode, 0, payload)
    }

    fn masked_frame_with_rsv(fin: bool, opcode: u8, rsv: u8, payload: &[u8]) -> Vec<u8> {
        let mask_key = [0x37, 0xfa, 0x21, 0x3d];
        let mut frame = Vec::new();
        frame.push((if fin { 0x80 } else { 0 }) | rsv | opcode);
        match payload.len() {
            0..=125 => frame.push(0x80 | u8::try_from(payload.len()).expect("payload <= 125")),
            126..=65_535 => {
                frame.push(0x80 | 0x7e);
                frame.extend_from_slice(
                    &u16::try_from(payload.len())
                        .expect("payload <= 65535")
                        .to_be_bytes(),
                );
            }
            _ => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask_key);
        for (i, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask_key[i % 4]);
        }
        frame
    }

    fn unmasked_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.push(0x80 | opcode);
        frame.push(u8::try_from(payload.len()).expect("test payload fits in one byte"));
        frame.extend_from_slice(payload);
        frame
    }

    fn masked_frame_with_declared_len(opcode: u8, declared_len: u64) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.push(0x80 | opcode);
        frame.push(0x80 | 127);
        frame.extend_from_slice(&declared_len.to_be_bytes());
        frame.extend_from_slice(&[0x37, 0xfa, 0x21, 0x3d]);
        frame
    }

    fn masked_frame_with_non_minimal_16_bit_len(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mask_key = [0x37, 0xfa, 0x21, 0x3d];
        let mut frame = Vec::new();
        frame.push(0x80 | opcode);
        frame.push(0x80 | 0x7e);
        frame.extend_from_slice(
            &u16::try_from(payload.len())
                .expect("test payload fits u16")
                .to_be_bytes(),
        );
        frame.extend_from_slice(&mask_key);
        for (i, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask_key[i % 4]);
        }
        frame
    }

    fn test_frame_header(fin: bool, opcode: u8, payload_len: u64) -> FrameHeader {
        FrameHeader {
            fin,
            rsv: 0,
            opcode,
            masked: true,
            payload_len,
            mask_key: Some([0x37, 0xfa, 0x21, 0x3d]),
            raw_header: Vec::new(),
        }
    }

    async fn wait_for_stalled_task<T>(task: &tokio::task::JoinHandle<T>) {
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "fixture task must be pending");
    }

    struct ReloadAfterFirstWrite {
        engine: Arc<OpaEngine>,
        output: Vec<u8>,
        writes: usize,
    }

    impl AsyncWrite for ReloadAfterFirstWrite {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buffer: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            this.output.extend_from_slice(buffer);
            this.writes += 1;
            if this.writes == 1 {
                this.engine
                    .replace_middleware_registry(
                        openshell_supervisor_middleware::MiddlewareRegistry::default(),
                    )
                    .expect("invalidate generation after frame header");
            }
            std::task::Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn relay_options_with_budget(budget: WebSocketAssemblyBudget) -> RelayOptions<'static> {
        RelayOptions {
            policy_name: "test-policy",
            assembly_budget: budget,
            resolver: None,
            generation_guard: None,
            provider_credentials: None,
            target: "/",
            inspector: None,
            compression: WebSocketCompression::None,
            middleware_session: None,
            middleware_context: None,
            deny_uninspected_credentials: false,
        }
    }

    fn close_payload(code: u16, reason: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason);
        payload
    }

    async fn run_client_to_server(input: Vec<u8>) -> Result<Vec<u8>> {
        let (_, resolver) = resolver();
        let (mut client_write, mut relay_read) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES + 1024);
        let (mut relay_write, mut upstream_read) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES + 1024);

        client_write.write_all(&input).await.unwrap();
        drop(client_write);

        let mut options = RelayOptions {
            policy_name: "test-policy",
            assembly_budget: WebSocketAssemblyBudget::default(),
            resolver: Some(&resolver),
            generation_guard: None,
            provider_credentials: None,
            target: "/",
            inspector: None,
            compression: WebSocketCompression::None,
            middleware_session: None,
            middleware_context: None,
            deny_uninspected_credentials: false,
        };
        let result = relay_client_to_server(
            &mut relay_read,
            &mut relay_write,
            "gateway.example.test",
            443,
            &mut options,
        )
        .await;
        drop(relay_write);

        let mut output = Vec::new();
        upstream_read.read_to_end(&mut output).await.unwrap();
        result
            .map(|_| output)
            .map_err(|termination| termination.error)
    }

    #[tokio::test]
    async fn parsed_relays_share_assembly_budget_without_middleware() {
        let budget = WebSocketAssemblyBudget::new(1, 0);
        let held_frame = masked_frame(true, OPCODE_TEXT, b"held");
        let (mut first_client, mut first_reader) = tokio::io::duplex(64);
        let (mut first_writer, _first_upstream) = tokio::io::duplex(64);
        first_client
            .write_all(&held_frame[..6])
            .await
            .expect("send frame header without payload");
        let first_budget = budget.clone();
        let first = tokio::spawn(async move {
            let mut options = relay_options_with_budget(first_budget);
            relay_client_to_server(
                &mut first_reader,
                &mut first_writer,
                "gateway.example.test",
                443,
                &mut options,
            )
            .await
        });
        wait_for_stalled_task(&first).await;

        let rejected_frame = masked_frame(true, OPCODE_TEXT, b"rejected");
        let (mut second_client, mut second_reader) = tokio::io::duplex(64);
        let (mut second_writer, mut second_upstream) = tokio::io::duplex(64);
        second_client
            .write_all(&rejected_frame)
            .await
            .expect("send rejected frame");
        drop(second_client);
        let mut second_options = relay_options_with_budget(budget.clone());
        let rejected = relay_client_to_server(
            &mut second_reader,
            &mut second_writer,
            "gateway.example.test",
            443,
            &mut second_options,
        )
        .await
        .expect_err("full assembly budget must shed");
        assert_eq!(rejected.cause, WebSocketTerminationCause::CapacityExhausted);
        drop(second_writer);
        let mut rejected_output = Vec::new();
        second_upstream
            .read_to_end(&mut rejected_output)
            .await
            .expect("read rejected upstream");
        assert!(rejected_output.is_empty());

        drop(first_client);
        first
            .await
            .expect("join held relay")
            .expect_err("incomplete message must end on disconnect");

        let admitted_frame = masked_frame(true, OPCODE_TEXT, b"admitted");
        let (mut third_client, mut third_reader) = tokio::io::duplex(64);
        let (mut third_writer, mut third_upstream) = tokio::io::duplex(64);
        third_client
            .write_all(&admitted_frame)
            .await
            .expect("send admitted frame");
        drop(third_client);
        let mut third_options = relay_options_with_budget(budget);
        relay_client_to_server(
            &mut third_reader,
            &mut third_writer,
            "gateway.example.test",
            443,
            &mut third_options,
        )
        .await
        .expect("released assembly budget must admit");
        drop(third_writer);
        let mut admitted_output = Vec::new();
        third_upstream
            .read_to_end(&mut admitted_output)
            .await
            .expect("read admitted upstream");
        assert_eq!(admitted_output, admitted_frame);
    }

    #[tokio::test]
    async fn assembly_budget_bounds_waiters_and_recovers_capacity() {
        let budget = WebSocketAssemblyBudget::new(1, 1);
        let first = match budget.reserve().await.expect("reserve active assembly") {
            WebSocketAssemblyAdmissionOutcome::Admitted(admission) => admission,
            WebSocketAssemblyAdmissionOutcome::QueueExhausted => {
                panic!("fresh budget must admit")
            }
        };
        let waiting_budget = budget.clone();
        let waiting = tokio::spawn(async move { waiting_budget.reserve().await });
        wait_for_stalled_task(&waiting).await;
        assert!(matches!(
            budget.reserve().await.expect("attempt shed admission"),
            WebSocketAssemblyAdmissionOutcome::QueueExhausted
        ));
        drop(first);
        assert!(matches!(
            waiting
                .await
                .expect("join waiting admission")
                .expect("waiting admission result"),
            WebSocketAssemblyAdmissionOutcome::Admitted(_)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn upstream_forwarding_timeout_releases_assembly_capacity() {
        let budget = WebSocketAssemblyBudget::new(1, 0);
        let assembly_admission = match budget.reserve().await.expect("reserve assembly") {
            WebSocketAssemblyAdmissionOutcome::Admitted(admission) => admission,
            WebSocketAssemblyAdmissionOutcome::QueueExhausted => {
                panic!("fresh assembly budget must admit")
            }
        };
        let payload = vec![b'x'; 64];
        let frame_bytes = masked_frame(true, OPCODE_TEXT, &payload);
        let mut frame = test_frame_header(true, OPCODE_TEXT, payload.len() as u64);
        frame.raw_header = frame_bytes[..6].to_vec();
        let (mut writer, _non_reading_upstream) = tokio::io::duplex(1);
        let forwarding = tokio::spawn(async move {
            let mut options = relay_options_with_budget(WebSocketAssemblyBudget::new(1, 0));
            relay_text_payload(
                &mut writer,
                &frame,
                payload,
                assembly_admission,
                None,
                false,
                false,
                "gateway.example.test",
                443,
                &mut options,
            )
            .await
        });
        wait_for_stalled_task(&forwarding).await;
        assert!(matches!(
            budget.reserve().await.expect("attempt shed admission"),
            WebSocketAssemblyAdmissionOutcome::QueueExhausted
        ));

        tokio::time::advance(TEXT_MESSAGE_FORWARD_TOTAL_TIMEOUT + StdDuration::from_millis(1))
            .await;
        let error = forwarding
            .await
            .expect("join forwarding")
            .expect_err("non-reading upstream must time out");
        assert_eq!(error.cause, WebSocketTerminationCause::PeerDisconnect);
        assert!(
            error
                .error
                .to_string()
                .contains("upstream forwarding total timeout")
        );
        assert!(matches!(
            budget
                .reserve()
                .await
                .expect("reserve after forwarding timeout"),
            WebSocketAssemblyAdmissionOutcome::Admitted(_)
        ));
    }

    #[tokio::test]
    async fn reload_after_frame_header_preserves_frame_boundary_before_close() {
        let engine = Arc::new(
            OpaEngine::from_strings(TEST_POLICY, "network_policies: {}\n").expect("test policy"),
        );
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .expect("generation guard");
        let payload = b"complete-frame";
        let (header, masked) = masked_frame_parts(OPCODE_TEXT, 0, payload);
        let mut writer = ReloadAfterFirstWrite {
            engine,
            output: Vec::new(),
            writes: 0,
        };

        let error = write_text_frame_guarded(
            &mut writer,
            &header,
            &masked,
            "gateway.example.test",
            443,
            "test-policy",
            Some(&generation_guard),
        )
        .await
        .expect_err("reload after header must close after completing the frame");
        assert_eq!(error.cause, WebSocketTerminationCause::PolicyReload);

        write_masked_close(&mut writer, &1012u16.to_be_bytes())
            .await
            .expect("write typed close");
        let frame_len = header.len() + masked.len();
        assert_eq!(&writer.output[..header.len()], header);
        assert_eq!(&writer.output[header.len()..frame_len], masked);
        let close = &writer.output[frame_len..];
        assert_eq!(close[0] & 0x0f, OPCODE_CLOSE);
        assert_eq!(
            u16::from_be_bytes(
                decode_masked_payload(close)[..2]
                    .try_into()
                    .expect("close code"),
            ),
            1012
        );
    }

    fn bound_websocket_provider_state() -> ProviderCredentialState {
        ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("DISCORD_BOT_TOKEN".to_string(), "real-token".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "DISCORD_BOT_TOKEN".to_string(),
                StaticCredentialBinding {
                    endpoints: vec![StaticCredentialEndpointBinding {
                        host: "gateway.example.test".to_string(),
                        port: 443,
                        path: "/socket".to_string(),
                    }],
                    credential_identity: "provider-a:DISCORD_BOT_TOKEN".to_string(),
                    workload_credential_handle: String::new(),
                },
            )]),
            Vec::new(),
        )
        .expect("bound websocket provider state")
    }

    async fn relay_frame_after_live_state_change(
        state: &ProviderCredentialState,
        fallback: &SecretResolver,
    ) -> (Result<()>, Vec<u8>) {
        let placeholder = b"openshell:resolve:env:v1_DISCORD_BOT_TOKEN";
        let input = masked_frame(true, 0x1, placeholder);
        let (mut client_write, mut relay_read) = tokio::io::duplex(4096);
        let (mut relay_write, mut upstream_read) = tokio::io::duplex(4096);
        client_write.write_all(&input).await.unwrap();
        drop(client_write);

        let mut options = RelayOptions {
            policy_name: "test-policy",
            assembly_budget: WebSocketAssemblyBudget::default(),
            resolver: Some(fallback),
            generation_guard: None,
            provider_credentials: Some(state),
            target: "/socket",
            inspector: None,
            compression: WebSocketCompression::None,
            middleware_session: None,
            middleware_context: None,
            deny_uninspected_credentials: false,
        };
        let result = relay_client_to_server(
            &mut relay_read,
            &mut relay_write,
            "gateway.example.test",
            443,
            &mut options,
        )
        .await;
        drop(relay_write);
        let mut output = Vec::new();
        upstream_read.read_to_end(&mut output).await.unwrap();
        (
            result.map(|_| ()).map_err(|termination| termination.error),
            output,
        )
    }

    #[tokio::test]
    async fn established_websocket_does_not_restore_resolver_after_detach() {
        let state = bound_websocket_provider_state();
        let fallback = state.resolver().expect("upgrade-time resolver");
        state.revoke_static_provider_environment(2);

        let (result, output) = relay_frame_after_live_state_change(&state, fallback.as_ref()).await;
        assert!(result.is_err(), "revoked placeholder must close the relay");
        assert!(
            output.is_empty(),
            "revoked WebSocket credential must not reach upstream"
        );
    }

    #[tokio::test]
    async fn established_websocket_does_not_restore_resolver_after_invalid_refresh() {
        let state = bound_websocket_provider_state();
        let fallback = state.resolver().expect("upgrade-time resolver");
        let refresh = state.install_bound_environment(
            2,
            HashMap::from([("DISCORD_BOT_TOKEN".to_string(), "rotated".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            Vec::new(),
        );
        assert!(
            refresh.is_err(),
            "incomplete bindings must revoke static state"
        );

        let (result, output) = relay_frame_after_live_state_change(&state, fallback.as_ref()).await;
        assert!(
            result.is_err(),
            "invalid-refresh placeholder must close the relay"
        );
        assert!(
            output.is_empty(),
            "invalid-refresh credential must not reach upstream"
        );
    }

    #[tokio::test]
    async fn guarded_websocket_uses_path_scoped_live_resolver() {
        let state = bound_websocket_provider_state();
        let placeholder = b"openshell:resolve:env:v1_DISCORD_BOT_TOKEN";
        let input = masked_frame(true, OPCODE_TEXT, placeholder);
        let (mut client_write, mut relay_read) = tokio::io::duplex(4096);
        let (mut relay_write, mut upstream_read) = tokio::io::duplex(4096);
        client_write.write_all(&input).await.unwrap();
        drop(client_write);

        let mut options = RelayOptions {
            policy_name: "test-policy",
            assembly_budget: WebSocketAssemblyBudget::default(),
            resolver: None,
            generation_guard: None,
            provider_credentials: Some(&state),
            target: "/socket",
            inspector: None,
            compression: WebSocketCompression::None,
            middleware_session: None,
            middleware_context: None,
            deny_uninspected_credentials: true,
        };
        let result = relay_client_to_server(
            &mut relay_read,
            &mut relay_write,
            "gateway.example.test",
            443,
            &mut options,
        )
        .await;
        assert!(
            result.is_ok(),
            "path-scoped live resolver must satisfy the credential guard: {result:?}"
        );

        drop(relay_write);
        let mut output = Vec::new();
        upstream_read.read_to_end(&mut output).await.unwrap();
        assert_eq!(decode_masked_text_frame(&output), "real-token");
    }

    #[tokio::test]
    async fn websocket_rewrite_rejects_revocation_before_frame_write() {
        let state = bound_websocket_provider_state();
        let fallback = state.resolver().expect("upgrade-time resolver");
        let placeholder = b"openshell:resolve:env:v1_DISCORD_BOT_TOKEN";
        let compressed = compress_permessage_deflate(placeholder).expect("compress placeholder");
        let frame = FrameHeader {
            fin: true,
            rsv: 0x40,
            opcode: OPCODE_TEXT,
            masked: true,
            payload_len: compressed.len() as u64,
            mask_key: Some([0x37, 0xfa, 0x21, 0x3d]),
            raw_header: Vec::new(),
        };
        let mut options = RelayOptions {
            policy_name: "test-policy",
            assembly_budget: WebSocketAssemblyBudget::default(),
            resolver: Some(fallback.as_ref()),
            generation_guard: None,
            provider_credentials: Some(&state),
            target: "/socket",
            inspector: None,
            compression: WebSocketCompression::PermessageDeflate,
            middleware_session: None,
            middleware_context: None,
            deny_uninspected_credentials: false,
        };
        let reached_write = tokio::sync::Barrier::new(2);
        let release_write = tokio::sync::Barrier::new(2);
        let (mut relay_write, mut upstream_read) = tokio::io::duplex(4096);

        let relay = relay_text_payload_with_before_credential_write(
            &mut relay_write,
            &frame,
            compressed,
            test_assembly_admission().await,
            None,
            false,
            true,
            "gateway.example.test",
            443,
            &mut options,
            async {
                reached_write.wait().await;
                release_write.wait().await;
            },
        );
        let revoke = async {
            reached_write.wait().await;
            state.revoke_static_provider_environment(2);
            release_write.wait().await;
        };
        let (result, ()) = tokio::join!(relay, revoke);
        assert!(
            result
                .as_ref()
                .is_err_and(|error| error.error.to_string().contains("generation changed")),
            "revoked credential generation must fail before the frame write: {result:?}"
        );

        drop(relay_write);
        let mut output = Vec::new();
        upstream_read.read_to_end(&mut output).await.unwrap();
        assert!(
            output.is_empty(),
            "credential revoked before the write guard must not reach upstream"
        );
    }

    async fn run_client_to_server_guarded(input: Vec<u8>) -> (Result<()>, Vec<u8>) {
        let (mut client_write, mut relay_read) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES + 1024);
        let (mut relay_write, mut upstream_read) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES + 1024);

        client_write.write_all(&input).await.unwrap();
        drop(client_write);

        let mut options = RelayOptions {
            policy_name: "test-policy",
            assembly_budget: WebSocketAssemblyBudget::default(),
            resolver: None,
            generation_guard: None,
            provider_credentials: None,
            target: "/",
            inspector: None,
            compression: WebSocketCompression::None,
            middleware_session: None,
            middleware_context: None,
            deny_uninspected_credentials: true,
        };
        let result = relay_client_to_server(
            &mut relay_read,
            &mut relay_write,
            "gateway.example.test",
            443,
            &mut options,
        )
        .await;
        drop(relay_write);

        let mut output = Vec::new();
        upstream_read.read_to_end(&mut output).await.unwrap();
        (
            result.map(|_| ()).map_err(|termination| termination.error),
            output,
        )
    }

    async fn run_client_to_server_with_graphql_policy(
        input: Vec<u8>,
        resolver: Option<&SecretResolver>,
    ) -> Result<Vec<u8>> {
        let engine = OpaEngine::from_strings(TEST_POLICY, GRAPHQL_WS_POLICY)
            .expect("GraphQL WebSocket policy should load");
        let network_input = NetworkInput {
            host: "realtime.graphql.test".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let generation = engine
            .evaluate_network_action_with_generation(&network_input)
            .expect("network action should evaluate")
            .1;
        let tunnel_engine = engine
            .clone_engine_for_tunnel(generation)
            .expect("tunnel engine");
        let ctx = L7EvalContext {
            host: "realtime.graphql.test".into(),
            port: 443,
            policy_name: "graphql_ws".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };
        let (mut client_write, mut relay_read) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES + 1024);
        let (mut relay_write, mut upstream_read) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES + 1024);

        client_write.write_all(&input).await.unwrap();
        drop(client_write);

        let mut options = RelayOptions {
            policy_name: "graphql_ws",
            assembly_budget: WebSocketAssemblyBudget::default(),
            resolver,
            generation_guard: Some(tunnel_engine.generation_guard()),
            provider_credentials: None,
            target: "/graphql",
            inspector: Some(InspectionOptions {
                engine: &tunnel_engine,
                ctx: &ctx,
                enforcement: EnforcementMode::Enforce,
                target: "/graphql".to_string(),
                query_params: HashMap::new(),
                graphql_policy: true,
            }),
            compression: WebSocketCompression::None,
            middleware_session: None,
            middleware_context: None,
            deny_uninspected_credentials: false,
        };
        let result = relay_client_to_server(
            &mut relay_read,
            &mut relay_write,
            "realtime.graphql.test",
            443,
            &mut options,
        )
        .await;
        drop(relay_write);

        let mut output = Vec::new();
        upstream_read.read_to_end(&mut output).await.unwrap();
        result
            .map(|_| output)
            .map_err(|termination| termination.error)
    }

    async fn run_client_to_server_compressed(input: Vec<u8>) -> Result<Vec<u8>> {
        let (_, resolver) = resolver();
        let (mut client_write, mut relay_read) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES + 1024);
        let (mut relay_write, mut upstream_read) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES + 1024);

        client_write.write_all(&input).await.unwrap();
        drop(client_write);

        let mut options = RelayOptions {
            policy_name: "test-policy",
            assembly_budget: WebSocketAssemblyBudget::default(),
            resolver: Some(&resolver),
            generation_guard: None,
            provider_credentials: None,
            target: "/",
            inspector: None,
            compression: WebSocketCompression::PermessageDeflate,
            middleware_session: None,
            middleware_context: None,
            deny_uninspected_credentials: false,
        };
        let result = relay_client_to_server(
            &mut relay_read,
            &mut relay_write,
            "gateway.example.test",
            443,
            &mut options,
        )
        .await;
        drop(relay_write);

        let mut output = Vec::new();
        upstream_read.read_to_end(&mut output).await.unwrap();
        result
            .map(|_| output)
            .map_err(|termination| termination.error)
    }

    fn decode_masked_text_frame(frame: &[u8]) -> String {
        assert_eq!(frame[0] & 0x0F, OPCODE_TEXT);
        assert_ne!(frame[1] & 0x80, 0);
        String::from_utf8(decode_masked_payload(frame)).unwrap()
    }

    fn decode_masked_payload(frame: &[u8]) -> Vec<u8> {
        assert_ne!(frame[1] & 0x80, 0);
        let len_code = frame[1] & 0x7F;
        let (payload_len, mask_offset) = match len_code {
            0..=125 => (usize::from(len_code), 2),
            126 => (usize::from(u16::from_be_bytes([frame[2], frame[3]])), 4),
            127 => {
                let len = u64::from_be_bytes(frame[2..10].try_into().unwrap());
                (usize::try_from(len).unwrap(), 10)
            }
            _ => unreachable!(),
        };
        let mask_key: [u8; 4] = frame[mask_offset..mask_offset + 4].try_into().unwrap();
        let mut payload = frame[mask_offset + 4..mask_offset + 4 + payload_len].to_vec();
        apply_mask(&mut payload, mask_key);
        payload
    }

    fn decode_compressed_masked_text_frame(frame: &[u8]) -> String {
        assert_eq!(frame[0] & 0x0F, OPCODE_TEXT);
        assert_eq!(frame[0] & 0x40, 0x40);
        let payload = decode_masked_payload(frame);
        String::from_utf8(decompress_permessage_deflate(&payload).unwrap()).unwrap()
    }

    async fn read_one_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
        let mut header = [0u8; 2];
        reader.read_exact(&mut header).await.unwrap();
        let len_code = header[1] & 0x7F;
        let extended_len = match len_code {
            0..=125 => Vec::new(),
            126 => {
                let mut bytes = vec![0u8; 2];
                reader.read_exact(&mut bytes).await.unwrap();
                bytes
            }
            127 => {
                let mut bytes = vec![0u8; 8];
                reader.read_exact(&mut bytes).await.unwrap();
                bytes
            }
            _ => unreachable!(),
        };
        let payload_len = match len_code {
            0..=125 => usize::from(len_code),
            126 => usize::from(u16::from_be_bytes(
                extended_len.as_slice().try_into().unwrap(),
            )),
            127 => usize::try_from(u64::from_be_bytes(
                extended_len.as_slice().try_into().unwrap(),
            ))
            .unwrap(),
            _ => unreachable!(),
        };
        let mask_len = if header[1] & 0x80 != 0 { 4 } else { 0 };
        let mut rest = vec![0u8; extended_len.len() + mask_len + payload_len];
        rest[..extended_len.len()].copy_from_slice(&extended_len);
        reader
            .read_exact(&mut rest[extended_len.len()..])
            .await
            .unwrap();

        let mut frame = header.to_vec();
        frame.extend_from_slice(&rest);
        frame
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_initial_text_payload_releases_middleware_admission() {
        let runner = openshell_supervisor_middleware::ChainRunner::default();
        let admission = runner
            .reserve_middleware_work_admission()
            .await
            .expect("reserve middleware work");
        let (client, mut reader) = tokio::io::duplex(8);
        let frame = test_frame_header(true, OPCODE_TEXT, 4);
        let task = tokio::spawn(async move {
            let mut assembly =
                TextMessageAssembly::new(false, test_assembly_admission().await, Some(admission));
            assembly.read_payload(&mut reader, &frame).await
        });

        wait_for_stalled_task(&task).await;
        tokio::time::advance(TEXT_MESSAGE_ASSEMBLY_IDLE_TIMEOUT + StdDuration::from_millis(1))
            .await;
        let error = task
            .await
            .expect("join stalled assembly")
            .expect_err("initial payload must time out");
        assert!(error.to_string().contains("assembly idle timeout"));

        runner
            .reserve_middleware_work_admission()
            .await
            .expect("timed-out initial payload releases admission");
        drop(client);
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_continuation_payload_releases_middleware_admission() {
        let runner = openshell_supervisor_middleware::ChainRunner::default();
        let admission = runner
            .reserve_middleware_work_admission()
            .await
            .expect("reserve middleware work");
        let (mut client, mut reader) = tokio::io::duplex(8);
        client
            .write_all(&[0x37])
            .await
            .expect("send partial continuation payload");
        let frame = test_frame_header(true, OPCODE_CONTINUATION, 2);
        let task = tokio::spawn(async move {
            let mut assembly =
                TextMessageAssembly::new(false, test_assembly_admission().await, Some(admission));
            assembly.payload.extend_from_slice(b"first");
            assembly.add_fragment().expect("continuation within limit");
            assembly.read_payload(&mut reader, &frame).await
        });

        wait_for_stalled_task(&task).await;
        tokio::time::advance(TEXT_MESSAGE_ASSEMBLY_IDLE_TIMEOUT + StdDuration::from_millis(1))
            .await;
        let error = task
            .await
            .expect("join stalled assembly")
            .expect_err("continuation payload must time out");
        assert!(error.to_string().contains("assembly idle timeout"));

        runner
            .reserve_middleware_work_admission()
            .await
            .expect("timed-out continuation releases admission");
        drop(client);
    }

    #[tokio::test(start_paused = true)]
    async fn missing_continuation_header_releases_middleware_admission() {
        let runner = openshell_supervisor_middleware::ChainRunner::default();
        let admission = runner
            .reserve_middleware_work_admission()
            .await
            .expect("reserve middleware work");
        let (client, mut reader) = tokio::io::duplex(8);
        let task = tokio::spawn(async move {
            let mut assembly =
                TextMessageAssembly::new(false, test_assembly_admission().await, Some(admission));
            assembly.payload.extend_from_slice(b"first");
            let result = read_frame_header(&mut reader, Some(&assembly)).await;
            drop(assembly);
            result
        });

        wait_for_stalled_task(&task).await;
        tokio::time::advance(TEXT_MESSAGE_ASSEMBLY_IDLE_TIMEOUT + StdDuration::from_millis(1))
            .await;
        let error = task
            .await
            .expect("join stalled assembly")
            .expect_err("missing continuation header must time out");
        assert!(error.to_string().contains("assembly idle timeout"));

        runner
            .reserve_middleware_work_admission()
            .await
            .expect("missing continuation releases admission");
        drop(client);
    }

    #[tokio::test(start_paused = true)]
    async fn text_assembly_total_deadline_does_not_reset_on_input_progress() {
        let runner = openshell_supervisor_middleware::ChainRunner::default();
        let admission = runner
            .reserve_middleware_work_admission()
            .await
            .expect("reserve middleware work");
        let (mut client, mut reader) = tokio::io::duplex(8);
        let frame = test_frame_header(true, OPCODE_TEXT, 1_024);
        let task = tokio::spawn(async move {
            let mut assembly =
                TextMessageAssembly::new(false, test_assembly_admission().await, Some(admission));
            assembly.read_payload(&mut reader, &frame).await
        });
        wait_for_stalled_task(&task).await;

        let progress_interval = TEXT_MESSAGE_ASSEMBLY_IDLE_TIMEOUT / 2;
        let mut elapsed = StdDuration::ZERO;
        while elapsed + progress_interval < TEXT_MESSAGE_ASSEMBLY_TOTAL_TIMEOUT {
            tokio::time::advance(progress_interval).await;
            elapsed += progress_interval;
            client
                .write_all(&[0x37])
                .await
                .expect("make progress before idle timeout");
            tokio::task::yield_now().await;
            assert!(!task.is_finished(), "idle deadline must reset on progress");
        }
        let until_total_timeout = TEXT_MESSAGE_ASSEMBLY_TOTAL_TIMEOUT
            .checked_sub(elapsed)
            .expect("progress schedule stays within total timeout");
        tokio::time::advance(until_total_timeout + StdDuration::from_millis(1)).await;
        let error = task
            .await
            .expect("join total assembly timeout")
            .expect_err("total assembly deadline must not reset");
        assert!(error.to_string().contains("assembly total timeout"));

        runner
            .reserve_middleware_work_admission()
            .await
            .expect("total timeout releases admission");
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_assemblies_release_the_saturated_shared_work_budget() {
        let runner = openshell_supervisor_middleware::ChainRunner::default();
        let mut clients = Vec::new();
        let mut stalled = Vec::new();
        for _ in 0..openshell_supervisor_middleware::MAX_CONCURRENT_MIDDLEWARE_WORK {
            let admission = runner
                .reserve_middleware_work_admission()
                .await
                .expect("fill shared middleware work budget");
            let (client, mut reader) = tokio::io::duplex(8);
            clients.push(client);
            let frame = test_frame_header(true, OPCODE_TEXT, 4);
            stalled.push(tokio::spawn(async move {
                let mut assembly = TextMessageAssembly::new(
                    false,
                    test_assembly_admission().await,
                    Some(admission),
                );
                assembly.read_payload(&mut reader, &frame).await
            }));
        }
        tokio::task::yield_now().await;
        assert!(stalled.iter().all(|task| !task.is_finished()));

        let later_runner = runner.clone();
        let later_work =
            tokio::spawn(async move { later_runner.reserve_middleware_work_admission().await });
        wait_for_stalled_task(&later_work).await;

        tokio::time::advance(TEXT_MESSAGE_ASSEMBLY_IDLE_TIMEOUT + StdDuration::from_millis(1))
            .await;
        for task in stalled {
            let error = task
                .await
                .expect("join stalled assembly")
                .expect_err("stalled assembly must time out");
            assert!(error.to_string().contains("assembly idle timeout"));
        }

        let admission = later_work
            .await
            .expect("join later middleware work")
            .expect("later middleware work acquires released capacity");
        assert!(
            admission.saturated(),
            "later work must have waited behind the saturated budget"
        );
        drop(clients);
    }

    #[test]
    fn classifies_graphql_transport_ws_subscribe_operation() {
        let message = r#"{"type":"subscribe","id":"1","payload":{"query":"subscription NewMessages { messageAdded }"}}"#;

        match classify_graphql_websocket_message(message) {
            GraphqlWebSocketMessage::Operation {
                message_type,
                graphql,
            } => {
                assert_eq!(message_type, "subscribe");
                assert!(
                    graphql.error.is_none(),
                    "unexpected error: {:?}",
                    graphql.error
                );
                assert_eq!(graphql.operations.len(), 1);
                assert_eq!(graphql.operations[0].operation_type, "subscription");
                assert_eq!(
                    graphql.operations[0].operation_name.as_deref(),
                    Some("NewMessages")
                );
                assert_eq!(graphql.operations[0].fields, vec!["messageAdded"]);
            }
            other @ GraphqlWebSocketMessage::Control { .. } => {
                panic!("expected operation, got {other:?}")
            }
        }
    }

    #[test]
    fn classifies_legacy_graphql_ws_start_operation() {
        let message = r#"{"type":"start","id":"1","payload":{"query":"query Viewer { viewer }"}}"#;

        match classify_graphql_websocket_message(message) {
            GraphqlWebSocketMessage::Operation {
                message_type,
                graphql,
            } => {
                assert_eq!(message_type, "start");
                assert!(
                    graphql.error.is_none(),
                    "unexpected error: {:?}",
                    graphql.error
                );
                assert_eq!(graphql.operations[0].operation_type, "query");
                assert_eq!(graphql.operations[0].fields, vec!["viewer"]);
            }
            other @ GraphqlWebSocketMessage::Control { .. } => {
                panic!("expected operation, got {other:?}")
            }
        }
    }

    #[test]
    fn classifies_graphql_websocket_control_message_without_payload_logging() {
        match classify_graphql_websocket_message(
            r#"{"type":"connection_init","payload":{"authorization":"secret"}}"#,
        ) {
            GraphqlWebSocketMessage::Control { message_type } => {
                assert_eq!(message_type, "connection_init");
            }
            other @ GraphqlWebSocketMessage::Operation { .. } => {
                panic!("expected control message, got {other:?}")
            }
        }
    }

    #[test]
    fn unsupported_graphql_websocket_message_type_fails_closed() {
        match classify_graphql_websocket_message(r#"{"type":"next","id":"1"}"#) {
            GraphqlWebSocketMessage::Operation { graphql, .. } => {
                assert!(
                    graphql
                        .error
                        .as_deref()
                        .is_some_and(|error| error.contains("unsupported"))
                );
            }
            other @ GraphqlWebSocketMessage::Control { .. } => {
                panic!("expected operation error, got {other:?}")
            }
        }
    }

    #[test]
    fn graphql_websocket_log_summary_excludes_payload_variables_and_secrets() {
        let placeholder = "openshell:resolve:env:T";
        let message = format!(
            r#"{{"type":"subscribe","id":"1","payload":{{"query":"query Viewer {{ viewer }}","variables":{{"token":"{placeholder}"}}}}}}"#
        );
        let graphql = match classify_graphql_websocket_message(&message) {
            GraphqlWebSocketMessage::Operation { graphql, .. } => graphql,
            other @ GraphqlWebSocketMessage::Control { .. } => {
                panic!("expected operation, got {other:?}")
            }
        };
        let summary = crate::l7::graphql::log_summary(&graphql);

        assert!(summary.contains("type=query"));
        assert!(summary.contains("fields=viewer"));
        assert!(!summary.contains(placeholder));
        assert!(!summary.contains("real-token"));
        assert!(!summary.contains("variables"));
        assert!(!summary.contains("token"));
        assert!(!summary.contains("secret_len"));
    }

    #[tokio::test]
    async fn rewrites_discord_like_identify_text_payload() {
        let (child_env, _) = resolver();
        let placeholder = child_env.get("DISCORD_BOT_TOKEN").unwrap();
        let payload = format!(r#"{{"op":2,"d":{{"token":"{placeholder}"}}}}"#);

        let output = run_client_to_server(masked_frame(true, OPCODE_TEXT, payload.as_bytes()))
            .await
            .expect("relay should succeed");

        assert_eq!(
            decode_masked_text_frame(&output),
            r#"{"op":2,"d":{"token":"real-token"}}"#
        );
    }

    #[tokio::test]
    async fn upgraded_relay_rewrites_client_text_before_upstream_receives_it() {
        let (child_env, resolver) = resolver();
        let placeholder = child_env.get("DISCORD_BOT_TOKEN").unwrap();
        let payload = format!(r#"{{"op":2,"d":{{"token":"{placeholder}"}}}}"#);
        let client_frame = masked_frame(true, OPCODE_TEXT, payload.as_bytes());
        assert!(
            !String::from_utf8_lossy(&client_frame).contains("real-token"),
            "client-side fixture must not contain the real token"
        );

        let (mut client_app, mut relay_client) = tokio::io::duplex(4096);
        let (mut relay_upstream, mut upstream_app) = tokio::io::duplex(4096);
        let relay = tokio::spawn(async move {
            relay_with_options(
                &mut relay_client,
                &mut relay_upstream,
                Vec::new(),
                "gateway.example.test",
                443,
                RelayOptions {
                    policy_name: "test-policy",
                    assembly_budget: WebSocketAssemblyBudget::default(),
                    resolver: Some(&resolver),
                    generation_guard: None,
                    provider_credentials: None,
                    target: "/",
                    inspector: None,
                    compression: WebSocketCompression::None,
                    middleware_session: None,
                    middleware_context: None,
                    deny_uninspected_credentials: false,
                },
            )
            .await
        });

        client_app.write_all(&client_frame).await.unwrap();
        client_app.flush().await.unwrap();

        let upstream_frame = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_one_frame(&mut upstream_app),
        )
        .await
        .expect("upstream should receive rewritten frame");
        assert_eq!(
            decode_masked_text_frame(&upstream_frame),
            r#"{"op":2,"d":{"token":"real-token"}}"#
        );

        drop(client_app);
        drop(upstream_app);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), relay).await;
    }

    #[derive(Debug)]
    enum ObservedWebSocketRequest {
        SessionStart,
        Message { sequence: u64, payload: String },
        SessionEnd(openshell_core::proto::WebSocketSessionEndReason),
    }

    #[derive(Clone, Default)]
    struct OpenAiWebSocketRedactor {
        observed: Option<tokio::sync::mpsc::UnboundedSender<ObservedWebSocketRequest>>,
        close_on_first_message: bool,
        message_received: Option<Arc<tokio::sync::Notify>>,
        release_message: Option<Arc<tokio::sync::Notify>>,
    }

    #[tonic::async_trait]
    impl SupervisorMiddleware for OpenAiWebSocketRedactor {
        type EvaluateWebSocketSessionStream =
            openshell_supervisor_middleware::WebSocketResponseStream;

        async fn describe(
            &self,
            _request: Request<()>,
        ) -> std::result::Result<Response<openshell_core::proto::MiddlewareManifest>, Status>
        {
            use openshell_core::proto::{
                MiddlewareBinding, MiddlewareManifest, SupervisorMiddlewareOperation,
                SupervisorMiddlewarePhase,
            };
            Ok(Response::new(MiddlewareManifest {
                name: "test/openai-websocket-redactor".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::WebsocketMessage as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: openshell_supervisor_middleware::MAX_MIDDLEWARE_PAYLOAD_BYTES
                        as u64,
                    timeout: "1s".into(),
                }],
                expected_audience: String::new(),
            }))
        }

        async fn validate_config(
            &self,
            _request: Request<openshell_core::proto::ValidateConfigRequest>,
        ) -> std::result::Result<Response<openshell_core::proto::ValidateConfigResponse>, Status>
        {
            Ok(Response::new(
                openshell_core::proto::ValidateConfigResponse {
                    valid: true,
                    reason: String::new(),
                },
            ))
        }

        async fn evaluate_http_request(
            &self,
            _request: Request<openshell_core::proto::HttpRequestEvaluation>,
        ) -> std::result::Result<Response<openshell_core::proto::HttpRequestResult>, Status>
        {
            Err(Status::unimplemented("WebSocket-only test middleware"))
        }

        async fn evaluate_web_socket_session(
            &self,
            request: Request<tonic::Streaming<openshell_core::proto::WebSocketSessionEvent>>,
        ) -> std::result::Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
            use openshell_core::proto::{
                Decision, WebSocketMessageResult, WebSocketPreflightAction,
                WebSocketPreflightDecision, WebSocketSessionEventResult, web_socket_message,
                web_socket_message_result, web_socket_session_event,
                web_socket_session_event_result,
            };
            let mut requests = request.into_inner();
            let observed = self.observed.clone();
            let close_on_first_message = self.close_on_first_message;
            let message_received = self.message_received.clone();
            let release_message = self.release_message.clone();
            let (responses_tx, responses_rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Ok(Some(request)) = requests.message().await {
                    let response = match request.event {
                        Some(web_socket_session_event::Event::Preflight(_)) => {
                            Some(WebSocketSessionEventResult {
                                result: Some(
                                    web_socket_session_event_result::Result::PreflightDecision(
                                        WebSocketPreflightDecision {
                                            action: WebSocketPreflightAction::Inspect as i32,
                                            ..Default::default()
                                        },
                                    ),
                                ),
                            })
                        }
                        Some(web_socket_session_event::Event::Message(message)) => {
                            let web_socket_message::Payload::Text(text) =
                                message.payload.expect("OpenAI event payload")
                            else {
                                panic!("OpenAI event must be text");
                            };
                            if let Some(observed) = &observed {
                                let _ = observed.send(ObservedWebSocketRequest::Message {
                                    sequence: message.sequence,
                                    payload: text.clone(),
                                });
                            }
                            if close_on_first_message {
                                break;
                            }
                            if let Some(received) = &message_received {
                                received.notify_one();
                            }
                            if let Some(release) = &release_message {
                                release.notified().await;
                            }
                            let deny = text.contains("deny-me");
                            let replacement = text.replace("customer-secret", "[REDACTED]");
                            Some(WebSocketSessionEventResult {
                                result: Some(
                                    web_socket_session_event_result::Result::MessageResult(
                                        WebSocketMessageResult {
                                            sequence: message.sequence,
                                            decision: if deny {
                                                Decision::Deny as i32
                                            } else {
                                                Decision::Allow as i32
                                            },
                                            replacement: (!deny).then_some(
                                                web_socket_message_result::Replacement::Text(
                                                    replacement,
                                                ),
                                            ),
                                            reason_code: if deny {
                                                "blocked".into()
                                            } else {
                                                "redacted".into()
                                            },
                                            ..Default::default()
                                        },
                                    ),
                                ),
                            })
                        }
                        Some(web_socket_session_event::Event::SessionStart(_)) => {
                            if let Some(observed) = &observed {
                                let _ = observed.send(ObservedWebSocketRequest::SessionStart);
                            }
                            None
                        }
                        Some(web_socket_session_event::Event::SessionEnd(end)) => {
                            if let Some(observed) = &observed
                                && let Ok(reason) =
                                    openshell_core::proto::WebSocketSessionEndReason::try_from(
                                        end.reason,
                                    )
                            {
                                let _ = observed.send(ObservedWebSocketRequest::SessionEnd(reason));
                            }
                            None
                        }
                        _ => None,
                    };
                    if let Some(response) = response
                        && responses_tx.send(Ok(response)).await.is_err()
                    {
                        break;
                    }
                }
            });
            Ok(Response::new(Box::pin(ReceiverStream::new(responses_rx))))
        }
    }

    async fn recording_middleware_session(
        scheme: &str,
    ) -> (
        openshell_supervisor_middleware::WebSocketSession,
        tokio::sync::mpsc::UnboundedReceiver<ObservedWebSocketRequest>,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<std::result::Result<(), tonic::transport::Error>>,
    ) {
        recording_middleware_session_with_controls(scheme, None, None).await
    }

    async fn recording_middleware_session_with_controls(
        scheme: &str,
        message_received: Option<Arc<tokio::sync::Notify>>,
        release_message: Option<Arc<tokio::sync::Notify>>,
    ) -> (
        openshell_supervisor_middleware::WebSocketSession,
        tokio::sync::mpsc::UnboundedReceiver<ObservedWebSocketRequest>,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<std::result::Result<(), tonic::transport::Error>>,
    ) {
        use openshell_core::proto::SupervisorMiddlewareService;
        use openshell_supervisor_middleware::{ChainEntry, MiddlewareRegistry, OnError};

        let (observed_tx, observed_rx) = tokio::sync::mpsc::unbounded_channel();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind WebSocket middleware");
        let address = listener.local_addr().expect("middleware address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tonic::transport::Server::builder()
            .add_service(SupervisorMiddlewareServer::new(OpenAiWebSocketRedactor {
                observed: Some(observed_tx),
                message_received,
                release_message,
                ..Default::default()
            }))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            });
        let server_task = tokio::spawn(server);
        let registry = MiddlewareRegistry::connect_services(
            Vec::new(),
            vec![SupervisorMiddlewareService {
                name: "openai-redactor".into(),
                grpc_endpoint: format!("http://{address}"),
                max_payload_bytes: openshell_supervisor_middleware::MAX_MIDDLEWARE_PAYLOAD_BYTES
                    as u64,
                timeout: "2s".into(),
                tls_ca_cert_pem: Vec::new(),
                audience: String::new(),
                allow_insecure_transport: false,
            }],
        )
        .await
        .expect("connect middleware");
        let runner = openshell_supervisor_middleware::ChainRunner::from_registry(registry);
        let preflight = runner
            .preflight_websocket(
                &[ChainEntry {
                    name: "redact-openai".into(),
                    implementation: "openai-redactor".into(),
                    order: 0,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                }],
                openshell_supervisor_middleware::WebSocketPreflightInput {
                    session_id: "session".into(),
                    request_id: "request".into(),
                    sandbox_id: "sandbox".into(),
                    scheme: scheme.into(),
                    host: "api.openai.com".into(),
                    port: if scheme == "wss" { 443 } else { 80 },
                    path: "/v1/responses".into(),
                    requested_subprotocols: Vec::new(),
                },
            )
            .await
            .expect("preflight");

        (
            preflight.session.expect("middleware inspects session"),
            observed_rx,
            shutdown_tx,
            server_task,
        )
    }

    async fn assert_invalid_close_termination(payload: Vec<u8>, expected_close_code: u16) {
        let (mut session, mut observed, shutdown_tx, server_task) =
            recording_middleware_session("wss").await;
        assert!(session.start("").await.allowed);
        assert!(matches!(
            observed.recv().await,
            Some(ObservedWebSocketRequest::SessionStart)
        ));

        let (mut client_app, mut relay_client) = tokio::io::duplex(4096);
        let (mut relay_upstream, mut upstream_app) = tokio::io::duplex(4096);
        let relay = tokio::spawn(async move {
            relay_with_options(
                &mut relay_client,
                &mut relay_upstream,
                Vec::new(),
                "api.openai.com",
                443,
                RelayOptions {
                    policy_name: "rest-api",
                    assembly_budget: WebSocketAssemblyBudget::default(),
                    resolver: None,
                    generation_guard: None,
                    provider_credentials: None,
                    target: "/",
                    inspector: None,
                    compression: WebSocketCompression::None,
                    middleware_session: Some(session),
                    middleware_context: None,
                    deny_uninspected_credentials: false,
                },
            )
            .await
        });

        client_app
            .write_all(&masked_frame(true, OPCODE_CLOSE, &payload))
            .await
            .expect("send invalid close frame");
        client_app.flush().await.expect("flush invalid close frame");

        let upstream_close = read_one_frame(&mut upstream_app).await;
        assert_eq!(upstream_close[0] & 0x0f, OPCODE_CLOSE);
        assert_eq!(
            u16::from_be_bytes(
                decode_masked_payload(&upstream_close)[..2]
                    .try_into()
                    .expect("upstream close code"),
            ),
            expected_close_code
        );
        let client_close = read_one_frame(&mut client_app).await;
        assert_eq!(client_close[0] & 0x0f, OPCODE_CLOSE);
        assert_eq!(
            u16::from_be_bytes(client_close[2..4].try_into().expect("client close code")),
            expected_close_code
        );

        relay
            .await
            .expect("join relay")
            .expect_err("invalid close frame must terminate relay");
        assert!(matches!(
            observed.recv().await,
            Some(ObservedWebSocketRequest::SessionEnd(
                openshell_core::proto::WebSocketSessionEndReason::ProtocolError,
            ))
        ));
        assert!(
            observed.try_recv().is_err(),
            "control-frame failure must not invoke middleware"
        );

        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join middleware server")
            .expect("middleware server");
    }

    #[tokio::test]
    async fn invalid_close_frames_close_both_peers_and_report_protocol_session_end() {
        assert_invalid_close_termination(vec![0x03], 1002).await;
        assert_invalid_close_termination(close_payload(1005, b""), 1002).await;
        assert_invalid_close_termination(close_payload(1000, &[0xff]), 1007).await;
    }

    #[test]
    fn invalid_close_frames_have_stable_telemetry_classes() {
        let cases = [
            (
                vec![0x03],
                WebSocketTerminationCause::ProtocolError,
                FrameFailureClass::InvalidCloseFrame,
                1002,
            ),
            (
                close_payload(1005, b""),
                WebSocketTerminationCause::ProtocolError,
                FrameFailureClass::InvalidCloseFrame,
                1002,
            ),
            (
                close_payload(1000, &[0xff]),
                WebSocketTerminationCause::InvalidUtf8,
                FrameFailureClass::InvalidUtf8,
                1007,
            ),
        ];

        for (payload, expected_cause, expected_class, expected_close_code) in cases {
            let frame_error =
                validate_close_payload(&payload).expect_err("close payload must be invalid");
            let termination = WebSocketTermination::from(frame_error);
            assert_eq!(termination.cause, expected_cause);
            assert_eq!(termination.failure_class, Some(expected_class));
            assert_eq!(termination.cause.close_code(), Some(expected_close_code));

            let event =
                protocol_failure_event("gateway.example.test", 443, "test-policy", expected_class);
            assert_eq!(
                event.base().status_detail.as_deref(),
                Some(expected_class.as_str())
            );
        }
    }

    #[tokio::test]
    async fn partial_control_payload_eof_is_peer_disconnect_without_generated_close() {
        let (mut session, mut observed, shutdown_tx, server_task) =
            recording_middleware_session("wss").await;
        assert!(session.start("").await.allowed);
        assert!(matches!(
            observed.recv().await,
            Some(ObservedWebSocketRequest::SessionStart)
        ));

        let (mut client_app, mut relay_client) = tokio::io::duplex(4096);
        let (mut relay_upstream, mut upstream_app) = tokio::io::duplex(4096);
        let relay = tokio::spawn(async move {
            relay_with_options(
                &mut relay_client,
                &mut relay_upstream,
                Vec::new(),
                "api.openai.com",
                443,
                RelayOptions {
                    policy_name: "rest-api",
                    assembly_budget: WebSocketAssemblyBudget::default(),
                    resolver: None,
                    generation_guard: None,
                    provider_credentials: None,
                    target: "/",
                    inspector: None,
                    compression: WebSocketCompression::None,
                    middleware_session: Some(session),
                    middleware_context: None,
                    deny_uninspected_credentials: false,
                },
            )
            .await
        });

        client_app
            .write_all(&[0x80 | OPCODE_CLOSE, 0x80 | 2, 0x37, 0xfa, 0x21, 0x3d])
            .await
            .expect("send truncated close frame");
        drop(client_app);

        let mut upstream_output = Vec::new();
        upstream_app
            .read_to_end(&mut upstream_output)
            .await
            .expect("read upstream shutdown");
        assert!(
            upstream_output.is_empty(),
            "peer EOF must not generate an upstream close frame"
        );
        relay
            .await
            .expect("join relay")
            .expect_err("truncated payload must end relay");
        assert!(matches!(
            observed.recv().await,
            Some(ObservedWebSocketRequest::SessionEnd(
                openshell_core::proto::WebSocketSessionEndReason::PeerDisconnect,
            ))
        ));

        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join middleware server")
            .expect("middleware server");
    }

    #[tokio::test]
    async fn denied_websocket_session_start_reports_middleware_failure_before_close() {
        let (session, mut observed, shutdown_tx, server_task) =
            recording_middleware_session("wss").await;
        let (mut client_app, mut relay_client) = tokio::io::duplex(4096);
        let (mut relay_upstream, mut upstream_app) = tokio::io::duplex(4096);

        crate::l7::relay::handle_upgrade(
            &mut relay_client,
            &mut relay_upstream,
            Vec::new(),
            "api.openai.com",
            443,
            crate::l7::relay::UpgradeRelayOptions {
                websocket_request: true,
                assembly_budget: Some(WebSocketAssemblyBudget::default()),
                middleware_session: Some(session),
                selected_subprotocol: Some("x".repeat(257)),
                ..Default::default()
            },
        )
        .await
        .expect("denied session start closes cleanly");

        assert!(matches!(
            observed.recv().await,
            Some(ObservedWebSocketRequest::SessionEnd(
                openshell_core::proto::WebSocketSessionEndReason::MiddlewareFailure,
            ))
        ));
        assert!(
            observed.try_recv().is_err(),
            "session start failure must send exactly one terminal event"
        );

        let client_close = read_one_frame(&mut client_app).await;
        assert_eq!(client_close[0] & 0x0f, OPCODE_CLOSE);
        assert_eq!(
            u16::from_be_bytes(client_close[2..4].try_into().expect("client close code")),
            1008
        );
        let upstream_close = read_one_frame(&mut upstream_app).await;
        assert_eq!(upstream_close[0] & 0x0f, OPCODE_CLOSE);
        assert_eq!(
            u16::from_be_bytes(
                decode_masked_payload(&upstream_close)[..2]
                    .try_into()
                    .expect("upstream close code"),
            ),
            1008
        );

        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join middleware server")
            .expect("middleware server");
    }

    #[tokio::test]
    async fn selected_middleware_reports_binary_gap_and_inspects_later_text_at_next_sequence() {
        let (session, mut observed, shutdown_tx, server_task) =
            recording_middleware_session("wss").await;
        let (mut client_app, mut relay_client) = tokio::io::duplex(4096);
        let (mut relay_upstream, mut upstream_app) = tokio::io::duplex(4096);
        let relay = tokio::spawn(async move {
            crate::l7::relay::handle_upgrade(
                &mut relay_client,
                &mut relay_upstream,
                Vec::new(),
                "api.openai.com",
                443,
                crate::l7::relay::UpgradeRelayOptions {
                    websocket_request: true,
                    assembly_budget: Some(WebSocketAssemblyBudget::default()),
                    ctx: Some(&L7EvalContext {
                        host: "api.openai.com".into(),
                        port: 443,
                        policy_name: "rest-api".into(),
                        ..Default::default()
                    }),
                    policy_name: "rest-api".into(),
                    middleware_session: Some(session),
                    ..Default::default()
                },
            )
            .await
        });

        assert!(matches!(
            observed.recv().await,
            Some(ObservedWebSocketRequest::SessionStart)
        ));

        let binary = masked_frame(true, OPCODE_BINARY, &[0, 1, 2, 3, 255]);
        let text = masked_frame(true, OPCODE_TEXT, br#"{"type":"response.create"}"#);
        client_app
            .write_all(&binary)
            .await
            .expect("send binary message");
        client_app
            .write_all(&text)
            .await
            .expect("send text message");

        assert_eq!(read_one_frame(&mut upstream_app).await, binary);
        assert_eq!(
            decode_masked_text_frame(&read_one_frame(&mut upstream_app).await),
            r#"{"type":"response.create"}"#
        );
        assert!(matches!(
            observed.recv().await,
            Some(ObservedWebSocketRequest::Message {
                sequence: 2,
                payload,
            }) if payload == r#"{"type":"response.create"}"#
        ));

        drop(client_app);
        drop(upstream_app);
        tokio::time::timeout(std::time::Duration::from_secs(2), relay)
            .await
            .expect("relay should stop")
            .expect("join relay")
            .expect("relay result");

        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join middleware server")
            .expect("middleware server");
    }

    async fn assert_middleware_only_relay_observes_reload(scheme: &str, fragmented: bool) {
        use openshell_supervisor_middleware::MiddlewareRegistry;

        let (session, mut observed, shutdown_tx, server_task) =
            recording_middleware_session(scheme).await;
        let engine = Arc::new(
            OpaEngine::from_strings(TEST_POLICY, "network_policies: {}\n").expect("test policy"),
        );
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .expect("generation guard");
        let (mut client_app, mut relay_client) = tokio::io::duplex(4096);
        let (mut relay_upstream, mut upstream_app) = tokio::io::duplex(4096);
        let port = if scheme == "wss" { 443 } else { 80 };
        let relay = tokio::spawn(async move {
            crate::l7::relay::handle_upgrade(
                &mut relay_client,
                &mut relay_upstream,
                Vec::new(),
                "api.openai.com",
                port,
                crate::l7::relay::UpgradeRelayOptions {
                    websocket_request: true,
                    assembly_budget: Some(WebSocketAssemblyBudget::default()),
                    generation_guard: Some(&generation_guard),
                    ctx: Some(&L7EvalContext {
                        host: "api.openai.com".into(),
                        port,
                        policy_name: "rest-api".into(),
                        ..Default::default()
                    }),
                    policy_name: "rest-api".into(),
                    middleware_session: Some(session),
                    ..Default::default()
                },
            )
            .await
        });

        assert!(matches!(
            observed.recv().await,
            Some(ObservedWebSocketRequest::SessionStart)
        ));
        let stale_frame = if fragmented {
            masked_frame(true, OPCODE_CONTINUATION, b"message")
        } else {
            masked_frame(true, OPCODE_TEXT, b"stale-message")
        };
        if fragmented {
            client_app
                .write_all(&masked_frame(false, OPCODE_TEXT, b"stale-"))
                .await
                .expect("send initial fragment");
        } else {
            client_app
                .write_all(&stale_frame[..7])
                .await
                .expect("send frame header and partial payload");
        }

        engine
            .replace_middleware_registry(MiddlewareRegistry::default())
            .expect("invalidate generation");
        let stale_input = if fragmented {
            &stale_frame[..6]
        } else {
            &stale_frame[7..]
        };
        client_app
            .write_all(stale_input)
            .await
            .expect("send stale data frame");

        let upstream_close = read_one_frame(&mut upstream_app).await;
        assert_eq!(upstream_close[0] & 0x0f, OPCODE_CLOSE);
        assert_eq!(
            u16::from_be_bytes(
                decode_masked_payload(&upstream_close)[..2]
                    .try_into()
                    .expect("upstream close code"),
            ),
            1012
        );
        let client_close = read_one_frame(&mut client_app).await;
        assert_eq!(client_close[0] & 0x0f, OPCODE_CLOSE);
        assert_eq!(
            u16::from_be_bytes(client_close[2..4].try_into().expect("client close code")),
            1012
        );
        let error = relay
            .await
            .expect("join relay")
            .expect_err("stale generation must terminate relay");
        assert!(error.to_string().contains("policy generation is stale"));
        match observed.recv().await {
            Some(ObservedWebSocketRequest::SessionEnd(
                openshell_core::proto::WebSocketSessionEndReason::PolicyReload,
            )) => {}
            Some(ObservedWebSocketRequest::Message { payload, .. }) => {
                panic!("stale message leaked {} bytes to middleware", payload.len());
            }
            other => panic!("unexpected middleware lifecycle event: {other:?}"),
        }
        assert!(
            observed.try_recv().is_err(),
            "stale data must not reach middleware"
        );

        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join middleware server")
            .expect("middleware server");
    }

    #[tokio::test]
    async fn middleware_only_rest_wss_relay_observes_policy_reload() {
        assert_middleware_only_relay_observes_reload("wss", false).await;
    }

    #[tokio::test]
    async fn middleware_only_rest_ws_relay_stops_fragment_after_policy_reload() {
        assert_middleware_only_relay_observes_reload("ws", true).await;
    }

    #[tokio::test]
    async fn reload_during_middleware_evaluation_blocks_credentials_and_payload() {
        use openshell_supervisor_middleware::MiddlewareRegistry;

        let message_received = Arc::new(tokio::sync::Notify::new());
        let release_message = Arc::new(tokio::sync::Notify::new());
        let (session, mut observed, shutdown_tx, server_task) =
            recording_middleware_session_with_controls(
                "wss",
                Some(Arc::clone(&message_received)),
                Some(Arc::clone(&release_message)),
            )
            .await;
        let engine = Arc::new(
            OpaEngine::from_strings(TEST_POLICY, "network_policies: {}\n").expect("test policy"),
        );
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .expect("generation guard");
        let assembly_budget = engine.websocket_assembly_budget();
        let (child_env, resolver) = resolver();
        let placeholder = child_env
            .get("DISCORD_BOT_TOKEN")
            .expect("credential placeholder")
            .clone();
        let (mut client_app, mut relay_client) = tokio::io::duplex(4096);
        let (mut relay_upstream, mut upstream_app) = tokio::io::duplex(4096);
        let relay = tokio::spawn(async move {
            crate::l7::relay::handle_upgrade(
                &mut relay_client,
                &mut relay_upstream,
                Vec::new(),
                "api.openai.com",
                443,
                crate::l7::relay::UpgradeRelayOptions {
                    websocket_request: true,
                    websocket: crate::l7::relay::WebSocketUpgradeBehavior {
                        credential_rewrite: true,
                        ..Default::default()
                    },
                    assembly_budget: Some(assembly_budget),
                    secret_resolver: Some(Arc::new(resolver)),
                    generation_guard: Some(&generation_guard),
                    policy_name: "rest-api".into(),
                    middleware_session: Some(session),
                    ..Default::default()
                },
            )
            .await
        });

        assert!(matches!(
            observed.recv().await,
            Some(ObservedWebSocketRequest::SessionStart)
        ));
        let payload = format!(r#"{{"authorization":"{placeholder}"}}"#);
        client_app
            .write_all(&masked_frame(true, OPCODE_TEXT, payload.as_bytes()))
            .await
            .expect("send credential-bearing message");
        message_received.notified().await;

        engine
            .replace_middleware_registry(MiddlewareRegistry::default())
            .expect("invalidate generation");
        release_message.notify_one();

        let upstream_close = read_one_frame(&mut upstream_app).await;
        assert_eq!(upstream_close[0] & 0x0f, OPCODE_CLOSE);
        assert_eq!(
            u16::from_be_bytes(
                decode_masked_payload(&upstream_close)[..2]
                    .try_into()
                    .expect("upstream close code"),
            ),
            1012
        );
        assert!(
            !String::from_utf8_lossy(&upstream_close).contains("real-token"),
            "resolved credential must not reach upstream"
        );
        let error = relay
            .await
            .expect("join relay")
            .expect_err("stale generation must terminate relay");
        assert!(error.to_string().contains("policy generation is stale"));

        let mut end_reason = None;
        while let Some(event) = observed.recv().await {
            if let ObservedWebSocketRequest::SessionEnd(reason) = event {
                end_reason = Some(reason);
                break;
            }
        }
        assert_eq!(
            end_reason,
            Some(openshell_core::proto::WebSocketSessionEndReason::PolicyReload)
        );

        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join middleware server")
            .expect("middleware server");
    }

    #[tokio::test]
    async fn pre_upgrade_reload_finalizes_session_as_policy_reload() {
        use openshell_supervisor_middleware::MiddlewareRegistry;

        let (session, mut observed, shutdown_tx, server_task) =
            recording_middleware_session("wss").await;
        let engine =
            OpaEngine::from_strings(TEST_POLICY, "network_policies: {}\n").expect("test policy");
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .expect("generation guard");
        engine
            .replace_middleware_registry(MiddlewareRegistry::default())
            .expect("invalidate generation");
        let mut session = Some(session);

        crate::l7::relay::finalize_websocket_pre_upgrade(
            &mut session,
            &generation_guard,
            "api.openai.com",
            443,
            "rest-api",
            Ok(crate::l7::provider::RelayOutcome::Reusable),
        )
        .await
        .expect_err("reload before upgrade must terminate");
        assert!(session.is_none());
        assert!(matches!(
            observed.recv().await,
            Some(ObservedWebSocketRequest::SessionEnd(
                openshell_core::proto::WebSocketSessionEndReason::PolicyReload
            ))
        ));

        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join middleware server")
            .expect("middleware server");
    }

    #[tokio::test]
    async fn reload_after_forwarded_upgrade_uses_typed_close_path() {
        use openshell_supervisor_middleware::MiddlewareRegistry;

        let (session, mut observed, shutdown_tx, server_task) =
            recording_middleware_session("wss").await;
        let engine =
            OpaEngine::from_strings(TEST_POLICY, "network_policies: {}\n").expect("test policy");
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .expect("generation guard");
        engine
            .replace_middleware_registry(MiddlewareRegistry::default())
            .expect("invalidate generation");
        let mut session = Some(session);
        let upgrade_response = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let (mut client_app, mut relay_client) = tokio::io::duplex(4096);
        let (mut relay_upstream, mut upstream_app) = tokio::io::duplex(4096);
        relay_client
            .write_all(upgrade_response)
            .await
            .expect("forward upgrade response");

        let outcome = crate::l7::relay::finalize_websocket_pre_upgrade(
            &mut session,
            &generation_guard,
            "api.openai.com",
            443,
            "rest-api",
            Ok(crate::l7::provider::RelayOutcome::Upgraded {
                overflow: Vec::new(),
                websocket_permessage_deflate: false,
                websocket_subprotocol: None,
            }),
        )
        .await
        .expect("upgraded outcome must reach typed close path");
        let crate::l7::provider::RelayOutcome::Upgraded {
            overflow,
            websocket_permessage_deflate,
            websocket_subprotocol,
        } = outcome
        else {
            panic!("expected upgraded outcome")
        };

        let error = crate::l7::relay::handle_upgrade(
            &mut relay_client,
            &mut relay_upstream,
            overflow,
            "api.openai.com",
            443,
            crate::l7::relay::UpgradeRelayOptions {
                websocket_request: true,
                websocket: crate::l7::relay::WebSocketUpgradeBehavior {
                    permessage_deflate: websocket_permessage_deflate,
                    ..Default::default()
                },
                assembly_budget: Some(WebSocketAssemblyBudget::default()),
                generation_guard: Some(&generation_guard),
                policy_name: "rest-api".into(),
                middleware_session: session.take(),
                selected_subprotocol: websocket_subprotocol,
                ..Default::default()
            },
        )
        .await
        .expect_err("stale upgraded connection must close");
        assert!(error.to_string().contains("policy generation is stale"));

        let mut client_output = Vec::new();
        client_app
            .read_to_end(&mut client_output)
            .await
            .expect("read upgrade and close");
        assert_eq!(&client_output[..upgrade_response.len()], upgrade_response);
        assert_eq!(
            &client_output[upgrade_response.len()..],
            &[0x88, 0x02, 0x03, 0xf4]
        );
        let upstream_close = read_one_frame(&mut upstream_app).await;
        assert_eq!(upstream_close[0] & 0x0f, OPCODE_CLOSE);
        assert_eq!(
            u16::from_be_bytes(
                decode_masked_payload(&upstream_close)[..2]
                    .try_into()
                    .expect("upstream close code"),
            ),
            1012
        );
        assert!(matches!(
            observed.recv().await,
            Some(ObservedWebSocketRequest::SessionEnd(
                openshell_core::proto::WebSocketSessionEndReason::PolicyReload
            ))
        ));

        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join middleware server")
            .expect("middleware server");
    }

    #[tokio::test]
    async fn graphql_policy_denial_reports_policy_denial_to_middleware() {
        let (mut session, mut observed, shutdown_tx, server_task) =
            recording_middleware_session("wss").await;
        assert!(session.start("").await.allowed);
        assert!(matches!(
            observed.recv().await,
            Some(ObservedWebSocketRequest::SessionStart)
        ));

        let engine = OpaEngine::from_strings(TEST_POLICY, GRAPHQL_WS_POLICY)
            .expect("GraphQL WebSocket policy should load");
        let network_input = NetworkInput {
            host: "realtime.graphql.test".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let generation = engine
            .evaluate_network_action_with_generation(&network_input)
            .expect("network action should evaluate")
            .1;
        let tunnel_engine = engine
            .clone_engine_for_tunnel(generation)
            .expect("tunnel engine");
        let ctx = L7EvalContext {
            host: "realtime.graphql.test".into(),
            port: 443,
            policy_name: "graphql_ws".into(),
            binary_path: "/usr/bin/node".into(),
            ..Default::default()
        };
        let (mut client_app, mut relay_client) = tokio::io::duplex(4096);
        let (mut relay_upstream, mut upstream_app) = tokio::io::duplex(4096);
        let relay = tokio::spawn(async move {
            relay_with_options(
                &mut relay_client,
                &mut relay_upstream,
                Vec::new(),
                "realtime.graphql.test",
                443,
                RelayOptions {
                    policy_name: "graphql_ws",
                    assembly_budget: WebSocketAssemblyBudget::default(),
                    resolver: None,
                    generation_guard: Some(tunnel_engine.generation_guard()),
                    provider_credentials: None,
                    target: "/graphql",
                    inspector: Some(InspectionOptions {
                        engine: &tunnel_engine,
                        ctx: &ctx,
                        enforcement: EnforcementMode::Enforce,
                        target: "/graphql".into(),
                        query_params: HashMap::new(),
                        graphql_policy: true,
                    }),
                    compression: WebSocketCompression::None,
                    middleware_session: Some(session),
                    middleware_context: Some(&ctx),
                    deny_uninspected_credentials: false,
                },
            )
            .await
        });

        let payload =
            br#"{"type":"subscribe","id":"1","payload":{"query":"query Admin { adminAuditLog }"}}"#;
        client_app
            .write_all(&masked_frame(true, OPCODE_TEXT, payload))
            .await
            .expect("send policy-denied message");

        let upstream_close = read_one_frame(&mut upstream_app).await;
        assert_eq!(
            u16::from_be_bytes(
                decode_masked_payload(&upstream_close)[..2]
                    .try_into()
                    .expect("upstream close code"),
            ),
            1008
        );
        let client_close = read_one_frame(&mut client_app).await;
        assert_eq!(
            u16::from_be_bytes(client_close[2..4].try_into().expect("client close code")),
            1008
        );
        let error = relay
            .await
            .expect("join relay")
            .expect_err("policy denial must terminate relay");
        assert!(
            error
                .to_string()
                .contains("websocket GraphQL message denied")
        );
        match observed.recv().await {
            Some(ObservedWebSocketRequest::SessionEnd(
                openshell_core::proto::WebSocketSessionEndReason::PolicyDenial,
            )) => {}
            Some(ObservedWebSocketRequest::Message { payload, .. }) => {
                panic!(
                    "built-in policy denial leaked {} bytes to middleware",
                    payload.len()
                );
            }
            other => panic!("unexpected middleware lifecycle event: {other:?}"),
        }

        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join middleware server")
            .expect("middleware server");
    }

    #[tokio::test]
    async fn parsed_relay_sends_redacted_openai_event_to_upstream() {
        use openshell_core::proto::SupervisorMiddlewareService;
        use openshell_supervisor_middleware::{ChainEntry, MiddlewareRegistry, OnError};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind WebSocket middleware");
        let address = listener.local_addr().expect("middleware address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tonic::transport::Server::builder()
            .add_service(SupervisorMiddlewareServer::new(
                OpenAiWebSocketRedactor::default(),
            ))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            });
        let server_task = tokio::spawn(server);
        let registry = MiddlewareRegistry::connect_services(
            Vec::new(),
            vec![SupervisorMiddlewareService {
                name: "openai-redactor".into(),
                grpc_endpoint: format!("http://{address}"),
                max_payload_bytes: openshell_supervisor_middleware::MAX_MIDDLEWARE_PAYLOAD_BYTES
                    as u64,
                timeout: "2s".into(),
                tls_ca_cert_pem: Vec::new(),
                audience: String::new(),
                allow_insecure_transport: false,
            }],
        )
        .await
        .expect("connect middleware");
        let runner = openshell_supervisor_middleware::ChainRunner::from_registry(registry);
        let preflight = runner
            .preflight_websocket(
                &[ChainEntry {
                    name: "redact-openai".into(),
                    implementation: "openai-redactor".into(),
                    order: 0,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                }],
                openshell_supervisor_middleware::WebSocketPreflightInput {
                    session_id: "session".into(),
                    request_id: "request".into(),
                    sandbox_id: "sandbox".into(),
                    scheme: "wss".into(),
                    host: "api.openai.com".into(),
                    port: 443,
                    path: "/v1/responses".into(),
                    requested_subprotocols: Vec::new(),
                },
            )
            .await
            .expect("preflight");
        let mut session = preflight.session.expect("middleware inspects session");
        assert!(session.start("").await.allowed);

        let original = br#"{"type":"response.create","response":{"input":"customer-secret"}}"#;
        let client_frame = masked_frame(true, OPCODE_TEXT, original);
        let (mut client_app, mut relay_client) = tokio::io::duplex(4096);
        let (mut relay_upstream, mut upstream_app) = tokio::io::duplex(4096);
        let relay = tokio::spawn(async move {
            relay_with_options(
                &mut relay_client,
                &mut relay_upstream,
                Vec::new(),
                "api.openai.com",
                443,
                RelayOptions {
                    policy_name: "openai",
                    assembly_budget: WebSocketAssemblyBudget::default(),
                    resolver: None,
                    generation_guard: None,
                    provider_credentials: None,
                    target: "/",
                    inspector: None,
                    compression: WebSocketCompression::None,
                    middleware_session: Some(session),
                    middleware_context: None,
                    deny_uninspected_credentials: false,
                },
            )
            .await
        });

        client_app
            .write_all(&client_frame)
            .await
            .expect("send event");
        client_app.flush().await.expect("flush event");
        let upstream_frame = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_one_frame(&mut upstream_app),
        )
        .await
        .expect("upstream receives event");
        let upstream_text = decode_masked_text_frame(&upstream_frame);
        assert!(upstream_text.contains("[REDACTED]"));
        assert!(!upstream_text.contains("customer-secret"));

        let denied = br#"{"type":"response.create","response":{"input":"deny-me"}}"#;
        client_app
            .write_all(&masked_frame(true, OPCODE_TEXT, denied))
            .await
            .expect("send denied event");
        client_app.flush().await.expect("flush denied event");
        let upstream_close = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_one_frame(&mut upstream_app),
        )
        .await
        .expect("upstream receives close");
        assert_eq!(upstream_close[0] & 0x0f, OPCODE_CLOSE);
        assert_eq!(
            u16::from_be_bytes(
                decode_masked_payload(&upstream_close)[..2]
                    .try_into()
                    .expect("close code"),
            ),
            1008
        );
        let client_close = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_one_frame(&mut client_app),
        )
        .await
        .expect("client receives close");
        assert_eq!(client_close[0] & 0x0f, OPCODE_CLOSE);
        assert_eq!(
            u16::from_be_bytes(client_close[2..4].try_into().expect("close code")),
            1008
        );

        drop(client_app);
        drop(upstream_app);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), relay).await;
        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join middleware")
            .expect("serve middleware");
    }

    #[tokio::test]
    async fn fully_disabled_session_bypasses_saturated_work_budget_without_rpc() {
        use openshell_core::proto::SupervisorMiddlewareService;
        use openshell_supervisor_middleware::{ChainEntry, MiddlewareRegistry, OnError};

        let (observed_tx, mut observed_rx) = tokio::sync::mpsc::unbounded_channel();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind WebSocket middleware");
        let address = listener.local_addr().expect("middleware address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tonic::transport::Server::builder()
            .add_service(SupervisorMiddlewareServer::new(OpenAiWebSocketRedactor {
                observed: Some(observed_tx),
                close_on_first_message: true,
                ..Default::default()
            }))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            });
        let server_task = tokio::spawn(server);
        let registry = MiddlewareRegistry::connect_services(
            Vec::new(),
            vec![SupervisorMiddlewareService {
                name: "openai-redactor".into(),
                grpc_endpoint: format!("http://{address}"),
                max_payload_bytes: openshell_supervisor_middleware::MAX_MIDDLEWARE_PAYLOAD_BYTES
                    as u64,
                timeout: "2s".into(),
                tls_ca_cert_pem: Vec::new(),
                audience: String::new(),
                allow_insecure_transport: false,
            }],
        )
        .await
        .expect("connect middleware");
        let runner = openshell_supervisor_middleware::ChainRunner::from_registry(registry);
        let preflight = runner
            .preflight_websocket(
                &[ChainEntry {
                    name: "redact-openai".into(),
                    implementation: "openai-redactor".into(),
                    order: 0,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailOpen,
                }],
                openshell_supervisor_middleware::WebSocketPreflightInput {
                    session_id: "disabled-session".into(),
                    request_id: "request".into(),
                    sandbox_id: "sandbox".into(),
                    scheme: "wss".into(),
                    host: "api.openai.com".into(),
                    port: 443,
                    path: "/v1/responses".into(),
                    requested_subprotocols: Vec::new(),
                },
            )
            .await
            .expect("preflight");
        let mut session = preflight.session.expect("middleware inspects session");
        assert!(session.start("").await.allowed);
        assert!(matches!(
            observed_rx.recv().await,
            Some(ObservedWebSocketRequest::SessionStart)
        ));

        let failed = session
            .evaluate_text(r#"{"type":"response.create"}"#.into())
            .await;
        assert!(failed.allowed);
        assert!(failed.invocations[0].stage_disabled);
        assert!(matches!(
            observed_rx.recv().await,
            Some(ObservedWebSocketRequest::Message { .. })
        ));

        let mut occupied_work = Vec::new();
        for _ in 0..openshell_supervisor_middleware::MAX_CONCURRENT_MIDDLEWARE_WORK {
            occupied_work.push(
                runner
                    .reserve_middleware_work_admission()
                    .await
                    .expect("fill middleware work budget"),
            );
        }

        let original = r#"{"type":"response.cancel","reason":"keep-original"}"#;
        let client_frame = masked_frame(true, OPCODE_TEXT, original.as_bytes());
        let (mut client_app, mut relay_client) = tokio::io::duplex(4096);
        let (mut relay_upstream, mut upstream_app) = tokio::io::duplex(4096);
        let relay = tokio::spawn(async move {
            relay_with_options(
                &mut relay_client,
                &mut relay_upstream,
                Vec::new(),
                "api.openai.com",
                443,
                RelayOptions {
                    policy_name: "openai",
                    assembly_budget: WebSocketAssemblyBudget::default(),
                    resolver: None,
                    generation_guard: None,
                    provider_credentials: None,
                    target: "/",
                    inspector: None,
                    compression: WebSocketCompression::None,
                    middleware_session: Some(session),
                    middleware_context: None,
                    deny_uninspected_credentials: false,
                },
            )
            .await
        });

        client_app
            .write_all(&client_frame)
            .await
            .expect("send bypassed event");
        client_app.flush().await.expect("flush bypassed event");
        let upstream_frame = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_one_frame(&mut upstream_app),
        )
        .await
        .expect("fully disabled session bypasses saturated work");
        assert_eq!(decode_masked_text_frame(&upstream_frame), original);
        assert!(
            observed_rx.try_recv().is_err(),
            "fully disabled session must not make another middleware RPC"
        );

        drop(occupied_work);
        drop(client_app);
        drop(upstream_app);
        tokio::time::timeout(std::time::Duration::from_secs(2), relay)
            .await
            .expect("relay finishes after disconnect")
            .expect("join relay")
            .expect("relay");
        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join middleware")
            .expect("serve middleware");
    }

    #[tokio::test]
    async fn parsed_relay_uses_builtin_regex_for_complete_client_text_messages() {
        use openshell_supervisor_middleware::{ChainEntry, MiddlewareRegistry, OnError};

        let registry = MiddlewareRegistry::connect_services(
            openshell_supervisor_middleware_builtins::services(),
            Vec::new(),
        )
        .await
        .expect("connect built-in middleware");
        let runner = openshell_supervisor_middleware::ChainRunner::from_registry(registry);
        let preflight = runner
            .preflight_websocket(
                &[ChainEntry {
                    name: "regex-redactor".into(),
                    implementation: openshell_supervisor_middleware_builtins::BUILTIN_REGEX.into(),
                    order: 0,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                }],
                openshell_supervisor_middleware::WebSocketPreflightInput {
                    session_id: "builtin-regex-session".into(),
                    request_id: "request".into(),
                    sandbox_id: "sandbox".into(),
                    scheme: "wss".into(),
                    host: "api.openai.com".into(),
                    port: 443,
                    path: "/v1/responses".into(),
                    requested_subprotocols: Vec::new(),
                },
            )
            .await
            .expect("preflight");
        let mut session = preflight.session.expect("built-in inspects session");
        assert!(session.start("").await.allowed);

        let original = br#"{"type":"response.create","response":{"input":"sk-ABCDEFGHIJKLMNOP"}}"#;
        let (mut client_app, mut relay_client) = tokio::io::duplex(4096);
        let (mut relay_upstream, mut upstream_app) = tokio::io::duplex(4096);
        let relay = tokio::spawn(async move {
            relay_with_options(
                &mut relay_client,
                &mut relay_upstream,
                Vec::new(),
                "api.openai.com",
                443,
                RelayOptions {
                    policy_name: "openai",
                    assembly_budget: WebSocketAssemblyBudget::default(),
                    resolver: None,
                    generation_guard: None,
                    provider_credentials: None,
                    target: "/",
                    inspector: None,
                    compression: WebSocketCompression::None,
                    middleware_session: Some(session),
                    middleware_context: None,
                    deny_uninspected_credentials: false,
                },
            )
            .await
        });

        let split = original
            .windows(b"sk-ABC".len())
            .position(|window| window == b"sk-ABC")
            .expect("token prefix")
            + b"sk-ABC".len();
        client_app
            .write_all(&masked_frame(false, OPCODE_TEXT, &original[..split]))
            .await
            .expect("send initial event fragment");
        client_app
            .write_all(&masked_frame(true, OPCODE_CONTINUATION, &original[split..]))
            .await
            .expect("send final event fragment");
        let upstream_frame = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_one_frame(&mut upstream_app),
        )
        .await
        .expect("upstream receives event");
        let upstream_text = decode_masked_text_frame(&upstream_frame);
        assert_eq!(
            upstream_text,
            r#"{"type":"response.create","response":{"input":"[REDACTED]"}}"#
        );

        drop(client_app);
        drop(upstream_app);
        tokio::time::timeout(std::time::Duration::from_secs(2), relay)
            .await
            .expect("relay finishes after disconnect")
            .expect("join relay")
            .expect("relay");
    }

    #[tokio::test]
    #[ignore = "PR 2 adds return-path inspection and completes this full-duplex fixture"]
    async fn pr2_full_duplex_external_middleware_vertical_slice() {
        // PR 2 should extend the real relay fixture above with controllable
        // server-to-client transforms plus slow, hanging, closed, duplicate,
        // missing, out-of-order, and oversized middleware responses.
        let deferred_faults = [
            "slow",
            "hanging",
            "closed",
            "duplicate",
            "missing",
            "out-of-order",
            "oversized",
        ];
        assert_eq!(deferred_faults.len(), 7);
    }

    #[tokio::test]
    async fn graphql_websocket_policy_allows_subscription_operation() {
        let payload = r#"{"type":"subscribe","id":"1","payload":{"query":"subscription NewMessages { messageAdded }"}}"#;
        let frame = masked_frame(true, OPCODE_TEXT, payload.as_bytes());

        let output = run_client_to_server_with_graphql_policy(frame.clone(), None)
            .await
            .expect("allowed subscription should relay");

        assert_eq!(output, frame);
        assert_eq!(decode_masked_text_frame(&output), payload);
    }

    #[tokio::test]
    async fn graphql_websocket_policy_denies_unlisted_operation_field() {
        let payload =
            r#"{"type":"subscribe","id":"1","payload":{"query":"query Admin { adminAuditLog }"}}"#;
        let frame = masked_frame(true, OPCODE_TEXT, payload.as_bytes());

        let err = run_client_to_server_with_graphql_policy(frame, None)
            .await
            .expect_err("unlisted field should be denied");

        assert!(err.to_string().contains("websocket GraphQL message denied"));
    }

    #[tokio::test]
    async fn graphql_websocket_control_message_rewrites_credentials_before_relay() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            std::iter::once(("T".to_string(), "real-token".to_string())).collect(),
        );
        let resolver = resolver.expect("resolver");
        let placeholder = child_env.get("T").expect("placeholder env");
        let payload = format!(
            r#"{{"type":"connection_init","payload":{{"authorization":"{placeholder}"}}}}"#
        );
        let frame = masked_frame(true, OPCODE_TEXT, payload.as_bytes());

        let output = run_client_to_server_with_graphql_policy(frame, Some(&resolver))
            .await
            .expect("control message should relay after credential rewrite");

        let rewritten = decode_masked_text_frame(&output);
        assert_eq!(
            rewritten,
            r#"{"type":"connection_init","payload":{"authorization":"real-token"}}"#
        );
        assert!(!rewritten.contains(placeholder));
    }

    #[tokio::test]
    async fn text_without_placeholder_passes_semantically_unchanged() {
        let frame = masked_frame(true, OPCODE_TEXT, br#"{"op":1,"d":42}"#);
        let output = run_client_to_server(frame.clone())
            .await
            .expect("relay should succeed");

        assert_eq!(output, frame);
        assert_eq!(decode_masked_text_frame(&output), r#"{"op":1,"d":42}"#);
    }

    #[tokio::test]
    async fn unknown_placeholder_fails_closed() {
        let frame = masked_frame(
            true,
            OPCODE_TEXT,
            br#"{"token":"openshell:resolve:env:UNKNOWN"}"#,
        );

        let err = run_client_to_server(frame)
            .await
            .expect_err("unknown placeholder should fail");

        assert!(
            err.to_string()
                .contains("credential placeholder resolution")
        );
    }

    #[tokio::test]
    async fn fragmented_text_rewrites_after_final_continuation() {
        let (child_env, _) = resolver();
        let placeholder = child_env.get("DISCORD_BOT_TOKEN").unwrap();
        let first = format!(r#"{{"token":"{placeholder}"#);
        let second = r#""}"#;
        let mut input = masked_frame(false, OPCODE_TEXT, first.as_bytes());
        input.extend(masked_frame(true, OPCODE_CONTINUATION, second.as_bytes()));

        let output = run_client_to_server(input)
            .await
            .expect("relay should succeed");

        assert_eq!(
            decode_masked_text_frame(&output),
            r#"{"token":"real-token"}"#
        );
    }

    #[tokio::test]
    async fn rejects_rsv_bits() {
        let mut frame = masked_frame(true, OPCODE_TEXT, b"hello");
        frame[0] |= 0x40;

        let err = run_client_to_server(frame)
            .await
            .expect_err("RSV frame should fail");

        assert!(err.to_string().contains("RSV bits"));
    }

    #[tokio::test]
    async fn rejects_unmasked_client_frame() {
        let err = run_client_to_server(unmasked_frame(OPCODE_TEXT, b"hello"))
            .await
            .expect_err("unmasked frame should fail");

        assert!(err.to_string().contains("not masked"));
    }

    #[tokio::test]
    async fn rejects_invalid_utf8_text() {
        let err = run_client_to_server(masked_frame(true, OPCODE_TEXT, &[0xff]))
            .await
            .expect_err("invalid UTF-8 should fail");

        assert!(err.to_string().contains("valid UTF-8"));
    }

    #[tokio::test]
    async fn rejects_oversize_text_message() {
        let payload = vec![b'a'; MAX_TEXT_MESSAGE_BYTES + 1];
        let err = run_client_to_server(masked_frame(true, OPCODE_TEXT, &payload))
            .await
            .expect_err("oversize text should fail");

        assert!(err.to_string().contains("exceeds"));
    }

    #[tokio::test]
    async fn fragmented_text_allows_interleaved_ping_pong_and_rewrites_at_completion() {
        let (child_env, _) = resolver();
        let placeholder = child_env.get("DISCORD_BOT_TOKEN").unwrap();
        let first = format!(r#"{{"token":"{placeholder}"#);
        let first_control_frame = masked_frame(true, OPCODE_PING, b"p");
        let second_control_frame = masked_frame(true, OPCODE_PONG, b"q");
        let mut input = masked_frame(false, OPCODE_TEXT, first.as_bytes());
        input.extend_from_slice(&first_control_frame);
        input.extend_from_slice(&second_control_frame);
        input.extend(masked_frame(true, OPCODE_CONTINUATION, br#""}"#));

        let output = run_client_to_server(input)
            .await
            .expect("relay should allow interleaved control frames");

        assert!(output.starts_with(&first_control_frame));
        assert_eq!(
            &output
                [first_control_frame.len()..first_control_frame.len() + second_control_frame.len()],
            second_control_frame.as_slice()
        );
        assert_eq!(
            decode_masked_text_frame(
                &output[first_control_frame.len() + second_control_frame.len()..]
            ),
            r#"{"token":"real-token"}"#
        );
    }

    #[tokio::test]
    async fn compressed_text_rewrites_with_permessage_deflate() {
        let (child_env, _) = resolver();
        let placeholder = child_env.get("DISCORD_BOT_TOKEN").unwrap();
        let payload = format!(r#"{{"token":"{placeholder}"}}"#);
        let compressed = compress_permessage_deflate(payload.as_bytes()).unwrap();
        let input = masked_frame_with_rsv(true, OPCODE_TEXT, 0x40, &compressed);

        let output = run_client_to_server_compressed(input)
            .await
            .expect("compressed text should relay");

        assert_eq!(
            decode_compressed_masked_text_frame(&output),
            r#"{"token":"real-token"}"#
        );
    }

    #[tokio::test]
    async fn compressed_text_rejects_decompressed_oversize_message() {
        let payload = vec![b'a'; MAX_TEXT_MESSAGE_BYTES + 1];
        let compressed = compress_permessage_deflate(&payload).unwrap();
        let input = masked_frame_with_rsv(true, OPCODE_TEXT, 0x40, &compressed);

        let err = run_client_to_server_compressed(input)
            .await
            .expect_err("oversize decompressed text should fail");

        assert!(err.to_string().contains("exceeds"));
    }

    #[tokio::test]
    async fn binary_frame_passes_through_unchanged() {
        let frame = masked_frame(true, OPCODE_BINARY, &[0, 1, 2, 3, 255]);

        let output = run_client_to_server(frame.clone())
            .await
            .expect("binary frame should pass through");

        assert_eq!(output, frame);
    }

    #[tokio::test]
    async fn credentialed_endpoint_denies_binary_frame_without_opt_in() {
        let frame = masked_frame(true, OPCODE_BINARY, &[0, 1, 2, 3, 255]);

        let (result, output) = run_client_to_server_guarded(frame).await;

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("binary frame denied")
        );
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn credentialed_endpoint_denies_text_placeholder_without_rewrite() {
        let frame = masked_frame(
            true,
            OPCODE_TEXT,
            br#"{"token":"openshell:resolve:env:API_TOKEN"}"#,
        );

        let (result, output) = run_client_to_server_guarded(frame).await;

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("rewrite is disabled")
        );
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn rejects_reserved_opcode() {
        let err = run_client_to_server(masked_frame(true, 0x3, b"reserved"))
            .await
            .expect_err("reserved opcode should fail");

        assert!(err.to_string().contains("reserved opcode"));
    }

    #[tokio::test]
    async fn rejects_continuation_without_active_message() {
        let err = run_client_to_server(masked_frame(true, OPCODE_CONTINUATION, b"orphan"))
            .await
            .expect_err("orphan continuation should fail");

        assert!(err.to_string().contains("continuation"));
    }

    #[tokio::test]
    async fn rejects_new_data_frame_before_fragment_completion() {
        let mut input = masked_frame(false, OPCODE_TEXT, b"partial");
        input.extend(masked_frame(true, OPCODE_TEXT, b"second"));

        let err = run_client_to_server(input)
            .await
            .expect_err("new data frame during fragmentation should fail");

        assert!(err.to_string().contains("previous fragmented message"));
    }

    #[tokio::test]
    async fn rejects_fragmented_control_frame() {
        let err = run_client_to_server(masked_frame(false, OPCODE_PING, b"ping"))
            .await
            .expect_err("fragmented control frame should fail");

        assert!(err.to_string().contains("control frame is fragmented"));
    }

    #[tokio::test]
    async fn rejects_control_frame_over_125_bytes() {
        let payload = vec![b'a'; 126];
        let err = run_client_to_server(masked_frame(true, OPCODE_PING, &payload))
            .await
            .expect_err("oversize control frame should fail");

        assert!(err.to_string().contains("control frame exceeds"));
    }

    #[tokio::test]
    async fn rejects_non_minimal_extended_length() {
        let err = run_client_to_server(masked_frame_with_non_minimal_16_bit_len(
            OPCODE_TEXT,
            b"hello",
        ))
        .await
        .expect_err("non-minimal length should fail");

        assert!(err.to_string().contains("non-minimal"));
    }

    #[tokio::test]
    async fn rejects_oversize_binary_frame_before_payload_buffering() {
        let err = run_client_to_server(masked_frame_with_declared_len(
            OPCODE_BINARY,
            MAX_RAW_FRAME_PAYLOAD_BYTES + 1,
        ))
        .await
        .expect_err("oversize binary frame should fail");

        assert!(err.to_string().contains("binary frame exceeds"));
    }

    #[tokio::test]
    async fn validates_close_frame_payloads() {
        let frame = masked_frame(true, OPCODE_CLOSE, &close_payload(1000, b"done"));

        let output = run_client_to_server(frame.clone())
            .await
            .expect("valid close frame should pass through");

        assert_eq!(output, frame);
    }

    #[tokio::test]
    async fn rejects_close_frame_with_one_byte_payload() {
        let err = run_client_to_server(masked_frame(true, OPCODE_CLOSE, &[0x03]))
            .await
            .expect_err("one-byte close frame should fail");

        assert!(err.to_string().contains("exactly one byte"));
    }

    #[tokio::test]
    async fn rejects_reserved_close_code() {
        let err = run_client_to_server(masked_frame(true, OPCODE_CLOSE, &close_payload(1005, b"")))
            .await
            .expect_err("reserved close code should fail");

        assert!(err.to_string().contains("invalid close code"));
    }

    #[tokio::test]
    async fn rejects_close_reason_with_invalid_utf8() {
        let err = run_client_to_server(masked_frame(
            true,
            OPCODE_CLOSE,
            &close_payload(1000, &[0xff]),
        ))
        .await
        .expect_err("invalid close reason should fail");

        assert!(err.to_string().contains("valid UTF-8"));
    }

    #[tokio::test]
    async fn rejects_frames_after_client_close_frame() {
        let mut input = masked_frame(true, OPCODE_CLOSE, &close_payload(1000, b"done"));
        input.extend(masked_frame(true, OPCODE_TEXT, b"late"));

        let err = run_client_to_server(input)
            .await
            .expect_err("frames after close should fail");

        assert!(err.to_string().contains("after close"));
    }

    #[test]
    fn websocket_ocsf_messages_do_not_include_payload_or_secret_material() {
        let placeholder = "openshell:resolve:env:DISCORD_BOT_TOKEN";
        let secret = "real-token";
        let payload = format!(r#"{{"op":2,"d":{{"token":"{placeholder}"}}}}"#);

        let rewrite = rewrite_event_message("gateway.example.test", 443, 1);
        let failure = protocol_failure_message("gateway.example.test", 443);
        let messages = [rewrite, failure];

        for message in messages {
            assert!(!message.contains(placeholder));
            assert!(!message.contains(secret));
            assert!(!message.contains(&payload));
            assert!(!message.contains("secret_len"));
            assert!(!message.contains("payload_len"));
        }
    }
}
