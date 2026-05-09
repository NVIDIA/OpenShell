// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! WebSocket relay for opt-in credential placeholder rewriting and message policy.
//!
//! The relay parses only client-to-server frames. Server-to-client bytes stay
//! raw passthrough so inspection and rewriting cannot expose response payloads.

use crate::l7::relay::{L7EvalContext, evaluate_l7_request};
use crate::l7::{EnforcementMode, L7RequestInfo};
use crate::opa::TunnelPolicyEngine;
use crate::secrets::SecretResolver;
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use miette::{IntoDiagnostic, Result, miette};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, NetworkActivityBuilder, SeverityId, StatusId,
    ocsf_emit,
};
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_TEXT_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_RAW_FRAME_PAYLOAD_BYTES: u64 = 16 * 1024 * 1024;
const COPY_BUF_SIZE: usize = 8192;
const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

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
    Text { payload: Vec<u8>, compressed: bool },
    Binary,
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
    pub(super) resolver: Option<&'a SecretResolver>,
    pub(super) inspector: Option<InspectionOptions<'a>>,
    pub(super) compression: WebSocketCompression,
}

/// Relay an upgraded WebSocket connection with optional client text inspection,
/// credential rewriting, and strict permessage-deflate handling.
pub(super) async fn relay_with_options<C, U>(
    client: &mut C,
    upstream: &mut U,
    overflow: Vec<u8>,
    host: &str,
    port: u16,
    options: RelayOptions<'_>,
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

    let client_to_server =
        relay_client_to_server(&mut client_read, &mut upstream_write, host, port, &options);
    let server_to_client = async {
        tokio::io::copy(&mut upstream_read, &mut client_write)
            .await
            .into_diagnostic()?;
        client_write.flush().await.into_diagnostic()?;
        Ok::<(), miette::Report>(())
    };

    let result = tokio::select! {
        result = client_to_server => result,
        result = server_to_client => result,
    };
    let _ = upstream_write.shutdown().await;
    let _ = client_write.shutdown().await;
    result
}

async fn relay_client_to_server<R, W>(
    reader: &mut R,
    writer: &mut W,
    host: &str,
    port: u16,
    options: &RelayOptions<'_>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut fragments = FragmentState::None;
    let mut close_seen = false;

    loop {
        let Some(frame) = read_frame_header(reader).await.inspect_err(|e| {
            emit_protocol_failure(host, port, options.policy_name, protocol_failure_class(e));
        })?
        else {
            writer.shutdown().await.into_diagnostic()?;
            return Ok(());
        };

        if close_seen {
            let e = miette!("websocket frame received after close frame");
            emit_protocol_failure(host, port, options.policy_name, protocol_failure_class(&e));
            return Err(e);
        }

        if let Err(e) = validate_frame_header(&frame, &fragments, options.compression) {
            emit_protocol_failure(host, port, options.policy_name, protocol_failure_class(&e));
            return Err(e);
        }

        match frame.opcode {
            OPCODE_TEXT => {
                let payload = read_masked_payload(reader, &frame).await.inspect_err(|e| {
                    emit_protocol_failure(
                        host,
                        port,
                        options.policy_name,
                        protocol_failure_class(e),
                    );
                })?;
                let compressed = frame.rsv == 0x40;
                if frame.fin {
                    relay_text_payload(
                        writer, &frame, payload, false, compressed, host, port, options,
                    )
                    .await
                    .inspect_err(|e| {
                        emit_protocol_failure(
                            host,
                            port,
                            options.policy_name,
                            protocol_failure_class(e),
                        );
                    })?;
                } else {
                    fragments = FragmentState::Text {
                        payload,
                        compressed,
                    };
                }
            }
            OPCODE_CONTINUATION => match &mut fragments {
                FragmentState::Text {
                    payload,
                    compressed,
                } => {
                    let next = read_masked_payload(reader, &frame).await.inspect_err(|e| {
                        emit_protocol_failure(
                            host,
                            port,
                            options.policy_name,
                            protocol_failure_class(e),
                        );
                    })?;
                    if let Err(e) = append_text_fragment(payload, next) {
                        emit_protocol_failure(
                            host,
                            port,
                            options.policy_name,
                            protocol_failure_class(&e),
                        );
                        return Err(e);
                    }
                    if frame.fin {
                        let complete = std::mem::take(payload);
                        let was_compressed = *compressed;
                        fragments = FragmentState::None;
                        relay_text_payload(
                            writer,
                            &frame,
                            complete,
                            true,
                            was_compressed,
                            host,
                            port,
                            options,
                        )
                        .await
                        .inspect_err(|e| {
                            emit_protocol_failure(
                                host,
                                port,
                                options.policy_name,
                                protocol_failure_class(e),
                            );
                        })?;
                    }
                }
                FragmentState::Binary => {
                    copy_raw_frame_payload(reader, writer, &frame)
                        .await
                        .inspect_err(|e| {
                            emit_protocol_failure(
                                host,
                                port,
                                options.policy_name,
                                protocol_failure_class(e),
                            );
                        })?;
                    if frame.fin {
                        fragments = FragmentState::None;
                    }
                }
                FragmentState::None => {
                    let e =
                        miette!("websocket continuation frame without active fragmented message");
                    emit_protocol_failure(
                        host,
                        port,
                        options.policy_name,
                        protocol_failure_class(&e),
                    );
                    return Err(e);
                }
            },
            OPCODE_BINARY => {
                if !frame.fin {
                    fragments = FragmentState::Binary;
                }
                copy_raw_frame_payload(reader, writer, &frame)
                    .await
                    .inspect_err(|e| {
                        emit_protocol_failure(
                            host,
                            port,
                            options.policy_name,
                            protocol_failure_class(e),
                        );
                    })?;
            }
            OPCODE_CLOSE | OPCODE_PING | OPCODE_PONG => {
                relay_control_frame(reader, writer, &frame)
                    .await
                    .inspect_err(|e| {
                        emit_protocol_failure(
                            host,
                            port,
                            options.policy_name,
                            protocol_failure_class(e),
                        );
                    })?;
                if frame.opcode == OPCODE_CLOSE {
                    close_seen = true;
                }
            }
            _ => unreachable!("validated opcode"),
        }
    }
}

async fn read_frame_header<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<FrameHeader>> {
    let first = match reader.read_u8().await {
        Ok(byte) => byte,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(miette!("{e}")),
    };
    let second = reader
        .read_u8()
        .await
        .map_err(|e| miette!("malformed websocket frame header: {e}"))?;

    let mut raw_header = vec![first, second];
    let len_code = second & 0x7F;
    let payload_len = match len_code {
        0..=125 => u64::from(len_code),
        126 => {
            let mut bytes = [0u8; 2];
            reader
                .read_exact(&mut bytes)
                .await
                .map_err(|e| miette!("malformed websocket extended length: {e}"))?;
            raw_header.extend_from_slice(&bytes);
            let len = u64::from(u16::from_be_bytes(bytes));
            if len < 126 {
                return Err(miette!(
                    "websocket frame uses non-minimal 16-bit extended length"
                ));
            }
            len
        }
        127 => {
            let mut bytes = [0u8; 8];
            reader
                .read_exact(&mut bytes)
                .await
                .map_err(|e| miette!("malformed websocket extended length: {e}"))?;
            if bytes[0] & 0x80 != 0 {
                return Err(miette!("websocket frame uses non-canonical 64-bit length"));
            }
            raw_header.extend_from_slice(&bytes);
            let len = u64::from_be_bytes(bytes);
            if u16::try_from(len).is_ok() {
                return Err(miette!(
                    "websocket frame uses non-minimal 64-bit extended length"
                ));
            }
            len
        }
        _ => unreachable!("7-bit length code"),
    };

    let masked = second & 0x80 != 0;
    let mask_key = if masked {
        let mut key = [0u8; 4];
        reader
            .read_exact(&mut key)
            .await
            .map_err(|e| miette!("malformed websocket mask key: {e}"))?;
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
) -> Result<()> {
    if !valid_rsv_bits(frame, fragments, compression) {
        return Err(miette!(
            "websocket frame has unsupported RSV bits or extension state"
        ));
    }
    if !frame.masked {
        return Err(miette!("websocket client frame is not masked"));
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
        return Err(miette!("websocket frame uses reserved opcode"));
    }
    if matches!(frame.opcode, OPCODE_CLOSE | OPCODE_PING | OPCODE_PONG) {
        if !frame.fin {
            return Err(miette!("websocket control frame is fragmented"));
        }
        if frame.payload_len > 125 {
            return Err(miette!("websocket control frame exceeds 125 bytes"));
        }
    }
    if matches!(frame.opcode, OPCODE_TEXT | OPCODE_BINARY)
        && !matches!(fragments, FragmentState::None)
    {
        return Err(miette!(
            "websocket data frame started before previous fragmented message completed"
        ));
    }
    if matches!(frame.opcode, OPCODE_CONTINUATION) && matches!(fragments, FragmentState::None) {
        return Err(miette!(
            "websocket continuation frame without active fragmented message"
        ));
    }
    if (frame.opcode == OPCODE_BINARY
        || (frame.opcode == OPCODE_CONTINUATION && matches!(fragments, FragmentState::Binary)))
        && frame.payload_len > MAX_RAW_FRAME_PAYLOAD_BYTES
    {
        return Err(miette!(
            "websocket binary frame exceeds {MAX_RAW_FRAME_PAYLOAD_BYTES} byte relay limit"
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
) -> Result<Vec<u8>> {
    let payload_len = usize::try_from(frame.payload_len)
        .map_err(|_| miette!("websocket text frame is too large to buffer"))?;
    if payload_len > MAX_TEXT_MESSAGE_BYTES {
        return Err(miette!(
            "websocket text message exceeds {MAX_TEXT_MESSAGE_BYTES} byte limit"
        ));
    }
    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| miette!("malformed websocket payload: {e}"))?;
    let mask_key = frame
        .mask_key
        .ok_or_else(|| miette!("websocket client frame is not masked"))?;
    apply_mask(&mut payload, mask_key);
    Ok(payload)
}

fn append_text_fragment(buffer: &mut Vec<u8>, next: Vec<u8>) -> Result<()> {
    let new_len = buffer
        .len()
        .checked_add(next.len())
        .ok_or_else(|| miette!("websocket text message length overflow"))?;
    if new_len > MAX_TEXT_MESSAGE_BYTES {
        return Err(miette!(
            "websocket text message exceeds {MAX_TEXT_MESSAGE_BYTES} byte limit"
        ));
    }
    buffer.extend_from_slice(&next);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn relay_text_payload<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &FrameHeader,
    payload: Vec<u8>,
    force_reframe: bool,
    compressed: bool,
    host: &str,
    port: u16,
    options: &RelayOptions<'_>,
) -> Result<()> {
    let message_payload = if compressed {
        decompress_permessage_deflate(&payload)?
    } else {
        payload
    };
    let mut text = String::from_utf8(message_payload)
        .map_err(|_| miette!("websocket text message is not valid UTF-8"))?;
    let replacements = if let Some(resolver) = options.resolver {
        resolver
            .rewrite_websocket_text_placeholders(&mut text)
            .map_err(|_| miette!("websocket credential placeholder resolution failed"))?
    } else {
        0
    };

    if let Some(inspector) = options.inspector.as_ref() {
        inspect_websocket_text_message(host, port, options.policy_name, inspector, &text)?;
    }

    if replacements == 0 && !force_reframe && !compressed {
        writer
            .write_all(&frame.raw_header)
            .await
            .into_diagnostic()?;
        let mut payload = text.into_bytes();
        let mask_key = frame
            .mask_key
            .ok_or_else(|| miette!("websocket client frame is not masked"))?;
        apply_mask(&mut payload, mask_key);
        writer.write_all(&payload).await.into_diagnostic()?;
        writer.flush().await.into_diagnostic()?;
        return Ok(());
    }

    if replacements > 0 {
        emit_rewrite_event(host, port, options.policy_name, replacements);
    }
    if compressed {
        let compressed_payload = compress_permessage_deflate(text.as_bytes())?;
        return write_masked_frame_with_rsv(writer, OPCODE_TEXT, 0x40, &compressed_payload).await;
    }
    write_masked_frame(writer, OPCODE_TEXT, text.as_bytes()).await
}

fn inspect_websocket_text_message(
    host: &str,
    port: u16,
    policy_name: &str,
    inspector: &InspectionOptions<'_>,
    text: &str,
) -> Result<()> {
    if inspector.graphql_policy {
        return inspect_graphql_websocket_message(host, port, policy_name, inspector, text);
    }

    let request_info = L7RequestInfo {
        action: "WEBSOCKET_TEXT".to_string(),
        target: inspector.target.clone(),
        query_params: inspector.query_params.clone(),
        graphql: None,
    };
    let (allowed, reason) = evaluate_l7_request(inspector.engine, inspector.ctx, &request_info)?;
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
        return Err(miette!("websocket text message denied by policy"));
    }
    Ok(())
}

fn inspect_graphql_websocket_message(
    host: &str,
    port: u16,
    policy_name: &str,
    inspector: &InspectionOptions<'_>,
    text: &str,
) -> Result<()> {
    match classify_graphql_websocket_message(text) {
        GraphqlWebSocketMessage::Control { message_type } => {
            let request_info = L7RequestInfo {
                action: "WEBSOCKET_CONTROL".to_string(),
                target: inspector.target.clone(),
                query_params: inspector.query_params.clone(),
                graphql: None,
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
            };
            let parse_error_reason = graphql
                .error
                .as_deref()
                .map(|error| format!("GraphQL WebSocket message rejected: {error}"));
            let force_deny = parse_error_reason.is_some();
            let (allowed, reason) = if let Some(reason) = parse_error_reason {
                (false, reason)
            } else {
                evaluate_l7_request(inspector.engine, inspector.ctx, &request_info)?
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
                return Err(miette!("websocket GraphQL message denied by policy"));
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
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let raw_payload_len = usize::try_from(frame.payload_len)
        .map_err(|_| miette!("websocket control frame payload length overflow"))?;
    let mut raw_payload = vec![0u8; raw_payload_len];
    reader
        .read_exact(&mut raw_payload)
        .await
        .map_err(|e| miette!("malformed websocket control payload: {e}"))?;

    if frame.opcode == OPCODE_CLOSE {
        let mut payload = raw_payload.clone();
        let mask_key = frame
            .mask_key
            .ok_or_else(|| miette!("websocket client frame is not masked"))?;
        apply_mask(&mut payload, mask_key);
        validate_close_payload(&payload)?;
    }

    writer
        .write_all(&frame.raw_header)
        .await
        .into_diagnostic()?;
    writer.write_all(&raw_payload).await.into_diagnostic()?;
    writer.flush().await.into_diagnostic()?;
    Ok(())
}

fn validate_close_payload(payload: &[u8]) -> Result<()> {
    if payload.len() == 1 {
        return Err(miette!(
            "websocket close frame payload cannot be exactly one byte"
        ));
    }
    if payload.len() < 2 {
        return Ok(());
    }

    let code = u16::from_be_bytes([payload[0], payload[1]]);
    if !valid_close_code(code) {
        return Err(miette!("websocket close frame uses invalid close code"));
    }
    if std::str::from_utf8(&payload[2..]).is_err() {
        return Err(miette!("websocket close frame reason is not valid UTF-8"));
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
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&frame.raw_header)
        .await
        .into_diagnostic()?;
    let mut remaining = frame.payload_len;
    let mut buf = [0u8; COPY_BUF_SIZE];
    while remaining > 0 {
        let to_read = usize::try_from(remaining)
            .unwrap_or(buf.len())
            .min(buf.len());
        let n = reader.read(&mut buf[..to_read]).await.into_diagnostic()?;
        if n == 0 {
            return Err(miette!("websocket payload ended before declared length"));
        }
        writer.write_all(&buf[..n]).await.into_diagnostic()?;
        remaining -= n as u64;
    }
    writer.flush().await.into_diagnostic()?;
    Ok(())
}

async fn write_masked_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    opcode: u8,
    payload: &[u8],
) -> Result<()> {
    write_masked_frame_with_rsv(writer, opcode, 0, payload).await
}

async fn write_masked_frame_with_rsv<W: AsyncWrite + Unpin>(
    writer: &mut W,
    opcode: u8,
    rsv: u8,
    payload: &[u8],
) -> Result<()> {
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
    writer.write_all(&header).await.into_diagnostic()?;
    writer.write_all(&masked).await.into_diagnostic()?;
    writer.flush().await.into_diagnostic()?;
    Ok(())
}

fn decompress_permessage_deflate(payload: &[u8]) -> Result<Vec<u8>> {
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
            .map_err(|e| miette!("websocket permessage-deflate decompression failed: {e}"))?;
        let read = usize::try_from(decoder.total_in() - before_in)
            .map_err(|_| miette!("websocket permessage-deflate input length overflow"))?;
        let written = usize::try_from(decoder.total_out() - before_out)
            .map_err(|_| miette!("websocket permessage-deflate output length overflow"))?;
        input_pos = input_pos
            .checked_add(read)
            .ok_or_else(|| miette!("websocket permessage-deflate input length overflow"))?;
        if out.len().saturating_add(written) > MAX_TEXT_MESSAGE_BYTES {
            return Err(miette!(
                "websocket text message exceeds {MAX_TEXT_MESSAGE_BYTES} byte limit"
            ));
        }
        out.extend_from_slice(&scratch[..written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if input_pos >= input.len() && written < scratch.len() {
            break;
        }
        if read == 0 && written == 0 {
            return Err(miette!(
                "websocket permessage-deflate decompression did not make progress"
            ));
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
    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
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
    let summary = graphql.map(graphql_log_summary).unwrap_or_default();
    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
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

fn graphql_log_summary(info: &crate::l7::graphql::GraphqlRequestInfo) -> String {
    if let Some(error) = info.error.as_deref() {
        return format!(" graphql_error={error:?}");
    }
    let ops: Vec<String> = info
        .operations
        .iter()
        .map(|op| {
            let name = op.operation_name.as_deref().unwrap_or("-");
            let fields = if op.fields.is_empty() {
                "-".to_string()
            } else {
                op.fields.join(",")
            };
            let persisted = op
                .persisted_query_hash
                .as_deref()
                .or(op.persisted_query_id.as_deref())
                .unwrap_or("-");
            format!(
                "type={} name={} fields={} persisted={}",
                op.operation_type, name, fields, persisted
            )
        })
        .collect();
    format!(" graphql_ops={}", ops.join(";"))
}

fn protocol_failure_class(error: &miette::Report) -> &'static str {
    let msg = error.to_string().to_ascii_lowercase();
    if msg.contains("credential") {
        "credential_resolution_failed"
    } else if msg.contains("utf-8") {
        "invalid_utf8"
    } else if msg.contains("close frame") || msg.contains("after close") {
        "invalid_close_frame"
    } else if msg.contains("control frame") {
        "invalid_control_frame"
    } else if msg.contains("length")
        || msg.contains("too large")
        || msg.contains("exceeds")
        || msg.contains("overflow")
    {
        "invalid_length"
    } else if msg.contains("continuation") || msg.contains("fragmented") {
        "invalid_fragmentation"
    } else if msg.contains("reserved opcode") {
        "reserved_opcode"
    } else if msg.contains("not masked") {
        "unmasked_client_frame"
    } else if msg.contains("rsv") {
        "rsv_bits"
    } else if msg.contains("malformed") {
        "malformed_frame"
    } else {
        "protocol_error"
    }
}

fn emit_protocol_failure(host: &str, port: u16, policy_name: &str, failure_class: &str) {
    let policy_name = if policy_name.is_empty() {
        "-"
    } else {
        policy_name
    };
    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Medium)
        .status(StatusId::Failure)
        .dst_endpoint(Endpoint::from_domain(host, port))
        .firewall_rule(policy_name, "l7-websocket")
        .message(protocol_failure_message(host, port))
        .status_detail(failure_class)
        .build();
    ocsf_emit!(event);
}

fn protocol_failure_message(host: &str, port: u16) -> String {
    format!("WEBSOCKET_CREDENTIAL_REWRITE closed ambiguous client frame [host:{host} port:{port}]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7::relay::L7EvalContext;
    use crate::opa::{NetworkInput, OpaEngine};
    use crate::secrets::SecretResolver;
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

        let options = RelayOptions {
            policy_name: "test-policy",
            resolver: Some(&resolver),
            inspector: None,
            compression: WebSocketCompression::None,
        };
        let result = relay_client_to_server(
            &mut relay_read,
            &mut relay_write,
            "gateway.example.test",
            443,
            &options,
        )
        .await;
        drop(relay_write);

        let mut output = Vec::new();
        upstream_read.read_to_end(&mut output).await.unwrap();
        result.map(|()| output)
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
        };
        let (mut client_write, mut relay_read) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES + 1024);
        let (mut relay_write, mut upstream_read) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES + 1024);

        client_write.write_all(&input).await.unwrap();
        drop(client_write);

        let options = RelayOptions {
            policy_name: "graphql_ws",
            resolver,
            inspector: Some(InspectionOptions {
                engine: &tunnel_engine,
                ctx: &ctx,
                enforcement: EnforcementMode::Enforce,
                target: "/graphql".to_string(),
                query_params: HashMap::new(),
                graphql_policy: true,
            }),
            compression: WebSocketCompression::None,
        };
        let result = relay_client_to_server(
            &mut relay_read,
            &mut relay_write,
            "realtime.graphql.test",
            443,
            &options,
        )
        .await;
        drop(relay_write);

        let mut output = Vec::new();
        upstream_read.read_to_end(&mut output).await.unwrap();
        result.map(|()| output)
    }

    async fn run_client_to_server_compressed(input: Vec<u8>) -> Result<Vec<u8>> {
        let (_, resolver) = resolver();
        let (mut client_write, mut relay_read) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES + 1024);
        let (mut relay_write, mut upstream_read) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES + 1024);

        client_write.write_all(&input).await.unwrap();
        drop(client_write);

        let options = RelayOptions {
            policy_name: "test-policy",
            resolver: Some(&resolver),
            inspector: None,
            compression: WebSocketCompression::PermessageDeflate,
        };
        let result = relay_client_to_server(
            &mut relay_read,
            &mut relay_write,
            "gateway.example.test",
            443,
            &options,
        )
        .await;
        drop(relay_write);

        let mut output = Vec::new();
        upstream_read.read_to_end(&mut output).await.unwrap();
        result.map(|()| output)
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
        let summary = graphql_log_summary(&graphql);

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
                    resolver: Some(&resolver),
                    inspector: None,
                    compression: WebSocketCompression::None,
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
