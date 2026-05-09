// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal WebSocket relay for opt-in credential placeholder rewriting.
//!
//! The relay parses only client-to-server frames. Server-to-client bytes stay
//! raw passthrough so this remains a narrow post-upgrade credential boundary,
//! not a general WebSocket inspection engine.

use crate::secrets::SecretResolver;
use miette::{IntoDiagnostic, Result, miette};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, NetworkActivityBuilder, SeverityId, StatusId,
    ocsf_emit,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_TEXT_MESSAGE_BYTES: usize = 1024 * 1024;
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
    Text { payload: Vec<u8> },
    Binary,
}

/// Relay an upgraded WebSocket connection, rewriting credential placeholders
/// in client-to-server UTF-8 text messages.
pub(super) async fn relay_with_credential_rewrite<C, U>(
    client: &mut C,
    upstream: &mut U,
    overflow: Vec<u8>,
    host: &str,
    port: u16,
    policy_name: &str,
    resolver: &SecretResolver,
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
        policy_name,
        resolver,
    );
    let server_to_client = async {
        tokio::io::copy(&mut upstream_read, &mut client_write)
            .await
            .into_diagnostic()?;
        client_write.flush().await.into_diagnostic()?;
        Ok::<(), miette::Report>(())
    };

    tokio::select! {
        result = client_to_server => result,
        result = server_to_client => result,
    }
}

async fn relay_client_to_server<R, W>(
    reader: &mut R,
    writer: &mut W,
    host: &str,
    port: u16,
    policy_name: &str,
    resolver: &SecretResolver,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut fragments = FragmentState::None;

    loop {
        let Some(frame) = read_frame_header(reader).await.inspect_err(|e| {
            emit_protocol_failure(host, port, policy_name, &e.to_string());
        })?
        else {
            writer.shutdown().await.into_diagnostic()?;
            return Ok(());
        };

        if let Err(e) = validate_frame_header(&frame, &fragments) {
            emit_protocol_failure(host, port, policy_name, &e.to_string());
            return Err(e);
        }

        match frame.opcode {
            OPCODE_TEXT => {
                let payload = read_masked_payload(reader, &frame).await.inspect_err(|e| {
                    emit_protocol_failure(host, port, policy_name, &e.to_string());
                })?;
                if frame.fin {
                    relay_text_payload(
                        writer,
                        &frame,
                        payload,
                        false,
                        host,
                        port,
                        policy_name,
                        resolver,
                    )
                    .await
                    .inspect_err(|e| {
                        emit_protocol_failure(host, port, policy_name, &e.to_string());
                    })?;
                } else {
                    fragments = FragmentState::Text { payload };
                }
            }
            OPCODE_CONTINUATION => match &mut fragments {
                FragmentState::Text { payload } => {
                    let next = read_masked_payload(reader, &frame).await.inspect_err(|e| {
                        emit_protocol_failure(host, port, policy_name, &e.to_string());
                    })?;
                    if let Err(e) = append_text_fragment(payload, next) {
                        emit_protocol_failure(host, port, policy_name, &e.to_string());
                        return Err(e);
                    }
                    if frame.fin {
                        let complete = std::mem::take(payload);
                        fragments = FragmentState::None;
                        relay_text_payload(
                            writer,
                            &frame,
                            complete,
                            true,
                            host,
                            port,
                            policy_name,
                            resolver,
                        )
                        .await
                        .inspect_err(|e| {
                            emit_protocol_failure(host, port, policy_name, &e.to_string());
                        })?;
                    }
                }
                FragmentState::Binary => {
                    copy_raw_frame_payload(reader, writer, &frame).await?;
                    if frame.fin {
                        fragments = FragmentState::None;
                    }
                }
                FragmentState::None => {
                    let e =
                        miette!("websocket continuation frame without active fragmented message");
                    emit_protocol_failure(host, port, policy_name, &e.to_string());
                    return Err(e);
                }
            },
            OPCODE_BINARY => {
                if !frame.fin {
                    fragments = FragmentState::Binary;
                }
                copy_raw_frame_payload(reader, writer, &frame).await?;
            }
            OPCODE_CLOSE | OPCODE_PING | OPCODE_PONG => {
                copy_raw_frame_payload(reader, writer, &frame).await?;
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
            u64::from(u16::from_be_bytes(bytes))
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
            u64::from_be_bytes(bytes)
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

fn validate_frame_header(frame: &FrameHeader, fragments: &FragmentState) -> Result<()> {
    if frame.rsv != 0 {
        return Err(miette!(
            "websocket frame has RSV bits set; compression/extensions are not supported"
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
    Ok(())
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
    host: &str,
    port: u16,
    policy_name: &str,
    resolver: &SecretResolver,
) -> Result<()> {
    let mut text = String::from_utf8(payload)
        .map_err(|_| miette!("websocket text message is not valid UTF-8"))?;
    let replacements = resolver
        .rewrite_websocket_text_placeholders(&mut text)
        .map_err(|e| miette!("{e}"))?;

    if replacements == 0 && !force_reframe {
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
        emit_rewrite_event(host, port, policy_name, replacements);
    }
    write_masked_frame(writer, OPCODE_TEXT, text.as_bytes()).await
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
    let mut header = Vec::with_capacity(14);
    header.push(0x80 | opcode);
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
        .message(format!(
            "WEBSOCKET_CREDENTIAL_REWRITE rewrote client text message [host:{host} port:{port} replacements:{replacements}]"
        ))
        .build();
    ocsf_emit!(event);
}

fn emit_protocol_failure(host: &str, port: u16, policy_name: &str, detail: &str) {
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
        .message(format!(
            "WEBSOCKET_CREDENTIAL_REWRITE closed ambiguous client frame [host:{host} port:{port}]"
        ))
        .status_detail(detail)
        .build();
    ocsf_emit!(event);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretResolver;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn resolver() -> (std::collections::HashMap<String, String>, SecretResolver) {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            std::iter::once(("DISCORD_BOT_TOKEN".to_string(), "real-token".to_string())).collect(),
        );
        (child_env, resolver.expect("resolver"))
    }

    fn masked_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mask_key = [0x37, 0xfa, 0x21, 0x3d];
        let mut frame = Vec::new();
        frame.push(if fin { 0x80 | opcode } else { opcode });
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

    async fn run_client_to_server(input: Vec<u8>) -> Result<Vec<u8>> {
        let (_, resolver) = resolver();
        let (mut client_write, mut relay_read) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES + 1024);
        let (mut relay_write, mut upstream_read) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES + 1024);

        client_write.write_all(&input).await.unwrap();
        drop(client_write);

        let result = relay_client_to_server(
            &mut relay_read,
            &mut relay_write,
            "gateway.example.test",
            443,
            "test-policy",
            &resolver,
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
        String::from_utf8(payload).unwrap()
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
            relay_with_credential_rewrite(
                &mut relay_client,
                &mut relay_upstream,
                Vec::new(),
                "gateway.example.test",
                443,
                "test-policy",
                &resolver,
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
                .contains("unresolved credential placeholder")
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
}
