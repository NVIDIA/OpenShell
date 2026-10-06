// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared HTTP/1.1 request helpers for L7 protocols carried over HTTP.

use crate::l7::provider::{BodyLength, L7Request};
use miette::{IntoDiagnostic, Result, miette};
use tokio::io::{AsyncRead, AsyncReadExt};

const READ_BUF_SIZE: usize = 8192;

pub async fn read_body_for_inspection<C: AsyncRead + Unpin>(
    client: &mut C,
    request: &mut L7Request,
    max_body_bytes: usize,
) -> Result<Vec<u8>> {
    let header_end = request
        .raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(request.raw_header.len(), |p| p + 4);
    let overflow = request.raw_header[header_end..].to_vec();

    match request.body_length {
        BodyLength::None => Ok(Vec::new()),
        BodyLength::ContentLength(len) => {
            let len = usize::try_from(len)
                .map_err(|_| miette!("HTTP request body length exceeds platform limit"))?;
            if len > max_body_bytes {
                return Err(miette!(
                    "HTTP request body exceeds {max_body_bytes} byte inspection limit"
                ));
            }
            if overflow.len() > len {
                return Err(miette!(
                    "HTTP request contains more body bytes than Content-Length"
                ));
            }
            let remaining = len - overflow.len();
            let mut body = overflow;
            if remaining > 0 {
                let start = body.len();
                body.resize(len, 0);
                client
                    .read_exact(&mut body[start..])
                    .await
                    .into_diagnostic()?;
            }
            request.raw_header.truncate(header_end);
            request.raw_header.extend_from_slice(&body);
            Ok(body)
        }
        BodyLength::Chunked => {
            let body = read_chunked_body_for_inspection(
                client,
                request,
                header_end,
                overflow,
                max_body_bytes,
            )
            .await?;
            normalize_chunked_request_to_content_length(request, header_end, &body)?;
            Ok(body)
        }
    }
}

fn normalize_chunked_request_to_content_length(
    request: &mut L7Request,
    header_end: usize,
    body: &[u8],
) -> Result<()> {
    let header_str = std::str::from_utf8(&request.raw_header[..header_end])
        .map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let header_str = header_str
        .strip_suffix("\r\n\r\n")
        .ok_or_else(|| miette!("HTTP headers missing terminator"))?;

    let mut normalized = Vec::with_capacity(header_str.len() + body.len() + 32);
    for (idx, line) in header_str.split("\r\n").enumerate() {
        if idx > 0 {
            let name = line
                .split_once(':')
                .map(|(name, _)| name.trim().to_ascii_lowercase());
            if matches!(
                name.as_deref(),
                Some("transfer-encoding" | "content-length" | "trailer")
            ) {
                continue;
            }
        }
        normalized.extend_from_slice(line.as_bytes());
        normalized.extend_from_slice(b"\r\n");
    }
    normalized.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    normalized.extend_from_slice(body);

    request.raw_header = normalized;
    request.body_length = BodyLength::ContentLength(body.len() as u64);
    Ok(())
}

async fn read_chunked_body_for_inspection<C: AsyncRead + Unpin>(
    client: &mut C,
    request: &mut L7Request,
    header_end: usize,
    overflow: Vec<u8>,
    max_body_bytes: usize,
) -> Result<Vec<u8>> {
    let mut raw = overflow;
    let mut decoded = Vec::new();
    let mut pos = 0usize;

    loop {
        let size_line_end = read_chunked_line(client, &mut raw, pos, max_body_bytes).await?;
        let size_line = std::str::from_utf8(&raw[pos..size_line_end])
            .into_diagnostic()
            .map_err(|_| miette!("Invalid UTF-8 in HTTP chunk-size line"))?;
        let size_token = size_line
            .split(';')
            .next()
            .map(str::trim)
            .unwrap_or_default();
        let chunk_size = usize::from_str_radix(size_token, 16)
            .into_diagnostic()
            .map_err(|_| miette!("Invalid HTTP chunk size token: {size_token:?}"))?;
        pos = size_line_end + 2;

        if decoded.len().saturating_add(chunk_size) > max_body_bytes {
            return Err(miette!(
                "HTTP request body exceeds {max_body_bytes} byte inspection limit"
            ));
        }

        if chunk_size == 0 {
            loop {
                let trailer_end = read_chunked_line(client, &mut raw, pos, max_body_bytes).await?;
                let trailer_line = &raw[pos..trailer_end];
                pos = trailer_end + 2;
                if trailer_line.is_empty() {
                    request.raw_header.truncate(header_end);
                    request.raw_header.extend_from_slice(&raw[..pos]);
                    return Ok(decoded);
                }
            }
        }

        let chunk_end = pos
            .checked_add(chunk_size)
            .ok_or_else(|| miette!("HTTP chunk size overflow"))?;
        let chunk_with_crlf_end = chunk_end
            .checked_add(2)
            .ok_or_else(|| miette!("HTTP chunk size overflow"))?;
        while raw.len() < chunk_with_crlf_end {
            let remaining = chunk_with_crlf_end - raw.len();
            read_more(client, &mut raw, max_body_bytes, remaining).await?;
        }
        decoded.extend_from_slice(&raw[pos..chunk_end]);
        if raw.get(chunk_end..chunk_with_crlf_end) != Some(&b"\r\n"[..]) {
            return Err(miette!("HTTP chunk payload missing terminating CRLF"));
        }
        pos = chunk_with_crlf_end;
    }
}

async fn read_chunked_line<C: AsyncRead + Unpin>(
    client: &mut C,
    raw: &mut Vec<u8>,
    start: usize,
    max_body_bytes: usize,
) -> Result<usize> {
    let mut scan_start = start;
    loop {
        if let Some(end) = find_crlf(raw, scan_start) {
            return Ok(end);
        }
        // Retain a possible trailing CR without rescanning the entire line.
        scan_start = raw.len().saturating_sub(1).max(start);
        // Framing has no known length. Stop at CRLF so the connection's reader
        // retains any following request for its own inspection and policy check.
        read_more(client, raw, max_body_bytes, 1).await?;
    }
}

async fn read_more<C: AsyncRead + Unpin>(
    client: &mut C,
    raw: &mut Vec<u8>,
    max_body_bytes: usize,
    remaining: usize,
) -> Result<()> {
    if raw.len() > max_body_bytes.saturating_mul(2).max(max_body_bytes) {
        return Err(miette!(
            "HTTP chunked request body exceeds inspection framing limit"
        ));
    }
    let mut buf = [0u8; READ_BUF_SIZE];
    // Payload reads stop at the declared chunk boundary, including its CRLF.
    let to_read = remaining.min(buf.len());
    let n = client.read(&mut buf[..to_read]).await.into_diagnostic()?;
    if n == 0 {
        return Err(miette!("HTTP chunked body ended before terminator"));
    }
    raw.extend_from_slice(&buf[..n]);
    Ok(())
}

fn find_crlf(buf: &[u8], start: usize) -> Option<usize> {
    buf.get(start..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| start + p)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use tokio::io::{AsyncWriteExt, BufReader};

    fn chunked_request() -> L7Request {
        L7Request {
            action: "POST".into(),
            target: "/mcp".into(),
            query_params: HashMap::new(),
            raw_header:
                b"POST /mcp HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n"
                    .to_vec(),
            body_length: BodyLength::Chunked,
        }
    }

    #[tokio::test]
    async fn chunked_inspection_preserves_pipelined_request() {
        let next = b"DELETE /next HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut wire = b"5\r\nhello\r\n0\r\n\r\n".to_vec();
        wire.extend_from_slice(next);
        let (mut sender, receiver) = tokio::io::duplex(8192);
        sender.write_all(&wire).await.unwrap();
        sender.shutdown().await.unwrap();
        let mut reader = BufReader::with_capacity(8192, receiver);
        let mut request = chunked_request();

        let body = read_body_for_inspection(&mut reader, &mut request, 1024)
            .await
            .unwrap();
        assert_eq!(body, b"hello");
        let mut remaining = Vec::new();
        reader.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(remaining, next, "inspection consumed the next request");
    }

    #[tokio::test]
    async fn chunked_inspection_preserves_boundary_with_fragmentation_and_buffered_prefix() {
        let next = b"GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let encoded = b"2;ext=value\r\nhe\r\n3\r\nllo\r\n0\r\nX-Checksum: ignored\r\n\r\n";
        for capacity in [1, 2, 8192] {
            for prefix_len in 0..=encoded.len() {
                let mut request = chunked_request();
                request.raw_header.extend_from_slice(&encoded[..prefix_len]);
                let mut wire = encoded[prefix_len..].to_vec();
                wire.extend_from_slice(next);
                let mut reader = BufReader::with_capacity(capacity, wire.as_slice());
                let body = read_body_for_inspection(&mut reader, &mut request, 1024)
                    .await
                    .unwrap();
                assert_eq!(body, b"hello");
                assert!(matches!(request.body_length, BodyLength::ContentLength(5)));
                assert_eq!(
                    request.raw_header,
                    b"POST /mcp HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello"
                );
                let mut remaining = Vec::new();
                reader.read_to_end(&mut remaining).await.unwrap();
                assert_eq!(remaining, next, "capacity={capacity}, prefix={prefix_len}");
            }
        }
    }

    #[tokio::test]
    async fn chunked_inspection_preserves_request_after_empty_body() {
        let next = b"GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut wire = b"0\r\n\r\n".to_vec();
        wire.extend_from_slice(next);
        let mut reader = BufReader::new(wire.as_slice());
        let mut request = chunked_request();
        assert!(
            read_body_for_inspection(&mut reader, &mut request, 1024)
                .await
                .unwrap()
                .is_empty()
        );
        let mut remaining = Vec::new();
        reader.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(remaining, next);
    }

    #[tokio::test]
    async fn chunked_inspection_rejects_malformed_or_incomplete_framing() {
        for (encoded, expected) in [
            (b"z\r\n".as_slice(), "Invalid HTTP chunk size token"),
            (b"\xff\r\n", "Invalid UTF-8 in HTTP chunk-size line"),
            (b"1\r\nx!!", "HTTP chunk payload missing terminating CRLF"),
            (b"1\r", "HTTP chunked body ended before terminator"),
            (b"5\r\nhe", "HTTP chunked body ended before terminator"),
            (
                b"0\r\nX-Trailer: unfinished",
                "HTTP chunked body ended before terminator",
            ),
        ] {
            let mut reader = BufReader::with_capacity(2, encoded);
            let error = read_body_for_inspection(&mut reader, &mut chunked_request(), 1024)
                .await
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[tokio::test]
    async fn chunked_inspection_enforces_body_and_framing_limits() {
        let mut reader = b"11\r\n".as_slice();
        let error = read_body_for_inspection(&mut reader, &mut chunked_request(), 16)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("16 byte inspection limit"));

        for encoded in [
            format!("0;{}\r\n\r\n", "x".repeat(64)),
            format!("0\r\nX-Trailer: {}\r\n\r\n", "x".repeat(64)),
        ] {
            let mut reader = encoded.as_bytes();
            let error = read_body_for_inspection(&mut reader, &mut chunked_request(), 16)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("inspection framing limit"));
        }
    }
}
