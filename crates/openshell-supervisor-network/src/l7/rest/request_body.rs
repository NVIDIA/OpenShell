// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Request bodies routed through version 2 request middleware.
//!
//! The body reader normalizes one HTTP/1 request body into units for the
//! stage pipeline without reading past the body, so a pipelined request stays
//! in the connection. A withheld body is inlined into the rebuilt request, as
//! legacy middleware does. A live body streams to the upstream while the
//! client uploads; its head commits on the pipeline's final `Start`.

use std::sync::atomic::{AtomicBool, Ordering};

use futures::FutureExt as _;
use openshell_supervisor_middleware::{HttpBodyOutput, HttpPipelineFinish};

use super::*;

/// Incremental reader for one normalized HTTP/1 request body.
pub enum RequestBodyReader {
    None,
    Fixed {
        buffered: Vec<u8>,
        position: usize,
        remaining: u64,
    },
    Chunked(ChunkedRequestBodyReader),
}

/// Decoder for a chunked request body. It reads framing byte by byte and
/// payload by exact length, so it never consumes bytes past the body.
pub struct ChunkedRequestBodyReader {
    buffered: Vec<u8>,
    position: usize,
    state: ChunkedState,
    trailers: Vec<HttpHeader>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkedState {
    Size,
    Data { remaining: usize },
    DataEnd,
    Done,
}

/// Prepare the head and an incremental body reader for request middleware.
///
/// `Expect: 100-continue` is answered locally, because middleware must see
/// the body before `OpenShell` contacts the upstream.
pub async fn prepare_request_body_stream<C: AsyncRead + AsyncWrite + Unpin>(
    req: &L7Request,
    client: &mut C,
) -> Result<(Vec<u8>, RequestBodyReader)> {
    let header_end = request_header_end(&req.raw_header);
    let mut headers = req.raw_header[..header_end].to_vec();
    let already_read = req.raw_header[header_end..].to_vec();
    let reader = match req.body_length {
        BodyLength::None => {
            if !already_read.is_empty() {
                return Err(miette!(
                    "HTTP request with no body framing has {} unread byte(s) after headers",
                    already_read.len()
                ));
            }
            handle_buffered_expect_continue(client, &mut headers, false).await?;
            RequestBodyReader::None
        }
        BodyLength::ContentLength(length) => {
            if already_read.len() as u64 > length {
                return Err(miette!(
                    "HTTP request read-ahead exceeds its declared Content-Length"
                ));
            }
            let needs_client_read = (already_read.len() as u64) < length;
            handle_buffered_expect_continue(client, &mut headers, needs_client_read).await?;
            RequestBodyReader::Fixed {
                buffered: already_read,
                position: 0,
                remaining: length,
            }
        }
        BodyLength::Chunked => {
            let needs_client_read = !chunked_body_is_fully_buffered(&already_read);
            handle_buffered_expect_continue(client, &mut headers, needs_client_read).await?;
            RequestBodyReader::Chunked(ChunkedRequestBodyReader {
                buffered: already_read,
                position: 0,
                state: ChunkedState::Size,
                trailers: Vec::new(),
            })
        }
    };
    Ok((headers, reader))
}

fn request_header_end(raw_header: &[u8]) -> usize {
    raw_header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(raw_header.len(), |position| position + 4)
}

impl RequestBodyReader {
    /// Read the next body unit of at most `limit` bytes, or `None` at the end
    /// of the body. A unit coalesces bytes that are ready without waiting:
    /// the reader waits only while the unit is still empty.
    pub async fn next_unit<C: AsyncRead + Unpin>(
        &mut self,
        client: &mut C,
        generation_guard: Option<&PolicyGenerationGuard>,
        limit: usize,
    ) -> Result<Option<Vec<u8>>> {
        if limit == 0 {
            return Err(miette!("request middleware unit limit is zero"));
        }
        match self {
            Self::None => Ok(None),
            Self::Fixed {
                buffered,
                position,
                remaining,
            } => {
                let mut unit = Vec::new();
                while *remaining > 0 && unit.len() < limit {
                    let want = usize::try_from(*remaining)
                        .unwrap_or(usize::MAX)
                        .min(limit - unit.len());
                    let read = read_payload(
                        buffered,
                        position,
                        client,
                        generation_guard,
                        &mut unit,
                        want,
                    )
                    .await?;
                    if read == 0 {
                        break;
                    }
                    *remaining -= read as u64;
                }
                Ok((!unit.is_empty()).then_some(unit))
            }
            Self::Chunked(reader) => reader.next_unit(client, generation_guard, limit).await,
        }
    }

    /// Trailers of a chunked body, available once the body ended.
    pub fn take_trailers(&mut self) -> Vec<HttpHeader> {
        match self {
            Self::Chunked(reader) => std::mem::take(&mut reader.trailers),
            Self::None | Self::Fixed { .. } => Vec::new(),
        }
    }
}

impl ChunkedRequestBodyReader {
    async fn next_unit<C: AsyncRead + Unpin>(
        &mut self,
        client: &mut C,
        generation_guard: Option<&PolicyGenerationGuard>,
        limit: usize,
    ) -> Result<Option<Vec<u8>>> {
        let mut unit = Vec::new();
        loop {
            match self.state {
                ChunkedState::Done => return Ok((!unit.is_empty()).then_some(unit)),
                ChunkedState::Data { remaining } => {
                    if unit.len() == limit {
                        return Ok(Some(unit));
                    }
                    let want = remaining.min(limit - unit.len());
                    let read = read_payload(
                        &self.buffered,
                        &mut self.position,
                        client,
                        generation_guard,
                        &mut unit,
                        want,
                    )
                    .await?;
                    if read == 0 {
                        return Ok(Some(unit));
                    }
                    self.state = if read == remaining {
                        ChunkedState::DataEnd
                    } else {
                        ChunkedState::Data {
                            remaining: remaining - read,
                        }
                    };
                }
                ChunkedState::DataEnd => {
                    if !unit.is_empty() && !self.ready(client)? {
                        return Ok(Some(unit));
                    }
                    let terminator = [
                        self.read_byte(client, generation_guard).await?,
                        self.read_byte(client, generation_guard).await?,
                    ];
                    if terminator != *b"\r\n" {
                        return Err(miette!("chunk missing terminating CRLF"));
                    }
                    self.state = ChunkedState::Size;
                }
                ChunkedState::Size => {
                    if !unit.is_empty() && !self.ready(client)? {
                        return Ok(Some(unit));
                    }
                    let line = self.read_line(client, generation_guard).await?;
                    let line = std::str::from_utf8(&line)
                        .map_err(|_| miette!("invalid UTF-8 in chunk-size line"))?;
                    let token = line.split(';').next().map(str::trim).unwrap_or_default();
                    let size = usize::from_str_radix(token, 16)
                        .map_err(|_| miette!("invalid chunk size token: {token:?}"))?;
                    if size == 0 {
                        self.read_trailers(client, generation_guard).await?;
                        if self.position < self.buffered.len() {
                            return Err(miette!(
                                "HTTP request read-ahead extends past the end of its chunked body"
                            ));
                        }
                        self.state = ChunkedState::Done;
                    } else {
                        self.state = ChunkedState::Data { remaining: size };
                    }
                }
            }
        }
    }

    /// True when a framing byte can be read without waiting. Consuming it is
    /// safe: an unfinished chunked body always has more framing.
    fn ready<C: AsyncRead + Unpin>(&mut self, client: &mut C) -> Result<bool> {
        if self.position < self.buffered.len() {
            return Ok(true);
        }
        match client.read_u8().now_or_never() {
            Some(Ok(byte)) => {
                self.buffered.clear();
                self.buffered.push(byte);
                self.position = 0;
                Ok(true)
            }
            Some(Err(error)) => Err(error).into_diagnostic(),
            None => Ok(false),
        }
    }

    async fn read_byte<C: AsyncRead + Unpin>(
        &mut self,
        client: &mut C,
        generation_guard: Option<&PolicyGenerationGuard>,
    ) -> Result<u8> {
        if let Some(byte) = self.buffered.get(self.position) {
            self.position += 1;
            return Ok(*byte);
        }
        let byte = client
            .read_u8()
            .await
            .map_err(|_| miette!("connection closed before the chunked request body ended"))?;
        if let Some(guard) = generation_guard {
            guard.ensure_current()?;
        }
        Ok(byte)
    }

    async fn read_line<C: AsyncRead + Unpin>(
        &mut self,
        client: &mut C,
        generation_guard: Option<&PolicyGenerationGuard>,
    ) -> Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            if line.len() == MAX_CHUNK_LINE_BYTES {
                return Err(miette!("chunked request line exceeds limit"));
            }
            line.push(self.read_byte(client, generation_guard).await?);
            if line.ends_with(b"\r\n") {
                line.truncate(line.len() - 2);
                return Ok(line);
            }
        }
    }

    async fn read_trailers<C: AsyncRead + Unpin>(
        &mut self,
        client: &mut C,
        generation_guard: Option<&PolicyGenerationGuard>,
    ) -> Result<()> {
        let mut trailer_bytes = 0usize;
        loop {
            let line = self.read_line(client, generation_guard).await?;
            trailer_bytes = trailer_bytes.saturating_add(line.len() + 2);
            if trailer_bytes > MAX_HEADER_BYTES {
                return Err(miette!("request trailers exceed {MAX_HEADER_BYTES} bytes"));
            }
            if line.is_empty() {
                return Ok(());
            }
            if self.trailers.len() == MAX_CHUNK_TRAILER_FIELDS {
                return Err(miette!(
                    "request trailers exceed {MAX_CHUNK_TRAILER_FIELDS} fields"
                ));
            }
            self.trailers.push(parse_request_trailer(&line)?);
        }
    }
}

/// Read at most `want` payload bytes into `unit`, first from read-ahead, then
/// from the client. Waits for the client only while `unit` is empty.
async fn read_payload<C: AsyncRead + Unpin>(
    buffered: &[u8],
    position: &mut usize,
    client: &mut C,
    generation_guard: Option<&PolicyGenerationGuard>,
    unit: &mut Vec<u8>,
    want: usize,
) -> Result<usize> {
    let available = buffered.len().saturating_sub(*position).min(want);
    if available > 0 {
        unit.extend_from_slice(&buffered[*position..*position + available]);
        *position += available;
        return Ok(available);
    }
    let start = unit.len();
    unit.resize(start + want, 0);
    let read = if start == 0 {
        Some(client.read(&mut unit[start..]).await)
    } else {
        client.read(&mut unit[start..]).now_or_never()
    };
    let read = match read {
        None => 0,
        Some(Ok(0)) => {
            unit.truncate(start);
            return Err(miette!("connection closed before the request body ended"));
        }
        Some(Ok(read)) => read,
        Some(Err(error)) => {
            unit.truncate(start);
            return Err(error).into_diagnostic();
        }
    };
    unit.truncate(start + read);
    if read > 0
        && let Some(guard) = generation_guard
    {
        guard.ensure_current()?;
    }
    Ok(read)
}

fn parse_request_trailer(line: &[u8]) -> Result<HttpHeader> {
    let Some(separator) = line.iter().position(|byte| *byte == b':') else {
        return Err(miette!("request trailer is missing ':'"));
    };
    let name = &line[..separator];
    let value = &line[separator + 1..];
    if name.is_empty() || !name.iter().copied().all(is_http_field_name_byte) {
        return Err(miette!("request trailer has an invalid field name"));
    }
    if !value.iter().copied().all(is_http_field_value_byte) {
        return Err(miette!("request trailer has an invalid field value"));
    }
    let name = std::str::from_utf8(name)
        .expect("validated HTTP field names are ASCII")
        .to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "authorization"
            | "content-length"
            | "cookie"
            | "host"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
    ) || name.starts_with("x-amz-")
        || name.starts_with("x-openshell-credential")
    {
        return Err(miette!("request trailer uses protected field '{name}'"));
    }
    let value = std::str::from_utf8(value)
        .map_err(|_| miette!("request trailer value is not valid UTF-8"))?
        .trim()
        .to_string();
    Ok(HttpHeader { name, value })
}

/// Apply request head mutations without consuming or changing body framing.
pub fn rebuild_request_headers_only(
    req: &L7Request,
    header_mutations: &[HeaderMutation],
) -> Result<L7Request> {
    let header_end = request_header_end(&req.raw_header);
    let mut raw_header = apply_header_mutations(&req.raw_header[..header_end], header_mutations)?;
    raw_header.extend_from_slice(&req.raw_header[header_end..]);
    Ok(L7Request {
        action: req.action.clone(),
        target: req.target.clone(),
        query_params: req.query_params.clone(),
        raw_header,
        body_length: req.body_length,
    })
}

/// Head of a request whose body request middleware streams. Framing and late
/// mutations are applied when the head commits.
pub fn rebuild_request_for_live_body(
    req: &L7Request,
    headers: &[u8],
    header_mutations: &[HeaderMutation],
) -> Result<L7Request> {
    Ok(L7Request {
        action: req.action.clone(),
        target: req.target.clone(),
        query_params: req.query_params.clone(),
        raw_header: apply_header_mutations(headers, header_mutations)?,
        body_length: BodyLength::Chunked,
    })
}

/// Rebuild a request around a complete body produced by request middleware.
///
/// The body follows the head inline, as with legacy middleware, so credential
/// signing and rewriting see it. A body without trailers gets
/// `Content-Length`; trailers need chunked framing.
pub fn rebuild_request_with_middleware_body(
    req: &L7Request,
    headers: &[u8],
    body: &[u8],
    trailers: &[HttpHeader],
    header_mutations: &[HeaderMutation],
) -> Result<L7Request> {
    if trailers.is_empty() {
        return rebuild_request_with_buffered_body(req, headers, body, header_mutations);
    }
    let mut header_bytes = strip_header(headers, "content-length")?;
    header_bytes = strip_header(&header_bytes, "transfer-encoding")?;
    header_bytes = strip_header(&header_bytes, "trailer")?;
    header_bytes = append_header(&header_bytes, "Transfer-Encoding", "chunked");
    let names = trailers
        .iter()
        .map(|trailer| trailer.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    header_bytes = append_header(&header_bytes, "Trailer", &names);
    header_bytes = apply_header_mutations(&header_bytes, header_mutations)?;
    if !body.is_empty() {
        header_bytes.extend_from_slice(format!("{:X}\r\n", body.len()).as_bytes());
        header_bytes.extend_from_slice(body);
        header_bytes.extend_from_slice(b"\r\n");
    }
    header_bytes.extend_from_slice(b"0\r\n");
    for trailer in trailers {
        header_bytes
            .extend_from_slice(format!("{}: {}\r\n", trailer.name, trailer.value).as_bytes());
    }
    header_bytes.extend_from_slice(b"\r\n");
    Ok(L7Request {
        action: req.action.clone(),
        target: req.target.clone(),
        query_params: req.query_params.clone(),
        raw_header: header_bytes,
        body_length: BodyLength::Chunked,
    })
}

/// Commit framing and late mutations on a live request head.
fn commit_live_head(
    head: &[u8],
    late_mutations: &[HeaderMutation],
    output_body_bytes: Option<u64>,
) -> Result<Vec<u8>> {
    let mut head = strip_header(head, "content-length")?;
    head = strip_header(&head, "transfer-encoding")?;
    head = match output_body_bytes {
        Some(length) => {
            let length = usize::try_from(length)
                .map_err(|_| miette!("middleware output length is not representable"))?;
            set_content_length(&strip_header(&head, "trailer")?, length)?
        }
        None => append_header(&head, "Transfer-Encoding", "chunked"),
    };
    apply_header_mutations(&head, late_mutations)
}

/// A live request body failed before any response byte reached the client.
/// The caller answers the client and closes the connection.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum LiveRequestFailure {
    /// Request middleware rejected or failed the body.
    #[error("{reason}")]
    Middleware {
        reason: String,
        denial: Option<openshell_supervisor_middleware::MiddlewareDenial>,
    },
    /// The sandbox stopped sending the request body.
    #[error("request body client progress timeout")]
    ClientTimeout,
}

/// The upstream stopped accepting the request body. It may have answered
/// before it stopped reading, for example with 413.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("upstream stopped accepting the request body: {detail}")]
pub struct UpstreamWriteFailed {
    detail: String,
}

/// Upstream write half that records whether a write failed.
struct UpstreamWrites<'a, W> {
    inner: &'a mut W,
    failed: &'a AtomicBool,
}

impl<W> UpstreamWrites<'_, W> {
    fn record<T>(
        &self,
        result: std::task::Poll<std::io::Result<T>>,
    ) -> std::task::Poll<std::io::Result<T>> {
        if matches!(result, std::task::Poll::Ready(Err(_))) {
            self.failed.store(true, Ordering::Release);
        }
        result
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for UpstreamWrites<'_, W> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut *this.inner).poll_write(cx, buf);
        this.record(result)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut *this.inner).poll_flush(cx);
        this.record(result)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut *this.inner).poll_shutdown(cx);
        this.record(result)
    }
}

/// Write half that records whether any response byte reached the client.
struct ResponseCommit<W> {
    inner: W,
    committed: bool,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ResponseCommit<W> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(result, std::task::Poll::Ready(Ok(written)) if written > 0) {
            this.committed = true;
        }
        result
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Relay a request whose body request middleware streams, and its response.
///
/// The upload and the response run concurrently. An upstream response that
/// arrives before the upload ends cancels the middleware stages; the client
/// may still have unread request bytes, so the connection closes. An upstream
/// that stops accepting the body may have answered first, so its response is
/// still delivered. Any other upload failure before a response byte returns
/// [`LiveRequestFailure`] or a body credential error for the caller to answer;
/// after that, delivery aborts.
pub(super) async fn relay_live_request_and_response<C, U>(
    req: &L7Request,
    client: &mut C,
    upstream: &mut U,
    body: &mut crate::l7::middleware::RequestBodyStream,
    options: RelayRequestOptions<'_>,
    response_options: RelayResponseOptions<'_>,
    response_middleware: Option<HttpResponseMiddlewareRelay<'_>>,
) -> Result<RelayOutcome>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let head = &req.raw_header[..request_header_end(&req.raw_header)];
    let (mut client_reader, client_writer) = tokio::io::split(&mut *client);
    let mut client_writer = ResponseCommit {
        inner: client_writer,
        committed: false,
    };
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(&mut *upstream);
    let mut upload = Box::pin(upload_live_request(
        head,
        body,
        &mut client_reader,
        &mut upstream_writer,
        options,
    ));
    let mut response = Box::pin(relay_response(
        &req.action,
        &mut upstream_reader,
        &mut client_writer,
        response_options,
        response_middleware,
    ));

    tokio::select! {
        biased;
        uploaded = upload.as_mut() => {
            drop(upload);
            if let Err(error) = uploaded {
                if error.downcast_ref::<UpstreamWriteFailed>().is_some() {
                    let _ = upstream_writer.shutdown().await;
                    // The client may finish sending its body before it reads
                    // the answer, so keep reading and discarding it.
                    let mut sink = tokio::io::sink();
                    let discard = tokio::io::copy(&mut client_reader, &mut sink);
                    let responded = tokio::select! {
                        responded = response.as_mut() => responded,
                        _ = discard => response.as_mut().await,
                    };
                    drop(response);
                    return match responded {
                        Ok(RelayOutcome::Reusable) => {
                            finish_response(&mut client_writer, true).await
                        }
                        Ok(RelayOutcome::Consumed | RelayOutcome::Upgraded { .. }) => {
                            Ok(RelayOutcome::Consumed)
                        }
                        Err(_) => Err(error),
                    };
                }
                drop(response);
                let _ = upstream_writer.shutdown().await;
                if client_writer.committed {
                    return Err(miette!(
                        "request body relay failed after the response started: {error}"
                    ));
                }
                return Err(error);
            }
            upstream_writer.flush().await.into_diagnostic()?;
            response.await
        }
        responded = response.as_mut() => {
            drop(response);
            // Dropping the upload cancels every request middleware stage.
            drop(upload);
            body.cancelled("upstream_response");
            let _ = upstream_writer.shutdown().await;
            match responded? {
                RelayOutcome::Reusable => finish_response(&mut client_writer, true).await,
                RelayOutcome::Consumed | RelayOutcome::Upgraded { .. } => {
                    Ok(RelayOutcome::Consumed)
                }
            }
        }
    }
}

/// Why the upstream writer stopped.
enum LiveWriteError {
    /// The pipeline ended without `End`; its own result explains why.
    OutputEnded,
    Failed(miette::Report),
}

/// Upload a live request body. A failed upstream write is an
/// [`UpstreamWriteFailed`], whatever else the upload reports.
async fn upload_live_request<C, U>(
    head: &[u8],
    body: &mut crate::l7::middleware::RequestBodyStream,
    client: &mut C,
    upstream: &mut U,
    options: RelayRequestOptions<'_>,
) -> Result<()>
where
    C: AsyncRead + Unpin,
    U: AsyncWrite + Unpin,
{
    let failed = AtomicBool::new(false);
    let mut upstream = UpstreamWrites {
        inner: upstream,
        failed: &failed,
    };
    let uploaded = upload_live_body(head, body, client, &mut upstream, options, &failed).await;
    match uploaded {
        Err(error) if failed.load(Ordering::Acquire) => {
            Err(miette::Report::new(UpstreamWriteFailed {
                detail: error.to_string(),
            }))
        }
        uploaded => uploaded,
    }
}

async fn upload_live_body<C, U>(
    head: &[u8],
    body: &mut crate::l7::middleware::RequestBodyStream,
    client: &mut C,
    upstream: &mut U,
    options: RelayRequestOptions<'_>,
    upstream_failed: &AtomicBool,
) -> Result<()>
where
    C: AsyncRead + Unpin,
    U: AsyncWrite + Unpin,
{
    let injected = body.take_injected_headers();
    // Chunked input may end with trailers, which only chunked output carries.
    let input_chunked = body.input_is_chunked();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
    let run = body.run_to(client, sender, upstream_failed);
    let upstream_for_write = &mut *upstream;
    let write = async move {
        let mut scanner = options
            .deny_uninspected_credentials
            .then(|| ReservedMarkerStreamGuard::new(options.body_classifier));
        let mut fixed_length = None;
        while let Some(event) = receiver.recv().await {
            match event {
                HttpBodyOutput::Start {
                    header_mutations,
                    output_body_bytes,
                    ..
                } if fixed_length.is_none() => {
                    let output_body_bytes = output_body_bytes.filter(|_| !input_chunked);
                    let head = commit_live_head(head, &header_mutations, output_body_bytes)
                        .and_then(|head| injected.apply(&head))
                        .map_err(LiveWriteError::Failed)?;
                    let head = strip_connection_nominated_headers(&head, false)
                        .map_err(LiveWriteError::Failed)?;
                    let head = rewrite_http_header_block(&head, options.resolver)
                        .map_err(|error| LiveWriteError::Failed(miette::Report::new(error)))?
                        .rewritten;
                    ensure_body_generation_current(options).map_err(LiveWriteError::Failed)?;
                    upstream_for_write
                        .write_all(&head)
                        .await
                        .into_diagnostic()
                        .map_err(LiveWriteError::Failed)?;
                    upstream_for_write
                        .flush()
                        .await
                        .into_diagnostic()
                        .map_err(LiveWriteError::Failed)?;
                    fixed_length = Some(output_body_bytes.is_some());
                }
                HttpBodyOutput::Chunk(data) if fixed_length.is_some() => {
                    let data = match scanner.as_mut() {
                        Some(scanner) => scanner
                            .push(&data)
                            .map_err(|error| LiveWriteError::Failed(error.into()))?,
                        None => data,
                    };
                    write_live_bytes(upstream_for_write, &data, fixed_length, options)
                        .await
                        .map_err(LiveWriteError::Failed)?;
                }
                HttpBodyOutput::End { .. } if fixed_length.is_some() => {
                    return Ok((scanner, fixed_length));
                }
                _ => {
                    return Err(LiveWriteError::Failed(miette!(
                        "invalid request middleware output order"
                    )));
                }
            }
        }
        Err(LiveWriteError::OutputEnded)
    };
    let (finish, written): (Result<HttpPipelineFinish>, _) = tokio::join!(run, write);
    let (finish, (scanner, fixed_length)) = match (finish, written) {
        (_, Err(LiveWriteError::Failed(error))) | (Err(error), _) => return Err(error),
        (Ok(_), Err(LiveWriteError::OutputEnded)) => {
            return Err(miette!("request middleware output ended early"));
        }
        (Ok(finish), Ok(written)) => (finish, written),
    };
    if let Some(scanner) = scanner {
        write_live_bytes(upstream, &scanner.finish()?, fixed_length, options).await?;
    }
    if fixed_length == Some(true) {
        if !finish.trailers.is_empty() {
            // The upstream already has the whole body; Content-Length framing
            // cannot carry the trailers request middleware added.
            debug!("Dropping request trailers after a declared middleware output length");
        }
        return Ok(());
    }
    write_body_bytes(upstream, b"0\r\n", options).await?;
    for trailer in finish.trailers {
        let encoded = format!("{}: {}\r\n", trailer.name, trailer.value);
        if options.deny_uninspected_credentials
            && contains_reserved_credential_marker_bytes(encoded.as_bytes())
        {
            return Err(BodyCredentialError::Trailer.into());
        }
        write_body_bytes(upstream, encoded.as_bytes(), options).await?;
    }
    write_body_bytes(upstream, b"\r\n", options).await
}

async fn write_live_bytes<U: AsyncWrite + Unpin>(
    upstream: &mut U,
    data: &[u8],
    fixed_length: Option<bool>,
    options: RelayRequestOptions<'_>,
) -> Result<()> {
    if fixed_length == Some(true) {
        write_body_bytes(upstream, data, options).await
    } else {
        write_guarded_chunk(upstream, data, options).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::*;

    fn request(raw_header: &[u8], body_length: BodyLength) -> L7Request {
        L7Request {
            action: "POST".into(),
            target: "/push".into(),
            query_params: HashMap::new(),
            raw_header: raw_header.to_vec(),
            body_length,
        }
    }

    const CHUNKED_HEAD: &[u8] =
        b"POST /push HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";

    async fn read_units(
        reader: &mut RequestBodyReader,
        client: &mut tokio::io::DuplexStream,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>> {
        let mut units = Vec::new();
        while let Some(unit) = reader.next_unit(client, None, limit).await? {
            assert!(!unit.is_empty() && unit.len() <= limit, "{unit:?}");
            units.push(unit);
        }
        Ok(units)
    }

    #[tokio::test]
    async fn upstream_writes_record_a_failed_write() {
        let (mut upstream, peer) = tokio::io::duplex(16);
        drop(peer);
        let failed = AtomicBool::new(false);
        let mut writes = UpstreamWrites {
            inner: &mut upstream,
            failed: &failed,
        };
        writes
            .write_all(b"body")
            .await
            .expect_err("the upstream closed");
        assert!(failed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn chunked_reader_coalesces_ready_chunks_up_to_the_unit_limit() {
        let wire = b"4\r\nWiki\r\n5;sample=yes\r\npedia\r\n0\r\nX-Trace: complete\r\n\r\n";
        for (limit, expected) in [
            (1024, vec![b"Wikipedia".to_vec()]),
            (3, vec![b"Wik".to_vec(), b"ipe".to_vec(), b"dia".to_vec()]),
        ] {
            let (mut client, mut app) = tokio::io::duplex(1024);
            app.write_all(wire).await.unwrap();
            let (_, mut reader) = prepare_request_body_stream(
                &request(CHUNKED_HEAD, BodyLength::Chunked),
                &mut client,
            )
            .await
            .unwrap();
            assert_eq!(
                read_units(&mut reader, &mut client, limit).await.unwrap(),
                expected
            );
            assert_eq!(
                reader.take_trailers(),
                [HttpHeader {
                    name: "x-trace".into(),
                    value: "complete".into(),
                }]
            );
        }
    }

    #[tokio::test]
    async fn body_readers_return_ready_bytes_without_waiting_to_fill_a_unit() {
        let fixed = request(
            b"POST /push HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\n",
            BodyLength::ContentLength(10),
        );
        for (req, wire) in [
            (fixed, &b"hello"[..]),
            (
                request(CHUNKED_HEAD, BodyLength::Chunked),
                &b"5\r\nhello\r\n"[..],
            ),
        ] {
            let (mut client, mut app) = tokio::io::duplex(1024);
            app.write_all(wire).await.unwrap();
            let (_, mut reader) = prepare_request_body_stream(&req, &mut client)
                .await
                .unwrap();
            let unit = tokio::time::timeout(
                Duration::from_secs(1),
                reader.next_unit(&mut client, None, 1024),
            )
            .await
            .expect("a unit is returned once its bytes are ready")
            .unwrap();
            assert_eq!(unit.as_deref(), Some(&b"hello"[..]));
        }
    }

    #[tokio::test]
    async fn chunked_reader_caps_lines_like_the_chunked_relay() {
        let mut wire =
            format!("1;{}\r\nx\r\n0\r\n\r\n", "e".repeat(MAX_CHUNK_LINE_BYTES)).into_bytes();
        let (mut client, mut app) = tokio::io::duplex(64 * 1024);
        app.write_all(&wire).await.unwrap();
        let (_, mut reader) =
            prepare_request_body_stream(&request(CHUNKED_HEAD, BodyLength::Chunked), &mut client)
                .await
                .unwrap();
        let error = read_units(&mut reader, &mut client, 1024)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds limit"), "{error}");

        // A line just under the cap is accepted.
        wire = format!(
            "1;{}\r\nx\r\n0\r\n\r\n",
            "e".repeat(MAX_CHUNK_LINE_BYTES - 5)
        )
        .into_bytes();
        let (mut client, mut app) = tokio::io::duplex(64 * 1024);
        app.write_all(&wire).await.unwrap();
        let (_, mut reader) =
            prepare_request_body_stream(&request(CHUNKED_HEAD, BodyLength::Chunked), &mut client)
                .await
                .unwrap();
        assert_eq!(
            read_units(&mut reader, &mut client, 1024).await.unwrap(),
            [b"x".to_vec()]
        );
    }

    #[tokio::test]
    async fn read_ahead_past_the_body_is_an_error() {
        let next = b"GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut chunked = CHUNKED_HEAD.to_vec();
        chunked.extend_from_slice(b"2\r\nhi\r\n0\r\n\r\n");
        chunked.extend_from_slice(next);
        let (mut client, _app) = tokio::io::duplex(1024);
        let (_, mut reader) =
            prepare_request_body_stream(&request(&chunked, BodyLength::Chunked), &mut client)
                .await
                .unwrap();
        let error = read_units(&mut reader, &mut client, 1024)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("past the end"), "{error}");

        let mut fixed =
            b"POST /push HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\nhi".to_vec();
        fixed.extend_from_slice(next);
        let error = prepare_request_body_stream(
            &request(&fixed, BodyLength::ContentLength(2)),
            &mut client,
        )
        .await
        .err()
        .expect("read-ahead past Content-Length is rejected");
        assert!(
            error.to_string().contains("exceeds its declared"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn body_readers_leave_the_next_pipelined_request_unread() {
        let next = b"GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n";
        for (req, body) in [
            (
                request(
                    b"POST /push HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n",
                    BodyLength::ContentLength(5),
                ),
                &b"hello"[..],
            ),
            (
                request(CHUNKED_HEAD, BodyLength::Chunked),
                &b"5\r\nhello\r\n0\r\n\r\n"[..],
            ),
        ] {
            let (mut client, mut app) = tokio::io::duplex(1024);
            app.write_all(body).await.unwrap();
            app.write_all(next).await.unwrap();
            app.shutdown().await.unwrap();
            let (_, mut reader) = prepare_request_body_stream(&req, &mut client)
                .await
                .unwrap();
            assert_eq!(
                read_units(&mut reader, &mut client, 1024)
                    .await
                    .unwrap()
                    .concat(),
                b"hello"
            );
            let mut remaining = Vec::new();
            client.read_to_end(&mut remaining).await.unwrap();
            assert_eq!(remaining, next);
        }
    }

    #[tokio::test]
    async fn relay_forwards_a_chunked_body_prefix_read_with_the_headers() {
        // A forward-proxy head read can already contain part of the body.
        let body = b"5;ext=1\r\nhello\r\n0\r\nX-Trace: done\r\n\r\n";
        let next = b"DELETE /blocked HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
        for prefix_len in 0..=body.len() {
            let mut raw_header = CHUNKED_HEAD.to_vec();
            raw_header.extend_from_slice(&body[..prefix_len]);
            let req = request(&raw_header, BodyLength::Chunked);
            let (client, mut app) = tokio::io::duplex(4096);
            app.write_all(&body[prefix_len..]).await.unwrap();
            app.write_all(next).await.unwrap();
            app.shutdown().await.unwrap();
            let mut client = tokio::io::BufReader::new(client);
            let (mut upstream, mut server) = tokio::io::duplex(4096);
            server.write_all(response).await.unwrap();

            let outcome = relay_http_request_with_options_guarded(
                &req,
                &mut client,
                &mut upstream,
                RelayRequestOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("prefix={prefix_len}: {error}"));
            assert!(
                matches!(outcome, RelayOutcome::Reusable),
                "prefix={prefix_len}"
            );

            drop(upstream);
            let mut forwarded = Vec::new();
            server.read_to_end(&mut forwarded).await.unwrap();
            let (_, forwarded_body) = forwarded.split_at(
                forwarded
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .unwrap()
                    + 4,
            );
            assert_eq!(forwarded_body, body, "prefix={prefix_len}");
            let mut remaining = Vec::new();
            client.read_to_end(&mut remaining).await.unwrap();
            assert_eq!(remaining, next, "prefix={prefix_len}");
        }
    }

    #[test]
    fn middleware_body_is_inlined_with_trailers_as_chunked() {
        let req = request(CHUNKED_HEAD, BodyLength::Chunked);
        let rebuilt = rebuild_request_with_middleware_body(
            &req,
            CHUNKED_HEAD,
            b"Wikipedia",
            &[HttpHeader {
                name: "x-trace".into(),
                value: "done".into(),
            }],
            &[],
        )
        .unwrap();
        assert!(matches!(rebuilt.body_length, BodyLength::Chunked));
        let raw = String::from_utf8(rebuilt.raw_header).unwrap();
        assert!(raw.contains("Transfer-Encoding: chunked\r\n"), "{raw}");
        assert!(raw.contains("Trailer: x-trace\r\n"), "{raw}");
        assert!(
            raw.ends_with("\r\n\r\n9\r\nWikipedia\r\n0\r\nx-trace: done\r\n\r\n"),
            "{raw}"
        );
        assert!(chunked_body_is_fully_buffered(
            raw.split_once("\r\n\r\n").unwrap().1.as_bytes()
        ));
    }

    #[test]
    fn live_head_commits_declared_length_or_chunked_framing() {
        let head = b"POST /push HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nTrailer: x-trace\r\n\r\n";
        let late = [HeaderMutation {
            operation: Some(header_mutation::Operation::Write(
                openshell_core::proto::WriteHeader {
                    name: "x-late".into(),
                    value: "1".into(),
                    on_existing: ExistingHeaderAction::Overwrite as i32,
                },
            )),
        }];
        let fixed = String::from_utf8(commit_live_head(head, &late, Some(7)).unwrap()).unwrap();
        assert!(fixed.contains("Content-Length: 7\r\n"), "{fixed}");
        assert!(!fixed.to_ascii_lowercase().contains("trailer:"), "{fixed}");
        assert!(fixed.ends_with("x-late: 1\r\n\r\n"), "{fixed}");
        let chunked = String::from_utf8(commit_live_head(head, &late, None).unwrap()).unwrap();
        assert!(
            chunked.contains("Transfer-Encoding: chunked\r\n"),
            "{chunked}"
        );
        assert!(chunked.contains("Trailer: x-trace\r\n"), "{chunked}");
        assert!(!chunked.contains("Content-Length"), "{chunked}");
    }
}
