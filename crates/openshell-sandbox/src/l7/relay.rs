// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protocol-aware bidirectional relay with L7 inspection.
//!
//! Replaces `copy_bidirectional` for endpoints with L7 configuration.
//! Parses each request within the tunnel, evaluates it against OPA policy,
//! and either forwards or denies the request.

use crate::denial_aggregator::DenialEvent;
use crate::l7::content::ContentScanConfig;
use crate::l7::privacy_scan;
use crate::l7::provider::{BodyLength, L7Provider, L7Request, RelayOutcome};
use crate::l7::{EnforcementMode, L7EndpointConfig, L7Protocol, L7RequestInfo};
use crate::secrets::{self, SecretResolver};
use miette::{IntoDiagnostic, Result, miette};
use openshell_ocsf::{
    ActionId, ActivityId, DetectionFindingBuilder, DispositionId, Endpoint, FindingInfo,
    HttpActivityBuilder, HttpRequest, NetworkActivityBuilder, SeverityId, Url as OcsfUrl,
    ocsf_emit,
};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Context for L7 request policy evaluation.
pub struct L7EvalContext {
    /// Host from the CONNECT request.
    pub host: String,
    /// Port from the CONNECT request.
    pub port: u16,
    /// Matched policy name from L4 evaluation.
    pub policy_name: String,
    /// Binary path (for cross-layer Rego evaluation).
    pub binary_path: String,
    /// Ancestor paths.
    pub ancestors: Vec<String>,
    /// Cmdline paths.
    pub cmdline_paths: Vec<String>,
    /// Supervisor-only placeholder resolver for outbound headers.
    pub(crate) secret_resolver: Option<Arc<SecretResolver>>,
    /// Denial aggregator channel. Content denials feed this with
    /// `denial_stage: "content_deny"` so they reach the draft-proposal flow.
    pub denial_tx: Option<mpsc::UnboundedSender<DenialEvent>>,
}

/// Run protocol-aware L7 inspection on a tunnel.
///
/// This replaces `copy_bidirectional` for L7-enabled endpoints.
/// Protocol detection (peek) is the caller's responsibility — this function
/// assumes the streams are already proven to carry the expected protocol.
/// For TLS-terminated connections, ALPN proves HTTP; for plaintext, the
/// caller peeks on the raw `TcpStream` before calling this.
pub async fn relay_with_inspection<C, U>(
    config: &L7EndpointConfig,
    engine: Mutex<regorus::Engine>,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    match config.protocol {
        L7Protocol::Rest => relay_rest(config, &engine, client, upstream, ctx).await,
        L7Protocol::Sql => {
            // SQL provider is Phase 3 — fall through to passthrough with warning
            {
                let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                    .activity(ActivityId::Other)
                    .severity(SeverityId::Low)
                    .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                    .message("SQL L7 provider not yet implemented, falling back to passthrough")
                    .build();
                ocsf_emit!(event);
            }
            tokio::io::copy_bidirectional(client, upstream)
                .await
                .into_diagnostic()?;
            Ok(())
        }
    }
}

/// REST relay with deferred upstream TLS.
///
/// Used when proxy-level scanning is active for a TLS L7 endpoint. Establishes
/// upstream TLS only after `prepare_content_scan` returns, so body buffering
/// never leaves the upstream connection idle.
pub async fn relay_rest_deferred_upstream<C>(
    config: &L7EndpointConfig,
    engine: &Mutex<regorus::Engine>,
    client: &mut C,
    raw_upstream: tokio::net::TcpStream,
    upstream_host: &str,
    upstream_tls_config: &Arc<rustls::ClientConfig>,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    let provider =
        crate::l7::rest::RestProvider::with_options(crate::l7::path::CanonicalizeOptions {
            allow_encoded_slash: config.allow_encoded_slash,
            ..Default::default()
        });

    let req = match provider.parse_request(client).await {
        Ok(Some(req)) => req,
        Ok(None) => return Ok(()),
        Err(e) => {
            if !is_benign_connection_error(&e) {
                let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                    .activity(ActivityId::Fail)
                    .severity(SeverityId::Low)
                    .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                    .message(format!("HTTP parse error in deferred relay: {e}"))
                    .build();
                ocsf_emit!(event);
            }
            return Ok(());
        }
    };

    let (_eval_target, redacted_target) = if let Some(ref resolver) = ctx.secret_resolver {
        match secrets::rewrite_target_for_eval(&req.target, resolver) {
            Ok(result) => (result.resolved, result.redacted),
            Err(e) => {
                warn!(error = %e, "credential resolution failed, rejecting");
                let resp = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                client.write_all(resp).await.into_diagnostic()?;
                client.flush().await.into_diagnostic()?;
                return Ok(());
            }
        }
    } else {
        (req.target.clone(), req.target.clone())
    };

    let request_info = L7RequestInfo {
        action: req.action.clone(),
        target: redacted_target.clone(),
        query_params: req.query_params.clone(),
    };

    let (allowed, reason) = evaluate_l7_request(engine, ctx, &request_info)?;
    let decision_str = if allowed {
        "allow"
    } else if config.enforcement == EnforcementMode::Enforce {
        "deny"
    } else {
        "audit"
    };

    {
        let (action_id, disposition_id, severity) = match decision_str {
            "allow" => (
                ActionId::Allowed,
                DispositionId::Allowed,
                SeverityId::Informational,
            ),
            "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
            _ => (
                ActionId::Allowed,
                DispositionId::Allowed,
                SeverityId::Informational,
            ),
        };
        let event = HttpActivityBuilder::new(crate::ocsf_ctx())
            .activity(ActivityId::Other)
            .action(action_id)
            .disposition(disposition_id)
            .severity(severity)
            .http_request(HttpRequest::new(
                &request_info.action,
                OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
            ))
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .firewall_rule(&ctx.policy_name, "l7")
            .message(format!(
                "L7_REQUEST {decision_str} {} {}:{}{} reason={}",
                request_info.action, ctx.host, ctx.port, redacted_target, reason,
            ))
            .build();
        ocsf_emit!(event);
    }

    if !(allowed || config.enforcement == EnforcementMode::Audit) {
        provider
            .deny_with_redacted_target(
                &req,
                &ctx.policy_name,
                &reason,
                client,
                Some(&redacted_target),
            )
            .await?;
        return Ok(());
    }

    // Content scan runs BEFORE upstream TLS connection.
    let scan_ready =
        prepare_content_scan(&req, client, ctx, config.content_policy.as_ref()).await?;

    match scan_ready {
        ContentScanReady::Relay {
            header_out,
            body_out,
        } => {
            let mut tls_upstream = crate::l7::tls::tls_connect_upstream(
                raw_upstream,
                upstream_host,
                upstream_tls_config,
            )
            .await?;

            tls_upstream
                .write_all(&header_out)
                .await
                .into_diagnostic()?;
            if !body_out.is_empty() {
                tls_upstream.write_all(&body_out).await.into_diagnostic()?;
            }
            tls_upstream.flush().await.into_diagnostic()?;

            crate::l7::rest::relay_response_public(&req.action, &mut tls_upstream, client).await?;
        }
        ContentScanReady::Passthrough => {
            let mut tls_upstream = crate::l7::tls::tls_connect_upstream(
                raw_upstream,
                upstream_host,
                upstream_tls_config,
            )
            .await?;
            crate::l7::rest::relay_http_request_with_resolver(
                &req,
                client,
                &mut tls_upstream,
                ctx.secret_resolver.as_deref(),
            )
            .await?;
        }
    }

    Ok(())
}

/// Handle an upgraded connection (101 Switching Protocols).
///
/// Forwards any overflow bytes from the upgrade response to the client, then
/// switches to raw bidirectional TCP copy for the upgraded protocol (WebSocket,
/// HTTP/2, etc.). L7 policy enforcement does not apply after the upgrade —
/// the initial HTTP request was already evaluated.
async fn handle_upgrade<C, U>(
    client: &mut C,
    upstream: &mut U,
    overflow: Vec<u8>,
    host: &str,
    port: u16,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    ocsf_emit!(
        NetworkActivityBuilder::new(crate::ocsf_ctx())
            .activity(ActivityId::Other)
            .activity_name("Upgrade")
            .severity(SeverityId::Informational)
            .dst_endpoint(Endpoint::from_domain(host, port))
            .message(format!(
                "101 Switching Protocols — raw bidirectional relay (L7 enforcement no longer active) \
                 [host:{host} port:{port} overflow_bytes:{}]",
                overflow.len()
            ))
            .build()
    );
    if !overflow.is_empty() {
        client.write_all(&overflow).await.into_diagnostic()?;
        client.flush().await.into_diagnostic()?;
    }
    tokio::io::copy_bidirectional(client, upstream)
        .await
        .into_diagnostic()?;
    Ok(())
}

/// REST relay loop: parse request -> evaluate -> allow/deny -> relay response -> repeat.
async fn relay_rest<C, U>(
    config: &L7EndpointConfig,
    engine: &Mutex<regorus::Engine>,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Build a provider carrying the per-endpoint canonicalization options so
    // request parsing honors the endpoint's `allow_encoded_slash` setting
    // (e.g. APIs like GitLab that embed `%2F` in path segments).
    let provider =
        crate::l7::rest::RestProvider::with_options(crate::l7::path::CanonicalizeOptions {
            allow_encoded_slash: config.allow_encoded_slash,
            ..Default::default()
        });
    loop {
        // Parse one HTTP request from client
        let req = match provider.parse_request(client).await {
            Ok(Some(req)) => req,
            Ok(None) => return Ok(()), // Client closed connection
            Err(e) => {
                if is_benign_connection_error(&e) {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "L7 connection closed"
                    );
                } else {
                    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Fail)
                        .severity(SeverityId::Low)
                        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                        .message(format!("HTTP parse error in L7 relay: {e}"))
                        .build();
                    ocsf_emit!(event);
                }
                return Ok(()); // Close connection on parse error
            }
        };

        // Rewrite credential placeholders in the request target BEFORE OPA
        // evaluation. OPA sees the redacted path; the resolved path goes only
        // to the upstream write.
        let (eval_target, redacted_target) = if let Some(ref resolver) = ctx.secret_resolver {
            match secrets::rewrite_target_for_eval(&req.target, resolver) {
                Ok(result) => (result.resolved, result.redacted),
                Err(e) => {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "credential resolution failed in request target, rejecting"
                    );
                    let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    client.write_all(response).await.into_diagnostic()?;
                    client.flush().await.into_diagnostic()?;
                    return Ok(());
                }
            }
        } else {
            (req.target.clone(), req.target.clone())
        };

        let request_info = L7RequestInfo {
            action: req.action.clone(),
            target: redacted_target.clone(),
            query_params: req.query_params.clone(),
        };

        // Evaluate L7 policy via Rego (using redacted target)
        let (allowed, reason) = evaluate_l7_request(engine, ctx, &request_info)?;

        // Check if this is an upgrade request for logging purposes.
        let header_end = req
            .raw_header
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map_or(req.raw_header.len(), |p| p + 4);
        let is_upgrade_request = {
            let h = String::from_utf8_lossy(&req.raw_header[..header_end]);
            h.lines()
                .skip(1)
                .any(|l| l.to_ascii_lowercase().starts_with("upgrade:"))
        };

        let decision_str = match (allowed, config.enforcement, is_upgrade_request) {
            (true, _, true) => "allow_upgrade",
            (true, _, false) => "allow",
            (false, EnforcementMode::Audit, _) => "audit",
            (false, EnforcementMode::Enforce, _) => "deny",
        };

        // Log every L7 decision as an OCSF HTTP Activity event.
        // Uses redacted_target (path only, no query params) to avoid logging secrets.
        {
            let (action_id, disposition_id, severity) = match decision_str {
                "allow" => (
                    ActionId::Allowed,
                    DispositionId::Allowed,
                    SeverityId::Informational,
                ),
                "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
                "audit" => (
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
            let event = HttpActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Other)
                .action(action_id)
                .disposition(disposition_id)
                .severity(severity)
                .http_request(HttpRequest::new(
                    &request_info.action,
                    OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .firewall_rule(&ctx.policy_name, "l7")
                .message(format!(
                    "L7_REQUEST {decision_str} {} {}:{}{} reason={}",
                    request_info.action, ctx.host, ctx.port, redacted_target, reason,
                ))
                .build();
            ocsf_emit!(event);
        }

        // Store the resolved target for the deny response redaction
        let _ = &eval_target;

        if allowed || config.enforcement == EnforcementMode::Audit {
            // Content scanning: buffer body + scan BEFORE writing to
            // upstream, so redaction and framing updates happen before relay.
            let scan_ready =
                prepare_content_scan(&req, client, ctx, config.content_policy.as_ref()).await?;

            let outcome = match scan_ready {
                ContentScanReady::Relay {
                    header_out,
                    body_out,
                } => {
                    upstream.write_all(&header_out).await.into_diagnostic()?;
                    if !body_out.is_empty() {
                        upstream.write_all(&body_out).await.into_diagnostic()?;
                    }
                    upstream.flush().await.into_diagnostic()?;
                    crate::l7::rest::relay_response_public(&req.action, upstream, client).await
                }
                ContentScanReady::Passthrough => {
                    crate::l7::rest::relay_http_request_with_resolver(
                        &req,
                        client,
                        upstream,
                        ctx.secret_resolver.as_deref(),
                    )
                    .await
                }
            }?;
            match outcome {
                RelayOutcome::Reusable => {} // continue loop
                RelayOutcome::Consumed => {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        "Upstream connection not reusable, closing L7 relay"
                    );
                    return Ok(());
                }
                RelayOutcome::Upgraded { overflow } => {
                    return handle_upgrade(client, upstream, overflow, &ctx.host, ctx.port).await;
                }
            }
        } else {
            // Enforce mode: deny with 403 and close connection (use redacted target)
            provider
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    &reason,
                    client,
                    Some(&redacted_target),
                )
                .await?;
            return Ok(());
        }
    }
}

/// Check if a miette error represents a benign connection close.
///
/// TLS handshake EOF, missing `close_notify`, connection resets, and broken
/// pipes are all normal lifecycle events for proxied connections — not worth
/// a WARN that interrupts the user's terminal.
fn is_benign_connection_error(err: &miette::Report) -> bool {
    const BENIGN: &[&str] = &[
        "close_notify",
        "tls handshake eof",
        "connection reset",
        "broken pipe",
        "unexpected eof",
        "client disconnected mid-request",
    ];
    let msg = err.to_string().to_ascii_lowercase();
    BENIGN.iter().any(|pat| msg.contains(pat))
}

/// Result of content scanning before upstream relay.
enum ContentScanReady {
    /// Ready to relay: processed headers + body. Upstream not touched yet.
    Relay {
        header_out: Vec<u8>,
        body_out: Vec<u8>,
    },
    /// Body could not be buffered (too large or chunked). The caller must
    /// stream the original request to upstream with credential rewriting.
    Passthrough,
}

const DEFAULT_MAX_SCAN_BYTES: u64 = 1_048_576;

/// Buffer the request body from the client, run the embedded privacy scanner,
/// and return the processed headers + body ready to relay to upstream. Does NOT
/// touch the upstream connection -- the caller establishes or reuses upstream
/// only after this returns.
async fn prepare_content_scan<C>(
    req: &L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    content_cfg: Option<&ContentScanConfig>,
) -> Result<ContentScanReady>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    let header_end = req
        .raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(req.raw_header.len(), |p| p + 4);

    let overflow = &req.raw_header[header_end..];
    let overflow_len = overflow.len() as u64;
    let max_scan = content_cfg.map_or(DEFAULT_MAX_SCAN_BYTES, |cfg| cfg.max_scan_bytes as u64);

    let header_str = std::str::from_utf8(&req.raw_header[..header_end]).unwrap_or("");
    let content_type = header_value(header_str, "content-type").unwrap_or_default();

    let body_bytes: Option<Vec<u8>> = match req.body_length {
        BodyLength::ContentLength(len) if len <= max_scan => {
            let mut buf = Vec::with_capacity(len as usize);
            buf.extend_from_slice(overflow);
            let remaining = len.saturating_sub(overflow_len);
            if remaining > 0 {
                buf.resize(overflow.len() + remaining as usize, 0);
                client
                    .read_exact(&mut buf[overflow.len()..])
                    .await
                    .into_diagnostic()?;
            }
            Some(buf)
        }
        BodyLength::ContentLength(len) => {
            let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Other)
                .severity(SeverityId::Low)
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .message(format!(
                    "CONTENT_SCAN_SKIP body size {len} exceeds max_scan_bytes {max_scan} \
                     [host:{} port:{}]",
                    ctx.host, ctx.port,
                ))
                .build();
            ocsf_emit!(event);
            None
        }
        BodyLength::Chunked => {
            let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Other)
                .severity(SeverityId::Low)
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .message(format!(
                    "CONTENT_SCAN_SKIP chunked transfer encoding not buffered \
                     [host:{} port:{}]",
                    ctx.host, ctx.port,
                ))
                .build();
            ocsf_emit!(event);
            None
        }
        BodyLength::None => Some(Vec::new()),
    };

    // Body not buffered -- caller must stream directly.
    if body_bytes.is_none() {
        return Ok(ContentScanReady::Passthrough);
    }

    let replacement_body: Option<Vec<u8>> = if let Some(ref body) = body_bytes {
        if body.is_empty() {
            None
        } else {
            let scan_context = privacy_scan::PrivacyScanRequestContext {
                method: &req.action,
                scheme: if ctx.port == 443 { "https" } else { "http" },
                host: &ctx.host,
                port: ctx.port,
                path: &req.target,
            };
            let result =
                privacy_scan::scan_body_for_request(scan_context, &content_type, body).await;
            if result.redacted {
                info!(
                    "CONTENT_SCAN_REDACTED matches={} labels={} backend={} endpoint={}:{}",
                    result.match_count,
                    result.matches.join(","),
                    result.backend,
                    ctx.host,
                    ctx.port,
                );

                let label_summary = result.matches.join(", ");
                let event = DetectionFindingBuilder::new(crate::ocsf_ctx())
                    .activity(ActivityId::Open)
                    .severity(SeverityId::Medium)
                    .disposition(DispositionId::Other)
                    .action(ActionId::Allowed)
                    .finding_info(
                        FindingInfo::new("privacy-router-scan", "Privacy Router Redaction")
                            .with_desc(&format!(
                                "Privacy scanner redacted {} matches in request body \
                             to {}:{} in {:.1}ms using {} [{}]",
                                result.match_count,
                                ctx.host,
                                ctx.port,
                                result.elapsed_ms,
                                result.backend,
                                label_summary,
                            )),
                    )
                    .evidence_pairs(&[
                        ("host", ctx.host.as_str()),
                        ("port", &ctx.port.to_string()),
                        ("match_count", &result.match_count.to_string()),
                        ("elapsed_ms", &format!("{:.1}", result.elapsed_ms)),
                        ("labels", &label_summary),
                        ("scanner_backend", &result.backend),
                    ])
                    .message(format!(
                        "CONTENT_SCAN_REDACTED {} matches in {:.1}ms [{}:{} backend:{} labels:{}]",
                        result.match_count,
                        result.elapsed_ms,
                        ctx.host,
                        ctx.port,
                        result.backend,
                        label_summary,
                    ))
                    .build();
                ocsf_emit!(event);

                Some(result.replacement_body)
            } else {
                None
            }
        }
    } else {
        None
    };

    let rewrite_result = secrets::rewrite_http_header_block(
        &req.raw_header[..header_end],
        ctx.secret_resolver.as_deref(),
    )
    .map_err(|e| miette!("credential injection failed: {e}"))?;

    let header_out = if let Some(ref new_body) = replacement_body {
        patch_body_framing(&rewrite_result.rewritten, new_body.len())
    } else {
        rewrite_result.rewritten.clone()
    };

    let body_out = if let Some(new_body) = replacement_body {
        new_body
    } else {
        body_bytes.unwrap_or_default()
    };

    Ok(ContentScanReady::Relay {
        header_out,
        body_out,
    })
}

/// Return the value of the first matching header (case-insensitive), trimmed.
fn header_value(header_block: &str, key: &str) -> Option<String> {
    for line in header_block.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(key) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Rewrite `Content-Length` to `new_body_len` and strip
/// `Transfer-Encoding: chunked` (and optionally `Transfer-Encoding` entirely
/// when it only names `chunked`). Preserves request-line and other headers
/// verbatim.
fn patch_body_framing(header_block: &[u8], new_body_len: usize) -> Vec<u8> {
    // Operate on the terminal `\r\n\r\n`, not lossy UTF-8: any byte that is
    // not ASCII gets passed through unchanged.
    let header_end = header_block
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(header_block.len(), |p| p + 4);
    let (headers, trailer) = header_block.split_at(header_end);

    let mut out: Vec<u8> = Vec::with_capacity(header_block.len() + 32);
    let mut cursor = 0usize;
    let mut saw_cl = false;

    while cursor < headers.len() {
        // Slice the next line up to and including CRLF.
        let rel_end = headers[cursor..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map_or(headers.len() - cursor, |p| p + 2);
        let line = &headers[cursor..cursor + rel_end];
        let trimmed = line.trim_ascii_end();

        // Blank line terminates the header section — emit any synthesized
        // Content-Length if we never saw one, then keep the blank line.
        if trimmed.is_empty() {
            if !saw_cl {
                out.extend_from_slice(format!("Content-Length: {new_body_len}\r\n").as_bytes());
            }
            out.extend_from_slice(line);
            cursor += rel_end;
            continue;
        }

        let text = std::str::from_utf8(trimmed).unwrap_or("");
        let lower = text.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            out.extend_from_slice(format!("Content-Length: {new_body_len}\r\n").as_bytes());
            saw_cl = true;
            cursor += rel_end;
            continue;
        }
        if lower.starts_with("transfer-encoding:") {
            // Strip the header entirely — the replacement body is a fixed
            // length buffer; emitting both CL and TE would be ambiguous.
            cursor += rel_end;
            continue;
        }

        out.extend_from_slice(line);
        cursor += rel_end;
    }

    out.extend_from_slice(trailer);
    out
}

/// Evaluate an L7 request against the OPA engine.
///
/// Returns `(allowed, deny_reason)`.
pub fn evaluate_l7_request(
    engine: &Mutex<regorus::Engine>,
    ctx: &L7EvalContext,
    request: &L7RequestInfo,
) -> Result<(bool, String)> {
    let input_json = serde_json::json!({
        "network": {
            "host": ctx.host,
            "port": ctx.port,
        },
        "exec": {
            "path": ctx.binary_path,
            "ancestors": ctx.ancestors,
            "cmdline_paths": ctx.cmdline_paths,
        },
        "request": {
            "method": request.action,
            "path": request.target,
            "query_params": request.query_params.clone(),
        }
    });

    let mut engine = engine
        .lock()
        .map_err(|_| miette!("OPA engine lock poisoned"))?;

    engine
        .set_input_json(&input_json.to_string())
        .map_err(|e| miette!("{e}"))?;

    let allowed = engine
        .eval_rule("data.openshell.sandbox.allow_request".into())
        .map_err(|e| miette!("{e}"))?;
    let allowed = allowed == regorus::Value::from(true);

    let reason = if allowed {
        String::new()
    } else {
        let val = engine
            .eval_rule("data.openshell.sandbox.request_deny_reason".into())
            .map_err(|e| miette!("{e}"))?;
        match val {
            regorus::Value::String(s) => s.to_string(),
            regorus::Value::Undefined => "request denied by policy".to_string(),
            other => other.to_string(),
        }
    };

    Ok((allowed, reason))
}

/// Relay HTTP traffic with credential injection only (no L7 OPA evaluation).
///
/// Used when TLS is auto-terminated but no L7 policy (`protocol` + `access`/`rules`)
/// is configured. Parses HTTP requests minimally to rewrite credential
/// placeholders and log requests for observability, then forwards everything.
pub async fn relay_passthrough_with_credentials<C, U>(
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Passthrough path: no L7 policy is enforced here, so use default
    // (strict) canonicalization options. Calls to GitLab-style APIs that
    // need `%2F` must be configured as L7 endpoints so the per-endpoint
    // `allow_encoded_slash` opt-in applies.
    let provider = crate::l7::rest::RestProvider::default();
    let mut request_count: u64 = 0;
    let resolver = ctx.secret_resolver.as_deref();

    loop {
        // Read next request from client.
        let req = match provider.parse_request(client).await {
            Ok(Some(req)) => req,
            Ok(None) => break, // Client closed connection.
            Err(e) => {
                if is_benign_connection_error(&e) {
                    break;
                }
                return Err(e);
            }
        };

        request_count += 1;

        // Resolve and redact the target for logging.
        let redacted_target = if let Some(ref res) = ctx.secret_resolver {
            match secrets::rewrite_target_for_eval(&req.target, res) {
                Ok(result) => result.redacted,
                Err(e) => {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "credential resolution failed in request target, rejecting"
                    );
                    let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    client.write_all(response).await.into_diagnostic()?;
                    client.flush().await.into_diagnostic()?;
                    return Ok(());
                }
            }
        } else {
            req.target.clone()
        };

        // Log for observability via OCSF HTTP Activity event.
        // Uses redacted_target (path only, no query params) to avoid logging secrets.
        let has_creds = resolver.is_some();
        {
            let event = HttpActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Other)
                .action(ActionId::Allowed)
                .disposition(DispositionId::Allowed)
                .severity(SeverityId::Informational)
                .http_request(HttpRequest::new(
                    &req.action,
                    OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .message(format!(
                    "HTTP_REQUEST {} {}:{}{} credentials_injected={has_creds} request_num={request_count}",
                    req.action, ctx.host, ctx.port, redacted_target,
                ))
                .build();
            ocsf_emit!(event);
        }

        // Forward request with credential rewriting and relay the response.
        // This path has no endpoint-level L7 content policy, so it uses the
        // default scan cap.
        let outcome = match prepare_content_scan(&req, client, ctx, None).await? {
            ContentScanReady::Relay {
                header_out,
                body_out,
            } => {
                upstream.write_all(&header_out).await.into_diagnostic()?;
                if !body_out.is_empty() {
                    upstream.write_all(&body_out).await.into_diagnostic()?;
                }
                upstream.flush().await.into_diagnostic()?;
                crate::l7::rest::relay_response_public(&req.action, upstream, client).await?
            }
            ContentScanReady::Passthrough => {
                crate::l7::rest::relay_http_request_with_resolver(&req, client, upstream, resolver)
                    .await?
            }
        };

        match outcome {
            RelayOutcome::Reusable => {} // continue loop
            RelayOutcome::Consumed => break,
            RelayOutcome::Upgraded { overflow } => {
                return handle_upgrade(client, upstream, overflow, &ctx.host, ctx.port).await;
            }
        }
    }

    debug!(
        host = %ctx.host,
        port = ctx.port,
        total_requests = request_count,
        "Credential injection relay completed"
    );

    Ok(())
}

#[cfg(test)]
mod phase2_tests {
    use super::*;

    #[test]
    fn patch_body_framing_replaces_content_length() {
        let headers = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 17\r\n\r\n";
        let patched = patch_body_framing(headers, 42);
        let text = std::str::from_utf8(&patched).unwrap();
        assert!(
            text.contains("Content-Length: 42\r\n"),
            "missing patched CL: {text:?}"
        );
        assert!(
            !text.contains("Content-Length: 17"),
            "original CL leaked: {text:?}"
        );
    }

    #[test]
    fn patch_body_framing_strips_chunked_te() {
        let headers = b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let patched = patch_body_framing(headers, 7);
        let text = std::str::from_utf8(&patched).unwrap();
        assert!(
            !text.to_ascii_lowercase().contains("transfer-encoding"),
            "TE should be stripped: {text:?}"
        );
        assert!(
            text.contains("Content-Length: 7\r\n"),
            "CL should be added: {text:?}"
        );
    }

    #[test]
    fn patch_body_framing_adds_content_length_when_missing() {
        let headers = b"POST /x HTTP/1.1\r\nHost: h\r\n\r\n";
        let patched = patch_body_framing(headers, 3);
        let text = std::str::from_utf8(&patched).unwrap();
        assert!(
            text.contains("Content-Length: 3\r\n"),
            "CL should be appended: {text:?}"
        );
        assert!(text.ends_with("\r\n\r\n"), "trailing CRLFCRLF preserved");
    }

    #[test]
    fn header_value_case_insensitive() {
        let h = "POST /x HTTP/1.1\r\nHost: example\r\nCONTENT-TYPE: application/json\r\n";
        assert_eq!(
            header_value(h, "content-type").as_deref(),
            Some("application/json")
        );
    }

    fn make_request(body: &[u8]) -> L7Request {
        let mut raw_header = format!(
            "POST /v1/chat HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw_header.extend_from_slice(body);
        L7Request {
            action: "POST".to_string(),
            target: "/v1/chat".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header,
            body_length: BodyLength::ContentLength(body.len() as u64),
        }
    }

    fn make_eval_ctx() -> L7EvalContext {
        L7EvalContext {
            host: "api.example.com".to_string(),
            port: 443,
            policy_name: "test-policy".to_string(),
            binary_path: "/usr/bin/curl".to_string(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            denial_tx: None,
        }
    }

    #[tokio::test]
    async fn prepare_content_scan_scans_without_content_policy() {
        let original = br#"{"api_key":"sk-proj-abcdefghijklmnopqrstuvwxyz123456"}"#;
        let replacement = br#"{"api_key":"[OPENAI_API_KEY]"}"#;
        let ctx = make_eval_ctx();
        let req = make_request(original);
        let (mut client, _peer) = tokio::io::duplex(1);

        let ready = prepare_content_scan(&req, &mut client, &ctx, None)
            .await
            .expect("scan prepares");

        match ready {
            ContentScanReady::Relay {
                header_out,
                body_out,
            } => {
                let header = std::str::from_utf8(&header_out).unwrap();
                assert!(
                    header.contains(&format!("Content-Length: {}\r\n", replacement.len())),
                    "replacement content length missing: {header:?}"
                );
                assert_eq!(body_out, replacement);
            }
            ContentScanReady::Passthrough => panic!("bounded body should be relayed"),
        }
    }

    #[tokio::test]
    async fn prepare_content_scan_no_match_uses_original_body() {
        let original = br#"{"message":"hello"}"#;
        let ctx = make_eval_ctx();
        let req = make_request(original);
        let (mut client, _peer) = tokio::io::duplex(1);

        let ready = prepare_content_scan(&req, &mut client, &ctx, None)
            .await
            .expect("scan should prepare");

        match ready {
            ContentScanReady::Relay {
                header_out,
                body_out,
            } => {
                let header = std::str::from_utf8(&header_out).unwrap();
                assert!(
                    header.contains(&format!("Content-Length: {}\r\n", original.len())),
                    "original content length should remain: {header:?}"
                );
                assert_eq!(body_out, original);
            }
            ContentScanReady::Passthrough => panic!("bounded body should be relayed"),
        }
    }

    #[tokio::test]
    async fn prepare_content_scan_oversized_body_passthrough() {
        let body = b"small";
        let mut req = make_request(body);
        req.body_length = BodyLength::ContentLength(DEFAULT_MAX_SCAN_BYTES + 1);
        let ctx = make_eval_ctx();
        let (mut client, _peer) = tokio::io::duplex(1);

        let ready = prepare_content_scan(&req, &mut client, &ctx, None)
            .await
            .expect("oversized body should skip scanning");

        assert!(matches!(ready, ContentScanReady::Passthrough));
    }
}
