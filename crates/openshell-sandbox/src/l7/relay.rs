// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protocol-aware bidirectional relay with L7 inspection.
//!
//! Replaces `copy_bidirectional` for endpoints with L7 configuration.
//! Parses each request within the tunnel, evaluates it against OPA policy,
//! and either forwards or denies the request.

use crate::l7::provider::L7Provider;
use crate::l7::{EnforcementMode, L7EndpointConfig, L7Protocol, L7RequestInfo};
use crate::secrets::SecretResolver;
use miette::{IntoDiagnostic, Result, miette};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite};
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
            warn!(
                host = %ctx.host,
                port = ctx.port,
                "SQL L7 provider not yet implemented, falling back to passthrough"
            );
            tokio::io::copy_bidirectional(client, upstream)
                .await
                .into_diagnostic()?;
            Ok(())
        }
    }
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
    loop {
        // Parse one HTTP request from client
        let req = match crate::l7::rest::RestProvider.parse_request(client).await {
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
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "HTTP parse error in L7 relay"
                    );
                }
                return Ok(()); // Close connection on parse error
            }
        };

        let request_info = L7RequestInfo {
            action: req.action.clone(),
            target: req.target.clone(),
        };

        // Evaluate L7 policy via Rego
        let (allowed, reason) = evaluate_l7_request(engine, ctx, &request_info)?;

        let decision_str = match (allowed, config.enforcement) {
            (true, _) => "allow",
            (false, EnforcementMode::Audit) => "audit",
            (false, EnforcementMode::Enforce) => "deny",
        };

        // Log every L7 decision
        info!(
            dst_host = %ctx.host,
            dst_port = ctx.port,
            policy = %ctx.policy_name,
            l7_protocol = "rest",
            l7_action = %request_info.action,
            l7_target = %request_info.target,
            l7_decision = decision_str,
            l7_deny_reason = %reason,
            "L7_REQUEST",
        );

        if allowed || config.enforcement == EnforcementMode::Audit {
            // Forward request to upstream and relay response
            let reusable = crate::l7::rest::relay_http_request_with_resolver(
                &req,
                client,
                upstream,
                ctx.secret_resolver.as_deref(),
            )
            .await?;
            if !reusable {
                debug!(
                    host = %ctx.host,
                    port = ctx.port,
                    "Upstream connection not reusable, closing L7 relay"
                );
                return Ok(());
            }
        } else {
            // Enforce mode: deny with 403 and close connection
            crate::l7::rest::RestProvider
                .deny(&req, &ctx.policy_name, &reason, client)
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

/// Evaluate an L7 request against the OPA engine.
///
/// Returns `(allowed, deny_reason)`.
fn evaluate_l7_request(
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
    let provider = crate::l7::rest::RestProvider;
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

        // Log for observability.
        let has_creds = resolver.is_some();
        info!(
            host = %ctx.host,
            port = ctx.port,
            method = %req.action,
            path = %req.target,
            credentials_injected = has_creds,
            request_num = request_count,
            "HTTP_REQUEST",
        );

        // Forward request with credential rewriting and relay the response.
        // relay_http_request_with_resolver handles both directions: it sends
        // the request upstream and reads the response back to the client.
        let reusable =
            crate::l7::rest::relay_http_request_with_resolver(&req, client, upstream, resolver)
                .await?;

        if !reusable {
            break;
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
