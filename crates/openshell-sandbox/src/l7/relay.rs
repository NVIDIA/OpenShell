// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protocol-aware bidirectional relay with L7 inspection.
//!
//! Replaces `copy_bidirectional` for endpoints with L7 configuration.
//! Parses each request within the tunnel, evaluates it against OPA policy,
//! and either forwards or denies the request.

use crate::l7::provider::{L7Provider, RelayOutcome};
use crate::l7::{EnforcementMode, L7EndpointConfig, L7Protocol, L7RequestInfo};
use crate::opa::{PolicyGenerationGuard, TunnelPolicyEngine};
use crate::secrets::{self, SecretResolver};
use miette::{IntoDiagnostic, Result, miette};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest,
    NetworkActivityBuilder, SeverityId, StatusId, Url as OcsfUrl, ocsf_emit,
};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

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

#[derive(Debug, Clone, Copy)]
enum ParseRejectionMode {
    L7Endpoint,
    Passthrough,
}

fn parse_rejection_detail(error: &str, mode: ParseRejectionMode) -> String {
    if error.contains("encoded '/' (%2F)") {
        match mode {
            ParseRejectionMode::L7Endpoint => format!(
                "{error}; set allow_encoded_slash: true on this endpoint if the upstream requires encoded slashes"
            ),
            ParseRejectionMode::Passthrough => format!(
                "{error}; passthrough credential relay uses strict path parsing, so configure this endpoint with protocol: rest and allow_encoded_slash: true for encoded-slash APIs, or use tls: skip if HTTP parsing is not needed"
            ),
        }
    } else {
        error.to_string()
    }
}

fn emit_parse_rejection(ctx: &L7EvalContext, detail: &str, engine_type: &str) {
    let policy_name = if ctx.policy_name.is_empty() {
        "-"
    } else {
        &ctx.policy_name
    };
    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Medium)
        .status(StatusId::Failure)
        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
        .firewall_rule(policy_name, engine_type)
        .message(format!(
            "HTTP request rejected before policy evaluation for {}:{}",
            ctx.host, ctx.port
        ))
        .status_detail(detail)
        .build();
    ocsf_emit!(event);
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
    engine: TunnelPolicyEngine,
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
            if close_if_stale(engine.generation_guard(), ctx) {
                return Ok(());
            }
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

/// Handle an upgraded connection (101 Switching Protocols).
///
/// Forwards any overflow bytes from the upgrade response to the client, then
/// switches to raw bidirectional TCP copy for the upgraded protocol (WebSocket,
/// HTTP/2, etc.). L7 policy enforcement does not apply after the upgrade —
/// the initial HTTP request was already evaluated.
pub(crate) async fn handle_upgrade<C, U>(
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
    engine: &TunnelPolicyEngine,
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
        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

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
                    let detail =
                        parse_rejection_detail(&e.to_string(), ParseRejectionMode::L7Endpoint);
                    emit_parse_rejection(ctx, &detail, "l7");
                }
                return Ok(()); // Close connection on parse error
            }
        };

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

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

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

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
            // Forward request to upstream and relay response
            let outcome = crate::l7::rest::relay_http_request_with_resolver_guarded(
                &req,
                client,
                upstream,
                ctx.secret_resolver.as_deref(),
                Some(engine.generation_guard()),
            )
            .await?;
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

fn close_if_stale(guard: &PolicyGenerationGuard, ctx: &L7EvalContext) -> bool {
    if !guard.is_stale() {
        return false;
    }

    ocsf_emit!(
        NetworkActivityBuilder::new(crate::ocsf_ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .firewall_rule(&ctx.policy_name, "l7")
            .message(format!(
                "L7 tunnel closed after policy reload [host:{} port:{} captured_generation:{} current_generation:{}]",
                ctx.host,
                ctx.port,
                guard.captured_generation(),
                guard.current_generation(),
            ))
            .build()
    );
    true
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
pub fn evaluate_l7_request(
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    request: &L7RequestInfo,
) -> Result<(bool, String)> {
    if engine.is_stale() {
        return Err(miette!(
            "L7 tunnel policy generation is stale [captured_generation:{} current_generation:{}]",
            engine.captured_generation(),
            engine.current_generation(),
        ));
    }

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
        .engine()
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
    generation_guard: &PolicyGenerationGuard,
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
        if close_if_stale(generation_guard, ctx) {
            return Ok(());
        }

        // Read next request from client.
        let req = match provider.parse_request(client).await {
            Ok(Some(req)) => req,
            Ok(None) => break, // Client closed connection.
            Err(e) => {
                if is_benign_connection_error(&e) {
                    break;
                }
                let detail =
                    parse_rejection_detail(&e.to_string(), ParseRejectionMode::Passthrough);
                emit_parse_rejection(ctx, &detail, "http-parser");
                return Ok(());
            }
        };

        if close_if_stale(generation_guard, ctx) {
            return Ok(());
        }

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
        // relay_http_request_with_resolver handles both directions: it sends
        // the request upstream and reads the response back to the client.
        let outcome = crate::l7::rest::relay_http_request_with_resolver_guarded(
            &req,
            client,
            upstream,
            resolver,
            Some(generation_guard),
        )
        .await?;

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
mod tests {
    use super::*;
    use crate::opa::{NetworkInput, OpaEngine};
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_POLICY: &str = include_str!("../../data/sandbox-policy.rego");

    #[test]
    fn parse_rejection_detail_adds_l7_hint_for_encoded_slash() {
        let detail = parse_rejection_detail(
            "HTTP request-target rejected: request-target contains an encoded '/' (%2F) which is not allowed on this endpoint",
            ParseRejectionMode::L7Endpoint,
        );

        assert!(detail.contains("allow_encoded_slash: true"));
        assert!(detail.contains("upstream requires encoded slashes"));
    }

    #[test]
    fn parse_rejection_detail_adds_passthrough_hint_for_encoded_slash() {
        let detail = parse_rejection_detail(
            "HTTP request-target rejected: request-target contains an encoded '/' (%2F) which is not allowed on this endpoint",
            ParseRejectionMode::Passthrough,
        );

        assert!(detail.contains("protocol: rest"));
        assert!(detail.contains("allow_encoded_slash: true"));
        assert!(detail.contains("tls: skip"));
    }

    #[test]
    fn parse_rejection_detail_preserves_other_errors() {
        let error = "HTTP headers contain invalid UTF-8";

        assert_eq!(
            parse_rejection_detail(error, ParseRejectionMode::L7Endpoint),
            error
        );
    }

    #[tokio::test]
    async fn l7_relay_closes_keep_alive_tunnel_after_policy_generation_change() {
        let initial_data = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: POST
              path: "/write"
    binaries:
      - { path: /usr/bin/curl }
"#;
        let reloaded_data = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/write"
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, initial_data).unwrap();
        let input = NetworkInput {
            host: "api.example.test".into(),
            port: 8080,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&endpoint_config.unwrap()).unwrap();
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 8080,
            policy_name: "rest_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
        };

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"POST /write HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

        let mut first_upstream = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut first_upstream),
        )
        .await
        .expect("first request should reach upstream")
        .unwrap();
        let first_upstream = String::from_utf8_lossy(&first_upstream[..n]);
        assert!(first_upstream.starts_with("POST /write HTTP/1.1"));

        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")
            .await
            .unwrap();

        let mut first_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut first_response),
        )
        .await
        .expect("first response should reach client")
        .unwrap();
        let first_response = String::from_utf8_lossy(&first_response[..n]);
        assert!(first_response.contains("200 OK"));

        engine.reload(TEST_POLICY, reloaded_data).unwrap();
        app.write_all(
            b"POST /write HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should close stale tunnel")
            .unwrap()
            .unwrap();

        let mut second_upstream = [0u8; 128];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut second_upstream),
        )
        .await
        .expect("upstream side should close")
        .unwrap();
        assert_eq!(n, 0, "stale request must not be forwarded upstream");
    }

    #[tokio::test]
    async fn passthrough_relay_closes_keep_alive_tunnel_after_policy_generation_change() {
        let policy_data = "network_policies: {}\n";
        let engine = OpaEngine::from_strings(TEST_POLICY, policy_data).unwrap();
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 8080,
            policy_name: "rest_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
        };

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_passthrough_with_credentials(
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
                &generation_guard,
            )
            .await
        });

        app.write_all(
            b"GET /first HTTP/1.1\r\nHost: api.example.test\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

        let mut first_upstream = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut first_upstream),
        )
        .await
        .expect("first passthrough request should reach upstream")
        .unwrap();
        let first_upstream = String::from_utf8_lossy(&first_upstream[..n]);
        assert!(first_upstream.starts_with("GET /first HTTP/1.1"));

        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")
            .await
            .unwrap();

        let mut first_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut first_response),
        )
        .await
        .expect("first passthrough response should reach client")
        .unwrap();
        let first_response = String::from_utf8_lossy(&first_response[..n]);
        assert!(first_response.contains("200 OK"));

        engine.reload(TEST_POLICY, policy_data).unwrap();
        app.write_all(
            b"GET /second HTTP/1.1\r\nHost: api.example.test\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("passthrough relay should close stale tunnel")
            .unwrap()
            .unwrap();

        let mut second_upstream = [0u8; 128];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut second_upstream),
        )
        .await
        .expect("upstream side should close")
        .unwrap();
        assert_eq!(
            n, 0,
            "stale passthrough request must not be forwarded upstream"
        );
    }
}
