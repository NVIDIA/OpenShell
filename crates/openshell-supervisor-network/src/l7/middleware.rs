// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor middleware application for L7 requests.

use crate::l7::relay::L7EvalContext;
use crate::opa::PolicyGenerationGuard;
use miette::{Result, miette};
use openshell_ocsf::{
    ActionId, ActivityId, DetectionFindingBuilder, DispositionId, Endpoint, FindingInfo,
    HttpActivityBuilder, HttpRequest, SeverityId, StatusId, Url as OcsfUrl, ocsf_emit,
};
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncWrite};

pub enum MiddlewareApplyResult {
    Allowed(crate::l7::provider::L7Request),
    Denied {
        denial: Option<openshell_supervisor_middleware::MiddlewareDenial>,
    },
}

/// How traffic a middleware chain can never inspect (h2c, non-HTTP TCP,
/// protocols without an L7 relay) must be handled for a matching chain.
///
/// This is derived from each entry's `on_error` today. A future per-config
/// `on_uninspectable` knob could let an operator keep `fail_closed` error
/// handling for HTTP traffic while allowing uninspectable protocols through
/// without maintaining host excludes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UninspectableTrafficGate {
    /// No middleware matches this destination; raw relay is unaffected.
    Unrestricted,
    /// Every matching entry is `fail_open`: relay raw bytes but emit a bypass
    /// detection finding.
    BypassWithFinding,
    /// At least one matching entry is `fail_closed`: deny, the middleware
    /// must be able to see the traffic for it to flow.
    Deny,
}

pub fn uninspectable_traffic_gate(
    chain: &[openshell_supervisor_middleware::ChainEntry],
) -> UninspectableTrafficGate {
    if chain.is_empty() {
        return UninspectableTrafficGate::Unrestricted;
    }
    if chain
        .iter()
        .all(|entry| entry.on_error == openshell_supervisor_middleware::OnError::FailOpen)
    {
        UninspectableTrafficGate::BypassWithFinding
    } else {
        UninspectableTrafficGate::Deny
    }
}

/// Emit the detection finding for traffic a matching middleware chain cannot
/// inspect: denied under a fail-closed chain, bypassed under fail-open.
pub fn emit_middleware_uninspectable(ctx: &L7EvalContext, detail: &str, denied: bool) {
    let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(if denied {
            SeverityId::High
        } else {
            SeverityId::Medium
        })
        .finding_info(FindingInfo::new(
            "openshell.middleware.traffic_uninspectable",
            "Supervisor middleware cannot inspect this traffic",
        ))
        .evidence_pairs(&[
            ("policy", ctx.policy_name.as_str()),
            ("host", ctx.host.as_str()),
            ("protocol", detail),
            ("disposition", if denied { "denied" } else { "fail_open" }),
        ])
        .message(if denied {
            "Uninspectable traffic to host with required middleware; denied"
        } else {
            "Uninspectable traffic bypassed middleware (fail_open)"
        })
        .build();
    ocsf_emit!(event);
}

/// Largest body-buffering limit across the entries that actually resolved to a
/// registered binding. Buffering for the most capable stage lets every stage
/// that can handle the body run; stages whose own limit is smaller are failed
/// individually with `request_body_over_capacity` through their `on_error`
/// policy in `evaluate_described`, instead of one undersized stage forcing the
/// whole chain onto the unbuffered path. Unresolved entries
/// (`is_resolved() == false`) report a zero limit and are excluded here: they
/// are handled by their `on_error` policy without inspecting the body.
/// Returns `None` when no entry resolved, so the caller can skip buffering.
pub(super) fn middleware_chain_body_limit(
    chain: &[openshell_supervisor_middleware::DescribedChainEntry],
) -> Option<usize> {
    chain
        .iter()
        .filter(|entry| entry.is_resolved())
        .map(openshell_supervisor_middleware::DescribedChainEntry::max_body_bytes)
        .max()
}

pub async fn apply_middleware_chain<C: AsyncRead + AsyncWrite + Unpin + Send>(
    req: crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    chain: Vec<openshell_supervisor_middleware::ChainEntry>,
    runner: &openshell_supervisor_middleware::ChainRunner,
    generation_guard: &PolicyGenerationGuard,
    transformed_body_policy: openshell_supervisor_middleware::TransformedBodyPolicy<'_>,
) -> Result<MiddlewareApplyResult> {
    apply_middleware_chain_for_scheme(
        req,
        client,
        ctx,
        "https",
        chain,
        runner,
        generation_guard,
        transformed_body_policy,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn apply_middleware_chain_for_scheme<C: AsyncRead + AsyncWrite + Unpin + Send>(
    req: crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    scheme: &str,
    chain: Vec<openshell_supervisor_middleware::ChainEntry>,
    runner: &openshell_supervisor_middleware::ChainRunner,
    generation_guard: &PolicyGenerationGuard,
    transformed_body_policy: openshell_supervisor_middleware::TransformedBodyPolicy<'_>,
) -> Result<MiddlewareApplyResult> {
    if chain.is_empty() {
        return Ok(MiddlewareApplyResult::Allowed(req));
    }
    let chain = runner.describe_chain(&chain).await?;
    let Some(max_body_bytes) = middleware_chain_body_limit(&chain) else {
        // No entry resolved to a registered binding, so nothing inspects the
        // body. Apply each entry's `on_error` policy without buffering (an
        // unresolved binding is handled before the body is read) and forward
        // the original request unchanged if the chain allows.
        let input = middleware_request_input(
            scheme,
            &req,
            ctx,
            Vec::new(),
            Vec::new(),
            String::new(),
            Vec::new(),
        );
        let outcome = runner.evaluate_described(&chain, input).await?;
        emit_middleware_events(ctx, &req, &outcome);
        return Ok(if outcome.allowed {
            MiddlewareApplyResult::Allowed(req)
        } else {
            MiddlewareApplyResult::Denied {
                denial: outcome.denial,
            }
        });
    };
    let buffered = match crate::l7::rest::buffer_request_body_for_middleware(
        &req,
        client,
        Some(generation_guard),
        max_body_bytes,
    )
    .await?
    {
        crate::l7::rest::BufferResult::Buffered(buffered) => buffered,
        crate::l7::rest::BufferResult::OverCapacity { recoverable } => {
            return Ok(resolve_unbuffered_body(ctx, req, &chain, recoverable));
        }
    };
    let headers = safe_middleware_headers(&buffered.headers)?;
    let query = raw_query_from_request_headers(&buffered.headers)?;
    let input = middleware_request_input(
        scheme,
        &req,
        ctx,
        headers.visible,
        headers.connection_nominated,
        query,
        buffered.body,
    );
    // The explicitly selected transformation policy either re-checks every
    // replacement or documents that this protocol's policy is body-independent.
    // An ALLOW outcome therefore means the final body is policy-compliant.
    let outcome = runner
        .evaluate_described_with_policy(&chain, input, transformed_body_policy)
        .await?;
    emit_middleware_events(ctx, &req, &outcome);
    if !outcome.allowed {
        return Ok(MiddlewareApplyResult::Denied {
            denial: outcome.denial,
        });
    }
    let rebuilt = crate::l7::rest::rebuild_request_with_buffered_body(
        &req,
        &buffered.headers,
        &outcome.body,
        &outcome.header_mutations,
    )?;
    Ok(MiddlewareApplyResult::Allowed(rebuilt))
}

pub async fn send_middleware_rejection_response<C: AsyncRead + AsyncWrite + Unpin + Send>(
    req: &crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    denial: Option<&openshell_supervisor_middleware::MiddlewareDenial>,
    redacted_target: &str,
) -> Result<()> {
    let context = Some(crate::l7::rest::DenyResponseContext {
        host: Some(&ctx.host),
        port: Some(ctx.port),
        binary: Some(&ctx.binary_path),
    });
    if let Some(denial) = denial {
        crate::l7::rest::send_middleware_deny_response(
            req,
            &ctx.policy_name,
            denial,
            client,
            Some(redacted_target),
            context,
        )
        .await
    } else {
        crate::l7::rest::send_middleware_failure_response(
            req,
            &ctx.policy_name,
            client,
            Some(redacted_target),
            context,
        )
        .await
    }
}

pub(super) fn middleware_request_input(
    scheme: &str,
    req: &crate::l7::provider::L7Request,
    ctx: &L7EvalContext,
    headers: Vec<(String, String)>,
    connection_nominated_headers: Vec<String>,
    query: String,
    body: Vec<u8>,
) -> openshell_supervisor_middleware::HttpRequestInput {
    openshell_supervisor_middleware::HttpRequestInput {
        request_id: uuid::Uuid::new_v4().to_string(),
        sandbox_id: openshell_ocsf::ctx::ctx().sandbox_id.clone(),
        scheme: scheme.into(),
        host: ctx.host.clone(),
        port: ctx.port,
        method: req.action.clone(),
        path: req.target.clone(),
        query,
        headers,
        connection_nominated_headers,
        body,
    }
}

pub(super) fn raw_query_from_request_headers(headers: &[u8]) -> Result<String> {
    let header_str =
        std::str::from_utf8(headers).map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let target = header_str
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| miette!("HTTP request line is missing a target"))?;
    Ok(target
        .split_once('?')
        .map_or_else(String::new, |(_, query)| query.to_string()))
}

/// Apply the chain's `on_error` policy when the request body exceeds every
/// stage's buffering limit. No stage can inspect such a body, so each stage
/// would individually fail with `request_body_over_capacity`; the aggregate is
/// a deny unless every attached middleware is `fail_open`, and passing the
/// body through is only safe when no bytes were consumed.
pub(super) fn resolve_unbuffered_body(
    ctx: &L7EvalContext,
    req: crate::l7::provider::L7Request,
    chain: &[openshell_supervisor_middleware::DescribedChainEntry],
    recoverable: bool,
) -> MiddlewareApplyResult {
    let all_fail_open = chain
        .iter()
        .all(|entry| entry.on_error() == openshell_supervisor_middleware::OnError::FailOpen);
    if recoverable && all_fail_open {
        emit_middleware_body_unavailable(ctx, false);
        return MiddlewareApplyResult::Allowed(req);
    }
    emit_middleware_body_unavailable(ctx, true);
    MiddlewareApplyResult::Denied { denial: None }
}

fn emit_middleware_body_unavailable(ctx: &L7EvalContext, denied: bool) {
    let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(if denied {
            SeverityId::High
        } else {
            SeverityId::Medium
        })
        .finding_info(FindingInfo::new(
            "openshell.middleware.body_unavailable",
            "Supervisor middleware could not inspect request body",
        ))
        .evidence_pairs(&[
            ("policy", ctx.policy_name.as_str()),
            ("host", ctx.host.as_str()),
            ("disposition", if denied { "denied" } else { "fail_open" }),
        ])
        .message(if denied {
            "Request body exceeded middleware inspection cap; denied"
        } else {
            "Request body exceeded middleware inspection cap; passed through (fail_open)"
        })
        .build();
    ocsf_emit!(event);
}

/// Parse the raw header block into middleware-visible headers, preserving
/// wire order and repeated names so middleware inspects every value the
/// upstream will receive. Credential-bearing and hop-by-hop headers are
/// omitted, while dynamically nominated names are retained separately for
/// mutation validation.
struct SafeMiddlewareHeaders {
    visible: Vec<(String, String)>,
    connection_nominated: Vec<String>,
}

fn safe_middleware_headers(headers: &[u8]) -> Result<SafeMiddlewareHeaders> {
    crate::l7::rest::validate_http_request_header_block(headers)?;
    let header_str =
        std::str::from_utf8(headers).map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let header_block = header_str
        .strip_suffix("\r\n\r\n")
        .expect("validated header block has terminator");
    let connection_nominated = crate::l7::rest::connection_nominated_header_names(headers)?;

    let visible = header_block
        .split("\r\n")
        .skip(1)
        .map(|line| {
            let (name, value) = line
                .split_once(':')
                .expect("validated header field contains colon");
            (name.to_ascii_lowercase(), value.trim().to_string())
        })
        .filter(|(name, _)| {
            !name.is_empty()
                && !matches!(
                    name.as_str(),
                    "authorization"
                        | "proxy-authorization"
                        | "proxy-authenticate"
                        | "cookie"
                        | "host"
                        | "content-length"
                        | "transfer-encoding"
                        | "connection"
                        | "proxy-connection"
                        | "keep-alive"
                        | "te"
                        | "trailer"
                        | "upgrade"
                )
                && !name.starts_with("x-amz-")
                && !name.starts_with("x-openshell-credential")
                && !connection_nominated.contains(name)
        })
        .collect();
    let mut connection_nominated: Vec<_> = connection_nominated.into_iter().collect();
    connection_nominated.sort();
    Ok(SafeMiddlewareHeaders {
        visible,
        connection_nominated,
    })
}

pub fn middleware_network_input(ctx: &L7EvalContext) -> crate::opa::NetworkInput {
    crate::opa::NetworkInput {
        host: ctx.host.clone(),
        port: ctx.port,
        binary_path: PathBuf::from(&ctx.binary_path),
        binary_sha256: String::new(),
        ancestors: ctx.ancestors.iter().map(PathBuf::from).collect(),
        cmdline_paths: ctx.cmdline_paths.iter().map(PathBuf::from).collect(),
    }
}

/// Build the OCSF events describing a middleware chain outcome, in emission
/// order. Separated from `emit_middleware_events` so tests can assert on the
/// events deterministically without routing through the global tracing pipeline,
/// whose callsite-interest cache is process-global and races under parallel
/// tests.
pub(super) fn middleware_events(
    ctx: &L7EvalContext,
    req: &crate::l7::provider::L7Request,
    outcome: &openshell_supervisor_middleware::ChainOutcome,
) -> Vec<openshell_ocsf::OcsfEvent> {
    let mut events = Vec::new();
    for invocation in &outcome.applied {
        let allowed = invocation.decision == openshell_core::proto::Decision::Allow;
        let mut event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Other)
            .action(if allowed {
                ActionId::Allowed
            } else {
                ActionId::Denied
            })
            .disposition(if allowed {
                DispositionId::Allowed
            } else {
                DispositionId::Blocked
            })
            .severity(if allowed {
                SeverityId::Informational
            } else {
                SeverityId::Medium
            })
            .http_request(HttpRequest::new(
                &req.action,
                OcsfUrl::new("http", &ctx.host, &req.target, ctx.port),
            ))
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .firewall_rule(&ctx.policy_name, "middleware")
            .unmapped("transformed", invocation.transformed)
            .unmapped("failed", invocation.failed)
            .message(format!(
                "MIDDLEWARE {} {} decision={:?}",
                invocation.name, invocation.implementation, invocation.decision
            ));
        if !allowed && !outcome.reason.is_empty() {
            event = event
                .status(StatusId::Failure)
                .status_detail(&outcome.reason);
        }
        let event = event.build();
        events.push(event);

        // A middleware that failed but was bypassed under `fail_open` is an
        // enforcement failure operators must be able to alert on, even though the
        // request proceeded.
        if invocation.failed && allowed {
            let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(SeverityId::Medium)
                .finding_info(FindingInfo::new(
                    "openshell.middleware.failure",
                    "Supervisor middleware failed open",
                ))
                .evidence_pairs(&[
                    ("middleware", invocation.name.as_str()),
                    ("implementation", invocation.implementation.as_str()),
                ])
                .unmapped("middleware", invocation.name.as_str())
                .unmapped("implementation", invocation.implementation.as_str())
                .message(format!(
                    "Middleware {} failed and was bypassed (fail_open)",
                    invocation.name
                ))
                .build();
            events.push(event);
        }
    }
    if !outcome.allowed && outcome.reason.starts_with("middleware_failed:") {
        let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(SeverityId::High)
            .finding_info(FindingInfo::new(
                "openshell.middleware.failure",
                "Supervisor middleware failure",
            ))
            .message("Required supervisor middleware failed closed")
            .build();
        events.push(event);
    }
    if !outcome.allowed
        && outcome
            .reason
            .starts_with("transformed_body_policy_evaluation_failed:")
    {
        let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(SeverityId::High)
            .finding_info(FindingInfo::new(
                "openshell.middleware.policy_evaluation_failure",
                "Post-middleware policy evaluation failed",
            ))
            .evidence_pairs(&[
                ("policy", ctx.policy_name.as_str()),
                ("host", ctx.host.as_str()),
            ])
            .message("Transformed request denied because policy evaluation failed")
            .build();
        events.push(event);
    }
    // Each stage and the selected chain are independently bounded by the
    // runner. Keep the derived chain-wide emission bound as defense in depth
    // for manually constructed or future outcome producers.
    for finding in outcome
        .findings
        .iter()
        .take(openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_FINDINGS)
    {
        let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(match finding.finding.severity.as_str() {
                "high" => SeverityId::High,
                "low" => SeverityId::Low,
                _ => SeverityId::Medium,
            })
            .finding_info(FindingInfo::new(
                &finding.finding.r#type,
                &finding.finding.label,
            ))
            .evidence_pairs(&[
                ("middleware", &finding.middleware),
                ("count", &finding.finding.count.to_string()),
            ])
            .unmapped("middleware", finding.middleware.as_str())
            .unmapped("count", finding.finding.count)
            .message(format!(
                "Middleware finding {} count={}",
                finding.finding.r#type, finding.finding.count
            ))
            .build();
        events.push(event);
    }
    events
}

/// Emit the OCSF events describing a middleware chain outcome through the
/// tracing pipeline.
fn emit_middleware_events(
    ctx: &L7EvalContext,
    req: &crate::l7::provider::L7Request,
    outcome: &openshell_supervisor_middleware::ChainOutcome,
) {
    for event in middleware_events(ctx, req, outcome) {
        ocsf_emit!(event);
    }
}

#[cfg(test)]
mod tests {
    use super::{safe_middleware_headers, send_middleware_rejection_response};
    use crate::l7::relay::L7EvalContext;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn direct_denial_uses_middleware_response_without_service_text() {
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "api-policy".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
        };
        let req = crate::l7::provider::L7Request {
            action: "POST".into(),
            target: "/v1/messages".into(),
            query_params: std::collections::HashMap::new(),
            raw_header: Vec::new(),
            body_length: crate::l7::provider::BodyLength::None,
        };
        let denial = openshell_supervisor_middleware::MiddlewareDenial {
            config_name: "prototype-content-guard".into(),
            reason_code: Some("content_match".into()),
        };
        let (mut client, mut server) = tokio::io::duplex(4096);

        send_middleware_rejection_response(&req, &mut server, &ctx, Some(&denial), "/v1/messages")
            .await
            .expect("send denial");
        drop(server);

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read denial");
        let response = String::from_utf8(response).expect("UTF-8 response");
        let (_, body) = response.split_once("\r\n\r\n").expect("HTTP response");
        let body: serde_json::Value = serde_json::from_str(body).expect("JSON response");
        assert_eq!(body["error"], "middleware_denied");
        assert_eq!(body["middleware"], "prototype-content-guard");
        assert_eq!(body["reason_code"], "content_match");
        assert!(body.get("rule_missing").is_none());
        assert!(body.get("next_steps").is_none());
        assert!(!body.to_string().contains("secret-value"));
    }

    #[tokio::test]
    async fn middleware_failure_uses_platform_response_without_policy_guidance() {
        let _proposals =
            openshell_core::proposals::test_helpers::ProposalsFlagGuard::set(true).await;
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "api-policy".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
        };
        let req = crate::l7::provider::L7Request {
            action: "POST".into(),
            target: "/v1/messages".into(),
            query_params: std::collections::HashMap::new(),
            raw_header: Vec::new(),
            body_length: crate::l7::provider::BodyLength::None,
        };
        let (mut client, mut server) = tokio::io::duplex(4096);

        send_middleware_rejection_response(&req, &mut server, &ctx, None, "/v1/messages")
            .await
            .expect("send failure");
        drop(server);

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read failure");
        let response = String::from_utf8(response).expect("UTF-8 response");
        let (_, body) = response.split_once("\r\n\r\n").expect("HTTP response");
        let body: serde_json::Value = serde_json::from_str(body).expect("JSON response");
        assert_eq!(body["error"], "middleware_failed");
        assert_eq!(
            body["detail"],
            "Request could not be processed by configured middleware"
        );
        assert!(body.get("rule").is_none());
        assert!(body.get("rule_missing").is_none());
        assert!(body.get("next_steps").is_none());
        assert!(body.get("agent_guidance").is_none());
    }

    #[test]
    fn middleware_headers_exclude_origin_and_proxy_credentials() {
        let headers = safe_middleware_headers(
            b"GET http://api.example.test/v1 HTTP/1.1\r\n\
              Authorization: Bearer origin-secret\r\n\
              Proxy-Authorization: Basic proxy-secret\r\n\
              X-Request-ID: request-123\r\n\r\n",
        )
        .expect("headers should parse");

        assert_eq!(
            headers.visible,
            vec![("x-request-id".to_string(), "request-123".to_string())]
        );
    }

    #[test]
    fn middleware_headers_preserve_repeated_names_in_wire_order() {
        // Repeated header names must reach middleware as separate entries in
        // wire order: keeping only one value would let a request smuggle a
        // differently-positioned duplicate past inspection while the upstream
        // still receives every original value.
        let headers = safe_middleware_headers(
            b"POST /v1 HTTP/1.1\r\n\
              X-Api-Key: first-value\r\n\
              Accept: application/json\r\n\
              X-Api-Key: second-value\r\n\r\n",
        )
        .expect("headers should parse");

        assert_eq!(
            headers.visible,
            vec![
                ("x-api-key".to_string(), "first-value".to_string()),
                ("accept".to_string(), "application/json".to_string()),
                ("x-api-key".to_string(), "second-value".to_string()),
            ]
        );
    }

    #[test]
    fn middleware_headers_omit_standard_and_connection_nominated_hop_by_hop_fields() {
        let headers = safe_middleware_headers(
            b"GET /v1 HTTP/1.1\r\n\
              X-Hop: secret-hop-value\r\n\
              Connection: keep-alive, x-hop\r\n\
              Keep-Alive: timeout=5\r\n\
              TE: trailers\r\n\
              Trailer: X-Checksum\r\n\
              Upgrade: websocket\r\n\
              X-Visible: visible-value\r\n\r\n",
        )
        .expect("headers should parse");

        assert_eq!(
            headers.visible,
            vec![("x-visible".to_string(), "visible-value".to_string())]
        );
        assert_eq!(headers.connection_nominated, vec!["keep-alive", "x-hop"]);
    }

    #[test]
    fn middleware_headers_reject_malformed_fields_instead_of_dropping_them() {
        for headers in [
            b"GET /v1 HTTP/1.1\r\nX-Test: first\r\n continued\r\n\r\n".as_slice(),
            b"GET /v1 HTTP/1.1\r\nX-Test value\r\n\r\n".as_slice(),
            b"GET /v1 HTTP/1.1\r\nX-Test : value\r\n\r\n".as_slice(),
            b"GET /v1 HTTP/1.1\r\nX@Test: value\r\n\r\n".as_slice(),
        ] {
            assert!(
                safe_middleware_headers(headers).is_err(),
                "middleware must reject malformed header fields"
            );
        }
    }
}
