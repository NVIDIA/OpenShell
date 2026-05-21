// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox-local policy advisor HTTP API.

use miette::{IntoDiagnostic, Result};
use openshell_core::proto::{
    L7Allow, L7DenyRule, L7Rule, NetworkBinary, NetworkEndpoint, NetworkPolicyRule, PolicyChunk,
    SandboxPolicy as ProtoSandboxPolicy,
};
use openshell_ocsf::{ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ocsf_emit};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::RwLock;

pub const POLICY_LOCAL_HOST: &str = "policy.local";

/// Filesystem path of the static agent guidance bundle inside the sandbox.
/// Single source of truth: the skill installer writes here, the L7 deny body
/// references this path in `next_steps`, and the skill's own documentation
/// renders the same path. Changing the location is a one-line update here.
pub const SKILL_PATH: &str = "/etc/openshell/skills/policy_advisor.md";

/// Routes served by the in-sandbox policy advisor API. Held in one place so
/// the L7 deny `next_steps` array, the route dispatcher, the skill content,
/// and tests all stay in sync — change the wire path here and every caller
/// follows. See `agent_next_steps()` for the consumer that surfaces these
/// to the agent on a 403.
pub const ROUTE_POLICY_CURRENT: &str = "/v1/policy/current";
pub const ROUTE_DENIALS: &str = "/v1/denials";
pub const ROUTE_PROPOSALS: &str = "/v1/proposals";
/// Per-proposal status and long-poll routes live below this prefix:
///   `GET /v1/proposals/{chunk_id}`              — immediate status
///   `GET /v1/proposals/{chunk_id}/wait?timeout` — long-poll until terminal
/// Trailing slash differentiates from the bare `POST /v1/proposals` submit.
const ROUTE_PROPOSALS_PREFIX: &str = "/v1/proposals/";

/// Long-poll bounds for `GET /v1/proposals/{id}/wait?timeout=<s>`. The agent
/// re-issues on timeout, so the cap is a hold ceiling, not a hard limit on
/// how long the agent can wait overall.
const PROPOSAL_WAIT_DEFAULT_SECS: u64 = 60;
const PROPOSAL_WAIT_MIN_SECS: u64 = 1;
const PROPOSAL_WAIT_MAX_SECS: u64 = 300;
const PROPOSAL_WAIT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
/// Minimum window the reload-readiness phase gets after a chunk
/// terminalizes, even if the caller's deadline is shorter. Without this,
/// approvals that arrive at T-50ms always return `policy_reloaded=false`
/// and force a re-issue. 500ms is well below typical supervisor poll
/// latency but enough to cover the in-memory coverage check.
const RELOAD_WAIT_MIN_FLOOR: std::time::Duration = std::time::Duration::from_millis(500);

const MAX_POLICY_LOCAL_BODY_BYTES: usize = 64 * 1024;
/// Hard ceiling on how long a single request body read can stall. Bounds a
/// slowloris-style upload from an in-sandbox process; the proxy listener only
/// accepts loopback connections, so practical impact is limited, but this is
/// cheap defense-in-depth.
const POLICY_LOCAL_BODY_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const DEFAULT_DENIALS_LIMIT: usize = 10;
const MAX_DENIALS_LIMIT: usize = 100;
/// The shorthand rolling appender keeps three files (daily rotation); read the
/// most recent two so a request just past midnight still has yesterday's
/// denials.
const DENIAL_LOG_FILES_TO_SCAN: usize = 2;
const LOG_DIR: &str = "/var/log";
/// Shorthand log filenames are `openshell.YYYY-MM-DD.log`. The trailing dot in
/// the prefix is intentional: it disambiguates from the OCSF JSONL appender's
/// `openshell-ocsf.YYYY-MM-DD.log`, which we never want to surface here (the
/// JSONL is opt-in via `ocsf_json_enabled` and not the source of truth for
/// `/v1/denials`).
const SHORTHAND_LOG_PREFIX: &str = "openshell.";
/// Defensive cap on per-line length returned to the agent so a pathological
/// log entry (very long URL path, etc.) cannot blow up the response.
const MAX_DENIAL_LINE_BYTES: usize = 4096;

#[derive(Debug)]
pub struct PolicyLocalContext {
    current_policy: Arc<RwLock<Option<ProtoSandboxPolicy>>>,
    gateway_endpoint: Option<String>,
    sandbox_name: Option<String>,
    shorthand_log_dir: PathBuf,
}

impl PolicyLocalContext {
    pub fn new(
        current_policy: Option<ProtoSandboxPolicy>,
        gateway_endpoint: Option<String>,
        sandbox_name: Option<String>,
    ) -> Self {
        Self::with_log_dir(
            current_policy,
            gateway_endpoint,
            sandbox_name,
            PathBuf::from(LOG_DIR),
        )
    }

    fn with_log_dir(
        current_policy: Option<ProtoSandboxPolicy>,
        gateway_endpoint: Option<String>,
        sandbox_name: Option<String>,
        shorthand_log_dir: PathBuf,
    ) -> Self {
        Self {
            current_policy: Arc::new(RwLock::new(current_policy)),
            gateway_endpoint,
            sandbox_name,
            shorthand_log_dir,
        }
    }

    pub async fn set_current_policy(&self, policy: ProtoSandboxPolicy) {
        *self.current_policy.write().await = Some(policy);
    }
}

pub async fn handle_forward_request<S>(
    ctx: &PolicyLocalContext,
    method: &str,
    path: &str,
    initial_request: &[u8],
    client: &mut S,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let body = read_request_body(initial_request, client).await?;
    let (status, payload) = route_request(ctx, method, path, &body).await;
    write_json_response(client, status, payload).await
}

async fn route_request(
    ctx: &PolicyLocalContext,
    method: &str,
    path: &str,
    body: &[u8],
) -> (u16, serde_json::Value) {
    let (route, query) = path.split_once('?').map_or((path, ""), |(r, q)| (r, q));
    // Gate every route on the feature flag so the agent surface is fully off
    // when the flag is off — including the diagnostic `current_policy` and
    // `denials` routes. The skill is also not installed in that mode, so a
    // disabled sandbox has no entry point into this API at all.
    if !crate::agent_proposals_enabled() {
        return (
            404,
            serde_json::json!({
                "error": "feature_disabled",
                "detail": "agent-driven policy proposals are not enabled in this sandbox; set the `agent_policy_proposals_enabled` setting to true to enable"
            }),
        );
    }
    match (method, route) {
        ("GET", ROUTE_POLICY_CURRENT) => current_policy_response(ctx).await,
        ("GET", ROUTE_DENIALS) => recent_denials_response(ctx, query).await,
        ("POST", ROUTE_PROPOSALS) => submit_proposal(ctx, body).await,
        ("GET", path) if path.starts_with(ROUTE_PROPOSALS_PREFIX) => {
            proposal_state_route(ctx, path, query).await
        }
        _ => (
            404,
            serde_json::json!({
                "error": "not_found",
                "detail": format!("policy.local route not found: {method} {route}")
            }),
        ),
    }
}

/// Parse `{chunk_id}` (status) or `{chunk_id}/wait` (long-poll) from the path
/// suffix and dispatch. Empty `chunk_id` or extra segments return 404 so a
/// malformed path cannot trigger a gateway call.
async fn proposal_state_route(
    ctx: &PolicyLocalContext,
    path: &str,
    query: &str,
) -> (u16, serde_json::Value) {
    let suffix = path
        .strip_prefix(ROUTE_PROPOSALS_PREFIX)
        .unwrap_or_default();
    let (chunk_id, wait) = match suffix.split_once('/') {
        Some((id, "wait")) => (id, true),
        Some(_) => return not_found_payload(path),
        None => (suffix, false),
    };
    if chunk_id.is_empty() {
        return not_found_payload(path);
    }
    if wait {
        proposal_wait_response(ctx, chunk_id, query).await
    } else {
        proposal_status_response(ctx, chunk_id).await
    }
}

fn not_found_payload(path: &str) -> (u16, serde_json::Value) {
    (
        404,
        serde_json::json!({
            "error": "not_found",
            "detail": format!("policy.local proposal sub-route not found: {path}")
        }),
    )
}

/// Build the `next_steps` array embedded in the L7 deny body so the agent has
/// machine-readable pointers to this API. Centralizes the shape here to keep
/// the deny body and the actual route table from drifting — adding or
/// renaming a route only requires touching the route constants above.
///
/// Returns an empty array when `agent_proposals_enabled()` is false so a
/// disabled sandbox doesn't advertise a surface that 404s. The deny body
/// caller still emits the field (with `[]`) so the wire shape is stable.
#[must_use]
pub fn agent_next_steps() -> serde_json::Value {
    if !crate::agent_proposals_enabled() {
        return serde_json::json!([]);
    }
    let host = POLICY_LOCAL_HOST;
    serde_json::json!([
        {
            "action": "read_skill",
            "path": SKILL_PATH,
        },
        {
            "action": "inspect_policy",
            "method": "GET",
            "url": format!("http://{host}{ROUTE_POLICY_CURRENT}"),
        },
        {
            "action": "inspect_recent_denials",
            "method": "GET",
            "url": format!("http://{host}{ROUTE_DENIALS}?last=5"),
        },
        {
            "action": "submit_proposal",
            "method": "POST",
            "url": format!("http://{host}{ROUTE_PROPOSALS}"),
            "body_type": "PolicyMergeOperation",
        },
    ])
}

async fn current_policy_response(ctx: &PolicyLocalContext) -> (u16, serde_json::Value) {
    let Some(policy) = ctx.current_policy.read().await.clone() else {
        return (
            404,
            serde_json::json!({
                "error": "policy_unavailable",
                "detail": "no current sandbox policy is loaded"
            }),
        );
    };

    match openshell_policy::serialize_sandbox_policy(&policy) {
        Ok(policy_yaml) => (
            200,
            serde_json::json!({
                "format": "yaml",
                "policy_yaml": policy_yaml
            }),
        ),
        Err(error) => (
            500,
            serde_json::json!({
                "error": "policy_serialize_failed",
                "detail": error.to_string()
            }),
        ),
    }
}

async fn recent_denials_response(
    ctx: &PolicyLocalContext,
    query: &str,
) -> (u16, serde_json::Value) {
    let limit = parse_last_query(query).unwrap_or(DEFAULT_DENIALS_LIMIT);
    let log_dir = ctx.shorthand_log_dir.clone();

    // Distinguish "shorthand log exists and no denials happened" from "no log
    // file yet, so we have nothing to read." Without this flag the agent sees
    // `[]` in both cases and cannot tell the difference. The shorthand log is
    // always-on (no setting gates it), so the only way `log_available=false`
    // happens in practice is if the supervisor has not flushed any events to
    // disk yet, or `/var/log` is not writable in this image.
    let log_available = matches!(
        collect_shorthand_log_files(&log_dir, 1),
        Ok(files) if !files.is_empty()
    );

    let denials = tokio::task::spawn_blocking(move || read_recent_denial_lines(&log_dir, limit))
        .await
        .unwrap_or_default();

    let mut payload = serde_json::json!({
        "denials": denials,
        "log_available": log_available,
    });
    if !log_available {
        payload["note"] = serde_json::json!(
            "no shorthand log file is present yet at /var/log/openshell.YYYY-MM-DD.log; the supervisor may not have emitted any events to disk yet"
        );
    }

    (200, payload)
}

fn parse_last_query(query: &str) -> Option<usize> {
    if query.is_empty() {
        return None;
    }
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if key == "last" {
            return value
                .parse::<usize>()
                .ok()
                .map(|n| n.clamp(1, MAX_DENIALS_LIMIT));
        }
    }
    None
}

/// Walk the shorthand log files (most-recent first) and return up to `limit`
/// raw denial lines in newest-first order. The agent receives the same
/// human-readable text that `openshell logs` displays — no parsing back into
/// structured form. Updating the shorthand format adds fields automatically;
/// no schema rev required.
///
/// Reads files synchronously and is intended to run inside `spawn_blocking`.
fn read_recent_denial_lines(log_dir: &Path, limit: usize) -> Vec<String> {
    let Ok(files) = collect_shorthand_log_files(log_dir, DENIAL_LOG_FILES_TO_SCAN) else {
        return Vec::new();
    };

    let mut lines: Vec<String> = Vec::with_capacity(limit);
    for path in files {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        // Walk lines newest-first. Within a single file, the last line written
        // is the freshest event.
        for line in contents.lines().rev() {
            if !is_ocsf_denial_line(line) {
                continue;
            }
            // Defense-in-depth: redact query strings before truncation. The
            // FORWARD deny path in `proxy.rs` populates the OCSF `message`
            // and URL with the raw request path including `?query=...`, which
            // the shorthand layer then renders verbatim. Stripping queries
            // here means the agent never sees the secret even if an upstream
            // emit site forgets to redact (TODO: harden the emit sites in
            // proxy.rs FORWARD path so the on-disk shorthand log itself is
            // clean — tracked separately). Redact first so truncation cannot
            // slice mid-secret.
            let redacted = redact_query_strings(line);
            let surfaced = truncate_at_char_boundary(&redacted, MAX_DENIAL_LINE_BYTES);
            lines.push(surfaced);
            if lines.len() >= limit {
                return lines;
            }
        }
    }
    lines
}

/// Replace any `?<query>` substring with `?[redacted]` to keep query-string
/// secrets out of the agent's view. Walks per Unicode scalar value so multi-byte
/// content is safe. A query is everything from `?` until the next whitespace or
/// `]` (the shorthand format uses `[...]` for context tags).
fn redact_query_strings(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '?' {
            out.push('?');
            out.push_str("[redacted]");
            // Consume until whitespace or `]` (preserved as the next token's
            // boundary by writing it back out).
            for next in chars.by_ref() {
                if next.is_whitespace() || next == ']' {
                    out.push(next);
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Truncate `s` at the largest UTF-8 char boundary <= `max_bytes`, appending a
/// `...[truncated]` suffix. Returning a `String` (not `&str`) avoids surprising
/// callers about lifetime relationships with `s`.
fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + "...[truncated]".len());
    out.push_str(&s[..end]);
    out.push_str("...[truncated]");
    out
}

/// True for OCSF denial events as rendered by the shorthand layer. The format
/// is `<ISO ts> OCSF <CLASS:ACTIVITY> <[SEV]> <ACTION> ...`. The literal
/// ` OCSF ` substring identifies an OCSF event (vs. a non-OCSF tracing line);
/// ` DENIED ` is the OCSF action label uppercased and surrounded by spaces, so
/// matching it is safe against substring collisions in URLs or hostnames.
fn is_ocsf_denial_line(line: &str) -> bool {
    line.contains(" OCSF ") && line.contains(" DENIED ")
}

fn collect_shorthand_log_files(log_dir: &Path, max_files: usize) -> std::io::Result<Vec<PathBuf>> {
    let mut entries: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(log_dir)?
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // `openshell.YYYY-MM-DD.log` only — the trailing dot in the prefix
            // disambiguates from `openshell-ocsf.YYYY-MM-DD.log`.
            if !name.starts_with(SHORTHAND_LOG_PREFIX) || !name.ends_with(".log") {
                return None;
            }
            let modified = entry.metadata().and_then(|m| m.modified()).ok()?;
            Some((modified, path))
        })
        .collect();

    entries.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    Ok(entries
        .into_iter()
        .take(max_files)
        .map(|(_, p)| p)
        .collect())
}

async fn submit_proposal(ctx: &PolicyLocalContext, body: &[u8]) -> (u16, serde_json::Value) {
    let Some(endpoint) = ctx.gateway_endpoint.as_deref() else {
        return (
            503,
            serde_json::json!({
                "error": "gateway_unavailable",
                "detail": "policy proposal submission requires a gateway-connected sandbox"
            }),
        );
    };
    let Some(sandbox_name) = ctx
        .sandbox_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
    else {
        return (
            503,
            serde_json::json!({
                "error": "sandbox_name_unavailable",
                "detail": "policy proposal submission requires a sandbox name"
            }),
        );
    };

    let chunks = match proposal_chunks_from_body(body) {
        Ok(chunks) => chunks,
        Err(error) => return (400, error_payload("invalid_proposal", error)),
    };

    let client = match crate::grpc_client::CachedOpenShellClient::connect(endpoint).await {
        Ok(client) => client,
        Err(error) => {
            return (
                502,
                serde_json::json!({
                    "error": "gateway_connect_failed",
                    "detail": error.to_string()
                }),
            );
        }
    };

    // Pre-compute the audit summaries before handing `chunks` to the
    // gateway client (which consumes the vec). The summaries pair up with
    // the gateway's `accepted_chunk_ids` by index for the propose events
    // emitted after submit returns.
    let audit_summaries: Vec<String> = chunks.iter().map(summarize_chunk_for_audit).collect();

    let response = match client
        .submit_policy_analysis(sandbox_name, vec![], chunks, "agent_authored")
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return (
                502,
                serde_json::json!({
                    "error": "proposal_submit_failed",
                    "detail": error.to_string()
                }),
            );
        }
    };

    // One OCSF event per accepted chunk so the audit trace in
    // `openshell logs <sandbox>` carries the propose beat alongside the
    // proxy deny and policy reload that bracket it.
    //
    // The gateway compresses its `accepted_chunk_ids` by skipping rejected
    // chunks (`grpc/policy.rs:1357-1436`); the proto does not promise 1:1
    // ordering against the request. Today client-side validation catches
    // both rejection causes (missing rule_name, missing proposed_rule)
    // before submit, so the lengths match in practice. If they don't, we
    // can't safely pair audit_summaries by index — fall back to a generic
    // event per accepted chunk_id rather than mis-attribute a summary.
    let pairing_is_safe = response.accepted_chunk_ids.len() == audit_summaries.len();
    for (idx, chunk_id) in response.accepted_chunk_ids.iter().enumerate() {
        let summary = if pairing_is_safe {
            audit_summaries[idx].as_str()
        } else {
            "(summary unavailable: gateway partially accepted)"
        };
        emit_policy_propose_event(chunk_id, summary);
    }

    (
        202,
        serde_json::json!({
            "status": "submitted",
            "accepted_chunks": response.accepted_chunks,
            "rejected_chunks": response.rejected_chunks,
            "rejection_reasons": response.rejection_reasons,
            "accepted_chunk_ids": response.accepted_chunk_ids,
        }),
    )
}

/// Emit one CONFIG:PROPOSED audit event for an agent-authored proposal that
/// the gateway just accepted. The message names the `chunk_id`, the binary,
/// and the endpoint the agent is asking to reach — what a developer needs
/// to see in the audit trace to correlate against the inbox card.
fn emit_policy_propose_event(chunk_id: &str, summary: &str) {
    ocsf_emit!(
        ConfigStateChangeBuilder::new(crate::ocsf_ctx())
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .state(StateId::Other, "PROPOSED")
            .unmapped("chunk_id", serde_json::json!(chunk_id))
            .message(format!(
                "agent_authored proposal chunk:{chunk_id} {summary}"
            ))
            .build()
    );
}

/// Emit one CONFIG:APPROVED or CONFIG:REJECTED audit event observed by the
/// `/wait` poll loop. The reviewer's free-form `rejection_reason` (if any)
/// is included verbatim so the audit trace shows what guidance the agent
/// received.
fn emit_policy_decision_event(chunk: &PolicyChunk) {
    let summary = summarize_chunk_for_audit(chunk);
    match chunk.status.as_str() {
        "approved" => ocsf_emit!(
            ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Enabled, "APPROVED")
                .unmapped("chunk_id", serde_json::json!(chunk.id))
                .message(format!("chunk:{} approved {summary}", chunk.id))
                .build()
        ),
        "rejected" => {
            // The reviewer's free-form rejection_reason is opaque user
            // input. The agent reads the raw text via `GET /v1/proposals/
            // {id}` to redraft; the OCSF surface (which can be shipped to
            // external SIEMs per AGENTS.md) gets a sanitized copy — caps
            // length and strips control characters so a stray credential
            // or escape sequence cannot leak into the audit log.
            let sanitized = sanitize_reason_for_audit(&chunk.rejection_reason);
            let reason_display = if sanitized.is_empty() {
                "(no guidance)".to_string()
            } else {
                format!("\"{sanitized}\"")
            };
            ocsf_emit!(
                ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                    .severity(SeverityId::Low)
                    .status(StatusId::Success)
                    .state(StateId::Disabled, "REJECTED")
                    .unmapped("chunk_id", serde_json::json!(chunk.id))
                    .unmapped("rejection_reason", serde_json::json!(sanitized))
                    .message(format!(
                        "chunk:{} rejected {summary} reason:{reason_display}",
                        chunk.id
                    ))
                    .build()
            );
        }
        // Caller is gated on `is_terminal_status`, so a non-terminal status
        // here is a code change that broke the invariant. Warn loudly so
        // the audit gap doesn't go silent.
        other => tracing::warn!(
            chunk_id = %chunk.id,
            status = %other,
            "emit_policy_decision_event called on non-terminal status; no audit event emitted"
        ),
    }
}

/// Sanitize a free-form reviewer-typed string before it lands in the OCSF
/// audit surface. The agent still reads the raw text via the API — this is
/// audit-side defense only.
fn sanitize_reason_for_audit(raw: &str) -> String {
    const MAX_CHARS: usize = 200;
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(MAX_CHARS)
        .collect();
    if raw.chars().count() > MAX_CHARS {
        format!("{cleaned}…")
    } else {
        cleaned
    }
}

/// One-line audit description of a chunk's target: binary, host, port, and
/// L7 method/path if present. Used by both the propose and approve/reject
/// audit events so the trace can be grepped by endpoint without parsing
/// JSON.
fn summarize_chunk_for_audit(chunk: &PolicyChunk) -> String {
    let Some(rule) = chunk.proposed_rule.as_ref() else {
        return format!("rule_name:{}", chunk.rule_name);
    };
    let endpoint = rule.endpoints.first().map_or_else(
        || "unknown".to_string(),
        |ep| format!("{}:{}", ep.host, ep.port),
    );
    let l7 = rule
        .endpoints
        .first()
        .and_then(|ep| ep.rules.first())
        .and_then(|r| r.allow.as_ref())
        .map(|a| format!(" {} {}", a.method, a.path))
        .unwrap_or_default();
    let binary = if chunk.binary.is_empty() {
        String::new()
    } else {
        format!(" by {}", chunk.binary)
    };
    format!("on {endpoint}{l7}{binary}")
}

/// `GET /v1/proposals/{chunk_id}` — immediate state. One gateway call, no loop.
async fn proposal_status_response(
    ctx: &PolicyLocalContext,
    chunk_id: &str,
) -> (u16, serde_json::Value) {
    let session = match open_lookup_session(ctx).await {
        Ok(session) => session,
        Err(err) => return err,
    };
    fetch_chunk_or_404(&session, chunk_id, false).await
}

/// `GET /v1/proposals/{chunk_id}/wait?timeout=<s>` — block until terminal or
/// timeout. Returns the chunk's current state on a status transition; on
/// timeout, returns the still-pending state with `timed_out: true` so the
/// agent can re-issue without ambiguity. The agent's wait costs zero LLM
/// tokens — the tool call sits in a socket recv until we return.
async fn proposal_wait_response(
    ctx: &PolicyLocalContext,
    chunk_id: &str,
    query: &str,
) -> (u16, serde_json::Value) {
    let session = match open_lookup_session(ctx).await {
        Ok(session) => session,
        Err(err) => return err,
    };
    let timeout_secs = parse_timeout_query(query);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        match fetch_chunk(&session, chunk_id).await {
            Ok(Some(chunk)) if is_terminal_status(&chunk.status) => {
                // Audit beat: emit at the moment this sandbox observes the
                // decision so the trace correlates with the proxy events
                // bracketing the loop. Multiple waiters on the same chunk
                // each fire one event — acceptable for a wakeup audit.
                emit_policy_decision_event(&chunk);
                let policy_reloaded = if chunk.status == "approved" {
                    // Hold the wait until the local supervisor has loaded a
                    // policy that semantically contains this chunk's
                    // proposed rule. Reloads triggered by *other* chunks or
                    // settings changes do not wake us; a missing
                    // proposed_rule (defensive) skips the check and
                    // returns reloaded=false so the agent can decide.
                    //
                    // Floor the reload-wait window to RELOAD_WAIT_MIN_FLOOR
                    // so an approval that arrives at T-50ms still gets a
                    // realistic shot at seeing the reload. Worst case we
                    // overshoot the caller's deadline by this floor —
                    // preferable to returning reloaded=false on every
                    // short-budget call and forcing the agent to re-issue.
                    let reload_deadline = std::cmp::max(
                        deadline,
                        tokio::time::Instant::now() + RELOAD_WAIT_MIN_FLOOR,
                    );
                    match chunk.proposed_rule.as_ref() {
                        Some(rule) => {
                            wait_for_local_policy_to_cover(ctx, rule, reload_deadline).await
                        }
                        None => false,
                    }
                } else {
                    // Rejected: no reload semantics — the agent reads
                    // rejection_reason and redrafts.
                    false
                };
                return (200, chunk_state_payload(&chunk, false, policy_reloaded));
            }
            Ok(Some(chunk)) => {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return (200, chunk_state_payload(&chunk, true, false));
                }
                let sleep_for = std::cmp::min(remaining, PROPOSAL_WAIT_POLL_INTERVAL);
                tokio::time::sleep(sleep_for).await;
            }
            Ok(None) => return chunk_not_found_payload(chunk_id),
            Err(err) => return err,
        }
    }
}

fn chunk_not_found_payload(chunk_id: &str) -> (u16, serde_json::Value) {
    (
        404,
        error_payload(
            "chunk_not_found",
            format!("chunk '{chunk_id}' is not present in this sandbox's draft policy"),
        ),
    )
}

async fn fetch_chunk_or_404(
    session: &LookupSession<'_>,
    chunk_id: &str,
    timed_out: bool,
) -> (u16, serde_json::Value) {
    match fetch_chunk(session, chunk_id).await {
        Ok(Some(chunk)) => (200, chunk_state_payload(&chunk, timed_out, false)),
        Ok(None) => chunk_not_found_payload(chunk_id),
        Err(err) => err,
    }
}

/// Build the agent-facing response for a chunk.
///
/// Selection rule: include the fields the agent needs to decide what to do
/// next on the redraft loop — identity (`chunk_id`, `status`), the proposal
/// it submitted (`rule_name`, `binary`), the two feedback signals
/// (`rejection_reason` from the reviewer, `validation_result` from the
/// gateway prover), and (on /wait) `policy_reloaded` so the agent can tell
/// "approved AND the new rule is loaded — safe to retry" from "approved
/// but the supervisor hasn't reloaded yet — re-issue /wait or surface to
/// user". Display-only proto fields (`hit_count`, `confidence`, `stage`,
/// timing) are left off until a concrete agent need surfaces them.
fn chunk_state_payload(
    chunk: &PolicyChunk,
    timed_out: bool,
    policy_reloaded: bool,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "chunk_id": chunk.id,
        "status": chunk.status,
        "rule_name": chunk.rule_name,
        "binary": chunk.binary,
        "rejection_reason": chunk.rejection_reason,
        "validation_result": chunk.validation_result,
    });
    if timed_out {
        payload["timed_out"] = serde_json::json!(true);
    }
    if chunk.status == "approved" {
        payload["policy_reloaded"] = serde_json::json!(policy_reloaded);
    }
    payload
}

fn is_terminal_status(status: &str) -> bool {
    matches!(status, "approved" | "rejected")
}

/// After a chunk is approved upstream, wait until the local supervisor has
/// loaded a policy that semantically contains the chunk's proposed rule.
/// Returns `true` if coverage was observed before the deadline, `false`
/// otherwise — the caller reports that bool back to the agent as
/// `policy_reloaded` so it can decide whether to retry immediately or
/// re-issue `/wait`.
///
/// Why rule-coverage instead of whole-policy diff (as we used to do):
///
/// 1. **False sleep.** If the agent re-issues `/wait` after a `timed_out`
///    response, the chunk may have approved AND the supervisor may have
///    reloaded between the two `/wait` calls. A diff-based check snapshots
///    the already-updated policy as baseline and then waits forever for
///    another change. The skill tells the agent to re-issue on
///    `timed_out`, so the diff approach is broken on the happy path.
/// 2. **False wakeup.** Any unrelated reload (another agent's approval,
///    settings change) flips a whole-policy diff, but the chunk's actual
///    rule may not be loaded yet. The agent retries, hits another
///    `policy_denied`, and the revise-loop fires with no real signal to
///    revise on.
///
/// The polling cadence here is faster than `PROPOSAL_WAIT_POLL_INTERVAL`
/// (which paces upstream gateway calls). This loop only reads in-memory
/// state, so 200ms gives a responsive handoff to the agent's retry once
/// the supervisor's own policy poll catches up.
async fn wait_for_local_policy_to_cover(
    ctx: &PolicyLocalContext,
    proposed_rule: &NetworkPolicyRule,
    deadline: tokio::time::Instant,
) -> bool {
    const TICK: std::time::Duration = std::time::Duration::from_millis(200);
    loop {
        // Clone the snapshot out of the RwLock before running coverage —
        // otherwise the read guard is held across `policy_covers_rule`'s
        // iteration of `network_policies`, serializing a writer (supervisor
        // reload) on the very thing we're waiting for. Clone-per-tick on
        // a few-KB struct is cheap for the bounded wait window here.
        let snapshot = ctx.current_policy.read().await.clone();
        if let Some(policy) = snapshot.as_ref()
            && openshell_policy::policy_covers_rule(policy, proposed_rule)
        {
            return true;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        tokio::time::sleep(std::cmp::min(remaining, TICK)).await;
    }
}

/// Parse `?timeout=<s>` from the query string. Default applies for missing
/// or unparseable values; bounds clamp to keep the agent's hold ceiling
/// sane. Re-issue is the right pattern for longer waits.
fn parse_timeout_query(query: &str) -> u64 {
    let raw = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == "timeout")
        .map_or("", |(_, v)| v);
    raw.parse::<u64>()
        .unwrap_or(PROPOSAL_WAIT_DEFAULT_SECS)
        .clamp(PROPOSAL_WAIT_MIN_SECS, PROPOSAL_WAIT_MAX_SECS)
}

/// One connected gateway client + the validated sandbox name. Built once
/// per request and reused for every `fetch_chunk` call in a wait loop so a
/// 60-second wait does one TLS handshake, not sixty.
struct LookupSession<'a> {
    client: crate::grpc_client::CachedOpenShellClient,
    sandbox_name: &'a str,
}

/// Validate ctx and open one gateway channel. Failures map to the canonical
/// error payload shape used by both `/proposals/{id}` and `/wait`.
async fn open_lookup_session(
    ctx: &PolicyLocalContext,
) -> std::result::Result<LookupSession<'_>, (u16, serde_json::Value)> {
    let endpoint = ctx.gateway_endpoint.as_deref().ok_or_else(|| {
        (
            503,
            error_payload(
                "gateway_unavailable",
                "proposal state lookup requires a gateway-connected sandbox".to_string(),
            ),
        )
    })?;
    let sandbox_name = ctx
        .sandbox_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            (
                503,
                error_payload(
                    "sandbox_name_unavailable",
                    "proposal state lookup requires a sandbox name".to_string(),
                ),
            )
        })?;
    let client = crate::grpc_client::CachedOpenShellClient::connect(endpoint)
        .await
        .map_err(|e| (502, error_payload("gateway_connect_failed", e.to_string())))?;
    Ok(LookupSession {
        client,
        sandbox_name,
    })
}

/// One gateway call: list the sandbox's draft chunks and find the matching
/// id. Returns `Ok(None)` only when the gateway responded successfully but
/// no chunk in this sandbox matches.
async fn fetch_chunk(
    session: &LookupSession<'_>,
    chunk_id: &str,
) -> std::result::Result<Option<PolicyChunk>, (u16, serde_json::Value)> {
    let chunks = session
        .client
        .get_draft_policy(session.sandbox_name, "")
        .await
        .map_err(|e| (502, error_payload("gateway_lookup_failed", e.to_string())))?;
    Ok(chunks.into_iter().find(|c| c.id == chunk_id))
}

fn proposal_chunks_from_body(body: &[u8]) -> std::result::Result<Vec<PolicyChunk>, String> {
    let request: ProposalRequest = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    if request.operations.is_empty() {
        return Err("proposal requires at least one operation".to_string());
    }

    let mut chunks = Vec::new();
    for operation in request.operations {
        let Some(add_rule) = operation.get("addRule").cloned() else {
            return Err(
                "this MVP accepts `addRule` operations; submit a full narrow NetworkPolicyRule"
                    .to_string(),
            );
        };
        let add_rule: AddNetworkRuleJson =
            serde_json::from_value(add_rule).map_err(|e| e.to_string())?;
        chunks.push(policy_chunk_from_add_rule(
            add_rule,
            request.intent_summary.as_deref().unwrap_or_default(),
        )?);
    }

    Ok(chunks)
}

fn policy_chunk_from_add_rule(
    add_rule: AddNetworkRuleJson,
    intent_summary: &str,
) -> std::result::Result<PolicyChunk, String> {
    let mut rule = network_rule_from_json(add_rule.rule)?;
    let rule_name = add_rule
        .rule_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map_or_else(|| rule.name.clone(), ToString::to_string);
    if rule_name.trim().is_empty() {
        return Err("addRule.ruleName or rule.name is required".to_string());
    }
    if rule.name.trim().is_empty() {
        rule.name.clone_from(&rule_name);
    }

    let binary = rule
        .binaries
        .first()
        .map(|binary| binary.path.clone())
        .unwrap_or_default();

    Ok(PolicyChunk {
        id: String::new(),
        status: "pending".to_string(),
        rule_name,
        proposed_rule: Some(rule),
        rationale: intent_summary.to_string(),
        security_notes: String::new(),
        confidence: 0.75,
        denial_summary_ids: vec![],
        created_at_ms: 0,
        decided_at_ms: 0,
        stage: "agent".to_string(),
        supersedes_chunk_id: String::new(),
        hit_count: 1,
        first_seen_ms: 0,
        last_seen_ms: 0,
        binary,
        validation_result: String::new(),
        rejection_reason: String::new(),
    })
}

fn network_rule_from_json(
    rule: NetworkPolicyRuleJson,
) -> std::result::Result<NetworkPolicyRule, String> {
    if rule.endpoints.is_empty() {
        return Err("rule.endpoints must contain at least one endpoint".to_string());
    }

    let endpoints = rule
        .endpoints
        .into_iter()
        .map(network_endpoint_from_json)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let binaries = rule
        .binaries
        .into_iter()
        .map(|binary| NetworkBinary {
            path: binary.path,
            ..Default::default()
        })
        .collect();

    Ok(NetworkPolicyRule {
        name: rule.name.unwrap_or_default(),
        endpoints,
        binaries,
    })
}

fn network_endpoint_from_json(
    endpoint: NetworkEndpointJson,
) -> std::result::Result<NetworkEndpoint, String> {
    if endpoint.host.trim().is_empty() {
        return Err("endpoint.host is required".to_string());
    }

    let mut ports = endpoint.ports;
    if ports.is_empty() && endpoint.port > 0 {
        ports.push(endpoint.port);
    }
    if ports.is_empty() {
        return Err("endpoint.port or endpoint.ports is required".to_string());
    }
    if endpoint
        .rules
        .iter()
        .any(|rule| rule.allow.path.contains('?'))
    {
        return Err("L7 allow paths must not include query strings".to_string());
    }

    let port = ports.first().copied().unwrap_or_default();
    let rules = endpoint
        .rules
        .into_iter()
        .map(|rule| L7Rule {
            allow: Some(L7Allow {
                method: rule.allow.method,
                path: rule.allow.path,
                command: rule.allow.command,
                query: HashMap::new(),
                // GraphQL fields default empty — agent-authored proposals from
                // policy.local target REST/SQL/L4 endpoints; GraphQL operation
                // matching is set on the policy server side or via direct YAML.
                operation_type: String::new(),
                operation_name: String::new(),
                fields: Vec::new(),
            }),
        })
        .collect();
    let deny_rules = endpoint
        .deny_rules
        .into_iter()
        .map(|rule| L7DenyRule {
            method: rule.method,
            path: rule.path,
            command: rule.command,
            query: HashMap::new(),
            operation_type: String::new(),
            operation_name: String::new(),
            fields: Vec::new(),
        })
        .collect();

    Ok(NetworkEndpoint {
        host: endpoint.host,
        port,
        protocol: endpoint.protocol,
        tls: endpoint.tls,
        enforcement: endpoint.enforcement,
        access: endpoint.access,
        rules,
        allowed_ips: endpoint.allowed_ips,
        ports,
        deny_rules,
        allow_encoded_slash: endpoint.allow_encoded_slash,
        websocket_credential_rewrite: false,
        request_body_credential_rewrite: false,
        // GraphQL persisted-query knobs and path scoping default empty —
        // agent proposals don't author them today.
        persisted_queries: String::new(),
        graphql_persisted_queries: HashMap::new(),
        graphql_max_body_bytes: 0,
        path: String::new(),
    })
}

async fn read_request_body<S>(initial_request: &[u8], client: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let Some(header_end) = find_header_end(initial_request) else {
        return Ok(Vec::new());
    };
    let content_length = parse_content_length(&initial_request[..header_end])?;
    if content_length > MAX_POLICY_LOCAL_BODY_BYTES {
        return Err(miette::miette!(
            "policy.local request body exceeds {MAX_POLICY_LOCAL_BODY_BYTES} bytes"
        ));
    }

    let mut body = initial_request[header_end..].to_vec();
    if body.len() > content_length {
        body.truncate(content_length);
    }
    let read_loop = async {
        while body.len() < content_length {
            let remaining = content_length - body.len();
            let mut chunk = vec![0u8; remaining.min(8192)];
            let n = client.read(&mut chunk).await.into_diagnostic()?;
            if n == 0 {
                return Err(miette::miette!("policy.local request body ended early"));
            }
            body.extend_from_slice(&chunk[..n]);
        }
        Ok::<(), miette::Report>(())
    };
    tokio::time::timeout(POLICY_LOCAL_BODY_READ_TIMEOUT, read_loop)
        .await
        .map_err(|_| miette::miette!("policy.local request body read timed out"))??;

    Ok(body)
}

fn parse_content_length(headers: &[u8]) -> Result<usize> {
    let headers = String::from_utf8_lossy(headers);
    for line in headers.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            return value
                .trim()
                .parse::<usize>()
                .into_diagnostic()
                .map_err(|_| miette::miette!("invalid policy.local Content-Length"));
        }
    }
    Ok(0)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

async fn write_json_response<S>(
    client: &mut S,
    status: u16,
    payload: serde_json::Value,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let body = payload.to_string();
    let response = format!(
        "HTTP/1.1 {status} {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        status_text(status),
        body.len(),
        body
    );
    client
        .write_all(response.as_bytes())
        .await
        .into_diagnostic()?;
    client.flush().await.into_diagnostic()?;
    Ok(())
}

fn status_text(status: u16) -> &'static str {
    match status {
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

fn error_payload(error: &str, detail: String) -> serde_json::Value {
    serde_json::json!({
        "error": error,
        "detail": detail
    })
}

#[derive(Debug, Deserialize)]
struct ProposalRequest {
    #[serde(default)]
    intent_summary: Option<String>,
    #[serde(default)]
    operations: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct AddNetworkRuleJson {
    #[serde(default, rename = "ruleName")]
    rule_name: Option<String>,
    rule: NetworkPolicyRuleJson,
}

#[derive(Debug, Deserialize)]
struct NetworkPolicyRuleJson {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    endpoints: Vec<NetworkEndpointJson>,
    #[serde(default)]
    binaries: Vec<NetworkBinaryJson>,
}

#[derive(Debug, Deserialize)]
struct NetworkEndpointJson {
    host: String,
    #[serde(default)]
    port: u32,
    #[serde(default)]
    ports: Vec<u32>,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    tls: String,
    #[serde(default)]
    enforcement: String,
    #[serde(default)]
    access: String,
    #[serde(default)]
    rules: Vec<L7RuleJson>,
    #[serde(default)]
    allowed_ips: Vec<String>,
    #[serde(default)]
    deny_rules: Vec<L7DenyRuleJson>,
    #[serde(default)]
    allow_encoded_slash: bool,
}

#[derive(Debug, Deserialize)]
struct NetworkBinaryJson {
    path: String,
}

#[derive(Debug, Deserialize)]
struct L7RuleJson {
    allow: L7AllowJson,
}

#[derive(Debug, Deserialize)]
struct L7AllowJson {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    command: String,
}

#[derive(Debug, Deserialize)]
struct L7DenyRuleJson {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    command: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_chunks_from_body_accepts_add_rule_operation() {
        let body = br#"{
            "intent_summary": "Allow gh to create one repo.",
            "operations": [
                {
                    "addRule": {
                        "ruleName": "github_api_repo_create",
                        "rule": {
                            "endpoints": [
                                {
                                    "host": "api.github.com",
                                    "port": 443,
                                    "protocol": "rest",
                                    "tls": "terminate",
                                    "enforcement": "enforce",
                                    "rules": [
                                        {
                                            "allow": {
                                                "method": "POST",
                                                "path": "/user/repos"
                                            }
                                        }
                                    ]
                                }
                            ],
                            "binaries": [
                                {
                                    "path": "/usr/bin/gh"
                                }
                            ]
                        }
                    }
                }
            ]
        }"#;

        let chunks = proposal_chunks_from_body(body).unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].rule_name, "github_api_repo_create");
        assert_eq!(chunks[0].rationale, "Allow gh to create one repo.");
        assert_eq!(chunks[0].binary, "/usr/bin/gh");
        let rule = chunks[0].proposed_rule.as_ref().unwrap();
        assert_eq!(rule.name, "github_api_repo_create");
        assert_eq!(rule.endpoints[0].host, "api.github.com");
        assert_eq!(rule.endpoints[0].port, 443);
        assert_eq!(rule.endpoints[0].ports, vec![443]);
        assert_eq!(rule.endpoints[0].protocol, "rest");
        assert_eq!(
            rule.endpoints[0].rules[0].allow.as_ref().unwrap().path,
            "/user/repos"
        );
    }

    #[test]
    fn proposal_chunks_from_body_rejects_query_in_l7_path() {
        let body = br#"{
            "operations": [
                {
                    "addRule": {
                        "ruleName": "bad",
                        "rule": {
                            "endpoints": [
                                {
                                    "host": "api.github.com",
                                    "port": 443,
                                    "rules": [
                                        {
                                            "allow": {
                                                "method": "GET",
                                                "path": "/repos?token=secret"
                                            }
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                }
            ]
        }"#;

        let error = proposal_chunks_from_body(body).unwrap_err();
        assert!(error.contains("query strings"));
        assert!(!error.contains("secret"));
    }

    #[test]
    fn parse_last_query_clamps_to_max() {
        assert_eq!(parse_last_query("last=5"), Some(5));
        assert_eq!(parse_last_query("foo=bar&last=20"), Some(20));
        assert_eq!(parse_last_query("last=999"), Some(MAX_DENIALS_LIMIT));
        assert_eq!(parse_last_query("last=0"), Some(1));
        assert_eq!(parse_last_query(""), None);
        assert_eq!(parse_last_query("other=1"), None);
    }

    #[test]
    fn is_ocsf_denial_line_filters_correctly() {
        // OCSF denial — match.
        assert!(is_ocsf_denial_line(
            "2026-05-06T17:02:00.000Z OCSF HTTP:PUT [MED] DENIED PUT http://api.github.com:443/x [policy:p engine:l7]"
        ));
        assert!(is_ocsf_denial_line(
            "2026-05-06T17:02:00.000Z OCSF NET:OPEN [MED] DENIED curl(42) -> blocked.com:443 [policy:- engine:opa]"
        ));

        // OCSF allowed — must not match.
        assert!(!is_ocsf_denial_line(
            "2026-05-06T17:02:00.000Z OCSF NET:OPEN [INFO] ALLOWED curl(42) -> api.example.com:443"
        ));

        // Non-OCSF tracing line — must not match even if it contains the word DENIED.
        assert!(!is_ocsf_denial_line(
            "2026-05-06T17:02:00.000Z INFO some::module: request DENIED in upstream"
        ));

        // Empty line — must not match.
        assert!(!is_ocsf_denial_line(""));
    }

    #[tokio::test]
    async fn recent_denials_returns_newest_first_from_shorthand_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("openshell.2026-05-06.log");
        // Mixed file: allowed events, non-OCSF info lines, two denials.
        // Lines are written in chronological order; reader walks newest-first.
        let body = "\
2026-05-06T17:02:00.000Z OCSF NET:OPEN [INFO] ALLOWED curl(10) -> api.example.com:443 [policy:default engine:opa]
2026-05-06T17:02:01.000Z INFO some::module: routine status check
2026-05-06T17:02:02.000Z OCSF HTTP:GET [MED] DENIED GET http://blocked.example/v1/data [policy:default-deny engine:l7]
2026-05-06T17:02:03.000Z OCSF NET:OPEN [INFO] ALLOWED curl(11) -> api.example.com:443
2026-05-06T17:02:04.000Z OCSF HTTP:PUT [MED] DENIED PUT http://api.github.com:443/repos/x/y/contents/z [policy:gh_readonly engine:l7]
";
        std::fs::write(&log_path, body).unwrap();

        let ctx = PolicyLocalContext::with_log_dir(None, None, None, dir.path().to_path_buf());
        let (status, payload) = recent_denials_response(&ctx, "last=10").await;
        assert_eq!(status, 200);
        assert_eq!(payload["log_available"], true);
        let denials = payload["denials"].as_array().unwrap();
        assert_eq!(denials.len(), 2);
        // Newest first.
        assert!(denials[0].as_str().unwrap().contains("HTTP:PUT"));
        assert!(
            denials[0]
                .as_str()
                .unwrap()
                .contains("/repos/x/y/contents/z")
        );
        assert!(denials[1].as_str().unwrap().contains("HTTP:GET"));
        assert!(denials[1].as_str().unwrap().contains("blocked.example"));
    }

    #[tokio::test]
    async fn recent_denials_skips_jsonl_log_files() {
        // The shorthand reader must not surface `openshell-ocsf.*.log` content
        // even if a deny-looking line is present, so the response stays
        // independent of the JSONL appender's enabled state.
        let dir = tempfile::tempdir().unwrap();
        let jsonl = dir.path().join("openshell-ocsf.2026-05-06.log");
        std::fs::write(
            &jsonl,
            r#"{"class_uid":4002,"action_id":2,"message":"DENIED","time":1}"#,
        )
        .unwrap();

        let ctx = PolicyLocalContext::with_log_dir(None, None, None, dir.path().to_path_buf());
        let (status, payload) = recent_denials_response(&ctx, "").await;
        assert_eq!(status, 200);
        assert_eq!(payload["log_available"], false);
        assert_eq!(payload["denials"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn recent_denials_signals_when_log_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = PolicyLocalContext::with_log_dir(None, None, None, dir.path().to_path_buf());
        let (status, payload) = recent_denials_response(&ctx, "").await;
        assert_eq!(status, 200);
        assert_eq!(payload["log_available"], false);
        assert_eq!(payload["denials"].as_array().unwrap().len(), 0);
        assert!(
            payload["note"]
                .as_str()
                .unwrap()
                .contains("/var/log/openshell.")
        );
    }

    #[test]
    fn redact_query_strings_removes_query_from_url_token() {
        let line = "2026-05-06T17:02:00.000Z OCSF HTTP:PUT [MED] DENIED PUT http://api.github.com/x?access_token=secret-token-1234 [policy:p engine:l7]";
        let redacted = redact_query_strings(line);
        assert!(!redacted.contains("secret-token-1234"));
        assert!(!redacted.contains("access_token"));
        assert!(redacted.contains("?[redacted]"));
        // Bracketed tag after the URL preserved.
        assert!(redacted.contains("[policy:p engine:l7]"));
    }

    #[test]
    fn redact_query_strings_removes_query_in_reason_tag() {
        // The FORWARD deny path's `message` becomes `[reason:...]` and may
        // include a path with query string lacking a `://` prefix.
        let line = "2026-05-06T17:02:00.000Z OCSF HTTP:PUT [MED] DENIED PUT http://api.github.com/x [policy:p engine:opa] [reason:FORWARD denied PUT api.github.com:443/x?token=secret-456]";
        let redacted = redact_query_strings(line);
        assert!(!redacted.contains("secret-456"));
        assert!(!redacted.contains("token=secret"));
        assert!(redacted.contains("?[redacted]]"));
    }

    #[test]
    fn redact_query_strings_handles_multibyte_chars() {
        let line = "ÜLÅUTF8 ? secret-x [policy:p]";
        // No `?<nonspace>` here, so no redaction — but must not panic.
        let _ = redact_query_strings(line);
    }

    #[test]
    fn truncate_at_char_boundary_does_not_panic_on_multibyte() {
        // 4-byte emoji sequence so byte-naive slicing would panic.
        let s = "🚀".repeat(2000); // 8000 bytes
        let truncated = truncate_at_char_boundary(&s, 4096);
        assert!(truncated.len() <= 4096 + "...[truncated]".len());
        assert!(truncated.ends_with("...[truncated]"));
        // Result must be valid UTF-8 — implicit if we return without panic.
    }

    #[tokio::test]
    async fn recent_denials_truncates_pathological_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("openshell.2026-05-06.log");
        // A single OCSF denial line exceeding MAX_DENIAL_LINE_BYTES.
        let huge_path = "/".to_string() + &"a".repeat(MAX_DENIAL_LINE_BYTES + 100);
        let line = format!(
            "2026-05-06T17:02:00.000Z OCSF HTTP:PUT [MED] DENIED PUT http://x{huge_path} [policy:p engine:l7]\n"
        );
        std::fs::write(&log_path, line).unwrap();

        let ctx = PolicyLocalContext::with_log_dir(None, None, None, dir.path().to_path_buf());
        let (_, payload) = recent_denials_response(&ctx, "last=1").await;
        let denials = payload["denials"].as_array().unwrap();
        assert_eq!(denials.len(), 1);
        let surfaced = denials[0].as_str().unwrap();
        assert!(surfaced.len() <= MAX_DENIAL_LINE_BYTES + "...[truncated]".len());
        assert!(surfaced.ends_with("...[truncated]"));
    }

    use crate::test_helpers::ProposalsFlagGuard;

    #[test]
    fn agent_next_steps_returns_empty_when_flag_off() {
        let _guard = ProposalsFlagGuard::set_blocking(false);
        let steps = agent_next_steps();
        let arr = steps.as_array().expect("agent_next_steps is an array");
        assert!(
            arr.is_empty(),
            "expected empty next_steps when feature is off, got {steps}"
        );
    }

    #[test]
    fn agent_next_steps_returns_full_array_when_flag_on() {
        let _guard = ProposalsFlagGuard::set_blocking(true);
        let steps = agent_next_steps();
        let arr = steps.as_array().expect("agent_next_steps is an array");
        assert_eq!(arr.len(), 4, "expected 4 next_steps when feature is on");
        let actions: Vec<&str> = arr
            .iter()
            .filter_map(|v| v.get("action").and_then(serde_json::Value::as_str))
            .collect();
        assert!(actions.contains(&"read_skill"));
        assert!(actions.contains(&"submit_proposal"));
    }

    #[tokio::test]
    async fn route_request_returns_feature_disabled_when_flag_off() {
        let _guard = ProposalsFlagGuard::set(false).await;
        let ctx = PolicyLocalContext::new(
            Some(ProtoSandboxPolicy {
                version: 1,
                ..Default::default()
            }),
            None,
            None,
        );

        // Even the otherwise-public `current_policy` route returns 404 with
        // a feature_disabled error: when the surface is off it's off
        // entirely, not selectively.
        let (status, payload) = route_request(&ctx, "GET", ROUTE_POLICY_CURRENT, &[]).await;
        assert_eq!(status, 404);
        assert_eq!(payload["error"], "feature_disabled");
        assert!(
            payload["detail"]
                .as_str()
                .unwrap()
                .contains("agent_policy_proposals_enabled"),
            "feature_disabled detail must name the setting key for actionability"
        );
    }

    #[tokio::test]
    async fn current_policy_route_returns_yaml_envelope() {
        let _guard = ProposalsFlagGuard::set(true).await;
        let ctx = PolicyLocalContext::new(
            Some(ProtoSandboxPolicy {
                version: 1,
                ..Default::default()
            }),
            None,
            None,
        );

        let (mut client, mut server) = tokio::io::duplex(4096);
        let request =
            b"GET http://policy.local/v1/policy/current HTTP/1.1\r\nHost: policy.local\r\n\r\n";
        let task = tokio::spawn(async move {
            handle_forward_request(&ctx, "GET", "/v1/policy/current", request, &mut server)
                .await
                .unwrap();
        });

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        task.await.unwrap();

        let response = String::from_utf8(received).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        let (_, body) = response.split_once("\r\n\r\n").unwrap();
        let body: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(body["format"], "yaml");
        assert!(body["policy_yaml"].as_str().unwrap().contains("version: 1"));
    }

    #[test]
    fn parse_timeout_query_defaults_and_clamps() {
        assert_eq!(parse_timeout_query(""), PROPOSAL_WAIT_DEFAULT_SECS);
        assert_eq!(parse_timeout_query("timeout="), PROPOSAL_WAIT_DEFAULT_SECS);
        assert_eq!(
            parse_timeout_query("timeout=abc"),
            PROPOSAL_WAIT_DEFAULT_SECS
        );
        assert_eq!(parse_timeout_query("timeout=30"), 30);
        assert_eq!(parse_timeout_query("foo=1&timeout=45"), 45);
        // Below floor clamps up; above ceiling clamps down.
        assert_eq!(parse_timeout_query("timeout=0"), PROPOSAL_WAIT_MIN_SECS);
        assert_eq!(parse_timeout_query("timeout=9999"), PROPOSAL_WAIT_MAX_SECS);
    }

    #[test]
    fn is_terminal_status_matches_only_approved_and_rejected() {
        assert!(!is_terminal_status("pending"));
        assert!(is_terminal_status("approved"));
        assert!(is_terminal_status("rejected"));
        assert!(!is_terminal_status(""));
    }

    #[test]
    fn chunk_state_payload_surfaces_loop_fields() {
        let chunk = PolicyChunk {
            id: "chunk-x".to_string(),
            status: "rejected".to_string(),
            rule_name: "allow_example".to_string(),
            binary: "/usr/bin/curl".to_string(),
            rejection_reason: "scope too broad".to_string(),
            validation_result: "no exfil paths".to_string(),
            ..Default::default()
        };
        let pending = chunk_state_payload(&chunk, false, false);
        assert_eq!(pending["chunk_id"], "chunk-x");
        assert_eq!(pending["status"], "rejected");
        assert_eq!(pending["rejection_reason"], "scope too broad");
        assert_eq!(pending["validation_result"], "no exfil paths");
        // timed_out and policy_reloaded only appear when relevant.
        assert!(pending.get("timed_out").is_none());
        assert!(
            pending.get("policy_reloaded").is_none(),
            "policy_reloaded is only meaningful for approved chunks"
        );

        let timed = chunk_state_payload(&chunk, true, false);
        assert_eq!(timed["timed_out"], true);
    }

    #[test]
    fn chunk_state_payload_includes_policy_reloaded_when_approved() {
        let chunk = PolicyChunk {
            id: "chunk-y".to_string(),
            status: "approved".to_string(),
            rule_name: "allow_github".to_string(),
            binary: "/usr/bin/curl".to_string(),
            ..Default::default()
        };
        let reloaded = chunk_state_payload(&chunk, false, true);
        assert_eq!(reloaded["status"], "approved");
        assert_eq!(reloaded["policy_reloaded"], true);

        let not_reloaded = chunk_state_payload(&chunk, false, false);
        assert_eq!(not_reloaded["policy_reloaded"], false);
    }

    #[tokio::test]
    async fn proposal_routes_reject_malformed_paths() {
        let _guard = ProposalsFlagGuard::set(true).await;
        let ctx = PolicyLocalContext::new(None, None, None);

        // Empty chunk_id after the prefix is 404, not a wildcard list.
        let (status, _) = route_request(&ctx, "GET", "/v1/proposals/", &[]).await;
        assert_eq!(status, 404);

        // More than one segment after the id (not "/wait") is 404, not a
        // partial match. Prevents `/v1/proposals/abc/extra` from silently
        // dispatching as a status lookup for "abc/extra".
        let (status, _) = route_request(&ctx, "GET", "/v1/proposals/abc/extra", &[]).await;
        assert_eq!(status, 404);

        // Trailing path after `/wait` also 404 — must not match the wait
        // arm as a wildcard.
        let (status, _) = route_request(&ctx, "GET", "/v1/proposals/abc/wait/extra", &[]).await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn proposal_status_route_returns_503_when_no_gateway() {
        let _guard = ProposalsFlagGuard::set(true).await;
        let ctx = PolicyLocalContext::new(None, None, Some("test-sandbox".to_string()));

        let (status, body) = route_request(&ctx, "GET", "/v1/proposals/chunk-id", &[]).await;
        assert_eq!(status, 503);
        assert_eq!(body["error"], "gateway_unavailable");
    }

    #[tokio::test]
    async fn proposal_wait_route_returns_503_when_no_gateway() {
        let _guard = ProposalsFlagGuard::set(true).await;
        let ctx = PolicyLocalContext::new(None, None, Some("test-sandbox".to_string()));

        let (status, body) =
            route_request(&ctx, "GET", "/v1/proposals/chunk-id/wait?timeout=1", &[]).await;
        assert_eq!(status, 503);
        assert_eq!(body["error"], "gateway_unavailable");
    }

    #[tokio::test]
    async fn proposal_routes_return_feature_disabled_when_flag_off() {
        let _guard = ProposalsFlagGuard::set(false).await;
        let ctx = PolicyLocalContext::new(None, None, Some("test-sandbox".to_string()));

        let (status, body) = route_request(&ctx, "GET", "/v1/proposals/abc", &[]).await;
        assert_eq!(status, 404);
        assert_eq!(body["error"], "feature_disabled");

        let (status, _) = route_request(&ctx, "GET", "/v1/proposals/abc/wait", &[]).await;
        assert_eq!(status, 404);
    }

    #[test]
    fn summarize_chunk_for_audit_includes_endpoint_l7_path_and_binary() {
        let chunk = PolicyChunk {
            id: "ignored".to_string(),
            rule_name: "github_write".to_string(),
            binary: "/usr/bin/curl".to_string(),
            proposed_rule: Some(NetworkPolicyRule {
                name: "github_write".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.github.com".to_string(),
                    port: 443,
                    rules: vec![L7Rule {
                        allow: Some(L7Allow {
                            method: "PUT".to_string(),
                            path: "/repos/foo/bar/contents/x.md".to_string(),
                            ..Default::default()
                        }),
                    }],
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/curl".to_string(),
                    ..Default::default()
                }],
            }),
            ..Default::default()
        };
        let summary = summarize_chunk_for_audit(&chunk);
        assert!(summary.contains("api.github.com:443"));
        assert!(summary.contains("PUT /repos/foo/bar/contents/x.md"));
        assert!(summary.contains("/usr/bin/curl"));
    }

    // Helpers — synthetic proposed rule + policy with that rule already
    // merged. Both reused across reload-readiness tests.
    fn proposed_curl_rule_for_github() -> NetworkPolicyRule {
        NetworkPolicyRule {
            name: "agent_proposed".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                ports: vec![443],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        }
    }

    fn policy_with_rule(rule: NetworkPolicyRule) -> ProtoSandboxPolicy {
        ProtoSandboxPolicy {
            version: 1,
            network_policies: HashMap::from([(rule.name.clone(), rule)]),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn wait_returns_reloaded_true_when_rule_already_loaded() {
        // John's false-sleep case: the supervisor has already reloaded a
        // policy containing the proposed rule before /wait starts. A
        // whole-policy diff would never see another change and burn the
        // full timeout. Rule-coverage must return immediately.
        let proposed = proposed_curl_rule_for_github();
        let ctx = PolicyLocalContext::new(Some(policy_with_rule(proposed.clone())), None, None);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);

        let start = tokio::time::Instant::now();
        let reloaded = wait_for_local_policy_to_cover(&ctx, &proposed, deadline).await;
        let elapsed = start.elapsed();

        assert!(reloaded, "should report reloaded=true on coverage");
        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "should return immediately, not poll-and-wait; took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn wait_does_not_wake_on_unrelated_policy_change() {
        // John's false-wakeup case: a *different* rule gets added to the
        // local policy (other agent's approval, settings change, etc.).
        // The agent's specific rule is still not loaded. A diff-based
        // check would wake here; coverage must not.
        let proposed = proposed_curl_rule_for_github();
        // Start with a policy that does NOT contain the proposed rule.
        let initial = ProtoSandboxPolicy {
            version: 1,
            ..Default::default()
        };
        let ctx = PolicyLocalContext::new(Some(initial), None, None);

        // Concurrently, an unrelated rule lands. We must not return.
        let unrelated_load = {
            let policy = ctx.current_policy.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                *policy.write().await = Some(policy_with_rule(NetworkPolicyRule {
                    name: "unrelated".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "api.example.com".to_string(),
                        port: 443,
                        ports: vec![443],
                        ..Default::default()
                    }],
                    binaries: vec![NetworkBinary {
                        path: "/usr/bin/curl".to_string(),
                        ..Default::default()
                    }],
                }));
            })
        };

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(400);
        let start = tokio::time::Instant::now();
        let reloaded = wait_for_local_policy_to_cover(&ctx, &proposed, deadline).await;
        unrelated_load.await.unwrap();
        let elapsed = start.elapsed();

        assert!(
            !reloaded,
            "must not wake on an unrelated reload; coverage was never satisfied"
        );
        assert!(
            elapsed >= std::time::Duration::from_millis(350),
            "should have held until the deadline; only waited {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn wait_wakes_when_matching_rule_arrives_mid_flight() {
        // Sandbox starts without the rule, then a reload lands containing
        // it. /wait should observe coverage and return reloaded=true.
        let proposed = proposed_curl_rule_for_github();
        let ctx = PolicyLocalContext::new(
            Some(ProtoSandboxPolicy {
                version: 1,
                ..Default::default()
            }),
            None,
            None,
        );

        let matching_load = {
            let policy = ctx.current_policy.clone();
            let target = proposed.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                *policy.write().await = Some(policy_with_rule(target));
            })
        };

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let start = tokio::time::Instant::now();
        let reloaded = wait_for_local_policy_to_cover(&ctx, &proposed, deadline).await;
        matching_load.await.unwrap();
        let elapsed = start.elapsed();

        assert!(reloaded, "should report reloaded=true after coverage lands");
        assert!(
            elapsed < std::time::Duration::from_millis(800),
            "should return shortly after coverage; took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn wait_returns_reloaded_false_at_deadline_when_no_coverage() {
        // Deadline budget exhausted, the proposed rule never showed up.
        // Coverage check returns false — the agent gets policy_reloaded=
        // false and decides whether to retry blind or re-issue /wait.
        let proposed = proposed_curl_rule_for_github();
        let ctx = PolicyLocalContext::new(
            Some(ProtoSandboxPolicy {
                version: 1,
                ..Default::default()
            }),
            None,
            None,
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(300);
        let start = tokio::time::Instant::now();
        let reloaded = wait_for_local_policy_to_cover(&ctx, &proposed, deadline).await;
        let elapsed = start.elapsed();

        assert!(!reloaded);
        assert!(
            elapsed >= std::time::Duration::from_millis(250),
            "should wait until ~deadline; only waited {elapsed:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(800),
            "should not extend past deadline by much; took {elapsed:?}"
        );
    }

    #[test]
    fn sanitize_reason_for_audit_strips_control_chars_and_caps_length() {
        // Tabs and newlines are stripped; ordinary printable chars survive;
        // multi-byte characters count as one char in the cap.
        let raw = "line one\nline\ttwo\u{0001}\u{0007}";
        let cleaned = sanitize_reason_for_audit(raw);
        assert!(!cleaned.contains('\n'));
        assert!(!cleaned.contains('\t'));
        assert!(!cleaned.contains('\u{0001}'));
        assert!(cleaned.contains("line one"));
        assert!(cleaned.contains("linetwo"));

        // Length cap with ellipsis marker so a downstream reader can tell
        // the audit string is truncated.
        let long: String = "x".repeat(500);
        let capped = sanitize_reason_for_audit(&long);
        assert!(capped.chars().count() <= 201);
        assert!(capped.ends_with('…'));

        // Empty input maps to empty output (caller renders "(no guidance)").
        assert_eq!(sanitize_reason_for_audit(""), "");
    }

    #[test]
    fn summarize_chunk_for_audit_falls_back_to_rule_name_without_rule() {
        let chunk = PolicyChunk {
            rule_name: "fallback".to_string(),
            proposed_rule: None,
            ..Default::default()
        };
        assert_eq!(summarize_chunk_for_audit(&chunk), "rule_name:fallback");
    }
}
