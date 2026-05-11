// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox-local policy advisor HTTP API.

use miette::{IntoDiagnostic, Result};
use openshell_core::proto::{
    L7Allow, L7DenyRule, L7Rule, NetworkBinary, NetworkEndpoint, NetworkPolicyRule, PolicyChunk,
    SandboxPolicy as ProtoSandboxPolicy,
};
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
        _ => (
            404,
            serde_json::json!({
                "error": "not_found",
                "detail": format!("policy.local route not found: {method} {route}")
            }),
        ),
    }
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

    (
        202,
        serde_json::json!({
            "status": "submitted",
            "accepted_chunks": response.accepted_chunks,
            "rejected_chunks": response.rejected_chunks,
            "rejection_reasons": response.rejection_reasons,
        }),
    )
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
}
