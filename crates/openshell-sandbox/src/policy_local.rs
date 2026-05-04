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

const MAX_POLICY_LOCAL_BODY_BYTES: usize = 64 * 1024;
const DEFAULT_DENIALS_LIMIT: usize = 10;
const MAX_DENIALS_LIMIT: usize = 100;
/// OCSF rolling appender keeps three files (daily rotation); read the most
/// recent two so a request just past midnight still has yesterday's denials.
const DENIAL_LOG_FILES_TO_SCAN: usize = 2;
const OCSF_LOG_DIR: &str = "/var/log";
const OCSF_LOG_PREFIX: &str = "openshell-ocsf";

#[derive(Debug)]
pub struct PolicyLocalContext {
    current_policy: Arc<RwLock<Option<ProtoSandboxPolicy>>>,
    gateway_endpoint: Option<String>,
    sandbox_name: Option<String>,
    ocsf_log_dir: PathBuf,
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
            PathBuf::from(OCSF_LOG_DIR),
        )
    }

    fn with_log_dir(
        current_policy: Option<ProtoSandboxPolicy>,
        gateway_endpoint: Option<String>,
        sandbox_name: Option<String>,
        ocsf_log_dir: PathBuf,
    ) -> Self {
        Self {
            current_policy: Arc::new(RwLock::new(current_policy)),
            gateway_endpoint,
            sandbox_name,
            ocsf_log_dir,
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
    match (method, route) {
        ("GET", "/v1/policy/current") => current_policy_response(ctx).await,
        ("GET", "/v1/denials") => recent_denials_response(ctx, query).await,
        ("POST", "/v1/proposals") => submit_proposal(ctx, body).await,
        _ => (
            404,
            serde_json::json!({
                "error": "not_found",
                "detail": format!("policy.local route not found: {method} {route}")
            }),
        ),
    }
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
    let log_dir = ctx.ocsf_log_dir.clone();

    let denials = tokio::task::spawn_blocking(move || read_recent_denials(&log_dir, limit))
        .await
        .unwrap_or_else(|_| Vec::new());

    (200, serde_json::json!({ "denials": denials }))
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

/// Walk the OCSF JSONL log files (most-recent first) and return up to `limit`
/// summarized denial events in newest-first order.
///
/// Reads files synchronously and is intended to run inside `spawn_blocking`.
fn read_recent_denials(log_dir: &Path, limit: usize) -> Vec<serde_json::Value> {
    let Ok(files) = collect_ocsf_log_files(log_dir, DENIAL_LOG_FILES_TO_SCAN) else {
        return Vec::new();
    };

    let mut summaries: Vec<serde_json::Value> = Vec::with_capacity(limit);
    for path in files {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        // Walk lines newest-first. Within a single file, last line written is
        // the freshest event.
        for line in contents.lines().rev() {
            if line.is_empty() {
                continue;
            }
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(summary) = denial_summary_from_event(&value) else {
                continue;
            };
            summaries.push(summary);
            if summaries.len() >= limit {
                return summaries;
            }
        }
    }
    summaries
}

fn collect_ocsf_log_files(log_dir: &Path, max_files: usize) -> std::io::Result<Vec<PathBuf>> {
    let mut entries: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(log_dir)?
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with(OCSF_LOG_PREFIX) {
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

/// Convert an OCSF event into a compact denial summary, or `None` if the event
/// is not a network/HTTP denial we want to surface to the agent.
fn denial_summary_from_event(value: &serde_json::Value) -> Option<serde_json::Value> {
    // OCSF action_id 2 = Denied. Filter aggressively to avoid leaking unrelated
    // events (allowed connections, app lifecycle, etc.) into the agent's view.
    if value.get("action_id").and_then(serde_json::Value::as_u64) != Some(2) {
        return None;
    }

    let class_uid = value.get("class_uid").and_then(serde_json::Value::as_u64)?;
    let layer = match class_uid {
        4001 => "l4",
        4002 => "l7",
        _ => return None,
    };

    let mut summary = serde_json::Map::new();
    summary.insert("layer".to_string(), serde_json::json!(layer));

    if let Some(time) = value.get("time").and_then(serde_json::Value::as_i64) {
        summary.insert("time_ms".to_string(), serde_json::json!(time));
    }
    if let Some(message) = value.get("message").and_then(serde_json::Value::as_str) {
        summary.insert("message".to_string(), serde_json::json!(message));
    }
    if let Some(dst) = value.get("dst_endpoint") {
        if let Some(host) = dst
            .get("hostname")
            .and_then(serde_json::Value::as_str)
            .or_else(|| dst.get("ip").and_then(serde_json::Value::as_str))
        {
            summary.insert("host".to_string(), serde_json::json!(host));
        }
        if let Some(port) = dst.get("port").and_then(serde_json::Value::as_u64) {
            summary.insert("port".to_string(), serde_json::json!(port));
        }
    }
    if let Some(req) = value.get("http_request") {
        if let Some(method) = req.get("http_method").and_then(serde_json::Value::as_str) {
            summary.insert("method".to_string(), serde_json::json!(method));
        }
        if let Some(url) = req.get("url")
            && let Some(path) = url.get("path").and_then(serde_json::Value::as_str)
        {
            summary.insert("path".to_string(), serde_json::json!(path));
        }
    }
    if let Some(binary) = value
        .get("actor")
        .and_then(|a| a.get("process"))
        .and_then(|p| p.get("file"))
        .and_then(|f| f.get("path"))
        .and_then(serde_json::Value::as_str)
    {
        summary.insert("binary".to_string(), serde_json::json!(binary));
    }
    if let Some(rule) = value
        .get("firewall_rule")
        .and_then(|r| r.get("name"))
        .and_then(serde_json::Value::as_str)
    {
        summary.insert("policy".to_string(), serde_json::json!(rule));
    }

    Some(serde_json::Value::Object(summary))
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
    while body.len() < content_length {
        let remaining = content_length - body.len();
        let mut chunk = vec![0u8; remaining.min(8192)];
        let n = client.read(&mut chunk).await.into_diagnostic()?;
        if n == 0 {
            return Err(miette::miette!("policy.local request body ended early"));
        }
        body.extend_from_slice(&chunk[..n]);
    }

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
    fn denial_summary_filters_to_l4_l7_denied_only() {
        let allowed = serde_json::json!({
            "class_uid": 4001,
            "action_id": 1,
            "dst_endpoint": {"hostname": "api.github.com", "port": 443}
        });
        assert!(denial_summary_from_event(&allowed).is_none());

        let unrelated = serde_json::json!({
            "class_uid": 6002,
            "action_id": 2,
            "message": "supervisor lifecycle"
        });
        assert!(denial_summary_from_event(&unrelated).is_none());

        let l4_denied = serde_json::json!({
            "class_uid": 4001,
            "action_id": 2,
            "time": 1_742_054_400_000_i64,
            "message": "CONNECT denied api.github.com:443",
            "dst_endpoint": {"hostname": "api.github.com", "port": 443},
            "actor": {"process": {"file": {"path": "/usr/bin/curl"}}},
            "firewall_rule": {"name": "github-readonly"}
        });
        let summary = denial_summary_from_event(&l4_denied).unwrap();
        assert_eq!(summary["layer"], "l4");
        assert_eq!(summary["host"], "api.github.com");
        assert_eq!(summary["port"], 443);
        assert_eq!(summary["binary"], "/usr/bin/curl");
        assert_eq!(summary["policy"], "github-readonly");
        assert_eq!(summary["time_ms"], 1_742_054_400_000_i64);

        let l7_denied = serde_json::json!({
            "class_uid": 4002,
            "action_id": 2,
            "message": "FORWARD denied PUT /repos/foo/bar/contents/x",
            "dst_endpoint": {"hostname": "api.github.com", "port": 443},
            "http_request": {
                "http_method": "PUT",
                "url": {"path": "/repos/foo/bar/contents/x"}
            }
        });
        let summary = denial_summary_from_event(&l7_denied).unwrap();
        assert_eq!(summary["layer"], "l7");
        assert_eq!(summary["method"], "PUT");
        assert_eq!(summary["path"], "/repos/foo/bar/contents/x");
    }

    #[tokio::test]
    async fn recent_denials_returns_newest_first_from_jsonl_files() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("openshell-ocsf.2026-05-04.log");
        let lines = [
            serde_json::json!({
                "class_uid": 4001,
                "action_id": 2,
                "time": 1,
                "message": "first",
                "dst_endpoint": {"hostname": "first.example", "port": 443}
            }),
            // An allowed event mixed in — must be filtered out.
            serde_json::json!({
                "class_uid": 4001,
                "action_id": 1,
                "time": 2,
                "dst_endpoint": {"hostname": "ok.example", "port": 443}
            }),
            serde_json::json!({
                "class_uid": 4002,
                "action_id": 2,
                "time": 3,
                "message": "second",
                "dst_endpoint": {"hostname": "second.example", "port": 443},
                "http_request": {"http_method": "PUT", "url": {"path": "/x"}}
            }),
        ];
        let body: String = lines
            .iter()
            .map(|v| format!("{v}\n"))
            .collect::<Vec<_>>()
            .concat();
        std::fs::write(&log_path, body).unwrap();

        let ctx = PolicyLocalContext::with_log_dir(None, None, None, dir.path().to_path_buf());
        let (status, payload) = recent_denials_response(&ctx, "last=10").await;
        assert_eq!(status, 200);
        let denials = payload["denials"].as_array().unwrap();
        assert_eq!(denials.len(), 2);
        // Newest first.
        assert_eq!(denials[0]["message"], "second");
        assert_eq!(denials[1]["message"], "first");
    }

    #[tokio::test]
    async fn current_policy_route_returns_yaml_envelope() {
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
