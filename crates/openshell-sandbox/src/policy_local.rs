// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox-local policy advisor HTTP API.

use miette::{IntoDiagnostic, Result};
use openshell_core::proto::{
    L7Allow, L7DenyRule, L7Rule, NetworkBinary, NetworkEndpoint, NetworkPolicyRule, PolicyChunk,
    SandboxPolicy as ProtoSandboxPolicy, SubmitPolicyAnalysisRequest,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::RwLock;

pub const POLICY_LOCAL_HOST: &str = "policy.local";

const MAX_POLICY_LOCAL_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct PolicyLocalContext {
    current_policy: Arc<RwLock<Option<ProtoSandboxPolicy>>>,
    gateway_endpoint: Option<String>,
    sandbox_name: Option<String>,
}

impl PolicyLocalContext {
    pub fn new(
        current_policy: Option<ProtoSandboxPolicy>,
        gateway_endpoint: Option<String>,
        sandbox_name: Option<String>,
    ) -> Self {
        Self {
            current_policy: Arc::new(RwLock::new(current_policy)),
            gateway_endpoint,
            sandbox_name,
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
    let route = path.split_once('?').map_or(path, |(route, _)| route);
    match (method, route) {
        ("GET", "/v1/policy/current") => current_policy_response(ctx).await,
        ("GET", "/v1/denials") => (
            200,
            serde_json::json!({
                "denials": [],
                "note": "recent-denial listing is not wired in this MVP slice; use the structured 403 body and /var/log/openshell*.log for now"
            }),
        ),
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

    let mut raw_client = client.raw_client();
    let response = match raw_client
        .submit_policy_analysis(SubmitPolicyAnalysisRequest {
            summaries: vec![],
            proposed_chunks: chunks,
            analysis_mode: "agent".to_string(),
            name: sandbox_name.to_string(),
        })
        .await
    {
        Ok(response) => response.into_inner(),
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
            "note": "the gateway assigns proposal ids; review pending proposals in the developer inbox"
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
        let Some(add_rule) = operation
            .get("addRule")
            .or_else(|| operation.get("add_rule"))
            .cloned()
        else {
            return Err(
                "this MVP accepts addRule operations; submit a full narrow NetworkPolicyRule"
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
    #[serde(default, rename = "ruleName", alias = "rule_name")]
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
