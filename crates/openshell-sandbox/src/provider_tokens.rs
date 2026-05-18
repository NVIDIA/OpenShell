// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox-local provider token resolvers.

use crate::grpc_client;
use miette::{IntoDiagnostic, Result, WrapErr};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

const MAX_REQUEST_HEADER_BYTES: usize = 8192;
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024;
const MICROSOFT_AGENT_S2S_TOKEN_PATH: &str = "/v1/microsoft-agent-s2s/token";
const MICROSOFT_AGENT_S2S_RESOLVER_PORT: u16 = 3130;
const TOKEN_URL_ENV: &str = "OPENSHELL_MICROSOFT_AGENT_S2S_TOKEN_URL";
const TOKEN_PROVIDER_URL_ENV: &str = "OPENSHELL_MICROSOFT_AGENT_S2S_TOKEN_PROVIDER_URL";
const DEFAULT_AUDIENCE_ENV: &str = "OPENSHELL_MICROSOFT_AGENT_S2S_DEFAULT_AUDIENCE";
const A365_TOKEN_PROVIDER_URL_ENV: &str = "A365_TOKEN_PROVIDER_URL";
const PROVIDER_NAME_ENV: &str = "OPENSHELL_MICROSOFT_AGENT_S2S_PROVIDER_NAME";

const MICROSOFT_AGENT_S2S_KEYS: &[&str] = &[
    "AZURE_TENANT_ID",
    "A365_BLUEPRINT_CLIENT_ID",
    "A365_BLUEPRINT_CLIENT_SECRET",
    "A365_RUNTIME_AGENT_ID",
    "A365_ALLOWED_AUDIENCES",
    "A365_OBSERVABILITY_RESOURCE",
    "A365_REQUIRED_ROLES",
    PROVIDER_NAME_ENV,
];

const MICROSOFT_AGENT_S2S_MARKER_KEYS: &[&str] = &[
    "A365_BLUEPRINT_CLIENT_ID",
    "A365_BLUEPRINT_CLIENT_SECRET",
    "A365_RUNTIME_AGENT_ID",
    PROVIDER_NAME_ENV,
];

pub(crate) struct PreparedProviderTokenResolver {
    pub environment: HashMap<String, String>,
    pub handle: Option<ProviderTokenResolverHandle>,
}

pub(crate) fn microsoft_agent_s2s_resolver_port(
    provider_env: &HashMap<String, String>,
) -> Option<u16> {
    contains_microsoft_agent_s2s_inputs(provider_env).then_some(MICROSOFT_AGENT_S2S_RESOLVER_PORT)
}

pub(crate) fn strip_microsoft_agent_s2s_inputs(
    provider_env: &mut HashMap<String, String>,
) -> Option<String> {
    if !contains_microsoft_agent_s2s_inputs(provider_env) {
        return None;
    }

    let provider_name = provider_env.get(PROVIDER_NAME_ENV).cloned();
    for key in MICROSOFT_AGENT_S2S_KEYS {
        provider_env.remove(*key);
    }
    provider_name
}

#[derive(Debug)]
pub(crate) struct ProviderTokenResolverHandle {
    local_addr: SocketAddr,
    token_path: String,
    join: JoinHandle<()>,
}

impl ProviderTokenResolverHandle {
    fn url(&self) -> String {
        format!("http://{}{}", self.local_addr, self.token_path)
    }
}

impl Drop for ProviderTokenResolverHandle {
    fn drop(&mut self) {
        self.join.abort();
    }
}

pub(crate) async fn prepare_microsoft_agent_s2s(
    raw_provider_env: &mut HashMap<String, String>,
    bind_addr: SocketAddr,
    endpoint: &str,
    sandbox_id: &str,
) -> Result<PreparedProviderTokenResolver> {
    if !contains_microsoft_agent_s2s_inputs(raw_provider_env) {
        return Ok(PreparedProviderTokenResolver {
            environment: HashMap::new(),
            handle: None,
        });
    }

    let provider_name = raw_provider_env
        .get(PROVIDER_NAME_ENV)
        .cloned()
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| miette::miette!("missing microsoft-agent-s2s provider name"))?;
    let default_audience = default_audience(raw_provider_env);
    let handle = start_microsoft_agent_s2s_resolver(
        endpoint.to_string(),
        sandbox_id.to_string(),
        provider_name,
        default_audience.clone(),
        bind_addr,
    )
    .await?;

    strip_microsoft_agent_s2s_inputs(raw_provider_env);
    let environment = resolver_environment(handle.url(), default_audience);

    Ok(PreparedProviderTokenResolver {
        environment,
        handle: Some(handle),
    })
}

fn contains_microsoft_agent_s2s_inputs(provider_env: &HashMap<String, String>) -> bool {
    MICROSOFT_AGENT_S2S_MARKER_KEYS
        .iter()
        .any(|key| provider_env.contains_key(*key))
}

fn default_audience(provider_env: &HashMap<String, String>) -> Option<String> {
    provider_env
        .get("A365_OBSERVABILITY_RESOURCE")
        .cloned()
        .or_else(|| {
            provider_env
                .get("A365_ALLOWED_AUDIENCES")
                .map(|value| split_csv(value))
                .and_then(|values| match values.as_slice() {
                    [only] => Some(only.clone()),
                    _ => None,
                })
        })
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn resolver_environment(
    resolver_url: String,
    default_audience: Option<String>,
) -> HashMap<String, String> {
    let mut environment = HashMap::from([
        (TOKEN_URL_ENV.to_string(), resolver_url.clone()),
        (TOKEN_PROVIDER_URL_ENV.to_string(), resolver_url.clone()),
        (A365_TOKEN_PROVIDER_URL_ENV.to_string(), resolver_url),
    ]);
    if let Some(audience) = default_audience {
        environment.insert(DEFAULT_AUDIENCE_ENV.to_string(), audience);
    }
    environment
}

async fn start_microsoft_agent_s2s_resolver(
    endpoint: String,
    sandbox_id: String,
    provider_name: String,
    default_audience: Option<String>,
    bind_addr: SocketAddr,
) -> Result<ProviderTokenResolverHandle> {
    let listener = TcpListener::bind(bind_addr).await.into_diagnostic()?;
    let local_addr = listener.local_addr().into_diagnostic()?;
    let token_path = format!("{MICROSOFT_AGENT_S2S_TOKEN_PATH}/{}", uuid::Uuid::new_v4());
    let token_path_for_task = token_path.clone();

    let join = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let endpoint = endpoint.clone();
                    let sandbox_id = sandbox_id.clone();
                    let provider_name = provider_name.clone();
                    let default_audience = default_audience.clone();
                    let token_path = token_path_for_task.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_microsoft_agent_s2s_connection(
                            stream,
                            &endpoint,
                            &sandbox_id,
                            &provider_name,
                            default_audience,
                            token_path,
                        )
                        .await
                        {
                            warn!(error = %err, "microsoft-agent-s2s token resolver request failed");
                        }
                    });
                }
                Err(err) => {
                    warn!(error = %err, "microsoft-agent-s2s token resolver accept failed");
                    break;
                }
            }
        }
    });

    Ok(ProviderTokenResolverHandle {
        local_addr,
        token_path,
        join,
    })
}

async fn handle_microsoft_agent_s2s_connection(
    mut stream: TcpStream,
    endpoint: &str,
    sandbox_id: &str,
    provider_name: &str,
    default_audience: Option<String>,
    token_path: String,
) -> Result<()> {
    let request = read_http_request(&mut stream).await?;
    let response = match parse_token_request(&request, default_audience.as_deref(), &token_path) {
        Ok(audience) => {
            match grpc_client::mint_provider_token(endpoint, sandbox_id, provider_name, &audience)
                .await
            {
                Ok(token) => json_response(
                    200,
                    "OK",
                    serde_json::json!({
                        "access_token": token.access_token,
                        "token_type": token.token_type,
                        "expires_at_unix": token.expires_at_unix,
                        "cache_hit": token.cache_hit,
                    }),
                ),
                Err(err) => json_response(
                    502,
                    "Bad Gateway",
                    serde_json::json!({ "error": err.to_string() }),
                ),
            }
        }
        Err(err) => err.into_response(),
    };
    stream
        .write_all(response.as_bytes())
        .await
        .into_diagnostic()?;
    Ok(())
}

async fn read_http_request(stream: &mut TcpStream) -> Result<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.into_diagnostic()?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buffer.len() > MAX_REQUEST_HEADER_BYTES {
            return Err(miette::miette!("token resolver request headers too large"));
        }
    }

    let header_end = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or_else(|| miette::miette!("incomplete HTTP request"))?;

    let content_length = content_length(&buffer[..header_end])?;
    if content_length > MAX_REQUEST_BODY_BYTES {
        return Err(miette::miette!("token resolver request body too large"));
    }

    while buffer.len().saturating_sub(header_end) < content_length {
        let read = stream.read(&mut chunk).await.into_diagnostic()?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len().saturating_sub(header_end) > MAX_REQUEST_BODY_BYTES {
            return Err(miette::miette!("token resolver request body too large"));
        }
    }

    if buffer.len().saturating_sub(header_end) < content_length {
        return Err(miette::miette!("incomplete HTTP request body"));
    }

    String::from_utf8(buffer).into_diagnostic()
}

fn content_length(headers: &[u8]) -> Result<usize> {
    let headers = std::str::from_utf8(headers).into_diagnostic()?;
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse::<usize>()
                .into_diagnostic()
                .wrap_err("invalid content-length header");
        }
    }
    Ok(0)
}

fn parse_token_request(
    request: &str,
    default_audience: Option<&str>,
    expected_path: &str,
) -> std::result::Result<String, HttpError> {
    let parsed = ParsedHttpRequest::parse(request)?;
    let method = parsed.method.as_str();
    let target = parsed.target.as_str();

    if method != "GET" && method != "POST" {
        return Err(HttpError::new(
            405,
            "Method Not Allowed",
            "method not allowed",
        ));
    }

    let (path, query) = target
        .split_once('?')
        .map_or((target, ""), |(path, query)| (path, query));
    if path != expected_path {
        return Err(HttpError::new(404, "Not Found", "token endpoint not found"));
    }

    let audience = if method == "GET" {
        audience_from_query(query)
    } else {
        audience_from_json_body(parsed.body)?
    }
    .or_else(|| default_audience.map(ToOwned::to_owned))
    .ok_or_else(|| HttpError::new(400, "Bad Request", "audience is required"))?;

    if audience.trim().is_empty() {
        return Err(HttpError::new(
            400,
            "Bad Request",
            "audience must not be empty",
        ));
    }

    debug!(audience = %audience, "microsoft-agent-s2s token resolver request accepted");
    Ok(audience)
}

fn audience_from_query(query: &str) -> Option<String> {
    query.split('&').find_map(|entry| {
        let (key, value) = entry.split_once('=')?;
        (key == "audience").then(|| value.to_string())
    })
}

fn audience_from_json_body(body: &str) -> std::result::Result<Option<String>, HttpError> {
    if body.trim().is_empty() {
        return Ok(None);
    }

    #[derive(Deserialize)]
    struct TokenRequestBody {
        audience: Option<String>,
    }

    serde_json::from_str::<TokenRequestBody>(body)
        .map(|payload| payload.audience)
        .map_err(|_| HttpError::new(400, "Bad Request", "invalid JSON request body"))
}

struct ParsedHttpRequest<'a> {
    method: String,
    target: String,
    body: &'a str,
}

impl<'a> ParsedHttpRequest<'a> {
    fn parse(request: &'a str) -> std::result::Result<Self, HttpError> {
        let Some((head, body)) = request.split_once("\r\n\r\n") else {
            return Err(HttpError::new(
                400,
                "Bad Request",
                "missing HTTP request separator",
            ));
        };
        let request_line = head
            .lines()
            .next()
            .ok_or_else(|| HttpError::new(400, "Bad Request", "missing HTTP request line"))?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let target = parts.next().unwrap_or_default().to_string();
        Ok(Self {
            method,
            target,
            body,
        })
    }
}

#[derive(Debug)]
struct HttpError {
    status: u16,
    reason: &'static str,
    message: &'static str,
}

impl HttpError {
    const fn new(status: u16, reason: &'static str, message: &'static str) -> Self {
        Self {
            status,
            reason,
            message,
        }
    }

    fn into_response(self) -> String {
        json_response(
            self.status,
            self.reason,
            serde_json::json!({ "error": self.message }),
        )
    }
}

fn json_response(status: u16, reason: &str, body: serde_json::Value) -> String {
    let body = body.to_string();
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nPragma: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_inputs_removes_microsoft_broker_material() {
        let mut provider_env = HashMap::from([
            (PROVIDER_NAME_ENV.to_string(), "work-microsoft".to_string()),
            (
                "A365_BLUEPRINT_CLIENT_SECRET".to_string(),
                "secret".to_string(),
            ),
            (
                "A365_ALLOWED_AUDIENCES".to_string(),
                "api://allowed".to_string(),
            ),
        ]);

        let provider_name = strip_microsoft_agent_s2s_inputs(&mut provider_env);
        assert_eq!(provider_name.as_deref(), Some("work-microsoft"));
        assert!(provider_env.is_empty());
    }

    #[test]
    fn resolver_environment_exposes_only_local_token_metadata() {
        let environment = resolver_environment(
            "http://127.0.0.1:3130/v1/microsoft-agent-s2s/token/capability".to_string(),
            Some("api://resource".to_string()),
        );

        assert_eq!(
            environment.get(TOKEN_URL_ENV),
            Some(&"http://127.0.0.1:3130/v1/microsoft-agent-s2s/token/capability".to_string())
        );
        assert_eq!(
            environment.get(TOKEN_PROVIDER_URL_ENV),
            environment.get(TOKEN_URL_ENV)
        );
        assert_eq!(
            environment.get(A365_TOKEN_PROVIDER_URL_ENV),
            environment.get(TOKEN_URL_ENV)
        );
        assert_eq!(
            environment.get(DEFAULT_AUDIENCE_ENV),
            Some(&"api://resource".to_string())
        );
        assert!(!environment.contains_key("A365_BLUEPRINT_CLIENT_SECRET"));
        assert!(!environment.contains_key("A365_BLUEPRINT_CLIENT_ID"));
    }

    #[test]
    fn parse_token_request_accepts_post_json_body() {
        let audience = parse_token_request(
            "POST /v1/microsoft-agent-s2s/token/test HTTP/1.1\r\nContent-Length: 31\r\n\r\n{\"audience\":\"api://resource\"}",
            None,
            "/v1/microsoft-agent-s2s/token/test",
        )
        .expect("audience");

        assert_eq!(audience, "api://resource");
    }

    #[test]
    fn parse_token_request_uses_default_audience_for_empty_post_body() {
        let audience = parse_token_request(
            "POST /v1/microsoft-agent-s2s/token/test HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
            Some("api://default"),
            "/v1/microsoft-agent-s2s/token/test",
        )
        .expect("audience");

        assert_eq!(audience, "api://default");
    }

    #[test]
    fn parse_token_request_rejects_invalid_json_body() {
        let err = parse_token_request(
            "POST /v1/microsoft-agent-s2s/token/test HTTP/1.1\r\nContent-Length: 9\r\n\r\nnot-json!",
            None,
            "/v1/microsoft-agent-s2s/token/test",
        )
        .expect_err("invalid request should fail");

        assert_eq!(err.status, 400);
        assert_eq!(err.message, "invalid JSON request body");
    }
}
