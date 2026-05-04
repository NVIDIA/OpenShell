// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox-local provider token resolvers.

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_provider_auth::microsoft_s2s::{MicrosoftS2sBroker, MicrosoftS2sConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

const MAX_REQUEST_HEADER_BYTES: usize = 8192;
const MICROSOFT_AGENT_S2S_TOKEN_PATH: &str = "/v1/microsoft-agent-s2s/token";
const MICROSOFT_AGENT_S2S_RESOLVER_PORT: u16 = 3130;
const TOKEN_URL_ENV: &str = "OPENSHELL_MICROSOFT_AGENT_S2S_TOKEN_URL";
const DEFAULT_AUDIENCE_ENV: &str = "OPENSHELL_MICROSOFT_AGENT_S2S_DEFAULT_AUDIENCE";
const A365_TOKEN_PROVIDER_URL_ENV: &str = "A365_TOKEN_PROVIDER_URL";

const MICROSOFT_AGENT_S2S_KEYS: &[&str] = &[
    "AZURE_TENANT_ID",
    "A365_BLUEPRINT_CLIENT_ID",
    "A365_BLUEPRINT_CLIENT_SECRET",
    "A365_RUNTIME_AGENT_ID",
    "A365_ALLOWED_AUDIENCES",
    "A365_OBSERVABILITY_RESOURCE",
    "A365_REQUIRED_ROLES",
];

const MICROSOFT_AGENT_S2S_MARKER_KEYS: &[&str] = &[
    "A365_BLUEPRINT_CLIENT_ID",
    "A365_BLUEPRINT_CLIENT_SECRET",
    "A365_RUNTIME_AGENT_ID",
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
) -> Result<PreparedProviderTokenResolver> {
    if !contains_microsoft_agent_s2s_inputs(raw_provider_env) {
        return Ok(PreparedProviderTokenResolver {
            environment: HashMap::new(),
            handle: None,
        });
    }

    let provider_map = remove_microsoft_agent_s2s_inputs(raw_provider_env);
    let config = MicrosoftS2sConfig::from_provider_maps(&provider_map, &HashMap::new())
        .into_diagnostic()
        .wrap_err("invalid microsoft-agent-s2s provider configuration")?;
    let default_audience = default_audience(&config);
    let broker = MicrosoftS2sBroker::new(config)
        .into_diagnostic()
        .wrap_err("failed to initialize microsoft-agent-s2s token broker")?;
    let handle = start_microsoft_agent_s2s_resolver(broker, default_audience.clone(), bind_addr)
        .await
        .wrap_err("failed to start microsoft-agent-s2s token resolver")?;

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

fn remove_microsoft_agent_s2s_inputs(
    provider_env: &mut HashMap<String, String>,
) -> HashMap<String, String> {
    let mut removed = HashMap::new();
    for key in MICROSOFT_AGENT_S2S_KEYS {
        if let Some(value) = provider_env.remove(*key) {
            removed.insert((*key).to_string(), value);
        }
    }
    removed
}

fn default_audience(config: &MicrosoftS2sConfig) -> Option<String> {
    config
        .observability_resource
        .clone()
        .or_else(|| match config.allowed_audiences.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        })
}

fn resolver_environment(
    resolver_url: String,
    default_audience: Option<String>,
) -> HashMap<String, String> {
    let mut environment = HashMap::from([
        (TOKEN_URL_ENV.to_string(), resolver_url.clone()),
        (A365_TOKEN_PROVIDER_URL_ENV.to_string(), resolver_url),
    ]);
    if let Some(audience) = default_audience {
        environment.insert(DEFAULT_AUDIENCE_ENV.to_string(), audience);
    }
    environment
}

async fn start_microsoft_agent_s2s_resolver(
    broker: MicrosoftS2sBroker,
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
                    let broker = broker.clone();
                    let default_audience = default_audience.clone();
                    let token_path = token_path_for_task.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_microsoft_agent_s2s_connection(
                            stream,
                            broker,
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
    broker: MicrosoftS2sBroker,
    default_audience: Option<String>,
    token_path: String,
) -> Result<()> {
    let request = read_http_request(&mut stream).await?;
    let response = match parse_token_request(&request, default_audience.as_deref(), &token_path) {
        Ok(audience) => match broker.access_token(&audience).await {
            Ok(token) => json_response(
                200,
                "OK",
                serde_json::json!({
                    "access_token": token.access_token,
                    "token_type": "Bearer",
                    "expires_at_unix": token.expires_at_unix,
                    "cache_hit": token.cache_hit,
                }),
            ),
            Err(err) => json_response(
                502,
                "Bad Gateway",
                serde_json::json!({ "error": err.to_string() }),
            ),
        },
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
    String::from_utf8(buffer).into_diagnostic()
}

fn parse_token_request(
    request: &str,
    default_audience: Option<&str>,
    expected_path: &str,
) -> std::result::Result<String, HttpError> {
    let request_line = request
        .lines()
        .next()
        .ok_or_else(|| HttpError::new(400, "Bad Request", "missing HTTP request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let _version = parts.next().unwrap_or_default();

    if method != "GET" {
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

    let audience = url::form_urlencoded::parse(query.as_bytes())
        .find_map(|(key, value)| (key == "audience").then(|| value.into_owned()))
        .or_else(|| default_audience.map(ToOwned::to_owned))
        .ok_or_else(|| {
            HttpError::new(400, "Bad Request", "audience query parameter is required")
        })?;

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

    #[tokio::test]
    async fn prepare_does_nothing_without_microsoft_s2s_inputs() {
        let mut provider_env = HashMap::from([("API_KEY".to_string(), "secret".to_string())]);
        let prepared = prepare_microsoft_agent_s2s(&mut provider_env, ([127, 0, 0, 1], 0).into())
            .await
            .expect("prepare");

        assert!(prepared.environment.is_empty());
        assert!(prepared.handle.is_none());
        assert_eq!(provider_env.get("API_KEY"), Some(&"secret".to_string()));
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
    fn parse_uses_default_audience_when_query_is_absent() {
        let request = "GET /v1/microsoft-agent-s2s/token/cap HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let audience = parse_token_request(
            request,
            Some("api://default"),
            "/v1/microsoft-agent-s2s/token/cap",
        )
        .expect("audience");
        assert_eq!(audience, "api://default");
    }

    #[test]
    fn parse_decodes_audience_query_param() {
        let request = "GET /v1/microsoft-agent-s2s/token/cap?audience=api%3A%2F%2Fresource HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let audience = parse_token_request(request, None, "/v1/microsoft-agent-s2s/token/cap")
            .expect("audience");
        assert_eq!(audience, "api://resource");
    }

    #[test]
    fn parse_rejects_missing_audience_without_default() {
        let request = "GET /v1/microsoft-agent-s2s/token/cap HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let err = parse_token_request(request, None, "/v1/microsoft-agent-s2s/token/cap")
            .expect_err("missing audience should fail");
        assert_eq!(err.status, 400);
    }

    #[test]
    fn parse_rejects_guessable_base_path() {
        let request = "GET /v1/microsoft-agent-s2s/token?audience=api%3A%2F%2Fresource HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let err = parse_token_request(request, None, "/v1/microsoft-agent-s2s/token/cap")
            .expect_err("base path should not authorize");
        assert_eq!(err.status, 404);
    }

    #[test]
    fn json_response_disables_token_caching() {
        let response = json_response(200, "OK", serde_json::json!({"access_token": "token"}));

        assert!(response.contains("Cache-Control: no-store\r\n"));
        assert!(response.contains("Pragma: no-cache\r\n"));
    }

    #[test]
    fn removes_broker_inputs_before_child_env_injection() {
        let mut provider_env = HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "tenant".to_string()),
            (
                "A365_BLUEPRINT_CLIENT_ID".to_string(),
                "blueprint".to_string(),
            ),
            (
                "A365_BLUEPRINT_CLIENT_SECRET".to_string(),
                "secret".to_string(),
            ),
            (
                "A365_RUNTIME_AGENT_ID".to_string(),
                "runtime-agent".to_string(),
            ),
            (
                "A365_ALLOWED_AUDIENCES".to_string(),
                "api://resource".to_string(),
            ),
            ("API_KEY".to_string(), "kept".to_string()),
        ]);

        let removed = remove_microsoft_agent_s2s_inputs(&mut provider_env);

        assert_eq!(
            removed.get("A365_BLUEPRINT_CLIENT_SECRET"),
            Some(&"secret".to_string())
        );
        assert!(!provider_env.contains_key("A365_BLUEPRINT_CLIENT_SECRET"));
        assert!(!provider_env.contains_key("A365_BLUEPRINT_CLIENT_ID"));
        assert!(!provider_env.contains_key("A365_RUNTIME_AGENT_ID"));
        assert_eq!(provider_env.get("API_KEY"), Some(&"kept".to_string()));
    }
}
