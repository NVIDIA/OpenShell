// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use base64::Engine as _;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use url::Url;

const AZURE_TOKEN_EXCHANGE_SCOPE: &str = "api://AzureADTokenExchange/.default";
const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const DEFAULT_AUTHORITY_HOST: &str = "https://login.microsoftonline.com";
const DEFAULT_REFRESH_SKEW: Duration = Duration::from_secs(300);

#[derive(Debug, thiserror::Error)]
pub enum MicrosoftS2sError {
    #[error("invalid Microsoft S2S provider config: {0}")]
    InvalidConfig(String),
    #[error("audience '{0}' is not allowed by provider config")]
    AudienceDenied(String),
    #[error("failed to build token endpoint URL: {0}")]
    Url(String),
    #[error("Microsoft token request failed with HTTP {status}: {body}")]
    TokenHttp { status: StatusCode, body: String },
    #[error("Microsoft token request failed: {0}")]
    TokenTransport(String),
    #[error("Microsoft token response did not include an access token")]
    MissingAccessToken,
    #[error("Microsoft token claim validation failed: {0}")]
    ClaimValidation(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicrosoftS2sConfig {
    pub tenant_id: String,
    pub blueprint_client_id: String,
    pub blueprint_client_secret: String,
    pub runtime_agent_id: String,
    pub allowed_audiences: Vec<String>,
    pub observability_resource: Option<String>,
    pub required_roles: Vec<String>,
}

impl MicrosoftS2sConfig {
    pub fn from_provider_maps(
        credentials: &HashMap<String, String>,
        config: &HashMap<String, String>,
    ) -> Result<Self, MicrosoftS2sError> {
        let provider_value = |key: &str| {
            credentials
                .get(key)
                .or_else(|| config.get(key))
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };

        let allowed_audiences = provider_value("A365_ALLOWED_AUDIENCES")
            .map(|value| split_csv(&value))
            .unwrap_or_default();
        let required_roles = provider_value("A365_REQUIRED_ROLES")
            .map(|value| split_csv(&value))
            .unwrap_or_default();

        let cfg = Self {
            tenant_id: provider_value("AZURE_TENANT_ID").unwrap_or_default(),
            blueprint_client_id: provider_value("A365_BLUEPRINT_CLIENT_ID").unwrap_or_default(),
            blueprint_client_secret: provider_value("A365_BLUEPRINT_CLIENT_SECRET")
                .unwrap_or_default(),
            runtime_agent_id: provider_value("A365_RUNTIME_AGENT_ID").unwrap_or_default(),
            allowed_audiences,
            observability_resource: provider_value("A365_OBSERVABILITY_RESOURCE"),
            required_roles,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), MicrosoftS2sError> {
        require_non_empty("AZURE_TENANT_ID", &self.tenant_id)?;
        require_non_empty("A365_BLUEPRINT_CLIENT_ID", &self.blueprint_client_id)?;
        require_non_empty(
            "A365_BLUEPRINT_CLIENT_SECRET",
            &self.blueprint_client_secret,
        )?;
        require_non_empty("A365_RUNTIME_AGENT_ID", &self.runtime_agent_id)?;

        if self.allowed_audiences.is_empty() && self.observability_resource.is_none() {
            return Err(MicrosoftS2sError::InvalidConfig(
                "at least one allowed audience or observability resource is required".to_string(),
            ));
        }

        Ok(())
    }

    fn allowed_audience_set(&self) -> BTreeSet<String> {
        let mut allowed = self
            .allowed_audiences
            .iter()
            .map(|audience| normalize_audience(audience))
            .filter(|audience| !audience.is_empty())
            .collect::<BTreeSet<_>>();
        if let Some(resource) = &self.observability_resource {
            let normalized = normalize_audience(resource);
            if !normalized.is_empty() {
                allowed.insert(normalized);
            }
        }
        allowed
    }
}

#[derive(Debug, Clone)]
pub struct MicrosoftS2sBrokerOptions {
    pub authority_host: Url,
    pub refresh_skew: Duration,
}

impl Default for MicrosoftS2sBrokerOptions {
    fn default() -> Self {
        Self {
            authority_host: Url::parse(DEFAULT_AUTHORITY_HOST)
                .expect("default authority host should parse"),
            refresh_skew: DEFAULT_REFRESH_SKEW,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MicrosoftS2sBroker {
    config: Arc<MicrosoftS2sConfig>,
    client: reqwest::Client,
    authority_host: Url,
    refresh_skew: Duration,
    cache: Arc<Mutex<HashMap<CacheKey, CachedToken>>>,
}

impl MicrosoftS2sBroker {
    pub fn new(config: MicrosoftS2sConfig) -> Result<Self, MicrosoftS2sError> {
        Self::with_options(config, MicrosoftS2sBrokerOptions::default())
    }

    pub fn with_options(
        config: MicrosoftS2sConfig,
        options: MicrosoftS2sBrokerOptions,
    ) -> Result<Self, MicrosoftS2sError> {
        config.validate()?;
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| MicrosoftS2sError::TokenTransport(e.to_string()))?;
        Ok(Self {
            config: Arc::new(config),
            client,
            authority_host: options.authority_host,
            refresh_skew: options.refresh_skew,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn authorization_header(
        &self,
        audience: &str,
    ) -> Result<AuthorizationHeader, MicrosoftS2sError> {
        let token = self.access_token(audience).await?;
        Ok(AuthorizationHeader {
            value: format!("Bearer {}", token.access_token),
            expires_at_unix: token.expires_at_unix,
            cache_hit: token.cache_hit,
        })
    }

    pub async fn access_token(
        &self,
        audience: &str,
    ) -> Result<BrokeredAccessToken, MicrosoftS2sError> {
        let audience = normalize_audience(audience);
        self.ensure_allowed_audience(&audience)?;

        let cache_key = CacheKey {
            tenant_id: self.config.tenant_id.clone(),
            runtime_agent_id: self.config.runtime_agent_id.clone(),
            audience: audience.clone(),
        };

        if let Some(cached) = self.cached_token(&cache_key).await {
            return Ok(BrokeredAccessToken {
                access_token: cached.access_token,
                expires_at_unix: cached.expires_at_unix,
                cache_hit: true,
            });
        }

        let assertion = self.fetch_blueprint_assertion().await?;
        let token = self
            .fetch_runtime_agent_token(&audience, &assertion)
            .await?;
        self.validate_runtime_token_claims(&audience, &token.access_token)?;

        let expires_at = token.expires_at(self.refresh_skew);
        let expires_at_unix = token.expires_at_unix();
        let cached = CachedToken {
            access_token: token.access_token,
            expires_at,
            expires_at_unix,
        };
        self.cache.lock().await.insert(cache_key, cached.clone());

        Ok(BrokeredAccessToken {
            access_token: cached.access_token,
            expires_at_unix: cached.expires_at_unix,
            cache_hit: false,
        })
    }

    pub async fn evict(&self, audience: &str) {
        let cache_key = CacheKey {
            tenant_id: self.config.tenant_id.clone(),
            runtime_agent_id: self.config.runtime_agent_id.clone(),
            audience: normalize_audience(audience),
        };
        self.cache.lock().await.remove(&cache_key);
    }

    fn ensure_allowed_audience(&self, audience: &str) -> Result<(), MicrosoftS2sError> {
        let allowed = self.config.allowed_audience_set();
        if allowed.contains(audience) {
            Ok(())
        } else {
            Err(MicrosoftS2sError::AudienceDenied(audience.to_string()))
        }
    }

    async fn cached_token(&self, cache_key: &CacheKey) -> Option<CachedToken> {
        let cached = self.cache.lock().await.get(cache_key).cloned()?;
        if Instant::now() < cached.expires_at {
            Some(cached)
        } else {
            None
        }
    }

    async fn fetch_blueprint_assertion(&self) -> Result<TokenResponse, MicrosoftS2sError> {
        let endpoint = self.token_endpoint()?;
        let form = [
            ("grant_type", "client_credentials"),
            ("client_id", self.config.blueprint_client_id.as_str()),
            (
                "client_secret",
                self.config.blueprint_client_secret.as_str(),
            ),
            ("scope", AZURE_TOKEN_EXCHANGE_SCOPE),
            ("fmi_path", self.config.runtime_agent_id.as_str()),
        ];
        self.post_token_form(endpoint, &form).await
    }

    async fn fetch_runtime_agent_token(
        &self,
        audience: &str,
        assertion: &TokenResponse,
    ) -> Result<TokenResponse, MicrosoftS2sError> {
        let endpoint = self.token_endpoint()?;
        let scope = default_scope_for_audience(audience);
        let form = [
            ("grant_type", "client_credentials"),
            ("client_id", self.config.runtime_agent_id.as_str()),
            ("client_assertion", assertion.access_token.as_str()),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE_JWT_BEARER),
            ("scope", scope.as_str()),
        ];
        self.post_token_form(endpoint, &form).await
    }

    async fn post_token_form(
        &self,
        endpoint: Url,
        form: &[(&str, &str)],
    ) -> Result<TokenResponse, MicrosoftS2sError> {
        let response = self
            .client
            .post(endpoint)
            .form(form)
            .send()
            .await
            .map_err(|e| MicrosoftS2sError::TokenTransport(e.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| MicrosoftS2sError::TokenTransport(e.to_string()))?;

        if !status.is_success() {
            return Err(MicrosoftS2sError::TokenHttp {
                status,
                body: sanitize_error_body(&body),
            });
        }

        let parsed = serde_json::from_str::<TokenResponse>(&body).map_err(|e| {
            MicrosoftS2sError::TokenTransport(format!("failed to parse token response: {e}"))
        })?;
        if parsed.access_token.trim().is_empty() {
            return Err(MicrosoftS2sError::MissingAccessToken);
        }
        Ok(parsed)
    }

    fn token_endpoint(&self) -> Result<Url, MicrosoftS2sError> {
        self.authority_host
            .join(&format!(
                "{}/oauth2/v2.0/token",
                self.config.tenant_id.trim_matches('/')
            ))
            .map_err(|e| MicrosoftS2sError::Url(e.to_string()))
    }

    fn validate_runtime_token_claims(
        &self,
        audience: &str,
        token: &str,
    ) -> Result<(), MicrosoftS2sError> {
        let claims = JwtClaims::decode_unverified(token)?;
        claims.expect_audience(audience)?;
        claims.expect_tenant(&self.config.tenant_id)?;
        claims.expect_runtime_agent(&self.config.runtime_agent_id)?;
        claims.expect_app_token()?;
        claims.expect_roles(&self.config.required_roles)?;
        claims.expect_not_expired()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationHeader {
    pub value: String,
    pub expires_at_unix: Option<u64>,
    pub cache_hit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokeredAccessToken {
    pub access_token: String,
    pub expires_at_unix: Option<u64>,
    pub cache_hit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    tenant_id: String,
    runtime_agent_id: String,
    audience: String,
}

#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: Instant,
    expires_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<u64>,
    #[serde(default)]
    expires_on: Option<String>,
}

impl TokenResponse {
    fn expires_at(&self, refresh_skew: Duration) -> Instant {
        let ttl = self.expires_in.unwrap_or(3600);
        let ttl = Duration::from_secs(ttl);
        Instant::now() + ttl.saturating_sub(refresh_skew)
    }

    fn expires_at_unix(&self) -> Option<u64> {
        if let Some(expires_on) = &self.expires_on
            && let Ok(value) = expires_on.parse::<u64>()
        {
            return Some(value);
        }
        let expires_in = self.expires_in?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        Some(now.saturating_add(expires_in))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct JwtClaims {
    #[serde(default)]
    aud: AudienceClaim,
    #[serde(default)]
    tid: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    appid: Option<String>,
    #[serde(default)]
    oid: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    idtyp: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    scp: Option<String>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
}

impl JwtClaims {
    fn decode_unverified(token: &str) -> Result<Self, MicrosoftS2sError> {
        let mut parts = token.split('.');
        let _header = parts.next();
        let payload = parts
            .next()
            .ok_or_else(|| MicrosoftS2sError::ClaimValidation("token is not a JWT".to_string()))?;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
            .map_err(|e| {
                MicrosoftS2sError::ClaimValidation(format!("token payload decode failed: {e}"))
            })?;
        serde_json::from_slice(&decoded).map_err(|e| {
            MicrosoftS2sError::ClaimValidation(format!("token payload parse failed: {e}"))
        })
    }

    fn expect_audience(&self, audience: &str) -> Result<(), MicrosoftS2sError> {
        if self
            .aud
            .values()
            .iter()
            .any(|actual| normalize_audience(actual) == audience)
        {
            Ok(())
        } else {
            Err(MicrosoftS2sError::ClaimValidation(format!(
                "audience claim does not include '{audience}'"
            )))
        }
    }

    fn expect_tenant(&self, tenant_id: &str) -> Result<(), MicrosoftS2sError> {
        match self.tid.as_deref() {
            Some(actual) if actual.eq_ignore_ascii_case(tenant_id) => Ok(()),
            Some(actual) => Err(MicrosoftS2sError::ClaimValidation(format!(
                "tenant claim '{actual}' does not match expected tenant"
            ))),
            None => Err(MicrosoftS2sError::ClaimValidation(
                "missing tenant claim".to_string(),
            )),
        }
    }

    fn expect_runtime_agent(&self, runtime_agent_id: &str) -> Result<(), MicrosoftS2sError> {
        let expected = runtime_agent_id.to_ascii_lowercase();
        let matches = [&self.azp, &self.appid, &self.oid, &self.sub]
            .into_iter()
            .flatten()
            .any(|value| value.to_ascii_lowercase() == expected);
        if matches {
            Ok(())
        } else {
            Err(MicrosoftS2sError::ClaimValidation(
                "token does not represent the runtime agent identity".to_string(),
            ))
        }
    }

    fn expect_app_token(&self) -> Result<(), MicrosoftS2sError> {
        match self.idtyp.as_deref() {
            Some("app") => Ok(()),
            Some(actual) => Err(MicrosoftS2sError::ClaimValidation(format!(
                "expected app token, got idtyp='{actual}'"
            ))),
            None => Err(MicrosoftS2sError::ClaimValidation(
                "missing idtyp claim".to_string(),
            )),
        }
    }

    fn expect_roles(&self, required_roles: &[String]) -> Result<(), MicrosoftS2sError> {
        for required in required_roles {
            if !self.roles.iter().any(|role| role == required) {
                return Err(MicrosoftS2sError::ClaimValidation(format!(
                    "missing required role '{required}'"
                )));
            }
        }
        Ok(())
    }

    fn expect_not_expired(&self) -> Result<(), MicrosoftS2sError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MicrosoftS2sError::ClaimValidation(e.to_string()))?
            .as_secs();
        if let Some(nbf) = self.nbf
            && now.saturating_add(60) < nbf
        {
            return Err(MicrosoftS2sError::ClaimValidation(
                "token is not valid yet".to_string(),
            ));
        }
        if let Some(exp) = self.exp
            && exp <= now.saturating_sub(60)
        {
            return Err(MicrosoftS2sError::ClaimValidation(
                "token is expired".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
    #[default]
    Missing,
}

impl AudienceClaim {
    fn values(&self) -> Vec<&str> {
        match self {
            Self::One(value) => vec![value.as_str()],
            Self::Many(values) => values.iter().map(String::as_str).collect(),
            Self::Missing => Vec::new(),
        }
    }
}

fn require_non_empty(name: &str, value: &str) -> Result<(), MicrosoftS2sError> {
    if value.trim().is_empty() {
        Err(MicrosoftS2sError::InvalidConfig(format!(
            "{name} is required"
        )))
    } else {
        Ok(())
    }
}

fn normalize_audience(input: &str) -> String {
    input
        .trim()
        .trim_end_matches("/.default")
        .trim_end_matches('/')
        .to_string()
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn default_scope_for_audience(audience: &str) -> String {
    format!("{}/.default", normalize_audience(audience))
}

fn sanitize_error_body(body: &str) -> String {
    const MAX_ERROR_BODY: usize = 1024;
    body.chars()
        .filter(|ch| !ch.is_control() || *ch == '\n' || *ch == '\t')
        .take(MAX_ERROR_BODY)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TENANT: &str = "11111111-1111-4111-8111-111111111111";
    const BLUEPRINT: &str = "22222222-2222-4222-8222-222222222222";
    const RUNTIME_AGENT: &str = "33333333-3333-4333-8333-333333333333";
    const RESOURCE: &str = "api://44444444-4444-4444-8444-444444444444";

    fn config() -> MicrosoftS2sConfig {
        MicrosoftS2sConfig {
            tenant_id: TENANT.to_string(),
            blueprint_client_id: BLUEPRINT.to_string(),
            blueprint_client_secret: "secret".to_string(),
            runtime_agent_id: RUNTIME_AGENT.to_string(),
            allowed_audiences: vec![RESOURCE.to_string()],
            observability_resource: None,
            required_roles: vec!["Agent365.Observability.OtelWrite".to_string()],
        }
    }

    fn broker(server: &FakeTokenServer) -> MicrosoftS2sBroker {
        MicrosoftS2sBroker::with_options(
            config(),
            MicrosoftS2sBrokerOptions {
                authority_host: Url::parse(&server.uri()).expect("fake server URL"),
                refresh_skew: Duration::from_secs(60),
            },
        )
        .expect("broker")
    }

    fn jwt(claims: serde_json::Value) -> String {
        let header = serde_json::json!({"alg": "none", "typ": "JWT"});
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        format!("{header}.{payload}.signature")
    }

    fn runtime_token() -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        jwt(serde_json::json!({
            "aud": RESOURCE,
            "tid": TENANT,
            "azp": RUNTIME_AGENT,
            "oid": RUNTIME_AGENT,
            "sub": RUNTIME_AGENT,
            "idtyp": "app",
            "roles": ["Agent365.Observability.OtelWrite"],
            "nbf": now.saturating_sub(30),
            "exp": now + 3600
        }))
    }

    #[test]
    fn builds_config_from_provider_maps() {
        let credentials = HashMap::from([
            ("AZURE_TENANT_ID".to_string(), TENANT.to_string()),
            (
                "A365_BLUEPRINT_CLIENT_SECRET".to_string(),
                "secret".to_string(),
            ),
        ]);
        let config = HashMap::from([
            (
                "A365_BLUEPRINT_CLIENT_ID".to_string(),
                BLUEPRINT.to_string(),
            ),
            (
                "A365_RUNTIME_AGENT_ID".to_string(),
                RUNTIME_AGENT.to_string(),
            ),
            (
                "A365_ALLOWED_AUDIENCES".to_string(),
                format!("{RESOURCE}, api://extra/.default"),
            ),
            (
                "A365_REQUIRED_ROLES".to_string(),
                "Agent365.Observability.OtelWrite".to_string(),
            ),
        ]);

        let cfg = MicrosoftS2sConfig::from_provider_maps(&credentials, &config)
            .expect("provider maps should build config");

        assert_eq!(cfg.tenant_id, TENANT);
        assert_eq!(cfg.blueprint_client_id, BLUEPRINT);
        assert_eq!(cfg.blueprint_client_secret, "secret");
        assert_eq!(cfg.runtime_agent_id, RUNTIME_AGENT);
        assert_eq!(
            cfg.allowed_audiences,
            vec![RESOURCE.to_string(), "api://extra/.default".to_string()]
        );
        assert_eq!(
            cfg.required_roles,
            vec!["Agent365.Observability.OtelWrite".to_string()]
        );
    }

    #[derive(Debug, Default)]
    struct FakeTokenState {
        runtime_token: Mutex<String>,
        blueprint_requests: Mutex<usize>,
        runtime_requests: Mutex<usize>,
    }

    #[derive(Clone)]
    struct FakeTokenServer {
        addr: SocketAddr,
        state: Arc<FakeTokenState>,
    }

    impl FakeTokenServer {
        async fn start(runtime_token: String) -> Self {
            let state = Arc::new(FakeTokenState {
                runtime_token: Mutex::new(runtime_token),
                blueprint_requests: Mutex::new(0),
                runtime_requests: Mutex::new(0),
            });
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind fake token server");
            let addr = listener.local_addr().expect("fake token server addr");
            let server_state = state.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _peer)) = listener.accept().await else {
                        break;
                    };
                    let state = server_state.clone();
                    tokio::spawn(async move {
                        handle_token_connection(stream, state).await;
                    });
                }
            });
            Self { addr, state }
        }

        fn uri(&self) -> String {
            format!("http://{}", self.addr)
        }

        async fn request_counts(&self) -> (usize, usize) {
            (
                *self.state.blueprint_requests.lock().await,
                *self.state.runtime_requests.lock().await,
            )
        }
    }

    async fn handle_token_connection(
        mut stream: tokio::net::TcpStream,
        state: Arc<FakeTokenState>,
    ) {
        let mut buffer = Vec::new();
        let mut temp = [0_u8; 1024];
        let mut content_length = None;
        let mut header_end = None;

        loop {
            let read = stream.read(&mut temp).await.expect("read fake request");
            if read == 0 {
                return;
            }
            buffer.extend_from_slice(&temp[..read]);
            if header_end.is_none()
                && let Some(pos) = find_header_end(&buffer)
            {
                header_end = Some(pos);
                let headers = String::from_utf8_lossy(&buffer[..pos]);
                content_length = parse_content_length(&headers);
            }
            if let (Some(end), Some(len)) = (header_end, content_length)
                && buffer.len() >= end + 4 + len
            {
                break;
            }
        }

        let end = header_end.expect("headers should be present");
        let len = content_length.expect("content length should be present");
        let body = &buffer[end + 4..end + 4 + len];
        let form = url::form_urlencoded::parse(body)
            .into_owned()
            .collect::<HashMap<String, String>>();
        let response = token_response_for_form(&state, &form).await;
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write fake response");
    }

    async fn token_response_for_form(
        state: &Arc<FakeTokenState>,
        form: &HashMap<String, String>,
    ) -> String {
        if form
            .get("client_id")
            .is_some_and(|value| value == BLUEPRINT)
        {
            assert_eq!(
                form.get("grant_type").map(String::as_str),
                Some("client_credentials")
            );
            assert_eq!(
                form.get("scope").map(String::as_str),
                Some(AZURE_TOKEN_EXCHANGE_SCOPE)
            );
            assert_eq!(
                form.get("fmi_path").map(String::as_str),
                Some(RUNTIME_AGENT)
            );
            *state.blueprint_requests.lock().await += 1;
            return json_response(
                200,
                serde_json::json!({
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "access_token": "blueprint-assertion"
                }),
            );
        }

        if form
            .get("client_id")
            .is_some_and(|value| value == RUNTIME_AGENT)
        {
            assert_eq!(
                form.get("grant_type").map(String::as_str),
                Some("client_credentials")
            );
            assert_eq!(
                form.get("client_assertion").map(String::as_str),
                Some("blueprint-assertion")
            );
            assert_eq!(
                form.get("client_assertion_type").map(String::as_str),
                Some(CLIENT_ASSERTION_TYPE_JWT_BEARER)
            );
            let expected_scope = format!("{RESOURCE}/.default");
            assert_eq!(
                form.get("scope").map(String::as_str),
                Some(expected_scope.as_str())
            );
            *state.runtime_requests.lock().await += 1;
            let runtime_token = state.runtime_token.lock().await.clone();
            return json_response(
                200,
                serde_json::json!({
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "access_token": runtime_token
                }),
            );
        }

        json_response(
            400,
            serde_json::json!({"error": "unexpected token request"}),
        )
    }

    fn find_header_end(buffer: &[u8]) -> Option<usize> {
        buffer.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn parse_content_length(headers: &str) -> Option<usize> {
        headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
    }

    fn json_response(status: u16, body: serde_json::Value) -> String {
        let reason = if status == 200 { "OK" } else { "Bad Request" };
        let body = body.to_string();
        format!(
            "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn mints_runtime_agent_token_with_two_step_exchange() {
        let runtime_token = runtime_token();
        let server = FakeTokenServer::start(runtime_token.clone()).await;

        let token = broker(&server)
            .access_token(RESOURCE)
            .await
            .expect("token should mint");

        assert_eq!(token.access_token, runtime_token);
        assert!(!token.cache_hit);
        assert!(token.expires_at_unix.is_some());
        assert_eq!(server.request_counts().await, (1, 1));
    }

    #[tokio::test]
    async fn returns_cached_token_for_same_audience() {
        let runtime_token = runtime_token();
        let server = FakeTokenServer::start(runtime_token.clone()).await;
        let broker = broker(&server);

        let first = broker.access_token(RESOURCE).await.expect("first token");
        let second = broker.access_token(RESOURCE).await.expect("cached token");

        assert_eq!(first.access_token, second.access_token);
        assert!(!first.cache_hit);
        assert!(second.cache_hit);
        assert_eq!(server.request_counts().await, (1, 1));
    }

    #[tokio::test]
    async fn rejects_unallowed_audience_before_network_call() {
        let server = FakeTokenServer::start(runtime_token()).await;
        let err = broker(&server)
            .access_token("api://not-allowed")
            .await
            .expect_err("audience should be denied");

        assert!(matches!(err, MicrosoftS2sError::AudienceDenied(_)));
        assert_eq!(server.request_counts().await, (0, 0));
    }

    #[tokio::test]
    async fn validates_runtime_agent_claims() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let wrong_agent_token = jwt(serde_json::json!({
            "aud": RESOURCE,
            "tid": TENANT,
            "azp": "a185cf21-03c8-4bf1-919a-ec8f0782118d",
            "idtyp": "app",
            "nbf": now.saturating_sub(30),
            "exp": now + 3600
        }));
        let server = FakeTokenServer::start(wrong_agent_token).await;

        let err = broker(&server)
            .access_token(RESOURCE)
            .await
            .expect_err("wrong runtime agent should fail validation");

        assert!(matches!(err, MicrosoftS2sError::ClaimValidation(_)));
        assert!(
            err.to_string().contains("runtime agent identity"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn validates_required_roles() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let missing_role_token = jwt(serde_json::json!({
            "aud": RESOURCE,
            "tid": TENANT,
            "azp": RUNTIME_AGENT,
            "oid": RUNTIME_AGENT,
            "sub": RUNTIME_AGENT,
            "idtyp": "app",
            "roles": ["Other.Role"],
            "nbf": now.saturating_sub(30),
            "exp": now + 3600
        }));
        let server = FakeTokenServer::start(missing_role_token).await;

        let err = broker(&server)
            .access_token(RESOURCE)
            .await
            .expect_err("missing required role should fail validation");

        assert!(matches!(err, MicrosoftS2sError::ClaimValidation(_)));
        assert!(
            err.to_string().contains("missing required role"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn returns_authorization_header() {
        let server = FakeTokenServer::start(runtime_token()).await;

        let header = broker(&server)
            .authorization_header(RESOURCE)
            .await
            .expect("authorization header");

        assert!(header.value.starts_with("Bearer "));
        assert!(!header.cache_hit);
    }
}
