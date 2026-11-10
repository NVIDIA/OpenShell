// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stateless built-in credential minting and safe upstream error classification.

#![allow(clippy::result_large_err)]

use async_trait::async_trait;
use openshell_core::proto::{
    ProviderCredentialRefreshRecoveryAction, ProviderCredentialRefreshStrategy,
};
use openshell_core::time::now_ms as current_time_ms;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tonic::{Code, Status};
use tracing::warn;

const DEFAULT_REFRESH_BEFORE_SECONDS: i64 = 300;
const DEFAULT_MAX_LIFETIME_SECONDS: i64 = 3600;
const MAX_OAUTH_ERROR_RESPONSE_BYTES: usize = 8 * 1024;

/// Owned, resolved input for one upstream exchange. Intentionally has no Debug
/// or serialization implementation because material contains plaintext secrets.
#[derive(Clone, Default)]
pub struct MintRequest {
    pub strategy: i32,
    pub material: HashMap<String, String>,
    pub token_url: String,
    pub scopes: Vec<String>,
    pub max_lifetime: Option<prost_types::Duration>,
    pub additional_output_keys: HashMap<String, String>,
}

/// Transient mint output. Intentionally has no Debug or serialization implementation.
pub struct MintedCredential {
    pub access_token: String,
    pub expires_at_ms: i64,
    pub refresh_token: Option<String>,
    pub additional_credentials: HashMap<String, String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuthErrorResponse {
    error: String,
    #[serde(default, deserialize_with = "deserialize_optional_oauth_string")]
    error_subtype: Option<String>,
}

fn deserialize_optional_oauth_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(value.as_str().map(str::to_owned))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OAuthGrantKind {
    UserRefreshToken,
    NonInteractive,
}

#[derive(Debug)]
pub struct RefreshFailure {
    pub status: Status,
    pub recovery_action: ProviderCredentialRefreshRecoveryAction,
    pub failure_code: &'static str,
    pub provider_error_subtype: Option<&'static str>,
    pub retry_schedule: RefreshRetrySchedule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshRetrySchedule {
    Short,
    Configuration,
    Parked,
}

impl RefreshFailure {
    pub fn retryable(status: Status, failure_code: &'static str) -> Self {
        Self {
            status,
            recovery_action: ProviderCredentialRefreshRecoveryAction::Retry,
            failure_code,
            provider_error_subtype: None,
            retry_schedule: RefreshRetrySchedule::Short,
        }
    }

    pub fn investigate(status: Status, failure_code: &'static str) -> Self {
        Self {
            status,
            recovery_action: ProviderCredentialRefreshRecoveryAction::Investigate,
            failure_code,
            provider_error_subtype: None,
            retry_schedule: RefreshRetrySchedule::Short,
        }
    }

    pub fn reauthorize(
        status: Status,
        failure_code: &'static str,
        provider_error_subtype: Option<&'static str>,
    ) -> Self {
        Self {
            status,
            recovery_action: ProviderCredentialRefreshRecoveryAction::Reauthorize,
            failure_code,
            provider_error_subtype,
            retry_schedule: RefreshRetrySchedule::Parked,
        }
    }

    pub fn fix_configuration(status: Status, failure_code: &'static str) -> Self {
        Self {
            status,
            recovery_action: ProviderCredentialRefreshRecoveryAction::FixConfiguration,
            failure_code,
            provider_error_subtype: None,
            retry_schedule: RefreshRetrySchedule::Configuration,
        }
    }

    pub fn fix_configuration_with_subtype(
        status: Status,
        failure_code: &'static str,
        provider_error_subtype: &'static str,
    ) -> Self {
        Self {
            status,
            recovery_action: ProviderCredentialRefreshRecoveryAction::FixConfiguration,
            failure_code,
            provider_error_subtype: Some(provider_error_subtype),
            retry_schedule: RefreshRetrySchedule::Configuration,
        }
    }

    pub fn into_status(self) -> Status {
        self.status
    }

    pub fn from_status(status: &Status) -> Self {
        Self::from(Status::new(status.code(), status.message().to_string()))
    }
}

impl From<Status> for RefreshFailure {
    fn from(status: Status) -> Self {
        match status.code() {
            Code::InvalidArgument
            | Code::FailedPrecondition
            | Code::PermissionDenied
            | Code::Unauthenticated => {
                Self::fix_configuration(status, "refresh_configuration_invalid")
            }
            Code::Unavailable
            | Code::DeadlineExceeded
            | Code::ResourceExhausted
            | Code::Aborted
            | Code::Internal => Self::retryable(status, "refresh_failed"),
            _ => Self::investigate(status, "refresh_failed"),
        }
    }
}

#[derive(Debug, Serialize)]
struct GoogleServiceAccountClaims<'a> {
    iss: &'a str,
    scope: String,
    aud: &'a str,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<&'a str>,
}

pub fn next_refresh_at_ms(
    expires_at_ms: i64,
    refresh_before: Option<&prost_types::Duration>,
) -> i64 {
    let refresh_before = refresh_before
        .and_then(|value| openshell_core::time::duration_to_std(value).ok())
        .unwrap_or_else(|| {
            Duration::from_secs(u64::try_from(DEFAULT_REFRESH_BEFORE_SECONDS).unwrap_or(u64::MAX))
        });
    let refresh_before_ms = refresh_before.as_millis().saturating_add(u128::from(
        !refresh_before.subsec_nanos().is_multiple_of(1_000_000),
    ));
    let refresh_before_ms = i64::try_from(refresh_before_ms).unwrap_or(i64::MAX);
    if expires_at_ms > 0 {
        return expires_at_ms.saturating_sub(refresh_before_ms);
    }
    0
}

// OAuth/JWT expiry fields use whole seconds. Round an exact positive profile
// duration up only at that protocol boundary so a fractional lifetime never
// collapses into the absent/default sentinel.
fn max_lifetime_seconds(state: &MintRequest) -> i64 {
    let Some(value) = state.max_lifetime.as_ref() else {
        return DEFAULT_MAX_LIFETIME_SECONDS;
    };
    let Ok(duration) = openshell_core::time::duration_to_std(value) else {
        return DEFAULT_MAX_LIFETIME_SECONDS;
    };
    let seconds = duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() != 0));
    i64::try_from(seconds).unwrap_or(i64::MAX).max(1)
}

pub fn refresh_strategy_name(strategy: i32) -> &'static str {
    match ProviderCredentialRefreshStrategy::try_from(strategy)
        .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified)
    {
        ProviderCredentialRefreshStrategy::Static => "static",
        ProviderCredentialRefreshStrategy::External => "external",
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken => "oauth2_refresh_token",
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials => "oauth2_client_credentials",
        ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt => "google_service_account_jwt",
        ProviderCredentialRefreshStrategy::AwsStsAssumeRole => "aws_sts_assume_role",
        ProviderCredentialRefreshStrategy::Unspecified => "unspecified",
    }
}

/// Secret source-material fields that are security-sensitive by strategy even
/// when a direct API caller omits `secret_material_keys`.
pub fn strategy_secret_material_keys(
    strategy: ProviderCredentialRefreshStrategy,
) -> &'static [&'static str] {
    match strategy {
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken => {
            &["refresh_token", "client_secret"]
        }
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials => &["client_secret"],
        ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt => &["private_key"],
        ProviderCredentialRefreshStrategy::AwsStsAssumeRole => {
            &["aws_secret_access_key", "aws_session_token"]
        }
        ProviderCredentialRefreshStrategy::Static
        | ProviderCredentialRefreshStrategy::External
        | ProviderCredentialRefreshStrategy::Unspecified => &[],
    }
}

/// One stateless upstream exchange. Persistence, retries and staging belong to
/// the refresh engine, not to minters.
#[async_trait]
pub trait TokenMinter: Send + Sync {
    async fn mint(&self, request: &MintRequest) -> Result<MintedCredential, RefreshFailure>;
}

struct OAuth2RefreshToken;
struct OAuth2ClientCredentials;
struct GoogleServiceAccountJwt;
struct AwsStsAssumeRole;

#[async_trait]
impl TokenMinter for OAuth2RefreshToken {
    async fn mint(&self, request: &MintRequest) -> Result<MintedCredential, RefreshFailure> {
        mint_oauth2_refresh_token(request).await
    }
}

#[async_trait]
impl TokenMinter for OAuth2ClientCredentials {
    async fn mint(&self, request: &MintRequest) -> Result<MintedCredential, RefreshFailure> {
        mint_oauth2_client_credentials(request).await
    }
}

#[async_trait]
impl TokenMinter for GoogleServiceAccountJwt {
    async fn mint(&self, request: &MintRequest) -> Result<MintedCredential, RefreshFailure> {
        mint_google_service_account_jwt(request).await
    }
}

#[async_trait]
impl TokenMinter for AwsStsAssumeRole {
    async fn mint(&self, request: &MintRequest) -> Result<MintedCredential, RefreshFailure> {
        mint_aws_sts_assume_role(request).await
    }
}

/// Immutable built-in-only registry. There is deliberately no registration API.
pub struct BuiltInMinterRegistry {
    entries: [(&'static str, &'static dyn TokenMinter); 4],
}

static BUILT_IN_MINTERS: BuiltInMinterRegistry = BuiltInMinterRegistry {
    entries: [
        ("oauth2_refresh_token", &OAuth2RefreshToken),
        ("oauth2_client_credentials", &OAuth2ClientCredentials),
        ("google_service_account_jwt", &GoogleServiceAccountJwt),
        ("aws_sts_assume_role", &AwsStsAssumeRole),
    ],
};

impl BuiltInMinterRegistry {
    pub fn lookup(&self, strategy_name: &str) -> Option<&'static dyn TokenMinter> {
        self.entries
            .iter()
            .find_map(|(name, minter)| (*name == strategy_name).then_some(*minter))
    }

    pub fn can_mint(&self, strategy: i32) -> bool {
        self.lookup(refresh_strategy_name(strategy)).is_some()
    }

    pub fn strategy_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.entries.iter().map(|(name, _)| *name)
    }
}

pub fn built_in_minters() -> &'static BuiltInMinterRegistry {
    &BUILT_IN_MINTERS
}

pub fn can_mint(strategy: i32) -> bool {
    built_in_minters().can_mint(strategy)
}

pub async fn mint_credential(request: &MintRequest) -> Result<MintedCredential, RefreshFailure> {
    if let Some(minter) = built_in_minters().lookup(refresh_strategy_name(request.strategy)) {
        return minter.mint(request).await;
    }
    let strategy = ProviderCredentialRefreshStrategy::try_from(request.strategy)
        .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
    Err(Status::failed_precondition(format!(
        "refresh strategy '{strategy:?}' cannot be minted by the gateway"
    ))
    .into())
}

async fn mint_oauth2_refresh_token(
    state: &MintRequest,
) -> Result<MintedCredential, RefreshFailure> {
    let token_url = oauth2_token_url(state)?;
    let client_id = required_material(&state.material, "client_id")?;
    let refresh_token = required_material(&state.material, "refresh_token")?;
    let mut form = vec![
        ("grant_type".to_string(), "refresh_token".to_string()),
        ("client_id".to_string(), client_id),
        ("refresh_token".to_string(), refresh_token),
    ];
    if let Some(client_secret) = material_value(&state.material, &["client_secret"]) {
        form.push(("client_secret".to_string(), client_secret));
    }
    let scope = refresh_scopes(state).join(" ");
    if !scope.is_empty() {
        form.push(("scope".to_string(), scope));
    }

    request_token(
        &token_url,
        &form,
        max_lifetime_seconds(state),
        OAuthGrantKind::UserRefreshToken,
    )
    .await
}

async fn mint_oauth2_client_credentials(
    state: &MintRequest,
) -> Result<MintedCredential, RefreshFailure> {
    let token_url = oauth2_token_url(state)?;
    let client_id = required_material(&state.material, "client_id")?;
    let client_secret = required_material(&state.material, "client_secret")?;
    let mut form = vec![
        ("grant_type".to_string(), "client_credentials".to_string()),
        ("client_id".to_string(), client_id),
        ("client_secret".to_string(), client_secret),
    ];
    let scope = refresh_scopes(state).join(" ");
    if !scope.is_empty() {
        form.push(("scope".to_string(), scope));
    }

    request_token(
        &token_url,
        &form,
        max_lifetime_seconds(state),
        OAuthGrantKind::NonInteractive,
    )
    .await
}

async fn mint_google_service_account_jwt(
    state: &MintRequest,
) -> Result<MintedCredential, RefreshFailure> {
    openshell_crypto::install_jwt_provider();
    let token_url = google_token_url(state);
    let client_email = required_material(&state.material, "client_email")?;
    let private_key = required_material(&state.material, "private_key")?;
    let scopes = refresh_scopes(state);
    if scopes.is_empty() {
        return Err(Status::invalid_argument(
            "google_service_account_jwt requires at least one scope",
        )
        .into());
    }
    let now_ms = current_time_ms();
    let now_secs = now_ms / 1000;
    let lifetime_secs = max_lifetime_seconds(state).min(DEFAULT_MAX_LIFETIME_SECONDS);
    let subject = material_value(&state.material, &["subject", "sub"]);
    let claims = GoogleServiceAccountClaims {
        iss: &client_email,
        scope: scopes.join(" "),
        aud: &token_url,
        iat: now_secs,
        exp: now_secs.saturating_add(lifetime_secs),
        sub: subject.as_deref(),
    };
    let assertion = openshell_crypto::jwt::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes()).map_err(|_| {
            Status::invalid_argument("google_service_account_jwt private_key must be RSA PEM")
        })?,
    )
    .map_err(|_| Status::internal("sign google service account jwt failed"))?;
    let form = vec![
        (
            "grant_type".to_string(),
            "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
        ),
        ("assertion".to_string(), assertion),
    ];
    request_token(
        &token_url,
        &form,
        lifetime_secs,
        OAuthGrantKind::NonInteractive,
    )
    .await
}

async fn mint_aws_sts_assume_role(state: &MintRequest) -> Result<MintedCredential, RefreshFailure> {
    let role_arn = required_material(&state.material, "role_arn")?;
    let session_name = material_value(&state.material, &["session_name"])
        .unwrap_or_else(|| "openshell-sandbox".to_string());
    let external_id = material_value(&state.material, &["external_id"]);
    let region =
        material_value(&state.material, &["aws_region"]).unwrap_or_else(|| "us-east-1".to_string());

    let region_provider = aws_sdk_sts::config::Region::new(region);
    let mut config_loader =
        aws_config::defaults(aws_config::BehaviorVersion::latest()).region(region_provider);

    // Explicit source credentials are all-or-nothing. A lone key must not
    // silently fall through to the gateway's ambient identity (CWE-20): the
    // caller asked for a specific principal, so an incomplete pair is an error.
    // An optional session token supports temporary source credentials (SSO or a
    // prior AssumeRole); it requires the access/secret pair.
    let session_token = material_value(&state.material, &["aws_session_token"]);
    match (
        material_value(&state.material, &["aws_access_key_id"]),
        material_value(&state.material, &["aws_secret_access_key"]),
    ) {
        (Some(access_key), Some(secret_key)) => {
            let creds = aws_sdk_sts::config::Credentials::new(
                access_key,
                secret_key,
                session_token,
                None,
                "openshell-provider-refresh",
            );
            config_loader = config_loader.credentials_provider(creds);
        }
        (None, None) if session_token.is_some() => {
            return Err(Status::invalid_argument(
                "aws_session_token requires aws_access_key_id and aws_secret_access_key",
            )
            .into());
        }
        (None, None) => {}
        _ => {
            return Err(Status::invalid_argument(
                "aws_access_key_id and aws_secret_access_key must both be set or both omitted",
            )
            .into());
        }
    }

    let sdk_config = config_loader.load().await;
    let sts_config = {
        let mut builder = aws_sdk_sts::config::Builder::from(&sdk_config);
        // Endpoint overrides exist only to point tests at a local mock STS. In
        // production the endpoint is always resolved from the region so a caller
        // cannot redirect an AWS-signed AssumeRole request at an arbitrary
        // service (CWE-918). See `test_sts_endpoint_override`.
        if let Some(endpoint) = test_sts_endpoint_override(state) {
            builder = builder.endpoint_url(endpoint);
        }
        builder.build()
    };
    let client = aws_sdk_sts::Client::from_conf(sts_config);

    let max_lifetime_i64 = max_lifetime_seconds(state);
    let max_lifetime = i32::try_from(max_lifetime_i64.min(i64::from(i32::MAX))).unwrap_or(i32::MAX);
    let max_lifetime_ms = i64::from(max_lifetime).saturating_mul(1000);

    let mut req = client
        .assume_role()
        .role_arn(&role_arn)
        .role_session_name(&session_name)
        .duration_seconds(max_lifetime);

    if let Some(eid) = external_id {
        req = req.external_id(eid);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| Status::internal(format!("STS AssumeRole failed: {e}")))?;

    let creds = resp
        .credentials()
        .ok_or_else(|| Status::internal("STS AssumeRole response missing credentials"))?;

    let access_key_id = creds.access_key_id().to_string();
    let secret_access_key = creds.secret_access_key().to_string();
    let session_token = creds.session_token().to_string();

    let now_ms = current_time_ms();
    let max_expires = now_ms.saturating_add(max_lifetime_ms);
    let expires_at_ms = creds.expiration().to_millis().unwrap_or(max_expires);
    let expires_at_ms = expires_at_ms.min(max_expires);

    // Map STS response fields to the env keys the profile bound to each semantic
    // output. Configure pins these from the profile's additional_outputs, so a
    // missing mapping means the state was not configured against a valid AWS STS
    // profile binding; refuse rather than guessing standard AWS names.
    let output_values = [
        ("secret_access_key", secret_access_key),
        ("session_token", session_token),
    ];
    let mut additional = HashMap::new();
    for (output_id, value) in output_values {
        let env_key = state.additional_output_keys.get(output_id).ok_or_else(|| {
            Status::failed_precondition(format!(
                "refresh state missing resolved output key for '{output_id}'; reconfigure the AWS STS refresh"
            ))
        })?;
        additional.insert(env_key.clone(), value);
    }

    Ok(MintedCredential {
        access_token: access_key_id,
        expires_at_ms,
        refresh_token: None,
        additional_credentials: additional,
    })
}

async fn request_token(
    token_url: &str,
    form: &[(String, String)],
    max_lifetime_seconds: i64,
    grant_kind: OAuthGrantKind,
) -> Result<MintedCredential, RefreshFailure> {
    let parsed = reqwest::Url::parse(token_url)
        .map_err(|_| Status::invalid_argument("token_url must be an absolute URL"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if parsed.host_str().is_some_and(is_loopback_host) => {}
        _ => {
            return Err(Status::invalid_argument(
                "token_url must use https, except loopback http for local tests",
            )
            .into());
        }
    }

    openshell_crypto::tls::ensure_default_provider();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| Status::internal(format!("build refresh HTTP client failed: {e}")))?;
    // GitHub returns form-encoded bodies unless JSON is requested.
    let response = client
        .post(parsed)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(form)
        .send()
        .await
        .map_err(|error| {
            let error_kind = if error.is_timeout() {
                "timeout"
            } else if error.is_connect() {
                "connect"
            } else if error.is_request() {
                "request"
            } else {
                "other"
            };
            warn!(
                error = %error.without_url(),
                error_kind,
                "OAuth token endpoint request failed"
            );
            if grant_kind == OAuthGrantKind::UserRefreshToken && error_kind != "connect" {
                RefreshFailure::reauthorize(
                    Status::failed_precondition(
                        "refresh token exchange has an uncertain outcome; reauthorize the grant",
                    ),
                    "oauth_refresh_exchange_uncertain",
                    None,
                )
            } else {
                RefreshFailure::retryable(
                    Status::unavailable("token endpoint request failed"),
                    "oauth_token_endpoint_unavailable",
                )
            }
        })?;
    let status = response.status();
    if !status.is_success() {
        let body = read_bounded_oauth_error_body(response).await;
        return Err(classify_oauth_token_error(status, &body, grant_kind));
    }
    let token = response.json::<TokenResponse>().await.map_err(|_| {
        if grant_kind == OAuthGrantKind::UserRefreshToken {
            return RefreshFailure::reauthorize(
                Status::failed_precondition(
                    "refresh token exchange returned an unusable response; reauthorize the grant",
                ),
                "oauth_refresh_exchange_uncertain",
                None,
            );
        }
        RefreshFailure::investigate(
            Status::failed_precondition("token endpoint returned invalid JSON"),
            "oauth_invalid_success_response",
        )
    })?;
    if token.access_token.trim().is_empty() {
        if grant_kind == OAuthGrantKind::UserRefreshToken {
            return Err(RefreshFailure::reauthorize(
                Status::failed_precondition(
                    "refresh token exchange returned no access token; reauthorize the grant",
                ),
                "oauth_refresh_exchange_uncertain",
                None,
            ));
        }
        return Err(RefreshFailure::investigate(
            Status::failed_precondition("token endpoint returned empty access_token"),
            "oauth_empty_access_token",
        ));
    }
    let now_ms = current_time_ms();
    let lifetime_cap_seconds = if max_lifetime_seconds > 0 {
        max_lifetime_seconds
    } else {
        DEFAULT_MAX_LIFETIME_SECONDS
    };
    let lifetime_seconds = token
        .expires_in
        .filter(|value| *value > 0)
        .unwrap_or(lifetime_cap_seconds);
    let lifetime_seconds = lifetime_seconds.min(lifetime_cap_seconds);
    Ok(MintedCredential {
        access_token: token.access_token,
        expires_at_ms: now_ms.saturating_add(lifetime_seconds.saturating_mul(1000)),
        refresh_token: token
            .refresh_token
            .filter(|refresh_token| !refresh_token.trim().is_empty()),
        additional_credentials: HashMap::new(),
    })
}

async fn read_bounded_oauth_error_body(mut response: reqwest::Response) -> Vec<u8> {
    let mut body = Vec::new();
    while body.len() < MAX_OAUTH_ERROR_RESPONSE_BYTES {
        let Ok(Some(chunk)) = response.chunk().await else {
            break;
        };
        let remaining = MAX_OAUTH_ERROR_RESPONSE_BYTES.saturating_sub(body.len());
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() >= remaining {
            break;
        }
    }
    body
}

fn classify_oauth_token_error(
    status: reqwest::StatusCode,
    body: &[u8],
    grant_kind: OAuthGrantKind,
) -> RefreshFailure {
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return RefreshFailure::retryable(
            Status::unavailable(format!("token endpoint returned HTTP {status}")),
            "oauth_token_endpoint_retryable",
        );
    }

    let Ok(error_response) = serde_json::from_slice::<OAuthErrorResponse>(body) else {
        return RefreshFailure::investigate(
            Status::failed_precondition(format!(
                "token endpoint returned HTTP {status} without a recognized OAuth error"
            )),
            "oauth_unrecognized_error_response",
        );
    };

    match error_response.error.as_str() {
        "invalid_grant" if grant_kind == OAuthGrantKind::UserRefreshToken => {
            let subtype = error_response
                .error_subtype
                .as_deref()
                .filter(|subtype| *subtype == "invalid_rapt")
                .map(|_| "invalid_rapt");
            let message = if subtype.is_some() {
                "OAuth refresh grant requires interactive reauthorization (invalid_grant/invalid_rapt)"
            } else {
                "OAuth refresh grant is no longer usable (invalid_grant); user reauthorization is required"
            };
            RefreshFailure::reauthorize(
                Status::failed_precondition(message),
                "oauth_invalid_grant",
                subtype,
            )
        }
        "invalid_client" => RefreshFailure::fix_configuration(
            Status::failed_precondition(
                "OAuth token endpoint rejected the client configuration (invalid_client)",
            ),
            "oauth_invalid_client",
        ),
        "unauthorized_client" => RefreshFailure::fix_configuration(
            Status::failed_precondition(
                "OAuth token endpoint rejected the client grant (unauthorized_client)",
            ),
            "oauth_unauthorized_client",
        ),
        "invalid_scope" => RefreshFailure::fix_configuration(
            Status::failed_precondition(
                "OAuth token endpoint rejected the configured scopes (invalid_scope)",
            ),
            "oauth_invalid_scope",
        ),
        "unsupported_grant_type" => RefreshFailure::fix_configuration(
            Status::failed_precondition(
                "OAuth token endpoint rejected the configured grant type (unsupported_grant_type)",
            ),
            "oauth_unsupported_grant_type",
        ),
        "admin_policy_enforced" => RefreshFailure::fix_configuration(
            Status::failed_precondition(
                "OAuth access is blocked by an administrator policy (admin_policy_enforced)",
            ),
            "oauth_admin_policy_enforced",
        ),
        "access_denied"
            if error_response.error_subtype.as_deref() == Some("admin_policy_enforced") =>
        {
            RefreshFailure::fix_configuration_with_subtype(
                Status::failed_precondition(
                    "OAuth access is blocked by an administrator policy (access_denied/admin_policy_enforced)",
                ),
                "oauth_admin_policy_enforced",
                "admin_policy_enforced",
            )
        }
        "access_denied" if grant_kind == OAuthGrantKind::UserRefreshToken => {
            RefreshFailure::reauthorize(
                Status::failed_precondition(
                    "OAuth access was denied; user reauthorization is required (access_denied)",
                ),
                "oauth_access_denied",
                None,
            )
        }
        "access_denied" => RefreshFailure::fix_configuration(
            Status::failed_precondition(
                "OAuth access was denied for the non-interactive grant (access_denied)",
            ),
            "oauth_access_denied",
        ),
        "invalid_grant" => RefreshFailure::fix_configuration(
            Status::failed_precondition(
                "OAuth token endpoint rejected the non-interactive grant (invalid_grant)",
            ),
            "oauth_invalid_grant",
        ),
        "server_error" | "temporarily_unavailable" => RefreshFailure::retryable(
            Status::unavailable("OAuth token endpoint reported a temporary failure"),
            "oauth_token_endpoint_retryable",
        ),
        _ => RefreshFailure::investigate(
            Status::failed_precondition(format!(
                "token endpoint returned HTTP {status} with an unrecognized OAuth error"
            )),
            "oauth_unrecognized_error",
        ),
    }
}

pub fn refresh_scopes(state: &MintRequest) -> Vec<String> {
    if !state.scopes.is_empty() {
        return state.scopes.clone();
    }
    material_scopes(&state.material)
}

pub fn material_scopes<S: std::hash::BuildHasher>(
    material: &HashMap<String, String, S>,
) -> Vec<String> {
    material_value(material, &["scope", "scopes"])
        .map(|raw| {
            raw.split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
                .map(str::trim)
                .filter(|scope| !scope.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn parse_material_i64<S: std::hash::BuildHasher>(
    material: &HashMap<String, String, S>,
    key: &str,
) -> Result<Option<i64>, Status> {
    let Some(value) = material_value(material, &[key]) else {
        return Ok(None);
    };
    value
        .parse::<i64>()
        .map(Some)
        .map_err(|_| Status::invalid_argument(format!("{key} material must be a signed integer")))
}

fn oauth2_token_url(state: &MintRequest) -> Result<String, Status> {
    if let Some(tenant_id) = material_value(&state.material, &["tenant_id"]) {
        return Ok(format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        ));
    }
    if !state.token_url.trim().is_empty() {
        return Ok(state.token_url.clone());
    }
    Err(Status::invalid_argument(
        "oauth2_client_credentials requires token_url or tenant_id material",
    ))
}

fn google_token_url(state: &MintRequest) -> String {
    if state.token_url.trim().is_empty() {
        "https://oauth2.googleapis.com/token".to_string()
    } else {
        state.token_url.clone()
    }
}

fn required_material(material: &HashMap<String, String>, key: &str) -> Result<String, Status> {
    material_value(material, &[key])
        .ok_or_else(|| Status::invalid_argument(format!("{key} material is required")))
}

fn material_value<S: std::hash::BuildHasher>(
    material: &HashMap<String, String, S>,
    keys: &[&str],
) -> Option<String> {
    for key in keys {
        if let Some(value) = material.get(*key).map(|value| value.trim())
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
    }
    None
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Test-only STS endpoint override. Reads the `sts_endpoint_url` material and
/// accepts it only when it is a loopback URL, so unit tests can target a local
/// mock STS. Available only in tests or explicit test-support builds; release
/// defaults cannot enable the override through request material. The configure
/// boundary also rejects the `sts_endpoint_url` material key.
#[cfg(any(test, feature = "test-support"))]
fn test_sts_endpoint_override(state: &MintRequest) -> Option<String> {
    material_value(&state.material, &["sts_endpoint_url"]).filter(|endpoint| {
        reqwest::Url::parse(endpoint)
            .ok()
            .and_then(|parsed| parsed.host_str().map(is_loopback_host))
            .unwrap_or(false)
    })
}

#[cfg(not(any(test, feature = "test-support")))]
#[allow(clippy::missing_const_for_fn)]
fn test_sts_endpoint_override(_state: &MintRequest) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn proto_duration(seconds: i64) -> prost_types::Duration {
        prost_types::Duration { seconds, nanos: 0 }
    }

    #[test]
    fn built_in_registry_contains_exactly_four_canonical_strategies() {
        let registry = built_in_minters();
        assert_eq!(
            registry.strategy_names().collect::<Vec<_>>(),
            [
                "oauth2_refresh_token",
                "oauth2_client_credentials",
                "google_service_account_jwt",
                "aws_sts_assume_role",
            ]
        );
        for strategy in [
            ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
            ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
            ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt,
            ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
        ] {
            assert!(registry.can_mint(strategy as i32));
            assert!(
                registry
                    .lookup(refresh_strategy_name(strategy as i32))
                    .is_some()
            );
        }
        assert!(registry.lookup("OAUTH2_REFRESH_TOKEN").is_none());
        assert!(registry.lookup("custom").is_none());
    }

    #[tokio::test]
    async fn unsupported_and_unknown_strategies_preserve_configuration_errors() {
        for (strategy, name) in [
            (ProviderCredentialRefreshStrategy::Static as i32, "Static"),
            (
                ProviderCredentialRefreshStrategy::External as i32,
                "External",
            ),
            (
                ProviderCredentialRefreshStrategy::Unspecified as i32,
                "Unspecified",
            ),
            (i32::MAX, "Unspecified"),
            (-1, "Unspecified"),
        ] {
            assert!(!built_in_minters().can_mint(strategy));
            let failure = mint_credential(&MintRequest {
                strategy,
                ..Default::default()
            })
            .await
            .err()
            .expect("unsupported strategy must not mint");
            assert_eq!(failure.status.code(), Code::FailedPrecondition);
            assert_eq!(
                failure.status.message(),
                format!("refresh strategy '{name}' cannot be minted by the gateway")
            );
            assert_eq!(failure.failure_code, "refresh_configuration_invalid");
            assert_eq!(
                failure.recovery_action,
                ProviderCredentialRefreshRecoveryAction::FixConfiguration
            );
            assert_eq!(failure.retry_schedule, RefreshRetrySchedule::Configuration);
        }
    }

    #[test]
    fn exact_refresh_durations_preserve_fractional_values_until_protocol_boundaries() {
        let refresh_before = prost_types::Duration {
            seconds: 0,
            nanos: 500_000_000,
        };
        assert_eq!(next_refresh_at_ms(10_000, Some(&refresh_before)), 9_500);
        let submillisecond = prost_types::Duration {
            seconds: 0,
            nanos: 1,
        };
        assert_eq!(next_refresh_at_ms(10_000, Some(&submillisecond)), 9_999);

        let state = MintRequest {
            max_lifetime: Some(refresh_before),
            ..Default::default()
        };
        assert_eq!(max_lifetime_seconds(&state), 1);
    }
    #[test]
    fn local_refresh_statuses_default_to_safe_recovery_actions() {
        for status in [
            Status::invalid_argument("missing material"),
            Status::failed_precondition("strategy cannot be minted"),
            Status::permission_denied("client is not allowed"),
        ] {
            let failure = RefreshFailure::from(status);
            assert_eq!(
                failure.recovery_action,
                ProviderCredentialRefreshRecoveryAction::FixConfiguration
            );
            assert_eq!(failure.failure_code, "refresh_configuration_invalid");
            assert_eq!(failure.retry_schedule, RefreshRetrySchedule::Configuration);
        }

        let retry = RefreshFailure::from(Status::unavailable("temporary backend outage"));
        assert_eq!(
            retry.recovery_action,
            ProviderCredentialRefreshRecoveryAction::Retry
        );
        assert_eq!(retry.retry_schedule, RefreshRetrySchedule::Short);

        let investigate = RefreshFailure::from(Status::unknown("unclassified failure"));
        assert_eq!(
            investigate.recovery_action,
            ProviderCredentialRefreshRecoveryAction::Investigate
        );
        assert_eq!(investigate.retry_schedule, RefreshRetrySchedule::Short);
    }

    #[test]
    fn oauth_invalid_grant_requires_user_reauthorization_without_exposing_description() {
        let failure = classify_oauth_token_error(
            reqwest::StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_grant","error_subtype":"invalid_rapt","error_description":"sensitive provider detail"}"#,
            OAuthGrantKind::UserRefreshToken,
        );

        assert_eq!(
            failure.recovery_action,
            ProviderCredentialRefreshRecoveryAction::Reauthorize
        );
        assert_eq!(failure.failure_code, "oauth_invalid_grant");
        assert_eq!(failure.provider_error_subtype, Some("invalid_rapt"));
        assert_eq!(failure.retry_schedule, RefreshRetrySchedule::Parked);
        assert!(
            failure
                .status
                .message()
                .contains("interactive reauthorization")
        );
        assert!(
            !failure
                .status
                .message()
                .contains("sensitive provider detail")
        );
    }

    #[test]
    fn oauth_invalid_grant_ignores_non_string_optional_subtype() {
        let failure = classify_oauth_token_error(
            reqwest::StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_grant","error_subtype":{"vendor":"value"}}"#,
            OAuthGrantKind::UserRefreshToken,
        );

        assert_eq!(
            failure.recovery_action,
            ProviderCredentialRefreshRecoveryAction::Reauthorize
        );
        assert_eq!(failure.failure_code, "oauth_invalid_grant");
        assert_eq!(failure.provider_error_subtype, None);
        assert_eq!(failure.retry_schedule, RefreshRetrySchedule::Parked);
    }

    #[test]
    fn oauth_noninteractive_invalid_grant_requires_configuration_fix() {
        let failure = classify_oauth_token_error(
            reqwest::StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_grant"}"#,
            OAuthGrantKind::NonInteractive,
        );

        assert_eq!(
            failure.recovery_action,
            ProviderCredentialRefreshRecoveryAction::FixConfiguration
        );
        assert_eq!(failure.failure_code, "oauth_invalid_grant");
        assert_eq!(failure.retry_schedule, RefreshRetrySchedule::Configuration);
    }

    #[test]
    fn oauth_admin_policy_subtype_requires_configuration_fix() {
        let failure = classify_oauth_token_error(
            reqwest::StatusCode::BAD_REQUEST,
            br#"{"error":"access_denied","error_subtype":"admin_policy_enforced"}"#,
            OAuthGrantKind::UserRefreshToken,
        );

        assert_eq!(
            failure.recovery_action,
            ProviderCredentialRefreshRecoveryAction::FixConfiguration
        );
        assert_eq!(failure.failure_code, "oauth_admin_policy_enforced");
        assert_eq!(
            failure.provider_error_subtype,
            Some("admin_policy_enforced")
        );
        assert_eq!(failure.retry_schedule, RefreshRetrySchedule::Configuration);
    }

    #[test]
    fn oauth_access_denied_recovery_depends_on_grant_kind() {
        let user_failure = classify_oauth_token_error(
            reqwest::StatusCode::FORBIDDEN,
            br#"{"error":"access_denied"}"#,
            OAuthGrantKind::UserRefreshToken,
        );
        assert_eq!(
            user_failure.recovery_action,
            ProviderCredentialRefreshRecoveryAction::Reauthorize
        );
        assert_eq!(user_failure.failure_code, "oauth_access_denied");
        assert_eq!(user_failure.retry_schedule, RefreshRetrySchedule::Parked);

        let service_failure = classify_oauth_token_error(
            reqwest::StatusCode::FORBIDDEN,
            br#"{"error":"access_denied"}"#,
            OAuthGrantKind::NonInteractive,
        );
        assert_eq!(
            service_failure.recovery_action,
            ProviderCredentialRefreshRecoveryAction::FixConfiguration
        );
        assert_eq!(service_failure.failure_code, "oauth_access_denied");
        assert_eq!(
            service_failure.retry_schedule,
            RefreshRetrySchedule::Configuration
        );
    }

    #[test]
    fn oauth_server_failure_remains_retryable() {
        let failure = classify_oauth_token_error(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            br#"{"error":"invalid_grant"}"#,
            OAuthGrantKind::UserRefreshToken,
        );

        assert_eq!(
            failure.recovery_action,
            ProviderCredentialRefreshRecoveryAction::Retry
        );
        assert_eq!(failure.failure_code, "oauth_token_endpoint_retryable");
        assert_eq!(failure.retry_schedule, RefreshRetrySchedule::Short);
    }

    #[test]
    fn unrecognized_oauth_error_requests_investigation_without_echoing_body() {
        let failure = classify_oauth_token_error(
            reqwest::StatusCode::BAD_REQUEST,
            br#"{"error":"vendor_secret_error","error_description":"do not expose me"}"#,
            OAuthGrantKind::UserRefreshToken,
        );

        assert_eq!(
            failure.recovery_action,
            ProviderCredentialRefreshRecoveryAction::Investigate
        );
        assert_eq!(failure.failure_code, "oauth_unrecognized_error");
        assert_eq!(failure.retry_schedule, RefreshRetrySchedule::Short);
        assert!(!failure.status.message().contains("vendor_secret_error"));
        assert!(!failure.status.message().contains("do not expose me"));
    }

    #[test]
    fn html_and_malformed_oauth_errors_are_investigated_without_echoing_body() {
        for body in [b"<html>issuer failure</html>".as_slice(), b"{".as_slice()] {
            let failure = classify_oauth_token_error(
                reqwest::StatusCode::BAD_REQUEST,
                body,
                OAuthGrantKind::UserRefreshToken,
            );

            assert_eq!(
                failure.recovery_action,
                ProviderCredentialRefreshRecoveryAction::Investigate
            );
            assert_eq!(failure.failure_code, "oauth_unrecognized_error_response");
            assert!(!failure.status.message().contains("issuer failure"));
        }
    }

    #[tokio::test]
    async fn oversized_oauth_error_body_is_bounded_and_investigated() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oversized"))
            .respond_with(ResponseTemplate::new(400).set_body_bytes(vec![
                b'x';
                MAX_OAUTH_ERROR_RESPONSE_BYTES
                    + 512
            ]))
            .mount(&mock_server)
            .await;

        openshell_crypto::tls::ensure_default_provider();
        let response = reqwest::get(format!("{}/oversized", mock_server.uri()))
            .await
            .unwrap();
        let status = response.status();
        let body = read_bounded_oauth_error_body(response).await;
        assert_eq!(body.len(), MAX_OAUTH_ERROR_RESPONSE_BYTES);

        let failure = classify_oauth_token_error(status, &body, OAuthGrantKind::UserRefreshToken);
        assert_eq!(
            failure.recovery_action,
            ProviderCredentialRefreshRecoveryAction::Investigate
        );
        assert_eq!(failure.failure_code, "oauth_unrecognized_error_response");
    }

    #[tokio::test]
    async fn request_token_sends_accept_json() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(header("accept", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-token",
                "expires_in": 3600
            })))
            .mount(&mock_server)
            .await;

        let minted = request_token(
            &format!("{}/token", mock_server.uri()),
            &[("grant_type".to_string(), "refresh_token".to_string())],
            60,
            OAuthGrantKind::UserRefreshToken,
        )
        .await
        .unwrap();
        assert_eq!(minted.access_token, "minted-token");
    }

    #[test]
    fn refresh_strategy_name_includes_aws_sts() {
        assert_eq!(
            refresh_strategy_name(ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32),
            "aws_sts_assume_role"
        );
    }

    #[test]
    fn aws_sts_max_expires_saturates_on_saturated_clock() {
        assert_eq!(i64::MAX.saturating_add(3_600_000), i64::MAX);
        let now_ms = i64::MAX - 1_000;
        let max_lifetime_ms = 3_600_000;
        let max_expires = now_ms.saturating_add(max_lifetime_ms);
        assert_eq!(max_expires, i64::MAX);
        assert!(max_expires >= now_ms);
    }
    #[tokio::test]
    async fn aws_sts_mint_writes_to_resolved_additional_output_keys() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAMOCKKEY</AccessKeyId>
      <SecretAccessKey>MockSecretAccessKey123</SecretAccessKey>
      <SessionToken>MockSessionTokenXYZ</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#,
            ))
            .mount(&mock_server)
            .await;

        let state = MintRequest {
            additional_output_keys: HashMap::from([
                ("secret_access_key".to_string(), "CUSTOM_SECRET".to_string()),
                ("session_token".to_string(), "CUSTOM_SESSION".to_string()),
            ]),
            strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
            material: HashMap::from([
                (
                    "role_arn".to_string(),
                    "arn:aws:iam::123456789012:role/TestRole".to_string(),
                ),
                ("aws_access_key_id".to_string(), "AKIATESTKEY".to_string()),
                (
                    "aws_secret_access_key".to_string(),
                    "TestSecretKey".to_string(),
                ),
                ("sts_endpoint_url".to_string(), mock_server.uri()),
            ]),
            token_url: String::new(),
            scopes: Vec::new(),
            max_lifetime: Some(proto_duration(3600)),
        };
        let minted = mint_credential(&state).await.unwrap();
        assert_eq!(minted.access_token, "ASIAMOCKKEY");
        assert_eq!(
            minted
                .additional_credentials
                .get("CUSTOM_SECRET")
                .map(String::as_str),
            Some("MockSecretAccessKey123")
        );
        assert_eq!(
            minted
                .additional_credentials
                .get("CUSTOM_SESSION")
                .map(String::as_str),
            Some("MockSessionTokenXYZ")
        );
        assert!(
            !minted
                .additional_credentials
                .contains_key("AWS_SECRET_ACCESS_KEY")
        );
        assert!(minted.expires_at_ms > current_time_ms());
        assert!(minted.expires_at_ms <= current_time_ms().saturating_add(3_600_000));
    }

    #[tokio::test]
    async fn aws_sts_mint_rejects_partial_source_credentials() {
        let state = MintRequest {
            additional_output_keys: HashMap::from([
                (
                    "secret_access_key".to_string(),
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                ),
                ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
            ]),
            strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
            material: HashMap::from([
                (
                    "role_arn".to_string(),
                    "arn:aws:iam::123456789012:role/TestRole".to_string(),
                ),
                ("aws_access_key_id".to_string(), "AKIATESTKEY".to_string()),
            ]),
            token_url: String::new(),
            scopes: Vec::new(),
            max_lifetime: Some(proto_duration(3600)),
        };
        let failure = mint_credential(&state)
            .await
            .err()
            .expect("invalid explicit source credentials must not mint");
        assert_eq!(failure.status.code(), Code::InvalidArgument);
        assert!(
            failure
                .status
                .message()
                .contains("both be set or both omitted")
        );
    }

    #[tokio::test]
    async fn aws_sts_mint_accepts_session_token_with_source_pair() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .and(header("x-amz-security-token", "SourceSessionToken"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAMOCKKEY</AccessKeyId>
      <SecretAccessKey>MockSecretAccessKey123</SecretAccessKey>
      <SessionToken>MockSessionTokenXYZ</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#,
            ))
            .mount(&mock_server)
            .await;

        let state = MintRequest {
            additional_output_keys: HashMap::from([
                (
                    "secret_access_key".to_string(),
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                ),
                ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
            ]),
            strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
            material: HashMap::from([
                (
                    "role_arn".to_string(),
                    "arn:aws:iam::123456789012:role/TestRole".to_string(),
                ),
                ("aws_access_key_id".to_string(), "ASIASOURCEKEY".to_string()),
                (
                    "aws_secret_access_key".to_string(),
                    "SourceSecretKey".to_string(),
                ),
                (
                    "aws_session_token".to_string(),
                    "SourceSessionToken".to_string(),
                ),
                ("sts_endpoint_url".to_string(), mock_server.uri()),
            ]),
            token_url: String::new(),
            scopes: Vec::new(),
            max_lifetime: Some(proto_duration(3600)),
        };
        let minted = mint_credential(&state).await.unwrap();
        assert_eq!(minted.access_token, "ASIAMOCKKEY");
    }

    #[tokio::test]
    async fn aws_sts_mint_rejects_session_token_without_source_pair() {
        let state = MintRequest {
            additional_output_keys: HashMap::from([
                (
                    "secret_access_key".to_string(),
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                ),
                ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
            ]),
            strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
            material: HashMap::from([
                (
                    "role_arn".to_string(),
                    "arn:aws:iam::123456789012:role/TestRole".to_string(),
                ),
                (
                    "aws_session_token".to_string(),
                    "SourceSessionToken".to_string(),
                ),
            ]),
            token_url: String::new(),
            scopes: Vec::new(),
            max_lifetime: Some(proto_duration(3600)),
        };
        let failure = mint_credential(&state)
            .await
            .err()
            .expect("invalid explicit source credentials must not mint");
        assert_eq!(failure.status.code(), Code::InvalidArgument);
        assert!(
            failure
                .status
                .message()
                .contains("aws_session_token requires")
        );
    }

    #[test]
    fn test_sts_endpoint_override_accepts_only_loopback_hosts() {
        for endpoint in ["http://127.0.0.1:1234", "http://localhost:1234"] {
            let request = MintRequest {
                material: HashMap::from([("sts_endpoint_url".into(), endpoint.into())]),
                ..Default::default()
            };
            assert_eq!(
                test_sts_endpoint_override(&request).as_deref(),
                Some(endpoint)
            );
        }
        for endpoint in [
            "https://attacker.example",
            "http://127.0.0.1.attacker.example",
            "invalid",
        ] {
            let request = MintRequest {
                material: HashMap::from([("sts_endpoint_url".into(), endpoint.into())]),
                ..Default::default()
            };
            assert!(test_sts_endpoint_override(&request).is_none());
        }
    }

    #[tokio::test]
    async fn oauth2_refresh_token_minter_preserves_request_and_rotated_material() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(header("accept", "application/json"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("client_id=client-id"))
            .and(body_string_contains("client_secret=client-secret"))
            .and(body_string_contains("refresh_token=old-refresh-token"))
            .and(body_string_contains("scope=one+two"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-token",
                "refresh_token": "rotated-token",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let request = MintRequest {
            strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32,
            material: HashMap::from([
                ("client_id".into(), "client-id".into()),
                ("client_secret".into(), "client-secret".into()),
                ("refresh_token".into(), "old-refresh-token".into()),
                ("scope".into(), "ignored-material-scope".into()),
            ]),
            token_url: format!("{}/token", mock_server.uri()),
            scopes: vec!["one".into(), "two".into()],
            max_lifetime: Some(proto_duration(60)),
            ..Default::default()
        };
        let before = current_time_ms();
        let minted = mint_credential(&request).await.unwrap();
        assert_eq!(minted.access_token, "minted-token");
        assert_eq!(minted.refresh_token.as_deref(), Some("rotated-token"));
        assert!(minted.additional_credentials.is_empty());
        assert!(minted.expires_at_ms >= before.saturating_add(60_000));
        assert!(minted.expires_at_ms <= current_time_ms().saturating_add(60_000));
    }

    #[tokio::test]
    async fn oauth2_client_credentials_minter_uses_material_scope_fallback() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("client_id=client-id"))
            .and(body_string_contains("client_secret=client-secret"))
            .and(body_string_contains("scope=one+two+three"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-token",
                "expires_in": 0,
                "refresh_token": " "
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let request = MintRequest {
            strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
            material: HashMap::from([
                ("client_id".into(), "client-id".into()),
                ("client_secret".into(), "client-secret".into()),
                ("scopes".into(), "one, two\tthree".into()),
            ]),
            token_url: format!("{}/token", mock_server.uri()),
            max_lifetime: Some(proto_duration(60)),
            ..Default::default()
        };
        let before = current_time_ms();
        let minted = mint_credential(&request).await.unwrap();
        assert_eq!(minted.access_token, "minted-token");
        assert!(minted.refresh_token.is_none());
        assert!(minted.expires_at_ms >= before.saturating_add(60_000));
        assert!(minted.expires_at_ms <= current_time_ms().saturating_add(60_000));
    }

    #[tokio::test]
    async fn oauth_success_response_failures_preserve_grant_specific_recovery() {
        let mock_server = MockServer::start().await;
        for (path_name, body, code) in [
            ("invalid-json", "{", "oauth_invalid_success_response"),
            (
                "empty-token",
                r#"{"access_token":" "}"#,
                "oauth_empty_access_token",
            ),
        ] {
            Mock::given(method("POST"))
                .and(path(format!("/{path_name}")))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .mount(&mock_server)
                .await;
            for grant_kind in [
                OAuthGrantKind::UserRefreshToken,
                OAuthGrantKind::NonInteractive,
            ] {
                let failure = request_token(
                    &format!("{}/{path_name}", mock_server.uri()),
                    &[],
                    60,
                    grant_kind,
                )
                .await
                .err()
                .expect("unusable response must fail");
                if grant_kind == OAuthGrantKind::UserRefreshToken {
                    assert_eq!(failure.failure_code, "oauth_refresh_exchange_uncertain");
                    assert_eq!(
                        failure.recovery_action,
                        ProviderCredentialRefreshRecoveryAction::Reauthorize
                    );
                    assert_eq!(failure.retry_schedule, RefreshRetrySchedule::Parked);
                } else {
                    assert_eq!(failure.failure_code, code);
                    assert_eq!(
                        failure.recovery_action,
                        ProviderCredentialRefreshRecoveryAction::Investigate
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn google_service_account_minter_signs_jwt_and_requests_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer",
            ))
            .and(body_string_contains("assertion="))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-drive-token",
                "expires_in": 1800,
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let request = MintRequest {
            strategy: ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt as i32,
            material: HashMap::from([
                (
                    "client_email".into(),
                    "svc@example.iam.gserviceaccount.com".into(),
                ),
                ("private_key".into(), TEST_RSA_PRIVATE_KEY.into()),
            ]),
            token_url: format!("{}/token", mock_server.uri()),
            scopes: vec!["https://www.googleapis.com/auth/drive.readonly".into()],
            max_lifetime: Some(proto_duration(3600)),
            ..Default::default()
        };
        let before = current_time_ms();
        let minted = mint_credential(&request).await.unwrap();
        assert_eq!(minted.access_token, "minted-drive-token");
        assert!(minted.expires_at_ms >= before.saturating_add(1_800_000));
        assert!(minted.expires_at_ms <= current_time_ms().saturating_add(1_800_000));
    }

    const TEST_RSA_PRIVATE_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvCoZ0mVHpCHsF
zeeqw2caNIe/eb4BQUccFPhZfRnF7sCfyB84zTBmuwG2umRBdjFnVsfIIZRp2HcD
OESrRYYiE1RGfjBXImGVg2Wtza0HYhL1sLyX1eaEefylxoilmApAgWDh9p36h8J2
s5YHwyXPTttx4DpdWDnxju1iNmwoIB8uVE/5amWgbNvlETMBOcB1RxDHtnVy+xJz
jjjrzK4Qz9WsUTHAvngdi4Yyxvci+yKpjYTg5+UWxmAN6iW522TpLe32MDb5Ug1d
trBvvepWmdQ6CBwPhBHCt/sMoSJAYSO4RKeBnBjeLQBXFTxaOv5iTGIsRTX3K471
epHp3cT5AgMBAAECggEASQlRv/4nZN5SgsH/K8v7zb3kdHsmUly8AJYpaCGgauvr
uN/mUyueyga2uNl+MqhQBef6VWHZjO6y/gdw86v/Q2GgVQebQQhKAnpAp2w+Ceoc
siKMFqi8VkOWLU+xPbM6d97kH3TpRxt1g1T8wYFmWeF0BEiE4eUJzGaQW14M9BJ+
G0QxmP/zjX9cNpVeApKTjBWKiH4CXG3DuI3pJ93VOMpUlOsrdLXvKGTze0e01itr
MX/MHHTE+VXB4FB+/zKSA4c36egi676OSXrGC/GDmM8ntJ4CUGeD5uZsMSADiAUn
iccv5iGRWVMIKxUS5Q4k0jy8uWuK+QVP4Y6cQWYArwKBgQDhuSNORBNpIGRfsKGN
iJo/h+qinz6pEIpa3D3oVl7rpkyvgIyaTwfXvC1vfdS9V5VIel2gV2Cx0OrI8yrr
nQu1JuNV/rLmtvqX321fgBLRdoiqF3pAy1gbmdUz1elerAIYL578gXQ6jg1bbdic
kJpn0MsoDUJGwvJnXcgLqG7q3wKBgQDGhRIa4oJsj1vqICc8zt8YsCAcot3vjWLH
588X7JdBGOWJdWxfdmGXQRn5Zw9UhMQnYa3uyTBPeVcXopThlPotYeuFhLSU856T
IJzfpzCJzC4zIQayoyvJFrKe7N70iUQ986dewYy9oxQhHvFKd/qe4ylbzZJXpthX
eWEuuBSjJwKBgGkqXt6qLPj/1IQYwUw15tfOtW0LEKCoSi3HCzjidNsJ4hSqqdeD
Fr5WuDyHvcRxt+XKzTBVRYHTOnBhiw+3XasK8UQxpJyFh/+WY1jpTNs2hLnqslTZ
6LUDWSgLc+1d6qPmHAa9Ma/OWz7L0O4xGR9hUiXY95YMYe/y668yzGq1AoGBAJyU
Gsqfu7U6gYmxoKEine6QBFPx1dD7GF2KJdq93jMXGvyHZFoLOkAdtgnz0rCcI0bY
kWKUxwj4MMxQjNM8OPMQl75xBCmz2XA8Od9htDQLmqjzNKAzePabc3lMZTJFDlE6
29kuGf79IIRbLn/JECDAFT/2baW60Ep2T0OVJ5njAoGAfaCaQ4aVgjI027q7Y5qP
KfNSI8uuA8PLqmUY30I9KFWzN6VDLu00eKa90F4w3CeWRRQWXW1+007tTz3V1mNw
20A24Fi3HGQmXc7NyuLDODTJsWBICuOemCnRkvcxIlxb+ec7jp+XRmzDwKkzSnVN
pM2zFU8SeVkvHKlEuoHaP0s=
-----END PRIVATE KEY-----";
}
