// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider credential refresh state.

#![allow(clippy::result_large_err)]

use crate::persistence::{ObjectType, Store, current_time_ms};
use openshell_core::proto::{
    Provider, ProviderCredentialRefreshStatus, ProviderCredentialRefreshStrategy,
    StoredProviderCredentialRefreshState,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tonic::Status;
use tracing::{info, warn};

const DEFAULT_REFRESH_BEFORE_SECONDS: i64 = 300;
const DEFAULT_MAX_LIFETIME_SECONDS: i64 = 3600;
const REFRESH_ERROR_RETRY_SECONDS: i64 = 60;
const REFRESH_WORKER_PAGE_SIZE: u32 = 1000;

impl ObjectType for StoredProviderCredentialRefreshState {
    fn object_type() -> &'static str {
        "provider_credential_refresh_state"
    }
}

pub fn refresh_state_name(provider_id: &str, credential_key: &str) -> String {
    let mut key = String::with_capacity(credential_key.len() * 2);
    for byte in credential_key.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut key, "{byte:02x}").expect("writing to String cannot fail");
    }
    format!("provider-refresh-{provider_id}-{key}")
}

pub async fn put_refresh_state(
    store: &Store,
    state: &StoredProviderCredentialRefreshState,
) -> Result<(), Status> {
    store
        .put_scoped_message(state, &state.provider_id)
        .await
        .map_err(|e| Status::internal(format!("persist provider refresh state failed: {e}")))
}

pub async fn list_refresh_states_for_provider(
    store: &Store,
    provider_id: &str,
) -> Result<Vec<StoredProviderCredentialRefreshState>, Status> {
    let records = store
        .list_by_scope(
            StoredProviderCredentialRefreshState::object_type(),
            provider_id,
            1000,
            0,
        )
        .await
        .map_err(|e| Status::internal(format!("list provider refresh states failed: {e}")))?;

    let mut states = Vec::with_capacity(records.len());
    for record in records {
        states.push(
            StoredProviderCredentialRefreshState::decode(record.payload.as_slice()).map_err(
                |e| Status::internal(format!("decode provider refresh state failed: {e}")),
            )?,
        );
    }
    Ok(states)
}

pub async fn list_all_refresh_states(
    store: &Store,
) -> Result<Vec<StoredProviderCredentialRefreshState>, Status> {
    let mut states = Vec::new();
    let mut offset = 0;
    loop {
        let records = store
            .list(
                StoredProviderCredentialRefreshState::object_type(),
                REFRESH_WORKER_PAGE_SIZE,
                offset,
            )
            .await
            .map_err(|e| Status::internal(format!("list provider refresh states failed: {e}")))?;
        if records.is_empty() {
            break;
        }
        offset = offset
            .checked_add(
                u32::try_from(records.len())
                    .map_err(|_| Status::internal("provider refresh page size exceeded u32"))?,
            )
            .ok_or_else(|| Status::internal("provider refresh pagination offset overflow"))?;
        for record in records {
            states.push(
                StoredProviderCredentialRefreshState::decode(record.payload.as_slice()).map_err(
                    |e| Status::internal(format!("decode provider refresh state failed: {e}")),
                )?,
            );
        }
    }
    Ok(states)
}

pub async fn get_refresh_state(
    store: &Store,
    provider_id: &str,
    credential_key: &str,
) -> Result<Option<StoredProviderCredentialRefreshState>, Status> {
    let name = refresh_state_name(provider_id, credential_key);
    store
        .get_message_by_name::<StoredProviderCredentialRefreshState>(&name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider refresh state failed: {e}")))
}

pub async fn delete_refresh_state(
    store: &Store,
    provider_id: &str,
    credential_key: &str,
) -> Result<bool, Status> {
    let name = refresh_state_name(provider_id, credential_key);
    store
        .delete_by_name(StoredProviderCredentialRefreshState::object_type(), &name)
        .await
        .map_err(|e| Status::internal(format!("delete provider refresh state failed: {e}")))
}

pub async fn delete_refresh_states_for_provider(
    store: &Store,
    provider_id: &str,
) -> Result<u64, Status> {
    let states = list_refresh_states_for_provider(store, provider_id).await?;
    let mut deleted = 0;
    for state in states {
        if store
            .delete_by_name(
                StoredProviderCredentialRefreshState::object_type(),
                state.object_name(),
            )
            .await
            .map_err(|e| Status::internal(format!("delete provider refresh state failed: {e}")))?
        {
            deleted += 1;
        }
    }
    Ok(deleted)
}

pub fn refresh_status_from_state(
    state: &StoredProviderCredentialRefreshState,
) -> ProviderCredentialRefreshStatus {
    ProviderCredentialRefreshStatus {
        provider_name: state.provider_name.clone(),
        provider_id: state.provider_id.clone(),
        credential_key: state.credential_key.clone(),
        strategy: state.strategy,
        status: state.status.clone(),
        expires_at_ms: state.expires_at_ms,
        next_refresh_at_ms: state.next_refresh_at_ms,
        last_refresh_at_ms: state.last_refresh_at_ms,
        last_error: state.last_error.clone(),
    }
}

pub struct NewRefreshStateConfig {
    pub strategy: ProviderCredentialRefreshStrategy,
    pub material: HashMap<String, String>,
    pub secret_material_keys: Vec<String>,
    pub expires_at_ms: i64,
    pub token_url: String,
    pub scopes: Vec<String>,
    pub refresh_before_seconds: i64,
    pub max_lifetime_seconds: i64,
}

#[allow(clippy::unnecessary_wraps)]
pub fn new_refresh_state(
    provider: &Provider,
    credential_key: &str,
    config: NewRefreshStateConfig,
) -> Result<StoredProviderCredentialRefreshState, Status> {
    let provider_id = provider.object_id().to_string();
    let provider_name = provider.object_name().to_string();
    let now_ms = current_time_ms();
    let next_refresh_at_ms = next_refresh_at_ms(
        config.expires_at_ms,
        config.refresh_before_seconds,
        config.max_lifetime_seconds,
        now_ms,
    );
    Ok(StoredProviderCredentialRefreshState {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: refresh_state_name(&provider_id, credential_key),
            created_at_ms: now_ms,
            labels: HashMap::new(),
            resource_version: 0,
        }),
        provider_id,
        provider_name,
        credential_key: credential_key.to_string(),
        strategy: config.strategy as i32,
        material: config.material,
        secret_material_keys: config.secret_material_keys,
        expires_at_ms: config.expires_at_ms,
        next_refresh_at_ms,
        last_refresh_at_ms: 0,
        status: "configured".to_string(),
        last_error: String::new(),
        token_url: config.token_url,
        scopes: config.scopes,
        refresh_before_seconds: config.refresh_before_seconds,
        max_lifetime_seconds: config.max_lifetime_seconds,
    })
}

use openshell_core::{ObjectId, ObjectName};

#[derive(Debug)]
struct MintedCredential {
    access_token: String,
    expires_at_ms: i64,
    refresh_token: Option<String>,
    additional_credentials: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
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
    refresh_before_seconds: i64,
    _max_lifetime_seconds: i64,
    _now_ms: i64,
) -> i64 {
    let refresh_before_seconds = if refresh_before_seconds > 0 {
        refresh_before_seconds
    } else {
        DEFAULT_REFRESH_BEFORE_SECONDS
    };
    if expires_at_ms > 0 {
        return expires_at_ms.saturating_sub(refresh_before_seconds.saturating_mul(1000));
    }
    0
}

fn seconds_until_ms(now_ms: i64, target_ms: i64) -> i64 {
    if target_ms <= 0 {
        return 0;
    }
    target_ms.saturating_sub(now_ms).max(0) / 1000
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

pub fn is_gateway_mintable_strategy(strategy: ProviderCredentialRefreshStrategy) -> bool {
    matches!(
        strategy,
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken
            | ProviderCredentialRefreshStrategy::Oauth2ClientCredentials
            | ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt
            | ProviderCredentialRefreshStrategy::AwsStsAssumeRole
    )
}

pub async fn refresh_provider_credential(
    store: &Store,
    provider_name: &str,
    credential_key: &str,
) -> Result<StoredProviderCredentialRefreshState, Status> {
    let provider = store
        .get_message_by_name::<Provider>(provider_name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| Status::not_found("provider not found"))?;
    let Some(mut state) = get_refresh_state(store, provider.object_id(), credential_key).await?
    else {
        return Err(Status::not_found("provider refresh state not found"));
    };

    info!(
        provider = %state.provider_name,
        credential_key = %state.credential_key,
        strategy = %refresh_strategy_name(state.strategy),
        status = %state.status,
        expires_at_ms = state.expires_at_ms,
        next_refresh_at_ms = state.next_refresh_at_ms,
        "provider credential refresh started"
    );

    match mint_credential(&state).await {
        Ok(minted) => {
            let now_ms = current_time_ms();
            if let Err(err) =
                apply_minted_credential(store, &provider, credential_key, &minted).await
            {
                state.status = "error".to_string();
                state.last_error = err.message().to_string();
                state.next_refresh_at_ms =
                    now_ms.saturating_add(REFRESH_ERROR_RETRY_SECONDS.saturating_mul(1000));
                put_refresh_state(store, &state).await?;
                warn!(
                    provider = %state.provider_name,
                    credential_key = %state.credential_key,
                    strategy = %refresh_strategy_name(state.strategy),
                    status = %state.status,
                    next_refresh_at_ms = state.next_refresh_at_ms,
                    seconds_until_refresh = seconds_until_ms(now_ms, state.next_refresh_at_ms),
                    error = %err,
                    "provider credential refresh errored"
                );
                return Err(err);
            }
            if let Some(refresh_token) = minted.refresh_token {
                state
                    .material
                    .insert("refresh_token".to_string(), refresh_token);
                if !state
                    .secret_material_keys
                    .iter()
                    .any(|key| key == "refresh_token")
                {
                    state.secret_material_keys.push("refresh_token".to_string());
                }
            }
            state.expires_at_ms = minted.expires_at_ms;
            state.next_refresh_at_ms = next_refresh_at_ms(
                minted.expires_at_ms,
                state.refresh_before_seconds,
                state.max_lifetime_seconds,
                now_ms,
            );
            state.last_refresh_at_ms = now_ms;
            state.status = "refreshed".to_string();
            state.last_error.clear();
            put_refresh_state(store, &state).await?;
            info!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                strategy = %refresh_strategy_name(state.strategy),
                status = %state.status,
                expires_at_ms = state.expires_at_ms,
                next_refresh_at_ms = state.next_refresh_at_ms,
                seconds_until_refresh = seconds_until_ms(now_ms, state.next_refresh_at_ms),
                "provider credential refresh completed"
            );
            Ok(state)
        }
        Err(err) => {
            let now_ms = current_time_ms();
            state.status = "error".to_string();
            state.last_error = err.message().to_string();
            state.next_refresh_at_ms =
                now_ms.saturating_add(REFRESH_ERROR_RETRY_SECONDS.saturating_mul(1000));
            put_refresh_state(store, &state).await?;
            warn!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                strategy = %refresh_strategy_name(state.strategy),
                status = %state.status,
                next_refresh_at_ms = state.next_refresh_at_ms,
                seconds_until_refresh = seconds_until_ms(now_ms, state.next_refresh_at_ms),
                error = %err,
                "provider credential refresh errored"
            );
            Err(err)
        }
    }
}

async fn apply_minted_credential(
    store: &Store,
    provider: &Provider,
    credential_key: &str,
    minted: &MintedCredential,
) -> Result<(), Status> {
    let mut updated = provider.clone();
    updated
        .credentials
        .insert(credential_key.to_string(), minted.access_token.clone());
    for (key, value) in &minted.additional_credentials {
        updated.credentials.insert(key.clone(), value.clone());
    }
    if minted.expires_at_ms > 0 {
        updated
            .credential_expires_at_ms
            .insert(credential_key.to_string(), minted.expires_at_ms);
        for key in minted.additional_credentials.keys() {
            updated
                .credential_expires_at_ms
                .insert(key.clone(), minted.expires_at_ms);
        }
    } else {
        updated.credential_expires_at_ms.remove(credential_key);
        for key in minted.additional_credentials.keys() {
            updated.credential_expires_at_ms.remove(key);
        }
    }
    crate::grpc::provider::validate_provider_update_against_attached_sandboxes(store, &updated)
        .await?;
    store
        .update_message_cas::<Provider, _>(provider.object_id(), 0, |current| {
            current
                .credentials
                .insert(credential_key.to_string(), minted.access_token.clone());
            for (key, value) in &minted.additional_credentials {
                current.credentials.insert(key.clone(), value.clone());
            }
            if minted.expires_at_ms > 0 {
                current
                    .credential_expires_at_ms
                    .insert(credential_key.to_string(), minted.expires_at_ms);
                for key in minted.additional_credentials.keys() {
                    current
                        .credential_expires_at_ms
                        .insert(key.clone(), minted.expires_at_ms);
                }
            } else {
                current.credential_expires_at_ms.remove(credential_key);
                for key in minted.additional_credentials.keys() {
                    current.credential_expires_at_ms.remove(key);
                }
            }
        })
        .await
        .map(|_| ())
        .map_err(|e| Status::internal(format!("persist refreshed provider credential failed: {e}")))
}

async fn mint_credential(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, Status> {
    let strategy = ProviderCredentialRefreshStrategy::try_from(state.strategy)
        .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
    match strategy {
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken => {
            mint_oauth2_refresh_token(state).await
        }
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials => {
            mint_oauth2_client_credentials(state).await
        }
        ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt => {
            mint_google_service_account_jwt(state).await
        }
        ProviderCredentialRefreshStrategy::AwsStsAssumeRole => {
            mint_aws_sts_assume_role(state).await
        }
        ProviderCredentialRefreshStrategy::External
        | ProviderCredentialRefreshStrategy::Static
        | ProviderCredentialRefreshStrategy::Unspecified => Err(Status::failed_precondition(
            format!("refresh strategy '{strategy:?}' cannot be minted by the gateway"),
        )),
    }
}

async fn mint_oauth2_refresh_token(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, Status> {
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

    request_token(&token_url, &form, state.max_lifetime_seconds).await
}

async fn mint_oauth2_client_credentials(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, Status> {
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

    request_token(&token_url, &form, state.max_lifetime_seconds).await
}

async fn mint_google_service_account_jwt(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, Status> {
    let token_url = google_token_url(state);
    let client_email = required_material(&state.material, "client_email")?;
    let private_key = required_material(&state.material, "private_key")?;
    let scopes = refresh_scopes(state);
    if scopes.is_empty() {
        return Err(Status::invalid_argument(
            "google_service_account_jwt requires at least one scope",
        ));
    }
    let now_ms = current_time_ms();
    let now_secs = now_ms / 1000;
    let lifetime_secs = if state.max_lifetime_seconds > 0 {
        state.max_lifetime_seconds.min(DEFAULT_MAX_LIFETIME_SECONDS)
    } else {
        DEFAULT_MAX_LIFETIME_SECONDS
    };
    let subject = material_value(&state.material, &["subject", "sub"]);
    let claims = GoogleServiceAccountClaims {
        iss: &client_email,
        scope: scopes.join(" "),
        aud: &token_url,
        iat: now_secs,
        exp: now_secs.saturating_add(lifetime_secs),
        sub: subject.as_deref(),
    };
    let assertion = jsonwebtoken::encode(
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
    request_token(&token_url, &form, lifetime_secs).await
}

async fn mint_aws_sts_assume_role(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, Status> {
    let role_arn = required_material(&state.material, "role_arn")?;
    let session_name = material_value(&state.material, &["session_name"])
        .unwrap_or_else(|| "openshell-sandbox".to_string());
    let external_id = material_value(&state.material, &["external_id"]);
    let region =
        material_value(&state.material, &["aws_region"]).unwrap_or_else(|| "us-east-1".to_string());

    let region_provider = aws_sdk_sts::config::Region::new(region);
    let mut config_loader =
        aws_config::defaults(aws_config::BehaviorVersion::latest()).region(region_provider);

    if let (Some(access_key), Some(secret_key)) = (
        material_value(&state.material, &["aws_access_key_id"]),
        material_value(&state.material, &["aws_secret_access_key"]),
    ) {
        let creds = aws_sdk_sts::config::Credentials::new(
            access_key,
            secret_key,
            None,
            None,
            "openshell-provider-refresh",
        );
        config_loader = config_loader.credentials_provider(creds);
    }

    let sdk_config = config_loader.load().await;
    let sts_config = {
        let mut builder = aws_sdk_sts::config::Builder::from(&sdk_config);
        if let Some(endpoint) = material_value(&state.material, &["sts_endpoint_url"])
            && let Ok(parsed) = reqwest::Url::parse(&endpoint)
            && parsed.host_str().is_some_and(is_loopback_host)
        {
            builder = builder.endpoint_url(endpoint);
        }
        builder.build()
    };
    let client = aws_sdk_sts::Client::from_conf(sts_config);

    let max_lifetime_i64 = if state.max_lifetime_seconds > 0 {
        state.max_lifetime_seconds
    } else {
        DEFAULT_MAX_LIFETIME_SECONDS
    };
    let max_lifetime = i32::try_from(max_lifetime_i64.min(i64::from(i32::MAX))).unwrap_or(i32::MAX);

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
    let expires_at_ms = creds
        .expiration()
        .to_millis()
        .unwrap_or_else(|_| now_ms + max_lifetime_i64 * 1000);
    let max_expires = now_ms + max_lifetime_i64 * 1000;
    let expires_at_ms = expires_at_ms.min(max_expires);

    let mut additional = HashMap::new();
    additional.insert("AWS_SECRET_ACCESS_KEY".to_string(), secret_access_key);
    additional.insert("AWS_SESSION_TOKEN".to_string(), session_token);

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
) -> Result<MintedCredential, Status> {
    let parsed = reqwest::Url::parse(token_url)
        .map_err(|_| Status::invalid_argument("token_url must be an absolute URL"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if parsed.host_str().is_some_and(is_loopback_host) => {}
        _ => {
            return Err(Status::invalid_argument(
                "token_url must use https, except loopback http for local tests",
            ));
        }
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| Status::internal(format!("build refresh HTTP client failed: {e}")))?;
    let response = client
        .post(parsed)
        .form(form)
        .send()
        .await
        .map_err(|e| Status::unavailable(format!("token endpoint request failed: {e}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(Status::failed_precondition(format!(
            "token endpoint returned HTTP {status}"
        )));
    }
    let token = response
        .json::<TokenResponse>()
        .await
        .map_err(|_| Status::failed_precondition("token endpoint returned invalid JSON"))?;
    if token.access_token.trim().is_empty() {
        return Err(Status::failed_precondition(
            "token endpoint returned empty access_token",
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

pub fn refresh_scopes(state: &StoredProviderCredentialRefreshState) -> Vec<String> {
    if !state.scopes.is_empty() {
        return state.scopes.clone();
    }
    material_scopes(&state.material)
}

pub fn material_scopes(material: &HashMap<String, String>) -> Vec<String> {
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

pub fn parse_material_i64(
    material: &HashMap<String, String>,
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

fn oauth2_token_url(state: &StoredProviderCredentialRefreshState) -> Result<String, Status> {
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

fn google_token_url(state: &StoredProviderCredentialRefreshState) -> String {
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

fn material_value(material: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
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

pub fn spawn_refresh_worker(state: std::sync::Arc<crate::ServerState>, interval: Duration) {
    info!(
        interval_seconds = interval.as_secs(),
        "provider credential refresh worker started"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(err) = run_refresh_worker_tick(state.store.as_ref()).await {
                warn!(error = %err, "provider credential refresh worker tick failed");
            }
        }
    });
}

async fn run_refresh_worker_tick(store: &Store) -> Result<(), Status> {
    let now_ms = current_time_ms();
    let states = list_all_refresh_states(store).await?;
    let watched_count = states.len();
    let due_count = states
        .iter()
        .filter(|state| state.next_refresh_at_ms <= 0 || state.next_refresh_at_ms <= now_ms)
        .count();
    let rotation_requested_count = states
        .iter()
        .filter(|state| state.status == "rotation_requested")
        .count();
    info!(
        watched_count,
        due_count, rotation_requested_count, "provider credential refresh worker sweep"
    );
    for state in states {
        let strategy = ProviderCredentialRefreshStrategy::try_from(state.strategy)
            .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
        let due = state.next_refresh_at_ms <= 0 || state.next_refresh_at_ms <= now_ms;
        let rotation_requested = state.status == "rotation_requested";
        info!(
            provider = %state.provider_name,
            credential_key = %state.credential_key,
            strategy = %refresh_strategy_name(state.strategy),
            status = %state.status,
            expires_at_ms = state.expires_at_ms,
            seconds_until_expiry = seconds_until_ms(now_ms, state.expires_at_ms),
            next_refresh_at_ms = state.next_refresh_at_ms,
            last_refresh_at_ms = state.last_refresh_at_ms,
            seconds_until_refresh = seconds_until_ms(now_ms, state.next_refresh_at_ms),
            due,
            rotation_requested,
            "provider credential refresh watch"
        );
        if !due && !rotation_requested {
            continue;
        }
        if !is_gateway_mintable_strategy(strategy) {
            warn!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                strategy = %refresh_strategy_name(state.strategy),
                status = %state.status,
                "skipping non-gateway-mintable provider credential refresh state"
            );
            continue;
        }
        info!(
            provider = %state.provider_name,
            credential_key = %state.credential_key,
            strategy = %refresh_strategy_name(state.strategy),
            status = %state.status,
            "refreshing provider credential"
        );
        if let Err(err) =
            refresh_provider_credential(store, &state.provider_name, &state.credential_key).await
        {
            warn!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                strategy = %refresh_strategy_name(state.strategy),
                status = %state.status,
                next_refresh_at_ms = state.next_refresh_at_ms,
                error = %err,
                "provider credential refresh failed"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        NewRefreshStateConfig, get_refresh_state, new_refresh_state, put_refresh_state,
        refresh_provider_credential, refresh_state_name, refresh_strategy_name,
        run_refresh_worker_tick, seconds_until_ms,
    };
    use crate::persistence::test_store;
    use openshell_core::ObjectId;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{
        Provider, ProviderCredentialRefreshStrategy, Sandbox, SandboxSpec,
    };
    use std::collections::HashMap;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn refresh_state_name_preserves_distinct_credential_keys() {
        let provider_id = "provider-id";

        assert_ne!(
            refresh_state_name(provider_id, "API_KEY"),
            refresh_state_name(provider_id, "api_key")
        );
        assert_ne!(
            refresh_state_name(provider_id, " alex-api "),
            refresh_state_name(provider_id, " alex_api")
        );
        assert_ne!(
            refresh_state_name(provider_id, "Alex-API"),
            refresh_state_name(provider_id, "alex-api")
        );
    }

    #[test]
    fn refresh_log_helpers_format_safe_operational_fields() {
        assert_eq!(seconds_until_ms(1_000, 61_000), 60);
        assert_eq!(seconds_until_ms(61_000, 1_000), 0);
        assert_eq!(seconds_until_ms(1_000, 0), 0);
        assert_eq!(
            refresh_strategy_name(ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32),
            "oauth2_refresh_token"
        );
        assert_eq!(
            refresh_strategy_name(
                ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32
            ),
            "oauth2_client_credentials"
        );
        assert_eq!(
            refresh_strategy_name(
                ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt as i32
            ),
            "google_service_account_jwt"
        );
        assert_eq!(refresh_strategy_name(i32::MAX), "unspecified");
    }

    #[tokio::test]
    async fn oauth2_client_credentials_refresh_mints_and_persists_access_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("client_id=client-id"))
            .and(body_string_contains(
                "scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-graph-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("my-graph", "outlook");
        store.put_message(&provider).await.unwrap();
        let before_refresh_ms = crate::persistence::current_time_ms();
        let state = new_refresh_state(
            &provider,
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: vec!["https://graph.microsoft.com/.default".to_string()],
                refresh_before_seconds: 30,
                max_lifetime_seconds: 60,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let refreshed = refresh_provider_credential(&store, "my-graph", "MS_GRAPH_ACCESS_TOKEN")
            .await
            .unwrap();
        assert_eq!(refreshed.status, "refreshed");
        assert!(refreshed.expires_at_ms > 0);
        assert!(refreshed.next_refresh_at_ms > 0);
        assert!(refreshed.expires_at_ms <= before_refresh_ms + 120_000);
        assert!(refreshed.last_error.is_empty());

        let stored = store
            .get_message_by_name::<Provider>("my-graph")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials.get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&"minted-graph-token".to_string())
        );
        assert_eq!(
            stored.credential_expires_at_ms.get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&refreshed.expires_at_ms)
        );
    }

    #[tokio::test]
    async fn refresh_rejects_minted_credential_key_collision_for_attached_sandbox() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-graph-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let mut provider_a = provider("existing-graph", "outlook");
        provider_a.credentials.insert(
            "MS_GRAPH_ACCESS_TOKEN".to_string(),
            "existing-token".to_string(),
        );
        store.put_message(&provider_a).await.unwrap();
        let provider_b = provider("refreshing-graph", "outlook");
        store.put_message(&provider_b).await.unwrap();
        store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: "sandbox-collision".to_string(),
                    name: "collision".to_string(),
                    created_at_ms: 1,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["existing-graph".to_string(), "refreshing-graph".to_string()],
                    ..SandboxSpec::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();
        let state = new_refresh_state(
            &provider_b,
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: Vec::new(),
                refresh_before_seconds: 30,
                max_lifetime_seconds: 60,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let err = refresh_provider_credential(&store, "refreshing-graph", "MS_GRAPH_ACCESS_TOKEN")
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("MS_GRAPH_ACCESS_TOKEN"));
        let stored_state =
            get_refresh_state(&store, provider_b.object_id(), "MS_GRAPH_ACCESS_TOKEN")
                .await
                .unwrap()
                .unwrap();
        assert_eq!(stored_state.status, "error");
        assert!(stored_state.last_error.contains("MS_GRAPH_ACCESS_TOKEN"));
        let stored_provider = store
            .get_message_by_name::<Provider>("refreshing-graph")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !stored_provider
                .credentials
                .contains_key("MS_GRAPH_ACCESS_TOKEN")
        );
    }

    #[tokio::test]
    async fn oauth2_refresh_token_refresh_mints_access_token_and_persists_rotated_refresh_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("client_id=client-id"))
            .and(body_string_contains("refresh_token=old-refresh-token"))
            .and(body_string_contains(
                "scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "delegated-graph-token",
                "refresh_token": "rotated-refresh-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("my-delegated-graph", "outlook");
        store.put_message(&provider).await.unwrap();
        let state = new_refresh_state(
            &provider,
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    ("refresh_token".to_string(), "old-refresh-token".to_string()),
                ]),
                secret_material_keys: vec!["refresh_token".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: vec!["https://graph.microsoft.com/.default".to_string()],
                refresh_before_seconds: 30,
                max_lifetime_seconds: 60,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let refreshed =
            refresh_provider_credential(&store, "my-delegated-graph", "MS_GRAPH_ACCESS_TOKEN")
                .await
                .unwrap();
        assert_eq!(refreshed.status, "refreshed");
        assert!(refreshed.expires_at_ms > 0);

        let stored_provider = store
            .get_message_by_name::<Provider>("my-delegated-graph")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored_provider.credentials.get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&"delegated-graph-token".to_string())
        );
        assert_eq!(
            stored_provider
                .credential_expires_at_ms
                .get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&refreshed.expires_at_ms)
        );

        let stored_state = get_refresh_state(&store, provider.object_id(), "MS_GRAPH_ACCESS_TOKEN")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored_state.material.get("refresh_token"),
            Some(&"rotated-refresh-token".to_string())
        );
        assert!(
            stored_state
                .secret_material_keys
                .iter()
                .any(|key| key == "refresh_token")
        );
    }

    #[tokio::test]
    async fn google_service_account_refresh_mints_and_persists_access_token() {
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
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("my-drive", "google-drive");
        store.put_message(&provider).await.unwrap();
        let state = new_refresh_state(
            &provider,
            "GOOGLE_DRIVE_ACCESS_TOKEN",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt,
                material: HashMap::from([
                    (
                        "client_email".to_string(),
                        "svc@example.iam.gserviceaccount.com".to_string(),
                    ),
                    ("private_key".to_string(), TEST_RSA_PRIVATE_KEY.to_string()),
                ]),
                secret_material_keys: vec!["private_key".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: vec!["https://www.googleapis.com/auth/drive.readonly".to_string()],
                refresh_before_seconds: 300,
                max_lifetime_seconds: 3600,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let refreshed =
            refresh_provider_credential(&store, "my-drive", "GOOGLE_DRIVE_ACCESS_TOKEN")
                .await
                .unwrap();
        assert_eq!(refreshed.status, "refreshed");
        assert!(refreshed.expires_at_ms > 0);

        let stored = store
            .get_message_by_name::<Provider>("my-drive")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials.get("GOOGLE_DRIVE_ACCESS_TOKEN"),
            Some(&"minted-drive-token".to_string())
        );
    }

    #[tokio::test]
    async fn refresh_worker_skips_non_gateway_mintable_strategies() {
        let store = test_store().await;
        let provider = provider("my-external", "outlook");
        store.put_message(&provider).await.unwrap();
        let state = new_refresh_state(
            &provider,
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::External,
                material: HashMap::new(),
                secret_material_keys: Vec::new(),
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before_seconds: 0,
                max_lifetime_seconds: 0,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        run_refresh_worker_tick(&store).await.unwrap();

        let stored_state = get_refresh_state(&store, provider.object_id(), "MS_GRAPH_ACCESS_TOKEN")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(stored_state.status, "error");
        assert!(stored_state.last_error.is_empty());

        let stored_provider = store
            .get_message_by_name::<Provider>("my-external")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !stored_provider
                .credentials
                .contains_key("MS_GRAPH_ACCESS_TOKEN")
        );
    }

    #[test]
    fn refresh_strategy_name_includes_aws_sts() {
        assert_eq!(
            refresh_strategy_name(ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32),
            "aws_sts_assume_role"
        );
    }

    #[tokio::test]
    async fn aws_sts_assume_role_mints_three_credentials_from_mock_endpoint() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .and(body_string_contains("RoleArn=arn"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <AssumedRoleUser>
      <AssumedRoleId>AROA3XFRBF23:test-session</AssumedRoleId>
      <Arn>arn:aws:sts::123456789012:assumed-role/TestRole/test-session</Arn>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAMOCKKEY</AccessKeyId>
      <SecretAccessKey>MockSecretAccessKey123</SecretAccessKey>
      <SessionToken>MockSessionTokenXYZ</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>"#,
            ))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let prov = provider("aws-sts-test", "aws");
        store.put_message(&prov).await.unwrap();

        let state = new_refresh_state(
            &prov,
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    ("session_name".to_string(), "test-session".to_string()),
                    ("aws_access_key_id".to_string(), "AKIATESTKEY".to_string()),
                    (
                        "aws_secret_access_key".to_string(),
                        "TestSecretKey".to_string(),
                    ),
                    ("sts_endpoint_url".to_string(), mock_server.uri()),
                ]),
                secret_material_keys: vec!["aws_secret_access_key".to_string()],
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before_seconds: 300,
                max_lifetime_seconds: 3600,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let refreshed = refresh_provider_credential(&store, "aws-sts-test", "AWS_ACCESS_KEY_ID")
            .await
            .unwrap();
        assert_eq!(refreshed.status, "refreshed");
        assert!(refreshed.expires_at_ms > 0);

        let stored = store
            .get_message_by_name::<Provider>("aws-sts-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials.get("AWS_ACCESS_KEY_ID"),
            Some(&"ASIAMOCKKEY".to_string())
        );
        assert_eq!(
            stored.credentials.get("AWS_SECRET_ACCESS_KEY"),
            Some(&"MockSecretAccessKey123".to_string())
        );
        assert_eq!(
            stored.credentials.get("AWS_SESSION_TOKEN"),
            Some(&"MockSessionTokenXYZ".to_string())
        );
    }

    #[tokio::test]
    async fn apply_minted_credential_writes_additional_keys() {
        use super::apply_minted_credential;

        let store = test_store().await;
        let mut prov = provider("aws-test", "aws");
        prov.credentials
            .insert("AWS_ACCESS_KEY_ID".to_string(), "old-key".to_string());
        store.put_message(&prov).await.unwrap();

        let minted = super::MintedCredential {
            access_token: "AKIAIOSFODNN7EXAMPLE".to_string(),
            expires_at_ms: 4_000_000_000_000,
            refresh_token: None,
            additional_credentials: HashMap::from([
                (
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
                ),
                (
                    "AWS_SESSION_TOKEN".to_string(),
                    "FwoGZXIvYXdzEBYaDH...EXAMPLETOKEN".to_string(),
                ),
            ]),
        };

        apply_minted_credential(&store, &prov, "AWS_ACCESS_KEY_ID", &minted)
            .await
            .unwrap();

        let stored = store
            .get_message_by_name::<Provider>("aws-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials.get("AWS_ACCESS_KEY_ID"),
            Some(&"AKIAIOSFODNN7EXAMPLE".to_string())
        );
        assert_eq!(
            stored.credentials.get("AWS_SECRET_ACCESS_KEY"),
            Some(&"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string())
        );
        assert_eq!(
            stored.credentials.get("AWS_SESSION_TOKEN"),
            Some(&"FwoGZXIvYXdzEBYaDH...EXAMPLETOKEN".to_string())
        );
        assert_eq!(
            stored.credential_expires_at_ms.get("AWS_ACCESS_KEY_ID"),
            Some(&4_000_000_000_000)
        );
        assert_eq!(
            stored.credential_expires_at_ms.get("AWS_SECRET_ACCESS_KEY"),
            Some(&4_000_000_000_000)
        );
        assert_eq!(
            stored.credential_expires_at_ms.get("AWS_SESSION_TOKEN"),
            Some(&4_000_000_000_000)
        );
    }

    #[tokio::test]
    async fn apply_minted_credential_validates_additional_keys_against_sandboxes() {
        use super::apply_minted_credential;

        let store = test_store().await;
        let mut existing_provider = provider("existing-aws", "aws");
        existing_provider
            .credentials
            .insert("AWS_SECRET_ACCESS_KEY".to_string(), "existing".to_string());
        store.put_message(&existing_provider).await.unwrap();

        let refreshing_provider = provider("refreshing-aws", "aws");
        store.put_message(&refreshing_provider).await.unwrap();

        store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: "sandbox-aws-collision".to_string(),
                    name: "aws-collision".to_string(),
                    created_at_ms: 1,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["existing-aws".to_string(), "refreshing-aws".to_string()],
                    ..SandboxSpec::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let minted = super::MintedCredential {
            access_token: "AKIAIOSFODNN7EXAMPLE".to_string(),
            expires_at_ms: 4_000_000_000_000,
            refresh_token: None,
            additional_credentials: HashMap::from([
                (
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                    "secret-key".to_string(),
                ),
                ("AWS_SESSION_TOKEN".to_string(), "session-token".to_string()),
            ]),
        };

        let err =
            apply_minted_credential(&store, &refreshing_provider, "AWS_ACCESS_KEY_ID", &minted)
                .await
                .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("AWS_SECRET_ACCESS_KEY"));
    }

    fn provider(name: &str, provider_type: &str) -> Provider {
        Provider {
            metadata: Some(ObjectMeta {
                id: format!("{name}-id"),
                name: name.to_string(),
                created_at_ms: 1,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            r#type: provider_type.to_string(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
        }
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
