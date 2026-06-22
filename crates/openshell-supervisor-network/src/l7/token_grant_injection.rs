// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Endpoint-bound dynamic token grant injection for HTTP relay paths.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use miette::{Result, miette};
use openshell_core::proto::{ProviderCredentialTokenGrant, ProviderProfileCredential};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest, SeverityId,
    StatusId, Url as OcsfUrl, ctx::ctx as ocsf_ctx, ocsf_emit,
};
use tracing::warn;

use crate::l7::provider::L7Request;
use crate::l7::relay::L7EvalContext;

pub struct TokenGrantRequest<'a> {
    pub provider_key: &'a str,
    pub token_endpoint: &'a str,
    pub jwt_svid_audience: &'a str,
    pub client_assertion_type: &'a str,
    pub audience: &'a str,
    pub scopes: &'a [String],
    pub cache_ttl_seconds: i64,
}

pub trait TokenGrantResolver: Send + Sync {
    fn obtain<'a>(
        &'a self,
        request: TokenGrantRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>>;
}

#[derive(Default)]
pub struct SpiffeTokenGrantResolver;

impl TokenGrantResolver for SpiffeTokenGrantResolver {
    fn obtain<'a>(
        &'a self,
        request: TokenGrantRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
        Box::pin(async move {
            crate::token_grant::obtain_provider_token(
                request.provider_key,
                request.token_endpoint,
                request.jwt_svid_audience,
                request.client_assertion_type,
                request.audience,
                request.scopes,
                request.cache_ttl_seconds,
            )
            .await
        })
    }
}

pub fn default_resolver() -> Arc<dyn TokenGrantResolver> {
    Arc::new(SpiffeTokenGrantResolver)
}

/// Checks for endpoint-bound token grant credentials and injects an
/// Authorization header before forwarding the request upstream.
pub async fn inject_if_needed(req: L7Request, ctx: &L7EvalContext) -> Result<L7Request> {
    let request_path = req
        .target
        .split('?')
        .next()
        .unwrap_or(req.target.as_str())
        .to_string();
    let matched_credential = ctx.dynamic_credentials.as_ref().and_then(|dyn_creds| {
        dyn_creds.read().map_or(None, |creds_guard| {
            creds_guard
                .iter()
                .filter_map(|(key, cred)| {
                    let score = dynamic_credential_key_match_score(
                        key,
                        &ctx.host,
                        ctx.port,
                        &request_path,
                    )?;
                    Some((score, key.clone(), cred.clone()))
                })
                .max_by_key(|(score, key, _)| (*score, key.clone()))
                .map(|(_, key, cred)| (key, cred))
        })
    });

    if let Some((provider_key, cred)) = matched_credential {
        check_placeholder_collision(&req.raw_header, &cred, &ctx.host, ctx.port, &provider_key)?;
        if let Some(ref token_grant) = cred.token_grant {
            inject_token_grant(req, ctx, &request_path, &provider_key, token_grant, &cred).await
        } else {
            inject_static_credential(req, ctx, &request_path, &provider_key, &cred)
        }
    } else {
        Ok(req)
    }
}

async fn inject_token_grant(
    req: L7Request,
    ctx: &L7EvalContext,
    request_path: &str,
    provider_key: &str,
    token_grant: &ProviderCredentialTokenGrant,
    cred: &ProviderProfileCredential,
) -> Result<L7Request> {
    let resolver = ctx
        .token_grant_resolver
        .as_ref()
        .ok_or_else(|| miette!("token grant resolver unavailable"))?;
    let request = token_grant_request(provider_key, token_grant);

    match resolver.obtain(request).await {
        Ok(access_token) => {
            let modified_raw_header =
                inject_token_grant_header(&req.raw_header, cred, &access_token)?;
            let provider_key = ocsf_message_field(provider_key);
            ocsf_emit!(
                HttpActivityBuilder::new(ocsf_ctx())
                    .activity(ActivityId::Other)
                    .action(ActionId::Allowed)
                    .disposition(DispositionId::Allowed)
                    .severity(SeverityId::Informational)
                    .http_request(HttpRequest::new(
                        &req.action,
                        OcsfUrl::new("http", &ctx.host, request_path, ctx.port),
                    ))
                    .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                    .message(format!(
                        "Token grant successful for {} to {}:{}",
                        provider_key, ctx.host, ctx.port
                    ))
                    .build()
            );
            Ok(L7Request {
                action: req.action,
                target: req.target,
                query_params: req.query_params,
                raw_header: modified_raw_header,
                body_length: req.body_length,
            })
        }
        Err(e) => {
            warn!(
                host = %ctx.host,
                port = ctx.port,
                provider = %provider_key,
                error = %e,
                "Token grant failed"
            );
            let provider_key = ocsf_message_field(provider_key);
            ocsf_emit!(
                HttpActivityBuilder::new(ocsf_ctx())
                    .activity(ActivityId::Fail)
                    .action(ActionId::Denied)
                    .disposition(DispositionId::Blocked)
                    .severity(SeverityId::Medium)
                    .status(StatusId::Failure)
                    .http_request(HttpRequest::new(
                        &req.action,
                        OcsfUrl::new("http", &ctx.host, request_path, ctx.port),
                    ))
                    .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                    .message(format!(
                        "Token grant failed for {} to {}:{}: {}",
                        provider_key, ctx.host, ctx.port, e
                    ))
                    .build()
            );
            Err(miette!("Token grant failed: {}", e))
        }
    }
}

fn inject_static_credential(
    req: L7Request,
    ctx: &L7EvalContext,
    request_path: &str,
    provider_key: &str,
    cred: &ProviderProfileCredential,
) -> Result<L7Request> {
    let Some(value) = cred.env_vars.iter().find_map(|env_var| {
        let placeholder = format!(
            "{}{env_var}",
            openshell_core::secrets::PLACEHOLDER_PREFIX_PUBLIC
        );
        ctx.secret_resolver
            .as_ref()
            .and_then(|r| r.resolve_placeholder(&placeholder))
    }) else {
        let provider_key = ocsf_message_field(provider_key);
        ocsf_emit!(
            HttpActivityBuilder::new(ocsf_ctx())
                .activity(ActivityId::Fail)
                .action(ActionId::Denied)
                .disposition(DispositionId::Blocked)
                .severity(SeverityId::Medium)
                .status(StatusId::Failure)
                .http_request(HttpRequest::new(
                    &req.action,
                    OcsfUrl::new("http", &ctx.host, request_path, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .message(format!(
                    "No credential found for {} on provider {}",
                    cred.name, provider_key
                ))
                .build()
        );
        return Err(miette!(
            "no credential value found for credential '{}' on provider {}",
            cred.name,
            provider_key,
        ));
    };
    match cred.auth_style.trim().to_ascii_lowercase().as_str() {
        "bearer" | "header" => {
            validate_static_credential_value(value)?;
            let (header_name, header_value) = credential_auth_header(cred, value)?;
            let modified_raw_header = inject_header(&req.raw_header, &header_name, &header_value)?;
            let provider_key = ocsf_message_field(provider_key);
            ocsf_emit!(
                HttpActivityBuilder::new(ocsf_ctx())
                    .activity(ActivityId::Other)
                    .action(ActionId::Allowed)
                    .disposition(DispositionId::Allowed)
                    .severity(SeverityId::Informational)
                    .http_request(HttpRequest::new(
                        &req.action,
                        OcsfUrl::new("http", &ctx.host, request_path, ctx.port),
                    ))
                    .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                    .message(format!(
                        "Provider credential injected for {} on {}:{}",
                        provider_key, ctx.host, ctx.port
                    ))
                    .build()
            );
            Ok(L7Request {
                action: req.action,
                target: req.target,
                query_params: req.query_params,
                raw_header: modified_raw_header,
                body_length: req.body_length,
            })
        }
        other => Err(miette!(
            "credential injection for auth_style '{}' is not yet supported",
            other
        )),
    }
}

/// Fail-closed check: reject injection if the request already has a
/// placeholder-based value for the header this credential targets.
/// Applies to both token grant and static credential paths.
///
/// This function operates byte-wise so that non-UTF-8 obs-text bytes
/// elsewhere in the header block do not cause the check to be silently
/// skipped.
fn check_placeholder_collision(
    raw_header: &[u8],
    cred: &ProviderProfileCredential,
    host: &str,
    port: u16,
    provider_key: &str,
) -> Result<()> {
    let header_name = match cred.auth_style.trim().to_ascii_lowercase().as_str() {
        "" | "bearer" => {
            if cred.header_name.trim().is_empty() {
                "Authorization"
            } else {
                cred.header_name.trim()
            }
        }
        "header" => cred.header_name.trim(),
        _ => return Ok(()),
    };
    if header_name.is_empty() {
        return Ok(());
    }
    let header_name_bytes = header_name.as_bytes();
    let placeholder_marker = openshell_core::secrets::PLACEHOLDER_PREFIX_PUBLIC.as_bytes();
    let alias_marker = openshell_core::secrets::PROVIDER_ALIAS_MARKER_PUBLIC.as_bytes();

    // Find the end of the header block (\r\n\r\n) so we don't scan the body.
    let header_end = raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw_header.len());

    // Split header block into lines (skip the request line).
    for line in raw_header[..header_end].split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon_pos) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = trim_ascii(&line[..colon_pos]);
        if !name.eq_ignore_ascii_case(header_name_bytes) {
            continue;
        }
        let value = &line[colon_pos + 1..];
        if contains_bytes(value, placeholder_marker) || contains_bytes(value, alias_marker) {
            return Err(miette!(
                "credential injection rejected: header '{}' on {}:{} already \
                 contains a placeholder-based value from provider {}; remove \
                 the placeholder or the profile credential to resolve the conflict",
                header_name,
                host,
                port,
                provider_key,
            ));
        }
    }
    Ok(())
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |p| p + 1);
    &bytes[start..end]
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn ocsf_message_field(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { '_' } else { ch })
        .collect()
}

fn token_grant_request<'a>(
    provider_key: &'a str,
    token_grant: &'a ProviderCredentialTokenGrant,
) -> TokenGrantRequest<'a> {
    TokenGrantRequest {
        provider_key,
        token_endpoint: &token_grant.token_endpoint,
        jwt_svid_audience: &token_grant.jwt_svid_audience,
        client_assertion_type: &token_grant.client_assertion_type,
        audience: &token_grant.audience,
        scopes: &token_grant.scopes,
        cache_ttl_seconds: token_grant.cache_ttl_seconds,
    }
}

#[cfg(test)]
fn dynamic_credential_key_matches(key: &str, host: &str, port: u16, request_path: &str) -> bool {
    dynamic_credential_key_match_score(key, host, port, request_path).is_some()
}

fn dynamic_credential_key_match_score(
    key: &str,
    host: &str,
    port: u16,
    request_path: &str,
) -> Option<u32> {
    let mut parts = key.splitn(4, '\t');
    let endpoint_host = parts.next()?;
    let endpoint_port = parts.next()?;
    let endpoint_path = parts.next()?;
    let _provider_key = parts.next()?;

    if endpoint_port.parse::<u16>().ok() != Some(port) {
        return None;
    }

    let host_lc = host.to_ascii_lowercase();
    let endpoint_host_lc = endpoint_host.to_ascii_lowercase();
    if !host_pattern_matches(&endpoint_host_lc, &host_lc)
        || !crate::l7::endpoint_path_matches(endpoint_path, request_path)
    {
        return None;
    }

    Some(host_pattern_specificity(&endpoint_host_lc) + endpoint_path_specificity(endpoint_path))
}

fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    if pattern == host {
        return true;
    }
    if !pattern.contains('*') {
        return false;
    }

    let pattern_labels: Vec<&str> = pattern.split('.').collect();
    let host_labels: Vec<&str> = host.split('.').collect();
    host_pattern_labels_match(&pattern_labels, &host_labels)
}

fn host_pattern_labels_match(pattern: &[&str], host: &[&str]) -> bool {
    match pattern.split_first() {
        None => host.is_empty(),
        Some((label, rest)) if *label == "**" => {
            host_pattern_labels_match(rest, host)
                || (!host.is_empty() && host_pattern_labels_match(pattern, &host[1..]))
        }
        Some((label, rest)) if *label == "*" => {
            !host.is_empty() && host_pattern_labels_match(rest, &host[1..])
        }
        Some((literal, rest)) => {
            host.first().is_some_and(|label| label == literal)
                && host_pattern_labels_match(rest, &host[1..])
        }
    }
}

fn host_pattern_specificity(pattern: &str) -> u32 {
    let wildcard_penalty = count_as_u32(pattern.matches('*').count());
    let label_count = count_as_u32(pattern.split('.').filter(|label| !label.is_empty()).count());
    let literal_chars = count_as_u32(pattern.chars().filter(|ch| *ch != '*').count());
    100_000u32
        .saturating_sub(wildcard_penalty.saturating_mul(10_000))
        .saturating_add(label_count.saturating_mul(100))
        .saturating_add(literal_chars)
}

fn endpoint_path_specificity(path: &str) -> u32 {
    if path.is_empty() || path == "**" {
        return 0;
    }
    1_000_000u32.saturating_add(count_as_u32(path.chars().filter(|ch| *ch != '*').count()))
}

fn count_as_u32(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// Validates a static credential value at the injection sink.  Unlike
/// `validate_access_token` (token68 for token grants), this only rejects
/// characters that would enable HTTP header injection.
fn validate_static_credential_value(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(miette!("static credential value must not be empty"));
    }
    if value.bytes().any(|b| matches!(b, b'\r' | b'\n' | b'\0')) {
        return Err(miette!(
            "static credential value contains unsafe HTTP header bytes (CR, LF, or NUL)"
        ));
    }
    Ok(())
}

fn inject_token_grant_header(
    raw_header: &[u8],
    credential: &ProviderProfileCredential,
    access_token: &str,
) -> Result<Vec<u8>> {
    crate::token_grant::validate_access_token(access_token)?;
    let (header_name, header_value) = credential_auth_header(credential, access_token)?;
    inject_header(raw_header, &header_name, &header_value)
}

fn credential_auth_header(
    credential: &ProviderProfileCredential,
    access_token: &str,
) -> Result<(String, String)> {
    match credential.auth_style.trim().to_ascii_lowercase().as_str() {
        "" | "bearer" => {
            let header_name = if credential.header_name.trim().is_empty() {
                "Authorization"
            } else {
                credential.header_name.trim()
            };
            validate_header_name(header_name)?;
            Ok((header_name.to_string(), format!("Bearer {access_token}")))
        }
        "header" => {
            let header_name = credential.header_name.trim();
            if header_name.is_empty() {
                return Err(miette!("credential auth_style header requires header_name"));
            }
            validate_header_name(header_name)?;
            Ok((header_name.to_string(), access_token.to_string()))
        }
        other => Err(miette!(
            "credential auth_style '{other}' is not supported; use bearer or header"
        )),
    }
}

fn validate_header_name(header_name: &str) -> Result<()> {
    let valid = !header_name.is_empty()
        && header_name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        });
    if !valid {
        return Err(miette!(
            "credential header_name is not a valid HTTP header name"
        ));
    }
    match header_name.to_ascii_lowercase().as_str() {
        "host" | "content-length" | "transfer-encoding" | "connection" => Err(miette!(
            "credential header_name may not override HTTP framing or connection headers"
        )),
        _ => Ok(()),
    }
}

fn inject_header(raw_header: &[u8], header_name: &str, header_value: &str) -> Result<Vec<u8>> {
    let header_end = raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| miette!("HTTP headers missing final CRLF CRLF"))?;

    let header_block = std::str::from_utf8(&raw_header[..header_end])
        .map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let mut lines = header_block.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| miette!("HTTP headers missing request line"))?;

    let inserted_header = format!("{header_name}: {header_value}");
    let mut new_raw_header = Vec::with_capacity(raw_header.len() + inserted_header.len() + 2);
    new_raw_header.extend_from_slice(request_line.as_bytes());
    new_raw_header.extend_from_slice(b"\r\n");

    for line in lines {
        if line.is_empty() {
            break;
        }
        if line
            .split_once(':')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case(header_name))
        {
            continue;
        }
        new_raw_header.extend_from_slice(line.as_bytes());
        new_raw_header.extend_from_slice(b"\r\n");
    }

    new_raw_header.extend_from_slice(inserted_header.as_bytes());
    new_raw_header.extend_from_slice(&raw_header[header_end..]);

    Ok(new_raw_header)
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use openshell_core::proto::{ProviderCredentialTokenGrant, ProviderProfileCredential};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    struct FakeTokenGrantResolver {
        requests: Arc<Mutex<Vec<OwnedTokenGrantRequest>>>,
        response: std::result::Result<String, String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct OwnedTokenGrantRequest {
        provider_key: String,
        token_endpoint: String,
        jwt_svid_audience: String,
        client_assertion_type: String,
        audience: String,
        scopes: Vec<String>,
        cache_ttl_seconds: i64,
    }

    pub struct TokenGrantTestFixture {
        dynamic_credentials: Arc<std::sync::RwLock<HashMap<String, ProviderProfileCredential>>>,
        resolver: Arc<dyn TokenGrantResolver>,
        requests: Arc<Mutex<Vec<OwnedTokenGrantRequest>>>,
    }

    impl TokenGrantTestFixture {
        pub fn success(key: &str, token: &str) -> Self {
            Self::new(key, Ok(token))
        }

        pub fn failure(key: &str, error: &str) -> Self {
            Self::new(key, Err(error))
        }

        fn new(key: &str, response: std::result::Result<&str, &str>) -> Self {
            let requests = Arc::new(Mutex::new(Vec::new()));
            let resolver = Arc::new(FakeTokenGrantResolver {
                requests: requests.clone(),
                response: response.map(str::to_string).map_err(str::to_string),
            });

            let mut dynamic_credentials = HashMap::new();
            dynamic_credentials.insert(
                key.to_string(),
                ProviderProfileCredential {
                    name: "access_token".to_string(),
                    auth_style: "bearer".to_string(),
                    header_name: "Authorization".to_string(),
                    token_grant: Some(token_grant()),
                    ..Default::default()
                },
            );

            Self {
                dynamic_credentials: Arc::new(std::sync::RwLock::new(dynamic_credentials)),
                resolver,
                requests,
            }
        }

        pub fn dynamic_credentials(
            &self,
        ) -> Arc<std::sync::RwLock<HashMap<String, ProviderProfileCredential>>> {
            self.dynamic_credentials.clone()
        }

        pub fn resolver(&self) -> Arc<dyn TokenGrantResolver> {
            self.resolver.clone()
        }

        pub fn assert_one_request(&self, expected_provider_key: &str) {
            let requests = self
                .requests
                .lock()
                .expect("fake token grant requests lock poisoned");
            assert_eq!(requests.len(), 1);

            let request = &requests[0];
            assert_eq!(request.provider_key, expected_provider_key);
            assert_eq!(request.token_endpoint, "https://auth.example.com/token");
            assert_eq!(request.jwt_svid_audience, "https://auth.example.com");
            assert_eq!(
                request.client_assertion_type,
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            );
            assert_eq!(request.audience, "api://example");
            assert_eq!(request.scopes, ["read"]);
            assert_eq!(request.cache_ttl_seconds, 300);
        }
    }

    fn token_grant() -> ProviderCredentialTokenGrant {
        ProviderCredentialTokenGrant {
            token_endpoint: "https://auth.example.com/token".to_string(),
            audience: "api://example".to_string(),
            jwt_svid_audience: "https://auth.example.com".to_string(),
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                .to_string(),
            scopes: vec!["read".to_string()],
            cache_ttl_seconds: 300,
            audience_overrides: Vec::new(),
        }
    }

    impl TokenGrantResolver for FakeTokenGrantResolver {
        fn obtain<'a>(
            &'a self,
            request: TokenGrantRequest<'a>,
        ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
            let owned = OwnedTokenGrantRequest {
                provider_key: request.provider_key.to_string(),
                token_endpoint: request.token_endpoint.to_string(),
                jwt_svid_audience: request.jwt_svid_audience.to_string(),
                client_assertion_type: request.client_assertion_type.to_string(),
                audience: request.audience.to_string(),
                scopes: request.scopes.to_vec(),
                cache_ttl_seconds: request.cache_ttl_seconds,
            };
            Box::pin(async move {
                self.requests
                    .lock()
                    .expect("fake token grant requests lock poisoned")
                    .push(owned);
                self.response.clone().map_err(|err| miette!("{err}"))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7::provider::{BodyLength, L7Request};
    use crate::l7::token_grant_injection::test_support::TokenGrantTestFixture;

    fn credential(auth_style: &str, header_name: &str) -> ProviderProfileCredential {
        ProviderProfileCredential {
            auth_style: auth_style.to_string(),
            header_name: header_name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn dynamic_credential_key_matches_endpoint_host_port_and_path() {
        let key = "api.example.com\t443\t/repos/**\tgithub:access_token";

        assert!(dynamic_credential_key_matches(
            key,
            "api.example.com",
            443,
            "/repos/owner/repo"
        ));
        assert!(!dynamic_credential_key_matches(
            key,
            "uploads.example.com",
            443,
            "/repos/owner/repo"
        ));
        assert!(!dynamic_credential_key_matches(
            key,
            "api.example.com",
            80,
            "/repos/owner/repo"
        ));
        assert!(!dynamic_credential_key_matches(
            key,
            "api.example.com",
            443,
            "/orgs/owner"
        ));
    }

    #[test]
    fn dynamic_credential_key_matches_wildcard_hosts_and_empty_path() {
        let key = "*.example.com\t443\t\tprovider:access_token";

        assert!(dynamic_credential_key_matches(
            key,
            "api.example.com",
            443,
            "/anything"
        ));
        assert!(!dynamic_credential_key_matches(
            key,
            "api.other.com",
            443,
            "/anything"
        ));
        assert!(!dynamic_credential_key_matches(
            key,
            "nested.api.example.com",
            443,
            "/anything"
        ));
    }

    #[test]
    fn dynamic_credential_key_matches_double_wildcard_hosts() {
        let key = "**.example.com\t443\t\tprovider:access_token";

        assert!(dynamic_credential_key_matches(
            key,
            "api.example.com",
            443,
            "/anything"
        ));
        assert!(dynamic_credential_key_matches(
            key,
            "nested.api.example.com",
            443,
            "/anything"
        ));
    }

    #[test]
    fn dynamic_credential_match_score_prefers_path_specific_key() {
        let default_key = "alpha.default.svc.cluster.local\t80\t\tprovider:access_token";
        let path_key = "alpha.default.svc.cluster.local\t80\t/admin/**\tprovider:access_token";
        let request_path = "/admin/users";

        let default_score = dynamic_credential_key_match_score(
            default_key,
            "alpha.default.svc.cluster.local",
            80,
            request_path,
        )
        .expect("default key should match");
        let path_score = dynamic_credential_key_match_score(
            path_key,
            "alpha.default.svc.cluster.local",
            80,
            request_path,
        )
        .expect("path key should match");

        assert!(path_score > default_score);
    }

    #[test]
    fn inject_token_grant_header_replaces_existing_authorization() {
        let raw = b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nauthorization: Bearer stale-token\r\nAccept: application/json\r\n\r\n";

        let rewritten =
            inject_token_grant_header(raw, &credential("bearer", "Authorization"), "grant-token")
                .expect("header should rewrite");
        let rewritten = String::from_utf8(rewritten).expect("rewritten header should be UTF-8");

        assert!(rewritten.contains("Authorization: Bearer grant-token\r\n"));
        assert!(!rewritten.contains("stale-token"));
        assert_eq!(
            rewritten
                .lines()
                .filter(|line| line
                    .split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization")))
                .count(),
            1
        );
    }

    #[test]
    fn inject_token_grant_header_replaces_existing_authorization_with_ows_before_colon() {
        let raw = b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization : Bearer stale-token\r\nAccept: application/json\r\n\r\n";

        let rewritten =
            inject_token_grant_header(raw, &credential("bearer", "Authorization"), "grant-token")
                .expect("header should rewrite");
        let rewritten = String::from_utf8(rewritten).expect("rewritten header should be UTF-8");

        assert!(rewritten.contains("Authorization: Bearer grant-token\r\n"));
        assert!(!rewritten.contains("stale-token"));
        assert_eq!(
            rewritten
                .lines()
                .filter(|line| line
                    .split_once(':')
                    .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("authorization")))
                .count(),
            1
        );
    }

    #[test]
    fn credential_auth_header_rejects_framing_and_connection_headers() {
        for header_name in ["Host", "Content-Length", "Transfer-Encoding", "Connection"] {
            let err = credential_auth_header(&credential("header", header_name), "grant-token")
                .expect_err("framing header override should be rejected");
            assert_eq!(
                err.to_string(),
                "credential header_name may not override HTTP framing or connection headers"
            );
        }
    }

    #[test]
    fn inject_token_grant_header_preserves_header_terminator_before_body() {
        let raw = b"POST /v1 HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\n\r\nOK";

        let rewritten = inject_token_grant_header(raw, &credential("bearer", ""), "grant-token")
            .expect("header should rewrite");

        assert_eq!(
            rewritten,
            b"POST /v1 HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\nAuthorization: Bearer grant-token\r\n\r\nOK"
        );
    }

    #[test]
    fn inject_token_grant_header_uses_custom_header_style() {
        let raw = b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nX-Api-Token: stale-token\r\n\r\n";

        let rewritten =
            inject_token_grant_header(raw, &credential("header", "X-Api-Token"), "grant-token")
                .expect("header should rewrite");
        let rewritten = String::from_utf8(rewritten).expect("rewritten header should be UTF-8");

        assert!(rewritten.contains("X-Api-Token: grant-token\r\n"));
        assert!(!rewritten.contains("stale-token"));
        assert!(!rewritten.contains("Bearer grant-token"));
    }

    #[test]
    fn inject_token_grant_header_rejects_malformed_access_token() {
        let raw = b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";

        let err = inject_token_grant_header(
            raw,
            &credential("bearer", "Authorization"),
            "grant-token\r\nX-Injected: yes",
        )
        .expect_err("malformed token must not be injected");

        assert_eq!(
            err.to_string(),
            "token grant returned a malformed access token"
        );
    }

    #[tokio::test]
    async fn inject_if_needed_uses_configured_resolver() {
        let fixture = TokenGrantTestFixture::success(
            "api.example.com\t443\t/v1/**\tprovider:access_token",
            "grant-token",
        );

        let ctx = L7EvalContext {
            host: "api.example.com".into(),
            port: 443,
            policy_name: "api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: Some(fixture.dynamic_credentials()),
            token_grant_resolver: Some(fixture.resolver()),
        };
        let req = L7Request {
            action: "GET".to_string(),
            target: "/v1/projects".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: b"GET /v1/projects HTTP/1.1\r\nHost: api.example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let rewritten = inject_if_needed(req, &ctx)
            .await
            .expect("fake token grant should inject");
        let rewritten =
            String::from_utf8(rewritten.raw_header).expect("rewritten request should be UTF-8");

        assert!(rewritten.contains("Authorization: Bearer grant-token\r\n"));
        fixture.assert_one_request("api.example.com\t443\t/v1/**\tprovider:access_token");
    }

    #[tokio::test]
    async fn inject_if_needed_rejects_malformed_resolver_token() {
        let fixture = TokenGrantTestFixture::success(
            "api.example.com\t443\t/v1/**\tprovider:access_token",
            "grant-token\r\nX-Injected: yes",
        );

        let ctx = L7EvalContext {
            host: "api.example.com".into(),
            port: 443,
            policy_name: "api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: Some(fixture.dynamic_credentials()),
            token_grant_resolver: Some(fixture.resolver()),
        };
        let req = L7Request {
            action: "GET".to_string(),
            target: "/v1/projects".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: b"GET /v1/projects HTTP/1.1\r\nHost: api.example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let err = inject_if_needed(req, &ctx)
            .await
            .expect_err("malformed resolver token should fail closed");

        assert_eq!(
            err.to_string(),
            "token grant returned a malformed access token"
        );
        fixture.assert_one_request("api.example.com\t443\t/v1/**\tprovider:access_token");
    }

    fn static_credential_ctx(
        env_var: &str,
        secret_value: &str,
        auth_style: &str,
        header_name: &str,
    ) -> (L7EvalContext, String) {
        let (_, resolver) = openshell_core::secrets::SecretResolver::from_provider_env(
            std::iter::once((env_var.to_string(), secret_value.to_string())).collect(),
        );

        let key = format!("api.example.com\t443\t\tmy-provider:{env_var}");
        let mut dynamic_credentials = std::collections::HashMap::new();
        dynamic_credentials.insert(
            key.clone(),
            ProviderProfileCredential {
                name: "api_token".to_string(),
                env_vars: vec![env_var.to_string()],
                auth_style: auth_style.to_string(),
                header_name: header_name.to_string(),
                token_grant: None,
                ..Default::default()
            },
        );

        let ctx = L7EvalContext {
            host: "api.example.com".into(),
            port: 443,
            policy_name: "api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: resolver.map(Arc::new),
            activity_tx: None,
            dynamic_credentials: Some(Arc::new(std::sync::RwLock::new(dynamic_credentials))),
            token_grant_resolver: None,
        };
        (ctx, key)
    }

    #[tokio::test]
    async fn inject_static_credential_injects_bearer_token() {
        let (ctx, _) =
            static_credential_ctx("GITHUB_TOKEN", "ghp_secret123", "bearer", "Authorization");
        let req = L7Request {
            action: "GET".to_string(),
            target: "/repos/owner/repo".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: b"GET /repos/owner/repo HTTP/1.1\r\nHost: api.example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let rewritten = inject_if_needed(req, &ctx)
            .await
            .expect("static credential injection should succeed");
        let rewritten =
            String::from_utf8(rewritten.raw_header).expect("rewritten request should be UTF-8");

        assert!(rewritten.contains("Authorization: Bearer ghp_secret123\r\n"));
    }

    #[tokio::test]
    async fn inject_static_credential_injects_custom_header() {
        let (ctx, _) =
            static_credential_ctx("ANTHROPIC_API_KEY", "sk-ant-secret", "header", "x-api-key");
        let req = L7Request {
            action: "GET".to_string(),
            target: "/v1/messages".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: b"GET /v1/messages HTTP/1.1\r\nHost: api.example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let rewritten = inject_if_needed(req, &ctx)
            .await
            .expect("static credential injection should succeed");
        let rewritten =
            String::from_utf8(rewritten.raw_header).expect("rewritten request should be UTF-8");

        assert!(rewritten.contains("x-api-key: sk-ant-secret\r\n"));
        assert!(!rewritten.contains("Bearer"));
    }

    #[tokio::test]
    async fn inject_static_credential_fails_when_credential_missing() {
        // Set up a credential entry pointing to an env var that is NOT in the resolver.
        let mut dynamic_credentials = std::collections::HashMap::new();
        dynamic_credentials.insert(
            "api.example.com\t443\t\tmy-provider:MISSING_TOKEN".to_string(),
            ProviderProfileCredential {
                name: "api_token".to_string(),
                env_vars: vec!["MISSING_TOKEN".to_string()],
                auth_style: "bearer".to_string(),
                header_name: "Authorization".to_string(),
                token_grant: None,
                ..Default::default()
            },
        );
        let ctx = L7EvalContext {
            host: "api.example.com".into(),
            port: 443,
            policy_name: "api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: Some(Arc::new(std::sync::RwLock::new(dynamic_credentials))),
            token_grant_resolver: None,
        };
        let req = L7Request {
            action: "GET".to_string(),
            target: "/v1/data".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: b"GET /v1/data HTTP/1.1\r\nHost: api.example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let err = inject_if_needed(req, &ctx)
            .await
            .expect_err("missing credential should fail closed");
        assert!(err.to_string().contains("no credential value found"));
    }

    #[tokio::test]
    async fn inject_static_credential_resolves_fallback_env_var() {
        // Credential declares two env vars, only the second is in the resolver.
        let (_, resolver) = openshell_core::secrets::SecretResolver::from_provider_env(
            std::iter::once(("GH_TOKEN".to_string(), "ghp_fallback".to_string())).collect(),
        );
        let mut dynamic_credentials = std::collections::HashMap::new();
        dynamic_credentials.insert(
            "api.example.com\t443\t\tmy-provider:api_token".to_string(),
            ProviderProfileCredential {
                name: "api_token".to_string(),
                env_vars: vec!["GITHUB_TOKEN".to_string(), "GH_TOKEN".to_string()],
                auth_style: "bearer".to_string(),
                header_name: "Authorization".to_string(),
                token_grant: None,
                ..Default::default()
            },
        );
        let ctx = L7EvalContext {
            host: "api.example.com".into(),
            port: 443,
            policy_name: "api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: resolver.map(Arc::new),
            activity_tx: None,
            dynamic_credentials: Some(Arc::new(std::sync::RwLock::new(dynamic_credentials))),
            token_grant_resolver: None,
        };
        let req = L7Request {
            action: "GET".to_string(),
            target: "/repos".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: b"GET /repos HTTP/1.1\r\nHost: api.example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let rewritten = inject_if_needed(req, &ctx)
            .await
            .expect("should resolve fallback env var");
        let rewritten =
            String::from_utf8(rewritten.raw_header).expect("rewritten request should be UTF-8");

        assert!(rewritten.contains("Authorization: Bearer ghp_fallback\r\n"));
    }

    #[tokio::test]
    async fn inject_static_credential_rejects_unsupported_auth_style() {
        let (ctx, _) = static_credential_ctx("API_KEY", "secret123", "query", "");
        let req = L7Request {
            action: "GET".to_string(),
            target: "/v1/data".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: b"GET /v1/data HTTP/1.1\r\nHost: api.example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let err = inject_if_needed(req, &ctx)
            .await
            .expect_err("unsupported auth_style should fail");
        assert!(err.to_string().contains("not yet supported"));
    }

    #[tokio::test]
    async fn inject_static_credential_rejects_placeholder_collision() {
        let (ctx, _) =
            static_credential_ctx("GITHUB_TOKEN", "ghp_secret123", "bearer", "Authorization");
        let req = L7Request {
            action: "GET".to_string(),
            target: "/repos/owner/repo".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: b"GET /repos/owner/repo HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer openshell:resolve:env:GITHUB_TOKEN\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let err = inject_if_needed(req, &ctx)
            .await
            .expect_err("placeholder/profile collision must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("placeholder"),
            "error should mention placeholder conflict, got: {msg}"
        );
    }

    #[tokio::test]
    async fn inject_token_grant_rejects_placeholder_collision() {
        let fixture = TokenGrantTestFixture::success(
            "api.example.com\t443\t/v1/**\tprovider:access_token",
            "grant-token",
        );
        let ctx = L7EvalContext {
            host: "api.example.com".into(),
            port: 443,
            policy_name: "api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: Some(fixture.dynamic_credentials()),
            token_grant_resolver: Some(fixture.resolver()),
        };
        let req = L7Request {
            action: "GET".to_string(),
            target: "/v1/projects".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: b"GET /v1/projects HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer openshell:resolve:env:MY_TOKEN\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let err = inject_if_needed(req, &ctx)
            .await
            .expect_err("placeholder/profile collision must fail closed for token grants too");
        let msg = err.to_string();
        assert!(
            msg.contains("placeholder"),
            "error should mention placeholder conflict, got: {msg}"
        );
    }

    #[tokio::test]
    async fn inject_static_credential_rejects_crlf_value_end_to_end() {
        // SecretResolver also rejects CRLF at resolution time, so the e2e
        // path fails before reaching the sink validation.  This test ensures
        // the overall pipeline fails closed for CRLF credential values.
        let (ctx, _) = static_credential_ctx(
            "API_KEY",
            "secret\r\nX-Injected: yes",
            "header",
            "x-api-key",
        );
        let req = L7Request {
            action: "GET".to_string(),
            target: "/v1/data".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: b"GET /v1/data HTTP/1.1\r\nHost: api.example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        inject_if_needed(req, &ctx)
            .await
            .expect_err("CRLF in credential value must be rejected");
    }

    #[test]
    fn validate_static_credential_value_rejects_crlf() {
        let err = validate_static_credential_value("secret\r\nX-Injected: yes")
            .expect_err("CRLF must be rejected");
        assert!(err.to_string().contains("unsafe HTTP header bytes"));
    }

    #[test]
    fn validate_static_credential_value_rejects_null() {
        let err =
            validate_static_credential_value("secret\0rest").expect_err("NUL must be rejected");
        assert!(err.to_string().contains("unsafe HTTP header bytes"));
    }

    #[test]
    fn validate_static_credential_value_rejects_empty() {
        let err = validate_static_credential_value("").expect_err("empty must be rejected");
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_static_credential_value_accepts_non_token68() {
        // Static credentials can contain characters outside the token68
        // alphabet — this is the key difference from token grant validation.
        validate_static_credential_value("sk-ant-api03-abc123")
            .expect("API key with non-token68 chars should be accepted");
    }

    #[tokio::test]
    async fn inject_no_match_passes_request_through() {
        let (ctx, _) = static_credential_ctx("TOKEN", "secret", "bearer", "Authorization");
        let req = L7Request {
            action: "GET".to_string(),
            target: "/data".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: b"GET /data HTTP/1.1\r\nHost: other.example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        // Host doesn't match, so request should pass through unmodified.
        let mut ctx_wrong_host = ctx;
        ctx_wrong_host.host = "other.example.com".into();

        let result = inject_if_needed(req, &ctx_wrong_host)
            .await
            .expect("unmatched request should pass through");
        let raw = String::from_utf8(result.raw_header).expect("UTF-8");
        assert!(!raw.contains("Authorization"));
    }

    #[tokio::test]
    async fn inject_static_credential_rejects_placeholder_collision_with_non_utf8_obs_text() {
        // A request with non-UTF-8 obs-text in another header must NOT cause
        // check_placeholder_collision to skip the scan.  The Authorization
        // header itself carries a placeholder, so the check must reject it
        // even though the overall header block is not valid UTF-8.
        let (ctx, _) =
            static_credential_ctx("GITHUB_TOKEN", "ghp_secret123", "bearer", "Authorization");
        let mut raw = b"GET /repos/owner/repo HTTP/1.1\r\nHost: api.example.com\r\n".to_vec();
        raw.extend_from_slice(b"Authorization: Bearer openshell:resolve:env:GITHUB_TOKEN\r\n");
        // obs-text byte (0x80) in a different header — valid HTTP but not valid UTF-8.
        raw.extend_from_slice(b"X-Custom: value\x80rest\r\n");
        raw.extend_from_slice(b"\r\n");
        let req = L7Request {
            action: "GET".to_string(),
            target: "/repos/owner/repo".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: raw,
            body_length: BodyLength::None,
        };

        let err = inject_if_needed(req, &ctx)
            .await
            .expect_err("placeholder collision must be detected despite non-UTF-8 elsewhere");
        let msg = err.to_string();
        assert!(
            msg.contains("placeholder"),
            "error should mention placeholder conflict, got: {msg}"
        );
    }

    #[tokio::test]
    async fn inject_if_needed_passthrough_preserves_graphql_body_in_raw_header() {
        // GraphQL inspection appends the full request body to raw_header.
        // inject_if_needed must pass this through unchanged when no credentials
        // are configured, so the relay function receives the body intact.
        let body = b"{\"query\":\"query Viewer { viewer { login } }\"}";
        let mut raw = b"POST /graphql HTTP/1.1\r\nHost: graphql.example.com\r\nContent-Type: application/json\r\nContent-Length: 46\r\n\r\n".to_vec();
        raw.extend_from_slice(body);
        let raw_clone = raw.clone();
        let ctx = L7EvalContext {
            host: "graphql.example.com".into(),
            port: 443,
            policy_name: "api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
        };
        let req = L7Request {
            action: "POST".to_string(),
            target: "/graphql".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: raw,
            body_length: BodyLength::ContentLength(body.len() as u64),
        };

        let result = inject_if_needed(req, &ctx)
            .await
            .expect("no-credential passthrough should succeed");
        assert_eq!(
            result.raw_header, raw_clone,
            "raw_header (including body) must be preserved exactly"
        );
        assert!(
            matches!(result.body_length, BodyLength::ContentLength(n) if n == body.len() as u64),
            "body_length must be preserved"
        );
    }

    #[tokio::test]
    async fn inject_static_credential_works_with_graphql_body_in_raw_header() {
        // When a credential IS injected on a GraphQL-style request (body in
        // raw_header), the body must be preserved after the rewritten headers.
        let body = b"{\"query\":\"query Viewer { viewer { login } }\"}";
        let mut raw = b"POST /graphql HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 46\r\n\r\n".to_vec();
        raw.extend_from_slice(body);
        let (ctx, _) = static_credential_ctx("API_KEY", "sk-secret", "header", "x-api-key");
        let req = L7Request {
            action: "POST".to_string(),
            target: "/graphql".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: raw,
            body_length: BodyLength::ContentLength(body.len() as u64),
        };

        let result = inject_if_needed(req, &ctx)
            .await
            .expect("credential injection on GraphQL body-in-raw-header should succeed");
        let raw_str = String::from_utf8(result.raw_header.clone()).expect("UTF-8");
        assert!(
            raw_str.contains("x-api-key: sk-secret\r\n"),
            "injected header must be present"
        );
        // Body must appear after \r\n\r\n
        let header_end = result
            .raw_header
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("must have header terminator");
        let body_after = &result.raw_header[header_end + 4..];
        assert_eq!(
            body_after, body,
            "body must be preserved after header injection"
        );
        assert!(
            matches!(result.body_length, BodyLength::ContentLength(n) if n == body.len() as u64),
            "body_length must be preserved"
        );
    }
}
