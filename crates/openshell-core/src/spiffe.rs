// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared SPIFFE helpers used by the gateway and sandbox supervisor.

use std::path::Path;

use base64::Engine as _;
use serde::Deserialize;

/// SPIFFE JWT-SVID claims used by `OpenShell` token exchange flows.
#[derive(Debug, Clone, Deserialize)]
pub struct SpiffeJwtClaims {
    pub iss: String,
    pub sub: String,
    pub aud: AudienceClaim,
    #[serde(default)]
    pub exp: i64,
}

/// JWT `aud` claim representation accepted by SPIFFE JWT-SVIDs.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl AudienceClaim {
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JwtSvidParseError {
    #[error("invalid JWT-SVID format")]
    Format,
    #[error("invalid JWT-SVID payload encoding")]
    PayloadEncoding,
    #[error("invalid JWT-SVID payload")]
    Payload,
}

/// Convert a path to a SPIFFE Workload API endpoint URL.
///
/// If the path already has a scheme (`unix:` or `tcp:`), use it as-is.
/// Otherwise, assume it is a Unix socket path and prepend `unix:`.
pub fn workload_api_endpoint(path: &Path) -> String {
    let path = path.to_string_lossy();
    if path.starts_with("unix:") || path.starts_with("tcp:") {
        path.into_owned()
    } else {
        format!("unix:{path}")
    }
}

pub fn parse_unverified_jwt_svid_claims(token: &str) -> Result<SpiffeJwtClaims, JwtSvidParseError> {
    let segments = token.split('.').collect::<Vec<_>>();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(JwtSvidParseError::Format);
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segments[1])
        .map_err(|_| JwtSvidParseError::PayloadEncoding)?;
    serde_json::from_slice::<SpiffeJwtClaims>(&decoded).map_err(|_| JwtSvidParseError::Payload)
}

pub fn trust_domain(subject: &str) -> Option<&str> {
    let rest = subject.strip_prefix("spiffe://")?;
    let (trust_domain, _) = rest.split_once('/').unwrap_or((rest, ""));
    (!trust_domain.is_empty()).then_some(trust_domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsigned_svid_fixture(issuer: &str, subject: &str, audience: serde_json::Value) -> String {
        let header = serde_json::json!({ "alg": "RS256", "kid": "test-key" });
        let payload = serde_json::json!({
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "exp": 4_102_444_800_i64
        });
        let encoded_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).expect("serialize header"));
        let encoded_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).expect("serialize payload"));
        format!("{encoded_header}.{encoded_payload}.signature")
    }

    #[test]
    fn workload_api_endpoint_preserves_explicit_scheme() {
        assert_eq!(
            workload_api_endpoint(Path::new("unix:/run/spire/agent.sock")),
            "unix:/run/spire/agent.sock"
        );
        assert_eq!(
            workload_api_endpoint(Path::new("tcp:127.0.0.1:8081")),
            "tcp:127.0.0.1:8081"
        );
    }

    #[test]
    fn workload_api_endpoint_defaults_to_unix_socket() {
        assert_eq!(
            workload_api_endpoint(Path::new("/run/spire/agent.sock")),
            "unix:/run/spire/agent.sock"
        );
    }

    #[test]
    fn parse_unverified_jwt_svid_claims_accepts_string_audience() {
        let token = unsigned_svid_fixture(
            "https://spiffe.example.test",
            "spiffe://openshell/openshell/sandbox/sb-a",
            serde_json::json!("https://auth.example.com"),
        );

        let claims = parse_unverified_jwt_svid_claims(&token).expect("valid claims");

        assert_eq!(claims.iss, "https://spiffe.example.test");
        assert_eq!(claims.sub, "spiffe://openshell/openshell/sandbox/sb-a");
        assert!(claims.aud.contains("https://auth.example.com"));
        assert!(!claims.aud.contains("https://other.example.com"));
    }

    #[test]
    fn parse_unverified_jwt_svid_claims_accepts_array_audience() {
        let token = unsigned_svid_fixture(
            "https://spiffe.example.test",
            "spiffe://openshell/openshell/sandbox/sb-a",
            serde_json::json!(["https://auth.example.com", "https://other.example.com"]),
        );

        let claims = parse_unverified_jwt_svid_claims(&token).expect("valid claims");

        assert!(claims.aud.contains("https://auth.example.com"));
        assert!(claims.aud.contains("https://other.example.com"));
    }

    #[test]
    fn parse_unverified_jwt_svid_claims_rejects_truncated_jwt() {
        assert!(matches!(
            parse_unverified_jwt_svid_claims("header.payload"),
            Err(JwtSvidParseError::Format)
        ));
    }

    #[test]
    fn parse_unverified_jwt_svid_claims_rejects_empty_jwt_segments() {
        assert!(matches!(
            parse_unverified_jwt_svid_claims("header..signature"),
            Err(JwtSvidParseError::Format)
        ));
    }

    #[test]
    fn trust_domain_extracts_domain_from_spiffe_id() {
        assert_eq!(
            trust_domain("spiffe://openshell/openshell/sandbox/sb-a"),
            Some("openshell")
        );
        assert_eq!(trust_domain("spiffe://openshell"), Some("openshell"));
        assert_eq!(trust_domain("not-a-spiffe-id"), None);
        assert_eq!(trust_domain("spiffe:///empty"), None);
    }
}
