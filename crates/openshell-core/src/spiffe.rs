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

/// # Security
///
/// This function decodes the JWT payload without verifying the signature.
/// Callers must separately verify the JWT signature before trusting the claims.
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

/// Longest SPIFFE ID the SPIFFE specification permits.
const MAX_SPIFFE_ID_BYTES: usize = 2048;

/// Operator-configured prefix of the stable SPIFFE IDs the gateway requests
/// for sandboxes using shared supervision.
///
/// A sandbox's ID is `<prefix>/gateway/<gateway-id>/sandbox/<sandbox-id>`.
/// Both IDs must already be valid SPIFFE path segments; nothing is encoded,
/// so distinct gateway and sandbox IDs always produce distinct SPIFFE IDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxSpiffeIdPrefix(String);

impl SandboxSpiffeIdPrefix {
    /// Accept `spiffe://<trust-domain>` optionally followed by path segments,
    /// with no trailing slash, query, fragment, or percent-encoding.
    pub fn parse(value: &str) -> Result<Self, String> {
        let invalid = || {
            format!(
                "SPIFFE ID prefix must be spiffe://<trust-domain>[/<segment>...] with lowercase trust domain characters [a-z0-9.-_] and path segment characters [A-Za-z0-9.-_]: {value:?}"
            )
        };
        let rest = value.strip_prefix("spiffe://").ok_or_else(invalid)?;
        let (domain, path) = rest
            .split_once('/')
            .map_or((rest, None), |(domain, path)| (domain, Some(path)));
        if domain.is_empty()
            || !domain.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-_".contains(&byte)
            })
        {
            return Err(invalid());
        }
        if let Some(path) = path
            && !path.split('/').all(is_spiffe_path_segment)
        {
            return Err(invalid());
        }
        Ok(Self(value.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Stable SPIFFE ID of `sandbox_id` under `gateway_id`.
    pub fn sandbox_spiffe_id(&self, gateway_id: &str, sandbox_id: &str) -> Result<String, String> {
        if !is_spiffe_path_segment(gateway_id) || !is_spiffe_path_segment(sandbox_id) {
            return Err(
                "gateway and sandbox IDs must be SPIFFE path segments [A-Za-z0-9.-_]".to_string(),
            );
        }
        let id = format!("{}/gateway/{gateway_id}/sandbox/{sandbox_id}", self.0);
        if id.len() > MAX_SPIFFE_ID_BYTES {
            return Err("sandbox SPIFFE ID exceeds 2048 bytes".to_string());
        }
        Ok(id)
    }
}

/// A non-empty SPIFFE path segment other than `.` and `..`.
#[must_use]
pub fn is_spiffe_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
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
    fn sandbox_spiffe_ids_are_unambiguous_and_reject_unsafe_input() {
        let prefix = SandboxSpiffeIdPrefix::parse("spiffe://example.org/openshell").unwrap();
        assert_eq!(
            prefix.sandbox_spiffe_id("gw", "4f1c2b3a-9d8e").unwrap(),
            "spiffe://example.org/openshell/gateway/gw/sandbox/4f1c2b3a-9d8e"
        );
        for invalid in [
            "spiffe://Example.org",
            "spiffe://example.org/",
            "spiffe://example.org//a",
            "spiffe://example.org/a/../b",
            "spiffe://example.org/a%2Fb",
            "spiffe://example.org:8443/a",
            "https://example.org/a",
        ] {
            assert!(SandboxSpiffeIdPrefix::parse(invalid).is_err(), "{invalid}");
        }
        for (gateway, sandbox) in [("gw/x", "a"), ("gw", "a/b"), ("gw", ".."), ("", "a")] {
            assert!(prefix.sandbox_spiffe_id(gateway, sandbox).is_err());
        }
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
