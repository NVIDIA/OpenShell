// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal, signature-unverified JWT inspection shared by gateway clients.
//!
//! Used only for client-side refresh scheduling (deciding when a bearer is
//! near expiry). It never verifies the signature and must not be used for
//! any authorization decision. Both the sandbox-side
//! [`crate::grpc_client`] and the user-facing `openshell-sdk` refresh path
//! derive token expiry from here so the decode lives in one place.

/// Decode the numeric `exp` claim (Unix seconds) from a JWT payload without
/// verifying the signature.
///
/// Returns `None` when `token` is not a parseable JWT or has no integer `exp`
/// claim. A leading `Bearer ` prefix is tolerated so callers can pass either a
/// raw token or an `authorization` header value.
#[must_use]
pub fn parse_exp_secs(token: &str) -> Option<i64> {
    use base64::Engine;
    let raw = token.strip_prefix("Bearer ").unwrap_or(token);
    let mut parts = raw.splitn(3, '.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    value.get("exp")?.as_i64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn jwt_with_payload(payload: &serde_json::Value) -> String {
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let header = b64(br#"{"alg":"none","typ":"JWT"}"#);
        let body = b64(serde_json::to_vec(payload).unwrap().as_slice());
        format!("{header}.{body}.")
    }

    #[test]
    fn reads_integer_exp() {
        let token = jwt_with_payload(&serde_json::json!({ "exp": 1_900_000_000_i64 }));
        assert_eq!(parse_exp_secs(&token), Some(1_900_000_000));
    }

    #[test]
    fn tolerates_bearer_prefix() {
        let token = jwt_with_payload(&serde_json::json!({ "exp": 42 }));
        assert_eq!(parse_exp_secs(&format!("Bearer {token}")), Some(42));
    }

    #[test]
    fn none_for_missing_exp_or_non_jwt() {
        assert_eq!(
            parse_exp_secs(&jwt_with_payload(&serde_json::json!({ "sub": "x" }))),
            None
        );
        assert_eq!(parse_exp_secs("not-a-jwt"), None);
        assert_eq!(parse_exp_secs(""), None);
    }
}
