// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reading the claims in a Keycloak access token.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use testkit::{Error, Result, ResultExt as _};

/// The claims in `token`, a JWT. The signature isn't checked: the token
/// comes from the test's own login, and the gateway checks it.
pub fn claims(token: &str) -> Result<Value> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| Error::msg("the access token is not a JWT"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|error| Error::msg(format!("decode the access token's claims: {error}")))?;
    serde_json::from_slice(&bytes).context("parse the access token's claims")
}

/// The `sub` claim in `token`: the subject the gateway names the user by,
/// such as in workspace memberships.
pub fn subject(token: &str) -> Result<String> {
    claims(token)?
        .get("sub")
        .and_then(Value::as_str)
        .filter(|subject| !subject.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Error::msg("the access token has no subject"))
}

/// Whether `claims` lists `role` among its realm roles
/// (`realm_access.roles`).
pub fn has_realm_role(claims: &Value, role: &str) -> bool {
    claims["realm_access"]["roles"]
        .as_array()
        .is_some_and(|roles| roles.iter().any(|r| r == role))
}

/// Whether the `aud` claim, a string or a list, includes `audience`.
pub fn audience_contains(claims: &Value, audience: &str) -> bool {
    match &claims["aud"] {
        Value::String(value) => value == audience,
        Value::Array(values) => values.iter().any(|value| value == audience),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(claims: &Value) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        format!("e30.{payload}.sig")
    }

    #[test]
    fn reads_claims() {
        let token = jwt(&serde_json::json!({
            "sub": "abc",
            "aud": ["account", "openshell-cli"],
            "realm_access": {"roles": ["openshell-user"]},
        }));
        let claims = claims(&token).unwrap();
        assert_eq!(subject(&token).unwrap(), "abc");
        assert!(has_realm_role(&claims, "openshell-user"));
        assert!(!has_realm_role(&claims, "openshell-admin"));
        assert!(audience_contains(&claims, "openshell-cli"));
        assert!(audience_contains(
            &serde_json::json!({"aud": "openshell-cli"}),
            "openshell-cli"
        ));
    }

    #[test]
    fn rejects_a_token_without_a_subject() {
        assert!(subject(&jwt(&serde_json::json!({"sub": ""}))).is_err());
        assert!(claims("not-a-jwt").is_err());
    }
}
