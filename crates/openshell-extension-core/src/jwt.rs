// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Maximum accepted lifetime for an extension bearer token.
///
/// Extension credentials cross the gateway trust boundary and must remain
/// short-lived even when legacy sandbox bootstrap credentials do not expire.
pub const MAX_EXTENSION_TOKEN_TTL: Duration = Duration::from_secs(3_600);

/// Explicit `typ` header value carried by every extension bearer token.
///
/// Extension tokens and sandbox-to-gateway bootstrap tokens are signed by the
/// same key and differ only in their audience. Explicit typing (RFC 8725
/// section 3.11) gives verifiers a second, independent discriminator: a
/// service that requires this `typ` cannot accept a sandbox bootstrap
/// credential even if it forgets to check `aud`.
pub const EXTENSION_JWT_TYP: &str = "openshell-ext+jwt";

/// `OpenShell` component calling an extension service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionCallerKind {
    Gateway,
    Supervisor,
}

/// JWT claim set accepted by external extension services.
///
/// This intentionally differs from sandbox bootstrap claims. Sharing a signing
/// key does not make a sandbox-to-gateway credential valid at an extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionJwtClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub caller_kind: ExtensionCallerKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_kind_uses_stable_snake_case_wire_values() {
        assert_eq!(
            serde_json::to_string(&ExtensionCallerKind::Gateway).unwrap(),
            "\"gateway\""
        );
        assert_eq!(
            serde_json::to_string(&ExtensionCallerKind::Supervisor).unwrap(),
            "\"supervisor\""
        );
    }

    #[test]
    fn gateway_claims_omit_sandbox_id() {
        let claims = ExtensionJwtClaims {
            iss: "openshell-gateway:test".to_string(),
            aud: "urn:openshell:extension:interceptor:test".to_string(),
            sub: "openshell-gateway:test".to_string(),
            iat: 1,
            exp: 2,
            jti: "unique".to_string(),
            caller_kind: ExtensionCallerKind::Gateway,
            sandbox_id: None,
        };
        let json = serde_json::to_value(claims).unwrap();
        assert!(json.get("sandbox_id").is_none());
        assert_eq!(json["caller_kind"], "gateway");
    }
}
