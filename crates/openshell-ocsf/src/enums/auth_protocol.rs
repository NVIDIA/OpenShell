// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `auth_protocol_id` enum for Authentication.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Authentication Protocol ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum AuthProtocolId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — NTLM
    Ntlm = 1,
    /// 2 — Kerberos
    Kerberos = 2,
    /// 3 — Digest
    Digest = 3,
    /// 4 — `OpenID`
    OpenId = 4,
    /// 5 — SAML
    Saml = 5,
    /// 6 — OAUTH 2.0
    OAuth2 = 6,
    /// 7 — PAP
    Pap = 7,
    /// 8 — CHAP
    Chap = 8,
    /// 9 — EAP
    Eap = 9,
    /// 10 — RADIUS
    Radius = 10,
    /// 11 — Basic Authentication
    Basic = 11,
    /// 12 — LDAP
    Ldap = 12,
    /// 99 — Other
    Other = 99,
}

impl AuthProtocolId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Ntlm => "NTLM",
            Self::Kerberos => "Kerberos",
            Self::Digest => "Digest",
            Self::OpenId => "OpenID",
            Self::Saml => "SAML",
            Self::OAuth2 => "OAUTH 2.0",
            Self::Pap => "PAP",
            Self::Chap => "CHAP",
            Self::Eap => "EAP",
            Self::Radius => "RADIUS",
            Self::Basic => "Basic Authentication",
            Self::Ldap => "LDAP",
            Self::Other => "Other",
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_protocol_json_roundtrip() {
        let json = serde_json::to_value(AuthProtocolId::OpenId).unwrap();
        assert_eq!(json, serde_json::json!(4));
        let deserialized: AuthProtocolId = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, AuthProtocolId::OpenId);
    }
}
