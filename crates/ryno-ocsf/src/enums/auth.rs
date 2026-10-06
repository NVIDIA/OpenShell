// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `auth_type_id` enum for SSH Activity.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Auth Type ID (0-6, 99).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum AuthTypeId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — Certificate Based
    CertificateBased = 1,
    /// 2 — GSSAPI
    Gssapi = 2,
    /// 3 — Host Based
    HostBased = 3,
    /// 4 — Keyboard Interactive
    KeyboardInteractive = 4,
    /// 5 — Password
    Password = 5,
    /// 6 — Public Key
    PublicKey = 6,
    /// 99 — Other (used for NSSH1)
    Other = 99,
}

impl AuthTypeId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::CertificateBased => "Certificate Based",
            Self::Gssapi => "GSSAPI",
            Self::HostBased => "Host Based",
            Self::KeyboardInteractive => "Keyboard Interactive",
            Self::Password => "Password",
            Self::PublicKey => "Public Key",
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
    fn test_auth_type_labels() {
        assert_eq!(AuthTypeId::Unknown.label(), "Unknown");
        assert_eq!(AuthTypeId::CertificateBased.label(), "Certificate Based");
        assert_eq!(AuthTypeId::PublicKey.label(), "Public Key");
        assert_eq!(AuthTypeId::Other.label(), "Other");
    }

    #[test]
    fn test_auth_type_integer_values() {
        assert_eq!(AuthTypeId::Unknown.as_u8(), 0);
        assert_eq!(AuthTypeId::CertificateBased.as_u8(), 1);
        assert_eq!(AuthTypeId::PublicKey.as_u8(), 6);
        assert_eq!(AuthTypeId::Other.as_u8(), 99);
    }

    #[test]
    fn test_auth_type_json_roundtrip() {
        let auth = AuthTypeId::Other;
        let json = serde_json::to_value(auth).unwrap();
        assert_eq!(json, serde_json::json!(99));
        let deserialized: AuthTypeId = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, AuthTypeId::Other);
    }
}
