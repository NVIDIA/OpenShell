// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF security-related enums: `security_level_id`, `confidence_id`, `risk_level_id`.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Security Level ID (0-3, 99).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum SecurityLevelId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — Secure
    Secure = 1,
    /// 2 — At Risk
    AtRisk = 2,
    /// 3 — Compromised
    Compromised = 3,
    /// 99 — Other
    Other = 99,
}

impl SecurityLevelId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Secure => "Secure",
            Self::AtRisk => "At Risk",
            Self::Compromised => "Compromised",
            Self::Other => "Other",
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// OCSF Confidence ID (0-3, 99).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum ConfidenceId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — Low
    Low = 1,
    /// 2 — Medium
    Medium = 2,
    /// 3 — High
    High = 3,
    /// 99 — Other
    Other = 99,
}

impl ConfidenceId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Other => "Other",
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// OCSF Risk Level ID (0-4, 99).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum RiskLevelId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — Info
    Info = 1,
    /// 2 — Low
    Low = 2,
    /// 3 — Medium
    Medium = 3,
    /// 4 — High
    High = 4,
    /// 5 — Critical
    Critical = 5,
    /// 99 — Other
    Other = 99,
}

impl RiskLevelId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
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
    fn test_security_level_labels() {
        assert_eq!(SecurityLevelId::Unknown.label(), "Unknown");
        assert_eq!(SecurityLevelId::Secure.label(), "Secure");
        assert_eq!(SecurityLevelId::AtRisk.label(), "At Risk");
        assert_eq!(SecurityLevelId::Compromised.label(), "Compromised");
    }

    #[test]
    fn test_confidence_labels() {
        assert_eq!(ConfidenceId::Unknown.label(), "Unknown");
        assert_eq!(ConfidenceId::Low.label(), "Low");
        assert_eq!(ConfidenceId::Medium.label(), "Medium");
        assert_eq!(ConfidenceId::High.label(), "High");
    }

    #[test]
    fn test_risk_level_labels() {
        assert_eq!(RiskLevelId::Unknown.label(), "Unknown");
        assert_eq!(RiskLevelId::Info.label(), "Info");
        assert_eq!(RiskLevelId::Low.label(), "Low");
        assert_eq!(RiskLevelId::Medium.label(), "Medium");
        assert_eq!(RiskLevelId::High.label(), "High");
        assert_eq!(RiskLevelId::Critical.label(), "Critical");
    }

    #[test]
    fn test_security_json_roundtrips() {
        let sl = SecurityLevelId::Secure;
        let json = serde_json::to_value(sl).unwrap();
        assert_eq!(json, serde_json::json!(1));

        let conf = ConfidenceId::High;
        let json = serde_json::to_value(conf).unwrap();
        assert_eq!(json, serde_json::json!(3));

        let risk = RiskLevelId::High;
        let json = serde_json::to_value(risk).unwrap();
        assert_eq!(json, serde_json::json!(4));
    }
}
