// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `severity_id` enum.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Severity ID (0-6, 99).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum SeverityId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — Informational
    Informational = 1,
    /// 2 — Low
    Low = 2,
    /// 3 — Medium
    Medium = 3,
    /// 4 — High
    High = 4,
    /// 5 — Critical
    Critical = 5,
    /// 6 — Fatal
    Fatal = 6,
    /// 99 — Other
    Other = 99,
}

impl SeverityId {
    /// Returns the OCSF string label for this severity.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Informational => "Informational",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
            Self::Fatal => "Fatal",
            Self::Other => "Other",
        }
    }

    /// Returns the single-character shorthand for log display.
    #[must_use]
    pub fn shorthand_char(self) -> char {
        match self {
            Self::Informational => 'I',
            Self::Low => 'L',
            Self::Medium => 'M',
            Self::High => 'H',
            Self::Critical => 'C',
            Self::Fatal => 'F',
            Self::Unknown | Self::Other => ' ',
        }
    }

    /// Returns the integer value for JSON serialization.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_labels() {
        assert_eq!(SeverityId::Unknown.label(), "Unknown");
        assert_eq!(SeverityId::Informational.label(), "Informational");
        assert_eq!(SeverityId::Low.label(), "Low");
        assert_eq!(SeverityId::Medium.label(), "Medium");
        assert_eq!(SeverityId::High.label(), "High");
        assert_eq!(SeverityId::Critical.label(), "Critical");
        assert_eq!(SeverityId::Fatal.label(), "Fatal");
        assert_eq!(SeverityId::Other.label(), "Other");
    }

    #[test]
    fn test_severity_shorthand_chars() {
        assert_eq!(SeverityId::Unknown.shorthand_char(), ' ');
        assert_eq!(SeverityId::Informational.shorthand_char(), 'I');
        assert_eq!(SeverityId::Low.shorthand_char(), 'L');
        assert_eq!(SeverityId::Medium.shorthand_char(), 'M');
        assert_eq!(SeverityId::High.shorthand_char(), 'H');
        assert_eq!(SeverityId::Critical.shorthand_char(), 'C');
        assert_eq!(SeverityId::Fatal.shorthand_char(), 'F');
        assert_eq!(SeverityId::Other.shorthand_char(), ' ');
    }

    #[test]
    fn test_severity_integer_values() {
        assert_eq!(SeverityId::Unknown.as_u8(), 0);
        assert_eq!(SeverityId::Informational.as_u8(), 1);
        assert_eq!(SeverityId::Low.as_u8(), 2);
        assert_eq!(SeverityId::Medium.as_u8(), 3);
        assert_eq!(SeverityId::High.as_u8(), 4);
        assert_eq!(SeverityId::Critical.as_u8(), 5);
        assert_eq!(SeverityId::Fatal.as_u8(), 6);
        assert_eq!(SeverityId::Other.as_u8(), 99);
    }

    #[test]
    fn test_severity_json_roundtrip() {
        let severity = SeverityId::High;
        let json = serde_json::to_value(severity).unwrap();
        assert_eq!(json, serde_json::json!(4));
        let deserialized: SeverityId = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, SeverityId::High);
    }
}
