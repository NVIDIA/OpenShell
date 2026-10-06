// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `status_id` and `state_id` enums.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Status ID (0-2, 99).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum StatusId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — Success
    Success = 1,
    /// 2 — Failure
    Failure = 2,
    /// 99 — Other
    Other = 99,
}

impl StatusId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Success => "Success",
            Self::Failure => "Failure",
            Self::Other => "Other",
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// OCSF State ID (0-2, 99) — used by Device Config State Change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum StateId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — Disabled
    Disabled = 1,
    /// 2 — Enabled
    Enabled = 2,
    /// 99 — Other
    Other = 99,
}

impl StateId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Disabled => "Disabled",
            Self::Enabled => "Enabled",
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
    fn test_status_labels() {
        assert_eq!(StatusId::Unknown.label(), "Unknown");
        assert_eq!(StatusId::Success.label(), "Success");
        assert_eq!(StatusId::Failure.label(), "Failure");
        assert_eq!(StatusId::Other.label(), "Other");
    }

    #[test]
    fn test_status_json_roundtrip() {
        let status = StatusId::Success;
        let json = serde_json::to_value(status).unwrap();
        assert_eq!(json, serde_json::json!(1));
        let deserialized: StatusId = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, StatusId::Success);
    }

    #[test]
    fn test_state_labels() {
        assert_eq!(StateId::Unknown.label(), "Unknown");
        assert_eq!(StateId::Disabled.label(), "Disabled");
        assert_eq!(StateId::Enabled.label(), "Enabled");
        assert_eq!(StateId::Other.label(), "Other");
    }

    #[test]
    fn test_state_json_roundtrip() {
        let state = StateId::Enabled;
        let json = serde_json::to_value(state).unwrap();
        assert_eq!(json, serde_json::json!(2));
        let deserialized: StateId = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, StateId::Enabled);
    }
}
