// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `action_id` enum.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Action ID (0-4, 99).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum ActionId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — Allowed
    Allowed = 1,
    /// 2 — Denied
    Denied = 2,
    /// 3 — Alerted
    Alerted = 3,
    /// 4 — Dropped
    Dropped = 4,
    /// 99 — Other
    Other = 99,
}

impl ActionId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Allowed => "Allowed",
            Self::Denied => "Denied",
            Self::Alerted => "Alerted",
            Self::Dropped => "Dropped",
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
    fn test_action_labels() {
        assert_eq!(ActionId::Unknown.label(), "Unknown");
        assert_eq!(ActionId::Allowed.label(), "Allowed");
        assert_eq!(ActionId::Denied.label(), "Denied");
        assert_eq!(ActionId::Alerted.label(), "Alerted");
        assert_eq!(ActionId::Dropped.label(), "Dropped");
        assert_eq!(ActionId::Other.label(), "Other");
    }

    #[test]
    fn test_action_json_roundtrip() {
        let action = ActionId::Denied;
        let json = serde_json::to_value(action).unwrap();
        assert_eq!(json, serde_json::json!(2));
        let deserialized: ActionId = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, ActionId::Denied);
    }
}
