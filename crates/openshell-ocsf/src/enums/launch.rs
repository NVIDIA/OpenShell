// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `launch_type_id` enum (new in v1.7.0).

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Launch Type ID (0-3, 99).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum LaunchTypeId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — Spawn
    Spawn = 1,
    /// 2 — Fork
    Fork = 2,
    /// 3 — Exec
    Exec = 3,
    /// 99 — Other
    Other = 99,
}

impl LaunchTypeId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Spawn => "Spawn",
            Self::Fork => "Fork",
            Self::Exec => "Exec",
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
    fn test_launch_type_labels() {
        assert_eq!(LaunchTypeId::Unknown.label(), "Unknown");
        assert_eq!(LaunchTypeId::Spawn.label(), "Spawn");
        assert_eq!(LaunchTypeId::Fork.label(), "Fork");
        assert_eq!(LaunchTypeId::Exec.label(), "Exec");
        assert_eq!(LaunchTypeId::Other.label(), "Other");
    }

    #[test]
    fn test_launch_type_json_roundtrip() {
        let launch = LaunchTypeId::Spawn;
        let json = serde_json::to_value(launch).unwrap();
        assert_eq!(json, serde_json::json!(1));
        let deserialized: LaunchTypeId = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, LaunchTypeId::Spawn);
    }
}
