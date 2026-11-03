// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `connection_info.direction_id` enum.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Network Connection Direction ID.
///
/// Values come from the OCSF `network_connection_info` `direction_id`
/// enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum ConnectionDirectionId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — Inbound
    Inbound = 1,
    /// 2 — Outbound
    Outbound = 2,
    /// 3 — Lateral
    Lateral = 3,
    /// 4 — Local
    Local = 4,
    /// 99 — Other
    Other = 99,
}

impl ConnectionDirectionId {
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for ConnectionDirectionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => "Unknown",
            Self::Inbound => "Inbound",
            Self::Outbound => "Outbound",
            Self::Lateral => "Lateral",
            Self::Local => "Local",
            Self::Other => "Other",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_direction_json_roundtrip() {
        for (direction, expected, label) in [
            (ConnectionDirectionId::Unknown, 0, "Unknown"),
            (ConnectionDirectionId::Inbound, 1, "Inbound"),
            (ConnectionDirectionId::Outbound, 2, "Outbound"),
            (ConnectionDirectionId::Lateral, 3, "Lateral"),
            (ConnectionDirectionId::Local, 4, "Local"),
            (ConnectionDirectionId::Other, 99, "Other"),
        ] {
            let json = serde_json::to_value(direction).unwrap();
            assert_eq!(json, serde_json::json!(expected));
            let decoded: ConnectionDirectionId = serde_json::from_value(json).unwrap();
            assert_eq!(decoded, direction);
            assert_eq!(direction.to_string(), label);
        }
    }
}
