// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `device.type_id` enum.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Device Type ID.
///
/// Only the values `OpenShell` can produce are modelled; the schema defines a
/// wider set (desktop, mobile, firewall, router, ...).
/// Values come from the OCSF device `type_id` enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum DeviceTypeId {
    /// 0 — Unknown
    Unknown = 0,
    /// 99 — Other
    Other = 99,
}

impl DeviceTypeId {
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for DeviceTypeId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => "Unknown",
            Self::Other => "Other",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_type_display_uses_schema_labels() {
        for (device_type, expected) in [
            (DeviceTypeId::Unknown, "Unknown"),
            (DeviceTypeId::Other, "Other"),
        ] {
            assert_eq!(device_type.to_string(), expected);
            assert_eq!(format!("{device_type}"), expected);
        }
    }

    #[test]
    fn device_type_json_roundtrip() {
        for (device_type, expected) in [(DeviceTypeId::Unknown, 0), (DeviceTypeId::Other, 99)] {
            let json = serde_json::to_value(device_type).unwrap();
            assert_eq!(json, serde_json::json!(expected));
            let decoded: DeviceTypeId = serde_json::from_value(json).unwrap();
            assert_eq!(decoded, device_type);
        }
    }
}
