// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `device.type_id` enum.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Device Type ID.
///
/// Only the values `OpenShell` can produce are modelled; the schema defines a
/// wider set (desktop, mobile, firewall, router, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum DeviceTypeId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — Server
    Server = 1,
    /// 99 — Other
    Other = 99,
}

impl DeviceTypeId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Server => "Server",
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
    fn device_type_labels() {
        assert_eq!(DeviceTypeId::Unknown.label(), "Unknown");
        assert_eq!(DeviceTypeId::Server.label(), "Server");
        assert_eq!(DeviceTypeId::Other.label(), "Other");
    }

    #[test]
    fn device_type_json_roundtrip() {
        let json = serde_json::to_value(DeviceTypeId::Server).unwrap();
        assert_eq!(json, serde_json::json!(1));
        let decoded: DeviceTypeId = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, DeviceTypeId::Server);
    }
}
