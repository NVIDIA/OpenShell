// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `device` and `os` objects.

use serde::{Deserialize, Serialize};

use crate::enums::DeviceTypeId;

/// OCSF Device object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Device hostname.
    pub hostname: String,

    /// Administrator-assigned device name, when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Stable unique identifier for the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// Device type id. Required by the OCSF schema.
    pub type_id: DeviceTypeId,

    /// Sibling label for `type_id`.
    #[serde(rename = "type")]
    pub type_label: String,

    /// Operating system info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<OsInfo>,
}

/// OCSF OS Info object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsInfo {
    /// OS name (e.g., "Linux").
    pub name: String,
}

impl Device {
    /// Create a Linux device with the given hostname.
    #[must_use]
    pub fn linux(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_string(),
            name: None,
            uid: None,
            type_id: DeviceTypeId::Server,
            type_label: DeviceTypeId::Server.label().to_string(),
            os: Some(OsInfo {
                name: "Linux".to_string(),
            }),
        }
    }

    /// Create the device for a gateway replica.
    #[must_use]
    pub fn gateway(hostname: &str, name: &str) -> Self {
        Self {
            name: Some(name.to_string()),
            // Keep the replica identity opaque rather than encoding multiple fields in the UID.
            uid: Some(hostname.to_string()),
            ..Self::linux(hostname)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_linux() {
        let device = Device::linux("sandbox-abc123");
        let json = serde_json::to_value(&device).unwrap();
        assert_eq!(json["hostname"], "sandbox-abc123");
        assert_eq!(json["os"]["name"], "Linux");
    }

    #[test]
    fn device_emits_the_schema_required_type_id() {
        let json = serde_json::to_value(Device::linux("sandbox-abc123")).unwrap();
        assert_eq!(json["type_id"], DeviceTypeId::Server.as_u8());
        assert_eq!(json["type"], "Server");
    }

    #[test]
    fn device_round_trips() {
        let device = Device::linux("sandbox-abc123");
        let json = serde_json::to_value(&device).unwrap();
        let decoded: Device = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(decoded, device);
        assert_eq!(serde_json::to_value(&decoded).unwrap(), json);
    }

    #[test]
    fn gateway_replicas_have_distinct_device_uids() {
        let first = Device::gateway("openshell-gateway-0", "production");
        let second = Device::gateway("openshell-gateway-1", "production");

        assert_ne!(
            first.uid, second.uid,
            "gateway replicas must have distinct OCSF device UIDs"
        );
    }
}
