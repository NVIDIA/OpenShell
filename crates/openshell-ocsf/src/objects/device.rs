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
    /// Create a Linux sandbox device with the given hostname.
    #[must_use]
    pub fn linux(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_string(),
            name: None,
            uid: None,
            type_id: DeviceTypeId::Other,
            type_label: "Sandbox".to_string(),
            os: Some(OsInfo {
                name: "Linux".to_string(),
            }),
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
    fn sandbox_device_type_is_independent_of_its_os() {
        let json = serde_json::to_value(Device::linux("sandbox-abc123")).unwrap();
        assert_eq!(json["type_id"], DeviceTypeId::Other.as_u8());
        assert_eq!(json["type"], "Sandbox");
        assert_eq!(json["os"]["name"], "Linux");
    }

    #[test]
    fn device_round_trips() {
        let device = Device::linux("sandbox-abc123");
        let json = serde_json::to_value(&device).unwrap();
        let decoded: Device = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(decoded, device);
        assert_eq!(serde_json::to_value(&decoded).unwrap(), json);
    }
}
