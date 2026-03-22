// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `device` and `os` objects.

use serde::{Deserialize, Serialize};

/// OCSF Device object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Device hostname.
    pub hostname: String,

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
}
