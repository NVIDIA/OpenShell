// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `metadata` and `product` objects.

use serde::{Deserialize, Serialize};

/// OCSF Metadata object — event provenance and schema info.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// OCSF schema version (e.g., "1.7.0").
    pub version: String,

    /// The product that generated the event.
    pub product: Product,

    /// OCSF profiles applied to this event.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,

    /// Unique event source identifier (sandbox ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// Log source path (e.g., "/dev/kmsg" for bypass detection).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_source: Option<String>,
}

/// OCSF Product object — identifies the software generating events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Product {
    /// Product name.
    pub name: String,

    /// Vendor name.
    pub vendor_name: String,

    /// Product version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl Product {
    /// Create the standard `OpenShell` Sandbox Supervisor product.
    #[must_use]
    pub fn openshell_sandbox(version: &str) -> Self {
        Self {
            name: "OpenShell Sandbox Supervisor".to_string(),
            vendor_name: "OpenShell".to_string(),
            version: Some(version.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_serialization() {
        let metadata = Metadata {
            version: "1.7.0".to_string(),
            product: Product::openshell_sandbox("0.1.0"),
            profiles: vec!["security_control".to_string(), "container".to_string()],
            uid: Some("sandbox-abc123".to_string()),
            log_source: None,
        };

        let json = serde_json::to_value(&metadata).unwrap();
        assert_eq!(json["version"], "1.7.0");
        assert_eq!(json["product"]["name"], "OpenShell Sandbox Supervisor");
        assert_eq!(json["product"]["vendor_name"], "OpenShell");
        assert!(json.get("log_source").is_none());
    }

    #[test]
    fn test_metadata_with_log_source() {
        let metadata = Metadata {
            version: "1.7.0".to_string(),
            product: Product::openshell_sandbox("0.1.0"),
            profiles: vec![],
            uid: None,
            log_source: Some("/dev/kmsg".to_string()),
        };

        let json = serde_json::to_value(&metadata).unwrap();
        assert_eq!(json["log_source"], "/dev/kmsg");
        // Empty profiles should be omitted
        assert!(json.get("profiles").is_none());
    }
}
