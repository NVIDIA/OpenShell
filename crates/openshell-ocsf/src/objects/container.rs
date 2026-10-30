// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `container` object.

use serde::{Deserialize, Serialize};

/// OCSF Container object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Container {
    /// Container name.
    pub name: String,

    /// Container unique identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_serialization() {
        let container = Container {
            name: "my-sandbox".to_string(),
            uid: Some("sandbox-abc123".to_string()),
        };

        let json = serde_json::to_value(&container).unwrap();
        assert_eq!(json["name"], "my-sandbox");
        assert_eq!(json["uid"], "sandbox-abc123");
    }

    #[test]
    fn test_container_minimal() {
        let container = Container {
            name: "test".to_string(),
            uid: None,
        };
        let json = serde_json::to_value(&container).unwrap();
        assert!(json.get("uid").is_none());
    }
}
