// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `api` object for API Activity [6003] events.

use serde::{Deserialize, Serialize};

/// The API object describes the API request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Api {
    /// The API operation (e.g., "POST /v1/messages").
    pub operation: String,
    /// The API version (e.g., "v1").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl Api {
    #[must_use]
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            version: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_serialization() {
        let api = Api::new("POST /v1/messages");
        let json = serde_json::to_value(&api).unwrap();
        assert_eq!(json["operation"], "POST /v1/messages");
        assert!(json.get("version").is_none());
    }
}
