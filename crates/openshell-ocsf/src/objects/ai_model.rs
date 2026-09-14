// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `ai_model` object (introduced with the `ai_operation` profile in v1.8.0).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiModel {
    pub name: String,
    pub ai_provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

impl AiModel {
    #[must_use]
    pub fn new(name: impl Into<String>, ai_provider: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ai_provider: ai_provider.into(),
            version: None,
            uid: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ai_model_serialization() {
        let model = AiModel::new("claude-3-haiku", "anthropic");
        let json = serde_json::to_value(&model).unwrap();
        assert_eq!(json["name"], "claude-3-haiku");
        assert_eq!(json["ai_provider"], "anthropic");
        assert!(json.get("version").is_none());
        assert!(json.get("uid").is_none());
    }

    #[test]
    fn test_ai_model_roundtrip() {
        let model = AiModel {
            name: "gpt-4o".to_string(),
            ai_provider: "openai".to_string(),
            version: Some("2024-05-13".to_string()),
            uid: Some("model-123".to_string()),
        };
        let json = serde_json::to_string(&model).unwrap();
        let deserialized: AiModel = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "gpt-4o");
        assert_eq!(deserialized.ai_provider, "openai");
        assert_eq!(deserialized.version.as_deref(), Some("2024-05-13"));
        assert_eq!(deserialized.uid.as_deref(), Some("model-123"));
    }
}
