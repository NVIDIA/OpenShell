// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Serde helpers for driver configuration read from `google.protobuf.Struct`.

use serde::{Deserialize, Deserializer, de::Error as _};

/// Deserialize a present field as a non-empty list of non-empty strings.
///
/// Use with `#[serde(default, deserialize_with = "...")]` on
/// `Option<Vec<String>>` fields. Missing fields use the option default; present
/// fields must be arrays and cannot be empty.
pub fn deserialize_optional_non_empty_string_list<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    if values.is_empty() {
        return Err(D::Error::custom("must be a non-empty list of strings"));
    }

    for (idx, value) in values.iter().enumerate() {
        if value.trim().is_empty() {
            return Err(D::Error::custom(format!(
                "[{idx}] must be a non-empty string"
            )));
        }
    }

    Ok(Some(values))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Default, Deserialize)]
    #[serde(default)]
    struct TestConfig {
        #[serde(
            default,
            deserialize_with = "deserialize_optional_non_empty_string_list"
        )]
        devices: Option<Vec<String>>,
    }

    #[test]
    fn optional_non_empty_string_list_defaults_when_absent() {
        let config: TestConfig = serde_json::from_value(serde_json::json!({})).unwrap();

        assert_eq!(config.devices, None);
    }

    #[test]
    fn optional_non_empty_string_list_parses_present_list() {
        let config: TestConfig =
            serde_json::from_value(serde_json::json!({"devices": ["nvidia.com/gpu=0"]})).unwrap();

        assert_eq!(config.devices, Some(vec!["nvidia.com/gpu=0".to_string()]));
    }

    #[test]
    fn optional_non_empty_string_list_rejects_empty_list() {
        let err =
            serde_json::from_value::<TestConfig>(serde_json::json!({"devices": []})).unwrap_err();

        assert!(err.to_string().contains("non-empty list"));
    }

    #[test]
    fn optional_non_empty_string_list_rejects_empty_string() {
        let err =
            serde_json::from_value::<TestConfig>(serde_json::json!({"devices": [""]})).unwrap_err();

        assert!(err.to_string().contains("non-empty string"));
    }
}
