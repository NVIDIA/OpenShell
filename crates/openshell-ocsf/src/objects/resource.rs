// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `resource_details` object.

use serde::{Deserialize, Serialize};

/// OCSF Resource Details object — a resource an event acted on.
///
/// The schema requires at least one of `name` or `uid`; the constructors
/// always set one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceDetails {
    /// Stable identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Resource type (e.g. "sandbox", "workspace").
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_label: Option<String>,

    /// Additional details about the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl ResourceDetails {
    /// A resource of `type_label` identified by `uid`.
    #[must_use]
    pub fn new(type_label: impl Into<String>, uid: impl Into<String>) -> Self {
        Self {
            uid: Some(uid.into()),
            name: None,
            type_label: Some(type_label.into()),
            data: None,
        }
    }

    /// A resource of `type_label` known only by its name.
    #[must_use]
    pub fn named(type_label: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            uid: None,
            name: Some(name.into()),
            type_label: Some(type_label.into()),
            data: None,
        }
    }

    /// This resource with additional details.
    #[must_use]
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_serializes_type_under_its_schema_name() {
        let json = serde_json::to_value(ResourceDetails::new("sandbox", "sb-1")).unwrap();
        assert_eq!(json, serde_json::json!({"uid": "sb-1", "type": "sandbox"}));
    }

    #[test]
    fn resource_carries_data() {
        let resource = ResourceDetails::named("setting", "log_level")
            .with_data(serde_json::json!({"value": "debug"}));
        let json = serde_json::to_value(resource).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"name": "log_level", "type": "setting", "data": {"value": "debug"}})
        );
    }

    #[test]
    fn named_resource_has_no_uid() {
        let json = serde_json::to_value(ResourceDetails::named("workspace", "default")).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"name": "default", "type": "workspace"})
        );
    }
}
