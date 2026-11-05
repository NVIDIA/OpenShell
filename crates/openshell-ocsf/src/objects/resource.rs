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
}

impl ResourceDetails {
    /// A resource of `type_label` identified by `uid`.
    #[must_use]
    pub fn new(type_label: impl Into<String>, uid: impl Into<String>) -> Self {
        Self {
            uid: Some(uid.into()),
            name: None,
            type_label: Some(type_label.into()),
        }
    }

    /// A resource of `type_label` known only by its name.
    #[must_use]
    pub fn named(type_label: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            uid: None,
            name: Some(name.into()),
            type_label: Some(type_label.into()),
        }
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
    fn named_resource_has_no_uid() {
        let json = serde_json::to_value(ResourceDetails::named("workspace", "default")).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"name": "default", "type": "workspace"})
        );
    }
}
