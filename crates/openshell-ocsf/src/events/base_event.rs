// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Base Event [0] and shared `BaseEventData`.

use serde::{Deserialize, Serialize};

use crate::enums::{SeverityId, StatusId};
use crate::objects::{Container, Device, Metadata};

/// Common fields shared by all OCSF event classes.
///
/// Every event class embeds this struct via `#[serde(flatten)]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BaseEventData {
    /// OCSF class UID (e.g., 4001 for Network Activity).
    pub class_uid: u32,

    /// Human-readable class name.
    pub class_name: String,

    /// OCSF category UID.
    pub category_uid: u8,

    /// Human-readable category name.
    pub category_name: String,

    /// Activity ID within the class.
    pub activity_id: u8,

    /// Human-readable activity name.
    pub activity_name: String,

    /// Computed type UID: `class_uid * 100 + activity_id`.
    pub type_uid: u32,

    /// Human-readable type name: "`class_name`: `activity_name`".
    pub type_name: String,

    /// Event timestamp in milliseconds since epoch.
    pub time: i64,

    /// Severity (typed enum, serialized as `severity_id` + `severity` pair).
    #[serde(rename = "severity_id")]
    pub severity: SeverityId,

    /// Status (typed enum, serialized as `status_id` + `status` pair).
    #[serde(rename = "status_id", default, skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusId>,

    /// Human-readable event message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Status detail / reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_detail: Option<String>,

    /// Event metadata (schema version, product, profiles).
    pub metadata: Metadata,

    /// Device info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<Device>,

    /// Container info (Container profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<Container>,

    /// Unmapped fields that don't fit the OCSF schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unmapped: Option<serde_json::Value>,
}

impl Serialize for BaseEventData {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        // Count fields: 9 required + severity pair (2) + up to 6 optional
        let mut map = serializer.serialize_map(None)?;

        map.serialize_entry("class_uid", &self.class_uid)?;
        map.serialize_entry("class_name", &self.class_name)?;
        map.serialize_entry("category_uid", &self.category_uid)?;
        map.serialize_entry("category_name", &self.category_name)?;
        map.serialize_entry("activity_id", &self.activity_id)?;
        map.serialize_entry("activity_name", &self.activity_name)?;
        map.serialize_entry("type_uid", &self.type_uid)?;
        map.serialize_entry("type_name", &self.type_name)?;
        map.serialize_entry("time", &self.time)?;

        // Severity — typed enum → id + label pair
        map.serialize_entry("severity_id", &self.severity.as_u8())?;
        map.serialize_entry("severity", self.severity.label())?;

        // Status — optional typed enum → id + label pair
        if let Some(status) = self.status {
            map.serialize_entry("status_id", &status.as_u8())?;
            map.serialize_entry("status", status.label())?;
        }

        if let Some(ref msg) = self.message {
            map.serialize_entry("message", msg)?;
        }
        if let Some(ref detail) = self.status_detail {
            map.serialize_entry("status_detail", detail)?;
        }
        map.serialize_entry("metadata", &self.metadata)?;
        if let Some(ref device) = self.device {
            map.serialize_entry("device", device)?;
        }
        if let Some(ref container) = self.container {
            map.serialize_entry("container", container)?;
        }
        if let Some(ref unmapped) = self.unmapped {
            map.serialize_entry("unmapped", unmapped)?;
        }

        map.end()
    }
}

impl BaseEventData {
    /// Create base event data with required fields.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        class_uid: u32,
        class_name: &str,
        category_uid: u8,
        category_name: &str,
        activity_id: u8,
        activity_name: &str,
        severity_id: SeverityId,
        metadata: Metadata,
    ) -> Self {
        let type_uid = class_uid * 100 + u32::from(activity_id);
        let type_name = format!("{class_name}: {activity_name}");

        Self {
            class_uid,
            class_name: class_name.to_string(),
            category_uid,
            category_name: category_name.to_string(),
            activity_id,
            activity_name: activity_name.to_string(),
            type_uid,
            type_name,
            time: chrono::Utc::now().timestamp_millis(),
            severity: severity_id,
            status: None,
            message: None,
            status_detail: None,
            metadata,
            device: None,
            container: None,
            unmapped: None,
        }
    }

    /// Set the timestamp (milliseconds since epoch).
    pub fn set_time(&mut self, time_ms: i64) {
        self.time = time_ms;
    }

    /// Set status.
    pub fn set_status(&mut self, status_id: StatusId) {
        self.status = Some(status_id);
    }

    /// Set message.
    pub fn set_message(&mut self, message: impl Into<String>) {
        self.message = Some(message.into());
    }

    /// Set status detail.
    pub fn set_status_detail(&mut self, detail: impl Into<String>) {
        self.status_detail = Some(detail.into());
    }

    /// Set device info.
    pub fn set_device(&mut self, device: Device) {
        self.device = Some(device);
    }

    /// Set container info.
    pub fn set_container(&mut self, container: Container) {
        self.container = Some(container);
    }

    /// Add an unmapped field.
    pub fn add_unmapped(&mut self, key: &str, value: impl Into<serde_json::Value>) {
        let map = self
            .unmapped
            .get_or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let serde_json::Value::Object(m) = map {
            m.insert(key.to_string(), value.into());
        }
    }
}

/// OCSF Base Event [0] — for events that don't fit a specific class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::Product;

    fn test_metadata() -> Metadata {
        Metadata {
            version: "1.7.0".to_string(),
            product: Product::openshell_sandbox("0.1.0"),
            profiles: vec!["container".to_string(), "host".to_string()],
            uid: Some("sandbox-abc123".to_string()),
            log_source: None,
        }
    }

    #[test]
    fn test_base_event_data_creation() {
        let base = BaseEventData::new(
            0,
            "Base Event",
            0,
            "Uncategorized",
            99,
            "Other",
            SeverityId::Informational,
            test_metadata(),
        );

        assert_eq!(base.class_uid, 0);
        assert_eq!(base.type_uid, 99); // 0 * 100 + 99
        assert_eq!(base.type_name, "Base Event: Other");
        assert_eq!(base.severity, SeverityId::Informational);
    }

    #[test]
    fn test_type_uid_computation() {
        let base = BaseEventData::new(
            4001,
            "Network Activity",
            4,
            "Network Activity",
            1,
            "Open",
            SeverityId::Informational,
            test_metadata(),
        );

        assert_eq!(base.type_uid, 400_101); // 4001 * 100 + 1
    }

    #[test]
    fn test_base_event_serialization() {
        let mut base = BaseEventData::new(
            0,
            "Base Event",
            0,
            "Uncategorized",
            99,
            "Network Namespace Created",
            SeverityId::Informational,
            test_metadata(),
        );
        base.set_status(StatusId::Success);
        base.set_message("Network namespace created");
        base.add_unmapped("namespace", serde_json::json!("openshell-sandbox-abc123"));

        let event = BaseEvent { base };
        let json = serde_json::to_value(&event).unwrap();

        assert_eq!(json["class_uid"], 0);
        assert_eq!(json["class_name"], "Base Event");
        assert_eq!(json["activity_name"], "Network Namespace Created");
        assert_eq!(json["status"], "Success");
        assert_eq!(json["message"], "Network namespace created");
        assert_eq!(json["unmapped"]["namespace"], "openshell-sandbox-abc123");
    }
}
