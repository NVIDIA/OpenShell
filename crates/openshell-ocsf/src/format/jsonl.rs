// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! JSONL formatter — full OCSF JSON output.

use crate::events::OcsfEvent;

impl OcsfEvent {
    /// Serialize to a `serde_json::Value`.
    ///
    /// Returns the full OCSF JSON object, or an error if serialization fails.
    pub fn to_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    /// Serialize as a single JSONL line (no pretty-printing, trailing newline).
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        let mut line = serde_json::to_string(self)?;
        line.push('\n');
        Ok(line)
    }
}

#[cfg(test)]
mod tests {
    use crate::enums::SeverityId;
    use crate::events::base_event::BaseEventData;
    use crate::events::{BaseEvent, OcsfEvent};
    use crate::objects::{Metadata, Product};

    fn test_event() -> OcsfEvent {
        let mut base = BaseEventData::new(
            0,
            "Base Event",
            0,
            "Uncategorized",
            99,
            "Other",
            SeverityId::Informational,
            Metadata {
                version: "1.7.0".to_string(),
                product: Product::openshell_sandbox("0.1.0"),
                profiles: vec!["container".to_string()],
                uid: Some("sandbox-abc123".to_string()),
                log_source: None,
            },
        );
        base.set_time(1_742_054_400_000);
        base.set_message("Test event");
        OcsfEvent::Base(BaseEvent { base })
    }

    #[test]
    fn test_to_json_has_required_fields() {
        let event = test_event();
        let json = event.to_json().unwrap();

        assert_eq!(json["class_uid"], 0);
        assert_eq!(json["class_name"], "Base Event");
        assert_eq!(json["category_uid"], 0);
        assert_eq!(json["activity_id"], 99);
        assert_eq!(json["type_uid"], 99);
        assert_eq!(json["time"], 1_742_054_400_000_i64);
        assert_eq!(json["severity_id"], 1);
        assert_eq!(json["severity"], "Informational");
        assert_eq!(json["metadata"]["version"], "1.7.0");
    }

    #[test]
    fn test_to_json_line_format() {
        let event = test_event();
        let line = event.to_json_line().unwrap();

        // Must be a single line ending with \n
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1);

        // Must parse back to the same JSON
        let parsed: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(parsed, event.to_json().unwrap());
    }

    #[test]
    fn test_optional_fields_omitted() {
        let event = test_event();
        let json = event.to_json().unwrap();

        // Optional fields should not appear when None
        assert!(json.get("device").is_none());
        assert!(json.get("container").is_none());
        assert!(json.get("unmapped").is_none());
        assert!(json.get("status_detail").is_none());
    }
}
