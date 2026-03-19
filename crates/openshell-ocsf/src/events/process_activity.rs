// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Process Activity [1007] event class.

use serde::{Deserialize, Serialize};

use crate::events::base_event::BaseEventData;
use crate::objects::{Actor, Process};

/// OCSF Process Activity Event [1007].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessActivityEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,

    /// The process being acted upon (required in v1.7.0).
    pub process: Process,

    /// Actor (parent/supervisor process, required in v1.7.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,

    /// Launch type ID (new in v1.7.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_type_id: Option<u8>,

    /// Launch type label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_type: Option<String>,

    /// Process exit code (for Terminate activity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    /// Action ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_id: Option<u8>,

    /// Action label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,

    /// Disposition ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition_id: Option<u8>,

    /// Disposition label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::SeverityId;
    use crate::objects::{Metadata, Product};

    #[test]
    fn test_process_activity_serialization() {
        let event = ProcessActivityEvent {
            base: BaseEventData::new(
                1007,
                "Process Activity",
                1,
                "System Activity",
                1,
                "Launch",
                SeverityId::Informational,
                Metadata {
                    version: "1.7.0".to_string(),
                    product: Product::openshell_sandbox("0.1.0"),
                    profiles: vec!["container".to_string()],
                    uid: Some("sandbox-abc123".to_string()),
                    log_source: None,
                },
            ),
            process: Process::new("python3", 42).with_cmd_line("python3 /app/main.py"),
            actor: Some(Actor {
                process: Process::new("openshell-sandbox", 1),
            }),
            launch_type_id: Some(1),
            launch_type: Some("Spawn".to_string()),
            exit_code: None,
            action_id: Some(1),
            action: Some("Allowed".to_string()),
            disposition_id: Some(1),
            disposition: Some("Allowed".to_string()),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 1007);
        assert_eq!(json["process"]["name"], "python3");
        assert_eq!(json["actor"]["process"]["name"], "openshell-sandbox");
        assert_eq!(json["launch_type"], "Spawn");
    }
}
