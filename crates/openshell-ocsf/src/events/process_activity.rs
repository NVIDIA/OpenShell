// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Process Activity [1007] event class.

use serde::{Deserialize, Serialize};

use crate::enums::{ActionId, DispositionId, LaunchTypeId};
use crate::events::base_event::BaseEventData;
use crate::objects::{Actor, Process};

/// OCSF Process Activity Event [1007].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProcessActivityEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,

    /// The process being acted upon (required in v1.7.0).
    pub process: Process,

    /// Actor (parent/supervisor process, required in v1.7.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,

    /// Launch type.
    #[serde(
        rename = "launch_type_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub launch_type: Option<LaunchTypeId>,

    /// Process exit code (for Terminate activity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    /// Action (Security Control profile).
    #[serde(rename = "action_id", default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionId>,

    /// Disposition.
    #[serde(
        rename = "disposition_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disposition: Option<DispositionId>,
}

impl Serialize for ProcessActivityEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::events::serde_helpers::{insert_enum_pair, insert_optional, insert_required};

        let mut base_val = serde_json::to_value(&self.base).map_err(serde::ser::Error::custom)?;
        let obj = base_val
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("expected object"))?;

        insert_required!(obj, "process", self.process);
        insert_optional!(obj, "actor", self.actor);
        insert_enum_pair!(obj, "launch_type", self.launch_type);
        insert_optional!(obj, "exit_code", self.exit_code);
        insert_enum_pair!(obj, "action", self.action);
        insert_enum_pair!(obj, "disposition", self.disposition);

        base_val.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{ActionId, DispositionId, LaunchTypeId, SeverityId};
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
            launch_type: Some(LaunchTypeId::Spawn),
            exit_code: None,
            action: Some(ActionId::Allowed),
            disposition: Some(DispositionId::Allowed),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 1007);
        assert_eq!(json["process"]["name"], "python3");
        assert_eq!(json["actor"]["process"]["name"], "openshell-sandbox");
        assert_eq!(json["launch_type"], "Spawn");
    }
}
