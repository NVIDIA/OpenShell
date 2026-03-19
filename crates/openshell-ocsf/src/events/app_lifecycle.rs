// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Application Lifecycle [6002] event class.

use serde::{Deserialize, Serialize};

use crate::events::base_event::BaseEventData;
use crate::objects::Product;

/// OCSF Application Lifecycle Event [6002].
///
/// Sandbox supervisor lifecycle events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationLifecycleEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,

    /// Application / product info (required).
    pub app: Product,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::SeverityId;
    use crate::objects::Metadata;

    #[test]
    fn test_app_lifecycle_serialization() {
        let mut base = BaseEventData::new(
            6002,
            "Application Lifecycle",
            6,
            "Application Activity",
            3,
            "Start",
            SeverityId::Informational,
            Metadata {
                version: "1.7.0".to_string(),
                product: Product::openshell_sandbox("0.1.0"),
                profiles: vec!["container".to_string()],
                uid: Some("sandbox-abc123".to_string()),
                log_source: None,
            },
        );
        base.set_message("Starting sandbox");

        let event = ApplicationLifecycleEvent {
            base,
            app: Product::openshell_sandbox("0.1.0"),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 6002);
        assert_eq!(json["type_uid"], 600_203);
        assert_eq!(json["app"]["name"], "OpenShell Sandbox Supervisor");
        assert_eq!(json["message"], "Starting sandbox");
    }
}
