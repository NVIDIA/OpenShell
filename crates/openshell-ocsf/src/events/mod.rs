// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF v1.7.0 event class definitions.

mod app_lifecycle;
pub(crate) mod base_event;
mod config_state_change;
mod detection_finding;
mod http_activity;
mod network_activity;
mod process_activity;
pub(crate) mod serde_helpers;
mod ssh_activity;

pub use app_lifecycle::ApplicationLifecycleEvent;
pub use base_event::{BaseEvent, BaseEventData};
pub use config_state_change::DeviceConfigStateChangeEvent;
pub use detection_finding::DetectionFindingEvent;
pub use http_activity::HttpActivityEvent;
pub use network_activity::NetworkActivityEvent;
pub use process_activity::ProcessActivityEvent;
pub use ssh_activity::SshActivityEvent;

use serde::{Deserialize, Serialize};

/// Top-level OCSF event enum encompassing all supported event classes.
///
/// Serialization delegates directly to the inner event struct (untagged).
/// Deserialization dispatches on the `class_uid` field to select the
/// correct variant, avoiding the ambiguity of `#[serde(untagged)]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcsfEvent {
    /// Network Activity [4001]
    NetworkActivity(NetworkActivityEvent),
    /// HTTP Activity [4002]
    HttpActivity(HttpActivityEvent),
    /// SSH Activity [4007]
    SshActivity(SshActivityEvent),
    /// Process Activity [1007]
    ProcessActivity(ProcessActivityEvent),
    /// Detection Finding [2004]
    DetectionFinding(DetectionFindingEvent),
    /// Application Lifecycle [6002]
    ApplicationLifecycle(ApplicationLifecycleEvent),
    /// Device Config State Change [5019]
    DeviceConfigStateChange(DeviceConfigStateChangeEvent),
    /// Base Event [0]
    Base(BaseEvent),
}

impl Serialize for OcsfEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::NetworkActivity(e) => e.serialize(serializer),
            Self::HttpActivity(e) => e.serialize(serializer),
            Self::SshActivity(e) => e.serialize(serializer),
            Self::ProcessActivity(e) => e.serialize(serializer),
            Self::DetectionFinding(e) => e.serialize(serializer),
            Self::ApplicationLifecycle(e) => e.serialize(serializer),
            Self::DeviceConfigStateChange(e) => e.serialize(serializer),
            Self::Base(e) => e.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for OcsfEvent {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize into a raw JSON value first, then dispatch on class_uid.
        let value = serde_json::Value::deserialize(deserializer)?;

        let class_uid = value
            .get("class_uid")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| serde::de::Error::missing_field("class_uid"))?;

        match class_uid {
            4001 => serde_json::from_value::<NetworkActivityEvent>(value)
                .map(Self::NetworkActivity)
                .map_err(serde::de::Error::custom),
            4002 => serde_json::from_value::<HttpActivityEvent>(value)
                .map(Self::HttpActivity)
                .map_err(serde::de::Error::custom),
            4007 => serde_json::from_value::<SshActivityEvent>(value)
                .map(Self::SshActivity)
                .map_err(serde::de::Error::custom),
            1007 => serde_json::from_value::<ProcessActivityEvent>(value)
                .map(Self::ProcessActivity)
                .map_err(serde::de::Error::custom),
            2004 => serde_json::from_value::<DetectionFindingEvent>(value)
                .map(Self::DetectionFinding)
                .map_err(serde::de::Error::custom),
            6002 => serde_json::from_value::<ApplicationLifecycleEvent>(value)
                .map(Self::ApplicationLifecycle)
                .map_err(serde::de::Error::custom),
            5019 => serde_json::from_value::<DeviceConfigStateChangeEvent>(value)
                .map(Self::DeviceConfigStateChange)
                .map_err(serde::de::Error::custom),
            0 => serde_json::from_value::<BaseEvent>(value)
                .map(Self::Base)
                .map_err(serde::de::Error::custom),
            other => Err(serde::de::Error::custom(format!(
                "unknown OCSF class_uid: {other}"
            ))),
        }
    }
}

impl OcsfEvent {
    /// Returns the OCSF `class_uid` for this event.
    #[must_use]
    pub fn class_uid(&self) -> u32 {
        match self {
            Self::NetworkActivity(_) => 4001,
            Self::HttpActivity(_) => 4002,
            Self::SshActivity(_) => 4007,
            Self::ProcessActivity(_) => 1007,
            Self::DetectionFinding(_) => 2004,
            Self::ApplicationLifecycle(_) => 6002,
            Self::DeviceConfigStateChange(_) => 5019,
            Self::Base(_) => 0,
        }
    }

    /// Returns the base event data common to all event classes.
    #[must_use]
    pub fn base(&self) -> &BaseEventData {
        match self {
            Self::NetworkActivity(e) => &e.base,
            Self::HttpActivity(e) => &e.base,
            Self::SshActivity(e) => &e.base,
            Self::ProcessActivity(e) => &e.base,
            Self::DetectionFinding(e) => &e.base,
            Self::ApplicationLifecycle(e) => &e.base,
            Self::DeviceConfigStateChange(e) => &e.base,
            Self::Base(e) => &e.base,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::{
        AppLifecycleBuilder, BaseEventBuilder, ConfigStateChangeBuilder, DetectionFindingBuilder,
        HttpActivityBuilder, NetworkActivityBuilder, ProcessActivityBuilder, SshActivityBuilder,
        test_sandbox_context,
    };
    use crate::enums::*;
    use crate::objects::*;

    /// Verify that every event class round-trips through JSON and deserializes
    /// to the correct `OcsfEvent` variant (not silently matching the wrong one).
    #[test]
    fn test_roundtrip_network_activity() {
        let ctx = test_sandbox_context();
        let event = NetworkActivityBuilder::new(&ctx)
            .activity(ActivityId::Open)
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .dst_endpoint(Endpoint::from_domain("example.com", 443))
            .build();

        let json = serde_json::to_value(&event).unwrap();
        let deserialized: OcsfEvent = serde_json::from_value(json).unwrap();
        assert!(matches!(deserialized, OcsfEvent::NetworkActivity(_)));
        assert_eq!(deserialized.class_uid(), 4001);
    }

    #[test]
    fn test_roundtrip_http_activity() {
        let ctx = test_sandbox_context();
        let event = HttpActivityBuilder::new(&ctx)
            .activity(ActivityId::Reset)
            .action(ActionId::Allowed)
            .severity(SeverityId::Informational)
            .http_request(HttpRequest::new(
                "GET",
                Url::new("https", "example.com", "/", 443),
            ))
            .build();

        let json = serde_json::to_value(&event).unwrap();
        let deserialized: OcsfEvent = serde_json::from_value(json).unwrap();
        assert!(matches!(deserialized, OcsfEvent::HttpActivity(_)));
        assert_eq!(deserialized.class_uid(), 4002);
    }

    #[test]
    fn test_roundtrip_ssh_activity() {
        let ctx = test_sandbox_context();
        let event = SshActivityBuilder::new(&ctx)
            .activity(ActivityId::Open)
            .action(ActionId::Allowed)
            .severity(SeverityId::Informational)
            .build();

        let json = serde_json::to_value(&event).unwrap();
        let deserialized: OcsfEvent = serde_json::from_value(json).unwrap();
        assert!(matches!(deserialized, OcsfEvent::SshActivity(_)));
        assert_eq!(deserialized.class_uid(), 4007);
    }

    #[test]
    fn test_roundtrip_process_activity() {
        let ctx = test_sandbox_context();
        let event = ProcessActivityBuilder::new(&ctx)
            .activity(ActivityId::Open)
            .severity(SeverityId::Informational)
            .process(Process::new("test", 1))
            .build();

        let json = serde_json::to_value(&event).unwrap();
        let deserialized: OcsfEvent = serde_json::from_value(json).unwrap();
        assert!(matches!(deserialized, OcsfEvent::ProcessActivity(_)));
        assert_eq!(deserialized.class_uid(), 1007);
    }

    #[test]
    fn test_roundtrip_detection_finding() {
        let ctx = test_sandbox_context();
        let event = DetectionFindingBuilder::new(&ctx)
            .severity(SeverityId::High)
            .finding_info(FindingInfo::new("test-uid", "Test Finding"))
            .build();

        let json = serde_json::to_value(&event).unwrap();
        let deserialized: OcsfEvent = serde_json::from_value(json).unwrap();
        assert!(matches!(deserialized, OcsfEvent::DetectionFinding(_)));
        assert_eq!(deserialized.class_uid(), 2004);
    }

    #[test]
    fn test_roundtrip_application_lifecycle() {
        let ctx = test_sandbox_context();
        let event = AppLifecycleBuilder::new(&ctx)
            .activity(ActivityId::Reset)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .build();

        let json = serde_json::to_value(&event).unwrap();
        let deserialized: OcsfEvent = serde_json::from_value(json).unwrap();
        assert!(matches!(deserialized, OcsfEvent::ApplicationLifecycle(_)));
        assert_eq!(deserialized.class_uid(), 6002);
    }

    #[test]
    fn test_roundtrip_config_state_change() {
        let ctx = test_sandbox_context();
        let event = ConfigStateChangeBuilder::new(&ctx)
            .state(StateId::Enabled, "loaded")
            .severity(SeverityId::Informational)
            .build();

        let json = serde_json::to_value(&event).unwrap();
        let deserialized: OcsfEvent = serde_json::from_value(json).unwrap();
        assert!(matches!(
            deserialized,
            OcsfEvent::DeviceConfigStateChange(_)
        ));
        assert_eq!(deserialized.class_uid(), 5019);
    }

    #[test]
    fn test_roundtrip_base_event() {
        let ctx = test_sandbox_context();
        let event = BaseEventBuilder::new(&ctx)
            .severity(SeverityId::Informational)
            .message("test")
            .build();

        let json = serde_json::to_value(&event).unwrap();
        let deserialized: OcsfEvent = serde_json::from_value(json).unwrap();
        assert!(matches!(deserialized, OcsfEvent::Base(_)));
        assert_eq!(deserialized.class_uid(), 0);
    }

    #[test]
    fn test_deserialize_unknown_class_uid_errors() {
        let json = serde_json::json!({"class_uid": 9999});
        let result = serde_json::from_value::<OcsfEvent>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_missing_class_uid_errors() {
        let json = serde_json::json!({"severity_id": 1});
        let result = serde_json::from_value::<OcsfEvent>(json);
        assert!(result.is_err());
    }
}
