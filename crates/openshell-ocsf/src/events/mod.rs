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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
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
