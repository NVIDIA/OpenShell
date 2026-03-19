// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `activity_id` enum — unified across event classes.
//!
//! OCSF defines per-class activity IDs. We use a single enum with variants
//! covering all classes. The `class_uid` context determines which variants
//! are valid for a given event.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Activity ID — unified across event classes.
///
/// Activity semantics vary by event class. The naming follows the most
/// common OCSF usage. See per-variant docs for which classes use each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum ActivityId {
    /// 0 — Unknown (all classes)
    Unknown = 0,

    // --- Network/SSH/HTTP Activity (4001, 4002, 4007) ---
    // --- Also Detection Finding: Create (2004) ---
    // --- Also Application Lifecycle: Install (6002) ---
    // --- Also Config State Change: Log (5019) ---
    /// 1 — Open (Network/SSH), Connect (HTTP), Create (Finding), Install (Lifecycle), Log (Config)
    Open = 1,
    /// 2 — Close (Network/SSH), Delete (HTTP), Update (Finding), Remove (Lifecycle), Collect (Config)
    Close = 2,
    /// 3 — Reset (Network), Get (HTTP), Close (Finding), Start (Lifecycle)
    Reset = 3,
    /// 4 — Fail (Network/SSH), Head (HTTP), Stop (Lifecycle)
    Fail = 4,
    /// 5 — Refuse (Network/SSH), Options (HTTP), Restart (Lifecycle)
    Refuse = 5,
    /// 6 — Traffic (Network), Post (HTTP), Enable (Lifecycle)
    Traffic = 6,
    /// 7 — Listen (Network/SSH), Put (HTTP), Disable (Lifecycle)
    Listen = 7,
    /// 8 — Trace (HTTP), Update (Lifecycle)
    Trace = 8,
    /// 9 — Patch (HTTP)
    Patch = 9,

    /// 99 — Other (all classes)
    Other = 99,
}

impl ActivityId {
    /// Returns a human-readable label for this activity in a network context.
    #[must_use]
    pub fn network_label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Open => "Open",
            Self::Close => "Close",
            Self::Reset => "Reset",
            Self::Fail => "Fail",
            Self::Refuse => "Refuse",
            Self::Traffic => "Traffic",
            Self::Listen => "Listen",
            Self::Trace => "Trace",
            Self::Patch => "Patch",
            Self::Other => "Other",
        }
    }

    /// Returns a human-readable label for HTTP activity context.
    #[must_use]
    pub fn http_label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Open => "Connect",
            Self::Close => "Delete",
            Self::Reset => "Get",
            Self::Fail => "Head",
            Self::Refuse => "Options",
            Self::Traffic => "Post",
            Self::Listen => "Put",
            Self::Trace => "Trace",
            Self::Patch => "Patch",
            Self::Other => "Other",
        }
    }

    /// Returns a human-readable label for Detection Finding activity context.
    #[must_use]
    pub fn finding_label(self) -> &'static str {
        match self {
            Self::Open => "Create",
            Self::Close => "Update",
            Self::Reset => "Close",
            _ => self.network_label(),
        }
    }

    /// Returns a human-readable label for Application Lifecycle activity context.
    #[must_use]
    pub fn lifecycle_label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Open => "Install",
            Self::Close => "Remove",
            Self::Reset => "Start",
            Self::Fail => "Stop",
            Self::Refuse => "Restart",
            Self::Traffic => "Enable",
            Self::Listen => "Disable",
            Self::Trace => "Update",
            Self::Patch | Self::Other => "Other",
        }
    }

    /// Returns a human-readable label for Config State Change activity context.
    #[must_use]
    pub fn config_label(self) -> &'static str {
        match self {
            Self::Open => "Log",
            Self::Close => "Collect",
            _ => self.network_label(),
        }
    }

    /// Returns a human-readable label for Process Activity context.
    #[must_use]
    pub fn process_label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Open => "Launch",
            Self::Close => "Terminate",
            Self::Reset => "Open",
            Self::Fail => "Inject",
            Self::Refuse => "Set User ID",
            _ => self.network_label(),
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activity_network_labels() {
        assert_eq!(ActivityId::Open.network_label(), "Open");
        assert_eq!(ActivityId::Close.network_label(), "Close");
        assert_eq!(ActivityId::Refuse.network_label(), "Refuse");
        assert_eq!(ActivityId::Listen.network_label(), "Listen");
    }

    #[test]
    fn test_activity_http_labels() {
        assert_eq!(ActivityId::Open.http_label(), "Connect");
        assert_eq!(ActivityId::Close.http_label(), "Delete");
        assert_eq!(ActivityId::Reset.http_label(), "Get");
        assert_eq!(ActivityId::Traffic.http_label(), "Post");
        assert_eq!(ActivityId::Listen.http_label(), "Put");
        assert_eq!(ActivityId::Patch.http_label(), "Patch");
    }

    #[test]
    fn test_activity_process_labels() {
        assert_eq!(ActivityId::Open.process_label(), "Launch");
        assert_eq!(ActivityId::Close.process_label(), "Terminate");
    }

    #[test]
    fn test_activity_json_roundtrip() {
        let activity = ActivityId::Open;
        let json = serde_json::to_value(activity).unwrap();
        assert_eq!(json, serde_json::json!(1));
        let deserialized: ActivityId = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, ActivityId::Open);
    }
}
