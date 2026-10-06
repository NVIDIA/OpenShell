// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `disposition_id` enum.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Disposition ID (0-27, 99).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum DispositionId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — Allowed
    Allowed = 1,
    /// 2 — Blocked
    Blocked = 2,
    /// 3 — Quarantined
    Quarantined = 3,
    /// 4 — Isolated
    Isolated = 4,
    /// 5 — Deleted
    Deleted = 5,
    /// 6 — Dropped
    Dropped = 6,
    /// 7 — Custom Action
    CustomAction = 7,
    /// 8 — Approved
    Approved = 8,
    /// 9 — Restored
    Restored = 9,
    /// 10 — Exonerated
    Exonerated = 10,
    /// 11 — Corrected
    Corrected = 11,
    /// 12 — Partially Corrected
    PartiallyCorrected = 12,
    /// 13 — Uncorrected
    Uncorrected = 13,
    /// 14 — Delayed
    Delayed = 14,
    /// 15 — Detected
    Detected = 15,
    /// 16 — No Action
    NoAction = 16,
    /// 17 — Logged
    Logged = 17,
    /// 18 — Tagged
    Tagged = 18,
    /// 19 — Alert
    Alert = 19,
    /// 20 — Count
    Count = 20,
    /// 21 — Reset
    Reset = 21,
    /// 22 — Captcha
    Captcha = 22,
    /// 23 — Challenge
    Challenge = 23,
    /// 24 — Access Revoked
    AccessRevoked = 24,
    /// 25 — Rejected
    Rejected = 25,
    /// 26 — Unauthorized
    Unauthorized = 26,
    /// 27 — Error
    Error = 27,
    /// 99 — Other
    Other = 99,
}

impl DispositionId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Allowed => "Allowed",
            Self::Blocked => "Blocked",
            Self::Quarantined => "Quarantined",
            Self::Isolated => "Isolated",
            Self::Deleted => "Deleted",
            Self::Dropped => "Dropped",
            Self::CustomAction => "Custom Action",
            Self::Approved => "Approved",
            Self::Restored => "Restored",
            Self::Exonerated => "Exonerated",
            Self::Corrected => "Corrected",
            Self::PartiallyCorrected => "Partially Corrected",
            Self::Uncorrected => "Uncorrected",
            Self::Delayed => "Delayed",
            Self::Detected => "Detected",
            Self::NoAction => "No Action",
            Self::Logged => "Logged",
            Self::Tagged => "Tagged",
            Self::Alert => "Alert",
            Self::Count => "Count",
            Self::Reset => "Reset",
            Self::Captcha => "Captcha",
            Self::Challenge => "Challenge",
            Self::AccessRevoked => "Access Revoked",
            Self::Rejected => "Rejected",
            Self::Unauthorized => "Unauthorized",
            Self::Error => "Error",
            Self::Other => "Other",
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
    fn test_disposition_labels() {
        assert_eq!(DispositionId::Unknown.label(), "Unknown");
        assert_eq!(DispositionId::Allowed.label(), "Allowed");
        assert_eq!(DispositionId::Blocked.label(), "Blocked");
        assert_eq!(DispositionId::Detected.label(), "Detected");
        assert_eq!(DispositionId::Logged.label(), "Logged");
        assert_eq!(DispositionId::Rejected.label(), "Rejected");
        assert_eq!(DispositionId::Error.label(), "Error");
        assert_eq!(DispositionId::Other.label(), "Other");
    }

    #[test]
    fn test_disposition_integer_values() {
        assert_eq!(DispositionId::Unknown.as_u8(), 0);
        assert_eq!(DispositionId::Allowed.as_u8(), 1);
        assert_eq!(DispositionId::Blocked.as_u8(), 2);
        assert_eq!(DispositionId::Rejected.as_u8(), 25);
        assert_eq!(DispositionId::Error.as_u8(), 27);
        assert_eq!(DispositionId::Other.as_u8(), 99);
    }

    #[test]
    fn test_disposition_json_roundtrip() {
        let disp = DispositionId::Blocked;
        let json = serde_json::to_value(disp).unwrap();
        assert_eq!(json, serde_json::json!(2));
        let deserialized: DispositionId = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, DispositionId::Blocked);
    }
}
