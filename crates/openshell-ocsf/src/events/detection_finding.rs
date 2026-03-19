// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Detection Finding [2004] event class.

use serde::{Deserialize, Serialize};

use crate::events::base_event::BaseEventData;
use crate::objects::{Attack, Evidence, FindingInfo, Remediation};

/// OCSF Detection Finding Event [2004].
///
/// Security-relevant findings from policy enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionFindingEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,

    /// Finding details (required).
    pub finding_info: FindingInfo,

    /// Evidence artifacts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidences: Option<Vec<Evidence>>,

    /// MITRE ATT&CK mappings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attacks: Option<Vec<Attack>>,

    /// Remediation guidance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Remediation>,

    /// Whether this finding is an alert.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_alert: Option<bool>,

    /// Confidence ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_id: Option<u8>,

    /// Confidence label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,

    /// Risk level ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level_id: Option<u8>,

    /// Risk level label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,

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
    fn test_detection_finding_serialization() {
        let event = DetectionFindingEvent {
            base: BaseEventData::new(
                2004,
                "Detection Finding",
                2,
                "Findings",
                1,
                "Create",
                SeverityId::High,
                Metadata {
                    version: "1.7.0".to_string(),
                    product: Product::openshell_sandbox("0.1.0"),
                    profiles: vec!["security_control".to_string()],
                    uid: Some("sandbox-abc123".to_string()),
                    log_source: None,
                },
            ),
            finding_info: FindingInfo::new("nssh1-replay-abc", "NSSH1 Nonce Replay Attack")
                .with_desc("A nonce was replayed."),
            evidences: Some(vec![Evidence::from_pairs(&[
                ("nonce", "0xdeadbeef"),
                ("peer_ip", "10.42.0.1"),
            ])]),
            attacks: Some(vec![Attack::mitre(
                "T1550",
                "Use Alternate Authentication Material",
                "TA0008",
                "Lateral Movement",
            )]),
            remediation: None,
            is_alert: Some(true),
            confidence_id: Some(3),
            confidence: Some("High".to_string()),
            risk_level_id: Some(4),
            risk_level: Some("High".to_string()),
            action_id: Some(2),
            action: Some("Denied".to_string()),
            disposition_id: Some(2),
            disposition: Some("Blocked".to_string()),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 2004);
        assert_eq!(json["finding_info"]["title"], "NSSH1 Nonce Replay Attack");
        assert_eq!(json["is_alert"], true);
        assert_eq!(json["confidence"], "High");
        assert_eq!(json["attacks"][0]["technique"]["uid"], "T1550");
    }
}
