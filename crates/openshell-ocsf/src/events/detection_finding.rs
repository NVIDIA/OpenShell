// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Detection Finding [2004] event class.

use serde::{Deserialize, Serialize};

use crate::enums::{ActionId, ConfidenceId, DispositionId, RiskLevelId};
use crate::events::base_event::BaseEventData;
use crate::objects::{Attack, Evidence, FindingInfo, Remediation};

/// OCSF Detection Finding Event [2004].
///
/// Security-relevant findings from policy enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

    #[serde(
        rename = "confidence_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub confidence: Option<ConfidenceId>,

    #[serde(
        rename = "risk_level_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub risk_level: Option<RiskLevelId>,

    #[serde(rename = "action_id", default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionId>,

    #[serde(
        rename = "disposition_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disposition: Option<DispositionId>,
}

impl Serialize for DetectionFindingEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::events::serde_helpers::{insert_enum_pair, insert_optional, insert_required};

        let mut base_val = serde_json::to_value(&self.base).map_err(serde::ser::Error::custom)?;
        let obj = base_val
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("expected object"))?;

        insert_required!(obj, "finding_info", self.finding_info);
        insert_optional!(obj, "evidences", self.evidences);
        insert_optional!(obj, "attacks", self.attacks);
        insert_optional!(obj, "remediation", self.remediation);
        insert_optional!(obj, "is_alert", self.is_alert);
        insert_enum_pair!(obj, "confidence", self.confidence);
        insert_enum_pair!(obj, "risk_level", self.risk_level);
        insert_enum_pair!(obj, "action", self.action);
        insert_enum_pair!(obj, "disposition", self.disposition);

        base_val.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{ActionId, ConfidenceId, DispositionId, RiskLevelId, SeverityId};
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
            confidence: Some(ConfidenceId::High),
            risk_level: Some(RiskLevelId::High),
            action: Some(ActionId::Denied),
            disposition: Some(DispositionId::Blocked),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 2004);
        assert_eq!(json["finding_info"]["title"], "NSSH1 Nonce Replay Attack");
        assert_eq!(json["is_alert"], true);
        assert_eq!(json["confidence"], "High");
        assert_eq!(json["attacks"][0]["technique"]["uid"], "T1550");
    }
}
