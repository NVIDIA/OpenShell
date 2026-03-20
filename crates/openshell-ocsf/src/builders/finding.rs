// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for Detection Finding [2004] events.

use crate::builders::SandboxContext;
use crate::enums::{ActionId, ActivityId, ConfidenceId, DispositionId, RiskLevelId, SeverityId};
use crate::events::base_event::BaseEventData;
use crate::events::{DetectionFindingEvent, OcsfEvent};
use crate::objects::{Attack, Evidence, FindingInfo, Remediation};

/// Builder for Detection Finding [2004] events.
pub struct DetectionFindingBuilder<'a> {
    ctx: &'a SandboxContext,
    activity: ActivityId,
    severity: SeverityId,
    action: Option<ActionId>,
    disposition: Option<DispositionId>,
    finding_info: Option<FindingInfo>,
    evidences: Vec<Evidence>,
    attacks: Vec<Attack>,
    remediation: Option<Remediation>,
    is_alert: Option<bool>,
    confidence: Option<ConfidenceId>,
    risk_level: Option<RiskLevelId>,
    message: Option<String>,
    log_source: Option<String>,
}

impl<'a> DetectionFindingBuilder<'a> {
    #[must_use]
    pub fn new(ctx: &'a SandboxContext) -> Self {
        Self {
            ctx,
            activity: ActivityId::Open,
            severity: SeverityId::Medium,
            action: None,
            disposition: None,
            finding_info: None,
            evidences: Vec::new(),
            attacks: Vec::new(),
            remediation: None,
            is_alert: None,
            confidence: None,
            risk_level: None,
            message: None,
            log_source: None,
        }
    }

    #[must_use]
    pub fn activity(mut self, id: ActivityId) -> Self {
        self.activity = id;
        self
    }
    #[must_use]
    pub fn severity(mut self, id: SeverityId) -> Self {
        self.severity = id;
        self
    }
    #[must_use]
    pub fn action(mut self, id: ActionId) -> Self {
        self.action = Some(id);
        self
    }
    #[must_use]
    pub fn disposition(mut self, id: DispositionId) -> Self {
        self.disposition = Some(id);
        self
    }
    #[must_use]
    pub fn finding_info(mut self, info: FindingInfo) -> Self {
        self.finding_info = Some(info);
        self
    }
    #[must_use]
    pub fn is_alert(mut self, alert: bool) -> Self {
        self.is_alert = Some(alert);
        self
    }
    #[must_use]
    pub fn confidence(mut self, id: ConfidenceId) -> Self {
        self.confidence = Some(id);
        self
    }
    #[must_use]
    pub fn risk_level(mut self, id: RiskLevelId) -> Self {
        self.risk_level = Some(id);
        self
    }
    #[must_use]
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }
    #[must_use]
    pub fn log_source(mut self, source: impl Into<String>) -> Self {
        self.log_source = Some(source.into());
        self
    }

    /// Add a remediation description.
    #[must_use]
    pub fn remediation(mut self, desc: &str) -> Self {
        self.remediation = Some(Remediation::new(desc));
        self
    }

    /// Add evidence key-value pair.
    #[must_use]
    pub fn evidence(mut self, key: &str, value: &str) -> Self {
        self.evidences.push(Evidence::from_pairs(&[(key, value)]));
        self
    }

    /// Add evidence from multiple pairs.
    #[must_use]
    pub fn evidence_pairs(mut self, pairs: &[(&str, &str)]) -> Self {
        self.evidences.push(Evidence::from_pairs(pairs));
        self
    }

    /// Add a MITRE ATT&CK mapping.
    #[must_use]
    pub fn attack(mut self, attack: Attack) -> Self {
        self.attacks.push(attack);
        self
    }

    #[must_use]
    pub fn build(self) -> OcsfEvent {
        let activity_name = self.activity.finding_label().to_string();
        let mut metadata = self
            .ctx
            .metadata(&["security_control", "container", "host"]);
        if let Some(source) = self.log_source {
            metadata.log_source = Some(source);
        }

        let mut base = BaseEventData::new(
            2004,
            "Detection Finding",
            2,
            "Findings",
            self.activity.as_u8(),
            &activity_name,
            self.severity,
            metadata,
        );
        if let Some(msg) = self.message {
            base.set_message(msg);
        }
        base.set_device(self.ctx.device());
        base.set_container(self.ctx.container());

        OcsfEvent::DetectionFinding(DetectionFindingEvent {
            base,
            finding_info: self
                .finding_info
                .unwrap_or_else(|| FindingInfo::new("unknown", "Unknown Finding")),
            evidences: if self.evidences.is_empty() {
                None
            } else {
                Some(self.evidences)
            },
            attacks: if self.attacks.is_empty() {
                None
            } else {
                Some(self.attacks)
            },
            remediation: self.remediation,
            is_alert: self.is_alert,
            confidence: self.confidence,
            risk_level: self.risk_level,
            action: self.action,
            disposition: self.disposition,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::test_sandbox_context;

    #[test]
    fn test_detection_finding_builder() {
        let ctx = test_sandbox_context();
        let event = DetectionFindingBuilder::new(&ctx)
            .activity(ActivityId::Open) // Create
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::High)
            .is_alert(true)
            .confidence(ConfidenceId::High)
            .risk_level(RiskLevelId::High)
            .finding_info(
                FindingInfo::new("nssh1-replay-abc", "NSSH1 Nonce Replay Attack")
                    .with_desc("A nonce was replayed."),
            )
            .evidence("nonce", "0xdeadbeef")
            .attack(Attack::mitre(
                "T1550",
                "Use Alternate Authentication Material",
                "TA0008",
                "Lateral Movement",
            ))
            .message("NSSH1 nonce replay detected")
            .build();

        let json = event.to_json().unwrap();
        assert_eq!(json["class_uid"], 2004);
        assert_eq!(json["finding_info"]["title"], "NSSH1 Nonce Replay Attack");
        assert_eq!(json["is_alert"], true);
        assert_eq!(json["confidence"], "High");
    }
}
