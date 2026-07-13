// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pure admission decisions for a managed maximum policy.
//!
//! Callers compose the live candidate and requested delta before invoking this
//! module. Persistence remains outside this boundary so every commit point can
//! re-run the same decision immediately before applying a change.

use openshell_prover::envelope::{
    MaximumPolicyCheck, PolicyCounterexample, check_within_auto_eligible_maximum,
    check_within_maximum,
};
use openshell_prover::policy::{PolicyModel, parse_policy_str};

/// User-selectable approval behavior inside a managed maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionMode {
    Ask,
    Auto,
}

impl PermissionMode {
    pub fn parse(mode: &str) -> Result<Self, String> {
        match mode.trim().to_ascii_lowercase().as_str() {
            "ask" => Ok(Self::Ask),
            "auto" => Ok(Self::Auto),
            _ => Err(format!(
                "unsupported managed permission mode '{mode}'; expected ask or auto"
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Auto => "auto",
        }
    }
}

/// Origin of an authority-changing candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionSource {
    SandboxCreate,
    DirectAuthenticated,
    AgentProposal,
}

impl AdmissionSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SandboxCreate => "sandbox_create",
            Self::DirectAuthenticated => "direct_authenticated",
            Self::AgentProposal => "agent_proposal",
        }
    }
}

/// One active gateway-owned boundary.
pub struct ManagedBoundary<'a> {
    pub id: &'a str,
    pub version: u64,
    pub maximum: &'a PolicyModel,
    pub allowed_modes: &'a [PermissionMode],
}

/// Validated, owned representation persisted by the gateway.
pub struct ManagedPolicyConfig {
    pub id: String,
    pub version: u64,
    pub maximum: PolicyModel,
    pub allowed_modes: Vec<PermissionMode>,
    pub default_mode: PermissionMode,
    pub audit_label: String,
}

impl ManagedPolicyConfig {
    /// Parse a managed maximum document without accepting a second policy
    /// language. Metadata is read from the document's top-level `metadata`
    /// block; authority is parsed by the normal prover policy model.
    pub fn parse(yaml: &str) -> Result<Self, String> {
        let maximum = parse_policy_str(yaml).map_err(|error| error.to_string())?;
        if maximum.version != 1 {
            return Err(format!(
                "managed maximum uses unsupported policy version {}; expected version 1",
                maximum.version
            ));
        }
        let metadata = maximum
            .managed_metadata
            .as_ref()
            .ok_or_else(|| "managed maximum requires a metadata block".to_owned())?;
        if metadata.policy_id.trim().is_empty() {
            return Err("managed maximum metadata.policy_id is required".to_owned());
        }
        if metadata.version == 0 {
            return Err("managed maximum metadata.version must be greater than zero".to_owned());
        }
        if !metadata.extra_fields.is_empty() {
            return Err(format!(
                "managed maximum metadata contains unsupported fields: {}",
                metadata.extra_fields.join(", ")
            ));
        }

        let mut allowed_modes = metadata
            .allowed_modes
            .iter()
            .map(|mode| PermissionMode::parse(mode))
            .collect::<Result<Vec<_>, _>>()?;
        allowed_modes.sort_by_key(|mode| match mode {
            PermissionMode::Ask => 0,
            PermissionMode::Auto => 1,
        });
        allowed_modes.dedup();
        if allowed_modes.is_empty() {
            return Err("managed maximum metadata.allowed_modes cannot be empty".to_owned());
        }
        let default_mode = PermissionMode::parse(&metadata.default_mode)?;
        if !allowed_modes.contains(&default_mode) {
            return Err("managed maximum default_mode must be in allowed_modes".to_owned());
        }

        match check_within_maximum(&maximum, &maximum) {
            MaximumPolicyCheck::WithinMax => {}
            MaximumPolicyCheck::Unsupported { reason } => return Err(reason),
            MaximumPolicyCheck::ExceedsMax { .. } => {
                return Err("managed maximum was not self-contained".to_owned());
            }
        }

        Ok(Self {
            id: metadata.policy_id.clone(),
            version: metadata.version,
            allowed_modes,
            default_mode,
            audit_label: metadata.audit_label.clone(),
            maximum,
        })
    }

    pub fn boundary(&self) -> ManagedBoundary<'_> {
        ManagedBoundary {
            id: &self.id,
            version: self.version,
            maximum: &self.maximum,
            allowed_modes: &self.allowed_modes,
        }
    }
}

/// Result shared by all authority commit points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// No managed maximum exists; the caller must use existing behavior.
    Unmanaged,
    Apply,
    Ask {
        reason: String,
        counterexample: Option<PolicyCounterexample>,
    },
    Reject {
        reason: String,
        counterexample: Option<PolicyCounterexample>,
    },
}

/// Decide whether one fully composed candidate may be committed.
pub fn admit(
    boundary: Option<&ManagedBoundary<'_>>,
    mode: PermissionMode,
    source: AdmissionSource,
    current: Option<&PolicyModel>,
    candidate: &PolicyModel,
    requested_delta: &PolicyModel,
) -> AdmissionDecision {
    let Some(boundary) = boundary else {
        return AdmissionDecision::Unmanaged;
    };

    if !boundary.allowed_modes.contains(&mode) {
        return AdmissionDecision::Reject {
            reason: format!(
                "permission mode {mode:?} is not allowed by managed maximum {}@{}",
                boundary.id, boundary.version
            ),
            counterexample: None,
        };
    }

    match check_within_maximum(boundary.maximum, candidate) {
        MaximumPolicyCheck::WithinMax => {}
        MaximumPolicyCheck::ExceedsMax { counterexample } => {
            return AdmissionDecision::Reject {
                reason: format!(
                    "candidate exceeds managed maximum {}@{}",
                    boundary.id, boundary.version
                ),
                counterexample: Some(*counterexample),
            };
        }
        MaximumPolicyCheck::Unsupported { reason } => {
            return AdmissionDecision::Reject {
                reason: format!(
                    "candidate cannot be evaluated against managed maximum {}@{}: {reason}",
                    boundary.id, boundary.version
                ),
                counterexample: None,
            };
        }
    }

    if source == AdmissionSource::SandboxCreate {
        return match check_within_auto_eligible_maximum(boundary.maximum, candidate) {
            MaximumPolicyCheck::WithinMax => AdmissionDecision::Apply,
            MaximumPolicyCheck::ExceedsMax { counterexample } => AdmissionDecision::Reject {
                reason: "sandbox creation includes review-required authority".to_owned(),
                counterexample: Some(*counterexample),
            },
            MaximumPolicyCheck::Unsupported { reason } => AdmissionDecision::Reject {
                reason,
                counterexample: None,
            },
        };
    }

    if source == AdmissionSource::DirectAuthenticated
        || current.is_some_and(|current| {
            matches!(
                check_within_maximum(current, candidate),
                MaximumPolicyCheck::WithinMax
            )
        })
    {
        return AdmissionDecision::Apply;
    }

    if mode == PermissionMode::Ask {
        return AdmissionDecision::Ask {
            reason: "managed permission mode requires approval".to_owned(),
            counterexample: None,
        };
    }

    match check_within_auto_eligible_maximum(boundary.maximum, requested_delta) {
        MaximumPolicyCheck::WithinMax => AdmissionDecision::Apply,
        MaximumPolicyCheck::ExceedsMax { counterexample } => AdmissionDecision::Ask {
            reason: "requested authority is inside the maximum but requires review".to_owned(),
            counterexample: Some(*counterexample),
        },
        MaximumPolicyCheck::Unsupported { reason } => AdmissionDecision::Reject {
            reason,
            counterexample: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_prover::policy::parse_policy_str;

    fn policy(rule: &str) -> PolicyModel {
        parse_policy_str(&format!(
            r"version: 1
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
{rule}
    binaries:
      - path: /usr/bin/gh
"
        ))
        .expect("policy should parse")
    }

    fn boundary(maximum: &PolicyModel) -> ManagedBoundary<'_> {
        ManagedBoundary {
            id: "engineering",
            version: 7,
            maximum,
            allowed_modes: &[PermissionMode::Ask, PermissionMode::Auto],
        }
    }

    #[test]
    fn managed_document_parses_policy_and_metadata_together() {
        let config = ManagedPolicyConfig::parse(
            r"version: 1
metadata:
  policy_id: engineering
  version: 3
  allowed_modes: [ask, auto]
  default_mode: auto
  audit_label: corp-dev
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/bin/gh
",
        )
        .expect("managed document should parse");
        assert_eq!(config.id, "engineering");
        assert_eq!(config.version, 3);
        assert_eq!(config.default_mode, PermissionMode::Auto);
        assert_eq!(config.audit_label, "corp-dev");
        assert_eq!(config.boundary().allowed_modes.len(), 2);
    }

    #[test]
    fn managed_document_rejects_default_mode_outside_allowed_modes() {
        let error = ManagedPolicyConfig::parse(
            r"version: 1
metadata:
  policy_id: engineering
  version: 1
  allowed_modes: [ask]
  default_mode: auto
",
        )
        .err()
        .expect("invalid default should fail");
        assert!(error.contains("default_mode"));
    }

    #[test]
    fn checked_in_managed_maximum_examples_are_supported() {
        ManagedPolicyConfig::parse(include_str!(
            "../../../examples/managed-maximum-policies/github-rest.yaml"
        ))
        .expect("checked-in REST example should be supported");
    }

    #[test]
    fn absent_boundary_preserves_unmanaged_behavior() {
        let candidate = policy("          - allow: { method: GET, path: /repos/** }");
        assert_eq!(
            admit(
                None,
                PermissionMode::Auto,
                AdmissionSource::AgentProposal,
                None,
                &candidate,
                &candidate,
            ),
            AdmissionDecision::Unmanaged
        );
    }

    #[test]
    fn outside_maximum_rejects_before_mode_logic() {
        let maximum = policy("          - allow: { method: GET, path: /repos/acme/** }");
        let candidate = policy("          - allow: { method: DELETE, path: /repos/acme/project }");
        assert!(matches!(
            admit(
                Some(&boundary(&maximum)),
                PermissionMode::Ask,
                AdmissionSource::AgentProposal,
                None,
                &candidate,
                &candidate,
            ),
            AdmissionDecision::Reject {
                counterexample: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn ask_mode_holds_in_maximum_agent_grant() {
        let maximum = policy("          - allow: { method: GET, path: /repos/** }");
        let candidate = policy("          - allow: { method: GET, path: /repos/acme/project }");
        assert!(matches!(
            admit(
                Some(&boundary(&maximum)),
                PermissionMode::Ask,
                AdmissionSource::AgentProposal,
                None,
                &candidate,
                &candidate,
            ),
            AdmissionDecision::Ask { .. }
        ));
    }

    #[test]
    fn auto_mode_applies_auto_eligible_agent_grant() {
        let maximum = policy("          - allow: { method: GET, path: /repos/** }");
        let candidate = policy("          - allow: { method: GET, path: /repos/acme/project }");
        assert_eq!(
            admit(
                Some(&boundary(&maximum)),
                PermissionMode::Auto,
                AdmissionSource::AgentProposal,
                None,
                &candidate,
                &candidate,
            ),
            AdmissionDecision::Apply
        );
    }

    #[test]
    fn review_required_agent_grant_asks_in_auto_mode() {
        let maximum = policy(
            "          - allow:\n              method: POST\n              path: /repos/*/pulls\n              review: { required: true }",
        );
        let candidate = policy("          - allow: { method: POST, path: /repos/acme/pulls }");
        assert!(matches!(
            admit(
                Some(&boundary(&maximum)),
                PermissionMode::Auto,
                AdmissionSource::AgentProposal,
                None,
                &candidate,
                &candidate,
            ),
            AdmissionDecision::Ask {
                counterexample: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn review_required_starting_authority_rejects() {
        let maximum = policy(
            "          - allow:\n              method: POST\n              path: /repos/*/pulls\n              review: { required: true }",
        );
        let candidate = policy("          - allow: { method: POST, path: /repos/acme/pulls }");
        assert!(matches!(
            admit(
                Some(&boundary(&maximum)),
                PermissionMode::Auto,
                AdmissionSource::SandboxCreate,
                None,
                &candidate,
                &candidate,
            ),
            AdmissionDecision::Reject { .. }
        ));
    }

    #[test]
    fn direct_authenticated_edit_is_approval_of_exact_request() {
        let maximum = policy(
            "          - allow:\n              method: POST\n              path: /repos/*/pulls\n              review: { required: true }",
        );
        let candidate = policy("          - allow: { method: POST, path: /repos/acme/pulls }");
        assert_eq!(
            admit(
                Some(&boundary(&maximum)),
                PermissionMode::Ask,
                AdmissionSource::DirectAuthenticated,
                None,
                &candidate,
                &candidate,
            ),
            AdmissionDecision::Apply
        );
    }

    #[test]
    fn removal_applies_without_asking() {
        let current = policy("          - allow: { method: GET, path: /repos/** }");
        let candidate = policy("          - allow: { method: GET, path: /repos/acme/** }");
        assert_eq!(
            admit(
                Some(&boundary(&current)),
                PermissionMode::Ask,
                AdmissionSource::AgentProposal,
                Some(&current),
                &candidate,
                &candidate,
            ),
            AdmissionDecision::Apply
        );
    }
}
