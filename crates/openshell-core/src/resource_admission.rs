// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operator-owned external resource admission. GPU attachments are temporarily
//! exempt; this policy must not be interpreted as permission to attach host paths.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::driver_utils::{LABEL_GATEWAY_ID, LABEL_MANAGED_BY, LABEL_SANDBOX_WORKSPACE};

const WORKSPACE_PLACEHOLDER: &str = "${workspace}";
const RESERVED_LABEL_KEYS: [&str; 3] =
    [LABEL_MANAGED_BY, LABEL_GATEWAY_ID, LABEL_SANDBOX_WORKSPACE];

/// Label policy shared by every compute driver. A supplied map replaces defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceAdmissionConfig {
    pub enabled: bool,
    pub required_labels: BTreeMap<String, String>,
}

impl Default for ResourceAdmissionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            required_labels: BTreeMap::from([
                ("openshell.ai/sandbox-attachable".into(), "true".into()),
                (
                    "openshell.ai/sandbox-attachable-workspace".into(),
                    WORKSPACE_PLACEHOLDER.into(),
                ),
            ]),
        }
    }
}

/// Effective policy acknowledged by a driver, including the independent JSON gate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DriverAdmissionConfig {
    pub allow_driver_config: bool,
    pub resource_admission: ResourceAdmissionConfig,
}

impl DriverAdmissionConfig {
    pub fn validate(&self) -> Result<(), String> {
        self.resource_admission.validate()
    }

    /// Versioned acknowledgement. Compare parsed policies, never an untrusted flag.
    #[must_use]
    pub fn acknowledgement(&self) -> String {
        // These types contain only strings, booleans and string-keyed maps.
        format!(
            "v1:{}",
            serde_json::to_string(self).expect("serializable admission policy")
        )
    }

    pub fn verify_acknowledgement(&self, value: &str) -> Result<(), String> {
        self.validate()?;
        if !self.resource_admission.enabled && value.is_empty() {
            // Explicit legacy-driver opt-out. The gateway still gates caller JSON.
            return Ok(());
        }
        let policy: Self = value
            .strip_prefix("v1:")
            .ok_or("compute driver does not acknowledge resource admission v1")
            .and_then(|json| {
                serde_json::from_str(json).map_err(|_| "invalid driver admission acknowledgement")
            })?;
        if policy != *self {
            return Err(
                "compute driver admission policy differs from gateway configuration".into(),
            );
        }
        Ok(())
    }
}

impl std::str::FromStr for DriverAdmissionConfig {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let policy: Self = serde_json::from_str(value).map_err(|error| error.to_string())?;
        policy.validate()?;
        Ok(policy)
    }
}

/// Reserved driver-owned runtime metadata; caller labels must never override it.
pub const CONFIG_USED_LABEL: &str = "openshell.ai/caller-driver-config-used";
pub const IDENTITIES_LABEL: &str = "openshell.ai/resource-admission-identities";

pub fn check_config_provenance(allowed: bool, recorded: Option<&str>) -> Result<(), tonic::Status> {
    match recorded {
        Some("false") => Ok(()),
        Some("true") if allowed => Ok(()),
        _ => Err(tonic::Status::failed_precondition(
            "sandbox uses forbidden driver config or lacks admission provenance; recreate it",
        )),
    }
}

/// Check caller config before resource lookups, including direct driver RPCs.
pub fn check_driver_config(
    allowed: bool,
    config: Option<&prost_types::Struct>,
) -> Result<(), tonic::Status> {
    if !allowed && config.is_some_and(|config| !config.fields.is_empty()) {
        return Err(tonic::Status::failed_precondition(
            "caller driver config is disabled; a gateway administrator must enable allow_driver_config",
        ));
    }
    Ok(())
}

pub fn check_sandbox_driver_config(
    allowed: bool,
    sandbox: &crate::proto::compute::v1::DriverSandbox,
) -> Result<(), tonic::Status> {
    check_driver_config(
        allowed,
        sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.template.as_ref())
            .and_then(|template| template.driver_config.as_ref()),
    )
}

impl ResourceAdmissionConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.required_labels.is_empty() {
            return Err(
                "resource_admission.required_labels must not be empty while enabled".into(),
            );
        }
        for (key, value) in &self.required_labels {
            if RESERVED_LABEL_KEYS.contains(&key.as_str()) {
                return Err(format!(
                    "resource admission label key is reserved for driver-owned metadata: {key}"
                ));
            }
            if !valid_label_key(key) {
                return Err(format!("invalid resource admission label key: {key}"));
            }
            if value != WORKSPACE_PLACEHOLDER && !valid_label_value(value) {
                return Err(format!(
                    "invalid resource admission label value for {key}; only whole-value ${{workspace}} substitution is supported"
                ));
            }
        }
        if self.enabled
            && self
                .required_labels
                .values()
                .all(|value| value == WORKSPACE_PLACEHOLDER)
        {
            return Err(
                "resource_admission.required_labels must include a shared approval label".into(),
            );
        }
        Ok(())
    }

    /// Evaluate labels read from the resource authority, never caller metadata.
    pub fn admit<'a>(
        &self,
        workspace: &str,
        labels: impl IntoIterator<Item = (&'a String, &'a String)>,
    ) -> Result<(), tonic::Status> {
        self.admit_labels(Some(workspace), labels)
    }

    /// Evaluate a shared operator resource. Fixed approval labels still apply,
    /// but workspace placeholders do not: cluster-scoped and intentionally
    /// shared resources cannot carry one tenant's identity.
    pub fn admit_shared<'a>(
        &self,
        labels: impl IntoIterator<Item = (&'a String, &'a String)>,
    ) -> Result<(), tonic::Status> {
        self.admit_labels(None, labels)
    }

    fn admit_labels<'a>(
        &self,
        workspace: Option<&str>,
        labels: impl IntoIterator<Item = (&'a String, &'a String)>,
    ) -> Result<(), tonic::Status> {
        self.validate()
            .map_err(tonic::Status::failed_precondition)?;
        if !self.enabled {
            return Ok(());
        }
        let labels: BTreeMap<_, _> = labels.into_iter().collect();
        for (key, expected) in &self.required_labels {
            let expected = if expected == WORKSPACE_PLACEHOLDER {
                let Some(workspace) = workspace else {
                    continue;
                };
                if workspace.is_empty() || !valid_label_value(workspace) {
                    return Err(tonic::Status::failed_precondition(
                        "resource not admitted: invalid workspace identity",
                    ));
                }
                workspace
            } else {
                expected
            };
            if labels.get(key).map(|value| value.as_str()) != Some(expected) {
                return Err(tonic::Status::failed_precondition(
                    "external resource not admitted by required labels",
                ));
            }
        }
        Ok(())
    }

    pub fn reject_unlabelable(&self, kind: &str) -> Result<(), tonic::Status> {
        if self.enabled {
            Err(tonic::Status::failed_precondition(format!(
                "{kind} cannot be attached while resource admission is enabled: no trusted label resolver"
            )))
        } else {
            Ok(())
        }
    }
}

fn valid_label_value(value: &str) -> bool {
    value.is_empty()
        || (value.len() <= 63
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c)))
}

fn valid_label_key(key: &str) -> bool {
    let (prefix, name) = key
        .split_once('/')
        .map_or((None, key), |(prefix, name)| (Some(prefix), name));
    !name.is_empty()
        && valid_label_value(name)
        && prefix.is_none_or(|prefix| {
            !prefix.is_empty()
                && prefix.len() <= 253
                && prefix.split('.').all(|part| {
                    !part.is_empty()
                        && part.len() <= 63
                        && part
                            .bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                        && part
                            .as_bytes()
                            .first()
                            .is_some_and(u8::is_ascii_alphanumeric)
                        && part
                            .as_bytes()
                            .last()
                            .is_some_and(u8::is_ascii_alphanumeric)
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(workspace: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("openshell.ai/sandbox-attachable".into(), "true".into()),
            (
                "openshell.ai/sandbox-attachable-workspace".into(),
                workspace.into(),
            ),
        ])
    }

    #[test]
    fn rejects_unapproved_and_cross_workspace_resources() {
        let policy = ResourceAdmissionConfig::default();
        assert!(policy.admit("a", &labels("a")).is_ok());
        assert!(policy.admit("b", &labels("a")).is_err());
        assert!(policy.admit_shared(&labels("a")).is_ok());
        assert!(policy.admit("a", &BTreeMap::new()).is_err());
        assert!(policy.admit_shared(&BTreeMap::new()).is_err());
        assert!(policy.admit("", &labels("")).is_err());
    }

    #[test]
    fn replacement_map_and_explicit_empty_policy() {
        let policy: ResourceAdmissionConfig =
            serde_json::from_str(r#"{"required_labels":{"example.com/approved":"yes"}}"#).unwrap();
        assert_eq!(policy.required_labels.len(), 1);
        assert!(
            policy
                .admit(
                    "a",
                    &BTreeMap::from([("example.com/approved".into(), "yes".into())])
                )
                .is_ok()
        );
        let empty: ResourceAdmissionConfig =
            serde_json::from_str(r#"{"required_labels":{}}"#).unwrap();
        assert!(empty.validate().is_err());
        let workspace_only: ResourceAdmissionConfig = serde_json::from_str(
            r#"{"required_labels":{"openshell.ai/sandbox-attachable-workspace":"${workspace}"}}"#,
        )
        .unwrap();
        assert!(workspace_only.validate().is_err());
        assert!(
            ResourceAdmissionConfig {
                enabled: false,
                ..empty
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn rejects_driver_owned_label_keys() {
        assert!(ResourceAdmissionConfig::default().validate().is_ok());
        for key in RESERVED_LABEL_KEYS {
            let policy = ResourceAdmissionConfig {
                required_labels: BTreeMap::from([
                    ("example.com/approved".into(), "true".into()),
                    (key.into(), "operator-value".into()),
                ]),
                ..Default::default()
            };
            assert_eq!(
                policy.validate(),
                Err(format!(
                    "resource admission label key is reserved for driver-owned metadata: {key}"
                ))
            );
        }
    }

    #[test]
    fn rejects_invalid_labels_and_interpolation() {
        for value in [
            "${workspace.id}",
            "prefix-${workspace}",
            "$HOME",
            "*",
            "x/y",
        ] {
            let policy = ResourceAdmissionConfig {
                required_labels: BTreeMap::from([("approved".into(), value.into())]),
                ..Default::default()
            };
            assert!(policy.validate().is_err(), "{value}");
        }
        for key in ["", "/a", "bad_domain/a", "a/b/c", "-a", "a/"] {
            assert!(!valid_label_key(key), "{key}");
        }
    }

    #[test]
    fn json_gate_is_independent_of_label_opt_out() {
        let config = prost_types::Struct {
            fields: BTreeMap::from([("gpu_device_ids".into(), prost_types::Value::default())]),
        };
        for enabled in [false, true] {
            let policy = DriverAdmissionConfig {
                resource_admission: ResourceAdmissionConfig {
                    enabled,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(check_driver_config(policy.allow_driver_config, Some(&config)).is_err());
            assert!(check_driver_config(true, Some(&config)).is_ok());
            assert!(check_driver_config(false, Some(&prost_types::Struct::default())).is_ok());
            assert!(check_driver_config(false, None).is_ok());
        }
    }

    #[test]
    fn driver_acknowledgement_must_match_effective_policy() {
        let policy = DriverAdmissionConfig::default();
        assert!(
            policy
                .verify_acknowledgement(&policy.acknowledgement())
                .is_ok()
        );
        assert!(policy.verify_acknowledgement("").is_err());
        let unsafe_policy = DriverAdmissionConfig {
            resource_admission: ResourceAdmissionConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            policy
                .verify_acknowledgement(&unsafe_policy.acknowledgement())
                .is_err()
        );
        assert!(unsafe_policy.verify_acknowledgement("").is_ok());
    }
}
