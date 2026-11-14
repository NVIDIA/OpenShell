// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operator assignments and durable Kubernetes workload identities.

use std::collections::BTreeMap;

use kube::core::DynamicObject;
use openshell_core::proto::compute::v1::{ResolvedWorkloadIdentity, WorkloadIdentityRequest};
use serde::{Deserialize, Serialize};

use crate::config::{
    ANNOTATION_SCC_SUPPLEMENTAL_GROUPS, ANNOTATION_SCC_UID_RANGE, KubernetesComputeConfig,
};

pub const NAMESPACE_UID: &str = "openshell.ai/sandbox-uid";
pub const NAMESPACE_GID: &str = "openshell.ai/sandbox-gid";
pub const RESOLVED_IDENTITY: &str = "openshell.ai/resolved-workload-identity";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum IdentitySource {
    Namespace,
    Driver,
    Openshift,
    Default,
    Legacy,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn annotations(uid: &str, gid: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            (NAMESPACE_UID.into(), uid.into()),
            (NAMESPACE_GID.into(), gid.into()),
        ])
    }

    #[test]
    fn namespace_pair_overrides_driver_and_scc_without_mixing_sources() {
        let config = KubernetesComputeConfig {
            sandbox_uid: Some(5000),
            sandbox_gid: Some(6000),
            ..Default::default()
        };
        let mut values = annotations("1500", "1600");
        values.insert(ANNOTATION_SCC_UID_RANGE.into(), "1000000000/10000".into());
        values.insert(
            ANNOTATION_SCC_SUPPLEMENTAL_GROUPS.into(),
            "1000000001/10000".into(),
        );
        let identity = WorkloadIdentity::resolve(&config, &values).unwrap();
        assert_eq!(
            (identity.uid, identity.gid, identity.source),
            (1500, 1600, IdentitySource::Namespace)
        );
    }

    #[test]
    fn namespace_pair_rejects_incomplete_and_unsupported_values_even_with_defaults() {
        let config = KubernetesComputeConfig {
            sandbox_uid: Some(5000),
            ..Default::default()
        };
        for values in [
            BTreeMap::from([(NAMESPACE_UID.into(), "1500".into())]),
            BTreeMap::from([(NAMESPACE_GID.into(), "1600".into())]),
        ] {
            assert!(
                WorkloadIdentity::resolve(&config, &values)
                    .unwrap_err()
                    .contains("requires both")
            );
        }
        for value in [
            "",
            "0",
            "-1",
            "+1",
            " 1500",
            "1500 ",
            "1.5",
            "1e3",
            "4294967295",
            "4294967296",
            "abc",
        ] {
            for values in [annotations(value, "1600"), annotations("1500", value)] {
                assert!(
                    WorkloadIdentity::resolve(&config, &values).is_err(),
                    "accepted {values:?}"
                );
            }
        }
        let identity = WorkloadIdentity::resolve(&config, &annotations("1", "4294967294")).unwrap();
        assert_eq!((identity.uid, identity.gid), (1, 4_294_967_294));
    }

    #[test]
    fn optional_mode_preserves_driver_scc_and_default_precedence() {
        let values = BTreeMap::from([
            (ANNOTATION_SCC_UID_RANGE.into(), "1000000000/10000".into()),
            (
                ANNOTATION_SCC_SUPPLEMENTAL_GROUPS.into(),
                "1000000001/10000".into(),
            ),
        ]);
        for (uid, gid, expected) in [
            (None, None, (1_000_000_000, 1_000_000_001)),
            (Some(1500), None, (1500, 1500)),
            (Some(1500), Some(1600), (1500, 1600)),
            (None, Some(1600), (1_000_000_000, 1600)),
        ] {
            let config = KubernetesComputeConfig {
                sandbox_uid: uid,
                sandbox_gid: gid,
                ..Default::default()
            };
            let identity = WorkloadIdentity::resolve(&config, &values).unwrap();
            assert_eq!((identity.uid, identity.gid), expected);
        }
        let identity =
            WorkloadIdentity::resolve(&KubernetesComputeConfig::default(), &BTreeMap::new())
                .unwrap();
        assert_eq!(
            (identity.uid, identity.gid, identity.source),
            (10001, 10001, IdentitySource::Default)
        );
    }

    #[test]
    fn required_mode_needs_explicit_pair_even_with_driver_or_scc_configuration() {
        let config = KubernetesComputeConfig {
            require_namespace_identity: true,
            sandbox_uid: Some(1500),
            sandbox_gid: Some(1600),
            ..Default::default()
        };
        let scc = BTreeMap::from([(ANNOTATION_SCC_UID_RANGE.into(), "1000000000/10000".into())]);
        for values in [BTreeMap::new(), scc] {
            assert!(WorkloadIdentity::resolve(&config, &values).is_err());
        }
        assert!(WorkloadIdentity::resolve(&config, &annotations("1500", "1600")).is_ok());
    }

    #[test]
    fn selectors_independently_accept_defaults_and_matching_ids_but_reject_conflicts() {
        let identity = WorkloadIdentity::resolve(
            &KubernetesComputeConfig::default(),
            &annotations("1500", "1600"),
        )
        .unwrap();
        identity.validate_request(None).unwrap();
        for user in ["", "sandbox", "1500", "+1500", "01500"] {
            for group in ["", "sandbox", "1600", "+1600", "01600"] {
                identity
                    .validate_request(Some(&WorkloadIdentityRequest {
                        user: user.into(),
                        group: group.into(),
                    }))
                    .unwrap();
            }
        }
        for (user, group, field) in [
            ("1501", "", "run_as_user"),
            ("sandbox", "1601", "run_as_group"),
        ] {
            let error = identity
                .validate_request(Some(&WorkloadIdentityRequest {
                    user: user.into(),
                    group: group.into(),
                }))
                .unwrap_err();
            assert!(
                error.contains(field) && error.contains("1500:1600"),
                "{error}"
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentity {
    version: u32,
    pub uid: u32,
    pub gid: u32,
    source: IdentitySource,
}

fn valid_id(value: u32) -> bool {
    (openshell_policy::MIN_SANDBOX_UID..=openshell_policy::MAX_SANDBOX_UID).contains(&value)
}

fn parse_id(key: &str, value: &str) -> Result<u32, String> {
    if !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && let Ok(id) = value.parse::<u32>()
        && valid_id(id)
    {
        return Ok(id);
    }
    Err(format!(
        "{key} must be a decimal integer between 1 and 4294967294"
    ))
}

impl WorkloadIdentity {
    pub(crate) fn resolve(
        config: &KubernetesComputeConfig,
        annotations: &BTreeMap<String, String>,
    ) -> Result<Self, String> {
        let uid = annotations.get(NAMESPACE_UID);
        let gid = annotations.get(NAMESPACE_GID);
        match (uid, gid) {
            (Some(uid), Some(gid)) => {
                return Ok(Self::new(
                    parse_id(NAMESPACE_UID, uid)?,
                    parse_id(NAMESPACE_GID, gid)?,
                    IdentitySource::Namespace,
                ));
            }
            (None, None) if !config.require_namespace_identity => {}
            _ => {
                return Err(format!(
                    "namespace identity requires both {NAMESPACE_UID} and {NAMESPACE_GID}; ask the namespace operator to configure them"
                ));
            }
        }
        let uid = config.resolve_sandbox_uid(Some(annotations));
        // Retain the existing driver override semantics, including the case
        // where only sandbox_gid is configured alongside SCC discovery.
        let gid = if config.sandbox_uid.is_some() || config.sandbox_gid.is_some() {
            config.resolve_sandbox_gid(uid, None)
        } else {
            annotations
                .get(ANNOTATION_SCC_SUPPLEMENTAL_GROUPS)
                .and_then(|range| {
                    KubernetesComputeConfig::from_open_shift_supplemental_groups(range)
                })
                .unwrap_or(uid)
        };
        let source = if config.sandbox_uid.is_some() || config.sandbox_gid.is_some() {
            IdentitySource::Driver
        } else if annotations
            .get(ANNOTATION_SCC_UID_RANGE)
            .and_then(|range| KubernetesComputeConfig::from_open_shift_uid_range(range))
            .is_some()
            || annotations
                .get(ANNOTATION_SCC_SUPPLEMENTAL_GROUPS)
                .and_then(|range| {
                    KubernetesComputeConfig::from_open_shift_supplemental_groups(range)
                })
                .is_some()
        {
            IdentitySource::Openshift
        } else {
            IdentitySource::Default
        };
        Ok(Self::new(uid, gid, source))
    }

    fn new(uid: u32, gid: u32, source: IdentitySource) -> Self {
        Self {
            version: 1,
            uid,
            gid,
            source,
        }
    }

    pub(crate) fn validate_request(
        &self,
        request: Option<&WorkloadIdentityRequest>,
    ) -> Result<(), String> {
        if let Some(request) = request {
            for (field, selector, expected) in [
                ("run_as_user", request.user.as_str(), self.uid),
                ("run_as_group", request.group.as_str(), self.gid),
            ] {
                if !selector.is_empty()
                    && selector != "sandbox"
                    && selector.parse::<u32>() != Ok(expected)
                {
                    return Err(format!(
                        "{field} '{selector}' conflicts with the assigned Kubernetes workload identity {}:{}; omit the selector, use 'sandbox', or select the assigned value",
                        self.uid, self.gid
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|error| error.to_string())
    }

    /// Validate the durable record against the template that will be launched.
    /// Legacy objects acquire the pair from their stored template, never from
    /// the current namespace or driver configuration.
    pub(crate) fn from_object(object: &DynamicObject) -> Result<Self, String> {
        let stored = object
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(RESOLVED_IDENTITY));
        let identity = if let Some(record) = stored {
            let identity: Self = serde_json::from_str(record)
                .map_err(|error| format!("invalid persisted workload identity: {error}"))?;
            if identity.version != 1 || !valid_id(identity.uid) || !valid_id(identity.gid) {
                return Err("invalid persisted workload identity version or UID/GID".into());
            }
            identity
        } else {
            let security = &object.data["spec"]["podTemplate"]["spec"]["securityContext"];
            let read = |field: &str| {
                security[field].as_u64()
                    .and_then(|value| u32::try_from(value).ok()).filter(|value| valid_id(*value))
                    .ok_or_else(|| format!("legacy sandbox has no valid persisted {field}; cannot recover its workload identity"))
            };
            Self::new(
                read("runAsUser")?,
                read("runAsGroup")?,
                IdentitySource::Legacy,
            )
        };
        let spec = &object.data["spec"]["podTemplate"]["spec"];
        for (field, expected) in [
            ("runAsUser", identity.uid),
            ("runAsGroup", identity.gid),
            ("fsGroup", identity.gid),
        ] {
            if spec["securityContext"][field].as_u64() != Some(u64::from(expected)) {
                return Err(format!(
                    "persisted workload identity {}:{} conflicts with pod {field}",
                    identity.uid, identity.gid
                ));
            }
        }
        // All workload-side helpers use the same pair, including storage seed.
        for (collection, name) in [
            ("containers", "agent"),
            ("initContainers", "openshell-sandbox-bootstrap"),
            ("initContainers", "workspace-init"),
        ] {
            if let Some(container) = spec[collection].as_array().and_then(|containers| {
                containers
                    .iter()
                    .find(|container| container["name"] == name)
            }) {
                for (field, expected) in [("runAsUser", identity.uid), ("runAsGroup", identity.gid)]
                {
                    if container["securityContext"][field].as_u64() != Some(u64::from(expected)) {
                        return Err(format!(
                            "persisted workload identity conflicts with {name} {field}"
                        ));
                    }
                }
            } else if collection == "containers" {
                return Err("sandbox template is missing its agent container".into());
            }
        }
        Ok(identity)
    }

    pub(crate) fn to_proto(&self, resource_uid: &str) -> ResolvedWorkloadIdentity {
        ResolvedWorkloadIdentity {
            uid: self.uid,
            gid: self.gid,
            supplementary_gids: Vec::new(),
            source: match self.source {
                IdentitySource::Namespace => "kubernetes-namespace",
                IdentitySource::Driver => "kubernetes-config",
                IdentitySource::Openshift => "kubernetes-openshift",
                IdentitySource::Default => "kubernetes-default",
                IdentitySource::Legacy => "kubernetes-legacy",
            }
            .into(),
            resource_digest: format!("sandbox:{resource_uid}"),
        }
    }
}
