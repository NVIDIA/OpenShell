// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-owned scheduling rules for a sandbox and its supervisor.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{
    Affinity, Pod, PodAffinityTerm, PodAntiAffinity, WeightedPodAffinityTerm,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;

use crate::config::KubernetesPodAntiAffinity;
use crate::isolation::{BOUNDARY_PAIR_LABEL, BOUNDARY_ROLE_LABEL};
use crate::sandbox_runtime::pair_label_value;

pub const BOOTSTRAP_SCHEDULING_GATE: &str = "openshell.ai/bootstrap";

#[derive(Clone, Copy, Debug)]
pub enum PairRole {
    Workload,
    Supervisor,
}

impl PairRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workload => "workload",
            Self::Supervisor => "supervisor",
        }
    }

    const fn peer(self) -> Self {
        match self {
            Self::Workload => Self::Supervisor,
            Self::Supervisor => Self::Workload,
        }
    }
}

fn pair_term(sandbox_id: &str, role: PairRole) -> PodAffinityTerm {
    PodAffinityTerm {
        topology_key: "kubernetes.io/hostname".to_string(),
        label_selector: Some(LabelSelector {
            match_labels: Some(BTreeMap::from([
                (
                    BOUNDARY_PAIR_LABEL.to_string(),
                    pair_label_value(sandbox_id),
                ),
                (
                    BOUNDARY_ROLE_LABEL.to_string(),
                    role.peer().as_str().to_string(),
                ),
            ])),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub fn has_required_pair_anti_affinity(
    affinity: Option<&Affinity>,
    sandbox_id: &str,
    role: PairRole,
) -> bool {
    affinity
        .and_then(|affinity| affinity.pod_anti_affinity.as_ref())
        .and_then(|anti| {
            anti.required_during_scheduling_ignored_during_execution
                .as_ref()
        })
        .is_some_and(|terms| terms.contains(&pair_term(sandbox_id, role)))
}

/// Capacity waits are not failed bootstrap, but only the recorded Pod may wait.
pub fn pair_pod_waiting_for_scheduling(
    pod: &Pod,
    expected_uid: &str,
    sandbox_id: &str,
    role: PairRole,
) -> bool {
    let Some(spec) = &pod.spec else {
        return false;
    };
    !expected_uid.is_empty()
        && pod.metadata.uid.as_deref() == Some(expected_uid)
        && pod.metadata.deletion_timestamp.is_none()
        && spec.node_name.as_ref().is_none_or(String::is_empty)
        && spec.scheduling_gates.as_ref().is_none_or(Vec::is_empty)
        && pod.metadata.labels.as_ref().is_some_and(|labels| {
            labels.get(BOUNDARY_PAIR_LABEL) == Some(&pair_label_value(sandbox_id))
                && labels.get(BOUNDARY_ROLE_LABEL).map(String::as_str) == Some(role.as_str())
        })
        && has_required_pair_anti_affinity(spec.affinity.as_ref(), sandbox_id, role)
        && pod.status.as_ref().is_some_and(|status| {
            status.phase.as_deref() == Some("Pending")
                && status.conditions.as_ref().is_some_and(|conditions| {
                    conditions.iter().any(|condition| {
                        condition.type_ == "PodScheduled"
                            && condition.status == "False"
                            && condition.reason.as_deref() == Some("Unschedulable")
                    })
                })
        })
}

/// Replace only the driver's exact pair term, preserving other scheduling rules.
pub fn reconcile_pair_anti_affinity(
    affinity: &mut Option<Affinity>,
    sandbox_id: &str,
    role: PairRole,
    mode: KubernetesPodAntiAffinity,
) {
    let term = pair_term(sandbox_id, role);
    if affinity.is_none() && mode == KubernetesPodAntiAffinity::Off {
        return;
    }
    let value = affinity.get_or_insert_default();
    let anti = value.pod_anti_affinity.get_or_insert_default();
    if let Some(required) = &mut anti.required_during_scheduling_ignored_during_execution {
        required.retain(|existing| existing != &term);
    }
    if let Some(preferred) = &mut anti.preferred_during_scheduling_ignored_during_execution {
        preferred.retain(|existing| existing.weight != 100 || existing.pod_affinity_term != term);
    }
    match mode {
        KubernetesPodAntiAffinity::Off => {}
        KubernetesPodAntiAffinity::Required => anti
            .required_during_scheduling_ignored_during_execution
            .get_or_insert_default()
            .push(term),
        KubernetesPodAntiAffinity::Preferred => anti
            .preferred_during_scheduling_ignored_during_execution
            .get_or_insert_default()
            .push(WeightedPodAffinityTerm {
                weight: 100,
                pod_affinity_term: term,
            }),
    }
    if anti
        .required_during_scheduling_ignored_during_execution
        .as_ref()
        .is_some_and(Vec::is_empty)
    {
        anti.required_during_scheduling_ignored_during_execution = None;
    }
    if anti
        .preferred_during_scheduling_ignored_during_execution
        .as_ref()
        .is_some_and(Vec::is_empty)
    {
        anti.preferred_during_scheduling_ignored_during_execution = None;
    }
    if *anti == PodAntiAffinity::default() {
        value.pod_anti_affinity = None;
    }
    if *value == Affinity::default() {
        *affinity = None;
    }
}

/// JSON merge patches must explicitly null removed terms rather than omit them.
pub fn workload_affinity_patch(
    stored: &serde_json::Value,
    sandbox_id: &str,
    mode: KubernetesPodAntiAffinity,
) -> Result<serde_json::Value, String> {
    let mut affinity: Option<Affinity> = serde_json::from_value(stored.clone())
        .map_err(|error| format!("invalid stored workload affinity: {error}"))?;
    reconcile_pair_anti_affinity(&mut affinity, sandbox_id, PairRole::Workload, mode);
    let Some(affinity) = affinity else {
        return Ok(serde_json::Value::Null);
    };
    let anti = affinity.pod_anti_affinity.map(|anti| serde_json::json!({
        "requiredDuringSchedulingIgnoredDuringExecution": anti.required_during_scheduling_ignored_during_execution,
        "preferredDuringSchedulingIgnoredDuringExecution": anti.preferred_during_scheduling_ignored_during_execution,
    }));
    Ok(serde_json::json!({
        "nodeAffinity": affinity.node_affinity,
        "podAffinity": affinity.pod_affinity,
        "podAntiAffinity": anti,
    }))
}

/// Required placement must survive admission and reach the standard scheduler.
pub fn validate_pair_scheduling(
    pod: &Pod,
    sandbox_id: &str,
    role: PairRole,
    mode: KubernetesPodAntiAffinity,
) -> Result<(), String> {
    if mode != KubernetesPodAntiAffinity::Required {
        return Ok(());
    }
    let fail = |reason: &str| {
        format!(
            "admitted {} Pod does not preserve required pair anti-affinity: {reason}",
            role.as_str()
        )
    };
    let labels = pod
        .metadata
        .labels
        .as_ref()
        .ok_or_else(|| fail("missing labels"))?;
    if labels.get(BOUNDARY_PAIR_LABEL) != Some(&pair_label_value(sandbox_id))
        || labels.get(BOUNDARY_ROLE_LABEL).map(String::as_str) != Some(role.as_str())
    {
        return Err(fail("pair or role label changed"));
    }
    let spec = pod.spec.as_ref().ok_or_else(|| fail("missing spec"))?;
    if spec.node_name.as_ref().is_some_and(|node| !node.is_empty()) {
        return Err(fail("nodeName bypasses scheduling"));
    }
    if spec
        .scheduler_name
        .as_deref()
        .is_some_and(|name| name != "default-scheduler")
    {
        return Err(fail("schedulerName must be default-scheduler"));
    }
    if !spec
        .scheduling_gates
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|gate| gate.name == BOOTSTRAP_SCHEDULING_GATE)
    {
        return Err(fail("bootstrap scheduling gate missing"));
    }
    let required = spec
        .affinity
        .as_ref()
        .and_then(|affinity| affinity.pod_anti_affinity.as_ref())
        .and_then(|anti| {
            anti.required_during_scheduling_ignored_during_execution
                .as_ref()
        });
    if !required.is_some_and(|terms| terms.contains(&pair_term(sandbox_id, role))) {
        return Err(fail("required pair term missing or changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KubernetesPodAntiAffinity;
    use crate::sandbox_runtime::pair_label_value;
    use k8s_openapi::api::core::v1::{Affinity, Pod};
    use serde_json::json;

    fn affinity(role: PairRole, mode: KubernetesPodAntiAffinity) -> Option<Affinity> {
        let mut value = None;
        reconcile_pair_anti_affinity(&mut value, "sandbox-1", role, mode);
        value
    }

    fn pod(role: PairRole, mode: KubernetesPodAntiAffinity) -> Pod {
        serde_json::from_value(json!({
            "metadata": {"labels": {
                "openshell.ai/boundary-pair": pair_label_value("sandbox-1"),
                "openshell.ai/boundary-role": role.as_str(),
            }},
            "spec": {
                "containers": [],
                "affinity": affinity(role, mode),
                "schedulingGates": [{"name": "openshell.ai/bootstrap"}],
            },
        }))
        .unwrap()
    }

    #[test]
    fn pair_anti_affinity_config_is_strict_and_defaults_off() {
        use crate::config::KubernetesSandboxRuntimeConfig;
        let default: KubernetesSandboxRuntimeConfig = serde_json::from_value(json!({})).unwrap();
        assert_eq!(default.pod_anti_affinity, KubernetesPodAntiAffinity::Off);
        for mode in ["off", "preferred", "required"] {
            let config: KubernetesSandboxRuntimeConfig =
                serde_json::from_value(json!({"pod_anti_affinity": mode})).unwrap();
            assert_eq!(
                serde_json::to_value(config).unwrap()["pod_anti_affinity"],
                mode
            );
        }
        assert!(
            serde_json::from_value::<KubernetesSandboxRuntimeConfig>(
                json!({"pod_anti_affinity": "require"})
            )
            .is_err()
        );
    }

    #[test]
    fn pair_anti_affinity_is_symmetric_and_scoped_to_one_pair() {
        for (role, peer) in [
            (PairRole::Workload, "supervisor"),
            (PairRole::Supervisor, "workload"),
        ] {
            let value =
                serde_json::to_value(affinity(role, KubernetesPodAntiAffinity::Required)).unwrap();
            let terms = value["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
                .as_array()
                .unwrap();
            assert_eq!(terms.len(), 1);
            assert_eq!(
                terms[0],
                json!({
                    "topologyKey": "kubernetes.io/hostname",
                    "labelSelector": {"matchLabels": {
                        "openshell.ai/boundary-pair": pair_label_value("sandbox-1"),
                        "openshell.ai/boundary-role": peer,
                    }},
                })
            );
        }
    }

    #[test]
    fn pair_anti_affinity_preferred_has_weight_100_and_off_omits_affinity() {
        let value = serde_json::to_value(affinity(
            PairRole::Workload,
            KubernetesPodAntiAffinity::Preferred,
        ))
        .unwrap();
        assert_eq!(
            value["podAntiAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"][0]["weight"],
            100
        );
        assert!(
            value["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"].is_null()
        );
        assert!(affinity(PairRole::Workload, KubernetesPodAntiAffinity::Off).is_none());
    }

    #[test]
    fn pair_anti_affinity_restart_replaces_owned_terms_and_preserves_other_rules() {
        let original = json!({
            "nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {
                "nodeSelectorTerms": [{"matchExpressions": [{"key": "pool", "operator": "In", "values": ["agents"]}]}]
            }},
            "podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [{
                "topologyKey": "kubernetes.io/hostname",
                "labelSelector": {"matchLabels": {"app": "database"}}
            }]},
        });
        let mut value: Option<Affinity> = serde_json::from_value(original.clone()).unwrap();
        for mode in [
            KubernetesPodAntiAffinity::Required,
            KubernetesPodAntiAffinity::Preferred,
            KubernetesPodAntiAffinity::Required,
            KubernetesPodAntiAffinity::Off,
        ] {
            reconcile_pair_anti_affinity(&mut value, "sandbox-1", PairRole::Workload, mode);
            let once = value.clone();
            reconcile_pair_anti_affinity(&mut value, "sandbox-1", PairRole::Workload, mode);
            assert_eq!(value, once, "reconciliation must be idempotent");
            assert_eq!(
                serde_json::to_value(&value).unwrap()["nodeAffinity"],
                original["nodeAffinity"]
            );
        }
        assert_eq!(serde_json::to_value(value).unwrap(), original);
        let mut value = affinity(PairRole::Workload, KubernetesPodAntiAffinity::Required);
        reconcile_pair_anti_affinity(
            &mut value,
            "sandbox-1",
            PairRole::Workload,
            KubernetesPodAntiAffinity::Off,
        );
        assert!(value.is_none());
    }

    #[test]
    fn pair_anti_affinity_restart_merge_patch_explicitly_clears_obsolete_terms() {
        let stored = serde_json::to_value(affinity(
            PairRole::Workload,
            KubernetesPodAntiAffinity::Required,
        ))
        .unwrap();
        let patch =
            workload_affinity_patch(&stored, "sandbox-1", KubernetesPodAntiAffinity::Preferred)
                .unwrap();
        assert!(
            patch["podAntiAffinity"]
                .as_object()
                .unwrap()
                .contains_key("requiredDuringSchedulingIgnoredDuringExecution")
        );
        assert!(
            patch["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"].is_null()
        );
        assert_eq!(
            patch["podAntiAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"][0]["weight"],
            100
        );
        assert!(
            workload_affinity_patch(&stored, "sandbox-1", KubernetesPodAntiAffinity::Off)
                .unwrap()
                .is_null()
        );
    }

    #[test]
    fn pair_anti_affinity_preserves_other_preference_weights() {
        let mut value = affinity(PairRole::Workload, KubernetesPodAntiAffinity::Preferred);
        value
            .as_mut()
            .unwrap()
            .pod_anti_affinity
            .as_mut()
            .unwrap()
            .preferred_during_scheduling_ignored_during_execution
            .as_mut()
            .unwrap()[0]
            .weight = 50;
        let original = value.clone();
        reconcile_pair_anti_affinity(
            &mut value,
            "sandbox-1",
            PairRole::Workload,
            KubernetesPodAntiAffinity::Off,
        );
        assert_eq!(value, original);
    }

    #[test]
    fn pair_anti_affinity_waits_only_for_current_unscheduled_generation() {
        for role in [PairRole::Workload, PairRole::Supervisor] {
            let mut pending = pod(role, KubernetesPodAntiAffinity::Required);
            pending.metadata.uid = Some("current".into());
            pending.spec.as_mut().unwrap().scheduling_gates = None;
            pending.status = Some(
                serde_json::from_value(json!({"phase": "Pending", "conditions": [
                    {"type": "PodScheduled", "status": "False", "reason": "Unschedulable"}
                ]}))
                .unwrap(),
            );
            assert!(pair_pod_waiting_for_scheduling(
                &pending,
                "current",
                "sandbox-1",
                role
            ));
            assert!(!pair_pod_waiting_for_scheduling(
                &pending,
                "old",
                "sandbox-1",
                role
            ));
            assert!(!pair_pod_waiting_for_scheduling(
                &pending, "current", "other", role
            ));
            let mut bound = pending.clone();
            bound.spec.as_mut().unwrap().node_name = Some("node-1".into());
            assert!(!pair_pod_waiting_for_scheduling(
                &bound,
                "current",
                "sandbox-1",
                role
            ));
            pending.spec.as_mut().unwrap().affinity =
                affinity(role, KubernetesPodAntiAffinity::Preferred);
            assert!(!pair_pod_waiting_for_scheduling(
                &pending,
                "current",
                "sandbox-1",
                role
            ));
        }
    }

    #[test]
    fn pair_anti_affinity_admission_requires_rule_labels_and_scheduler() {
        for role in [PairRole::Workload, PairRole::Supervisor] {
            let good = pod(role, KubernetesPodAntiAffinity::Required);
            assert!(
                validate_pair_scheduling(
                    &good,
                    "sandbox-1",
                    role,
                    KubernetesPodAntiAffinity::Required
                )
                .is_ok()
            );
            for mutation in [
                "missing",
                "preferred",
                "node",
                "scheduler",
                "pair",
                "role",
                "gate",
            ] {
                let mut changed = good.clone();
                match mutation {
                    "missing" => changed.spec.as_mut().unwrap().affinity = None,
                    "preferred" => {
                        changed.spec.as_mut().unwrap().affinity =
                            affinity(role, KubernetesPodAntiAffinity::Preferred);
                    }
                    "node" => changed.spec.as_mut().unwrap().node_name = Some("node-1".into()),
                    "scheduler" => {
                        changed.spec.as_mut().unwrap().scheduler_name = Some("custom".into());
                    }
                    "pair" => {
                        changed
                            .metadata
                            .labels
                            .as_mut()
                            .unwrap()
                            .insert("openshell.ai/boundary-pair".into(), "other".into());
                    }
                    "role" => {
                        changed
                            .metadata
                            .labels
                            .as_mut()
                            .unwrap()
                            .insert("openshell.ai/boundary-role".into(), "other".into());
                    }
                    "gate" => changed.spec.as_mut().unwrap().scheduling_gates = None,
                    _ => unreachable!(),
                }
                assert!(
                    validate_pair_scheduling(
                        &changed,
                        "sandbox-1",
                        role,
                        KubernetesPodAntiAffinity::Required
                    )
                    .is_err(),
                    "accepted {mutation}"
                );
            }
        }
    }
}
