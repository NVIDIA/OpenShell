// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operator-owned placement of workload and supervisor pods, across namespaces.

use std::collections::BTreeMap;
use std::str::FromStr;

use k8s_openapi::api::core::v1::{Pod, Toleration};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const ROLE_LABEL: &str = "openshell.ai/runtime-role";
const PLACEMENT_ANNOTATION: &str = "openshell.ai/workload-placement";
const BOOTSTRAP_GATE: &str = "openshell.ai/bootstrap";

/// Strength of the scheduling rule between workloads and supervisors.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesPodAntiAffinity {
    Off,
    #[default]
    Preferred,
    Required,
}

impl FromStr for KubernetesPodAntiAffinity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "off" => Ok(Self::Off),
            "preferred" => Ok(Self::Preferred),
            "required" => Ok(Self::Required),
            _ => Err("pod_anti_affinity must be off, preferred, or required".into()),
        }
    }
}

/// Optional operator restrictions, independent of caller driver-config opt-in.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesWorkloadPlacement {
    pub node_selector: BTreeMap<String, String>,
    pub tolerations: Vec<Toleration>,
}

// Remember only the operator's changes, so changing/removing operator placement
// on restart restores caller settings and preserves unrelated admission rules.
#[derive(Default, Serialize, Deserialize)]
struct AppliedPlacement {
    node_selector: BTreeMap<String, String>,
    original_selector: BTreeMap<String, String>,
    added_tolerations: Vec<Value>,
}

fn term(peer: &str, namespaces: &LabelSelector) -> Value {
    json!({
        "topologyKey": "kubernetes.io/hostname",
        "namespaceSelector": namespaces,
        "labelSelector": {"matchLabels": {ROLE_LABEL: peer}},
    })
}

fn owned_term(value: &Value, peer: &str) -> bool {
    value["topologyKey"] == "kubernetes.io/hostname"
        && value["labelSelector"] == json!({"matchLabels": {ROLE_LABEL: peer}})
        && value.as_object().is_some_and(|map| {
            map.keys().all(|key| {
                matches!(
                    key.as_str(),
                    "topologyKey" | "labelSelector" | "namespaceSelector"
                )
            })
        })
}

/// Reconcile only the reserved role rule. Other affinity is left intact.
pub fn configure_affinity(
    spec: &mut Value,
    mode: KubernetesPodAntiAffinity,
    namespaces: &LabelSelector,
    peer: &str,
) {
    if spec["affinity"].is_null() && mode == KubernetesPodAntiAffinity::Off {
        return;
    }
    if spec["affinity"].is_null() {
        spec["affinity"] = json!({});
    }
    let affinity = &mut spec["affinity"];
    if affinity["podAntiAffinity"].is_null() {
        affinity["podAntiAffinity"] = json!({});
    }
    let anti = &mut affinity["podAntiAffinity"];
    let required = "requiredDuringSchedulingIgnoredDuringExecution";
    let preferred = "preferredDuringSchedulingIgnoredDuringExecution";
    if let Some(terms) = anti.get_mut(required).and_then(Value::as_array_mut) {
        terms.retain(|value| !owned_term(value, peer));
    }
    if let Some(terms) = anti.get_mut(preferred).and_then(Value::as_array_mut) {
        terms
            .retain(|value| value["weight"] != 100 || !owned_term(&value["podAffinityTerm"], peer));
    }
    let generated = term(peer, namespaces);
    let (key, value) = match mode {
        KubernetesPodAntiAffinity::Off => (required, None),
        KubernetesPodAntiAffinity::Required => (required, Some(generated)),
        KubernetesPodAntiAffinity::Preferred => (
            preferred,
            Some(json!({"weight": 100, "podAffinityTerm": generated})),
        ),
    };
    if let Some(value) = value {
        if anti[key].is_null() {
            anti[key] = json!([]);
        }
        anti[key]
            .as_array_mut()
            .expect("affinity terms are arrays")
            .push(value);
    }
    for key in [required, preferred] {
        if anti[key].as_array().is_some_and(Vec::is_empty) {
            anti.as_object_mut().unwrap().remove(key);
        }
    }
    if anti.as_object().is_some_and(serde_json::Map::is_empty) {
        affinity.as_object_mut().unwrap().remove("podAntiAffinity");
    }
    if affinity.as_object().is_some_and(serde_json::Map::is_empty) {
        spec.as_object_mut().unwrap().remove("affinity");
    }
}

pub fn configure_workload(
    template: &mut Value,
    config: &crate::KubernetesSandboxRuntimeConfig,
) -> Result<(), String> {
    let previous: AppliedPlacement = template["metadata"]["annotations"][PLACEMENT_ANNOTATION]
        .as_str()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|error| format!("invalid stored workload placement: {error}"))?
        .unwrap_or_default();
    let spec = &mut template["spec"];
    if !spec["affinity"].is_null() {
        serde_json::from_value::<k8s_openapi::api::core::v1::Affinity>(spec["affinity"].clone())
            .map_err(|error| format!("invalid stored affinity: {error}"))?;
    }
    let mut selector: BTreeMap<String, String> =
        serde_json::from_value(spec["nodeSelector"].clone())
            .or_else(|_| {
                if spec["nodeSelector"].is_null() {
                    Ok(BTreeMap::new())
                } else {
                    Err("invalid nodeSelector")
                }
            })
            .map_err(str::to_string)?;
    for (key, value) in &previous.node_selector {
        if selector.get(key) == Some(value) {
            selector.remove(key);
            if let Some(original) = previous.original_selector.get(key) {
                selector.insert(key.clone(), original.clone());
            }
        }
    }
    let mut applied = AppliedPlacement::default();
    for (key, value) in &config.workload_placement.node_selector {
        if let Some(existing) = selector.get(key) {
            if existing != value {
                return Err(format!(
                    "workload node selector '{key}' conflicts with operator workload_placement"
                ));
            }
            applied
                .original_selector
                .insert(key.clone(), existing.clone());
        }
        selector.insert(key.clone(), value.clone());
    }
    applied
        .node_selector
        .clone_from(&config.workload_placement.node_selector);
    if selector.is_empty() {
        spec.as_object_mut().unwrap().remove("nodeSelector");
    } else {
        spec["nodeSelector"] = json!(selector);
    }
    let mut tolerations = spec["tolerations"].as_array().cloned().unwrap_or_default();
    for previous in previous.added_tolerations {
        if let Some(index) = tolerations.iter().position(|value| *value == previous) {
            tolerations.remove(index);
        }
    }
    for toleration in &config.workload_placement.tolerations {
        let value = json!(toleration);
        if !tolerations.contains(&value) {
            tolerations.push(value.clone());
            applied.added_tolerations.push(value);
        }
    }
    if tolerations.is_empty() {
        spec.as_object_mut().unwrap().remove("tolerations");
    } else {
        spec["tolerations"] = json!(tolerations);
    }
    configure_affinity(
        spec,
        config.pod_anti_affinity,
        &config.pod_anti_affinity_namespace_selector,
        "supervisor",
    );
    if template["metadata"].is_null() {
        template["metadata"] = json!({});
    }
    if template["metadata"]["labels"].is_null() {
        template["metadata"]["labels"] = json!({});
    }
    template["metadata"]["labels"][ROLE_LABEL] = "workload".into();
    if template["metadata"]["annotations"].is_null() {
        template["metadata"]["annotations"] = json!({});
    }
    template["metadata"]["annotations"][PLACEMENT_ANNOTATION] = serde_json::to_string(&applied)
        .map_err(|error| error.to_string())?
        .into();
    Ok(())
}

/// A merge patch must explicitly null removed fields (including selector keys).
pub fn merge_patch(old: &Value, new: &Value) -> Value {
    if let (Some(old), Some(new)) = (old.as_object(), new.as_object()) {
        let mut patch = serde_json::Map::new();
        for key in old.keys().chain(new.keys()) {
            if old.get(key) != new.get(key) {
                patch.insert(
                    key.clone(),
                    merge_patch(
                        old.get(key).unwrap_or(&Value::Null),
                        new.get(key).unwrap_or(&Value::Null),
                    ),
                );
            }
        }
        Value::Object(patch)
    } else {
        new.clone()
    }
}

pub fn validate_workload(
    pod: &Pod,
    config: &crate::KubernetesSandboxRuntimeConfig,
) -> Result<(), String> {
    validate_role(pod, config, "workload", "supervisor")
}

pub fn validate_supervisor(
    pod: &Pod,
    config: &crate::KubernetesSandboxRuntimeConfig,
) -> Result<(), String> {
    let config = crate::KubernetesSandboxRuntimeConfig {
        workload_placement: KubernetesWorkloadPlacement::default(),
        ..config.clone()
    };
    validate_role(pod, &config, "supervisor", "workload")
}

fn validate_role(
    pod: &Pod,
    config: &crate::KubernetesSandboxRuntimeConfig,
    role: &str,
    peer: &str,
) -> Result<(), String> {
    let fail = |reason| format!("admitted {role} does not preserve operator scheduling: {reason}");
    if pod
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(ROLE_LABEL))
        .map(String::as_str)
        != Some(role)
    {
        return Err(fail("runtime role label changed"));
    }
    let spec = pod.spec.as_ref().ok_or_else(|| fail("missing spec"))?;
    for (key, value) in &config.workload_placement.node_selector {
        if spec
            .node_selector
            .as_ref()
            .and_then(|selector| selector.get(key))
            != Some(value)
        {
            return Err(fail("node selector changed"));
        }
    }
    for value in &config.workload_placement.tolerations {
        if !spec
            .tolerations
            .as_ref()
            .is_some_and(|values| values.contains(value))
        {
            return Err(fail("operator toleration removed"));
        }
    }
    if config.pod_anti_affinity != KubernetesPodAntiAffinity::Required
        && config.workload_placement.node_selector.is_empty()
    {
        return Ok(());
    }
    if spec.node_name.as_ref().is_some_and(|name| !name.is_empty())
        || spec
            .scheduler_name
            .as_deref()
            .is_some_and(|name| name != "default-scheduler")
        || !spec
            .scheduling_gates
            .as_ref()
            .is_some_and(|gates| gates.iter().any(|gate| gate.name == BOOTSTRAP_GATE))
    {
        return Err(fail(
            "default scheduler and bootstrap scheduling gate required; nodeName must be empty",
        ));
    }
    if config.pod_anti_affinity == KubernetesPodAntiAffinity::Required {
        let expected = term(peer, &config.pod_anti_affinity_namespace_selector);
        let value = json!(spec);
        if !value["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
            .as_array()
            .is_some_and(|terms| terms.contains(&expected))
        {
            return Err(fail("required anti-affinity changed"));
        }
    }
    Ok(())
}

/// Scheduling waits do not consume startup grace; once bound, startup gets a
/// bounded grace from `PodScheduled`, including after a gateway outage.
pub fn scheduling_wait(pod: &Pod, now_ms: i64, grace_ms: i64) -> bool {
    if pod.metadata.deletion_timestamp.is_some() {
        return false;
    }
    let Some(status) = &pod.status else {
        return false;
    };
    if matches!(status.phase.as_deref(), Some("Failed" | "Succeeded")) {
        return false;
    }
    let Some(spec) = &pod.spec else {
        return false;
    };
    status.conditions.as_ref().is_some_and(|conditions| {
        conditions.iter().any(|condition| {
            if condition.type_ != "PodScheduled" {
                return false;
            }
            if condition.status == "False" && condition.reason.as_deref() == Some("Unschedulable") {
                return spec.node_name.as_ref().is_none_or(String::is_empty)
                    && spec.scheduling_gates.as_ref().is_none_or(Vec::is_empty);
            }
            condition.status == "True"
                && condition
                    .last_transition_time
                    .as_ref()
                    .is_some_and(|time| now_ms.saturating_sub(time.0.timestamp_millis()) < grace_ms)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KubernetesSandboxRuntimeConfig as Config;

    fn template() -> Value {
        json!({"metadata": {}, "spec": {"containers": []}})
    }

    fn merge(target: &mut Value, patch: &Value) {
        if let Some(fields) = patch.as_object() {
            if !target.is_object() {
                *target = json!({});
            }
            for (key, value) in fields {
                if value.is_null() {
                    target.as_object_mut().unwrap().remove(key);
                } else {
                    merge(&mut target[key], value);
                }
            }
        } else {
            *target = patch.clone();
        }
    }

    #[test]
    fn defaults_prefer_cross_namespace_separation_without_node_placement() {
        let config: Config = serde_json::from_value(json!({})).unwrap();
        let mut pod = template();
        configure_workload(&mut pod, &config).unwrap();
        assert_eq!(pod["metadata"]["labels"][ROLE_LABEL], "workload");
        assert!(pod["spec"].get("nodeSelector").is_none());
        assert!(pod["spec"].get("tolerations").is_none());
        let preference = &pod["spec"]["affinity"]["podAntiAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"]
            [0];
        assert_eq!(preference["weight"], 100);
        assert_eq!(
            preference["podAffinityTerm"]["namespaceSelector"],
            json!({})
        );
        assert_eq!(
            preference["podAffinityTerm"]["labelSelector"]["matchLabels"][ROLE_LABEL],
            "supervisor"
        );
        assert!(serde_json::from_value::<Config>(json!({"pod_anti_affinity": "require"})).is_err());
        assert!(
            serde_json::from_value::<Config>(json!({"workload_placement": {"nodeSelector": {}}}))
                .is_err()
        );
    }

    #[test]
    fn restart_policy_and_scope_transitions_preserve_operator_rules() {
        let mut pod = template();
        pod["spec"]["affinity"] = json!({
            "nodeAffinity": {"preferredDuringSchedulingIgnoredDuringExecution": []},
            "podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [
                {"topologyKey": "rack", "labelSelector": {"matchLabels": {"app": "database"}}}
            ]}
        });
        let original = pod["spec"]["affinity"].clone();
        let mut config = Config::default();
        for (mode, namespaces) in [
            (KubernetesPodAntiAffinity::Required, json!({})),
            (
                KubernetesPodAntiAffinity::Preferred,
                json!({"matchLabels": {"pool": "a"}}),
            ),
            (KubernetesPodAntiAffinity::Off, json!({})),
        ] {
            config.pod_anti_affinity = mode;
            config.pod_anti_affinity_namespace_selector =
                serde_json::from_value(namespaces).unwrap();
            let old = pod.clone();
            configure_workload(&mut pod, &config).unwrap();
            let mut admitted = old.clone();
            merge(&mut admitted, &merge_patch(&old, &pod));
            assert_eq!(admitted, pod, "merge patch must remove obsolete terms");
            let once = pod.clone();
            configure_workload(&mut pod, &config).unwrap();
            assert_eq!(pod, once);
        }
        assert_eq!(pod["spec"]["affinity"], original);
    }

    #[test]
    fn node_placement_restores_caller_values_and_preserves_admission_additions() {
        let mut pod = template();
        let caller_toleration = json!({"key": "gpu", "operator": "Exists"});
        pod["spec"]["nodeSelector"] = json!({"pool": "sandbox", "gpu": "yes"});
        pod["spec"]["tolerations"] = json!([caller_toleration]);
        let config: Config = serde_json::from_value(json!({"workload_placement": {
            "node_selector": {"pool": "sandbox", "operator": "yes"},
            "tolerations": [{"key": "gpu", "operator": "Exists"}, {"key": "sandbox", "operator": "Exists", "effect": "NoSchedule"}]
        }})).unwrap();
        configure_workload(&mut pod, &config).unwrap();
        let once = pod.clone();
        configure_workload(&mut pod, &config).unwrap();
        assert_eq!(pod, once);
        assert_eq!(pod["spec"]["tolerations"].as_array().unwrap().len(), 2);
        pod["spec"]["nodeSelector"]["admission"] = "yes".into();
        configure_workload(&mut pod, &Config::default()).unwrap();
        assert_eq!(
            pod["spec"]["nodeSelector"],
            json!({"pool": "sandbox", "gpu": "yes", "admission": "yes"})
        );
        assert_eq!(pod["spec"]["tolerations"], json!([caller_toleration]));
        let conflict: Config = serde_json::from_value(
            json!({"workload_placement": {"node_selector": {"pool": "infrastructure"}}}),
        )
        .unwrap();
        assert!(
            configure_workload(&mut pod, &conflict)
                .unwrap_err()
                .contains("conflicts with operator")
        );
    }

    #[test]
    fn required_admission_rejects_scheduler_bypasses_and_changed_policy() {
        let config = Config {
            pod_anti_affinity: KubernetesPodAntiAffinity::Required,
            ..Config::default()
        };
        let mut good = template();
        good["spec"]["schedulingGates"] = json!([{"name": BOOTSTRAP_GATE}]);
        configure_workload(&mut good, &config).unwrap();
        validate_workload(&serde_json::from_value(good.clone()).unwrap(), &config).unwrap();
        for (path, value) in [
            (
                "/metadata/labels/openshell.ai~1runtime-role",
                json!("supervisor"),
            ),
            ("/spec/affinity", json!({})),
            ("/spec/schedulingGates", json!([])),
        ] {
            let mut mutated = good.clone();
            *mutated.pointer_mut(path).unwrap() = value;
            assert!(validate_workload(&serde_json::from_value(mutated).unwrap(), &config).is_err());
        }
        for (key, value) in [("schedulerName", "custom"), ("nodeName", "node-1")] {
            let mut mutated = good.clone();
            mutated["spec"][key] = value.into();
            assert!(validate_workload(&serde_json::from_value(mutated).unwrap(), &config).is_err());
        }
    }

    #[test]
    fn operator_node_placement_is_validated_after_admission() {
        let config: Config = serde_json::from_value(json!({"workload_placement": {
            "node_selector": {"pool": "sandbox"},
            "tolerations": [{"key": "pool", "operator": "Exists"}]
        }}))
        .unwrap();
        config.validate().unwrap();
        let mut pod = template();
        pod["spec"]["schedulingGates"] = json!([{"name": BOOTSTRAP_GATE}]);
        configure_workload(&mut pod, &config).unwrap();
        validate_workload(&serde_json::from_value(pod.clone()).unwrap(), &config).unwrap();
        let original = pod.clone();
        pod["spec"]["nodeSelector"]["pool"] = "infrastructure".into();
        assert!(validate_workload(&serde_json::from_value(pod).unwrap(), &config).is_err());
        let mut pod = original;
        pod["spec"]["tolerations"] = json!([]);
        assert!(validate_workload(&serde_json::from_value(pod).unwrap(), &config).is_err());
        let invalid: Config = serde_json::from_value(json!({"workload_placement": {
            "tolerations": [{"operator": "Exists", "value": "not-empty"}]
        }}))
        .unwrap();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn restored_capacity_gets_bounded_startup_grace_from_scheduling_transition() {
        let mut pod: Pod = serde_json::from_value(json!({
            "metadata": {}, "spec": {"containers": []},
            "status": {"phase": "Pending", "conditions": [{
                "type": "PodScheduled", "status": "False", "reason": "Unschedulable"
            }]}
        }))
        .unwrap();
        assert!(scheduling_wait(&pod, 10_000_000, 300_000));
        pod.spec.as_mut().unwrap().node_name = Some("new-node".into());
        pod.status.as_mut().unwrap().conditions = Some(serde_json::from_value(json!([{
            "type": "PodScheduled", "status": "True", "lastTransitionTime": "1970-01-01T02:46:40Z"
        }])).unwrap());
        assert!(
            scheduling_wait(&pod, 10_100_000, 300_000),
            "ContainerCreating after a long capacity wait must survive"
        );
        assert!(
            !scheduling_wait(&pod, 10_300_000, 300_000),
            "startup failures must eventually be cleaned up"
        );
        pod.status.as_mut().unwrap().phase = Some("Failed".into());
        assert!(!scheduling_wait(&pod, 10_100_000, 300_000));
    }
}
