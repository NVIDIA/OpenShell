// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Translate an [`OpenShellSandbox`] CR into the gateway's
//! [`CreateSandboxRequest`] protobuf.
//!
//! Keeping this in its own module lets it be unit-tested without spinning up
//! a kube client or the rest of the reconciler.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use kube::ResourceExt;
use openshell_core::proto::openshell::{CreateSandboxRequest, SandboxSpec, SandboxTemplate};
use openshell_policy::parse_sandbox_policy;

use crate::types::OpenShellSandbox;

/// Label key carrying the CR's `metadata.uid` on every gateway-side sandbox.
///
/// The controller uses this label as an unforgeable idempotency key on
/// re-reconcile so it doesn't have to rely on name matching.
pub const LABEL_CR_UID: &str = "openshell.nvidia.com/cr-uid";

/// Label key carrying the CR's `metadata.generation` at create time.
///
/// Lets the controller spot a stale gateway-side sandbox after a spec
/// edit (current CR generation > sandbox label).
pub const LABEL_CR_GENERATION: &str = "openshell.nvidia.com/cr-generation";

/// Prefix reserved for controller-managed labels. User-supplied labels
/// (from `spec.labels`) with this prefix are dropped before forwarding so
/// user input can't shadow the idempotency key.
const RESERVED_LABEL_PREFIX: &str = "openshell.nvidia.com/";

/// Build a [`CreateSandboxRequest`] from a CR.
///
/// # Errors
///
/// - Missing `metadata.uid` (the kube apiserver should always set this — if
///   it's absent we have no idempotency key, so we refuse rather than risk
///   creating an orphan sandbox).
/// - `policyYaml` fails to parse via
///   [`openshell_policy::parse_sandbox_policy`].
pub fn build_create_request(cr: &OpenShellSandbox) -> Result<CreateSandboxRequest> {
    let uid = cr
        .metadata
        .uid
        .as_deref()
        .ok_or_else(|| anyhow!("OpenShellSandbox has no metadata.uid — refusing to create"))?;

    // parse_sandbox_policy returns miette::Result which is incompatible with
    // anyhow's Context trait, so map the error manually.
    let policy = parse_sandbox_policy(&cr.spec.policy_yaml).map_err(|e| {
        anyhow!(
            "parsing spec.policyYaml on OpenShellSandbox {}: {e}",
            cr.name_any()
        )
    })?;

    let template = SandboxTemplate {
        image: cr.spec.image.clone(),
        runtime_class_name: cr.spec.runtime_class_name.clone().unwrap_or_default(),
        ..Default::default()
    };

    let spec = SandboxSpec {
        log_level: cr.spec.log_level.clone().unwrap_or_default(),
        environment: cr
            .spec
            .environment
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        template: Some(template),
        policy: Some(policy),
        providers: cr.spec.providers.clone(),
        gpu: cr.spec.gpu,
        gpu_device: cr.spec.gpu_device.clone().unwrap_or_default(),
    };

    // Start with the user-supplied labels, then overlay the controller's
    // reserved labels. Strip user keys under our reserved prefix so they
    // can't shadow `cr-uid` / `cr-generation`.
    let mut labels: HashMap<String, String> = cr
        .spec
        .labels
        .iter()
        .filter(|(k, _)| !k.starts_with(RESERVED_LABEL_PREFIX))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    labels.insert(LABEL_CR_UID.to_owned(), uid.to_owned());
    if let Some(generation) = cr.metadata.generation {
        labels.insert(LABEL_CR_GENERATION.to_owned(), generation.to_string());
    }

    Ok(CreateSandboxRequest {
        spec: Some(spec),
        name: cr.name_any(),
        labels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::OpenShellSandboxSpec;
    use kube::core::ObjectMeta;

    fn cr_with(spec: OpenShellSandboxSpec) -> OpenShellSandbox {
        OpenShellSandbox {
            metadata: ObjectMeta {
                name: Some("sample".into()),
                namespace: Some("default".into()),
                uid: Some("abc-123".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn minimal_spec() -> OpenShellSandboxSpec {
        OpenShellSandboxSpec {
            image: "ghcr.io/nvidia/openshell/sandbox:latest".into(),
            policy_yaml: "version: 1\n".into(),
            environment: std::collections::BTreeMap::default(),
            providers: Vec::new(),
            gpu: false,
            gpu_device: None,
            log_level: None,
            runtime_class_name: None,
            labels: std::collections::BTreeMap::default(),
        }
    }

    #[test]
    fn translates_minimum_spec() {
        let req = build_create_request(&cr_with(minimal_spec())).expect("translate ok");
        assert_eq!(req.name, "sample");
        let spec = req.spec.as_ref().expect("spec set");
        let tpl = spec.template.as_ref().expect("template set");
        assert_eq!(tpl.image, "ghcr.io/nvidia/openshell/sandbox:latest");
        assert!(spec.policy.is_some(), "policy populated from policyYaml");
        assert_eq!(req.labels.get(LABEL_CR_UID).map(String::as_str), Some("abc-123"));
        assert_eq!(req.labels.get(LABEL_CR_GENERATION).map(String::as_str), Some("1"));
    }

    #[test]
    fn rejects_cr_without_uid() {
        let mut cr = cr_with(minimal_spec());
        cr.metadata.uid = None;
        assert!(build_create_request(&cr).is_err());
    }

    #[test]
    fn surfaces_policy_parse_errors() {
        let mut spec = minimal_spec();
        spec.policy_yaml = ":\n  bad: [unterminated".into();
        assert!(build_create_request(&cr_with(spec)).is_err());
    }

    #[test]
    fn rejects_empty_image_via_minlength() {
        // An empty image string is forbidden by CRD `minLength: 1` so the
        // apiserver rejects at admission. translate doesn't need to
        // re-validate, but we cover the case where someone constructs a
        // CR struct by hand.
        let mut spec = minimal_spec();
        spec.image = String::new();
        let req = build_create_request(&cr_with(spec)).expect("translate doesn't validate image");
        let tpl = req.spec.as_ref().unwrap().template.as_ref().unwrap();
        assert_eq!(tpl.image, "");
    }

    #[test]
    fn rejects_empty_policy_yaml_via_minlength() {
        // Same as above — empty policyYaml is rejected at admission by
        // `minLength: 1`. The parser also rejects an empty string.
        let mut spec = minimal_spec();
        spec.policy_yaml = String::new();
        assert!(build_create_request(&cr_with(spec)).is_err());
    }

    #[test]
    fn propagates_environment_providers_gpu_loglevel_runtimeclass() {
        let mut spec = minimal_spec();
        spec.environment
            .insert("HTTP_PROXY".into(), "http://corp:3128".into());
        spec.providers = vec!["aws".into(), "github".into()];
        spec.gpu = true;
        spec.gpu_device = Some("0".into());
        spec.log_level = Some("debug".into());
        spec.runtime_class_name = Some("kata-containers".into());

        let req = build_create_request(&cr_with(spec)).expect("translate ok");
        let inner = req.spec.as_ref().unwrap();
        assert_eq!(
            inner.environment.get("HTTP_PROXY").map(String::as_str),
            Some("http://corp:3128")
        );
        assert_eq!(inner.providers, vec!["aws", "github"]);
        assert!(inner.gpu);
        assert_eq!(inner.gpu_device, "0");
        assert_eq!(inner.log_level, "debug");
        assert_eq!(
            inner.template.as_ref().unwrap().runtime_class_name,
            "kata-containers"
        );
    }

    #[test]
    fn user_labels_propagate_but_reserved_prefix_is_stripped() {
        let mut spec = minimal_spec();
        spec.labels.insert("team".into(), "platform".into());
        // User tries to shadow the reserved key — this must be dropped.
        spec.labels.insert(
            "openshell.nvidia.com/cr-uid".into(),
            "attacker-uid".into(),
        );

        let req = build_create_request(&cr_with(spec)).expect("translate ok");
        assert_eq!(req.labels.get("team").map(String::as_str), Some("platform"));
        // Controller's cr-uid wins; user input was stripped.
        assert_eq!(req.labels.get(LABEL_CR_UID).map(String::as_str), Some("abc-123"));
    }
}
