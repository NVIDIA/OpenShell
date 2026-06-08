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
        ..Default::default()
    };

    let spec = SandboxSpec {
        template: Some(template),
        policy: Some(policy),
        ..Default::default()
    };

    let mut labels: HashMap<String, String> = HashMap::new();
    labels.insert(LABEL_CR_UID.to_owned(), uid.to_owned());
    // `gen` is a reserved keyword in Rust 2024, so destructure under a
    // different name.
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
    use crate::types::{ExposeSpec, OpenShellSandboxSpec};
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

    #[test]
    fn translates_minimum_spec() {
        let cr = cr_with(OpenShellSandboxSpec {
            image: "ghcr.io/nvidia/openshell/sandbox:latest".into(),
            start_command: None,
            policy_yaml: "version: 1\n".into(),
            expose: ExposeSpec { port: 8080 },
            pod_customisations: None,
        });

        let req = build_create_request(&cr).expect("translate ok");
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
        let mut cr = cr_with(OpenShellSandboxSpec {
            image: "x".into(),
            start_command: None,
            policy_yaml: "version: 1\n".into(),
            expose: ExposeSpec { port: 80 },
            pod_customisations: None,
        });
        cr.metadata.uid = None;
        assert!(build_create_request(&cr).is_err());
    }

    #[test]
    fn surfaces_policy_parse_errors() {
        let cr = cr_with(OpenShellSandboxSpec {
            image: "x".into(),
            start_command: None,
            policy_yaml: ":\n  bad: [unterminated".into(),
            expose: ExposeSpec { port: 80 },
            pod_customisations: None,
        });
        assert!(build_create_request(&cr).is_err());
    }
}
