// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared projections for selected stopped-sandbox configuration changes.
use crate::proto::{Sandbox, SandboxCommandUpdate, SandboxMapUpdate};
use std::collections::HashMap;

/// Gateway-owned identity and lifecycle metadata is never caller-replaceable.
/// Other keys, including user keys under `OpenShell` domains, remain editable.
#[must_use]
pub fn is_system_metadata_key(key: &str) -> bool {
    key.starts_with("internal.openshell.ai/")
        || matches!(
            key,
            "openshell.nvidia.com/retention"
                | "openshell.ai/managed-by"
                | "openshell.ai/sandbox-id"
                | "openshell.ai/sandbox-name"
                | "openshell.ai/sandbox-namespace"
                | "openshell.ai/sandbox-workspace"
                | "openshell.ai/gateway-id"
                | "openshell.ai/caller-driver-config-used"
                | "openshell.ai/resource-admission-identities"
        )
}

fn replace_user_metadata(current: &mut HashMap<String, String>, update: &SandboxMapUpdate) {
    current.retain(|key, _| is_system_metadata_key(key));
    current.extend(update.values.clone());
}

/// Caller must validate syntax and forbid system keys before projecting.
pub fn apply_configuration(
    sandbox: &mut Sandbox,
    command: Option<&SandboxCommandUpdate>,
    environment: Option<&SandboxMapUpdate>,
    labels: Option<&SandboxMapUpdate>,
    annotations: Option<&SandboxMapUpdate>,
) {
    if let Some(spec) = sandbox.spec.as_mut() {
        if let Some(command) = command {
            spec.command.clone_from(&command.argv);
        }
        if let Some(environment) = environment {
            spec.environment.clone_from(&environment.values);
        }
    }
    if let Some(metadata) = sandbox.metadata.as_mut() {
        if let Some(labels) = labels {
            replace_user_metadata(&mut metadata.labels, labels);
        }
        if let Some(annotations) = annotations {
            replace_user_metadata(&mut metadata.annotations, annotations);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_preserves_owned_keys_without_freezing_user_domains() {
        let mut metadata = HashMap::from([
            ("internal.openshell.ai/auth-epoch".into(), "trusted".into()),
            ("openshell.nvidia.com/retention".into(), "ephemeral".into()),
            ("openshell.ai/user-note".into(), "old".into()),
            ("agents.x-k8s.io/user-note".into(), "old".into()),
        ]);
        replace_user_metadata(&mut metadata, &SandboxMapUpdate::default());
        assert_eq!(metadata.len(), 2);
        assert_eq!(metadata["openshell.nvidia.com/retention"], "ephemeral");
        assert!(!is_system_metadata_key("openshell.ai/user-note"));
        assert!(!is_system_metadata_key("agents.x-k8s.io/user-note"));
    }
}
