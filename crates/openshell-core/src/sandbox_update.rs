// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared projections for selected stopped-sandbox configuration changes.
use crate::proto::{Sandbox, SandboxCommandUpdate, SandboxMapUpdate};
use std::collections::HashMap;

/// System metadata is never caller-replaceable, including subdomains.
#[must_use]
pub fn is_system_metadata_key(key: &str) -> bool {
    key.split_once('/').is_some_and(|(domain, _)| {
        domain == "openshell.ai"
            || domain.ends_with(".openshell.ai")
            || domain == "agents.x-k8s.io"
            || domain.ends_with(".agents.x-k8s.io")
    })
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
