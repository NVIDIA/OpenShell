// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interceptable `OpenShell` route classification.

use std::collections::{BTreeMap, BTreeSet};

use prost::Message as _;
use prost_types::FileDescriptorSet;

use crate::{InterceptorError, Result};

const SERVICE_OPEN_SHELL: &str = "openshell.v1.OpenShell";

/// Unary `openshell.v1.OpenShell` methods that are deliberately excluded from
/// gateway interception. New unary methods are interceptable by default unless
/// added here in the same change.
pub const NON_INTERCEPTABLE_METHODS: &[&str] = &[
    "Health",
    "WatchSandbox",
    "ExecSandbox",
    "ForwardTcp",
    "ExecSandboxInteractive",
    "PushSandboxLogs",
    "ConnectSupervisor",
    "RelayStream",
    "GetSandboxConfig",
    "GetSandboxProviderEnvironment",
    "ReportPolicyStatus",
    "SubmitPolicyAnalysis",
    "IssueSandboxToken",
    "RefreshSandboxToken",
    "GetSandbox",
    "ListSandboxes",
    "ListSandboxProviders",
    "GetProvider",
    "ListProviders",
    "ListProviderProfiles",
    "GetProviderProfile",
    "LintProviderProfiles",
    "GetProviderRefreshStatus",
    "GetGatewayConfig",
    "GetSandboxPolicyStatus",
    "ListSandboxPolicies",
    "GetSandboxLogs",
    "GetDraftPolicy",
    "GetDraftHistory",
    "GetService",
    "ListServices",
];

#[derive(Debug, Clone)]
pub struct OpenShellRouteIndex {
    all_methods: BTreeSet<String>,
    unary_methods: BTreeSet<String>,
    input_types: BTreeMap<String, String>,
}

impl OpenShellRouteIndex {
    pub fn from_descriptor_set(bytes: &[u8]) -> Result<Self> {
        let set = FileDescriptorSet::decode(bytes)
            .map_err(|e| InterceptorError::Config(format!("decode descriptor set: {e}")))?;
        let mut all_methods = BTreeSet::new();
        let mut unary_methods = BTreeSet::new();
        let mut input_types = BTreeMap::new();

        for file in &set.file {
            if file.package.as_deref() != Some("openshell.v1") {
                continue;
            }
            for service in &file.service {
                if service.name.as_deref() != Some("OpenShell") {
                    continue;
                }
                for method in &service.method {
                    let name = method.name.clone().unwrap_or_default();
                    all_methods.insert(name.clone());
                    if !method.client_streaming.unwrap_or(false)
                        && !method.server_streaming.unwrap_or(false)
                    {
                        let input_type = method
                            .input_type
                            .as_deref()
                            .unwrap_or_default()
                            .strip_prefix('.')
                            .unwrap_or_else(|| method.input_type.as_deref().unwrap_or_default())
                            .to_string();
                        unary_methods.insert(name.clone());
                        input_types.insert(name, input_type);
                    }
                }
            }
        }

        let index = Self {
            all_methods,
            unary_methods,
            input_types,
        };
        index.validate_non_interceptable_list()?;
        Ok(index)
    }

    #[must_use]
    pub fn is_interceptable(&self, service: &str, method: &str) -> bool {
        service == SERVICE_OPEN_SHELL
            && self.unary_methods.contains(method)
            && !NON_INTERCEPTABLE_METHODS.contains(&method)
    }

    #[must_use]
    pub fn input_type(&self, service: &str, method: &str) -> Option<&str> {
        if service == SERVICE_OPEN_SHELL && self.unary_methods.contains(method) {
            self.input_types.get(method).map(String::as_str)
        } else {
            None
        }
    }

    fn validate_non_interceptable_list(&self) -> Result<()> {
        let mut stale = Vec::new();
        for method in NON_INTERCEPTABLE_METHODS {
            if !self.all_methods.contains(*method) {
                stale.push((*method).to_string());
            }
        }
        if !stale.is_empty() {
            return Err(InterceptorError::Config(format!(
                "non-interceptable route list has stale methods: {stale:?}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_interceptable_entries_match_real_methods() {
        OpenShellRouteIndex::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
    }

    #[test]
    fn write_methods_are_interceptable_by_default() {
        let index =
            OpenShellRouteIndex::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        assert!(index.is_interceptable("openshell.v1.OpenShell", "CreateSandbox"));
        assert!(index.is_interceptable("openshell.v1.OpenShell", "UpdateConfig"));
        assert!(!index.is_interceptable("openshell.v1.OpenShell", "GetSandbox"));
        assert!(!index.is_interceptable("openshell.v1.OpenShell", "WatchSandbox"));
    }
}
