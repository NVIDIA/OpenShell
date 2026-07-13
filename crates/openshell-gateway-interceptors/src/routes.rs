// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interceptable `OpenShell` route classification.

use std::collections::{BTreeMap, BTreeSet};

use prost_reflect::DescriptorPool;

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
    output_types: BTreeMap<String, String>,
}

impl OpenShellRouteIndex {
    pub fn from_descriptor_set(bytes: &[u8]) -> Result<Self> {
        let pool = DescriptorPool::decode(bytes)
            .map_err(|e| InterceptorError::Config(format!("decode descriptor set: {e}")))?;
        Self::from_descriptor_pool(&pool)
    }

    pub(crate) fn from_descriptor_pool(pool: &DescriptorPool) -> Result<Self> {
        let service = pool
            .get_service_by_name(SERVICE_OPEN_SHELL)
            .ok_or_else(|| {
                InterceptorError::Config(format!(
                    "descriptor set does not contain service '{SERVICE_OPEN_SHELL}'"
                ))
            })?;
        let mut all_methods = BTreeSet::new();
        let mut unary_methods = BTreeSet::new();
        let mut input_types = BTreeMap::new();
        let mut output_types = BTreeMap::new();

        for method in service.methods() {
            let name = method.name().to_string();
            all_methods.insert(name.clone());
            if !method.is_client_streaming() && !method.is_server_streaming() {
                unary_methods.insert(name.clone());
                input_types.insert(name.clone(), method.input().full_name().to_string());
                output_types.insert(name, method.output().full_name().to_string());
            }
        }

        let index = Self {
            all_methods,
            unary_methods,
            input_types,
            output_types,
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

    #[must_use]
    pub fn output_type(&self, service: &str, method: &str) -> Option<&str> {
        if service == SERVICE_OPEN_SHELL && self.unary_methods.contains(method) {
            self.output_types.get(method).map(String::as_str)
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
        assert_eq!(
            index.output_type("openshell.v1.OpenShell", "CreateSandbox"),
            Some("openshell.v1.SandboxResponse")
        );
    }
}
