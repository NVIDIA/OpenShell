// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interceptable public gateway route classification.

use std::collections::{BTreeMap, BTreeSet};

use prost_reflect::DescriptorPool;

use crate::{InterceptorError, Result};

const SERVICE_OPEN_SHELL: &str = "openshell.v1.OpenShell";
const SERVICE_SANDBOX_UPDATES: &str = "openshell.v1.SandboxUpdates";

/// Unary sandbox-update methods that may be targeted by gateway interceptors.
pub const INTERCEPTABLE_SANDBOX_UPDATE_METHODS: &[&str] = &["UpdateSandbox"];

/// Unary `openshell.v1.OpenShell` methods that may be targeted by gateway
/// interceptors. New methods are non-interceptable until deliberately added
/// here.
pub const INTERCEPTABLE_METHODS: &[&str] = &[
    "CreateSandbox",
    "AttachSandboxProvider",
    "DetachSandboxProvider",
    "DeleteSandbox",
    "CreateSshSession",
    "ExposeService",
    "DeleteService",
    "RevokeSshSession",
    "CreateProvider",
    "ImportProviderProfiles",
    "UpdateProviderProfiles",
    "UpdateProvider",
    "ConfigureProviderRefresh",
    "RotateProviderCredential",
    "DeleteProviderRefresh",
    "DeleteProvider",
    "DeleteProviderProfile",
    "UpdateConfig",
    "SubmitPolicyAnalysis",
    "ApproveDraftChunk",
    "RejectDraftChunk",
    "ApproveAllDraftChunks",
    "EditDraftChunk",
    "UndoDraftChunk",
    "ClearDraftChunks",
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
        let mut all_methods = BTreeSet::new();
        let mut unary_methods = BTreeSet::new();
        let mut input_types = BTreeMap::new();
        let mut output_types = BTreeMap::new();

        for service_name in [SERVICE_OPEN_SHELL, SERVICE_SANDBOX_UPDATES] {
            let service = pool.get_service_by_name(service_name).ok_or_else(|| {
                InterceptorError::Config(format!(
                    "descriptor set does not contain service '{service_name}'"
                ))
            })?;
            for method in service.methods() {
                let route = format!("{service_name}/{}", method.name());
                all_methods.insert(route.clone());
                if !method.is_client_streaming() && !method.is_server_streaming() {
                    unary_methods.insert(route.clone());
                    input_types.insert(route.clone(), method.input().full_name().to_string());
                    output_types.insert(route, method.output().full_name().to_string());
                }
            }
        }

        let index = Self {
            all_methods,
            unary_methods,
            input_types,
            output_types,
        };
        index.validate_interceptable_list()?;
        Ok(index)
    }

    #[must_use]
    pub fn is_interceptable(&self, service: &str, method: &str) -> bool {
        let allowed = match service {
            SERVICE_OPEN_SHELL => INTERCEPTABLE_METHODS,
            SERVICE_SANDBOX_UPDATES => INTERCEPTABLE_SANDBOX_UPDATE_METHODS,
            _ => return false,
        };
        allowed.contains(&method) && self.unary_methods.contains(&format!("{service}/{method}"))
    }

    #[must_use]
    pub fn input_type(&self, service: &str, method: &str) -> Option<&str> {
        self.input_types
            .get(&format!("{service}/{method}"))
            .map(String::as_str)
    }

    #[must_use]
    pub fn output_type(&self, service: &str, method: &str) -> Option<&str> {
        self.output_types
            .get(&format!("{service}/{method}"))
            .map(String::as_str)
    }

    fn validate_interceptable_list(&self) -> Result<()> {
        let mut stale = Vec::new();
        let mut streaming = Vec::new();
        for (service, methods) in [
            (SERVICE_OPEN_SHELL, INTERCEPTABLE_METHODS),
            (
                SERVICE_SANDBOX_UPDATES,
                INTERCEPTABLE_SANDBOX_UPDATE_METHODS,
            ),
        ] {
            for method in methods {
                let route = format!("{service}/{method}");
                if !self.all_methods.contains(&route) {
                    stale.push(route);
                } else if !self.unary_methods.contains(&route) {
                    streaming.push(route);
                }
            }
        }
        if !stale.is_empty() {
            return Err(InterceptorError::Config(format!(
                "interceptable route list has stale methods: {stale:?}"
            )));
        }
        if !streaming.is_empty() {
            return Err(InterceptorError::Config(format!(
                "interceptable route list has streaming methods: {streaming:?}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interceptable_entries_match_real_unary_methods() {
        OpenShellRouteIndex::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
    }

    #[test]
    fn only_explicitly_allowed_write_methods_are_interceptable() {
        let index =
            OpenShellRouteIndex::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        assert!(index.is_interceptable("openshell.v1.OpenShell", "CreateSandbox"));
        assert!(index.is_interceptable(SERVICE_SANDBOX_UPDATES, "UpdateSandbox"));
        assert!(!index.is_interceptable(SERVICE_OPEN_SHELL, "UpdateSandbox"));
        assert!(!index.is_interceptable(SERVICE_SANDBOX_UPDATES, "CreateSandbox"));
        assert_eq!(
            index.input_type(SERVICE_SANDBOX_UPDATES, "UpdateSandbox"),
            Some("openshell.v1.UpdateSandboxRequest")
        );
        assert_eq!(
            index.output_type(SERVICE_SANDBOX_UPDATES, "UpdateSandbox"),
            Some("openshell.v1.SandboxResponse")
        );
        assert!(
            index
                .input_type(SERVICE_OPEN_SHELL, "UpdateSandbox")
                .is_none()
        );
        assert!(index.is_interceptable("openshell.v1.OpenShell", "UpdateConfig"));
        assert!(index.is_interceptable("openshell.v1.OpenShell", "SubmitPolicyAnalysis"));
        assert!(!index.is_interceptable("openshell.v1.OpenShell", "Health"));
        assert!(!index.is_interceptable("openshell.v1.OpenShell", "GetSandbox"));
        assert!(!index.is_interceptable("openshell.v1.OpenShell", "WatchSandbox"));
        assert!(!index.is_interceptable("openshell.v1.OpenShell", "FutureUnaryMethod"));
        assert_eq!(
            index.output_type("openshell.v1.OpenShell", "CreateSandbox"),
            Some("openshell.v1.SandboxResponse")
        );
    }
}
