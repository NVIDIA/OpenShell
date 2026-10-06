// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interceptable `Ryno` route classification.

use std::collections::{BTreeMap, BTreeSet};

use prost_reflect::DescriptorPool;

use crate::{InterceptorError, Result};

const SERVICE_RYNO: &str = "ryno.v1.Ryno";

/// Unary `ryno.v1.Ryno` methods that may be targeted by gateway
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
pub struct RynoRouteIndex {
    all_methods: BTreeSet<String>,
    unary_methods: BTreeSet<String>,
    input_types: BTreeMap<String, String>,
    output_types: BTreeMap<String, String>,
}

impl RynoRouteIndex {
    pub fn from_descriptor_set(bytes: &[u8]) -> Result<Self> {
        let pool = DescriptorPool::decode(bytes)
            .map_err(|e| InterceptorError::Config(format!("decode descriptor set: {e}")))?;
        Self::from_descriptor_pool(&pool)
    }

    pub(crate) fn from_descriptor_pool(pool: &DescriptorPool) -> Result<Self> {
        let service = pool.get_service_by_name(SERVICE_RYNO).ok_or_else(|| {
            InterceptorError::Config(format!(
                "descriptor set does not contain service '{SERVICE_RYNO}'"
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
        index.validate_interceptable_list()?;
        Ok(index)
    }

    #[must_use]
    pub fn is_interceptable(&self, service: &str, method: &str) -> bool {
        service == SERVICE_RYNO
            && self.unary_methods.contains(method)
            && INTERCEPTABLE_METHODS.contains(&method)
    }

    #[must_use]
    pub fn input_type(&self, service: &str, method: &str) -> Option<&str> {
        if service == SERVICE_RYNO && self.unary_methods.contains(method) {
            self.input_types.get(method).map(String::as_str)
        } else {
            None
        }
    }

    #[must_use]
    pub fn output_type(&self, service: &str, method: &str) -> Option<&str> {
        if service == SERVICE_RYNO && self.unary_methods.contains(method) {
            self.output_types.get(method).map(String::as_str)
        } else {
            None
        }
    }

    fn validate_interceptable_list(&self) -> Result<()> {
        let mut stale = Vec::new();
        let mut streaming = Vec::new();
        for method in INTERCEPTABLE_METHODS {
            if !self.all_methods.contains(*method) {
                stale.push((*method).to_string());
            } else if !self.unary_methods.contains(*method) {
                streaming.push((*method).to_string());
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
        RynoRouteIndex::from_descriptor_set(ryno_core::FILE_DESCRIPTOR_SET).unwrap();
    }

    #[test]
    fn only_explicitly_allowed_write_methods_are_interceptable() {
        let index = RynoRouteIndex::from_descriptor_set(ryno_core::FILE_DESCRIPTOR_SET).unwrap();
        assert!(index.is_interceptable("ryno.v1.Ryno", "CreateSandbox"));
        assert!(index.is_interceptable("ryno.v1.Ryno", "UpdateConfig"));
        assert!(index.is_interceptable("ryno.v1.Ryno", "SubmitPolicyAnalysis"));
        assert!(!index.is_interceptable("ryno.v1.Ryno", "Health"));
        assert!(!index.is_interceptable("ryno.v1.Ryno", "GetSandbox"));
        assert!(!index.is_interceptable("ryno.v1.Ryno", "WatchSandbox"));
        assert!(!index.is_interceptable("ryno.v1.Ryno", "FutureUnaryMethod"));
        assert_eq!(
            index.output_type("ryno.v1.Ryno", "CreateSandbox"),
            Some("ryno.v1.SandboxResponse")
        );
    }
}
