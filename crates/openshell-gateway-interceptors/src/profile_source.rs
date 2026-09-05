// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interceptor-vended provider profile snapshots.

use std::time::Duration;

use openshell_core::mcp::normalize_provider_profile_mcp_fields;
use openshell_core::proto::ProviderProfile;
use openshell_core::proto::gateway_interceptor::v1::{
    ProviderProfileSnapshotRequest, gateway_interceptor_client::GatewayInterceptorClient,
};
use prost::Message as _;
use sha2::Digest as _;
use tonic::Request;

use crate::{ExtensionChannel, InterceptorError, Result};

#[derive(Debug, Clone)]
pub struct ProviderProfileSourceSnapshot {
    pub revision: String,
    pub profiles: Vec<ProviderProfile>,
}

#[derive(Clone)]
pub struct GatewayInterceptorProfileSource {
    interceptor_name: String,
    source_id: String,
    timeout: Duration,
    client: GatewayInterceptorClient<ExtensionChannel>,
}

impl GatewayInterceptorProfileSource {
    pub(crate) fn new(
        interceptor_name: String,
        source_id: String,
        timeout: Duration,
        client: GatewayInterceptorClient<ExtensionChannel>,
    ) -> Self {
        Self {
            interceptor_name,
            source_id,
            timeout,
            client,
        }
    }

    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub async fn snapshot(&self) -> Result<ProviderProfileSourceSnapshot> {
        let mut client = self.client.clone();
        let response = tokio::time::timeout(
            self.timeout,
            client.snapshot_provider_profiles(Request::new(ProviderProfileSnapshotRequest {})),
        )
        .await
        .map_err(|_| {
            InterceptorError::Transport(format!(
                "SnapshotProviderProfiles timed out for '{}'",
                self.interceptor_name
            ))
        })?
        .map_err(|status| {
            InterceptorError::Transport(format!(
                "SnapshotProviderProfiles failed for '{}': {status}",
                self.interceptor_name
            ))
        })?
        .into_inner();

        let revision =
            resolve_provider_profile_snapshot_revision(response.revision, &response.profiles);
        Ok(ProviderProfileSourceSnapshot {
            revision,
            profiles: response.profiles,
        })
    }
}

impl std::fmt::Debug for GatewayInterceptorProfileSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayInterceptorProfileSource")
            .field("interceptor_name", &self.interceptor_name)
            .field("source_id", &self.source_id)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

fn provider_profile_snapshot_revision(profiles: &[ProviderProfile]) -> String {
    let mut profiles = profiles.to_vec();
    profiles
        .iter_mut()
        .for_each(normalize_provider_profile_mcp_fields);
    profiles.sort_by(|left, right| left.id.cmp(&right.id));
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"openshell-provider-profile-snapshot-v1");
    for profile in profiles {
        hasher.update(profile.encode_to_vec());
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn resolve_provider_profile_snapshot_revision(
    revision: String,
    profiles: &[ProviderProfile],
) -> String {
    if revision.trim().is_empty() {
        // Whitespace-only carries no source identity, so treat it as omitted
        // and derive a stable revision from the canonical profile payloads.
        provider_profile_snapshot_revision(profiles)
    } else {
        // A nonblank revision is opaque source-owned state. Preserve it
        // exactly instead of substituting a locally derived fingerprint.
        revision
    }
}

#[cfg(test)]
mod tests {
    use openshell_core::proto::{McpOptions, NetworkEndpoint};

    use super::*;

    fn profile_with_mcp_versions(versions: Option<&[&str]>) -> ProviderProfile {
        ProviderProfile {
            id: "governed-mcp".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "mcp.example.com".to_string(),
                port: 443,
                protocol: "mcp".to_string(),
                mcp: versions.map(|versions| McpOptions {
                    versions: versions
                        .iter()
                        .map(|version| (*version).to_string())
                        .collect(),
                    ..McpOptions::default()
                }),
                ..NetworkEndpoint::default()
            }],
            ..ProviderProfile::default()
        }
    }

    #[test]
    fn fallback_revision_equates_omitted_empty_and_explicit_default_mcp_versions() {
        let omitted = profile_with_mcp_versions(None);
        let empty = profile_with_mcp_versions(Some(&[]));
        let explicit = profile_with_mcp_versions(Some(&["2025-11-25"]));

        let expected = resolve_provider_profile_snapshot_revision(
            " \t".to_string(),
            std::slice::from_ref(&explicit),
        );
        assert_eq!(
            resolve_provider_profile_snapshot_revision(
                String::new(),
                std::slice::from_ref(&omitted),
            ),
            expected
        );
        assert_eq!(
            resolve_provider_profile_snapshot_revision(String::new(), std::slice::from_ref(&empty),),
            expected
        );
    }

    #[test]
    fn fallback_revision_equates_valid_mcp_version_orderings() {
        let canonical = profile_with_mcp_versions(Some(&["2025-03-26", "2025-11-25"]));
        let reordered = profile_with_mcp_versions(Some(&["2025-11-25", "2025-03-26"]));

        assert_eq!(
            provider_profile_snapshot_revision(std::slice::from_ref(&canonical)),
            provider_profile_snapshot_revision(std::slice::from_ref(&reordered))
        );
    }

    #[test]
    fn fallback_revision_preserves_malformed_mcp_evidence() {
        let malformed = profile_with_mcp_versions(Some(&["latest", "2025-11-25", "2025-11-25"]));
        let original = malformed.clone();
        let canonical = profile_with_mcp_versions(Some(&["2025-11-25"]));

        assert_ne!(
            provider_profile_snapshot_revision(std::slice::from_ref(&malformed)),
            provider_profile_snapshot_revision(std::slice::from_ref(&canonical))
        );
        assert_eq!(malformed, original);
    }

    #[test]
    fn source_supplied_revision_remains_opaque_and_exact() {
        let profiles = [profile_with_mcp_versions(None)];
        let source_revision = " governance:v7 ".to_string();

        assert_eq!(
            resolve_provider_profile_snapshot_revision(source_revision.clone(), &profiles),
            source_revision
        );
        assert_eq!(
            resolve_provider_profile_snapshot_revision(" \t".to_string(), &profiles),
            provider_profile_snapshot_revision(&profiles)
        );
    }
}
