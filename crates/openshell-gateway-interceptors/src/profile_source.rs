// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interceptor-vended provider profile snapshots.

use std::time::Duration;

use openshell_core::proto::ProviderProfile;
use openshell_core::proto::gateway_interceptor::v1::{
    ProviderProfileSnapshotRequest, gateway_interceptor_client::GatewayInterceptorClient,
};
use prost::Message as _;
use sha2::Digest as _;
use tonic::{Request, transport::Channel};

use crate::{InterceptorError, Result};

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
    client: GatewayInterceptorClient<Channel>,
}

impl GatewayInterceptorProfileSource {
    pub(crate) fn new(
        interceptor_name: String,
        source_id: String,
        timeout: Duration,
        client: GatewayInterceptorClient<Channel>,
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

        let revision = if response.revision.trim().is_empty() {
            provider_profile_snapshot_revision(&response.profiles)
        } else {
            response.revision
        };
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
    profiles.sort_by(|left, right| left.id.cmp(&right.id));
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"openshell-provider-profile-snapshot-v1");
    for profile in profiles {
        hasher.update(profile.encode_to_vec());
    }
    format!("sha256:{:x}", hasher.finalize())
}
