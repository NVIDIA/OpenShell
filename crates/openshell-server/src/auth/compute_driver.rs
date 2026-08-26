// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compute-driver delegated sandbox bootstrap authentication.

use super::authenticator::Authenticator;
use super::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
use crate::compute::ComputeRuntime;
use async_trait::async_trait;
use tonic::Status;

/// The only public gateway method on which driver-native credentials apply.
pub const ISSUE_SANDBOX_TOKEN_PATH: &str = "/openshell.v1.OpenShell/IssueSandboxToken";

#[derive(Clone, Debug)]
pub struct ComputeDriverAuthenticator {
    compute: ComputeRuntime,
}

impl ComputeDriverAuthenticator {
    pub fn new(compute: ComputeRuntime) -> Self {
        Self { compute }
    }
}

#[async_trait]
impl Authenticator for ComputeDriverAuthenticator {
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        path: &str,
    ) -> Result<Option<Principal>, Status> {
        if path != ISSUE_SANDBOX_TOKEN_PATH {
            return Ok(None);
        }

        let Some(credential) = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        else {
            return Ok(None);
        };

        let sandbox_id = self.compute.authenticate_sandbox(credential).await?;
        if sandbox_id.is_empty() {
            return Err(Status::permission_denied(
                "compute driver returned an empty sandbox identity",
            ));
        }

        Ok(Some(Principal::Sandbox(SandboxPrincipal {
            sandbox_id,
            source: SandboxIdentitySource::ComputeDriver {
                driver_name: self.compute.selected_driver_name().to_string(),
            },
            trust_domain: Some("openshell".to_string()),
        })))
    }
}
