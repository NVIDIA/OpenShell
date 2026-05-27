// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SPIFFE JWT-SVID authentication for sandbox supervisors.
//!
//! The gateway does not validate SPIFFE JWT-SVID signatures itself. Instead it
//! delegates validation to the local SPIFFE Workload API, keeping algorithm and
//! bundle handling inside the configured SPIFFE implementation.

use super::authenticator::Authenticator;
use super::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
use async_trait::async_trait;
use openshell_core::SpiffeConfig;
use spiffe::{JwtSvid, WorkloadApiClient};
use std::path::Path;
use tonic::Status;
use tracing::{debug, info, warn};

/// Authenticator backed by the SPIFFE Workload API `ValidateJWTSVID` RPC.
pub struct SpiffeAuthenticator {
    client: WorkloadApiClient,
    config: SpiffeConfig,
}

impl std::fmt::Debug for SpiffeAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeAuthenticator")
            .field("socket", &self.config.workload_api_socket_path)
            .field("trust_domain", &self.config.trust_domain)
            .field("audience", &self.config.audience)
            .field("sandbox_id_prefix", &self.config.sandbox_id_prefix)
            .finish_non_exhaustive()
    }
}

impl SpiffeAuthenticator {
    pub async fn new(config: SpiffeConfig) -> Result<Self, String> {
        let endpoint = workload_api_endpoint(&config.workload_api_socket_path);
        let client = WorkloadApiClient::connect_to(&endpoint)
            .await
            .map_err(|e| {
                format!("failed to connect to SPIFFE Workload API endpoint {endpoint}: {e}")
            })?;
        info!(
            socket = %config.workload_api_socket_path.display(),
            trust_domain = %config.trust_domain,
            audience = %config.audience,
            "SPIFFE JWT-SVID sandbox authenticator enabled"
        );
        Ok(Self { client, config })
    }

    #[allow(clippy::result_large_err)]
    async fn validate_bearer(&self, token: &str) -> Result<Option<Principal>, Status> {
        let Some(candidate_id) = candidate_spiffe_id(token) else {
            return Ok(None);
        };
        if parse_sandbox_id_from_spiffe_id(
            &candidate_id,
            &self.config.trust_domain,
            &self.config.sandbox_id_prefix,
        )
        .is_none()
        {
            return Ok(None);
        }

        let svid = self
            .client
            .validate_jwt_token(&self.config.audience, token)
            .await
            .map_err(|status| {
                debug!(error = %status, "SPIFFE JWT-SVID validation failed");
                Status::unauthenticated("invalid SPIFFE JWT-SVID")
            })?;

        self.principal_from_validated_svid(&svid)
    }

    #[allow(clippy::result_large_err)]
    fn principal_from_validated_svid(&self, svid: &JwtSvid) -> Result<Option<Principal>, Status> {
        let spiffe_id = svid.spiffe_id().to_string();
        let Some(sandbox_id) = parse_sandbox_id_from_spiffe_id(
            &spiffe_id,
            &self.config.trust_domain,
            &self.config.sandbox_id_prefix,
        ) else {
            warn!(
                spiffe_id = %spiffe_id,
                trust_domain = %self.config.trust_domain,
                prefix = %self.config.sandbox_id_prefix,
                "validated SPIFFE ID is outside the configured sandbox identity namespace"
            );
            return Err(Status::permission_denied(
                "SPIFFE ID is not authorized as an OpenShell sandbox",
            ));
        };

        Ok(Some(Principal::Sandbox(SandboxPrincipal {
            sandbox_id,
            source: SandboxIdentitySource::SpiffeSvid { spiffe_id },
            trust_domain: Some(self.config.trust_domain.clone()),
        })))
    }
}

#[async_trait]
impl Authenticator for SpiffeAuthenticator {
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        _path: &str,
    ) -> Result<Option<Principal>, Status> {
        let Some(token) = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        else {
            return Ok(None);
        };
        self.validate_bearer(token).await
    }
}

fn parse_sandbox_id_from_spiffe_id(
    spiffe_id: &str,
    trust_domain: &str,
    sandbox_id_prefix: &str,
) -> Option<String> {
    let trust_domain = trust_domain.trim().trim_start_matches("spiffe://");
    let prefix = format!(
        "spiffe://{}{}",
        trust_domain.trim_end_matches('/'),
        normalize_spiffe_path_prefix(sandbox_id_prefix)
    );
    let sandbox_id = spiffe_id.strip_prefix(&prefix)?;
    (!sandbox_id.is_empty() && !sandbox_id.contains('/')).then(|| sandbox_id.to_string())
}

fn normalize_spiffe_path_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim();
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn candidate_spiffe_id(jwt: &str) -> Option<String> {
    JwtSvid::parse_insecure(jwt)
        .ok()
        .map(|svid| svid.spiffe_id().to_string())
}

fn workload_api_endpoint(path: &Path) -> String {
    let path = path.to_string_lossy();
    if path.starts_with("unix:") || path.starts_with("tcp:") {
        path.into_owned()
    } else {
        format!("unix:{path}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sandbox_id_from_configured_spiffe_id() {
        assert_eq!(
            parse_sandbox_id_from_spiffe_id(
                "spiffe://openshell.local/openshell/sandbox/abc",
                "openshell.local",
                "/openshell/sandbox/",
            )
            .as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn rejects_spiffe_id_outside_sandbox_namespace() {
        assert!(
            parse_sandbox_id_from_spiffe_id(
                "spiffe://openshell.local/ns/openshell/sa/default",
                "openshell.local",
                "/openshell/sandbox/",
            )
            .is_none()
        );
        assert!(
            parse_sandbox_id_from_spiffe_id(
                "spiffe://other.local/openshell/sandbox/abc",
                "openshell.local",
                "/openshell/sandbox/",
            )
            .is_none()
        );
    }

    #[test]
    fn prefixes_plain_socket_paths_as_unix_endpoints() {
        assert_eq!(
            workload_api_endpoint(Path::new("/spiffe-workload-api/spire-agent.sock")),
            "unix:/spiffe-workload-api/spire-agent.sock"
        );
        assert_eq!(
            workload_api_endpoint(Path::new("unix:/tmp/spire.sock")),
            "unix:/tmp/spire.sock"
        );
    }
}
