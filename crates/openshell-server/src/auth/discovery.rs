// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operator-managed grants for verified discovery client certificates.

use super::{
    identity::{Identity, IdentityProvider},
    principal::DiscoveryPrincipal,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;
use tokio::io::AsyncReadExt as _;
use tonic::Status;

pub const MAX_WORKSPACES: usize = 64;
const MAX_FILE_BYTES: usize = 256 * 1024;

/// Certificate OU marks a restricted credential class, never an authority grant.
/// The separate operator-controlled fingerprint mapping supplies authority.
pub fn is_certificate(identity: &Identity) -> bool {
    identity.provider == IdentityProvider::Mtls && identity.roles.iter().any(|r| r == "discovery")
}

pub fn is_method(path: &str) -> bool {
    matches!(
        path,
        "/openshell.v1.OpenShell/GetServiceRouteSnapshot"
            | "/openshell.v1.OpenShell/WatchServiceRoutes"
    ) && super::method_authz::lookup(path).is_some_and(|entry| {
        entry.auth_mode == super::method_authz::AuthMode::Bearer
            && entry.scope.as_deref() == Some("sandbox:read")
            && entry.workspace_role.as_deref() == Some("user")
            && entry.global_role.is_none()
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grants {
    readers: Vec<Grant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub certificate_sha256: String,
    #[serde(default)]
    pub workspaces: Vec<String>,
    #[serde(default)]
    pub all_workspaces: bool,
}

pub async fn grant(path: Option<&Path>, principal: &DiscoveryPrincipal) -> Result<Grant, Status> {
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        load_grant(path, principal),
    )
    .await
    .map_err(|_| Status::unavailable("discovery grant read timed out"))?
}

async fn load_grant(path: Option<&Path>, principal: &DiscoveryPrincipal) -> Result<Grant, Status> {
    if principal.expires_at_ms <= crate::persistence::current_time_ms() {
        return Err(Status::unauthenticated("discovery certificate expired"));
    }
    let path = path.ok_or_else(|| Status::permission_denied("discovery grant required"))?;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| Status::unavailable("discovery grants unavailable"))?;
    let mut bytes = Vec::new();
    file.take(
        u64::try_from(MAX_FILE_BYTES + 1).map_err(|_| Status::internal("invalid file limit"))?,
    )
    .read_to_end(&mut bytes)
    .await
    .map_err(|_| Status::unavailable("discovery grants unavailable"))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Status::resource_exhausted(
            "discovery grants file too large",
        ));
    }
    let grants: Grants = serde_json::from_slice(&bytes)
        .map_err(|_| Status::unavailable("invalid discovery grants"))?;
    if grants.readers.len() > 1024 {
        return Err(Status::resource_exhausted("too many discovery grants"));
    }
    let mut fingerprints = BTreeSet::new();
    for reader in &grants.readers {
        if reader.certificate_sha256.len() != 64
            || !reader
                .certificate_sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || !fingerprints.insert(&reader.certificate_sha256)
            || reader.workspaces.len() > MAX_WORKSPACES
            || reader.all_workspaces != reader.workspaces.is_empty()
        {
            return Err(Status::unavailable("invalid discovery grant mapping"));
        }
        let mut names = BTreeSet::new();
        for workspace in &reader.workspaces {
            crate::grpc::workspace::validate_workspace_name(workspace)
                .map_err(|_| Status::unavailable("invalid discovery workspace grant"))?;
            if !names.insert(workspace) {
                return Err(Status::unavailable("duplicate discovery workspace grant"));
            }
        }
    }
    grants
        .readers
        .into_iter()
        .find(|g| g.certificate_sha256 == principal.certificate_sha256)
        .ok_or_else(|| Status::permission_denied("discovery grant revoked or missing"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn fingerprint_grants_reload_and_never_derive_authority_from_subject_roles() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let reader = DiscoveryPrincipal {
            certificate_sha256: "a".repeat(64),
            expires_at_ms: crate::persistence::current_time_ms() + 60_000,
        };
        let write = |readers: serde_json::Value| {
            std::fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!({"readers":readers})).unwrap(),
            )
            .unwrap();
        };
        write(
            serde_json::json!([{"certificate_sha256":reader.certificate_sha256,"workspaces":["default"]}]),
        );
        assert_eq!(
            grant(Some(&path), &reader).await.unwrap().workspaces,
            vec!["default"]
        );
        let unrelated = DiscoveryPrincipal {
            certificate_sha256: "b".repeat(64),
            ..reader.clone()
        };
        assert_eq!(
            grant(Some(&path), &unrelated).await.err().unwrap().code(),
            tonic::Code::PermissionDenied
        );
        write(serde_json::json!([]));
        assert_eq!(
            grant(Some(&path), &reader).await.err().unwrap().code(),
            tonic::Code::PermissionDenied
        );
        write(
            serde_json::json!([{"certificate_sha256":reader.certificate_sha256,"all_workspaces":true,"workspaces":["default"]}]),
        );
        assert_eq!(
            grant(Some(&path), &reader).await.err().unwrap().code(),
            tonic::Code::Unavailable
        );
        assert_eq!(
            grant(
                Some(&path),
                &DiscoveryPrincipal {
                    expires_at_ms: 0,
                    ..reader
                }
            )
            .await
            .err()
            .unwrap()
            .code(),
            tonic::Code::Unauthenticated
        );
    }
    #[test]
    fn every_other_rpc_is_denied_including_unclassified_methods() {
        for path in super::super::method_authz::all_paths() {
            assert_eq!(
                is_method(path),
                matches!(
                    path,
                    "/openshell.v1.OpenShell/GetServiceRouteSnapshot"
                        | "/openshell.v1.OpenShell/WatchServiceRoutes"
                ),
                "{path}"
            );
        }
        assert!(!is_method("/openshell.v1.OpenShell/FutureReadMethod"));
    }
}
