// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Descriptor-pool-based authorization metadata.
//!
//! Reads per-method `(openshell.options.v1.authorization)` annotations from
//! the compiled `FileDescriptorSet` and builds an auth lookup table keyed by
//! gRPC path. The `method_authz` module re-exports the public API from here.

use std::collections::HashMap;
use std::sync::LazyLock;

use prost_reflect::{DescriptorPool, Value};

use super::method_authz::{AuthMode, Role};

const AUTHORIZATION_EXTENSION: &str = "openshell.options.v1.authorization";

/// Gateway-served protobuf packages.
const GATEWAY_PACKAGES: &[&str] = &["openshell.v1", "openshell.inference.v1"];

/// Bearer-authenticated methods that deliberately require no role or scope.
///
/// Keep this list explicit so an incomplete authorization annotation cannot
/// silently turn a future RPC into an authentication-only endpoint.
const AUTH_ONLY_METHODS: &[&str] = &["/openshell.v1.OpenShell/GetCurrentUser"];

/// Per-method authorization entry decoded from proto annotations.
#[derive(Debug, Clone)]
pub struct DescriptorAuthEntry {
    pub auth_mode: AuthMode,
    pub scope: Option<String>,
    pub workspace_role: Option<String>,
    pub global_role: Option<String>,
}

impl DescriptorAuthEntry {
    /// Map the Phase 2 role fields back to the flat `Role` enum used by the
    /// existing middleware. `global_role: "platform_admin"` and
    /// `workspace_role: "admin"` both map to `Role::Admin`;
    /// `workspace_role: "user"` maps to `Role::User`.
    pub fn effective_role(&self) -> Option<Role> {
        self.global_role.as_deref().map_or_else(
            || {
                self.workspace_role.as_deref().and_then(|wr| match wr {
                    "admin" => Some(Role::Admin),
                    "user" => Some(Role::User),
                    _ => None,
                })
            },
            |gr| match gr {
                "platform_admin" => Some(Role::Admin),
                _ => None,
            },
        )
    }

    /// Returns `true` when this method uses workspace-level authorization
    /// (checked by the handler) rather than global-level (checked by
    /// middleware).
    #[allow(dead_code)]
    pub fn is_workspace_scoped(&self) -> bool {
        self.workspace_role.is_some()
    }
}

/// Auth table built from the descriptor pool.
pub struct DescriptorAuthTable {
    entries: HashMap<String, DescriptorAuthEntry>,
}

static TABLE: LazyLock<Result<DescriptorAuthTable, String>> =
    LazyLock::new(|| DescriptorAuthTable::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET));

impl DescriptorAuthTable {
    fn from_descriptor_set(bytes: &[u8]) -> Result<Self, String> {
        let pool =
            DescriptorPool::decode(bytes).map_err(|e| format!("decode descriptor pool: {e}"))?;

        let auth_ext = pool
            .get_extension_by_name(AUTHORIZATION_EXTENSION)
            .ok_or_else(|| {
                format!("extension {AUTHORIZATION_EXTENSION} not found in descriptor pool")
            })?;

        let mut entries = HashMap::new();

        for service in pool.services() {
            let file = service.parent_file();
            let package = file.package_name();
            if !GATEWAY_PACKAGES.contains(&package) {
                continue;
            }

            for method in service.methods() {
                let path = format!("/{}.{}/{}", package, service.name(), method.name());
                let options = method.options();

                if !options.has_extension(&auth_ext) {
                    return Err(format!("method {path} missing (authorization) option"));
                }

                let auth_value = options.get_extension(&auth_ext);
                let Value::Message(ref auth_msg) = *auth_value else {
                    return Err(format!(
                        "method {path}: authorization option is not a message"
                    ));
                };

                let auth_mode_str = string_field(auth_msg, "auth_mode");
                let workspace_role_str = string_field(auth_msg, "workspace_role");
                let global_role_str = string_field(auth_msg, "global_role");
                let scope_str = string_field(auth_msg, "scope");

                let auth_mode = match auth_mode_str.as_str() {
                    "unauthenticated" => AuthMode::Unauthenticated,
                    "sandbox" => AuthMode::Sandbox,
                    "bearer" => AuthMode::Bearer,
                    "dual" => AuthMode::Dual,
                    other => {
                        return Err(format!("method {path}: unknown auth_mode '{other}'"));
                    }
                };

                let workspace_role = non_empty(workspace_role_str);
                let global_role = non_empty(global_role_str);
                let scope = non_empty(scope_str);

                validate_entry(
                    &path,
                    auth_mode,
                    workspace_role.as_deref(),
                    global_role.as_deref(),
                    scope.as_deref(),
                )?;

                entries.insert(
                    path,
                    DescriptorAuthEntry {
                        auth_mode,
                        scope,
                        workspace_role,
                        global_role,
                    },
                );
            }
        }

        Ok(Self { entries })
    }
}

fn validate_entry(
    path: &str,
    auth_mode: AuthMode,
    workspace_role: Option<&str>,
    global_role: Option<&str>,
    scope: Option<&str>,
) -> Result<(), String> {
    if workspace_role.is_some() && global_role.is_some() {
        return Err(format!(
            "method {path}: workspace_role and global_role are mutually exclusive"
        ));
    }

    if !matches!(auth_mode, AuthMode::Bearer | AuthMode::Dual) {
        return Ok(());
    }

    let role_missing = workspace_role.is_none() && global_role.is_none();
    if role_missing && scope.is_none() {
        if AUTH_ONLY_METHODS.contains(&path) {
            return Ok(());
        }
        return Err(format!(
            "method {path}: bearer method declares no role and no scope"
        ));
    }

    if role_missing {
        return Err(format!("method {path}: bearer method declares no role"));
    }
    if scope.is_none() {
        return Err(format!("method {path}: bearer method declares no scope"));
    }

    Ok(())
}

fn string_field(msg: &prost_reflect::DynamicMessage, name: &str) -> String {
    msg.get_field_by_name(name)
        .and_then(|v| match &*v {
            Value::String(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

/// Look up descriptor-pool auth metadata for a gRPC method path.
pub fn lookup(method: &str) -> Option<&'static DescriptorAuthEntry> {
    TABLE
        .as_ref()
        .expect("descriptor authorization table must be validated during startup")
        .entries
        .get(method)
}

/// Build and validate the descriptor authorization table.
///
/// The gateway calls this before binding any listener so invalid annotations
/// fail startup rather than panicking on the first gRPC request.
pub fn init() -> Result<(), String> {
    TABLE.as_ref().map(|_| ()).map_err(Clone::clone)
}

/// Iterator over all registered method paths.
#[cfg(test)]
pub fn all_paths() -> impl Iterator<Item = &'static str> {
    TABLE
        .as_ref()
        .expect("descriptor authorization table must be valid in tests")
        .entries
        .keys()
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FUTURE_RPC: &str = "/openshell.v1.OpenShell/FutureRpc";

    #[test]
    fn every_proto_rpc_has_authorization_option() {
        let pool = DescriptorPool::decode(openshell_core::FILE_DESCRIPTOR_SET)
            .expect("decode descriptor set");
        let table = DescriptorAuthTable::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET)
            .expect("every RPC authorization annotation must be complete and valid");

        let mut missing: Vec<String> = Vec::new();

        for service in pool.services() {
            let file = service.parent_file();
            let package = file.package_name();
            if !GATEWAY_PACKAGES.contains(&package) {
                continue;
            }
            for method in service.methods() {
                let path = format!("/{}.{}/{}", package, service.name(), method.name());
                if !table.entries.contains_key(&path) {
                    missing.push(path);
                }
            }
        }

        assert!(
            missing.is_empty(),
            "RPC methods missing (authorization) option: {missing:?}"
        );
    }

    #[test]
    fn no_duplicate_paths() {
        let paths: Vec<&str> = all_paths().collect();
        let mut seen = Vec::new();
        for path in &paths {
            assert!(
                !seen.contains(path),
                "duplicate path in descriptor auth table: {path}"
            );
            seen.push(path);
        }
    }

    #[test]
    fn authentication_only_rpc_must_be_explicitly_allowlisted() {
        assert!(validate_entry(AUTH_ONLY_METHODS[0], AuthMode::Bearer, None, None, None).is_ok());

        let err = validate_entry(FUTURE_RPC, AuthMode::Bearer, None, None, None)
            .expect_err("unlisted authentication-only RPC must be rejected");
        assert_eq!(
            err,
            "method /openshell.v1.OpenShell/FutureRpc: bearer method declares no role and no scope"
        );
    }

    #[test]
    fn bearer_rpc_requires_both_role_and_scope() {
        let missing_role = validate_entry(
            FUTURE_RPC,
            AuthMode::Bearer,
            None,
            None,
            Some("sandbox:read"),
        )
        .expect_err("missing role must be rejected");
        assert!(missing_role.ends_with("bearer method declares no role"));

        let missing_scope = validate_entry(FUTURE_RPC, AuthMode::Bearer, Some("user"), None, None)
            .expect_err("missing scope must be rejected");
        assert!(missing_scope.ends_with("bearer method declares no scope"));
    }

    #[test]
    fn workspace_and_global_roles_are_mutually_exclusive() {
        let err = validate_entry(
            FUTURE_RPC,
            AuthMode::Bearer,
            Some("admin"),
            Some("platform_admin"),
            Some("sandbox:write"),
        )
        .expect_err("multiple authorization layers must be rejected");
        assert!(err.ends_with("workspace_role and global_role are mutually exclusive"));
    }
}
