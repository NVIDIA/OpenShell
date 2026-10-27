// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

/// Workspace-scoped storage ownership. Kinds are explicit at the Rust boundary;
/// existing drivers still receive their original provider-shaped scope fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretOwner<'a> {
    pub workspace: &'a str,
    pub kind: SecretOwnerKind<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretOwnerKind<'a> {
    Provider {
        id: &'a str,
        name: &'a str,
    },
    Sandbox {
        id: &'a str,
    },
    /// Gateway-owned browser application session storage identity.
    ApplicationSession {
        id: &'a str,
    },
    /// Launch material is owned by a sandbox assignment, not the host/route.
    SupervisorInstance {
        sandbox_id: &'a str,
    },
}

pub struct LegacyScope<'a> {
    pub provider: Cow<'a, str>,
    pub workspace: &'a str,
    pub id: &'a str,
}

impl<'a> SecretOwner<'a> {
    pub fn provider(workspace: &'a str, id: &'a str, name: &'a str) -> Self {
        Self {
            workspace,
            kind: SecretOwnerKind::Provider { id, name },
        }
    }

    pub fn sandbox(workspace: &'a str, id: &'a str) -> Self {
        Self {
            workspace,
            kind: SecretOwnerKind::Sandbox { id },
        }
    }

    pub fn supervisor_instance(workspace: &'a str, sandbox_id: &'a str) -> Self {
        Self {
            workspace,
            kind: SecretOwnerKind::SupervisorInstance { sandbox_id },
        }
    }

    /// `id` is the existing `service-session-<session ID>` storage identity.
    pub fn application_session(workspace: &'a str, id: &'a str) -> Self {
        Self {
            workspace,
            kind: SecretOwnerKind::ApplicationSession { id },
        }
    }

    pub(crate) fn legacy_scope(self) -> LegacyScope<'a> {
        let (provider, id) = match self.kind {
            SecretOwnerKind::Provider { id, name } => (Cow::Borrowed(name), id),
            SecretOwnerKind::ApplicationSession { id } => {
                (Cow::Borrowed("gateway-service-session"), id)
            }
            SecretOwnerKind::Sandbox { id } => (Cow::Owned(format!("sandbox-ssh-{id}")), id),
            SecretOwnerKind::SupervisorInstance { sandbox_id } => (
                Cow::Owned(format!("sandbox-instance-{sandbox_id}")),
                sandbox_id,
            ),
        };
        LegacyScope {
            provider,
            workspace: self.workspace,
            id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_owner_fields_are_unchanged() {
        for (owner, expected_name, expected_id) in [
            (
                SecretOwner::provider("workspace-a", "provider-id", "provider-name"),
                "provider-name",
                "provider-id",
            ),
            (
                SecretOwner::application_session("workspace-a", "service-session-session-id"),
                "gateway-service-session",
                "service-session-session-id",
            ),
            (
                SecretOwner::sandbox("workspace-a", "sandbox-id"),
                "sandbox-ssh-sandbox-id",
                "sandbox-id",
            ),
            (
                SecretOwner::supervisor_instance("workspace-a", "sandbox-id"),
                "sandbox-instance-sandbox-id",
                "sandbox-id",
            ),
        ] {
            let scope = owner.legacy_scope();
            assert_eq!(scope.workspace, "workspace-a");
            assert_eq!(scope.provider, expected_name);
            assert_eq!(scope.id, expected_id);
        }
    }
}
