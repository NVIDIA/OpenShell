// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide OCSF identity for gateway-origin events.
//!
//! Gateway events are emitted from places with no access to the server config
//! (the TLS reload watcher, the service router), so the identity is resolved
//! once at startup rather than threaded through all of them.

use std::sync::OnceLock;

use openshell_ocsf::{EventOrigin, SandboxContext};

/// Identity shared by every gateway-origin OCSF event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayIdentity {
    /// Operator-assigned gateway name, shared across replicas of one install.
    pub name: String,
    /// Per-replica hostname (the pod name under Kubernetes).
    pub hostname: String,
}

static IDENTITY: OnceLock<GatewayIdentity> = OnceLock::new();

/// Initialise the process-wide gateway identity.
///
/// Returns `false` if it was already set; the caller may log and continue.
pub fn set_identity(identity: GatewayIdentity) -> bool {
    IDENTITY.set(identity).is_ok()
}

/// Return the gateway identity, falling back to placeholders when unset (in
/// tests, and in any code path that runs before startup completes).
#[must_use]
pub fn identity() -> GatewayIdentity {
    IDENTITY.get().cloned().unwrap_or_else(|| GatewayIdentity {
        name: openshell_core::config::DEFAULT_GATEWAY_NAME.to_string(),
        hostname: "openshell-gateway".to_string(),
    })
}

/// Build the OCSF context for a gateway-origin event.
///
/// `sandbox_id` and `sandbox_name` describe the sandbox the event is *about*,
/// and may be empty. The emitting device is always the gateway.
#[must_use]
pub fn context(sandbox_id: &str, sandbox_name: &str) -> SandboxContext {
    let identity = identity();
    SandboxContext {
        sandbox_id: sandbox_id.to_string(),
        sandbox_name: sandbox_name.to_string(),
        container_image: String::new(),
        hostname: identity.hostname,
        product_version: openshell_core::VERSION.to_string(),
        proxy_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        proxy_port: 0,
        origin: EventOrigin::Gateway {
            name: identity.name,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_marks_events_as_gateway_origin() {
        let ctx = context("sb-1", "agent-01");

        assert!(matches!(ctx.origin, EventOrigin::Gateway { .. }));
        assert_eq!(ctx.sandbox_id, "sb-1");
        assert_eq!(ctx.sandbox_name, "agent-01");
    }

    #[test]
    fn gateway_context_produces_gateway_product_and_no_container() {
        let ctx = context("", "");

        assert_eq!(ctx.metadata(&[]).product.name, "OpenShell Gateway");
        assert!(ctx.container().is_none());
    }

    #[test]
    fn identity_falls_back_when_unset() {
        let identity = identity();
        assert!(!identity.name.is_empty());
        assert!(!identity.hostname.is_empty());
    }
}
