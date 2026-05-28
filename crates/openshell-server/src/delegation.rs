// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox delegation bindings for on-behalf-of token exchange.
//!
//! Lane 3 needs a stable server-side record of which signed-in user created a
//! sandbox and which inbound bearer token was available at that time. This
//! module owns that persisted binding so later broker code can exchange the
//! user token for a delegated downstream token without storing long-lived
//! user material inside the sandbox itself.

use crate::persistence::{ObjectType, Store, current_time_ms};
use openshell_core::proto::{Sandbox, StoredSandboxDelegationBinding};
use openshell_core::{ObjectId, ObjectName};
use tonic::Status;

impl ObjectType for StoredSandboxDelegationBinding {
    fn object_type() -> &'static str {
        "sandbox_delegation_binding"
    }
}

pub fn binding_name(sandbox_id: &str) -> String {
    format!("sandbox-delegation-{sandbox_id}")
}

pub fn new_binding(
    sandbox: &Sandbox,
    subject: &str,
    display_name: Option<&str>,
    identity_provider: &str,
    access_token: &str,
    scopes: &[String],
) -> Result<StoredSandboxDelegationBinding, Status> {
    let sandbox_id = sandbox.object_id().trim();
    let sandbox_name = sandbox.object_name().trim();
    if sandbox_id.is_empty() {
        return Err(Status::internal("sandbox is missing metadata.id"));
    }
    if sandbox_name.is_empty() {
        return Err(Status::internal("sandbox is missing metadata.name"));
    }
    if subject.trim().is_empty() {
        return Err(Status::invalid_argument("delegation subject is required"));
    }
    if access_token.trim().is_empty() {
        return Err(Status::invalid_argument(
            "delegation access token is required",
        ));
    }

    let now_ms = current_time_ms();
    Ok(StoredSandboxDelegationBinding {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: binding_name(sandbox_id),
            created_at_ms: now_ms,
            labels: std::collections::HashMap::new(),
            resource_version: 0,
        }),
        sandbox_id: sandbox_id.to_string(),
        sandbox_name: sandbox_name.to_string(),
        subject: subject.trim().to_string(),
        display_name: display_name.unwrap_or_default().trim().to_string(),
        identity_provider: identity_provider.trim().to_string(),
        access_token: access_token.trim().to_string(),
        scopes: scopes.to_vec(),
        captured_at_ms: now_ms,
    })
}

pub async fn put_binding(
    store: &Store,
    binding: &StoredSandboxDelegationBinding,
) -> Result<(), Status> {
    store
        .put_scoped_message(binding, &binding.sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("persist sandbox delegation binding failed: {e}")))
}

#[cfg_attr(not(test), allow(dead_code))]
pub async fn get_binding(
    store: &Store,
    sandbox_id: &str,
) -> Result<Option<StoredSandboxDelegationBinding>, Status> {
    store
        .get_message_by_name::<StoredSandboxDelegationBinding>(&binding_name(sandbox_id))
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox delegation binding failed: {e}")))
}

pub async fn delete_binding(store: &Store, sandbox_id: &str) -> Result<bool, Status> {
    store
        .delete_by_name(
            StoredSandboxDelegationBinding::object_type(),
            &binding_name(sandbox_id),
        )
        .await
        .map_err(|e| Status::internal(format!("delete sandbox delegation binding failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    fn sandbox() -> Sandbox {
        Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-123".to_string(),
                name: "demo-sandbox".to_string(),
                created_at_ms: 0,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: None,
            status: None,
            phase: 0,
            current_policy_version: 0,
        }
    }

    #[tokio::test]
    async fn binding_round_trip_works() {
        let store = Store::connect("sqlite::memory:")
            .await
            .expect("in-memory store");
        let sandbox = sandbox();
        let binding = new_binding(
            &sandbox,
            "user-123",
            Some("alex"),
            "oidc",
            "token-value",
            &["sandbox:write".to_string()],
        )
        .expect("binding");

        put_binding(&store, &binding)
            .await
            .expect("persist binding");
        let loaded = get_binding(&store, "sb-123")
            .await
            .expect("load binding")
            .expect("binding present");
        assert_eq!(loaded.subject, "user-123");
        assert_eq!(loaded.sandbox_name, "demo-sandbox");
        assert_eq!(loaded.identity_provider, "oidc");
        assert_eq!(loaded.access_token, "token-value");

        let deleted = delete_binding(&store, "sb-123")
            .await
            .expect("delete binding");
        assert!(deleted);
        assert!(
            get_binding(&store, "sb-123")
                .await
                .expect("load binding")
                .is_none()
        );
    }
}
