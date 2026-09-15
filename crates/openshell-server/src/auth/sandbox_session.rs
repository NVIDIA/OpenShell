// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable sandbox runtime identity used to authorize session JWTs.

use std::collections::HashMap;

use openshell_core::jwt::{AuthenticatedSandboxSession, CredentialEpoch, SessionJwtError};
use openshell_core::proto::{Sandbox, SandboxPhase};
use openshell_core::sandbox_generation::SandboxGenerationId;
use tonic::Status;
use uuid::Uuid;

use crate::persistence::Store;

pub const RUNTIME_GENERATION_ANNOTATION: &str = "internal.openshell.ai/runtime-generation";
pub const AUTH_EPOCH_ANNOTATION: &str = "internal.openshell.ai/auth-epoch";
pub const GATEWAY_TOKEN_ID_ANNOTATION: &str = "internal.openshell.ai/gateway-token-id";

/// The complete durable authorization identity for one sandbox runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedSandboxIdentity {
    pub runtime_generation: SandboxGenerationId,
    pub auth_epoch: CredentialEpoch,
    pub gateway_token_id: Uuid,
}

impl PersistedSandboxIdentity {
    pub fn new() -> Result<Self, SessionJwtError> {
        Ok(Self {
            runtime_generation: SandboxGenerationId::parse(Uuid::new_v4().to_string())
                .map_err(|_| SessionJwtError::InvalidRuntimeIdentity)?,
            auth_epoch: CredentialEpoch::new(1)?,
            gateway_token_id: Uuid::new_v4(),
        })
    }

    pub fn read(annotations: &HashMap<String, String>) -> Result<Self, SessionJwtError> {
        let runtime_generation = annotations
            .get(RUNTIME_GENERATION_ANNOTATION)
            .ok_or(SessionJwtError::MissingRuntimeIdentity)
            .and_then(|value| {
                SandboxGenerationId::parse(value.clone())
                    .map_err(|_| SessionJwtError::InvalidRuntimeIdentity)
            })?;
        let auth_epoch = annotations
            .get(AUTH_EPOCH_ANNOTATION)
            .ok_or(SessionJwtError::MissingRuntimeIdentity)?
            .parse::<u64>()
            .map_err(|_| SessionJwtError::InvalidCredentialEpoch)
            .and_then(CredentialEpoch::new)?;
        let gateway_token_id = annotations
            .get(GATEWAY_TOKEN_ID_ANNOTATION)
            .ok_or(SessionJwtError::MissingRuntimeIdentity)
            .and_then(|value| Uuid::parse_str(value).map_err(|_| SessionJwtError::InvalidJti))?;
        Ok(Self {
            runtime_generation,
            auth_epoch,
            gateway_token_id,
        })
    }

    pub fn write(&self, annotations: &mut HashMap<String, String>) {
        annotations.insert(
            RUNTIME_GENERATION_ANNOTATION.to_string(),
            self.runtime_generation.to_string(),
        );
        annotations.insert(
            AUTH_EPOCH_ANNOTATION.to_string(),
            self.auth_epoch.get().to_string(),
        );
        annotations.insert(
            GATEWAY_TOKEN_ID_ANNOTATION.to_string(),
            self.gateway_token_id.to_string(),
        );
    }

    #[must_use]
    pub fn next_gateway_token(&self) -> Self {
        Self {
            runtime_generation: self.runtime_generation.clone(),
            auth_epoch: self.auth_epoch,
            gateway_token_id: Uuid::new_v4(),
        }
    }
}

/// Load the authoritative runtime identity and compare it with a signed JWT.
///
/// Every gateway replica checks the persisted gateway-token ID in addition to
/// the runtime generation and authorization epoch. Refresh replaces that ID
/// with CAS, so an older bearer cannot rejoin the active credential lineage.
#[allow(clippy::result_large_err)]
async fn load_authorized(
    store: &Store,
    principal: &AuthenticatedSandboxSession,
) -> Result<(Sandbox, PersistedSandboxIdentity), Status> {
    let sandbox = store
        .get_message::<Sandbox>(principal.sandbox_id.as_str())
        .await
        .map_err(|error| Status::unavailable(format!("load sandbox identity failed: {error}")))?
        .ok_or_else(|| Status::unauthenticated("sandbox identity does not exist"))?;

    let phase = SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown);
    if !matches!(
        phase,
        SandboxPhase::Provisioning
            | SandboxPhase::Ready
            | SandboxPhase::Starting
            | SandboxPhase::Completed
            | SandboxPhase::Error
    ) {
        return Err(Status::failed_precondition(
            "sandbox runtime identity is not active",
        ));
    }

    let metadata = sandbox
        .metadata
        .as_ref()
        .ok_or_else(|| Status::unauthenticated("sandbox identity metadata is missing"))?;
    let identity = PersistedSandboxIdentity::read(&metadata.annotations)
        .map_err(|_| Status::unauthenticated("sandbox runtime identity is invalid"))?;
    let presented = (
        &principal.runtime_generation,
        principal.auth_epoch,
        principal.token_id,
    );
    let expected = (
        &identity.runtime_generation,
        identity.auth_epoch,
        identity.gateway_token_id,
    );
    if presented != expected {
        return Err(Status::unauthenticated(
            "gateway token does not match the active sandbox identity",
        ));
    }
    Ok((sandbox, identity))
}

#[allow(clippy::result_large_err)]
pub async fn authorize_persisted(
    store: &Store,
    principal: &AuthenticatedSandboxSession,
) -> Result<PersistedSandboxIdentity, Status> {
    load_authorized(store, principal)
        .await
        .map(|(_, identity)| identity)
}

/// Atomically consume the presented gateway bearer and install its successor.
///
/// A concurrent refresh or unrelated sandbox mutation causes the CAS to fail;
/// callers retry from freshly authenticated state. The old token is never
/// accepted after a successful update on any gateway replica.
#[allow(clippy::result_large_err)]
pub async fn rotate_gateway_token(
    store: &Store,
    principal: &AuthenticatedSandboxSession,
    next: &PersistedSandboxIdentity,
) -> Result<PersistedSandboxIdentity, Status> {
    let (sandbox, current) = load_authorized(store, principal).await?;
    if next.runtime_generation != current.runtime_generation
        || next.auth_epoch != current.auth_epoch
        || next.gateway_token_id == current.gateway_token_id
    {
        return Err(Status::internal("gateway token successor is invalid"));
    }
    let metadata = sandbox
        .metadata
        .as_ref()
        .ok_or_else(|| Status::unauthenticated("sandbox identity metadata is missing"))?;
    store
        .update_message_cas::<Sandbox, _>(
            principal.sandbox_id.as_str(),
            metadata.resource_version,
            |sandbox| {
                if let Some(metadata) = sandbox.metadata.as_mut() {
                    next.write(&mut metadata.annotations);
                }
            },
        )
        .await
        .map_err(|error| Status::aborted(format!("rotate gateway token: {error}")))?;
    Ok(next.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::jwt::SandboxId;
    use openshell_core::proto::SandboxStatus;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use uuid::Uuid;

    async fn persist_sandbox(store: &Store, phase: SandboxPhase) {
        let identity = PersistedSandboxIdentity {
            runtime_generation: SandboxGenerationId::parse("generation-a")
                .expect("runtime generation"),
            auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
            gateway_token_id: Uuid::from_u128(1),
        };
        let mut metadata = ObjectMeta {
            id: "sandbox-a".to_string(),
            name: "sandbox-a".to_string(),
            workspace: "default".to_string(),
            ..Default::default()
        };
        identity.write(&mut metadata.annotations);
        let sandbox = Sandbox {
            metadata: Some(metadata),
            status: Some(SandboxStatus {
                phase: phase as i32,
                ..Default::default()
            }),
            ..Default::default()
        };
        store.put_message(&sandbox).await.expect("persist sandbox");
    }

    fn principal(auth_epoch: u64, token_id: Uuid) -> AuthenticatedSandboxSession {
        AuthenticatedSandboxSession {
            sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox ID"),
            runtime_generation: SandboxGenerationId::parse("generation-a")
                .expect("runtime generation"),
            auth_epoch: CredentialEpoch::new(auth_epoch).expect("auth epoch"),
            token_id,
            issued_at: 1,
            expires_at: 2,
        }
    }

    #[tokio::test]
    async fn shared_identity_authorizes_every_replica_and_revokes_old_epochs() {
        let store = Store::connect("sqlite::memory:").await.expect("store");
        persist_sandbox(&store, SandboxPhase::Ready).await;

        authorize_persisted(&store, &principal(1, Uuid::from_u128(1)))
            .await
            .expect("first replica authorizes from persistence");
        authorize_persisted(&store, &principal(1, Uuid::from_u128(1)))
            .await
            .expect("second replica authorizes without local state");

        let error = authorize_persisted(&store, &principal(1, Uuid::from_u128(2)))
            .await
            .expect_err("a different token lineage must be rejected");
        assert_eq!(error.code(), tonic::Code::Unauthenticated);

        store
            .update_message_cas::<Sandbox, _>("sandbox-a", 0, |sandbox| {
                let next = PersistedSandboxIdentity {
                    runtime_generation: SandboxGenerationId::parse("generation-a")
                        .expect("runtime generation"),
                    auth_epoch: CredentialEpoch::new(2).expect("auth epoch"),
                    gateway_token_id: Uuid::from_u128(2),
                };
                next.write(&mut sandbox.metadata.as_mut().expect("metadata").annotations);
            })
            .await
            .expect("advance auth epoch");

        let error = authorize_persisted(&store, &principal(1, Uuid::from_u128(1)))
            .await
            .expect_err("old epoch must be revoked on every replica");
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        authorize_persisted(&store, &principal(2, Uuid::from_u128(2)))
            .await
            .expect("new epoch is active");

        store
            .update_message_cas::<Sandbox, _>("sandbox-a", 0, |sandbox| {
                sandbox.set_phase(SandboxPhase::Stopped as i32);
            })
            .await
            .expect("stop sandbox");
        let error = authorize_persisted(&store, &principal(2, Uuid::from_u128(2)))
            .await
            .expect_err("stopped runtime must reject its token");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn terminal_runtime_remains_authorized_for_exit_delivery() {
        for phase in [SandboxPhase::Completed, SandboxPhase::Error] {
            let store = Store::connect("sqlite::memory:").await.expect("store");
            persist_sandbox(&store, phase).await;

            authorize_persisted(&store, &principal(1, Uuid::from_u128(1)))
                .await
                .expect("terminal runtime can finish delivering exit state");
        }
    }

    #[tokio::test]
    async fn rotating_gateway_token_revokes_its_predecessor() {
        let store = Store::connect("sqlite::memory:").await.expect("store");
        persist_sandbox(&store, SandboxPhase::Ready).await;
        let first = principal(1, Uuid::from_u128(1));

        let expected = PersistedSandboxIdentity {
            runtime_generation: first.runtime_generation.clone(),
            auth_epoch: first.auth_epoch,
            gateway_token_id: Uuid::from_u128(2),
        };
        let next = rotate_gateway_token(&store, &first, &expected)
            .await
            .expect("rotate current gateway token");
        assert_ne!(next.gateway_token_id, first.token_id);

        let error = authorize_persisted(&store, &first)
            .await
            .expect_err("consumed gateway token must be rejected");
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        authorize_persisted(&store, &principal(1, next.gateway_token_id))
            .await
            .expect("successor gateway token is current");
    }
}
