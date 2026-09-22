// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable sandbox runtime identity used to authorize session JWTs.

use std::collections::HashMap;

use openshell_core::jwt::{AuthenticatedSandboxSession, CredentialEpoch, SessionJwtError};
use openshell_core::proto::SandboxPhase;
use openshell_core::sandbox_generation::SandboxGenerationId;
use sha2::{Digest as _, Sha256};
use tonic::Status;
use uuid::Uuid;

use crate::persistence::Store;
use crate::storage_proto::StoredSandbox as Sandbox;

pub const RUNTIME_GENERATION_ANNOTATION: &str = "internal.openshell.ai/runtime-generation";
pub const AUTH_EPOCH_ANNOTATION: &str = "internal.openshell.ai/auth-epoch";
pub const GATEWAY_TOKEN_ID_ANNOTATION: &str = "internal.openshell.ai/gateway-token-id";
const PREVIOUS_GATEWAY_TOKEN_ID_ANNOTATION: &str =
    "internal.openshell.ai/previous-gateway-token-id";
const REFRESH_REPLAY_UNTIL_ANNOTATION: &str = "internal.openshell.ai/refresh-replay-until";
const REFRESH_REQUEST_HASH_ANNOTATION: &str = "internal.openshell.ai/refresh-request-hash";
const REFRESH_ISSUED_AT_ANNOTATION: &str = "internal.openshell.ai/refresh-issued-at";
const REFRESH_ROTATION_ID_ANNOTATION: &str = "internal.openshell.ai/refresh-rotation-id";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshRequestHash(String);

impl RefreshRequestHash {
    #[must_use]
    pub fn from_extension_services(names: &[String]) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"openshell-refresh-v1\0");
        for name in names {
            let length = u64::try_from(name.len()).unwrap_or(u64::MAX);
            digest.update(length.to_be_bytes());
            digest.update(name.as_bytes());
        }
        Self(hex::encode(digest.finalize()))
    }

    fn parse(value: String) -> Result<Self, SessionJwtError> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(SessionJwtError::InvalidRuntimeIdentity);
        }
        Ok(Self(value))
    }
}

impl std::fmt::Display for RefreshRequestHash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayRefreshReplay {
    pub previous_gateway_token_id: Uuid,
    pub request_hash: RefreshRequestHash,
    pub replay_until: i64,
    pub issued_at: i64,
    pub rotation_id: Uuid,
}

impl GatewayRefreshReplay {
    #[must_use]
    pub fn sandbox_token_id(&self) -> Uuid {
        derive_token_id(self.rotation_id, b"sandbox")
    }

    #[must_use]
    pub fn extension_token_id(&self, service_name: &str, audience: &str) -> Uuid {
        let mut label = Vec::with_capacity(service_name.len() + audience.len() + 11);
        label.extend_from_slice(b"extension\0");
        label.extend_from_slice(service_name.as_bytes());
        label.push(0);
        label.extend_from_slice(audience.as_bytes());
        derive_token_id(self.rotation_id, &label)
    }
}

fn derive_token_id(rotation_id: Uuid, label: &[u8]) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"openshell-refresh-token-v1\0");
    digest.update(rotation_id.as_bytes());
    digest.update(label);
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

/// The complete durable authorization identity for one sandbox runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedSandboxIdentity {
    pub runtime_generation: SandboxGenerationId,
    pub auth_epoch: CredentialEpoch,
    pub gateway_token_id: Uuid,
    pub refresh_replay: Option<GatewayRefreshReplay>,
}

impl PersistedSandboxIdentity {
    pub fn new() -> Result<Self, SessionJwtError> {
        Ok(Self {
            runtime_generation: SandboxGenerationId::parse(Uuid::new_v4().to_string())
                .map_err(|_| SessionJwtError::InvalidRuntimeIdentity)?,
            auth_epoch: CredentialEpoch::new(1)?,
            gateway_token_id: Uuid::new_v4(),
            refresh_replay: None,
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
        let replay_values = (
            annotations.get(PREVIOUS_GATEWAY_TOKEN_ID_ANNOTATION),
            annotations.get(REFRESH_REQUEST_HASH_ANNOTATION),
            annotations.get(REFRESH_REPLAY_UNTIL_ANNOTATION),
            annotations.get(REFRESH_ISSUED_AT_ANNOTATION),
            annotations.get(REFRESH_ROTATION_ID_ANNOTATION),
        );
        let refresh_replay = match replay_values {
            (None, None, None, None, None) => None,
            (
                Some(previous),
                Some(request_hash),
                Some(replay_until),
                Some(issued_at),
                Some(rotation_id),
            ) => {
                let issued_at = issued_at
                    .parse::<i64>()
                    .map_err(|_| SessionJwtError::InvalidRuntimeIdentity)?;
                let replay_until = replay_until
                    .parse::<i64>()
                    .map_err(|_| SessionJwtError::InvalidRuntimeIdentity)?;
                if issued_at <= 0 || replay_until < issued_at {
                    return Err(SessionJwtError::InvalidRuntimeIdentity);
                }
                Some(GatewayRefreshReplay {
                    previous_gateway_token_id: Uuid::parse_str(previous)
                        .map_err(|_| SessionJwtError::InvalidJti)?,
                    request_hash: RefreshRequestHash::parse(request_hash.clone())?,
                    replay_until,
                    issued_at,
                    rotation_id: Uuid::parse_str(rotation_id)
                        .map_err(|_| SessionJwtError::InvalidJti)?,
                })
            }
            _ => return Err(SessionJwtError::InvalidRuntimeIdentity),
        };
        Ok(Self {
            runtime_generation,
            auth_epoch,
            gateway_token_id,
            refresh_replay,
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
        if let Some(replay) = &self.refresh_replay {
            annotations.insert(
                PREVIOUS_GATEWAY_TOKEN_ID_ANNOTATION.to_string(),
                replay.previous_gateway_token_id.to_string(),
            );
            annotations.insert(
                REFRESH_REQUEST_HASH_ANNOTATION.to_string(),
                replay.request_hash.to_string(),
            );
            annotations.insert(
                REFRESH_REPLAY_UNTIL_ANNOTATION.to_string(),
                replay.replay_until.to_string(),
            );
            annotations.insert(
                REFRESH_ISSUED_AT_ANNOTATION.to_string(),
                replay.issued_at.to_string(),
            );
            annotations.insert(
                REFRESH_ROTATION_ID_ANNOTATION.to_string(),
                replay.rotation_id.to_string(),
            );
        } else {
            for key in [
                PREVIOUS_GATEWAY_TOKEN_ID_ANNOTATION,
                REFRESH_REQUEST_HASH_ANNOTATION,
                REFRESH_REPLAY_UNTIL_ANNOTATION,
                REFRESH_ISSUED_AT_ANNOTATION,
                REFRESH_ROTATION_ID_ANNOTATION,
            ] {
                annotations.remove(key);
            }
        }
    }

    #[must_use]
    pub fn next_gateway_token(
        &self,
        request_hash: RefreshRequestHash,
        issued_at: i64,
        replay_grace_seconds: i64,
    ) -> Self {
        let rotation_id = Uuid::new_v4();
        Self {
            runtime_generation: self.runtime_generation.clone(),
            auth_epoch: self.auth_epoch,
            gateway_token_id: derive_token_id(rotation_id, b"gateway"),
            refresh_replay: Some(GatewayRefreshReplay {
                previous_gateway_token_id: self.gateway_token_id,
                request_hash,
                replay_until: issued_at.saturating_add(replay_grace_seconds),
                issued_at,
                rotation_id,
            }),
        }
    }
}

#[allow(clippy::result_large_err)]
async fn load_identity(
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
    if principal.runtime_generation != identity.runtime_generation
        || principal.auth_epoch != identity.auth_epoch
    {
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
    let (_, identity) = load_identity(store, principal).await?;
    if principal.token_id != identity.gateway_token_id {
        return Err(Status::unauthenticated(
            "gateway token does not match the active sandbox identity",
        ));
    }
    Ok(identity)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshAuthorization {
    Current(PersistedSandboxIdentity),
    Replay(PersistedSandboxIdentity),
}

#[allow(clippy::result_large_err)]
pub async fn authorize_refresh(
    store: &Store,
    principal: &AuthenticatedSandboxSession,
    request_hash: &RefreshRequestHash,
    now: i64,
) -> Result<RefreshAuthorization, Status> {
    let (_, identity) = load_identity(store, principal).await?;
    if principal.token_id == identity.gateway_token_id {
        return Ok(RefreshAuthorization::Current(identity));
    }
    let Some(replay) = &identity.refresh_replay else {
        return Err(Status::unauthenticated(
            "gateway token does not match the active sandbox identity",
        ));
    };
    if principal.token_id != replay.previous_gateway_token_id
        || request_hash != &replay.request_hash
        || now > replay.replay_until
    {
        return Err(Status::unauthenticated(
            "gateway refresh retry does not match the active lineage",
        ));
    }
    Ok(RefreshAuthorization::Replay(identity))
}

/// Atomically consume the presented gateway bearer and install its successor.
///
/// A concurrent refresh or unrelated sandbox mutation causes the CAS to fail.
/// The consumed token remains eligible only for the bounded, request-matched
/// retry recorded in `next`; ordinary RPCs reject it immediately.
#[allow(clippy::result_large_err)]
pub async fn rotate_gateway_token(
    store: &Store,
    principal: &AuthenticatedSandboxSession,
    next: &PersistedSandboxIdentity,
) -> Result<PersistedSandboxIdentity, Status> {
    let (sandbox, current) = load_identity(store, principal).await?;
    if principal.token_id != current.gateway_token_id {
        return Err(Status::unauthenticated(
            "gateway token does not match the active sandbox identity",
        ));
    }
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
            refresh_replay: None,
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
                    refresh_replay: None,
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
    async fn rotating_gateway_token_allows_one_bounded_idempotent_retry() {
        let store = Store::connect("sqlite::memory:").await.expect("store");
        persist_sandbox(&store, SandboxPhase::Ready).await;
        let first = principal(1, Uuid::from_u128(1));

        let request_hash = RefreshRequestHash::from_extension_services(&[]);
        let expected = authorize_persisted(&store, &first)
            .await
            .expect("current identity")
            .next_gateway_token(request_hash.clone(), 100, 30);
        let next = rotate_gateway_token(&store, &first, &expected)
            .await
            .expect("rotate current gateway token");
        assert_ne!(next.gateway_token_id, first.token_id);

        let error = authorize_persisted(&store, &first)
            .await
            .expect_err("consumed gateway token must be rejected");
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert!(matches!(
            authorize_refresh(&store, &first, &request_hash, 130)
                .await
                .expect("immediate predecessor may retry"),
            RefreshAuthorization::Replay(_)
        ));
        let error = authorize_refresh(&store, &first, &request_hash, 131)
            .await
            .expect_err("predecessor retry must expire");
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        authorize_persisted(&store, &principal(1, next.gateway_token_id))
            .await
            .expect("successor gateway token is current");
    }
}
