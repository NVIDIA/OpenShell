// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Transport-neutral authentication for `OpenShell` Sandbox Protocol connections.

use std::sync::Mutex;

use openshell_core::SandboxSessionId;
use openshell_core::jwt::{
    AuthenticatedSandboxSession, CredentialEpoch, SandboxId, SessionJwtError, SessionJwtVerifier,
};
use tonic::metadata::MetadataMap;
use uuid::Uuid;

/// Server-local identity assigned after a byte stream completes TLS.
///
/// It cannot be supplied by a compute driver or workload. Protocol handlers use
/// it to bind authenticated requests to the connection that performed attach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SandboxConnectionId(Uuid);

impl SandboxConnectionId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SandboxConnectionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Principal returned only after strict bearer validation and identity binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxProtocolPrincipal {
    connection_id: SandboxConnectionId,
    session: AuthenticatedSandboxSession,
}

impl SandboxProtocolPrincipal {
    #[must_use]
    pub const fn connection_id(&self) -> SandboxConnectionId {
        self.connection_id
    }

    #[must_use]
    pub const fn session(&self) -> &AuthenticatedSandboxSession {
        &self.session
    }
}

/// Validates Sandbox Protocol metadata without depending on its byte transport.
pub struct SandboxProtocolAuthenticator {
    verifier: SessionJwtVerifier,
    expected_sandbox_id: SandboxId,
    expected_session_id: SandboxSessionId,
}

impl std::fmt::Debug for SandboxProtocolAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxProtocolAuthenticator")
            .field("verifier", &self.verifier)
            .field("expected_sandbox_id", &self.expected_sandbox_id)
            .field("expected_session_id", &self.expected_session_id)
            .finish()
    }
}

impl SandboxProtocolAuthenticator {
    #[must_use]
    pub const fn new(
        verifier: SessionJwtVerifier,
        expected_sandbox_id: SandboxId,
        expected_session_id: SandboxSessionId,
    ) -> Self {
        Self {
            verifier,
            expected_sandbox_id,
            expected_session_id,
        }
    }

    pub fn authenticate(
        &self,
        connection_id: SandboxConnectionId,
        metadata: &MetadataMap,
    ) -> Result<SandboxProtocolPrincipal, SandboxAuthError> {
        let mut values = metadata.get_all("authorization").iter();
        let value = values.next().ok_or(SandboxAuthError::MissingBearer)?;
        if values.next().is_some() {
            return Err(SandboxAuthError::DuplicateBearer);
        }
        let value = value
            .to_str()
            .map_err(|_| SandboxAuthError::InvalidBearer)?;
        let token = value
            .strip_prefix("Bearer ")
            .filter(|token| !token.is_empty() && !token.chars().any(char::is_whitespace))
            .ok_or(SandboxAuthError::InvalidBearer)?;
        let session = self.verifier.verify(token)?;
        if session.sandbox_id != self.expected_sandbox_id {
            return Err(SandboxAuthError::WrongSandbox);
        }
        if session.session_id != self.expected_session_id {
            return Err(SandboxAuthError::WrongSession);
        }
        Ok(SandboxProtocolPrincipal {
            connection_id,
            session,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActiveConnection {
    id: SandboxConnectionId,
    epoch: CredentialEpoch,
}

#[derive(Debug, Default)]
struct ConnectionState {
    active: Option<ActiveConnection>,
    highest_epoch: Option<CredentialEpoch>,
    terminal: bool,
}

/// Enforces the one-active-connection and monotonically increasing epoch rules.
#[derive(Debug, Default)]
pub struct SandboxConnectionRegistry {
    state: Mutex<ConnectionState>,
}

impl SandboxConnectionRegistry {
    /// Attach a fully authenticated connection. The returned ID identifies the
    /// older connection that must be closed after the replacement is committed.
    pub fn attach(
        &self,
        principal: &SandboxProtocolPrincipal,
    ) -> Result<Option<SandboxConnectionId>, SandboxAuthError> {
        let epoch = principal
            .session
            .credential_epoch
            .ok_or(SandboxAuthError::MissingCredentialEpoch)?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.terminal {
            return Err(SandboxAuthError::TerminalSession);
        }
        if let Some(active) = state.active {
            if active.id == principal.connection_id && active.epoch == epoch {
                return Ok(None);
            }
            if epoch <= active.epoch {
                return Err(SandboxAuthError::StaleCredentialEpoch);
            }
            state.highest_epoch = Some(epoch);
            state.active = Some(ActiveConnection {
                id: principal.connection_id,
                epoch,
            });
            return Ok(Some(active.id));
        }
        if state.highest_epoch.is_some_and(|highest| epoch < highest) {
            return Err(SandboxAuthError::StaleCredentialEpoch);
        }
        state.highest_epoch = Some(epoch);
        state.active = Some(ActiveConnection {
            id: principal.connection_id,
            epoch,
        });
        Ok(None)
    }

    pub fn require_active(
        &self,
        principal: &SandboxProtocolPrincipal,
    ) -> Result<(), SandboxAuthError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.terminal {
            return Err(SandboxAuthError::TerminalSession);
        }
        if state
            .active
            .is_none_or(|active| active.id != principal.connection_id)
        {
            return Err(SandboxAuthError::ConnectionNotAttached);
        }
        Ok(())
    }

    pub fn disconnect(&self, connection_id: SandboxConnectionId) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state
            .active
            .is_some_and(|active| active.id == connection_id)
        {
            state.active = None;
        }
    }

    pub fn mark_terminal(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.terminal = true;
        state.active = None;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SandboxAuthError {
    #[error("authorization metadata is missing")]
    MissingBearer,
    #[error("authorization metadata must occur exactly once")]
    DuplicateBearer,
    #[error("authorization metadata is not a valid bearer credential")]
    InvalidBearer,
    #[error("sandbox JWT validation failed: {0}")]
    Jwt(#[from] SessionJwtError),
    #[error("authenticated sandbox identity does not match this runtime")]
    WrongSandbox,
    #[error("authenticated sandbox session does not match this runtime")]
    WrongSession,
    #[error("Sandbox Protocol token is missing its credential epoch")]
    MissingCredentialEpoch,
    #[error("Sandbox Protocol credential epoch is stale or already active")]
    StaleCredentialEpoch,
    #[error("Sandbox Protocol connection has not completed attach")]
    ConnectionNotAttached,
    #[error("sandbox session is terminal")]
    TerminalSession,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use openshell_core::jwt::{
        DEFAULT_SESSION_TOKEN_TTL, JwtClock, SandboxSessionIdentity, SessionJwtIssuer,
        SessionTokenProfile, SessionVerificationKey,
    };
    use rcgen::{KeyPair, PKCS_ED25519};

    use super::*;

    #[derive(Debug)]
    struct FixedClock;

    impl JwtClock for FixedClock {
        fn now_unix_seconds(&self) -> i64 {
            1_900_000_000
        }
    }

    fn fixture(
        epoch: u64,
    ) -> (
        SandboxProtocolAuthenticator,
        openshell_core::jwt::MintedSessionToken,
    ) {
        let key = KeyPair::generate_for(&PKCS_ED25519).expect("generate key");
        let public_key_pem = key.public_key_pem().into_bytes();
        let clock: Arc<dyn JwtClock> = Arc::new(FixedClock);
        let sandbox_id = SandboxId::parse("sandbox-a").expect("sandbox ID");
        let session_id = SandboxSessionId::new();
        let issuer = SessionJwtIssuer::from_ed25519_pem(
            key.serialize_pem().as_bytes(),
            "current",
            "test",
            DEFAULT_SESSION_TOKEN_TTL,
            clock.clone(),
        )
        .expect("issuer");
        let verifier = SessionJwtVerifier::new(
            "test",
            SessionTokenProfile::Sandbox,
            [SessionVerificationKey {
                key_id: "current".to_string(),
                public_key_pem,
            }],
            clock,
        )
        .expect("verifier");
        let token = issuer
            .mint_pair(
                &SandboxSessionIdentity {
                    sandbox_id: sandbox_id.clone(),
                    session_id,
                },
                CredentialEpoch::new(epoch).expect("epoch"),
            )
            .expect("token pair")
            .sandbox;
        (
            SandboxProtocolAuthenticator::new(verifier, sandbox_id, session_id),
            token,
        )
    }

    fn metadata(token: &str) -> MetadataMap {
        let mut metadata = MetadataMap::new();
        metadata.insert(
            "authorization",
            format!("Bearer {token}").parse().expect("metadata value"),
        );
        metadata
    }

    #[test]
    fn bearer_metadata_must_occur_exactly_once() {
        let (authenticator, token) = fixture(1);
        assert_eq!(
            authenticator.authenticate(SandboxConnectionId::new(), &MetadataMap::new()),
            Err(SandboxAuthError::MissingBearer)
        );
        let mut duplicate = metadata(token.token.expose_secret());
        duplicate.append(
            "authorization",
            format!("Bearer {}", token.token.expose_secret())
                .parse()
                .expect("metadata value"),
        );
        assert_eq!(
            authenticator.authenticate(SandboxConnectionId::new(), &duplicate),
            Err(SandboxAuthError::DuplicateBearer)
        );
    }

    #[test]
    fn reconnect_requires_disconnect_and_terminal_is_final() {
        let (first_authenticator, first_token) = fixture(1);
        let first_id = SandboxConnectionId::new();
        let first = first_authenticator
            .authenticate(first_id, &metadata(first_token.token.expose_secret()))
            .expect("first principal");
        let registry = SandboxConnectionRegistry::default();
        assert_eq!(registry.attach(&first), Ok(None));
        assert_eq!(registry.attach(&first), Ok(None));

        registry.disconnect(first_id);
        assert_eq!(registry.attach(&first), Ok(None));
        registry.mark_terminal();
        assert_eq!(
            registry.require_active(&first),
            Err(SandboxAuthError::TerminalSession)
        );
        assert_eq!(
            registry.attach(&first),
            Err(SandboxAuthError::TerminalSession)
        );
    }
}
