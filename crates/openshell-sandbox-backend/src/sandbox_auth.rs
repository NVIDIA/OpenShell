// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Transport-neutral authentication for `OpenShell` Sandbox Protocol connections.
//!
//! A runtime generation is owned by one supervisor process at a time. The
//! owner's term is the credential epoch the runtime currently accepts, and
//! the owner's process identity is pinned at its first attach. A different
//! process can take over only with a gateway-signed takeover grant for a
//! strictly higher epoch, naming that process; the replacement is staged
//! while the current owner stays active and is promoted only when the
//! replacement confirms, which advances the accepted epoch, moves the pin,
//! and retires every connection of the previous term. Credentials of lower
//! epochs are rejected from then on. Ordinary credential renewal keeps the
//! epoch and cannot move ownership.

use std::str::FromStr as _;
use std::sync::Mutex;

use openshell_core::jwt::{
    AuthenticatedSandboxSession, CredentialEpoch, SandboxId, SessionJwtError, SessionJwtVerifier,
    VerifiedSupervisorTakeover,
};
use openshell_core::sandbox_generation::SandboxGenerationId;
use tonic::metadata::MetadataMap;
use uuid::Uuid;

use crate::boundary_protocol::SupervisorInstanceId;

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
    expected_runtime_generation: SandboxGenerationId,
    /// Epoch the runtime was launched with. No credential below it is ever
    /// valid; [`SandboxConnectionRegistry`] holds the owner term in force.
    launch_auth_epoch: CredentialEpoch,
}

impl std::fmt::Debug for SandboxProtocolAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxProtocolAuthenticator")
            .field("verifier", &self.verifier)
            .field("expected_sandbox_id", &self.expected_sandbox_id)
            .field(
                "expected_runtime_generation",
                &self.expected_runtime_generation,
            )
            .field("launch_auth_epoch", &self.launch_auth_epoch)
            .finish()
    }
}

impl SandboxProtocolAuthenticator {
    #[must_use]
    pub const fn new(
        verifier: SessionJwtVerifier,
        expected_sandbox_id: SandboxId,
        expected_runtime_generation: SandboxGenerationId,
        launch_auth_epoch: CredentialEpoch,
    ) -> Self {
        Self {
            verifier,
            expected_sandbox_id,
            expected_runtime_generation,
            launch_auth_epoch,
        }
    }

    /// Verify a supervisor takeover grant for this runtime generation. The
    /// registry decides whether its epoch may replace the current owner.
    pub fn verify_takeover(
        &self,
        grant: &str,
    ) -> Result<VerifiedSupervisorTakeover, SandboxAuthError> {
        let verified = self.verifier.verify_supervisor_takeover(grant)?;
        if verified.takeover.sandbox_id != self.expected_sandbox_id {
            return Err(SandboxAuthError::WrongSandbox);
        }
        if verified.takeover.runtime_generation != self.expected_runtime_generation {
            return Err(SandboxAuthError::WrongRuntimeGeneration);
        }
        Ok(verified)
    }

    /// Verify the bearer for this sandbox and generation. Its epoch is only
    /// checked against the launch epoch here; the connection registry admits
    /// the current owner term, stages takeovers, and rejects older terms.
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
        let token = openshell_core::auth::strip_bearer_scheme(value)
            .filter(|token| !token.is_empty() && !token.chars().any(char::is_whitespace))
            .ok_or(SandboxAuthError::InvalidBearer)?;
        let session = self.verifier.verify(token)?;
        if session.sandbox_id != self.expected_sandbox_id {
            return Err(SandboxAuthError::WrongSandbox);
        }
        if session.runtime_generation != self.expected_runtime_generation {
            return Err(SandboxAuthError::WrongRuntimeGeneration);
        }
        if session.auth_epoch < self.launch_auth_epoch {
            return Err(SandboxAuthError::StaleCredentialEpoch);
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

/// A connection attached but not yet confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingConnection {
    id: SandboxConnectionId,
    epoch: CredentialEpoch,
    /// Present when the connection replaces the owner under a takeover grant.
    takeover: Option<StagedTakeover>,
}

/// A verified takeover staged on a pending connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedTakeover {
    /// Process identity pinned when the takeover is confirmed.
    pub supervisor_instance_id: SupervisorInstanceId,
    /// Owner term accepted once the takeover is confirmed.
    pub auth_epoch: CredentialEpoch,
    /// Pool member that owns the new term, for audit.
    pub owner: String,
    pub grant_id: Uuid,
}

/// What a confirmation changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Promotion {
    /// The previously active connection, which may now be closed without
    /// creating an unsupervised interval.
    pub replaced: Option<SandboxConnectionId>,
    /// The takeover this confirmation completed. Every connection of the
    /// previous owner term is then stale and must be closed.
    pub takeover: Option<StagedTakeover>,
}

#[derive(Debug)]
struct ConnectionState {
    active: Option<ActiveConnection>,
    pending: Option<PendingConnection>,
    highest_epoch: Option<CredentialEpoch>,
    /// The owner term in force: credentials below it are stale, and
    /// credentials above it act only to stage a granted takeover.
    accepted_epoch: CredentialEpoch,
    supervisor_instance_id: Option<SupervisorInstanceId>,
    terminal: bool,
}

/// Enforces the one-active-connection and monotonically increasing epoch
/// rules, and the owner term a takeover must advance.
#[derive(Debug)]
pub struct SandboxConnectionRegistry {
    state: Mutex<ConnectionState>,
}

impl SandboxConnectionRegistry {
    /// Track connections of a runtime launched at `launch_auth_epoch`.
    #[must_use]
    pub fn new(
        _session_id: openshell_core::SandboxSessionId,
        _session_rotation: openshell_core::jwt::SessionRotation,
        launch_auth_epoch: CredentialEpoch,
    ) -> Self {
        Self {
            state: Mutex::new(ConnectionState {
                active: None,
                pending: None,
                highest_epoch: None,
                accepted_epoch: launch_auth_epoch,
                supervisor_instance_id: None,
                terminal: false,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ConnectionState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The owner term in force.
    #[must_use]
    pub fn accepted_epoch(&self) -> CredentialEpoch {
        self.lock().accepted_epoch
    }

    /// The supervisor process allowed to attach without a takeover grant.
    #[must_use]
    pub fn supervisor_instance(&self) -> Option<SupervisorInstanceId> {
        self.lock().supervisor_instance_id
    }

    /// Reject credentials of an owner term that has been replaced. Higher
    /// epochs pass so a granted replacement can open its boundary and stage
    /// its attach; nothing else accepts them until it is confirmed.
    pub fn admit(&self, principal: &SandboxProtocolPrincipal) -> Result<(), SandboxAuthError> {
        if principal.session.auth_epoch < self.lock().accepted_epoch {
            return Err(SandboxAuthError::StaleCredentialEpoch);
        }
        Ok(())
    }

    /// Check, without changing anything, whether [`Self::attach`] would
    /// accept this attach. Callers that act on the boundary before
    /// committing the attach run this first, under the same serialization
    /// as the commit, so a rejected candidate never touches the boundary.
    pub fn check_attach(
        &self,
        principal: &SandboxProtocolPrincipal,
        supervisor_instance_id: SupervisorInstanceId,
        takeover: Option<&VerifiedSupervisorTakeover>,
    ) -> Result<(), SandboxAuthError> {
        plan_attach(&self.lock(), principal, supervisor_instance_id, takeover).map(drop)
    }

    /// Stage a fully authenticated connection for confirmation. The returned
    /// ID identifies an older unconfirmed candidate that may be closed. The
    /// current active connection remains authoritative until [`Self::confirm`]
    /// promotes this candidate.
    ///
    /// Without `takeover`, only the pinned supervisor process (or the first
    /// one, which is then pinned) may attach, at the accepted epoch. With a
    /// verified grant, a process named by the grant may stage a replacement
    /// at the grant's epoch when it exceeds the accepted epoch and is not
    /// below any epoch already staged; replaying the attach of an already
    /// confirmed takeover is an ordinary attach.
    pub fn attach(
        &self,
        principal: &SandboxProtocolPrincipal,
        supervisor_instance_id: SupervisorInstanceId,
        takeover: Option<&VerifiedSupervisorTakeover>,
    ) -> Result<Option<SandboxConnectionId>, SandboxAuthError> {
        let mut state = self.lock();
        let AttachPlan::Stage { takeover: staged } =
            plan_attach(&state, principal, supervisor_instance_id, takeover)?
        else {
            return Ok(None);
        };
        let epoch = principal.session.auth_epoch;
        let replaced = state
            .pending
            .take()
            .map(|pending| pending.id)
            .filter(|id| *id != principal.connection_id);
        state.highest_epoch = Some(
            state
                .highest_epoch
                .map_or(epoch, |highest| highest.max(epoch)),
        );
        if staged.is_none() {
            // The first process to attach is pinned; a replacement then
            // needs a grant.
            state
                .supervisor_instance_id
                .get_or_insert(supervisor_instance_id);
        }
        state.pending = Some(PendingConnection {
            id: principal.connection_id,
            epoch,
            takeover: staged,
        });
        Ok(replaced)
    }

    /// Promote an attached, confirmed candidate to the active connection.
    /// Confirming a staged takeover advances the accepted epoch and pins the
    /// replacement process before the previous owner's connection is
    /// reported for closing.
    pub fn confirm(
        &self,
        principal: &SandboxProtocolPrincipal,
    ) -> Result<Promotion, SandboxAuthError> {
        let epoch = principal.session.auth_epoch;
        let mut state = self.lock();
        if state.terminal {
            return Err(SandboxAuthError::TerminalSession);
        }
        if state
            .active
            .is_some_and(|active| active.id == principal.connection_id && active.epoch == epoch)
        {
            return Ok(Promotion::default());
        }
        let pending = state
            .pending
            .clone()
            .filter(|pending| pending.id == principal.connection_id && pending.epoch == epoch)
            .ok_or(SandboxAuthError::ConnectionNotAttached)?;
        if let Some(takeover) = &pending.takeover {
            state.accepted_epoch = takeover.auth_epoch;
            state.supervisor_instance_id = Some(takeover.supervisor_instance_id);
        }
        let replaced = state.active.map(|active| active.id);
        state.active = Some(ActiveConnection {
            id: pending.id,
            epoch: pending.epoch,
        });
        state.pending = None;
        Ok(Promotion {
            replaced,
            takeover: pending.takeover,
        })
    }

    /// Confirm may run on either the active connection (an idempotent replay)
    /// or its staged replacement. Other operations require the active one.
    pub fn require_attached(
        &self,
        principal: &SandboxProtocolPrincipal,
    ) -> Result<(), SandboxAuthError> {
        let epoch = principal.session.auth_epoch;
        let state = self.lock();
        if state.terminal {
            return Err(SandboxAuthError::TerminalSession);
        }
        if state
            .active
            .is_some_and(|active| active.id == principal.connection_id && active.epoch == epoch)
            || state.pending.as_ref().is_some_and(|pending| {
                pending.id == principal.connection_id && pending.epoch == epoch
            })
        {
            Ok(())
        } else {
            Err(SandboxAuthError::ConnectionNotAttached)
        }
    }

    pub fn require_active(
        &self,
        principal: &SandboxProtocolPrincipal,
    ) -> Result<(), SandboxAuthError> {
        let epoch = principal.session.auth_epoch;
        let state = self.lock();
        if state.terminal {
            return Err(SandboxAuthError::TerminalSession);
        }
        if epoch != state.accepted_epoch {
            return Err(SandboxAuthError::StaleCredentialEpoch);
        }
        if state
            .active
            .is_none_or(|active| active.id != principal.connection_id || active.epoch != epoch)
        {
            return Err(SandboxAuthError::ConnectionNotAttached);
        }
        Ok(())
    }

    /// Remove a physical connection. Returns `true` only when it was the
    /// confirmed active connection and recovery must begin.
    pub fn disconnect(&self, connection_id: SandboxConnectionId) -> bool {
        let mut state = self.lock();
        let was_active = state
            .active
            .is_some_and(|active| active.id == connection_id);
        if was_active {
            state.active = None;
        }
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.id == connection_id)
        {
            state.pending = None;
        }
        was_active
    }

    pub fn mark_terminal(&self) {
        let mut state = self.lock();
        state.terminal = true;
        state.active = None;
        state.pending = None;
    }
}

/// What an accepted attach does to the registry.
enum AttachPlan {
    /// The connection is already attached at this epoch.
    Unchanged,
    /// Stage the connection, as a takeover when one is given.
    Stage { takeover: Option<StagedTakeover> },
}

/// Decide an attach against the current registry state without changing it.
fn plan_attach(
    state: &ConnectionState,
    principal: &SandboxProtocolPrincipal,
    supervisor_instance_id: SupervisorInstanceId,
    takeover: Option<&VerifiedSupervisorTakeover>,
) -> Result<AttachPlan, SandboxAuthError> {
    let epoch = principal.session.auth_epoch;
    let connection_id = principal.connection_id;
    if state.terminal {
        return Err(SandboxAuthError::TerminalSession);
    }
    if epoch < state.accepted_epoch {
        return Err(SandboxAuthError::StaleCredentialEpoch);
    }
    let staged = if let Some(grant) = takeover {
        let staged = staged_takeover(grant, epoch, supervisor_instance_id)?;
        let promoted = epoch == state.accepted_epoch
            && state.supervisor_instance_id == Some(supervisor_instance_id);
        if promoted {
            // A replayed attach of the confirmed takeover is an ordinary
            // attach by the owner it pinned.
            None
        } else if epoch <= state.accepted_epoch {
            return Err(SandboxAuthError::StaleCredentialEpoch);
        } else {
            Some(staged)
        }
    } else {
        if epoch > state.accepted_epoch {
            return Err(SandboxAuthError::TakeoverRequired);
        }
        if state
            .supervisor_instance_id
            .is_some_and(|expected| expected != supervisor_instance_id)
        {
            return Err(SandboxAuthError::WrongSupervisorInstance);
        }
        None
    };
    if staged.is_none()
        && let Some(active) = state.active
    {
        if active.id == connection_id && active.epoch == epoch {
            return Ok(AttachPlan::Unchanged);
        }
        if epoch == active.epoch {
            return Err(SandboxAuthError::ConnectionStillActive);
        }
        if epoch < active.epoch {
            return Err(SandboxAuthError::StaleCredentialEpoch);
        }
    }
    // A term below the highest one ever staged can no longer win, even after
    // that candidate disconnected: the gateway granted the higher term
    // later and has already fenced the lower one.
    if state.highest_epoch.is_some_and(|highest| epoch < highest) {
        return Err(SandboxAuthError::StaleCredentialEpoch);
    }
    if let Some(pending) = &state.pending {
        if pending.id == connection_id && pending.epoch == epoch && pending.takeover == staged {
            return Ok(AttachPlan::Unchanged);
        }
        if epoch < pending.epoch {
            return Err(SandboxAuthError::StaleCredentialEpoch);
        }
    }
    Ok(AttachPlan::Stage { takeover: staged })
}

/// Bind a verified grant to the attach that presents it.
fn staged_takeover(
    grant: &VerifiedSupervisorTakeover,
    epoch: CredentialEpoch,
    supervisor_instance_id: SupervisorInstanceId,
) -> Result<StagedTakeover, SandboxAuthError> {
    let granted = SupervisorInstanceId::from_str(&grant.takeover.supervisor_instance)
        .map_err(|_| SandboxAuthError::TakeoverMismatch)?;
    if grant.takeover.auth_epoch != epoch || granted != supervisor_instance_id {
        return Err(SandboxAuthError::TakeoverMismatch);
    }
    Ok(StagedTakeover {
        supervisor_instance_id,
        auth_epoch: epoch,
        owner: grant.takeover.owner.clone(),
        grant_id: grant.token_id,
    })
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
    #[error("authenticated runtime generation does not match this sandbox runtime")]
    WrongRuntimeGeneration,
    #[error("Sandbox Protocol credential epoch is stale")]
    StaleCredentialEpoch,
    /// Retryable: the previous connection's disconnect has not been observed yet.
    #[error("another Sandbox Protocol connection with this credential epoch is still active")]
    ConnectionStillActive,
    #[error("sandbox runtime is already bound to another supervisor process")]
    WrongSupervisorInstance,
    #[error("Sandbox Protocol connection has not completed attach")]
    ConnectionNotAttached,
    #[error("sandbox session is terminal")]
    TerminalSession,
    /// The bearer is ahead of the owner term in force, which only a
    /// takeover grant may advance.
    #[error("Sandbox Protocol credential epoch requires a supervisor takeover grant")]
    TakeoverRequired,
    #[error("supervisor takeover grant does not match this attach")]
    TakeoverMismatch,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use openshell_core::jwt::{
        DEFAULT_SESSION_TOKEN_TTL, JwtClock, SandboxRuntimeIdentity, SessionJwtIssuer,
        SessionTokenProfile, SessionVerificationKey, SupervisorTakeover,
    };
    use openshell_core::sandbox_generation::SandboxGenerationId;
    use rcgen::PKCS_ED25519;

    use super::*;

    #[derive(Debug)]
    struct FixedClock;

    impl JwtClock for FixedClock {
        fn now_unix_seconds(&self) -> i64 {
            1_900_000_000
        }
    }

    /// One gateway issuer and the runtime that trusts it, launched at epoch 1.
    struct Gateway {
        issuer: SessionJwtIssuer,
        authenticator: SandboxProtocolAuthenticator,
    }

    impl Gateway {
        fn new() -> Self {
            Self::launched_at(1)
        }

        fn launched_at(launch_epoch: u64) -> Self {
            let key =
                openshell_crypto::pki::generate_keypair_for(&PKCS_ED25519).expect("generate key");
            let public_key_pem = key.public_key_pem().into_bytes();
            let clock: Arc<dyn JwtClock> = Arc::new(FixedClock);
            let issuer = SessionJwtIssuer::from_ed25519_pem(
                key.serialize_pem().unwrap().as_bytes(),
                "current",
                "test",
                Some(DEFAULT_SESSION_TOKEN_TTL),
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
            Self {
                issuer,
                authenticator: SandboxProtocolAuthenticator::new(
                    verifier,
                    SandboxId::parse("sandbox-a").expect("sandbox ID"),
                    SandboxGenerationId::parse("generation-1").expect("runtime generation"),
                    CredentialEpoch::new(launch_epoch).expect("epoch"),
                ),
            }
        }

        fn registry(&self) -> SandboxConnectionRegistry {
            SandboxConnectionRegistry::new(
                openshell_core::SandboxSessionId::new(),
                openshell_core::jwt::SessionRotation::new(1).expect("rotation"),
                self.authenticator.launch_auth_epoch,
            )
        }

        /// A Sandbox Protocol bearer for `epoch`.
        fn token(&self, epoch: u64) -> String {
            self.issuer
                .mint_pair(&SandboxRuntimeIdentity {
                    sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox ID"),
                    runtime_generation: SandboxGenerationId::parse("generation-1")
                        .expect("runtime generation"),
                    auth_epoch: CredentialEpoch::new(epoch).expect("epoch"),
                })
                .expect("token pair")
                .sandbox
                .token
                .expose_secret()
                .to_string()
        }

        /// Authenticate `token` on a new physical connection.
        fn connect(&self, token: &str) -> SandboxProtocolPrincipal {
            self.authenticator
                .authenticate(SandboxConnectionId::new(), &metadata(token))
                .expect("principal")
        }

        /// A verified grant for `instance` to own `epoch`.
        fn grant(&self, epoch: u64, instance: SupervisorInstanceId) -> VerifiedSupervisorTakeover {
            let minted = self
                .issuer
                .mint_supervisor_takeover(
                    &SupervisorTakeover {
                        sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox ID"),
                        runtime_generation: SandboxGenerationId::parse("generation-1")
                            .expect("runtime generation"),
                        auth_epoch: CredentialEpoch::new(epoch).expect("epoch"),
                        supervisor_instance: instance.to_string(),
                        owner: "supervisor-b".to_string(),
                    },
                    std::time::Duration::from_mins(5),
                )
                .expect("mint grant");
            self.authenticator
                .verify_takeover(minted.token.expose_secret())
                .expect("verify grant")
        }
    }

    fn metadata(token: &str) -> MetadataMap {
        let mut metadata = MetadataMap::new();
        metadata.insert(
            "authorization",
            format!("Bearer {token}").parse().expect("metadata value"),
        );
        metadata
    }

    fn epoch(value: u64) -> CredentialEpoch {
        CredentialEpoch::new(value).expect("epoch")
    }

    #[test]
    fn bearer_identity_must_match_the_provisioned_runtime() {
        let mut gateway = Gateway::new();
        let metadata = metadata(&gateway.token(1));
        gateway.authenticator.expected_sandbox_id = SandboxId::parse("sandbox-b").unwrap();
        assert_eq!(
            gateway
                .authenticator
                .authenticate(SandboxConnectionId::new(), &metadata),
            Err(SandboxAuthError::WrongSandbox)
        );
        gateway.authenticator.expected_sandbox_id = SandboxId::parse("sandbox-a").unwrap();
        gateway.authenticator.expected_runtime_generation =
            SandboxGenerationId::parse("generation-2").unwrap();
        assert_eq!(
            gateway
                .authenticator
                .authenticate(SandboxConnectionId::new(), &metadata),
            Err(SandboxAuthError::WrongRuntimeGeneration)
        );
    }

    #[test]
    fn credentials_below_the_launch_epoch_are_never_valid() {
        let gateway = Gateway::launched_at(3);
        assert_eq!(
            gateway
                .authenticator
                .authenticate(SandboxConnectionId::new(), &metadata(&gateway.token(2))),
            Err(SandboxAuthError::StaleCredentialEpoch)
        );
    }

    #[test]
    fn bearer_metadata_must_occur_exactly_once() {
        let gateway = Gateway::new();
        let token = gateway.token(1);
        assert_eq!(
            gateway
                .authenticator
                .authenticate(SandboxConnectionId::new(), &MetadataMap::new()),
            Err(SandboxAuthError::MissingBearer)
        );
        let mut duplicate = metadata(&token);
        duplicate.append(
            "authorization",
            format!("Bearer {token}").parse().expect("metadata value"),
        );
        assert_eq!(
            gateway
                .authenticator
                .authenticate(SandboxConnectionId::new(), &duplicate),
            Err(SandboxAuthError::DuplicateBearer)
        );
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        let gateway = Gateway::new();
        let token = gateway.token(1);
        for scheme in ["bearer", "BEARER"] {
            let mut metadata = MetadataMap::new();
            metadata.insert(
                "authorization",
                format!("{scheme} {token}").parse().expect("metadata value"),
            );
            assert!(
                gateway
                    .authenticator
                    .authenticate(SandboxConnectionId::new(), &metadata)
                    .is_ok(),
                "{scheme}"
            );
        }
    }

    #[test]
    fn reconnect_requires_disconnect_and_terminal_is_final() {
        let gateway = Gateway::new();
        let token = gateway.token(1);
        let first = gateway.connect(&token);
        let registry = gateway.registry();
        let instance = SupervisorInstanceId::new();
        assert_eq!(registry.attach(&first, instance, None), Ok(None));
        assert_eq!(registry.attach(&first, instance, None), Ok(None));
        assert_eq!(registry.confirm(&first), Ok(Promotion::default()));
        assert_eq!(registry.confirm(&first), Ok(Promotion::default()));

        let second = gateway.connect(&token);
        assert_eq!(
            registry.attach(&second, instance, None),
            Err(SandboxAuthError::ConnectionStillActive)
        );

        assert!(registry.disconnect(first.connection_id()));
        assert_eq!(registry.attach(&second, instance, None), Ok(None));
        assert_eq!(registry.confirm(&second), Ok(Promotion::default()));
        assert!(registry.disconnect(second.connection_id()));
        assert_eq!(registry.attach(&first, instance, None), Ok(None));
        assert_eq!(registry.confirm(&first), Ok(Promotion::default()));
        registry.mark_terminal();
        assert_eq!(
            registry.require_active(&first),
            Err(SandboxAuthError::TerminalSession)
        );
        assert_eq!(
            registry.attach(&first, instance, None),
            Err(SandboxAuthError::TerminalSession)
        );
    }

    #[test]
    fn replacement_supervisor_cannot_resume_existing_runtime_generation() {
        let gateway = Gateway::new();
        let token = gateway.token(1);
        let first = gateway.connect(&token);
        let registry = gateway.registry();
        let first_instance = SupervisorInstanceId::new();
        registry
            .attach(&first, first_instance, None)
            .expect("attach first supervisor");
        registry.confirm(&first).expect("confirm first supervisor");
        assert!(registry.disconnect(first.connection_id()));

        // Launch credentials, a renewed bearer, or a bearer from a later
        // epoch never move ownership without a grant.
        let replacement = gateway.connect(&token);
        assert_eq!(
            registry.attach(&replacement, SupervisorInstanceId::new(), None),
            Err(SandboxAuthError::WrongSupervisorInstance)
        );
        let renewed = gateway.connect(&gateway.token(1));
        assert_eq!(
            registry.attach(&renewed, SupervisorInstanceId::new(), None),
            Err(SandboxAuthError::WrongSupervisorInstance)
        );
        let ahead = gateway.connect(&gateway.token(2));
        assert_eq!(
            registry.attach(&ahead, SupervisorInstanceId::new(), None),
            Err(SandboxAuthError::TakeoverRequired)
        );
        assert_eq!(
            registry.attach(&ahead, first_instance, None),
            Err(SandboxAuthError::TakeoverRequired)
        );
        assert_eq!(
            registry.attach(&replacement, first_instance, None),
            Ok(None)
        );
        assert_eq!(registry.accepted_epoch(), epoch(1));
    }

    #[test]
    fn replacement_does_not_displace_active_connection_before_confirm() {
        let gateway = Gateway::new();
        let first = gateway.connect(&gateway.token(1));
        let registry = gateway.registry();
        let owner = SupervisorInstanceId::new();
        registry.attach(&first, owner, None).expect("attach first");
        registry.confirm(&first).expect("confirm first");

        let candidate = SupervisorInstanceId::new();
        let replacement = gateway.connect(&gateway.token(2));
        let grant = gateway.grant(2, candidate);
        assert_eq!(
            registry.attach(&replacement, candidate, Some(&grant)),
            Ok(None)
        );
        registry
            .require_active(&first)
            .expect("first remains active");
        assert_eq!(
            registry.require_active(&replacement),
            Err(SandboxAuthError::StaleCredentialEpoch)
        );
        registry
            .require_attached(&replacement)
            .expect("replacement may confirm");
        let promotion = registry.confirm(&replacement).expect("confirm");
        assert_eq!(promotion.replaced, Some(first.connection_id()));
        assert_eq!(
            promotion.takeover.map(|takeover| takeover.auth_epoch),
            Some(epoch(2))
        );
        assert_eq!(
            registry.require_active(&first),
            Err(SandboxAuthError::StaleCredentialEpoch)
        );
        registry
            .require_active(&replacement)
            .expect("replacement became active");
    }

    #[test]
    fn confirmed_takeover_fences_every_older_credential_and_process() {
        let gateway = Gateway::new();
        let registry = gateway.registry();
        let old_owner = SupervisorInstanceId::new();
        let old = gateway.connect(&gateway.token(1));
        registry.attach(&old, old_owner, None).expect("attach old");
        registry.confirm(&old).expect("confirm old");
        // The old owner's process dies: the runtime freezes.
        assert!(registry.disconnect(old.connection_id()));

        let candidate = SupervisorInstanceId::new();
        let replacement = gateway.connect(&gateway.token(2));
        let grant = gateway.grant(2, candidate);
        assert_eq!(
            registry.attach(&replacement, candidate, Some(&grant)),
            Ok(None)
        );
        // A staged takeover already outranks the old term: the old owner can
        // no longer reattach while the replacement prepares.
        let returning = gateway.connect(&gateway.token(1));
        assert_eq!(
            registry.attach(&returning, old_owner, None),
            Err(SandboxAuthError::StaleCredentialEpoch)
        );
        let promotion = registry.confirm(&replacement).expect("confirm takeover");
        assert_eq!(promotion.replaced, None);
        assert_eq!(registry.accepted_epoch(), epoch(2));
        assert_eq!(registry.supervisor_instance(), Some(candidate));

        // Every credential of the replaced term is now stale, including a
        // renewal minted for it and an attempt to reuse the old process pin.
        for token in [gateway.token(1), gateway.token(1)] {
            let stale = gateway.connect(&token);
            assert_eq!(
                registry.admit(&stale),
                Err(SandboxAuthError::StaleCredentialEpoch)
            );
            assert_eq!(
                registry.attach(&stale, old_owner, None),
                Err(SandboxAuthError::StaleCredentialEpoch)
            );
            assert_eq!(
                registry.attach(&stale, candidate, None),
                Err(SandboxAuthError::StaleCredentialEpoch)
            );
        }
        // The same grant cannot be replayed by another process, and a grant
        // for the term in force cannot move it.
        let thief = SupervisorInstanceId::new();
        let replayed = gateway.connect(&gateway.token(2));
        assert_eq!(
            registry.attach(&replayed, thief, Some(&grant)),
            Err(SandboxAuthError::TakeoverMismatch)
        );
        assert_eq!(
            registry.attach(&replayed, thief, Some(&gateway.grant(2, thief))),
            Err(SandboxAuthError::StaleCredentialEpoch)
        );
        // The new owner's own transport recovery attaches without the grant,
        // and replaying its takeover attach is harmless.
        assert!(registry.disconnect(replacement.connection_id()));
        let reconnect = gateway.connect(&gateway.token(2));
        assert_eq!(
            registry.attach(&reconnect, candidate, Some(&grant)),
            Ok(None)
        );
        let plain = gateway.connect(&gateway.token(2));
        assert_eq!(
            registry.attach(&plain, candidate, None),
            Ok(Some(reconnect.connection_id()))
        );
        assert_eq!(registry.confirm(&plain), Ok(Promotion::default()));
        registry
            .require_active(&plain)
            .expect("same owner recovered");
    }

    #[test]
    fn concurrent_candidates_resolve_to_the_highest_granted_term() {
        let gateway = Gateway::new();
        let registry = gateway.registry();
        let owner = SupervisorInstanceId::new();
        let launch = gateway.connect(&gateway.token(1));
        registry.attach(&launch, owner, None).expect("attach");
        registry.confirm(&launch).expect("confirm");

        let (second, third) = (SupervisorInstanceId::new(), SupervisorInstanceId::new());
        let candidate_two = gateway.connect(&gateway.token(2));
        let candidate_three = gateway.connect(&gateway.token(3));
        assert_eq!(
            registry.attach(&candidate_two, second, Some(&gateway.grant(2, second))),
            Ok(None)
        );
        // A higher term replaces the lower staged candidate, which is closed.
        assert_eq!(
            registry.attach(&candidate_three, third, Some(&gateway.grant(3, third))),
            Ok(Some(candidate_two.connection_id()))
        );
        assert_eq!(
            registry.confirm(&candidate_two),
            Err(SandboxAuthError::ConnectionNotAttached)
        );
        // The lower candidate cannot stage again behind the higher one.
        let retry = gateway.connect(&gateway.token(2));
        assert_eq!(
            registry.attach(&retry, second, Some(&gateway.grant(2, second))),
            Err(SandboxAuthError::StaleCredentialEpoch)
        );
        let promotion = registry
            .confirm(&candidate_three)
            .expect("highest term wins");
        assert_eq!(promotion.replaced, Some(launch.connection_id()));
        assert_eq!(registry.accepted_epoch(), epoch(3));
        // Grants with a mismatched epoch or instance never stage.
        let fourth = SupervisorInstanceId::new();
        let ahead = gateway.connect(&gateway.token(4));
        assert_eq!(
            registry.attach(&ahead, fourth, Some(&gateway.grant(5, fourth))),
            Err(SandboxAuthError::TakeoverMismatch)
        );
        assert_eq!(
            registry.attach(
                &ahead,
                fourth,
                Some(&gateway.grant(4, SupervisorInstanceId::new()))
            ),
            Err(SandboxAuthError::TakeoverMismatch)
        );
    }

    #[test]
    fn a_dropped_higher_candidate_still_outranks_lower_grants() {
        // The gateway granted term 2 to a slow candidate, then term 3 to
        // another that staged and lost its transport before confirming. The
        // slow candidate's still-valid term-2 grant must not win.
        let gateway = Gateway::new();
        let registry = gateway.registry();
        let owner = SupervisorInstanceId::new();
        let launch = gateway.connect(&gateway.token(1));
        registry.attach(&launch, owner, None).expect("attach");
        registry.confirm(&launch).expect("confirm");

        let (slow, third) = (SupervisorInstanceId::new(), SupervisorInstanceId::new());
        let stage3 = gateway.connect(&gateway.token(3));
        let grant3 = gateway.grant(3, third);
        assert_eq!(registry.attach(&stage3, third, Some(&grant3)), Ok(None));
        assert!(!registry.disconnect(stage3.connection_id()));

        let attempt2 = gateway.connect(&gateway.token(2));
        assert_eq!(
            registry.check_attach(&attempt2, slow, Some(&gateway.grant(2, slow))),
            Err(SandboxAuthError::StaleCredentialEpoch)
        );
        assert_eq!(
            registry.attach(&attempt2, slow, Some(&gateway.grant(2, slow))),
            Err(SandboxAuthError::StaleCredentialEpoch)
        );
        assert_eq!(registry.accepted_epoch(), epoch(1));

        // The term-3 candidate may still stage again and win.
        let retry3 = gateway.connect(&gateway.token(3));
        assert_eq!(registry.attach(&retry3, third, Some(&grant3)), Ok(None));
        let promotion = registry.confirm(&retry3).expect("term 3 confirms");
        assert_eq!(promotion.replaced, Some(launch.connection_id()));
        assert_eq!(registry.accepted_epoch(), epoch(3));
        assert_eq!(registry.supervisor_instance(), Some(third));
    }

    #[test]
    fn attach_checks_match_commits_without_changing_the_registry() {
        let gateway = Gateway::new();
        let registry = gateway.registry();
        let owner = SupervisorInstanceId::new();
        let first = gateway.connect(&gateway.token(1));
        // A check never pins or stages: a different first process still wins.
        registry
            .check_attach(&first, SupervisorInstanceId::new(), None)
            .expect("check");
        assert_eq!(registry.supervisor_instance(), None);
        registry.attach(&first, owner, None).expect("attach");
        assert_eq!(registry.supervisor_instance(), Some(owner));
        let candidate = SupervisorInstanceId::new();
        let ahead = gateway.connect(&gateway.token(2));
        assert_eq!(
            registry.check_attach(&ahead, candidate, None),
            Err(SandboxAuthError::TakeoverRequired)
        );
        let grant = gateway.grant(2, candidate);
        registry
            .check_attach(&ahead, candidate, Some(&grant))
            .expect("granted candidate passes the check");
        assert_eq!(
            registry.confirm(&ahead),
            Err(SandboxAuthError::ConnectionNotAttached),
            "a check alone stages nothing"
        );
        assert_eq!(
            registry.check_attach(&ahead, SupervisorInstanceId::new(), Some(&grant)),
            Err(SandboxAuthError::TakeoverMismatch)
        );
    }

    #[test]
    fn takeover_grants_bind_this_runtime_and_terminal_sessions_reject_them() {
        let gateway = Gateway::new();
        let other = Gateway::new();
        let candidate = SupervisorInstanceId::new();
        // A grant signed by another gateway's key is not verifiable here.
        let minted = other
            .issuer
            .mint_supervisor_takeover(
                &SupervisorTakeover {
                    sandbox_id: SandboxId::parse("sandbox-a").unwrap(),
                    runtime_generation: SandboxGenerationId::parse("generation-1").unwrap(),
                    auth_epoch: epoch(2),
                    supervisor_instance: candidate.to_string(),
                    owner: "supervisor-b".to_string(),
                },
                std::time::Duration::from_mins(5),
            )
            .unwrap();
        assert!(matches!(
            gateway
                .authenticator
                .verify_takeover(minted.token.expose_secret()),
            Err(SandboxAuthError::Jwt(_))
        ));
        // A grant for another sandbox or generation is refused.
        for (sandbox, generation, expected) in [
            ("sandbox-b", "generation-1", SandboxAuthError::WrongSandbox),
            (
                "sandbox-a",
                "generation-2",
                SandboxAuthError::WrongRuntimeGeneration,
            ),
        ] {
            let minted = gateway
                .issuer
                .mint_supervisor_takeover(
                    &SupervisorTakeover {
                        sandbox_id: SandboxId::parse(sandbox).unwrap(),
                        runtime_generation: SandboxGenerationId::parse(generation).unwrap(),
                        auth_epoch: epoch(2),
                        supervisor_instance: candidate.to_string(),
                        owner: "supervisor-b".to_string(),
                    },
                    std::time::Duration::from_mins(5),
                )
                .unwrap();
            assert_eq!(
                gateway
                    .authenticator
                    .verify_takeover(minted.token.expose_secret()),
                Err(expected)
            );
        }
        let registry = gateway.registry();
        registry.mark_terminal();
        let replacement = gateway.connect(&gateway.token(2));
        assert_eq!(
            registry.attach(&replacement, candidate, Some(&gateway.grant(2, candidate))),
            Err(SandboxAuthError::TerminalSession)
        );
    }

    #[test]
    fn a_fresh_runtime_accepts_a_granted_first_owner() {
        // The launch owner died before attaching; its replacement starts the
        // runtime under a grant, which pins the granted process.
        let gateway = Gateway::new();
        let registry = gateway.registry();
        let candidate = SupervisorInstanceId::new();
        let replacement = gateway.connect(&gateway.token(2));
        assert_eq!(
            registry.attach(&replacement, candidate, Some(&gateway.grant(2, candidate))),
            Ok(None)
        );
        registry.confirm(&replacement).expect("confirm");
        assert_eq!(registry.supervisor_instance(), Some(candidate));
        let launch_owner = gateway.connect(&gateway.token(1));
        assert_eq!(
            registry.attach(&launch_owner, SupervisorInstanceId::new(), None),
            Err(SandboxAuthError::StaleCredentialEpoch)
        );
    }
}
