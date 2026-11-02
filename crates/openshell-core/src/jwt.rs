// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal, signature-unverified JWT inspection shared by gateway clients.
//!
//! Used only for client-side refresh scheduling (deciding when a bearer is
//! near expiry). It never verifies the signature and must not be used for
//! any authorization decision. Both the sandbox-side
//! [`crate::grpc_client`] and the user-facing `openshell-sdk` refresh path
//! derive token expiry from here so the decode lives in one place.

/// Decode the numeric `exp` claim (Unix seconds) from a JWT payload without
/// verifying the signature.
///
/// Returns `None` when `token` is not a parseable JWT or has no integer `exp`
/// claim. A leading `Bearer ` prefix is tolerated so callers can pass either a
/// raw token or an `authorization` header value.
#[must_use]
pub fn parse_exp_secs(token: &str) -> Option<i64> {
    use base64::Engine;
    let raw = crate::auth::strip_bearer_scheme(token).unwrap_or(token);
    let mut parts = raw.splitn(3, '.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    value.get("exp")?.as_i64()
}

#[cfg(feature = "jwt")]
mod session {
    use std::collections::BTreeMap;
    use std::fmt;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode_header};
    use openshell_crypto::jwt::{decode, encode};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use crate::SandboxSessionId;
    use crate::sandbox_generation::SandboxGenerationId;

    pub const GATEWAY_SESSION_JWT_TYPE: &str = "openshell-gateway-session+jwt";
    pub const SANDBOX_SESSION_JWT_TYPE: &str = "openshell-sandbox-session+jwt";
    /// JOSE `typ` of the supervisor token: the credential of the gateway's
    /// shared supervisor process for the assignment stream, and nothing else.
    pub const SUPERVISOR_JWT_TYPE: &str = "openshell-supervisor+jwt";
    /// JOSE `typ` of a supervisor takeover grant.
    ///
    /// The grant is the gateway's authorization for one supervisor process to
    /// replace the owner of one runtime generation at a strictly higher
    /// credential epoch. Only the sandbox runtime verifies it, and only while
    /// staging a replacement attach.
    pub const SUPERVISOR_TAKEOVER_JWT_TYPE: &str = "openshell-supervisor-takeover+jwt";
    /// Longest lifetime of a takeover grant. Replay safety comes from the
    /// strictly increasing epoch it names; the bound only limits how long an
    /// unused grant stays usable.
    pub const MAX_SUPERVISOR_TAKEOVER_TTL: Duration = Duration::from_mins(10);
    pub const SANDBOX_SESSION_AUDIENCE: &str = "openshell-sandbox";
    pub const DEFAULT_SESSION_TOKEN_TTL: Duration = Duration::from_hours(1);
    pub const MIN_SESSION_TOKEN_TTL: Duration = Duration::from_mins(1);
    pub const MAX_SESSION_TOKEN_TTL: Duration = Duration::from_hours(1);
    pub const MAX_SESSION_CLOCK_LEEWAY: Duration = Duration::from_secs(30);

    const GATEWAY_ISSUER_PREFIX: &str = "openshell-gateway:";
    const SANDBOX_SUBJECT_PREFIX: &str = "spiffe://openshell/sandbox/";
    const SUPERVISOR_SUBJECT_PREFIX: &str = "openshell-supervisor:";

    /// Canonical sandbox identity carried by both session-token profiles.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct SandboxId(String);

    impl SandboxId {
        pub fn parse(value: impl Into<String>) -> Result<Self, SessionJwtError> {
            let value = value.into();
            if value.is_empty() || value.trim() != value || value.chars().any(char::is_whitespace) {
                return Err(SessionJwtError::InvalidSandboxId);
            }
            Ok(Self(value))
        }

        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    impl fmt::Display for SandboxId {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&self.0)
        }
    }

    /// Monotonic order for authenticated Sandbox Protocol connections.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct CredentialEpoch(u64);

    impl CredentialEpoch {
        pub fn new(value: u64) -> Result<Self, SessionJwtError> {
            if value == 0 {
                return Err(SessionJwtError::InvalidCredentialEpoch);
            }
            Ok(Self(value))
        }

        #[must_use]
        pub const fn get(self) -> u64 {
            self.0
        }
    }

    /// Monotonic identity for Sandbox Protocol attachment state.
    ///
    /// This is a protocol coordination value, not part of JWT authorization.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct SessionRotation(u64);

    impl SessionRotation {
        pub fn new(value: u64) -> Result<Self, SessionJwtError> {
            if value == 0 {
                return Err(SessionJwtError::InvalidSessionRotation);
            }
            Ok(Self(value))
        }

        #[must_use]
        pub const fn get(self) -> u64 {
            self.0
        }

        pub fn successor(self) -> Result<Self, SessionJwtError> {
            self.0
                .checked_add(1)
                .ok_or(SessionJwtError::SessionRotationOverflow)
                .and_then(Self::new)
        }
    }

    /// The only component authorized by either sandbox-session token profile.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum SessionComponent {
        #[serde(rename = "openshell-supervisor")]
        OpenShellSupervisor,
    }

    /// Exact token profile. The profile chooses both the JOSE `typ` and JWT `aud`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SessionTokenProfile {
        Gateway,
        Sandbox,
    }

    impl SessionTokenProfile {
        #[must_use]
        pub const fn token_type(self) -> &'static str {
            match self {
                Self::Gateway => GATEWAY_SESSION_JWT_TYPE,
                Self::Sandbox => SANDBOX_SESSION_JWT_TYPE,
            }
        }

        fn audience(self, issuer: &str) -> &str {
            match self {
                Self::Gateway => issuer,
                Self::Sandbox => SANDBOX_SESSION_AUDIENCE,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SessionClaims {
        iss: String,
        sub: String,
        aud: String,
        iat: i64,
        exp: i64,
        jti: String,
        sandbox_id: SandboxId,
        runtime_generation: SandboxGenerationId,
        auth_epoch: CredentialEpoch,
        component: SessionComponent,
    }

    /// Claims of the supervisor token. It names no sandbox, generation, or
    /// credential epoch: the shared supervisor acts for sandboxes only with the
    /// per-instance credentials each assignment carries.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SupervisorClaims {
        iss: String,
        sub: String,
        aud: String,
        iat: i64,
        exp: i64,
        jti: String,
        component: SessionComponent,
    }

    /// Claims of a supervisor takeover grant. The subject and audience are the
    /// sandbox's, like its Sandbox Protocol session token, but the JOSE `typ`
    /// keeps the two from ever being accepted for each other.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SupervisorTakeoverClaims {
        iss: String,
        sub: String,
        aud: String,
        iat: i64,
        exp: i64,
        jti: String,
        sandbox_id: SandboxId,
        runtime_generation: SandboxGenerationId,
        auth_epoch: CredentialEpoch,
        supervisor_instance: String,
        owner: String,
        component: SessionComponent,
    }

    /// The replacement of the supervisor that owns one runtime generation.
    ///
    /// The gateway grants it only after durably advancing the sandbox's
    /// credential epoch to `auth_epoch`; ordinary credential refresh keeps the
    /// epoch and never produces a grant.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SupervisorTakeover {
        pub sandbox_id: SandboxId,
        pub runtime_generation: SandboxGenerationId,
        /// Ownership term the grant starts; it must exceed the term the
        /// runtime currently accepts.
        pub auth_epoch: CredentialEpoch,
        /// Supervisor process identity the runtime pins once the replacement
        /// is confirmed (a canonical UUID chosen by the gateway).
        pub supervisor_instance: String,
        /// Supervisor pool member that owns the new term, for audit.
        pub owner: String,
    }

    /// A takeover grant whose signature, issuer, audience, and lifetime were
    /// verified.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct VerifiedSupervisorTakeover {
        pub takeover: SupervisorTakeover,
        pub token_id: Uuid,
        pub expires_at: i64,
    }

    /// Durable identity shared by every short-lived token for one sandbox runtime.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SandboxRuntimeIdentity {
        pub sandbox_id: SandboxId,
        pub runtime_generation: SandboxGenerationId,
        pub auth_epoch: CredentialEpoch,
    }

    /// A JWT whose contents are deliberately omitted from `Debug` output and
    /// zeroed when its final owner is dropped.
    #[derive(Clone)]
    pub struct SecretJwt(Zeroizing<String>);

    impl SecretJwt {
        pub fn parse(value: impl Into<String>) -> Result<Self, SessionJwtError> {
            let value = value.into();
            if value.is_empty() || value.chars().any(char::is_whitespace) {
                return Err(SessionJwtError::InvalidTokenEncoding);
            }
            Ok(Self(Zeroizing::new(value)))
        }

        #[must_use]
        pub fn expose_secret(&self) -> &str {
            self.0.as_str()
        }
    }

    impl fmt::Debug for SecretJwt {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("SecretJwt([REDACTED])")
        }
    }

    impl Serialize for SecretJwt {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(self.expose_secret())
        }
    }

    impl<'de> Deserialize<'de> for SecretJwt {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = String::deserialize(deserializer)?;
            Self::parse(value).map_err(serde::de::Error::custom)
        }
    }

    /// Private SSH key material is redacted from diagnostics and cleared on drop.
    #[derive(Clone)]
    pub struct SecretSshHostKey(Zeroizing<String>);

    impl SecretSshHostKey {
        #[must_use]
        pub fn new(value: String) -> Self {
            Self(Zeroizing::new(value))
        }

        #[must_use]
        pub fn expose_secret(&self) -> &str {
            &self.0
        }
    }

    impl fmt::Debug for SecretSshHostKey {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("SecretSshHostKey([REDACTED])")
        }
    }

    impl Serialize for SecretSshHostKey {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(self.expose_secret())
        }
    }

    impl<'de> Deserialize<'de> for SecretSshHostKey {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            String::deserialize(deserializer).map(Self::new)
        }
    }

    /// OTLP collector request headers, such as an authorization token, in
    /// the `OTEL_EXPORTER_OTLP_HEADERS` format. Redacted from diagnostics and
    /// cleared on drop.
    #[derive(Clone)]
    pub struct SecretOtlpHeaders(Zeroizing<String>);

    impl SecretOtlpHeaders {
        #[must_use]
        pub fn new(value: String) -> Self {
            Self(Zeroizing::new(value))
        }

        #[must_use]
        pub fn expose_secret(&self) -> &str {
            &self.0
        }
    }

    impl fmt::Debug for SecretOtlpHeaders {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("SecretOtlpHeaders([REDACTED])")
        }
    }

    impl Serialize for SecretOtlpHeaders {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(self.expose_secret())
        }
    }

    impl<'de> Deserialize<'de> for SecretOtlpHeaders {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            String::deserialize(deserializer).map(Self::new)
        }
    }

    /// Trusted launch input delivered only to `openshell-supervisor`.
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SupervisorAuthBundle {
        /// Correlates the two ends of one Sandbox Protocol launch. This value
        /// is not carried in JWTs and is not an authorization identity.
        pub session_id: SandboxSessionId,
        pub runtime_generation: SandboxGenerationId,
        /// Orders protocol attachment replacement, independently of auth.
        pub session_rotation: SessionRotation,
        pub auth_epoch: CredentialEpoch,
        pub gateway_token: SecretJwt,
        pub gateway_expires_at: i64,
        pub sandbox_token: SecretJwt,
        pub sandbox_expires_at: i64,
        /// Never delivered to the workload. Missing only in older bundles.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ssh_host_private_key: Option<SecretSshHostKey>,
        /// Headers for the OCSF OTLP collector, present only when the gateway
        /// has them. Never delivered to the workload.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ocsf_otlp_headers: Option<SecretOtlpHeaders>,
    }

    /// Gateway-created authentication input trusted by a compute driver.
    ///
    /// Drivers split this structure: the supervisor receives `supervisor`,
    /// while the sandbox receives only the gateway identity and public keys.
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SandboxLaunchAuthentication {
        pub supervisor: SupervisorAuthBundle,
        pub gateway_id: String,
        pub verification_keys: Vec<SessionVerificationKey>,
    }

    impl SandboxLaunchAuthentication {
        pub fn validate(&self) -> Result<(), SessionJwtError> {
            self.supervisor.validate()?;
            validate_gateway_id(&self.gateway_id)?;
            if self.verification_keys.is_empty() {
                return Err(SessionJwtError::NoVerificationKeys);
            }
            let mut key_ids = std::collections::BTreeSet::new();
            for key in &self.verification_keys {
                validate_key_id(key.key_id.clone())?;
                if key.public_key_pem.is_empty() {
                    return Err(SessionJwtError::InvalidVerificationKey);
                }
                if !key_ids.insert(key.key_id.as_str()) {
                    return Err(SessionJwtError::DuplicateKeyId);
                }
            }
            Ok(())
        }
    }

    impl fmt::Debug for SandboxLaunchAuthentication {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SandboxLaunchAuthentication")
                .field("supervisor", &self.supervisor)
                .field("gateway_id", &self.gateway_id)
                .field(
                    "verification_key_ids",
                    &self
                        .verification_keys
                        .iter()
                        .map(|key| key.key_id.as_str())
                        .collect::<Vec<_>>(),
                )
                .finish()
        }
    }

    impl SupervisorAuthBundle {
        pub fn validate(&self) -> Result<(), SessionJwtError> {
            if self.gateway_expires_at < 0 || self.sandbox_expires_at < 0 {
                return Err(SessionJwtError::InvalidLifetime);
            }
            SandboxGenerationId::parse(self.runtime_generation.to_string())
                .map_err(|_| SessionJwtError::InvalidRuntimeIdentity)?;
            SessionRotation::new(self.session_rotation.get())?;
            Ok(())
        }

        pub fn sandbox_bearer_slot(&self) -> Result<SessionBearerTokenSlot, SessionJwtError> {
            SessionBearerTokenSlot::new(
                self.sandbox_token.clone(),
                self.sandbox_expires_at,
                self.auth_epoch,
            )
        }
    }

    impl fmt::Debug for SupervisorAuthBundle {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SupervisorAuthBundle")
                .field("session_id", &self.session_id)
                .field("runtime_generation", &self.runtime_generation)
                .field("session_rotation", &self.session_rotation)
                .field("auth_epoch", &self.auth_epoch)
                .field("gateway_token", &"[REDACTED]")
                .field("gateway_expires_at", &self.gateway_expires_at)
                .field("sandbox_token", &"[REDACTED]")
                .field("sandbox_expires_at", &self.sandbox_expires_at)
                .field("ssh_host_private_key", &self.ssh_host_private_key)
                .field("ocsf_otlp_headers", &self.ocsf_otlp_headers)
                .finish()
        }
    }

    #[derive(Clone, Debug)]
    pub struct MintedSessionToken {
        pub token: SecretJwt,
        pub expires_at: i64,
        pub token_id: Uuid,
    }

    #[derive(Clone, Debug)]
    pub struct MintedSessionTokenPair {
        pub gateway: MintedSessionToken,
        pub sandbox: MintedSessionToken,
        pub auth_epoch: CredentialEpoch,
    }

    /// Refreshable Sandbox Protocol bearer credential shared by all streams on
    /// the supervisor's current HTTP/2 connection.
    #[derive(Clone)]
    pub struct SessionBearerTokenSlot {
        inner: Arc<std::sync::RwLock<Option<StoredBearer>>>,
    }

    #[derive(Clone)]
    struct StoredBearer {
        token: SecretJwt,
        expires_at: i64,
        credential_epoch: CredentialEpoch,
    }

    impl SessionBearerTokenSlot {
        #[must_use]
        pub fn empty() -> Self {
            Self {
                inner: Arc::new(std::sync::RwLock::new(None)),
            }
        }

        pub fn new(
            token: SecretJwt,
            expires_at: i64,
            credential_epoch: CredentialEpoch,
        ) -> Result<Self, SessionJwtError> {
            let slot = Self::empty();
            slot.update(token, expires_at, credential_epoch)?;
            Ok(slot)
        }

        pub fn update(
            &self,
            token: SecretJwt,
            expires_at: i64,
            credential_epoch: CredentialEpoch,
        ) -> Result<(), SessionJwtError> {
            if expires_at < 0 {
                return Err(SessionJwtError::InvalidLifetime);
            }
            let mut stored = self
                .inner
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if stored
                .as_ref()
                .is_some_and(|current| credential_epoch < current.credential_epoch)
            {
                return Err(SessionJwtError::StaleCredentialEpoch);
            }
            *stored = Some(StoredBearer {
                token,
                expires_at,
                credential_epoch,
            });
            Ok(())
        }

        pub fn clear(&self) {
            *self
                .inner
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }

        #[must_use]
        pub fn expires_at(&self) -> Option<i64> {
            self.inner
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .map(|stored| stored.expires_at)
        }

        #[must_use]
        pub fn credential_epoch(&self) -> Option<CredentialEpoch> {
            self.inner
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .map(|stored| stored.credential_epoch)
        }

        pub fn authorization_metadata(
            &self,
        ) -> Result<tonic::metadata::AsciiMetadataValue, SessionJwtError> {
            let stored = self
                .inner
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let stored = stored.as_ref().ok_or(SessionJwtError::TokenUnavailable)?;
            if stored.expires_at > 0 && stored.expires_at <= SystemJwtClock.now_unix_seconds() {
                return Err(SessionJwtError::Expired);
            }
            format!("Bearer {}", stored.token.expose_secret())
                .parse()
                .map_err(|_| SessionJwtError::InvalidTokenEncoding)
        }
    }

    impl Default for SessionBearerTokenSlot {
        fn default() -> Self {
            Self::empty()
        }
    }

    impl fmt::Debug for SessionBearerTokenSlot {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SessionBearerTokenSlot")
                .field("expires_at", &self.expires_at())
                .field("credential_epoch", &self.credential_epoch())
                .finish_non_exhaustive()
        }
    }

    pub trait JwtClock: Send + Sync {
        fn now_unix_seconds(&self) -> i64;
    }

    #[derive(Debug)]
    pub struct SystemJwtClock;

    impl JwtClock for SystemJwtClock {
        fn now_unix_seconds(&self) -> i64 {
            i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_secs()),
            )
            .unwrap_or(i64::MAX)
        }
    }

    /// Gateway-side issuer shared by both token profiles.
    pub struct SessionJwtIssuer {
        encoding_key: EncodingKey,
        key_id: String,
        issuer: String,
        ttl: Option<Duration>,
        clock: Arc<dyn JwtClock>,
    }

    impl fmt::Debug for SessionJwtIssuer {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SessionJwtIssuer")
                .field("key_id", &self.key_id)
                .field("issuer", &self.issuer)
                .field("ttl", &self.ttl)
                .finish_non_exhaustive()
        }
    }

    impl SessionJwtIssuer {
        pub fn from_ed25519_pem(
            signing_key_pem: &[u8],
            key_id: impl Into<String>,
            gateway_id: &str,
            ttl: Option<Duration>,
            clock: Arc<dyn JwtClock>,
        ) -> Result<Self, SessionJwtError> {
            install_crypto_provider();
            if let Some(ttl) = ttl {
                validate_ttl(ttl)?;
            }
            let key_id = validate_key_id(key_id.into())?;
            let gateway_id = validate_gateway_id(gateway_id)?;
            let encoding_key = EncodingKey::from_ed_pem(signing_key_pem)
                .map_err(|_| SessionJwtError::InvalidSigningKey)?;
            Ok(Self {
                encoding_key,
                key_id,
                issuer: format!("{GATEWAY_ISSUER_PREFIX}{gateway_id}"),
                ttl,
                clock,
            })
        }

        pub fn mint_pair(
            &self,
            identity: &SandboxRuntimeIdentity,
        ) -> Result<MintedSessionTokenPair, SessionJwtError> {
            self.mint_pair_with_gateway_token_id(identity, Uuid::new_v4())
        }

        /// Mint a token pair whose gateway-facing credential has a caller-owned
        /// lineage identifier.
        ///
        /// The gateway persists this identifier before returning the token so
        /// refresh can reject every superseded bearer across all replicas. The
        /// Sandbox Protocol credential remains independently identified.
        pub fn mint_pair_with_gateway_token_id(
            &self,
            identity: &SandboxRuntimeIdentity,
            gateway_token_id: Uuid,
        ) -> Result<MintedSessionTokenPair, SessionJwtError> {
            self.mint_pair_with_token_metadata(
                identity,
                gateway_token_id,
                Uuid::new_v4(),
                self.clock.now_unix_seconds(),
            )
        }

        /// Mint a reproducible token pair for a persisted refresh successor.
        pub fn mint_pair_with_token_metadata(
            &self,
            identity: &SandboxRuntimeIdentity,
            gateway_token_id: Uuid,
            sandbox_token_id: Uuid,
            issued_at: i64,
        ) -> Result<MintedSessionTokenPair, SessionJwtError> {
            Ok(MintedSessionTokenPair {
                gateway: self.mint(
                    SessionTokenProfile::Gateway,
                    identity,
                    gateway_token_id,
                    issued_at,
                )?,
                sandbox: self.mint(
                    SessionTokenProfile::Sandbox,
                    identity,
                    sandbox_token_id,
                    issued_at,
                )?,
                auth_epoch: identity.auth_epoch,
            })
        }

        /// Mint the shared supervisor's token for the gateway's assignment
        /// stream with its own bounded lifetime, independent of the session
        /// token lifetime (which may be non-expiring).
        pub fn mint_supervisor_token(
            &self,
            ttl: Duration,
        ) -> Result<MintedSessionToken, SessionJwtError> {
            validate_ttl(ttl)?;
            let issued_at = self.clock.now_unix_seconds();
            let expires_at =
                issued_at.saturating_add(i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX));
            let token_id = Uuid::new_v4();
            let gateway_id = &self.issuer[GATEWAY_ISSUER_PREFIX.len()..];
            let claims = SupervisorClaims {
                iss: self.issuer.clone(),
                sub: format!("{SUPERVISOR_SUBJECT_PREFIX}{gateway_id}"),
                aud: self.issuer.clone(),
                iat: issued_at,
                exp: expires_at,
                jti: token_id.to_string(),
                component: SessionComponent::OpenShellSupervisor,
            };
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some(self.key_id.clone());
            header.typ = Some(SUPERVISOR_JWT_TYPE.to_string());
            let token = encode(&header, &claims, &self.encoding_key)
                .map_err(|_| SessionJwtError::SigningFailed)?;
            Ok(MintedSessionToken {
                token: SecretJwt::parse(token)?,
                expires_at,
                token_id,
            })
        }

        /// Mint a takeover grant for `takeover`, valid for `ttl` (at most
        /// [`MAX_SUPERVISOR_TAKEOVER_TTL`]). The caller must already have
        /// advanced the sandbox's persisted credential epoch to
        /// `takeover.auth_epoch`.
        pub fn mint_supervisor_takeover(
            &self,
            takeover: &SupervisorTakeover,
            ttl: Duration,
        ) -> Result<MintedSessionToken, SessionJwtError> {
            if ttl.is_zero() || ttl > MAX_SUPERVISOR_TAKEOVER_TTL {
                return Err(SessionJwtError::InvalidLifetime);
            }
            validate_takeover_identity(&takeover.supervisor_instance, &takeover.owner)?;
            let issued_at = self.clock.now_unix_seconds();
            let expires_at =
                issued_at.saturating_add(i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX));
            let token_id = Uuid::new_v4();
            let claims = SupervisorTakeoverClaims {
                iss: self.issuer.clone(),
                sub: format!("{SANDBOX_SUBJECT_PREFIX}{}", takeover.sandbox_id),
                aud: SANDBOX_SESSION_AUDIENCE.to_string(),
                iat: issued_at,
                exp: expires_at,
                jti: token_id.to_string(),
                sandbox_id: takeover.sandbox_id.clone(),
                runtime_generation: takeover.runtime_generation.clone(),
                auth_epoch: takeover.auth_epoch,
                supervisor_instance: takeover.supervisor_instance.clone(),
                owner: takeover.owner.clone(),
                component: SessionComponent::OpenShellSupervisor,
            };
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some(self.key_id.clone());
            header.typ = Some(SUPERVISOR_TAKEOVER_JWT_TYPE.to_string());
            let token = encode(&header, &claims, &self.encoding_key)
                .map_err(|_| SessionJwtError::SigningFailed)?;
            Ok(MintedSessionToken {
                token: SecretJwt::parse(token)?,
                expires_at,
                token_id,
            })
        }

        fn mint(
            &self,
            profile: SessionTokenProfile,
            identity: &SandboxRuntimeIdentity,
            token_id: Uuid,
            issued_at: i64,
        ) -> Result<MintedSessionToken, SessionJwtError> {
            let expires_at = self.ttl.map_or(0, |ttl| {
                issued_at.saturating_add(i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX))
            });
            let claims = SessionClaims {
                iss: self.issuer.clone(),
                sub: format!("{SANDBOX_SUBJECT_PREFIX}{}", identity.sandbox_id),
                aud: profile.audience(&self.issuer).to_string(),
                iat: issued_at,
                exp: expires_at,
                jti: token_id.to_string(),
                sandbox_id: identity.sandbox_id.clone(),
                runtime_generation: identity.runtime_generation.clone(),
                auth_epoch: identity.auth_epoch,
                component: SessionComponent::OpenShellSupervisor,
            };
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some(self.key_id.clone());
            header.typ = Some(profile.token_type().to_string());
            let token = encode(&header, &claims, &self.encoding_key)
                .map_err(|_| SessionJwtError::SigningFailed)?;
            Ok(MintedSessionToken {
                token: SecretJwt::parse(token)?,
                expires_at,
                token_id,
            })
        }
    }

    /// One accepted public key from the immutable sandbox verification bundle.
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SessionVerificationKey {
        pub key_id: String,
        pub public_key_pem: Vec<u8>,
    }

    /// Strict verifier used by either the gateway or the Sandbox Protocol.
    pub struct SessionJwtVerifier {
        keys: BTreeMap<String, DecodingKey>,
        issuer: String,
        profile: SessionTokenProfile,
        clock: Arc<dyn JwtClock>,
    }

    impl fmt::Debug for SessionJwtVerifier {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SessionJwtVerifier")
                .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
                .field("issuer", &self.issuer)
                .field("profile", &self.profile)
                .finish_non_exhaustive()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AuthenticatedSandboxSession {
        pub sandbox_id: SandboxId,
        pub runtime_generation: SandboxGenerationId,
        pub auth_epoch: CredentialEpoch,
        pub token_id: Uuid,
        pub issued_at: i64,
        pub expires_at: i64,
    }

    impl SessionJwtVerifier {
        pub fn new(
            gateway_id: &str,
            profile: SessionTokenProfile,
            keys: impl IntoIterator<Item = SessionVerificationKey>,
            clock: Arc<dyn JwtClock>,
        ) -> Result<Self, SessionJwtError> {
            install_crypto_provider();
            let gateway_id = validate_gateway_id(gateway_id)?;
            Ok(Self {
                keys: parse_verification_keys(keys)?,
                issuer: format!("{GATEWAY_ISSUER_PREFIX}{gateway_id}"),
                profile,
                clock,
            })
        }

        pub fn verify(&self, token: &str) -> Result<AuthenticatedSandboxSession, SessionJwtError> {
            let claims = decode_signed::<SessionClaims>(
                &self.keys,
                token,
                self.profile.token_type(),
                &["iss", "aud", "iat", "exp", "sub", "jti"],
            )?;
            self.validate_claims(claims)
        }

        /// Verify a supervisor takeover grant. Only the Sandbox profile, which
        /// the runtime uses, verifies grants; the gateway profile refuses them.
        pub fn verify_supervisor_takeover(
            &self,
            token: &str,
        ) -> Result<VerifiedSupervisorTakeover, SessionJwtError> {
            if self.profile != SessionTokenProfile::Sandbox {
                return Err(SessionJwtError::WrongTokenType);
            }
            let claims = decode_signed::<SupervisorTakeoverClaims>(
                &self.keys,
                token,
                SUPERVISOR_TAKEOVER_JWT_TYPE,
                &["iss", "aud", "iat", "exp", "sub", "jti"],
            )?;
            if claims.iss != self.issuer {
                return Err(SessionJwtError::WrongIssuer);
            }
            if claims.aud != SANDBOX_SESSION_AUDIENCE {
                return Err(SessionJwtError::WrongAudience);
            }
            if claims.sub != format!("{SANDBOX_SUBJECT_PREFIX}{}", claims.sandbox_id) {
                return Err(SessionJwtError::SubjectMismatch);
            }
            SandboxGenerationId::parse(claims.runtime_generation.to_string())
                .map_err(|_| SessionJwtError::InvalidRuntimeIdentity)?;
            validate_takeover_identity(&claims.supervisor_instance, &claims.owner)?;
            let token_id = Uuid::parse_str(&claims.jti).map_err(|_| SessionJwtError::InvalidJti)?;
            // A grant must expire, within its own bound.
            let max_lifetime =
                i64::try_from(MAX_SUPERVISOR_TAKEOVER_TTL.as_secs()).unwrap_or(i64::MAX);
            if claims.exp == 0
                || claims.exp <= claims.iat
                || claims.exp.saturating_sub(claims.iat) > max_lifetime
            {
                return Err(SessionJwtError::InvalidLifetime);
            }
            validate_lifetime(claims.iat, claims.exp, self.clock.now_unix_seconds())?;
            Ok(VerifiedSupervisorTakeover {
                takeover: SupervisorTakeover {
                    sandbox_id: claims.sandbox_id,
                    runtime_generation: claims.runtime_generation,
                    auth_epoch: claims.auth_epoch,
                    supervisor_instance: claims.supervisor_instance,
                    owner: claims.owner,
                },
                token_id,
                expires_at: claims.exp,
            })
        }

        fn validate_claims(
            &self,
            claims: SessionClaims,
        ) -> Result<AuthenticatedSandboxSession, SessionJwtError> {
            if claims.iss != self.issuer {
                return Err(SessionJwtError::WrongIssuer);
            }
            if claims.aud != self.profile.audience(&self.issuer) {
                return Err(SessionJwtError::WrongAudience);
            }
            if claims.sub != format!("{SANDBOX_SUBJECT_PREFIX}{}", claims.sandbox_id) {
                return Err(SessionJwtError::SubjectMismatch);
            }
            SandboxGenerationId::parse(claims.runtime_generation.to_string())
                .map_err(|_| SessionJwtError::InvalidRuntimeIdentity)?;
            let token_id = Uuid::parse_str(&claims.jti).map_err(|_| SessionJwtError::InvalidJti)?;
            validate_lifetime(claims.iat, claims.exp, self.clock.now_unix_seconds())?;
            Ok(AuthenticatedSandboxSession {
                sandbox_id: claims.sandbox_id,
                runtime_generation: claims.runtime_generation,
                auth_epoch: claims.auth_epoch,
                token_id,
                issued_at: claims.iat,
                expires_at: claims.exp,
            })
        }
    }

    /// A verified supervisor token.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AuthenticatedSupervisor {
        /// `openshell-supervisor:<gateway_id>`.
        pub subject: String,
        pub token_id: Uuid,
        pub issued_at: i64,
        pub expires_at: i64,
    }

    /// Strict gateway-side verifier of supervisor tokens. Accepts only the
    /// supervisor profile signed by this gateway for this gateway.
    pub struct SupervisorJwtVerifier {
        keys: BTreeMap<String, DecodingKey>,
        issuer: String,
        subject: String,
        clock: Arc<dyn JwtClock>,
    }

    impl fmt::Debug for SupervisorJwtVerifier {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SupervisorJwtVerifier")
                .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
                .field("issuer", &self.issuer)
                .finish_non_exhaustive()
        }
    }

    impl SupervisorJwtVerifier {
        pub fn new(
            gateway_id: &str,
            keys: impl IntoIterator<Item = SessionVerificationKey>,
            clock: Arc<dyn JwtClock>,
        ) -> Result<Self, SessionJwtError> {
            install_crypto_provider();
            let gateway_id = validate_gateway_id(gateway_id)?;
            Ok(Self {
                keys: parse_verification_keys(keys)?,
                issuer: format!("{GATEWAY_ISSUER_PREFIX}{gateway_id}"),
                subject: format!("{SUPERVISOR_SUBJECT_PREFIX}{gateway_id}"),
                clock,
            })
        }

        pub fn verify(&self, token: &str) -> Result<AuthenticatedSupervisor, SessionJwtError> {
            let claims = decode_signed::<SupervisorClaims>(
                &self.keys,
                token,
                SUPERVISOR_JWT_TYPE,
                &["iss", "aud", "iat", "exp", "sub", "jti"],
            )?;
            if claims.iss != self.issuer {
                return Err(SessionJwtError::WrongIssuer);
            }
            if claims.aud != self.issuer {
                return Err(SessionJwtError::WrongAudience);
            }
            if claims.sub != self.subject {
                return Err(SessionJwtError::SubjectMismatch);
            }
            let token_id = Uuid::parse_str(&claims.jti).map_err(|_| SessionJwtError::InvalidJti)?;
            // Supervisor tokens must expire; a non-expiring one is refused.
            if claims.exp == 0 {
                return Err(SessionJwtError::InvalidLifetime);
            }
            validate_lifetime(claims.iat, claims.exp, self.clock.now_unix_seconds())?;
            Ok(AuthenticatedSupervisor {
                subject: claims.sub,
                token_id,
                issued_at: claims.iat,
                expires_at: claims.exp,
            })
        }
    }

    fn parse_verification_keys(
        keys: impl IntoIterator<Item = SessionVerificationKey>,
    ) -> Result<BTreeMap<String, DecodingKey>, SessionJwtError> {
        let mut parsed = BTreeMap::new();
        for key in keys {
            let key_id = validate_key_id(key.key_id)?;
            let decoding_key = DecodingKey::from_ed_pem(&key.public_key_pem)
                .map_err(|_| SessionJwtError::InvalidVerificationKey)?;
            if parsed.insert(key_id, decoding_key).is_some() {
                return Err(SessionJwtError::DuplicateKeyId);
            }
        }
        if parsed.is_empty() {
            return Err(SessionJwtError::NoVerificationKeys);
        }
        Ok(parsed)
    }

    /// Check the header (`EdDSA` only, exact `typ`, known `kid`) and the
    /// signature, then decode the claims. Time and audience are validated by
    /// the caller against its own clock and profile.
    fn decode_signed<T: serde::de::DeserializeOwned>(
        keys: &BTreeMap<String, DecodingKey>,
        token: &str,
        token_type: &str,
        required_claims: &[&str],
    ) -> Result<T, SessionJwtError> {
        install_crypto_provider();
        let header = decode_header(token).map_err(|_| SessionJwtError::InvalidToken)?;
        if header.alg != Algorithm::EdDSA {
            return Err(SessionJwtError::WrongAlgorithm);
        }
        if header.typ.as_deref() != Some(token_type) {
            return Err(SessionJwtError::WrongTokenType);
        }
        let key_id = header.kid.ok_or(SessionJwtError::MissingKeyId)?;
        let key = keys.get(&key_id).ok_or(SessionJwtError::UnknownKeyId)?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.algorithms = vec![Algorithm::EdDSA];
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.set_required_spec_claims(required_claims);
        Ok(decode::<T>(token, key, &validation)
            .map_err(|_| SessionJwtError::InvalidToken)?
            .claims)
    }

    /// Shared lifetime rules: not issued in the future, and when expiring,
    /// a positive lifetime within the session bound that has not passed.
    fn validate_lifetime(issued_at: i64, expires_at: i64, now: i64) -> Result<(), SessionJwtError> {
        let leeway = i64::try_from(MAX_SESSION_CLOCK_LEEWAY.as_secs()).unwrap_or(30);
        if issued_at > now.saturating_add(leeway) {
            return Err(SessionJwtError::IssuedInFuture);
        }
        if expires_at != 0 {
            if expires_at <= issued_at {
                return Err(SessionJwtError::InvalidLifetime);
            }
            let lifetime = expires_at.saturating_sub(issued_at);
            if lifetime > i64::try_from(MAX_SESSION_TOKEN_TTL.as_secs()).unwrap_or(i64::MAX) {
                return Err(SessionJwtError::InvalidLifetime);
            }
            if expires_at < now.saturating_sub(leeway) {
                return Err(SessionJwtError::Expired);
            }
        }
        Ok(())
    }

    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    pub enum SessionJwtError {
        #[error("sandbox ID is invalid")]
        InvalidSandboxId,
        #[error("gateway ID is invalid")]
        InvalidGatewayId,
        #[error("credential epoch must be positive")]
        InvalidCredentialEpoch,
        #[error("credential epoch does not advance the active credential")]
        StaleCredentialEpoch,
        #[error("session rotation must be positive")]
        InvalidSessionRotation,
        #[error("session rotation overflow")]
        SessionRotationOverflow,
        #[error("sandbox runtime identity is missing")]
        MissingRuntimeIdentity,
        #[error("sandbox runtime identity is invalid")]
        InvalidRuntimeIdentity,
        #[error("key ID is invalid")]
        InvalidKeyId,
        #[error("verification key IDs must be unique")]
        DuplicateKeyId,
        #[error("at least one verification key is required")]
        NoVerificationKeys,
        #[error("Ed25519 signing key is invalid")]
        InvalidSigningKey,
        #[error("Ed25519 verification key is invalid")]
        InvalidVerificationKey,
        #[error("session token lifetime must be non-expiring or between 60 and 3600 seconds")]
        InvalidLifetime,
        #[error("session token profile does not match its claims")]
        ProfileMismatch,
        #[error("session token could not be signed")]
        SigningFailed,
        #[error("session token encoding is invalid")]
        InvalidTokenEncoding,
        #[error("session token is unavailable")]
        TokenUnavailable,
        #[error("session token is invalid")]
        InvalidToken,
        #[error("session token algorithm must be EdDSA")]
        WrongAlgorithm,
        #[error("session token type is invalid")]
        WrongTokenType,
        #[error("session token key ID is missing")]
        MissingKeyId,
        #[error("session token key ID is unknown")]
        UnknownKeyId,
        #[error("session token issuer is invalid")]
        WrongIssuer,
        #[error("session token audience is invalid")]
        WrongAudience,
        #[error("session token subject does not match its sandbox ID")]
        SubjectMismatch,
        #[error("session token ID is not a UUID")]
        InvalidJti,
        #[error("session token was issued in the future")]
        IssuedInFuture,
        #[error("session token has expired")]
        Expired,
    }

    fn install_crypto_provider() {
        openshell_crypto::install_jwt_provider();
    }

    fn validate_ttl(ttl: Duration) -> Result<(), SessionJwtError> {
        if !(MIN_SESSION_TOKEN_TTL..=MAX_SESSION_TOKEN_TTL).contains(&ttl) {
            return Err(SessionJwtError::InvalidLifetime);
        }
        Ok(())
    }

    fn validate_gateway_id(gateway_id: &str) -> Result<&str, SessionJwtError> {
        if gateway_id.is_empty()
            || gateway_id.trim() != gateway_id
            || gateway_id.chars().any(char::is_whitespace)
        {
            return Err(SessionJwtError::InvalidGatewayId);
        }
        Ok(gateway_id)
    }

    /// A takeover names a non-blank supervisor instance and owner without
    /// whitespace; the runtime compares the instance with its attach request.
    fn validate_takeover_identity(
        supervisor_instance: &str,
        owner: &str,
    ) -> Result<(), SessionJwtError> {
        let valid = |value: &str| {
            !value.is_empty() && value.len() <= 253 && !value.chars().any(char::is_whitespace)
        };
        if valid(supervisor_instance) && valid(owner) {
            Ok(())
        } else {
            Err(SessionJwtError::InvalidRuntimeIdentity)
        }
    }

    fn validate_key_id(key_id: String) -> Result<String, SessionJwtError> {
        if key_id.is_empty() || key_id.trim() != key_id || key_id.chars().any(char::is_whitespace) {
            return Err(SessionJwtError::InvalidKeyId);
        }
        Ok(key_id)
    }
}

#[cfg(feature = "jwt")]
pub use session::*;

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestClaims<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        exp: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sub: Option<&'a str>,
    }

    fn jwt_with_payload(payload: &TestClaims<'_>) -> String {
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let header = b64(br#"{"alg":"none","typ":"JWT"}"#);
        let body = b64(serde_json::to_vec(payload).unwrap().as_slice());
        format!("{header}.{body}.")
    }

    #[test]
    fn reads_integer_exp() {
        let token = jwt_with_payload(&TestClaims {
            exp: Some(1_900_000_000),
            sub: None,
        });
        assert_eq!(parse_exp_secs(&token), Some(1_900_000_000));
    }

    #[test]
    fn tolerates_bearer_prefix() {
        let token = jwt_with_payload(&TestClaims {
            exp: Some(42),
            sub: None,
        });
        assert_eq!(parse_exp_secs(&format!("Bearer {token}")), Some(42));
        assert_eq!(parse_exp_secs(&format!("bearer {token}")), Some(42));
    }

    #[test]
    fn none_for_missing_exp_or_non_jwt() {
        assert_eq!(
            parse_exp_secs(&jwt_with_payload(&TestClaims {
                exp: None,
                sub: Some("x"),
            })),
            None
        );
        assert_eq!(parse_exp_secs("not-a-jwt"), None);
        assert_eq!(parse_exp_secs(""), None);
    }

    #[cfg(feature = "jwt")]
    mod session_tests {
        use std::sync::Arc;

        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        use openshell_crypto::jwt::encode;
        use rcgen::PKCS_ED25519;
        use serde::Serialize;

        use super::super::session::*;
        use crate::SandboxSessionId;
        use crate::sandbox_generation::SandboxGenerationId;

        #[derive(Debug)]
        struct FixedClock(i64);

        impl JwtClock for FixedClock {
            fn now_unix_seconds(&self) -> i64 {
                self.0
            }
        }

        fn fixture() -> (
            SessionJwtIssuer,
            SessionJwtVerifier,
            SessionJwtVerifier,
            SandboxRuntimeIdentity,
        ) {
            let key = openshell_crypto::pki::generate_keypair_for(&PKCS_ED25519)
                .expect("generate Ed25519 key");
            let public_key_pem = key.public_key_pem().into_bytes();
            let clock: Arc<dyn JwtClock> = Arc::new(FixedClock(1_900_000_000));
            let issuer = SessionJwtIssuer::from_ed25519_pem(
                key.serialize_pem().unwrap().as_bytes(),
                "current",
                "test",
                Some(DEFAULT_SESSION_TOKEN_TTL),
                clock.clone(),
            )
            .expect("issuer");
            let key = || SessionVerificationKey {
                key_id: "current".to_string(),
                public_key_pem: public_key_pem.clone(),
            };
            let gateway = SessionJwtVerifier::new(
                "test",
                SessionTokenProfile::Gateway,
                [key()],
                clock.clone(),
            )
            .expect("gateway verifier");
            let sandbox =
                SessionJwtVerifier::new("test", SessionTokenProfile::Sandbox, [key()], clock)
                    .expect("sandbox verifier");
            let identity = SandboxRuntimeIdentity {
                sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox ID"),
                runtime_generation: SandboxGenerationId::parse("generation-1")
                    .expect("runtime generation"),
                auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
            };
            (issuer, gateway, sandbox, identity)
        }

        #[test]
        fn token_profiles_are_not_interchangeable() {
            let (issuer, gateway, sandbox, identity) = fixture();
            let pair = issuer.mint_pair(&identity).expect("token pair");

            let gateway_session = gateway
                .verify(pair.gateway.token.expose_secret())
                .expect("gateway token");
            assert_eq!(gateway_session.auth_epoch, identity.auth_epoch);

            let sandbox_session = sandbox
                .verify(pair.sandbox.token.expose_secret())
                .expect("sandbox token");
            assert_eq!(sandbox_session.auth_epoch, identity.auth_epoch);

            assert_eq!(
                gateway.verify(pair.sandbox.token.expose_secret()),
                Err(SessionJwtError::WrongTokenType)
            );
            assert_eq!(
                sandbox.verify(pair.gateway.token.expose_secret()),
                Err(SessionJwtError::WrongTokenType)
            );
        }

        #[test]
        fn supervisor_tokens_are_a_separate_profile_bound_to_the_gateway() {
            let (issuer, gateway, sandbox, _identity) = fixture();
            let minted = issuer
                .mint_supervisor_token(std::time::Duration::from_mins(15))
                .expect("supervisor token");
            assert_eq!(minted.expires_at, 1_900_000_000 + 900);

            let key = openshell_crypto::pki::generate_keypair_for(&PKCS_ED25519).unwrap();
            let public_key_pem = key.public_key_pem().into_bytes();
            let clock: Arc<dyn JwtClock> = Arc::new(FixedClock(1_900_000_000));
            // A verifier holding a different key under the same key ID sees a
            // signature failure, not a key lookup failure.
            let verification_key = |pem: Vec<u8>| SessionVerificationKey {
                key_id: "current".to_string(),
                public_key_pem: pem,
            };
            let wrong_key = SupervisorJwtVerifier::new(
                "test",
                [verification_key(public_key_pem)],
                clock.clone(),
            )
            .expect("verifier");
            assert_eq!(
                wrong_key.verify(minted.token.expose_secret()),
                Err(SessionJwtError::InvalidToken)
            );

            // Session verifiers refuse the supervisor profile and the supervisor
            // verifier refuses session tokens, whatever key signed them.
            assert_eq!(
                gateway.verify(minted.token.expose_secret()),
                Err(SessionJwtError::WrongTokenType)
            );
            assert_eq!(
                sandbox.verify(minted.token.expose_secret()),
                Err(SessionJwtError::WrongTokenType)
            );
            let identity = SandboxRuntimeIdentity {
                sandbox_id: SandboxId::parse("sandbox-a").unwrap(),
                runtime_generation: SandboxGenerationId::parse("generation-1").unwrap(),
                auth_epoch: CredentialEpoch::new(1).unwrap(),
            };
            let pair = issuer.mint_pair(&identity).unwrap();
            assert_eq!(
                wrong_key.verify(pair.gateway.token.expose_secret()),
                Err(SessionJwtError::WrongTokenType)
            );

            // The supervisor lifetime is bounded on its own, whatever the
            // session lifetime is.
            drop(clock);
            for ttl in [
                std::time::Duration::from_secs(59),
                std::time::Duration::from_secs(3_601),
            ] {
                assert_eq!(
                    issuer.mint_supervisor_token(ttl).unwrap_err(),
                    SessionJwtError::InvalidLifetime
                );
            }
        }

        #[test]
        fn supervisor_tokens_verify_only_for_their_gateway_and_lifetime() {
            let key = openshell_crypto::pki::generate_keypair_for(&PKCS_ED25519).unwrap();
            let public_key_pem = key.public_key_pem().into_bytes();
            let signing_pem = key.serialize_pem().unwrap();
            let verification_key = || SessionVerificationKey {
                key_id: "current".to_string(),
                public_key_pem: public_key_pem.clone(),
            };
            let issuer = |gateway_id: &str, now: i64| {
                SessionJwtIssuer::from_ed25519_pem(
                    signing_pem.as_bytes(),
                    "current",
                    gateway_id,
                    Some(std::time::Duration::from_mins(15)),
                    Arc::new(FixedClock(now)),
                )
                .unwrap()
            };
            let verifier = |gateway_id: &str, now: i64| {
                SupervisorJwtVerifier::new(
                    gateway_id,
                    [verification_key()],
                    Arc::new(FixedClock(now)),
                )
                .unwrap()
            };

            let minted = issuer("gw-a", 1_900_000_000)
                .mint_supervisor_token(std::time::Duration::from_mins(15))
                .unwrap();
            let authenticated = verifier("gw-a", 1_900_000_100)
                .verify(minted.token.expose_secret())
                .expect("valid supervisor token");
            assert_eq!(authenticated.subject, "openshell-supervisor:gw-a");
            assert_eq!(authenticated.token_id, minted.token_id);
            assert_eq!(authenticated.expires_at, 1_900_000_900);

            // Another gateway's token is refused by issuer, audience, and subject.
            assert_eq!(
                verifier("gw-b", 1_900_000_100).verify(minted.token.expose_secret()),
                Err(SessionJwtError::WrongIssuer)
            );
            // Expired tokens are refused past the leeway.
            assert_eq!(
                verifier("gw-a", 1_900_001_000).verify(minted.token.expose_secret()),
                Err(SessionJwtError::Expired)
            );
            assert_eq!(
                verifier("gw-a", 1_899_999_000).verify(minted.token.expose_secret()),
                Err(SessionJwtError::IssuedInFuture)
            );
            assert_eq!(
                verifier("gw-a", 1_900_000_100).verify("not-a-token"),
                Err(SessionJwtError::InvalidToken)
            );
        }

        #[derive(Serialize)]
        struct NonExpiringSupervisor<'a> {
            iss: &'a str,
            sub: &'a str,
            aud: &'a str,
            iat: i64,
            exp: i64,
            jti: String,
            component: SessionComponent,
        }

        #[test]
        fn non_expiring_session_tokens_remain_usable() {
            let key = openshell_crypto::pki::generate_keypair_for(&PKCS_ED25519)
                .expect("generate Ed25519 key");
            let public_key_pem = key.public_key_pem().into_bytes();
            let issuer = SessionJwtIssuer::from_ed25519_pem(
                key.serialize_pem().unwrap().as_bytes(),
                "current",
                "test",
                None,
                Arc::new(FixedClock(1_900_000_000)),
            )
            .expect("issuer");
            let verifier = SessionJwtVerifier::new(
                "test",
                SessionTokenProfile::Sandbox,
                [SessionVerificationKey {
                    key_id: "current".to_string(),
                    public_key_pem,
                }],
                Arc::new(FixedClock(2_000_000_000)),
            )
            .expect("verifier");
            let identity = SandboxRuntimeIdentity {
                sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox ID"),
                runtime_generation: SandboxGenerationId::parse("generation-1")
                    .expect("runtime generation"),
                auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
            };
            let pair = issuer.mint_pair(&identity).expect("token pair");

            assert_eq!(pair.gateway.expires_at, 0);
            assert_eq!(pair.sandbox.expires_at, 0);
            verifier
                .verify(pair.sandbox.token.expose_secret())
                .expect("non-expiring token remains valid");

            // The default (non-expiring) session issuer still mints expiring
            // supervisor tokens, and a supervisor token must expire.
            let supervisor = issuer
                .mint_supervisor_token(std::time::Duration::from_mins(15))
                .expect("supervisor token from a non-expiring issuer");
            assert_eq!(supervisor.expires_at, 1_900_000_000 + 900);
            let supervisor_verifier = SupervisorJwtVerifier::new(
                "test",
                [SessionVerificationKey {
                    key_id: "current".to_string(),
                    public_key_pem: key.public_key_pem().into_bytes(),
                }],
                Arc::new(FixedClock(1_900_000_100)),
            )
            .unwrap();
            supervisor_verifier
                .verify(supervisor.token.expose_secret())
                .expect("expiring supervisor token");
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some("current".to_string());
            header.typ = Some(SUPERVISOR_JWT_TYPE.to_string());
            let forever = encode(
                &header,
                &NonExpiringSupervisor {
                    iss: "openshell-gateway:test",
                    sub: "openshell-supervisor:test",
                    aud: "openshell-gateway:test",
                    iat: 1_900_000_000,
                    exp: 0,
                    jti: uuid::Uuid::new_v4().to_string(),
                    component: SessionComponent::OpenShellSupervisor,
                },
                &EncodingKey::from_ed_pem(key.serialize_pem().unwrap().as_bytes()).unwrap(),
            )
            .unwrap();
            assert_eq!(
                supervisor_verifier.verify(&forever),
                Err(SessionJwtError::InvalidLifetime)
            );

            let slot = SessionBearerTokenSlot::new(
                pair.sandbox.token.clone(),
                pair.sandbox.expires_at,
                pair.auth_epoch,
            )
            .expect("non-expiring bearer slot");
            slot.authorization_metadata()
                .expect("non-expiring bearer remains available");

            let bundle = SupervisorAuthBundle {
                session_id: SandboxSessionId::new(),
                session_rotation: SessionRotation::new(1).expect("session rotation"),
                runtime_generation: identity.runtime_generation,
                auth_epoch: pair.auth_epoch,
                gateway_token: pair.gateway.token,
                gateway_expires_at: pair.gateway.expires_at,
                sandbox_token: pair.sandbox.token,
                sandbox_expires_at: pair.sandbox.expires_at,
                ssh_host_private_key: None,
                ocsf_otlp_headers: None,
            };
            bundle.validate().expect("non-expiring auth bundle");
        }

        fn takeover(epoch: u64) -> SupervisorTakeover {
            SupervisorTakeover {
                sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox ID"),
                runtime_generation: SandboxGenerationId::parse("generation-1")
                    .expect("runtime generation"),
                auth_epoch: CredentialEpoch::new(epoch).expect("auth epoch"),
                supervisor_instance: "6a8f1f4e-8c0e-4d55-9d8c-1d6e2f3a4b5c".to_string(),
                owner: "supervisor-1".to_string(),
            }
        }

        #[test]
        fn takeover_grants_are_their_own_profile_verified_only_by_the_runtime() {
            let (issuer, gateway, sandbox, identity) = fixture();
            let expected = takeover(2);
            let minted = issuer
                .mint_supervisor_takeover(&expected, std::time::Duration::from_mins(5))
                .expect("mint takeover grant");
            let verified = sandbox
                .verify_supervisor_takeover(minted.token.expose_secret())
                .expect("runtime verifies the grant");
            assert_eq!(verified.takeover, expected);
            assert_eq!(verified.token_id, minted.token_id);
            assert_eq!(verified.expires_at, 1_900_000_000 + 300);

            // A grant is never a session credential, and no other credential is
            // a grant: neither session profile nor the shared supervisor token.
            assert_eq!(
                sandbox.verify(minted.token.expose_secret()),
                Err(SessionJwtError::WrongTokenType)
            );
            assert_eq!(
                gateway.verify_supervisor_takeover(minted.token.expose_secret()),
                Err(SessionJwtError::WrongTokenType)
            );
            let pair = issuer.mint_pair(&identity).expect("token pair");
            for token in [&pair.sandbox.token, &pair.gateway.token] {
                assert_eq!(
                    sandbox.verify_supervisor_takeover(token.expose_secret()),
                    Err(SessionJwtError::WrongTokenType)
                );
            }
            let host = issuer
                .mint_supervisor_token(std::time::Duration::from_mins(15))
                .expect("supervisor token");
            assert_eq!(
                sandbox.verify_supervisor_takeover(host.token.expose_secret()),
                Err(SessionJwtError::WrongTokenType)
            );
        }

        #[test]
        fn takeover_grants_are_bounded_named_and_expire() {
            let (issuer, _gateway, _sandbox, _identity) = fixture();
            for ttl in [
                std::time::Duration::ZERO,
                MAX_SUPERVISOR_TAKEOVER_TTL + std::time::Duration::from_secs(1),
            ] {
                assert_eq!(
                    issuer.mint_supervisor_takeover(&takeover(2), ttl).err(),
                    Some(SessionJwtError::InvalidLifetime)
                );
            }
            for (instance, owner) in [("", "member"), ("instance", ""), ("in stance", "m")] {
                let mut unnamed = takeover(2);
                unnamed.supervisor_instance = instance.to_string();
                unnamed.owner = owner.to_string();
                assert_eq!(
                    issuer
                        .mint_supervisor_takeover(&unnamed, std::time::Duration::from_mins(5))
                        .err(),
                    Some(SessionJwtError::InvalidRuntimeIdentity)
                );
            }

            let key = openshell_crypto::pki::generate_keypair_for(&PKCS_ED25519).unwrap();
            let issuer = SessionJwtIssuer::from_ed25519_pem(
                key.serialize_pem().unwrap().as_bytes(),
                "current",
                "test",
                None,
                Arc::new(FixedClock(1_900_000_000)),
            )
            .unwrap();
            let verifier_at = |now| {
                SessionJwtVerifier::new(
                    "test",
                    SessionTokenProfile::Sandbox,
                    [SessionVerificationKey {
                        key_id: "current".to_string(),
                        public_key_pem: key.public_key_pem().into_bytes(),
                    }],
                    Arc::new(FixedClock(now)),
                )
                .unwrap()
            };
            // A non-expiring session issuer still mints expiring grants.
            let minted = issuer
                .mint_supervisor_takeover(&takeover(3), std::time::Duration::from_mins(1))
                .unwrap();
            verifier_at(1_900_000_030)
                .verify_supervisor_takeover(minted.token.expose_secret())
                .expect("grant within its lifetime");
            assert_eq!(
                verifier_at(1_900_000_200).verify_supervisor_takeover(minted.token.expose_secret()),
                Err(SessionJwtError::Expired)
            );
        }

        #[test]
        fn token_debug_is_redacted() {
            let (issuer, _gateway, _sandbox, identity) = fixture();
            let pair = issuer.mint_pair(&identity).expect("token pair");
            let debug = format!("{:?}", pair.sandbox.token);
            assert_eq!(debug, "SecretJwt([REDACTED])");
            assert!(!debug.contains(pair.sandbox.token.expose_secret()));
        }

        #[test]
        fn supervisor_auth_bundle_round_trips_without_exposing_secrets_in_debug() {
            let (issuer, _gateway, _sandbox, identity) = fixture();
            let pair = issuer.mint_pair(&identity).expect("token pair");
            let bundle = SupervisorAuthBundle {
                session_id: SandboxSessionId::new(),
                session_rotation: SessionRotation::new(1).expect("session rotation"),
                runtime_generation: identity.runtime_generation.clone(),
                auth_epoch: identity.auth_epoch,
                gateway_token: pair.gateway.token,
                gateway_expires_at: pair.gateway.expires_at,
                sandbox_token: pair.sandbox.token,
                sandbox_expires_at: pair.sandbox.expires_at,
                ssh_host_private_key: Some(SecretSshHostKey::new(
                    "private-ssh-host-key".to_string(),
                )),
                ocsf_otlp_headers: Some(SecretOtlpHeaders::new(
                    "authorization=collector-token".to_string(),
                )),
            };

            let encoded = serde_json::to_vec(&bundle).expect("serialize auth bundle");
            let decoded: SupervisorAuthBundle =
                serde_json::from_slice(&encoded).expect("deserialize auth bundle");
            assert_eq!(decoded.auth_epoch, bundle.auth_epoch);
            assert_eq!(
                decoded.gateway_token.expose_secret(),
                bundle.gateway_token.expose_secret()
            );
            assert_eq!(
                decoded.sandbox_token.expose_secret(),
                bundle.sandbox_token.expose_secret()
            );

            let debug = format!("{bundle:?}");
            assert!(!debug.contains(bundle.gateway_token.expose_secret()));
            assert!(!debug.contains(bundle.sandbox_token.expose_secret()));
            assert!(!debug.contains("private-ssh-host-key"));
            assert!(!debug.contains("collector-token"));
            assert_eq!(debug.matches("[REDACTED]").count(), 4);
            assert_eq!(
                decoded.ssh_host_private_key.unwrap().expose_secret(),
                "private-ssh-host-key"
            );
            assert_eq!(
                decoded.ocsf_otlp_headers.unwrap().expose_secret(),
                "authorization=collector-token"
            );
            let mut legacy = serde_json::to_value(&bundle).unwrap();
            let fields = legacy.as_object_mut().unwrap();
            fields.remove("ssh_host_private_key");
            fields.remove("ocsf_otlp_headers");
            let legacy: SupervisorAuthBundle = serde_json::from_value(legacy).unwrap();
            assert!(legacy.ssh_host_private_key.is_none());
            assert!(legacy.ocsf_otlp_headers.is_none());
        }

        #[derive(Serialize)]
        struct AudienceArrayClaims<'a> {
            iss: &'a str,
            sub: &'a str,
            aud: [&'a str; 1],
            iat: i64,
            exp: i64,
            jti: String,
            sandbox_id: &'a str,
            runtime_generation: &'a str,
            auth_epoch: CredentialEpoch,
            component: SessionComponent,
        }

        #[test]
        fn audience_arrays_are_rejected() {
            let key = openshell_crypto::pki::generate_keypair_for(&PKCS_ED25519)
                .expect("generate Ed25519 key");
            let clock: Arc<dyn JwtClock> = Arc::new(FixedClock(1_900_000_000));
            let verifier = SessionJwtVerifier::new(
                "test",
                SessionTokenProfile::Gateway,
                [SessionVerificationKey {
                    key_id: "current".to_string(),
                    public_key_pem: key.public_key_pem().into_bytes(),
                }],
                clock,
            )
            .expect("verifier");
            let claims = AudienceArrayClaims {
                iss: "openshell-gateway:test",
                sub: "spiffe://openshell/sandbox/sandbox-a",
                aud: ["openshell-gateway:test"],
                iat: 1_900_000_000,
                exp: 1_900_003_600,
                jti: uuid::Uuid::new_v4().to_string(),
                sandbox_id: "sandbox-a",
                runtime_generation: "generation-1",
                auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
                component: SessionComponent::OpenShellSupervisor,
            };
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some("current".to_string());
            header.typ = Some(GATEWAY_SESSION_JWT_TYPE.to_string());
            let token = encode(
                &header,
                &claims,
                &EncodingKey::from_ed_pem(key.serialize_pem().unwrap().as_bytes())
                    .expect("encoding key"),
            )
            .expect("token");
            assert_eq!(verifier.verify(&token), Err(SessionJwtError::InvalidToken));
        }
    }
}
