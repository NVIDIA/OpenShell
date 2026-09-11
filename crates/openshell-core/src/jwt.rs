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
    let raw = token.strip_prefix("Bearer ").unwrap_or(token);
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

    use jsonwebtoken::{
        Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
    };
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use crate::SandboxSessionId;

    pub const GATEWAY_SESSION_JWT_TYPE: &str = "openshell-gateway-session+jwt";
    pub const SANDBOX_SESSION_JWT_TYPE: &str = "openshell-sandbox-session+jwt";
    pub const SANDBOX_SESSION_AUDIENCE: &str = "openshell-sandbox";
    pub const DEFAULT_SESSION_TOKEN_TTL: Duration = Duration::from_secs(60 * 60);
    pub const MIN_SESSION_TOKEN_TTL: Duration = Duration::from_secs(60);
    pub const MAX_SESSION_TOKEN_TTL: Duration = Duration::from_secs(60 * 60);
    pub const MAX_SESSION_CLOCK_LEEWAY: Duration = Duration::from_secs(30);

    const GATEWAY_ISSUER_PREFIX: &str = "openshell-gateway:";
    const SANDBOX_SUBJECT_PREFIX: &str = "spiffe://openshell/sandbox/";

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
        session_id: SandboxSessionId,
        component: SessionComponent,
        #[serde(skip_serializing_if = "Option::is_none")]
        credential_epoch: Option<CredentialEpoch>,
    }

    /// Authoritative fields used to mint one token pair.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SandboxSessionIdentity {
        pub sandbox_id: SandboxId,
        pub session_id: SandboxSessionId,
    }

    /// A JWT whose contents are deliberately omitted from `Debug` output and
    /// zeroed when its final owner is dropped.
    #[derive(Clone)]
    pub struct SecretJwt(Zeroizing<String>);

    impl SecretJwt {
        fn new(value: String) -> Result<Self, SessionJwtError> {
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
        pub credential_epoch: CredentialEpoch,
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
        ttl: Duration,
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
            ttl: Duration,
            clock: Arc<dyn JwtClock>,
        ) -> Result<Self, SessionJwtError> {
            install_crypto_provider();
            validate_ttl(ttl)?;
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
            identity: &SandboxSessionIdentity,
            credential_epoch: CredentialEpoch,
        ) -> Result<MintedSessionTokenPair, SessionJwtError> {
            Ok(MintedSessionTokenPair {
                gateway: self.mint(SessionTokenProfile::Gateway, identity, None)?,
                sandbox: self.mint(
                    SessionTokenProfile::Sandbox,
                    identity,
                    Some(credential_epoch),
                )?,
                credential_epoch,
            })
        }

        fn mint(
            &self,
            profile: SessionTokenProfile,
            identity: &SandboxSessionIdentity,
            credential_epoch: Option<CredentialEpoch>,
        ) -> Result<MintedSessionToken, SessionJwtError> {
            if matches!(profile, SessionTokenProfile::Gateway) && credential_epoch.is_some()
                || matches!(profile, SessionTokenProfile::Sandbox) && credential_epoch.is_none()
            {
                return Err(SessionJwtError::ProfileMismatch);
            }
            let issued_at = self.clock.now_unix_seconds();
            let expires_at = issued_at.saturating_add(
                i64::try_from(self.ttl.as_secs()).map_err(|_| SessionJwtError::InvalidLifetime)?,
            );
            let token_id = Uuid::new_v4();
            let claims = SessionClaims {
                iss: self.issuer.clone(),
                sub: format!("{SANDBOX_SUBJECT_PREFIX}{}", identity.sandbox_id),
                aud: profile.audience(&self.issuer).to_string(),
                iat: issued_at,
                exp: expires_at,
                jti: token_id.to_string(),
                sandbox_id: identity.sandbox_id.clone(),
                session_id: identity.session_id,
                component: SessionComponent::OpenShellSupervisor,
                credential_epoch,
            };
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some(self.key_id.clone());
            header.typ = Some(profile.token_type().to_string());
            let token = encode(&header, &claims, &self.encoding_key)
                .map_err(|_| SessionJwtError::SigningFailed)?;
            Ok(MintedSessionToken {
                token: SecretJwt::new(token)?,
                expires_at,
                token_id,
            })
        }
    }

    /// One accepted public key from the immutable sandbox verification bundle.
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
        pub session_id: SandboxSessionId,
        pub credential_epoch: Option<CredentialEpoch>,
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
            Ok(Self {
                keys: parsed,
                issuer: format!("{GATEWAY_ISSUER_PREFIX}{gateway_id}"),
                profile,
                clock,
            })
        }

        pub fn verify(&self, token: &str) -> Result<AuthenticatedSandboxSession, SessionJwtError> {
            install_crypto_provider();
            let header = decode_header(token).map_err(|_| SessionJwtError::InvalidToken)?;
            if header.alg != Algorithm::EdDSA {
                return Err(SessionJwtError::WrongAlgorithm);
            }
            if header.typ.as_deref() != Some(self.profile.token_type()) {
                return Err(SessionJwtError::WrongTokenType);
            }
            let key_id = header.kid.ok_or(SessionJwtError::MissingKeyId)?;
            let key = self
                .keys
                .get(&key_id)
                .ok_or(SessionJwtError::UnknownKeyId)?;
            let mut validation = Validation::new(Algorithm::EdDSA);
            validation.algorithms = vec![Algorithm::EdDSA];
            validation.validate_exp = false;
            validation.validate_aud = false;
            validation.set_required_spec_claims(&["iss", "aud", "iat", "exp", "sub", "jti"]);
            let claims = decode::<SessionClaims>(token, key, &validation)
                .map_err(|_| SessionJwtError::InvalidToken)?
                .claims;
            self.validate_claims(claims)
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
            let expected_epoch = matches!(self.profile, SessionTokenProfile::Sandbox);
            if claims.credential_epoch.is_some() != expected_epoch {
                return Err(SessionJwtError::ProfileMismatch);
            }
            let token_id = Uuid::parse_str(&claims.jti).map_err(|_| SessionJwtError::InvalidJti)?;
            if claims.exp <= claims.iat {
                return Err(SessionJwtError::InvalidLifetime);
            }
            let lifetime = claims.exp.saturating_sub(claims.iat);
            if lifetime > i64::try_from(MAX_SESSION_TOKEN_TTL.as_secs()).unwrap_or(i64::MAX) {
                return Err(SessionJwtError::InvalidLifetime);
            }
            let now = self.clock.now_unix_seconds();
            let leeway = i64::try_from(MAX_SESSION_CLOCK_LEEWAY.as_secs()).unwrap_or(30);
            if claims.iat > now.saturating_add(leeway) {
                return Err(SessionJwtError::IssuedInFuture);
            }
            if claims.exp < now.saturating_sub(leeway) {
                return Err(SessionJwtError::Expired);
            }
            Ok(AuthenticatedSandboxSession {
                sandbox_id: claims.sandbox_id,
                session_id: claims.session_id,
                credential_epoch: claims.credential_epoch,
                token_id,
                issued_at: claims.iat,
                expires_at: claims.exp,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    pub enum SessionJwtError {
        #[error("sandbox ID is invalid")]
        InvalidSandboxId,
        #[error("gateway ID is invalid")]
        InvalidGatewayId,
        #[error("credential epoch must be positive")]
        InvalidCredentialEpoch,
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
        #[error("session token lifetime must be between 60 and 3600 seconds")]
        InvalidLifetime,
        #[error("session token profile does not match its claims")]
        ProfileMismatch,
        #[error("session token could not be signed")]
        SigningFailed,
        #[error("session token encoding is invalid")]
        InvalidTokenEncoding,
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
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
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

        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        use rcgen::{KeyPair, PKCS_ED25519};
        use serde::Serialize;

        use super::super::session::*;
        use crate::SandboxSessionId;

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
            SandboxSessionIdentity,
        ) {
            let key = KeyPair::generate_for(&PKCS_ED25519).expect("generate Ed25519 key");
            let public_key_pem = key.public_key_pem().into_bytes();
            let clock: Arc<dyn JwtClock> = Arc::new(FixedClock(1_900_000_000));
            let issuer = SessionJwtIssuer::from_ed25519_pem(
                key.serialize_pem().as_bytes(),
                "current",
                "test",
                DEFAULT_SESSION_TOKEN_TTL,
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
            let identity = SandboxSessionIdentity {
                sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox ID"),
                session_id: SandboxSessionId::new(),
            };
            (issuer, gateway, sandbox, identity)
        }

        #[test]
        fn token_profiles_are_not_interchangeable() {
            let (issuer, gateway, sandbox, identity) = fixture();
            let epoch = CredentialEpoch::new(1).expect("epoch");
            let pair = issuer.mint_pair(&identity, epoch).expect("token pair");

            let gateway_session = gateway
                .verify(pair.gateway.token.expose_secret())
                .expect("gateway token");
            assert_eq!(gateway_session.session_id, identity.session_id);
            assert_eq!(gateway_session.credential_epoch, None);

            let sandbox_session = sandbox
                .verify(pair.sandbox.token.expose_secret())
                .expect("sandbox token");
            assert_eq!(sandbox_session.credential_epoch, Some(epoch));

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
        fn token_debug_is_redacted() {
            let (issuer, _gateway, _sandbox, identity) = fixture();
            let pair = issuer
                .mint_pair(&identity, CredentialEpoch::new(1).expect("epoch"))
                .expect("token pair");
            let debug = format!("{:?}", pair.sandbox.token);
            assert_eq!(debug, "SecretJwt([REDACTED])");
            assert!(!debug.contains(pair.sandbox.token.expose_secret()));
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
            session_id: SandboxSessionId,
            component: SessionComponent,
        }

        #[test]
        fn audience_arrays_are_rejected() {
            let key = KeyPair::generate_for(&PKCS_ED25519).expect("generate Ed25519 key");
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
                session_id: SandboxSessionId::new(),
                component: SessionComponent::OpenShellSupervisor,
            };
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some("current".to_string());
            header.typ = Some(GATEWAY_SESSION_JWT_TYPE.to_string());
            let token = encode(
                &header,
                &claims,
                &EncodingKey::from_ed_pem(key.serialize_pem().as_bytes()).expect("encoding key"),
            )
            .expect("token");
            assert_eq!(verifier.verify(&token), Err(SessionJwtError::InvalidToken));
        }
    }
}
