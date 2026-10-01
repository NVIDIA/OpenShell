// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-minted session and extension JWTs.
//!
//! [`SandboxSessionJwtAuthority`] mints and verifies generation-bound sandbox
//! session tokens. [`ExtensionJwtIssuer`] mints explicitly typed credentials
//! for supervisor middleware and gateway interceptors and publishes the
//! corresponding JWKS metadata.
//!
//! Algorithm: `EdDSA` (Ed25519). Pinned via `Validation::algorithms` to
//! prevent algorithm-confusion attacks.

use super::authenticator::Authenticator;
use super::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, decode_header, encode};
pub use openshell_extension_core::{
    EXTENSION_JWT_TYP, ExtensionAudience, ExtensionCallerKind, ExtensionJwtClaims,
    MAX_EXTENSION_TOKEN_TTL,
};
use serde::Serialize;
use std::{
    io::Cursor,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tonic::Status;
use tracing::warn;
use x509_parser::{oid_registry::OID_SIG_ED25519, prelude::FromDer, x509::SubjectPublicKeyInfo};

use openshell_core::SandboxSessionId;
use openshell_core::jwt::{
    AuthenticatedSandboxSession, CredentialEpoch, GATEWAY_SESSION_JWT_TYPE, SandboxId,
    SandboxLaunchAuthentication, SandboxRuntimeIdentity, SessionJwtIssuer, SessionJwtVerifier,
    SessionTokenProfile, SessionVerificationKey, SupervisorAuthBundle, SystemJwtClock,
};
use openshell_core::sandbox_generation::SandboxGenerationId;

/// SPIFFE-shaped subject prefix. Embedded in the `sub` claim of every
/// minted token so a future migration to per-sandbox certs or SPIRE can
/// reuse the same subject namespace without breaking handler equality
/// checks.
const SPIFFE_SUBJECT_PREFIX: &str = "spiffe://openshell/sandbox/";

/// Public JSON Web Key Set served by the gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GatewayJwks {
    pub keys: Vec<GatewayJwk>,
}

/// Ed25519 public key entry in the gateway JWKS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GatewayJwk {
    pub kty: &'static str,
    pub crv: &'static str,
    pub alg: &'static str,
    #[serde(rename = "use")]
    pub key_use: &'static str,
    pub kid: String,
    pub x: String,
}

/// Mints typed extension JWTs and publishes their verification metadata.
pub struct ExtensionJwtIssuer {
    encoding_key: EncodingKey,
    kid: String,
    issuer: String,
    gateway_audience: String,
    ttl: Duration,
    jwks: GatewayJwks,
}

impl std::fmt::Debug for ExtensionJwtIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionJwtIssuer")
            .field("kid", &self.kid)
            .field("issuer", &self.issuer)
            .field("gateway_audience", &self.gateway_audience)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

/// Outcome of a successful mint.
#[derive(Debug, Clone)]
pub struct MintedToken {
    pub token: String,
    pub expires_at_ms: i64,
}

/// Issuer and verifier for launch-scoped supervisor credentials.
pub struct SandboxSessionJwtAuthority {
    issuer: SessionJwtIssuer,
    gateway_verifier: SessionJwtVerifier,
    gateway_id: String,
    verification_keys: Vec<SessionVerificationKey>,
}

impl std::fmt::Debug for SandboxSessionJwtAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxSessionJwtAuthority")
            .field("gateway_id", &self.gateway_id)
            .field(
                "verification_key_ids",
                &self
                    .verification_keys
                    .iter()
                    .map(|key| key.key_id.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl SandboxSessionJwtAuthority {
    pub fn from_pem(
        signing_key_pem: &[u8],
        public_key_pem: &[u8],
        key_id: String,
        gateway_id: &str,
        ttl: Option<Duration>,
    ) -> Result<Self, String> {
        let clock = Arc::new(SystemJwtClock);
        let issuer = SessionJwtIssuer::from_ed25519_pem(
            signing_key_pem,
            key_id.clone(),
            gateway_id,
            ttl,
            clock.clone(),
        )
        .map_err(|error| error.to_string())?;
        let verification_keys = vec![SessionVerificationKey {
            key_id,
            public_key_pem: public_key_pem.to_vec(),
        }];
        let gateway_verifier = SessionJwtVerifier::new(
            gateway_id,
            SessionTokenProfile::Gateway,
            verification_keys.clone(),
            clock,
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            issuer,
            gateway_verifier,
            gateway_id: gateway_id.to_string(),
            verification_keys,
        })
    }

    #[allow(clippy::result_large_err)]
    pub fn mint_persisted_launch(
        &self,
        sandbox_id: &str,
        identity: &crate::auth::sandbox_session::PersistedSandboxIdentity,
    ) -> Result<SandboxLaunchAuthentication, Status> {
        let token_metadata = identity
            .refresh_replay
            .as_ref()
            .map(|replay| (replay.sandbox_token_id(), replay.issued_at));
        self.mint_launch_with_metadata(
            sandbox_id,
            identity.runtime_generation.clone(),
            identity.auth_epoch,
            identity.gateway_token_id,
            token_metadata,
        )
    }

    #[allow(clippy::result_large_err)]
    pub fn mint_launch(
        &self,
        sandbox_id: &str,
        runtime_generation: SandboxGenerationId,
        auth_epoch: CredentialEpoch,
        gateway_token_id: uuid::Uuid,
    ) -> Result<SandboxLaunchAuthentication, Status> {
        self.mint_launch_with_metadata(
            sandbox_id,
            runtime_generation,
            auth_epoch,
            gateway_token_id,
            None,
        )
    }

    #[allow(clippy::result_large_err)]
    fn mint_launch_with_metadata(
        &self,
        sandbox_id: &str,
        runtime_generation: SandboxGenerationId,
        auth_epoch: CredentialEpoch,
        gateway_token_id: uuid::Uuid,
        token_metadata: Option<(uuid::Uuid, i64)>,
    ) -> Result<SandboxLaunchAuthentication, Status> {
        let identity = SandboxRuntimeIdentity {
            sandbox_id: SandboxId::parse(sandbox_id)
                .map_err(|_| Status::invalid_argument("sandbox ID is invalid"))?,
            runtime_generation: runtime_generation.clone(),
            auth_epoch,
        };
        let pair = token_metadata
            .map_or_else(
                || {
                    self.issuer
                        .mint_pair_with_gateway_token_id(&identity, gateway_token_id)
                },
                |(sandbox_token_id, issued_at)| {
                    self.issuer.mint_pair_with_token_metadata(
                        &identity,
                        gateway_token_id,
                        sandbox_token_id,
                        issued_at,
                    )
                },
            )
            .map_err(|error| {
                warn!(%error, "failed to mint launch-scoped sandbox credentials");
                Status::internal("failed to mint sandbox launch credentials")
            })?;
        Ok(SandboxLaunchAuthentication {
            supervisor: SupervisorAuthBundle {
                session_id: SandboxSessionId::new(),
                runtime_generation,
                session_rotation: openshell_core::jwt::SessionRotation::new(1)
                    .map_err(|error| Status::internal(error.to_string()))?,
                auth_epoch: pair.auth_epoch,
                gateway_token: pair.gateway.token,
                gateway_expires_at: pair.gateway.expires_at,
                sandbox_token: pair.sandbox.token,
                sandbox_expires_at: pair.sandbox.expires_at,
            },
            gateway_id: self.gateway_id.clone(),
            verification_keys: self.verification_keys.clone(),
        })
    }

    pub fn verify_gateway_token(&self, token: &str) -> Result<AuthenticatedSandboxSession, Status> {
        self.gateway_verifier
            .verify(token)
            .map_err(|error| Status::unauthenticated(format!("invalid gateway session: {error}")))
    }
}

/// Authenticates launch-scoped supervisor tokens and checks their identity
/// against the durable sandbox record.
pub struct SandboxSessionJwtAuthenticator {
    authority: Arc<SandboxSessionJwtAuthority>,
    store: Arc<crate::persistence::Store>,
}

impl SandboxSessionJwtAuthenticator {
    pub fn new(
        authority: Arc<SandboxSessionJwtAuthority>,
        store: Arc<crate::persistence::Store>,
    ) -> Self {
        Self { authority, store }
    }
}

impl std::fmt::Debug for SandboxSessionJwtAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxSessionJwtAuthenticator")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Authenticator for SandboxSessionJwtAuthenticator {
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        path: &str,
    ) -> Result<Option<Principal>, Status> {
        let Some(token) = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        else {
            return Ok(None);
        };
        let Ok(header) = decode_header(token) else {
            return Ok(None);
        };
        if header.typ.as_deref() != Some(GATEWAY_SESSION_JWT_TYPE) {
            return Ok(None);
        }
        let authenticated = self.authority.verify_gateway_token(token)?;
        // Refresh performs its own lineage check so the immediately consumed
        // bearer can recover an already-committed successor after a lost
        // response. Every other RPC accepts only the current bearer.
        if path != "/openshell.v1.OpenShell/RefreshSandboxToken" {
            crate::auth::sandbox_session::authorize_persisted(&self.store, &authenticated).await?;
        }
        Ok(Some(Principal::Sandbox(SandboxPrincipal {
            sandbox_id: authenticated.sandbox_id.to_string(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "launch-session".to_string(),
            },
            trust_domain: Some("openshell".to_string()),
        })))
    }
}

impl ExtensionJwtIssuer {
    pub fn from_pem(
        signing_key_pem: &[u8],
        public_key_pem: &[u8],
        kid: String,
        gateway_id: &str,
        ttl: Duration,
    ) -> Result<Self, String> {
        crate::install_jsonwebtoken_crypto_provider();

        if ttl.is_zero() {
            return Err("gateway token TTL must be positive".to_string());
        }

        let encoding_key = EncodingKey::from_ed_pem(signing_key_pem)
            .map_err(|e| format!("failed to parse Ed25519 signing key PEM: {e}"))?;
        let jwks = GatewayJwks::from_public_key_pem(public_key_pem, kid.clone())?;
        let identity = format!("openshell-gateway:{gateway_id}");
        Ok(Self {
            encoding_key,
            kid,
            issuer: identity.clone(),
            gateway_audience: identity,
            ttl,
            jwks,
        })
    }

    /// Mint a short-lived bearer token for one exact extension audience.
    ///
    /// `sandbox_id` is required for supervisor calls and forbidden for
    /// gateway calls. The subject follows the existing SPIFFE-shaped sandbox
    /// identity for supervisor calls; gateway calls use the issuer identity.
    #[allow(clippy::result_large_err)]
    pub fn mint_extension_token(
        &self,
        audience: &ExtensionAudience,
        caller_kind: ExtensionCallerKind,
        sandbox_id: Option<&str>,
        ttl: Duration,
    ) -> Result<MintedToken, Status> {
        self.mint_extension_token_with_metadata(
            audience,
            caller_kind,
            sandbox_id,
            ttl,
            now_secs(),
            uuid::Uuid::new_v4(),
        )
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn mint_extension_token_with_metadata(
        &self,
        audience: &ExtensionAudience,
        caller_kind: ExtensionCallerKind,
        sandbox_id: Option<&str>,
        ttl: Duration,
        issued_at: i64,
        token_id: uuid::Uuid,
    ) -> Result<MintedToken, Status> {
        if audience.as_str() == self.gateway_audience {
            return Err(Status::invalid_argument(
                "extension audience must not equal the gateway sandbox audience",
            ));
        }
        if ttl.is_zero() || ttl > MAX_EXTENSION_TOKEN_TTL {
            return Err(Status::invalid_argument(format!(
                "extension token TTL must be between 1 and {} seconds",
                MAX_EXTENSION_TOKEN_TTL.as_secs()
            )));
        }

        let (sub, sandbox_id) = match (caller_kind, sandbox_id) {
            (ExtensionCallerKind::Gateway, None) => (self.issuer.clone(), None),
            (ExtensionCallerKind::Supervisor, Some(id)) if !id.trim().is_empty() => {
                (format!("{SPIFFE_SUBJECT_PREFIX}{id}"), Some(id.to_string()))
            }
            (ExtensionCallerKind::Gateway, Some(_)) => {
                return Err(Status::invalid_argument(
                    "gateway extension tokens must not include a sandbox ID",
                ));
            }
            (ExtensionCallerKind::Supervisor, _) => {
                return Err(Status::invalid_argument(
                    "supervisor extension tokens require a sandbox ID",
                ));
            }
        };

        let exp = issued_at.saturating_add(i64::try_from(ttl.as_secs()).unwrap_or(3_600));
        let claims = ExtensionJwtClaims {
            iss: self.issuer.clone(),
            aud: audience.as_str().to_string(),
            sub,
            iat: issued_at,
            exp,
            jti: token_id.to_string(),
            caller_kind,
            sandbox_id,
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        // Explicit typing so an extension that requires this `typ` cannot be
        // handed a sandbox-to-gateway bootstrap token signed by the same key.
        header.typ = Some(EXTENSION_JWT_TYP.to_string());
        let token = encode(&header, &claims, &self.encoding_key).map_err(|e| {
            warn!(error = %e, "failed to mint extension JWT");
            Status::internal("failed to mint extension token")
        })?;
        Ok(MintedToken {
            token,
            expires_at_ms: exp.saturating_mul(1000),
        })
    }

    pub const fn token_ttl(&self) -> Duration {
        self.ttl
    }

    /// Return the public signing keys integrations use to verify extension
    /// tokens.
    #[must_use]
    pub const fn jwks(&self) -> &GatewayJwks {
        &self.jwks
    }

    /// The exact `iss` claim carried by every token this gateway mints.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

impl GatewayJwks {
    fn from_public_key_pem(public_key_pem: &[u8], kid: String) -> Result<Self, String> {
        let item = rustls_pemfile::read_one(&mut Cursor::new(public_key_pem))
            .map_err(|e| format!("failed to parse Ed25519 public key PEM for JWKS: {e}"))?;
        let Some(rustls_pemfile::Item::SubjectPublicKeyInfo(der)) = item else {
            return Err("Ed25519 public key PEM does not contain a PUBLIC KEY block".into());
        };
        let (remainder, spki) = SubjectPublicKeyInfo::from_der(der.as_ref())
            .map_err(|e| format!("failed to parse SubjectPublicKeyInfo for JWKS: {e}"))?;
        if !remainder.is_empty() || spki.algorithm.algorithm != OID_SIG_ED25519 {
            return Err("public key is not an RFC 8410 Ed25519 SubjectPublicKeyInfo key".into());
        }
        let raw_key = spki.subject_public_key.data.as_ref();
        if raw_key.len() != 32 {
            return Err("Ed25519 public key must be 32 bytes".to_string());
        }

        Ok(Self {
            keys: vec![GatewayJwk {
                kty: "OKP",
                crv: "Ed25519",
                alg: "EdDSA",
                key_use: "sig",
                kid,
                x: URL_SAFE_NO_PAD.encode(raw_key),
            }],
        })
    }
}

fn now_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation, decode};
    use openshell_bootstrap::jwt::generate_jwt_key;

    fn issuer(ttl: Duration) -> ExtensionJwtIssuer {
        let mat = generate_jwt_key().expect("jwt key");
        ExtensionJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.public_key_pem.as_bytes(),
            mat.kid,
            "test-gateway",
            ttl,
        )
        .expect("issuer")
    }

    fn extension_audience(value: &str) -> ExtensionAudience {
        ExtensionAudience::new(value).expect("valid extension audience")
    }

    #[test]
    fn zero_ttl_is_rejected() {
        let mat = generate_jwt_key().expect("jwt key");
        let error = ExtensionJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.public_key_pem.as_bytes(),
            mat.kid,
            "test-gateway",
            Duration::ZERO,
        )
        .expect_err("Duration::ZERO must not reintroduce a sentinel");
        assert!(error.contains("must be positive"));
    }

    #[test]
    fn extension_tokens_have_exact_audience_and_caller_identity() {
        let mat = generate_jwt_key().expect("jwt key");
        let issuer = ExtensionJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.public_key_pem.as_bytes(),
            mat.kid.clone(),
            "gateway-a",
            Duration::from_mins(15),
        )
        .expect("issuer");
        let decoding_key = DecodingKey::from_ed_pem(mat.public_key_pem.as_bytes()).unwrap();

        let gateway = issuer
            .mint_extension_token(
                &extension_audience("urn:openshell:extension:middleware:scanner"),
                ExtensionCallerKind::Gateway,
                None,
                Duration::from_mins(5),
            )
            .expect("gateway token");
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&["openshell-gateway:gateway-a"]);
        validation.set_audience(&["urn:openshell:extension:middleware:scanner"]);
        validation.set_required_spec_claims(&["iss", "aud", "sub", "iat", "exp"]);
        let claims = decode::<ExtensionJwtClaims>(&gateway.token, &decoding_key, &validation)
            .expect("valid extension token")
            .claims;
        assert_eq!(claims.sub, "openshell-gateway:gateway-a");
        assert_eq!(claims.caller_kind, ExtensionCallerKind::Gateway);
        assert_eq!(claims.sandbox_id, None);
        assert!(!claims.jti.is_empty());
        assert_eq!(gateway.expires_at_ms, claims.exp * 1000);

        let supervisor = issuer
            .mint_extension_token(
                &extension_audience("urn:openshell:extension:middleware:scanner"),
                ExtensionCallerKind::Supervisor,
                Some("sandbox-a"),
                Duration::from_mins(5),
            )
            .expect("supervisor token");
        let claims = decode::<ExtensionJwtClaims>(&supervisor.token, &decoding_key, &validation)
            .expect("valid supervisor extension token")
            .claims;
        assert_eq!(claims.sub, "spiffe://openshell/sandbox/sandbox-a");
        assert_eq!(claims.caller_kind, ExtensionCallerKind::Supervisor);
        assert_eq!(claims.sandbox_id.as_deref(), Some("sandbox-a"));
    }

    #[test]
    fn extension_tokens_are_explicitly_typed() {
        let issuer = issuer(Duration::from_hours(1));
        let extension = issuer
            .mint_extension_token(
                &extension_audience("urn:openshell:extension:middleware:scanner"),
                ExtensionCallerKind::Gateway,
                None,
                Duration::from_mins(5),
            )
            .expect("extension token");
        assert_eq!(
            decode_header(&extension.token).unwrap().typ.as_deref(),
            Some(EXTENSION_JWT_TYP)
        );
    }

    #[test]
    fn extension_token_rejects_wrong_audience() {
        let mat = generate_jwt_key().expect("jwt key");
        let issuer = ExtensionJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.public_key_pem.as_bytes(),
            mat.kid,
            "gateway-a",
            Duration::from_mins(15),
        )
        .expect("issuer");
        let minted = issuer
            .mint_extension_token(
                &extension_audience("service-a"),
                ExtensionCallerKind::Gateway,
                None,
                Duration::from_mins(1),
            )
            .expect("token");
        let decoding_key = DecodingKey::from_ed_pem(mat.public_key_pem.as_bytes()).unwrap();
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&["openshell-gateway:gateway-a"]);
        validation.set_audience(&["service-b"]);
        assert!(decode::<ExtensionJwtClaims>(&minted.token, &decoding_key, &validation).is_err());
    }

    #[test]
    fn extension_token_rejects_gateway_sandbox_audience() {
        let issuer = issuer(Duration::from_hours(1));
        let error = issuer
            .mint_extension_token(
                &extension_audience("openshell-gateway:test-gateway"),
                ExtensionCallerKind::Supervisor,
                Some("sandbox-a"),
                Duration::from_mins(1),
            )
            .expect_err("gateway sandbox audience must be reserved");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            error.message(),
            "extension audience must not equal the gateway sandbox audience"
        );
    }

    #[test]
    fn extension_token_enforces_positive_bounded_ttl_and_caller_shape() {
        let issuer = issuer(Duration::from_mins(15));
        for ttl in [
            Duration::ZERO,
            MAX_EXTENSION_TOKEN_TTL + Duration::from_secs(1),
        ] {
            let error = issuer
                .mint_extension_token(
                    &extension_audience("service"),
                    ExtensionCallerKind::Gateway,
                    None,
                    ttl,
                )
                .expect_err("invalid TTL");
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
        assert!(
            issuer
                .mint_extension_token(
                    &extension_audience("service"),
                    ExtensionCallerKind::Supervisor,
                    None,
                    Duration::from_mins(1),
                )
                .is_err()
        );
        assert!(
            issuer
                .mint_extension_token(
                    &extension_audience("service"),
                    ExtensionCallerKind::Gateway,
                    Some("sandbox-a"),
                    Duration::from_mins(1),
                )
                .is_err()
        );
        assert!(ExtensionAudience::new("  ").is_err());
    }

    #[test]
    fn jwks_contains_public_ed25519_key_without_pem_material() {
        let mat = generate_jwt_key().expect("jwt key");
        let issuer = ExtensionJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.public_key_pem.as_bytes(),
            mat.kid.clone(),
            "gateway-a",
            Duration::from_mins(15),
        )
        .expect("issuer");
        let jwks = issuer.jwks();
        assert_eq!(jwks.keys.len(), 1);
        let key = &jwks.keys[0];
        assert_eq!(key.kid, mat.kid);
        assert_eq!(key.kty, "OKP");
        assert_eq!(key.crv, "Ed25519");
        assert_eq!(key.alg, "EdDSA");
        assert_eq!(key.key_use, "sig");
        assert_eq!(URL_SAFE_NO_PAD.decode(&key.x).unwrap().len(), 32);

        let json = serde_json::to_string(jwks).expect("JSON");
        assert!(!json.contains("BEGIN PUBLIC KEY"));
        assert!(!json.contains("PRIVATE"));
        assert!(json.contains(r#""use":"sig""#));
    }
}
