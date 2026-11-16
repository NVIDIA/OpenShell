// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The supervisor token: the credential of the gateway's shared supervisor
//! for the private assignment stream.
//!
//! The token is minted and verified by the launch-signing
//! [`super::sandbox_jwt::SandboxSessionJwtAuthority`] with the same Ed25519
//! key, key ID, and gateway identity as the sandbox session tokens, under a
//! distinct profile (`typ`, subject, claims), so no sandbox, extension, user,
//! or peer credential is accepted on the stream and the supervisor token is
//! accepted nowhere else. [`SupervisorTokenAuthenticator`] slots the verifier
//! into the gateway's authenticator chain.

use std::sync::Arc;

use async_trait::async_trait;
use jsonwebtoken::decode_header;
use openshell_core::jwt::SUPERVISOR_JWT_TYPE;
use openshell_supervisor_control::HostIdentity;

use super::authenticator::{AuthRejection, Authentication, Authenticator, bearer_credential};
use super::principal::{Principal, SupervisorPrincipal};
use super::sandbox_jwt::SandboxSessionJwtAuthority;

/// Authenticates bearers typed as supervisor tokens. Any other bearer is not
/// this authenticator's business; a supervisor-typed bearer that fails
/// verification ends the chain.
pub struct SupervisorTokenAuthenticator {
    authority: Arc<SandboxSessionJwtAuthority>,
}

impl SupervisorTokenAuthenticator {
    pub fn new(authority: Arc<SandboxSessionJwtAuthority>) -> Self {
        Self { authority }
    }
}

impl std::fmt::Debug for SupervisorTokenAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SupervisorTokenAuthenticator")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Authenticator for SupervisorTokenAuthenticator {
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        _path: &str,
    ) -> Result<Authentication, AuthRejection> {
        let Some(token) = bearer_credential(headers) else {
            return Ok(Authentication::NotApplicable);
        };
        let Ok(header) = decode_header(token) else {
            return Ok(Authentication::NotApplicable);
        };
        if header.typ.as_deref() != Some(SUPERVISOR_JWT_TYPE) {
            return Ok(Authentication::NotApplicable);
        }
        let authenticated = self.authority.verify_supervisor_token(token)?;
        Ok(Authentication::Accepted(Principal::Supervisor(
            SupervisorPrincipal {
                identity: HostIdentity {
                    subject: authenticated.subject,
                    token_id: authenticated.token_id.to_string(),
                    expires_at: authenticated.expires_at,
                },
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::auth::authenticator::{AuthFailureReason, AuthMechanism};
    use openshell_bootstrap::jwt::generate_jwt_key;

    fn authority(gateway_id: &str) -> Arc<SandboxSessionJwtAuthority> {
        let material = generate_jwt_key().expect("jwt key");
        Arc::new(
            SandboxSessionJwtAuthority::from_pem(
                material.signing_key_pem.as_bytes(),
                material.public_key_pem.as_bytes(),
                material.kid,
                gateway_id,
                None,
            )
            .expect("authority"),
        )
    }

    fn headers(token: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn supervisor_tokens_authenticate_only_as_the_supervisor() {
        let attach = "/openshell.supervisor.host.v1.SupervisorHost/Attach";
        let gateway = authority("test-gateway");
        let minted = gateway
            .mint_supervisor_token(Duration::from_mins(15))
            .expect("mint");
        let authenticator = SupervisorTokenAuthenticator::new(gateway.clone());

        let accepted = authenticator
            .authenticate(&headers(minted.token.expose_secret()), attach)
            .await
            .expect("valid token");
        match accepted {
            Authentication::Accepted(Principal::Supervisor(supervisor)) => {
                assert_eq!(
                    supervisor.identity.subject,
                    "openshell-supervisor:test-gateway"
                );
                assert_eq!(supervisor.identity.token_id, minted.token_id.to_string());
                assert_eq!(supervisor.identity.expires_at, minted.expires_at);
            }
            other => panic!("unexpected outcome {other:?}"),
        }

        // Session tokens of the same authority, opaque bearers, and non-JWT
        // bearers fall through to the other authenticators.
        let identity = crate::auth::sandbox_session::PersistedSandboxIdentity::new().unwrap();
        let launch = gateway
            .mint_persisted_launch("sandbox-a", &identity)
            .unwrap();
        for bearer in [
            launch.supervisor.gateway_token.expose_secret(),
            "opaque-user-token",
            "a.b.c",
        ] {
            assert!(matches!(
                authenticator
                    .authenticate(&headers(bearer), attach)
                    .await
                    .unwrap(),
                Authentication::NotApplicable
            ));
        }
        // And the session verifier refuses the supervisor token.
        assert!(
            gateway
                .verify_gateway_token(minted.token.expose_secret())
                .is_err()
        );

        // A supervisor-typed token signed by another gateway's key fails
        // closed, as does one for another gateway identity.
        let other_key = authority("test-gateway");
        let foreign = other_key
            .mint_supervisor_token(Duration::from_mins(15))
            .unwrap();
        let rejection = authenticator
            .authenticate(&headers(foreign.token.expose_secret()), attach)
            .await
            .expect_err("foreign key must be rejected");
        assert_eq!(rejection.mechanism, AuthMechanism::SupervisorToken);
        assert_eq!(rejection.reason, AuthFailureReason::InvalidCredential);
        assert_eq!(rejection.status.code(), tonic::Code::Unauthenticated);
        let other_gateway = authority("other-gateway");
        let rejection = SupervisorTokenAuthenticator::new(other_gateway.clone())
            .authenticate(
                &headers(
                    other_gateway
                        .mint_supervisor_token(Duration::from_mins(15))
                        .unwrap()
                        .token
                        .expose_secret(),
                ),
                attach,
            )
            .await
            .expect("own token verifies");
        assert!(matches!(rejection, Authentication::Accepted(_)));
    }
}
