// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pluggable authentication trait + chain dispatch.
//!
//! The gateway runs every authenticated request through an
//! [`AuthenticatorChain`] of [`Authenticator`] implementations. The chain
//! evaluates authenticators in order; the first one that recognizes the
//! caller produces the [`Principal`]. An authenticator that does not apply
//! (e.g. an OIDC authenticator seeing no Bearer header) returns
//! [`Authentication::NotApplicable`] so the chain falls through to the next.
//! An authenticator that rejects a credential another authenticator may still
//! accept returns [`Authentication::Declined`], which also falls through. An
//! authenticator that *does* apply but rejects the caller returns
//! `Err(AuthRejection)`, which terminates the chain — fail-closed.
//!
//! Live authenticators slotting into the chain:
//! - [`super::sandbox_jwt::SandboxSessionJwtAuthenticator`] — generation-bound
//!   gateway session JWTs
//! - [`super::compute_driver::ComputeDriverAuthenticator`] — driver-native
//!   sandbox bootstrap credentials (path-scoped to `IssueSandboxToken`)
//! - [`super::oidc::OidcAuthenticator`] — user OIDC Bearer tokens
use super::principal::Principal;
use async_trait::async_trait;
use std::sync::Arc;
use tonic::Status;

/// Pluggable authentication step.
///
/// Implementations are expected to be cheap to clone (they live behind
/// `Arc<dyn Authenticator>` inside an [`AuthenticatorChain`]).
#[async_trait]
pub trait Authenticator: Send + Sync + 'static {
    /// Inspect an inbound request and return the authenticated principal.
    ///
    /// - `Accepted(principal)` — this authenticator recognized the caller.
    ///   The chain stops and the principal is inserted into request
    ///   extensions.
    /// - `NotApplicable` — this authenticator does not apply (e.g. no Bearer
    ///   token for an OIDC authenticator). The chain falls through to
    ///   the next authenticator.
    /// - `Declined(decline)` — this authenticator rejected the credential,
    ///   but another may accept it. The chain falls through, keeping the
    ///   decline to classify the request if nothing accepts it.
    /// - `Err(rejection)` — this authenticator applies but rejected the
    ///   caller. The chain terminates and the rejection's status is returned
    ///   to the client. Fail-closed.
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        path: &str,
    ) -> Result<Authentication, AuthRejection>;
}

/// Outcome of an authenticator, or of the whole chain, that did not fail
/// closed.
#[derive(Debug, Clone)]
pub enum Authentication {
    Accepted(Principal),
    NotApplicable,
    Declined(AuthDecline),
}

/// A credential an authenticator rejected without ending the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthDecline {
    pub mechanism: AuthMechanism,
    pub reason: AuthFailureReason,
}

/// Why an authentication attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailureReason {
    /// No credential was presented.
    MissingCredential,
    /// Credentials for more than one mechanism were presented together.
    ConflictingCredentials,
    /// The credential could not be parsed.
    MalformedCredential,
    /// The credential failed signature, key, or claim verification.
    InvalidCredential,
    /// The credential was valid but has expired.
    ExpiredCredential,
    /// The credential was issued by or for a different party.
    AudienceOrIssuerMismatch,
    /// The credential names an identity the gateway does not know.
    UnknownIdentity,
    /// The credential names an identity that has since been replaced or revoked.
    StaleIdentity,
    /// The service that verifies the credential could not be reached.
    IdentityProviderUnavailable,
}

/// The mechanism a caller attempted to authenticate with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMechanism {
    Mtls,
    Oidc,
    SandboxJwt,
    ComputeDriver,
    GatewayPeer,
}

/// A rejected authentication attempt: the status returned to the caller and
/// the category recorded in the audit event.
#[derive(Debug, Clone)]
pub struct AuthRejection {
    pub mechanism: AuthMechanism,
    pub reason: AuthFailureReason,
    pub status: Status,
}

impl AuthRejection {
    pub fn new(mechanism: AuthMechanism, reason: AuthFailureReason, status: Status) -> Self {
        Self {
            mechanism,
            reason,
            status,
        }
    }
}

/// Bearer credential from the request's `authorization` header, if any.
///
/// The scheme is matched case-insensitively. Non-Bearer or non-UTF-8 headers
/// yield `None` so the chain falls through.
pub fn bearer_credential(headers: &http::HeaderMap) -> Option<&str> {
    headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(openshell_core::auth::strip_bearer_scheme)
}

/// First-match-wins authenticator chain.
///
/// The chain owns its authenticators behind `Arc` so the entire chain is
/// cheap to clone — required because `tower::Service::call` clones the
/// router on every request.
#[derive(Clone)]
pub struct AuthenticatorChain {
    authenticators: Arc<[Arc<dyn Authenticator>]>,
}

impl AuthenticatorChain {
    /// Build a chain from an ordered list of authenticators. Earlier
    /// entries are evaluated first.
    pub fn new(authenticators: Vec<Arc<dyn Authenticator>>) -> Self {
        Self {
            authenticators: Arc::from(authenticators),
        }
    }

    /// Run the chain. Returns the first principal produced, or the first
    /// rejection. If neither occurs, the result is the first decline, or
    /// `NotApplicable` — the router translates either to `unauthenticated`.
    pub async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        path: &str,
    ) -> Result<Authentication, AuthRejection> {
        let mut declined: Option<AuthDecline> = None;
        for authenticator in self.authenticators.iter() {
            match authenticator.authenticate(headers, path).await? {
                Authentication::Accepted(principal) => {
                    return Ok(Authentication::Accepted(principal));
                }
                Authentication::NotApplicable => {}
                Authentication::Declined(decline) => {
                    declined.get_or_insert(decline);
                }
            }
        }
        Ok(declined.map_or(Authentication::NotApplicable, Authentication::Declined))
    }
}

impl std::fmt::Debug for AuthenticatorChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatorChain")
            .field("len", &self.authenticators.len())
            .finish()
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use std::sync::Mutex;

    /// Authenticator that always returns the configured outcome. Used by
    /// tests to inject a known principal (or rejection) without running real
    /// crypto. Each call records the path it was invoked with so tests can
    /// assert chain ordering.
    pub struct MockAuthenticator {
        pub outcome: Result<Authentication, AuthRejection>,
        pub calls: Mutex<Vec<String>>,
    }

    impl MockAuthenticator {
        pub fn returning(outcome: Result<Authentication, AuthRejection>) -> Self {
            Self {
                outcome,
                calls: Mutex::new(Vec::new()),
            }
        }

        pub fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl Authenticator for MockAuthenticator {
        async fn authenticate(
            &self,
            _headers: &http::HeaderMap,
            path: &str,
        ) -> Result<Authentication, AuthRejection> {
            self.calls.lock().unwrap().push(path.to_string());
            self.outcome.clone()
        }
    }

    impl Authentication {
        pub fn principal(self) -> Option<Principal> {
            match self {
                Self::Accepted(principal) => Some(principal),
                Self::NotApplicable | Self::Declined(_) => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MockAuthenticator;
    use super::*;
    use crate::auth::identity::{Identity, IdentityProvider};
    use crate::auth::principal::UserPrincipal;

    fn user_principal(subject: &str) -> Principal {
        Principal::User(UserPrincipal {
            identity: Identity {
                subject: subject.to_string(),
                display_name: None,
                roles: vec![],
                scopes: vec![],
                provider: IdentityProvider::Oidc,
            },
        })
    }

    #[test]
    fn bearer_credential_matches_scheme_case_insensitively() {
        for scheme in ["Bearer", "bearer", "BEARER"] {
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::AUTHORIZATION,
                format!("{scheme} abc").parse().unwrap(),
            );
            assert_eq!(bearer_credential(&headers), Some("abc"), "{scheme}");
        }
        let mut headers = http::HeaderMap::new();
        assert_eq!(bearer_credential(&headers), None);
        headers.insert(http::header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert_eq!(bearer_credential(&headers), None);
    }

    #[tokio::test]
    async fn chain_returns_first_match() {
        let first = Arc::new(MockAuthenticator::returning(Ok(Authentication::Accepted(
            user_principal("alice"),
        ))));
        let second = Arc::new(MockAuthenticator::returning(Ok(Authentication::Accepted(
            user_principal("bob"),
        ))));
        let chain = AuthenticatorChain::new(vec![first.clone(), second.clone()]);
        let result = chain
            .authenticate(&http::HeaderMap::new(), "/some/path")
            .await
            .unwrap()
            .principal()
            .expect("expected a principal");
        match result {
            Principal::User(u) => assert_eq!(u.identity.subject, "alice"),
            _ => panic!("expected user principal"),
        }
        assert_eq!(first.call_count(), 1);
        assert_eq!(
            second.call_count(),
            0,
            "second authenticator must be skipped after first matches"
        );
    }

    #[tokio::test]
    async fn chain_falls_through_on_none() {
        let first = Arc::new(MockAuthenticator::returning(Ok(
            Authentication::NotApplicable,
        )));
        let second = Arc::new(MockAuthenticator::returning(Ok(Authentication::Accepted(
            user_principal("bob"),
        ))));
        let chain = AuthenticatorChain::new(vec![first.clone(), second.clone()]);
        let result = chain
            .authenticate(&http::HeaderMap::new(), "/some/path")
            .await
            .unwrap()
            .principal()
            .expect("expected a principal");
        match result {
            Principal::User(u) => assert_eq!(u.identity.subject, "bob"),
            _ => panic!("expected user principal"),
        }
        assert_eq!(first.call_count(), 1);
        assert_eq!(second.call_count(), 1);
    }

    #[tokio::test]
    async fn chain_fails_closed_on_first_error() {
        let first = Arc::new(MockAuthenticator::returning(Err(AuthRejection::new(
            AuthMechanism::Oidc,
            AuthFailureReason::InvalidCredential,
            Status::unauthenticated("bad token"),
        ))));
        let second = Arc::new(MockAuthenticator::returning(Ok(Authentication::Accepted(
            user_principal("bob"),
        ))));
        let chain = AuthenticatorChain::new(vec![first.clone(), second.clone()]);
        let err = chain
            .authenticate(&http::HeaderMap::new(), "/some/path")
            .await
            .expect_err("must short-circuit on error");
        assert_eq!(err.status.code(), tonic::Code::Unauthenticated);
        assert_eq!(first.call_count(), 1);
        assert_eq!(
            second.call_count(),
            0,
            "must not consult later authenticators after an error"
        );
    }

    #[tokio::test]
    async fn empty_chain_returns_none() {
        let chain = AuthenticatorChain::new(vec![]);
        let result = chain
            .authenticate(&http::HeaderMap::new(), "/some/path")
            .await
            .unwrap();
        assert!(matches!(result, Authentication::NotApplicable));
    }

    fn peer_decline() -> AuthDecline {
        AuthDecline {
            mechanism: AuthMechanism::GatewayPeer,
            reason: AuthFailureReason::ExpiredCredential,
        }
    }

    #[tokio::test]
    async fn chain_falls_through_a_decline_and_reports_it_when_nothing_accepts() {
        let first = Arc::new(MockAuthenticator::returning(Ok(Authentication::Declined(
            peer_decline(),
        ))));
        let second = Arc::new(MockAuthenticator::returning(Ok(
            Authentication::NotApplicable,
        )));
        let chain = AuthenticatorChain::new(vec![first, second.clone()]);

        let result = chain
            .authenticate(&http::HeaderMap::new(), "/some/path")
            .await
            .unwrap();

        assert_eq!(second.call_count(), 1);
        assert!(matches!(result, Authentication::Declined(d) if d == peer_decline()));
    }

    #[tokio::test]
    async fn chain_accepts_a_principal_after_a_decline() {
        let first = Arc::new(MockAuthenticator::returning(Ok(Authentication::Declined(
            peer_decline(),
        ))));
        let second = Arc::new(MockAuthenticator::returning(Ok(Authentication::Accepted(
            user_principal("bob"),
        ))));
        let chain = AuthenticatorChain::new(vec![first, second]);

        let result = chain
            .authenticate(&http::HeaderMap::new(), "/some/path")
            .await
            .unwrap();

        assert!(result.principal().is_some());
    }

    #[tokio::test]
    async fn rejection_after_a_decline_keeps_its_own_classification() {
        let first = Arc::new(MockAuthenticator::returning(Ok(Authentication::Declined(
            peer_decline(),
        ))));
        let second = Arc::new(MockAuthenticator::returning(Err(AuthRejection::new(
            AuthMechanism::Oidc,
            AuthFailureReason::InvalidCredential,
            Status::unauthenticated("invalid token: unknown signing key"),
        ))));
        let chain = AuthenticatorChain::new(vec![first, second]);

        let err = chain
            .authenticate(&http::HeaderMap::new(), "/some/path")
            .await
            .expect_err("a later rejection still fails closed");

        assert_eq!(err.status.message(), "invalid token: unknown signing key");
        assert_eq!(err.mechanism, AuthMechanism::Oidc);
        assert_eq!(err.reason, AuthFailureReason::InvalidCredential);
    }
}
