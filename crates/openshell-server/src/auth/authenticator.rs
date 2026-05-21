// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pluggable authentication trait + chain dispatch.
//!
//! The gateway runs every authenticated request through an
//! [`AuthenticatorChain`] of [`Authenticator`] implementations. The chain
//! evaluates authenticators in order; the first one that recognizes the
//! caller produces the [`Principal`]. An authenticator that does not apply
//! (e.g. an OIDC authenticator seeing no Bearer header) returns `Ok(None)`
//! so the chain falls through to the next. An authenticator that *does*
//! apply but rejects the caller returns `Err(Status)`, which terminates
//! the chain — fail-closed.
//!
//! Live authenticators slotting into the chain:
//! - [`super::sandbox_jwt::SandboxJwtAuthenticator`] — gateway-minted JWTs
//! - [`super::k8s_sa::K8sServiceAccountAuthenticator`] — K8s projected SA
//!   tokens (path-scoped to `IssueSandboxToken`)
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
    /// - `Ok(Some(principal))` — this authenticator recognized the caller.
    ///   The chain stops and the principal is inserted into request
    ///   extensions.
    /// - `Ok(None)` — this authenticator does not apply (e.g. no Bearer
    ///   token for an OIDC authenticator). The chain falls through to
    ///   the next authenticator.
    /// - `Err(status)` — this authenticator applies but rejected the
    ///   caller. The chain terminates and the status is returned to the
    ///   client. Fail-closed.
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        path: &str,
    ) -> Result<Option<Principal>, Status>;
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

    /// Run the chain. Returns the first principal produced. If every
    /// authenticator returns `Ok(None)`, the result is `Ok(None)` — the
    /// router translates that to `unauthenticated`.
    pub async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        path: &str,
    ) -> Result<Option<Principal>, Status> {
        for authenticator in self.authenticators.iter() {
            if let Some(principal) = authenticator.authenticate(headers, path).await? {
                return Ok(Some(principal));
            }
        }
        Ok(None)
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
        pub outcome: Result<Option<Principal>, Status>,
        pub calls: Mutex<Vec<String>>,
    }

    impl MockAuthenticator {
        pub fn returning(outcome: Result<Option<Principal>, Status>) -> Self {
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
        ) -> Result<Option<Principal>, Status> {
            self.calls.lock().unwrap().push(path.to_string());
            self.outcome.clone()
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

    #[tokio::test]
    async fn chain_returns_first_match() {
        let first = Arc::new(MockAuthenticator::returning(Ok(Some(user_principal(
            "alice",
        )))));
        let second = Arc::new(MockAuthenticator::returning(Ok(Some(user_principal(
            "bob",
        )))));
        let chain = AuthenticatorChain::new(vec![first.clone(), second.clone()]);
        let result = chain
            .authenticate(&http::HeaderMap::new(), "/some/path")
            .await
            .unwrap()
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
        let first = Arc::new(MockAuthenticator::returning(Ok(None)));
        let second = Arc::new(MockAuthenticator::returning(Ok(Some(user_principal(
            "bob",
        )))));
        let chain = AuthenticatorChain::new(vec![first.clone(), second.clone()]);
        let result = chain
            .authenticate(&http::HeaderMap::new(), "/some/path")
            .await
            .unwrap()
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
        let first = Arc::new(MockAuthenticator::returning(Err(Status::unauthenticated(
            "bad token",
        ))));
        let second = Arc::new(MockAuthenticator::returning(Ok(Some(user_principal(
            "bob",
        )))));
        let chain = AuthenticatorChain::new(vec![first.clone(), second.clone()]);
        let err = chain
            .authenticate(&http::HeaderMap::new(), "/some/path")
            .await
            .expect_err("must short-circuit on error");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
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
        assert!(result.is_none());
    }
}
