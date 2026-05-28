// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OIDC bearer-token refresh contract.
//!
//! The SDK never talks to a browser or any specific `IdP`. Callers that need
//! the SDK to rotate an OIDC bearer mid-session implement [`Refresh`] and
//! construct a [`TokenSource`] around it. Implementations live where the
//! browser flow / token store / FFI callback belongs — in `openshell-cli`
//! for the desktop browser flow, in `openshell-sdk-node` for a JS callback.
//!
//! The trait is intentionally minimal. Single-flight coalescing (one refresh
//! in flight at a time, with all waiters sharing the result) is the SDK's
//! responsibility, not the implementer's; see [`TokenSource`].
//!
//! TODO(rfc-0004): plumb [`TokenSource`] into the gRPC auth interceptor so
//! refreshes happen automatically before each request. Today the napi
//! binding exposes [`TokenSource::refresh_now`] / [`TokenSource::current`]
//! directly to JS callers, which can rotate the token by calling
//! `set_oidc_token` on a future iteration of the SDK client.

use crate::error::{Result, SdkError};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};

/// Errors a refresher can return.
///
/// Domain-specific, deliberately not coupled to `tonic`, `napi`, or any
/// FFI-facing error type. The SDK maps these into [`SdkError::Auth`] before
/// surfacing to callers.
#[derive(Debug)]
#[non_exhaustive]
pub enum RefreshError {
    /// Refresh failed but a retry might succeed (network blip, transient
    /// `IdP` error).
    Transient(String),
    /// Refresh cannot succeed without user interaction (refresh token
    /// expired, `IdP` revoked the session). Callers should not retry; they
    /// should re-authenticate.
    Terminal(String),
}

impl fmt::Display for RefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transient(msg) => write!(f, "transient refresh error: {msg}"),
            Self::Terminal(msg) => write!(f, "terminal refresh error: {msg}"),
        }
    }
}

impl std::error::Error for RefreshError {}

impl From<RefreshError> for SdkError {
    fn from(value: RefreshError) -> Self {
        Self::auth(value.to_string())
    }
}

/// A freshly minted access token + its absolute expiry.
///
/// `expires_at` is seconds since the Unix epoch. `None` means the token's
/// expiry was not advertised — the SDK will not refresh it proactively but
/// may refresh on demand if [`Refresh::refresh`] is called.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RefreshedToken {
    pub access_token: String,
    pub expires_at: Option<u64>,
}

impl RefreshedToken {
    pub fn new(access_token: impl Into<String>) -> Self {
        Self {
            access_token: access_token.into(),
            expires_at: None,
        }
    }

    #[must_use]
    pub fn with_expires_at(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

/// Pluggable OIDC refresher.
///
/// Implementations should be cheap to clone and safe to call from any tokio
/// task. They MUST NOT do their own single-flight coalescing — that's the
/// SDK's job (see [`TokenSource`]).
#[async_trait::async_trait]
pub trait Refresh: Send + Sync + 'static {
    /// Mint a fresh access token. Called by the SDK when it determines the
    /// current token is near expiry (or has been explicitly invalidated).
    async fn refresh(&self) -> std::result::Result<RefreshedToken, RefreshError>;
}

/// Mutable token state shared between the auth interceptor and the
/// background refresh task.
#[derive(Debug)]
struct TokenState {
    token: String,
    expires_at: Option<u64>,
}

/// A bearer-token source with single-flight refresh coalescing.
///
/// Wraps a [`Refresh`] implementation and tracks the current token + its
/// advertised expiry. Phase 3 of the RFC plumbs this into the auth path; for
/// now language bindings hand it out directly so JS/Python code can drive
/// refreshes externally.
#[derive(Clone)]
pub struct TokenSource {
    state: Arc<RwLock<TokenState>>,
    refresher: Arc<dyn Refresh>,
    in_flight: Arc<Mutex<()>>,
    /// Refresh `skew` seconds before the advertised `expires_at`. Tokens
    /// without `expires_at` are not auto-refreshed.
    skew: Duration,
}

impl TokenSource {
    /// Construct a token source backed by `refresher`. Use this when wiring
    /// an FFI callback or browser flow into the SDK.
    pub fn new(initial: RefreshedToken, refresher: Arc<dyn Refresh>) -> Self {
        Self {
            state: Arc::new(RwLock::new(TokenState {
                token: initial.access_token,
                expires_at: initial.expires_at,
            })),
            refresher,
            in_flight: Arc::new(Mutex::new(())),
            skew: Duration::from_secs(60),
        }
    }

    /// Current token without checking expiry. Used by the sync gRPC
    /// interceptor, which can't await.
    pub fn snapshot(&self) -> String {
        self.state
            .try_read()
            .map(|s| s.token.clone())
            .unwrap_or_default()
    }

    /// Async-fetch the current token, refreshing if it's within `skew` of
    /// expiry. Single-flight: concurrent callers share one refresh.
    pub async fn current(&self) -> Result<String> {
        if !self.needs_refresh().await {
            return Ok(self.state.read().await.token.clone());
        }
        self.refresh_now().await
    }

    /// Force a refresh regardless of expiry. Used on `Unauthenticated`
    /// responses from the gateway.
    pub async fn refresh_now(&self) -> Result<String> {
        // Single-flight: only one refresh in flight at a time. Other waiters
        // block here and then see the updated state on re-check.
        let _guard = self.in_flight.lock().await;

        // Re-check inside the critical section: another caller may have just
        // refreshed while we were waiting on the lock.
        if !self.needs_refresh().await {
            return Ok(self.state.read().await.token.clone());
        }

        let refreshed = self.refresher.refresh().await?;
        let mut state = self.state.write().await;
        state.token.clone_from(&refreshed.access_token);
        state.expires_at = refreshed.expires_at;
        Ok(refreshed.access_token)
    }

    async fn needs_refresh(&self) -> bool {
        let state = self.state.read().await;
        let Some(expires_at) = state.expires_at else {
            return false;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now + self.skew.as_secs() >= expires_at
    }

    /// Replace the current token without invoking the refresher.
    ///
    /// Used by callers that manage refresh externally (e.g. the napi
    /// binding's JS-side timer) or for testing.
    pub async fn replace(&self, token: RefreshedToken) {
        let mut state = self.state.write().await;
        state.token = token.access_token;
        state.expires_at = token.expires_at;
    }
}

impl fmt::Debug for TokenSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSource")
            .field("skew", &self.skew)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingRefresher {
        calls: Arc<AtomicUsize>,
        delay: Duration,
    }

    #[async_trait::async_trait]
    impl Refresh for CountingRefresher {
        async fn refresh(&self) -> std::result::Result<RefreshedToken, RefreshError> {
            tokio::time::sleep(self.delay).await;
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(RefreshedToken::new(format!("token-{n}")).with_expires_at(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 3600,
            ))
        }
    }

    #[tokio::test]
    async fn refresh_now_coalesces_concurrent_callers() {
        let calls = Arc::new(AtomicUsize::new(0));
        let refresher = Arc::new(CountingRefresher {
            calls: Arc::clone(&calls),
            delay: Duration::from_millis(50),
        });
        let source = TokenSource::new(RefreshedToken::new("initial").with_expires_at(0), refresher);

        let tasks = (0..5).map(|_| {
            let src = source.clone();
            tokio::spawn(async move { src.refresh_now().await })
        });
        for t in tasks {
            t.await.unwrap().unwrap();
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "single-flight should have collapsed 5 concurrent calls into 1 refresh"
        );
    }

    #[tokio::test]
    async fn current_returns_cached_when_not_near_expiry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let refresher = Arc::new(CountingRefresher {
            calls: Arc::clone(&calls),
            delay: Duration::from_millis(0),
        });
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let source = TokenSource::new(
            RefreshedToken::new("fresh").with_expires_at(future),
            refresher,
        );

        let token = source.current().await.unwrap();
        assert_eq!(token, "fresh");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn current_refreshes_when_within_skew() {
        let calls = Arc::new(AtomicUsize::new(0));
        let refresher = Arc::new(CountingRefresher {
            calls: Arc::clone(&calls),
            delay: Duration::from_millis(0),
        });
        let near = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 5;
        let source = TokenSource::new(
            RefreshedToken::new("stale").with_expires_at(near),
            refresher,
        );

        let token = source.current().await.unwrap();
        assert_eq!(token, "token-1");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
