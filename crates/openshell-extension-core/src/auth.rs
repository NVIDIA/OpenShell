// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tonic::metadata::AsciiMetadataValue;
use tonic::{Request, Status};

#[derive(Clone)]
pub struct BearerTokenSlot {
    inner: Arc<RwLock<Option<Token>>>,
}

#[derive(Clone)]
struct Token {
    authorization: AsciiMetadataValue,
    expires_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenSlotError {
    #[error("extension bearer token is not valid for an HTTP authorization header")]
    InvalidToken,
    #[error("extension bearer token expiry must be a positive Unix timestamp in milliseconds")]
    InvalidExpiry,
}

impl BearerTokenSlot {
    /// Create an empty slot. Requests fail closed until [`Self::update`] is called.
    pub fn empty() -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
        }
    }

    pub fn new(token: &str, expires_at_ms: i64) -> Result<Self, TokenSlotError> {
        let slot = Self::empty();
        slot.update(token, expires_at_ms)?;
        Ok(slot)
    }

    /// Replace the credential without rebuilding channels or generated clients.
    pub fn update(&self, token: &str, expires_at_ms: i64) -> Result<(), TokenSlotError> {
        if expires_at_ms <= 0 {
            return Err(TokenSlotError::InvalidExpiry);
        }
        if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(TokenSlotError::InvalidToken);
        }
        let authorization = AsciiMetadataValue::try_from(format!("Bearer {token}"))
            .map_err(|_| TokenSlotError::InvalidToken)?;
        *self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Token {
            authorization,
            expires_at_ms,
        });
        Ok(())
    }

    /// Remove the credential immediately. Subsequent requests fail closed.
    pub fn clear(&self) {
        *self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    pub fn expires_at_ms(&self) -> Option<i64> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|token| token.expires_at_ms)
    }

    pub fn interceptor(&self) -> BearerTokenInterceptor {
        BearerTokenInterceptor {
            slot: Some(self.clone()),
        }
    }

    fn authorization_at(&self, now_ms: i64) -> Result<AsciiMetadataValue, Status> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let token = guard
            .as_ref()
            .ok_or_else(|| Status::unauthenticated("extension bearer token is unavailable"))?;
        if token.expires_at_ms <= now_ms {
            return Err(Status::unauthenticated(
                "extension bearer token has expired",
            ));
        }
        Ok(token.authorization.clone())
    }
}

impl Default for BearerTokenSlot {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for BearerTokenSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BearerTokenSlot")
            .field("expires_at_ms", &self.expires_at_ms())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct BearerTokenInterceptor {
    slot: Option<BearerTokenSlot>,
}

impl BearerTokenInterceptor {
    /// Create an explicit no-op interceptor for legacy registrations that have
    /// not opted into audience authentication.
    pub const fn disabled() -> Self {
        Self { slot: None }
    }
}

impl fmt::Debug for BearerTokenInterceptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BearerTokenInterceptor")
            .field("enabled", &self.slot.is_some())
            .field("slot", &self.slot)
            .finish()
    }
}

impl tonic::service::Interceptor for BearerTokenInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let Some(slot) = &self.slot else {
            return Ok(request);
        };
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
            });
        let authorization = slot.authorization_at(now_ms)?;
        request
            .metadata_mut()
            .insert("authorization", authorization);
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use tonic::service::Interceptor;

    use super::*;

    #[test]
    fn slot_rotates_all_interceptor_clones_in_place() {
        let slot = BearerTokenSlot::new("first-secret", i64::MAX).unwrap();
        let mut first = slot.interceptor();
        let mut second = first.clone();

        assert_eq!(
            first
                .call(Request::new(()))
                .unwrap()
                .metadata()
                .get("authorization")
                .unwrap(),
            "Bearer first-secret"
        );
        slot.update("second-secret", i64::MAX).unwrap();
        assert_eq!(
            second
                .call(Request::new(()))
                .unwrap()
                .metadata()
                .get("authorization")
                .unwrap(),
            "Bearer second-secret"
        );
    }

    #[test]
    fn empty_expired_and_cleared_slots_fail_closed() {
        let slot = BearerTokenSlot::empty();
        assert_eq!(
            slot.interceptor()
                .call(Request::new(()))
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );

        slot.update("expired", 1).unwrap();
        assert_eq!(
            slot.interceptor()
                .call(Request::new(()))
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );

        slot.update("current", i64::MAX).unwrap();
        slot.clear();
        assert_eq!(
            slot.interceptor()
                .call(Request::new(()))
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }

    #[test]
    fn debug_and_errors_do_not_expose_token_material() {
        let secret = "super-secret-extension-token";
        let slot = BearerTokenSlot::new(secret, i64::MAX).unwrap();
        assert!(!format!("{slot:?}").contains(secret));
        assert!(!format!("{:?}", slot.interceptor()).contains(secret));

        let error = BearerTokenSlot::new("contains\nnewline", i64::MAX).unwrap_err();
        assert!(!error.to_string().contains("contains"));
        assert_eq!(
            BearerTokenSlot::new("", i64::MAX).unwrap_err(),
            TokenSlotError::InvalidToken
        );
    }

    #[test]
    fn disabled_interceptor_leaves_authorization_untouched() {
        let mut interceptor = BearerTokenInterceptor::disabled();
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", "Bearer caller-value".parse().unwrap());
        let request = interceptor.call(request).unwrap();
        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer caller-value"
        );
        assert!(format!("{interceptor:?}").contains("enabled: false"));
    }
}
