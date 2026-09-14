// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authoritative launch-scoped sandbox authentication state.

use std::collections::HashMap;
use std::sync::Mutex;

use openshell_core::SandboxSessionId;
use openshell_core::jwt::{
    CredentialEpoch, SandboxLaunchAuthentication, SecretJwt, SessionJwtError,
};
use uuid::Uuid;

use crate::auth::sandbox_jwt::SandboxSessionJwtAuthority;

#[derive(Clone)]
struct RefreshResult {
    consumed_token_id: Uuid,
    authentication: SandboxLaunchAuthentication,
}

#[derive(Clone)]
struct ActiveSession {
    session_id: SandboxSessionId,
    credential_epoch: CredentialEpoch,
    current_gateway_token_id: Uuid,
    active: bool,
    last_refresh: Option<RefreshResult>,
    authentication: SandboxLaunchAuthentication,
}

/// One active launch generation per sandbox.
#[derive(Default)]
pub struct SandboxSessionRegistry {
    sessions: Mutex<HashMap<String, ActiveSession>>,
}

impl std::fmt::Debug for SandboxSessionRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxSessionRegistry")
            .finish_non_exhaustive()
    }
}

impl SandboxSessionRegistry {
    /// Authorize a cryptographically verified gateway-profile session token.
    ///
    /// Ordinary supervisor RPCs accept only the currently active token. The
    /// refresh RPC may replay the immediately consumed token so a lost refresh
    /// response can be retried without extending any older credential.
    #[allow(clippy::result_large_err)]
    pub fn authorize(
        &self,
        principal: &openshell_core::jwt::AuthenticatedSandboxSession,
        allow_last_refresh: bool,
    ) -> Result<(), tonic::Status> {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let session = sessions
            .get(principal.sandbox_id.as_str())
            .filter(|session| session.active)
            .ok_or_else(|| tonic::Status::failed_precondition("sandbox session is not active"))?;
        if principal.session_id != session.session_id || principal.credential_epoch.is_some() {
            return Err(tonic::Status::unauthenticated(
                "gateway session does not match the active sandbox generation",
            ));
        }
        let current = principal.token_id == session.current_gateway_token_id;
        let retry = allow_last_refresh
            && session
                .last_refresh
                .as_ref()
                .is_some_and(|refresh| refresh.consumed_token_id == principal.token_id);
        if !current && !retry {
            return Err(tonic::Status::unauthenticated(
                "gateway session token has been replaced",
            ));
        }
        Ok(())
    }

    pub fn activate(
        &self,
        sandbox_id: &str,
        authentication: &SandboxLaunchAuthentication,
        authority: &SandboxSessionJwtAuthority,
    ) -> Result<(), SessionJwtError> {
        authentication.validate()?;
        let principal = authority
            .verify_gateway_token(authentication.supervisor.gateway_token.expose_secret())
            .map_err(|_| SessionJwtError::InvalidToken)?;
        if principal.session_id != authentication.supervisor.session_id
            || principal.credential_epoch.is_some()
        {
            return Err(SessionJwtError::ProfileMismatch);
        }
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                sandbox_id.to_string(),
                ActiveSession {
                    session_id: authentication.supervisor.session_id,
                    credential_epoch: authentication.supervisor.credential_epoch,
                    current_gateway_token_id: principal.token_id,
                    active: true,
                    last_refresh: None,
                    authentication: authentication.clone(),
                },
            );
        Ok(())
    }

    pub fn current(&self, sandbox_id: &str) -> Option<(SandboxSessionId, CredentialEpoch)> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(sandbox_id)
            .filter(|session| session.active)
            .map(|session| (session.session_id, session.credential_epoch))
    }

    pub fn authentication(&self, sandbox_id: &str) -> Option<SandboxLaunchAuthentication> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(sandbox_id)
            .filter(|session| session.active)
            .map(|session| session.authentication.clone())
    }

    pub fn deactivate(&self, sandbox_id: &str) {
        if let Some(session) = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(sandbox_id)
        {
            session.active = false;
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn refresh(
        &self,
        sandbox_id: &str,
        presented_token: &SecretJwt,
        authority: &SandboxSessionJwtAuthority,
    ) -> Result<SandboxLaunchAuthentication, tonic::Status> {
        let principal = authority.verify_gateway_token(presented_token.expose_secret())?;
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let session = sessions
            .get_mut(sandbox_id)
            .ok_or_else(|| tonic::Status::failed_precondition("sandbox session is not active"))?;
        if !session.active || principal.session_id != session.session_id {
            return Err(tonic::Status::failed_precondition(
                "sandbox session is not active",
            ));
        }
        if let Some(previous) = &session.last_refresh
            && previous.consumed_token_id == principal.token_id
        {
            return Ok(previous.authentication.clone());
        }
        if principal.token_id != session.current_gateway_token_id {
            return Err(tonic::Status::unauthenticated(
                "gateway session token has already been replaced",
            ));
        }
        let next_epoch = session
            .credential_epoch
            .get()
            .checked_add(1)
            .and_then(|value| CredentialEpoch::new(value).ok())
            .ok_or_else(|| tonic::Status::internal("sandbox credential epoch overflow"))?;
        let authentication = authority.mint_launch(sandbox_id, session.session_id, next_epoch)?;
        let next_principal = authority
            .verify_gateway_token(authentication.supervisor.gateway_token.expose_secret())?;
        session.credential_epoch = next_epoch;
        session.current_gateway_token_id = next_principal.token_id;
        session.authentication = authentication.clone();
        session.last_refresh = Some(RefreshResult {
            consumed_token_id: principal.token_id,
            authentication: authentication.clone(),
        });
        Ok(authentication)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use openshell_bootstrap::jwt::generate_jwt_key;

    use super::*;

    #[test]
    fn authorization_tracks_active_token_and_refresh_retry() {
        let key = generate_jwt_key().expect("JWT key");
        let authority = SandboxSessionJwtAuthority::from_pem(
            key.signing_key_pem.as_bytes(),
            key.public_key_pem.as_bytes(),
            key.kid,
            "gateway-a",
            Duration::from_hours(1),
        )
        .expect("session authority");
        let registry = SandboxSessionRegistry::default();
        let authentication = authority
            .mint_launch(
                "sandbox-a",
                SandboxSessionId::new(),
                CredentialEpoch::new(1).expect("credential epoch"),
            )
            .expect("launch authentication");
        registry
            .activate("sandbox-a", &authentication, &authority)
            .expect("activate session");

        let original = authority
            .verify_gateway_token(authentication.supervisor.gateway_token.expose_secret())
            .expect("original principal");
        registry
            .authorize(&original, false)
            .expect("current token is authorized");

        let refreshed = registry
            .refresh(
                "sandbox-a",
                &authentication.supervisor.gateway_token,
                &authority,
            )
            .expect("refresh session");
        assert!(registry.authorize(&original, false).is_err());
        registry
            .authorize(&original, true)
            .expect("immediately consumed token can retry refresh");
        let current = authority
            .verify_gateway_token(refreshed.supervisor.gateway_token.expose_secret())
            .expect("refreshed principal");
        registry
            .authorize(&current, false)
            .expect("refreshed token is authorized");

        registry.deactivate("sandbox-a");
        assert!(registry.authorize(&current, false).is_err());
    }
}
