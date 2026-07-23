// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Side-effect-free gateway authentication status RPC.

use crate::auth::identity::IdentityProvider;
use crate::auth::principal::Principal;
use openshell_core::proto::{
    AuthenticationProvider, GetAuthenticationStatusRequest, GetAuthenticationStatusResponse,
    authentication_server::Authentication,
};
use openshell_server_macros::rpc_authz;
use tonic::{Request, Response, Status};

#[derive(Debug, Clone, Copy, Default)]
pub struct AuthenticationService;

#[rpc_authz(service = "openshell.v1.Authentication")]
#[tonic::async_trait]
impl Authentication for AuthenticationService {
    #[rpc_auth(auth = "bearer")]
    async fn get_status(
        &self,
        request: Request<GetAuthenticationStatusRequest>,
    ) -> Result<Response<GetAuthenticationStatusResponse>, Status> {
        let (authenticated, provider) = match request.extensions().get::<Principal>() {
            Some(Principal::User(user)) => {
                let provider = match user.identity.provider {
                    IdentityProvider::Oidc => AuthenticationProvider::Oidc,
                    IdentityProvider::Mtls => AuthenticationProvider::Mtls,
                    IdentityProvider::CloudflareAccess => AuthenticationProvider::CloudflareAccess,
                    IdentityProvider::LocalDev => AuthenticationProvider::LocalDev,
                };
                (
                    user.identity.provider != IdentityProvider::LocalDev,
                    provider,
                )
            }
            Some(Principal::Sandbox(_) | Principal::Anonymous) | None => {
                (false, AuthenticationProvider::Unspecified)
            }
        };

        Ok(Response::new(GetAuthenticationStatusResponse {
            authenticated,
            provider: provider.into(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::Identity;
    use crate::auth::principal::UserPrincipal;

    #[tokio::test]
    async fn reports_authenticated_oidc_principal() {
        let mut request = Request::new(GetAuthenticationStatusRequest {});
        request
            .extensions_mut()
            .insert(Principal::User(UserPrincipal {
                identity: Identity {
                    subject: "alice".to_string(),
                    display_name: None,
                    roles: Vec::new(),
                    scopes: Vec::new(),
                    provider: IdentityProvider::Oidc,
                },
            }));

        let response = AuthenticationService
            .get_status(request)
            .await
            .expect("authentication status")
            .into_inner();

        assert!(response.authenticated);
        assert_eq!(response.provider(), AuthenticationProvider::Oidc);
    }

    #[tokio::test]
    async fn reports_no_application_principal() {
        let response = AuthenticationService
            .get_status(Request::new(GetAuthenticationStatusRequest {}))
            .await
            .expect("authentication status")
            .into_inner();

        assert!(!response.authenticated);
        assert_eq!(response.provider(), AuthenticationProvider::Unspecified);
    }
}
