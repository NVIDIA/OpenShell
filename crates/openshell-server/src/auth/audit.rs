// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF security events for gateway authentication outcomes.
//!
//! Events carry a low-cardinality reason category, never presented
//! credentials or raw verification errors.

use openshell_ocsf::{
    ActionId, AuthProtocolId, AuthenticationBuilder, DispositionId, Endpoint, HttpMethod,
    HttpRequest, Service, SeverityId, StatusId, Url, User, ocsf_emit,
};
use std::net::SocketAddr;

/// Where a gateway connection came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionSource {
    /// A direct TCP connection. The address is the immediate peer, which is
    /// a proxy or load balancer when one fronts the gateway.
    Peer(SocketAddr),
    /// A connection carried over the WebSocket tunnel endpoint.
    EdgeTunnel,
}

impl ConnectionSource {
    fn endpoint(self) -> Endpoint {
        match self {
            Self::Peer(addr) => Endpoint::from_ip(addr.ip().to_canonical(), addr.port()),
            Self::EdgeTunnel => Endpoint::from_name("edge-tunnel"),
        }
    }
}

/// Request details recorded on every audit event about the request.
#[derive(Debug, Clone, Default)]
pub struct RequestOrigin {
    source: Option<ConnectionSource>,
    request_id: Option<String>,
}

impl RequestOrigin {
    /// Only a canonical UUID `x-request-id` is kept: the value is
    /// client-controlled and the gateway generates one when it is absent.
    pub fn new(source: Option<ConnectionSource>, headers: &http::HeaderMap) -> Self {
        let request_id = headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .filter(|value| openshell_core::endpoint_failure::is_canonical_request_id(value))
            .map(str::to_owned);
        Self { source, request_id }
    }
}

use super::authenticator::{AuthFailureReason, AuthMechanism};

fn category(reason: AuthFailureReason) -> &'static str {
    match reason {
        AuthFailureReason::MissingCredential => "missing_credential",
        AuthFailureReason::ConflictingCredentials => "conflicting_credentials",
        AuthFailureReason::MalformedCredential => "malformed_credential",
        AuthFailureReason::InvalidCredential => "invalid_credential",
        AuthFailureReason::ExpiredCredential => "expired_credential",
        AuthFailureReason::AudienceOrIssuerMismatch => "audience_or_issuer_mismatch",
        AuthFailureReason::UnknownIdentity => "unknown_identity",
        AuthFailureReason::StaleIdentity => "stale_identity",
        AuthFailureReason::IdentityProviderUnavailable => "identity_provider_unavailable",
    }
}

fn severity(reason: AuthFailureReason) -> SeverityId {
    match reason {
        AuthFailureReason::MissingCredential | AuthFailureReason::ExpiredCredential => {
            SeverityId::Low
        }
        AuthFailureReason::ConflictingCredentials
        | AuthFailureReason::MalformedCredential
        | AuthFailureReason::InvalidCredential
        | AuthFailureReason::AudienceOrIssuerMismatch
        | AuthFailureReason::UnknownIdentity
        | AuthFailureReason::StaleIdentity
        | AuthFailureReason::IdentityProviderUnavailable => SeverityId::Medium,
    }
}

fn with_protocol(
    builder: AuthenticationBuilder<'_>,
    mechanism: AuthMechanism,
) -> AuthenticationBuilder<'_> {
    match mechanism {
        AuthMechanism::Oidc => builder.auth_protocol(AuthProtocolId::OpenId),
        AuthMechanism::Mtls => builder.auth_protocol_other("mtls"),
        AuthMechanism::SandboxJwt => builder.auth_protocol_other("sandbox_jwt"),
        AuthMechanism::ComputeDriver => builder.auth_protocol_other("compute_driver"),
        AuthMechanism::GatewayPeer => builder.auth_protocol_other("k8s_service_account"),
    }
}

/// Emit an Authentication failure event for a gRPC request to `path`.
pub fn emit_authentication_failure(
    path: &str,
    origin: &RequestOrigin,
    mechanism: Option<AuthMechanism>,
    reason: AuthFailureReason,
) {
    let ctx = crate::gateway_ocsf::context("", "");
    let mut builder = AuthenticationBuilder::new(
        &ctx,
        User::unidentified(),
        Service::new("openshell-gateway"),
    )
    .action(ActionId::Denied)
    .disposition(DispositionId::Blocked)
    .severity(severity(reason))
    .status(StatusId::Failure)
    .status_detail(category(reason))
    .http_request(HttpRequest {
        http_method: HttpMethod::Post,
        url: Some(Url::from_path(path)),
    })
    .message(format!("authentication failed: {}", category(reason)));
    if let Some(mechanism) = mechanism {
        builder = with_protocol(builder, mechanism);
    }
    if let Some(source) = origin.source {
        builder = builder.src_endpoint(source.endpoint());
    }
    if let Some(request_id) = &origin.request_id {
        builder = builder.correlation_uid(request_id);
    }
    ocsf_emit!(builder.build());
}
