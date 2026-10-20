// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF security events for gateway authentication outcomes and credential
//! disclosure.
//!
//! Events carry a low-cardinality reason category, never presented
//! credentials, disclosed secrets, or raw verification errors.

use openshell_ocsf::{
    ActionId, AuthProtocolId, AuthenticationBuilder, ConfigStateChangeBuilder, DispositionId,
    Endpoint, HttpMethod, HttpRequest, Service, SeverityId, StateId, StatusId, Url, User,
    ocsf_emit,
};
use std::net::SocketAddr;
use tonic::{Code, Request, Status};

use super::principal::Principal;

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

    /// The origin of a gRPC request, from the extensions and headers the
    /// multiplexer attached to it.
    pub fn from_request<T>(request: &Request<T>) -> Self {
        Self::new(
            request.extensions().get::<ConnectionSource>().copied(),
            request.metadata().as_ref(),
        )
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

const MAX_RESOURCE_CHARS: usize = 256;

/// Audit record for one attempt to read secret-bearing material through a
/// gateway RPC. The read changes no state, but the disclosure must stay
/// accountable.
///
/// Exactly one event is emitted per attempt: by [`Self::finish`], or as a
/// cancellation when the RPC future is dropped first. Any new RPC that returns
/// secret-bearing material must begin one of these before it authorizes the
/// caller. Record only identifiers, never the disclosed values.
pub struct DisclosureAudit {
    operation: &'static str,
    actor: String,
    request_id: Option<String>,
    sandbox: Option<(String, String)>,
    resource: Vec<(&'static str, String)>,
    emitted: bool,
}

impl DisclosureAudit {
    /// Start the record for `operation`, naming the caller from the principal
    /// the gateway authenticated rather than from the request body.
    pub fn begin<T>(operation: &'static str, request: &Request<T>) -> Self {
        Self {
            operation,
            actor: request
                .extensions()
                .get::<Principal>()
                .map_or_else(|| "unknown".to_string(), Principal::audit_actor),
            request_id: RequestOrigin::from_request(request).request_id,
            sandbox: None,
            resource: Vec::new(),
            emitted: false,
        }
    }

    /// Name the sandbox the disclosed material belongs to.
    pub fn sandbox(&mut self, id: &str, name: &str) {
        self.sandbox = Some((id.to_string(), name.to_string()));
    }

    /// Name a disclosed resource by identifier. Never pass a credential value.
    /// Values can come from the request, so they are bounded.
    pub fn resource(&mut self, key: &'static str, value: impl Into<String>) {
        let mut value = value.into();
        if let Some((end, _)) = value.char_indices().nth(MAX_RESOURCE_CHARS) {
            value.truncate(end);
        }
        self.resource.push((key, value));
    }

    /// Emit the record for the attempt's final result.
    pub fn finish<T>(mut self, result: &Result<T, Status>) {
        let outcome = match result {
            Ok(_) => DisclosureOutcome::Disclosed,
            Err(status)
                if matches!(
                    status.code(),
                    Code::PermissionDenied | Code::Unauthenticated
                ) =>
            {
                DisclosureOutcome::Denied(status.code())
            }
            Err(status) => DisclosureOutcome::Failed(status.code()),
        };
        self.emit(outcome);
    }

    fn emit(&mut self, outcome: DisclosureOutcome) {
        self.emitted = true;
        let label = outcome.label();
        let (sandbox_id, sandbox_name) = self
            .sandbox
            .as_ref()
            .map_or(("", ""), |(id, name)| (id, name));
        let ctx = crate::gateway_ocsf::context(sandbox_id, sandbox_name);
        let mut builder = ConfigStateChangeBuilder::new(&ctx)
            .state(StateId::Other, label)
            .severity(outcome.severity())
            .status(match outcome {
                DisclosureOutcome::Disclosed => StatusId::Success,
                _ => StatusId::Failure,
            })
            .message(format!("{} {label}", self.operation))
            .unmapped("operation", self.operation)
            .unmapped("actor", self.actor.clone())
            .unmapped("outcome", label);
        if let Some(code) = outcome.code() {
            builder = builder.unmapped("status_code", format!("{code:?}"));
        }
        for (key, value) in &self.resource {
            builder = builder.unmapped(key, value.clone());
        }
        if let Some(request_id) = &self.request_id {
            builder = builder.correlation_uid(request_id);
        }
        ocsf_emit!(builder.build());
    }
}

#[derive(Clone, Copy)]
enum DisclosureOutcome {
    Disclosed,
    Denied(Code),
    Failed(Code),
    Cancelled,
}

impl DisclosureOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Disclosed => "disclosed",
            Self::Denied(_) => "denied",
            Self::Failed(_) => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    fn severity(self) -> SeverityId {
        match self {
            Self::Disclosed => SeverityId::Informational,
            Self::Denied(_) => SeverityId::Medium,
            Self::Failed(_) | Self::Cancelled => SeverityId::Low,
        }
    }

    fn code(self) -> Option<Code> {
        match self {
            Self::Denied(code) | Self::Failed(code) => Some(code),
            Self::Disclosed | Self::Cancelled => None,
        }
    }
}

impl Drop for DisclosureAudit {
    fn drop(&mut self) {
        if !self.emitted {
            self.emit(DisclosureOutcome::Cancelled);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::{Identity, IdentityProvider};
    use crate::auth::principal::UserPrincipal;
    use openshell_ocsf::test_support::OcsfCapture;

    const REQUEST_ID: &str = "6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f";

    fn request() -> Request<()> {
        let mut request = Request::new(());
        request
            .extensions_mut()
            .insert(Principal::User(UserPrincipal {
                identity: Identity {
                    subject: "reviewer".into(),
                    display_name: None,
                    roles: vec![],
                    scopes: vec![],
                    provider: IdentityProvider::Oidc,
                },
            }));
        request
            .metadata_mut()
            .insert("x-request-id", REQUEST_ID.parse().unwrap());
        request
    }

    fn events(capture: &OcsfCapture) -> Vec<serde_json::Value> {
        capture
            .events()
            .iter()
            .map(|event| event.to_json().unwrap())
            .collect()
    }

    #[test]
    fn finish_emits_one_event_naming_actor_resource_and_request() {
        let capture = OcsfCapture::default();
        {
            let _guard = capture.install();
            let mut audit = DisclosureAudit::begin("GetThing", &request());
            audit.sandbox("sb-1", "agent");
            audit.resource("provider", "work");
            audit.finish(&Ok::<_, Status>(()));
        }

        let events = events(&capture);
        assert_eq!(events.len(), 1, "{events:?}");
        let event = &events[0];
        assert_eq!(event["class_uid"], 5019);
        assert_eq!(event["message"], "GetThing disclosed");
        assert_eq!(event["metadata"]["correlation_uid"], REQUEST_ID);
        assert_eq!(event["unmapped"]["actor"], "user:reviewer");
        assert_eq!(event["unmapped"]["operation"], "GetThing");
        assert_eq!(event["unmapped"]["outcome"], "disclosed");
        assert_eq!(event["unmapped"]["provider"], "work");
        assert_eq!(event["container"]["uid"], "sb-1");
        assert!(event["unmapped"].get("status_code").is_none());
    }

    #[test]
    fn failures_record_the_code_but_not_the_status_message() {
        let capture = OcsfCapture::default();
        {
            let _guard = capture.install();
            DisclosureAudit::begin("GetThing", &request()).finish(&Err::<(), _>(
                Status::permission_denied("secret-in-message"),
            ));
            DisclosureAudit::begin("GetThing", &request())
                .finish(&Err::<(), _>(Status::internal("secret-in-message")));
        }

        let events = events(&capture);
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(events[0]["unmapped"]["outcome"], "denied");
        assert_eq!(events[0]["unmapped"]["status_code"], "PermissionDenied");
        assert_eq!(events[0]["severity"], "Medium");
        assert_eq!(events[1]["unmapped"]["outcome"], "failed");
        assert_eq!(events[1]["unmapped"]["status_code"], "Internal");
        assert!(
            !serde_json::to_string(&events)
                .unwrap()
                .contains("secret-in-message")
        );
    }

    #[test]
    fn a_dropped_attempt_is_recorded_once_as_cancelled() {
        let capture = OcsfCapture::default();
        {
            let _guard = capture.install();
            drop(DisclosureAudit::begin("GetThing", &request()));
        }

        let events = events(&capture);
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0]["unmapped"]["outcome"], "cancelled");
    }

    #[test]
    fn an_unauthenticated_request_is_attributed_to_unknown() {
        let capture = OcsfCapture::default();
        {
            let _guard = capture.install();
            DisclosureAudit::begin("GetThing", &Request::new(()))
                .finish(&Err::<(), _>(Status::unauthenticated("no")));
        }

        let events = events(&capture);
        assert_eq!(events[0]["unmapped"]["actor"], "unknown");
        assert!(events[0]["metadata"].get("correlation_uid").is_none());
    }

    #[test]
    fn request_derived_values_are_bounded() {
        let capture = OcsfCapture::default();
        {
            let _guard = capture.install();
            let mut audit = DisclosureAudit::begin("GetThing", &request());
            audit.resource("requested_sandbox_id", "é".repeat(10_000));
            audit.finish(&Ok::<_, Status>(()));
        }

        let events = events(&capture);
        let recorded = events[0]["unmapped"]["requested_sandbox_id"]
            .as_str()
            .unwrap();
        assert_eq!(recorded.chars().count(), MAX_RESOURCE_CHARS);
    }
}
