// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF security events for gateway authentication and authorization
//! outcomes.
//!
//! Events carry a low-cardinality reason category, never presented
//! credentials, raw verification errors, or request bodies.

use openshell_ocsf::{
    ActionId, ActivityId, ApiActivityBuilder, AuthProtocolId, AuthenticationBuilder, ConfidenceId,
    DetectionFindingBuilder, DispositionId, Endpoint, FindingInfo, HttpMethod, HttpRequest,
    ResourceDetails, Service, SeverityId, StatusId, Url, User, UserTypeId, ocsf_emit,
};
use std::future::Future;
use std::net::SocketAddr;

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

tokio::task_local! {
    static REQUEST: RequestContext;
}

/// The request whose authorization decisions handlers are making.
#[derive(Debug, Clone)]
struct RequestContext {
    path: String,
    origin: RequestOrigin,
}

/// Run a request handler so the authorization denials it raises are
/// recorded against `path` and `origin`.
///
/// The scope covers the handler future only. Wrap work the handler spawns in
/// [`in_current_request`]; denials raised while a streaming response body is
/// polled are recorded without the request's path and origin.
pub async fn with_request<F: Future>(path: String, origin: RequestOrigin, handler: F) -> F::Output {
    REQUEST
        .scope(RequestContext { path, origin }, handler)
        .await
}

/// Carry the current request's audit context into `future`, for work a
/// handler runs in a spawned task.
pub fn in_current_request<F: Future>(future: F) -> impl Future<Output = F::Output> {
    let request = REQUEST.try_with(Clone::clone).ok();
    async move {
        match request {
            Some(request) => REQUEST.scope(request, future).await,
            None => future.await,
        }
    }
}

/// Why the gateway refused an authenticated caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzDenial<'a> {
    /// The principal type may not call the method, or may not call it with
    /// these arguments.
    MethodNotPermitted,
    /// The method is not one the gateway knows, for example one added by a
    /// newer client.
    UnknownMethod,
    /// The caller lacks the role the method requires.
    MissingRole,
    /// The caller's token lacks the scope the method requires.
    MissingScope,
    /// A sandbox principal referenced a sandbox other than its own by ID.
    CrossSandbox { sandbox_id: &'a str },
    /// A sandbox principal referenced a sandbox other than its own by name.
    CrossSandboxName { name: &'a str },
    /// The caller is not a member of the workspace.
    NotWorkspaceMember { workspace: &'a str },
    /// The caller's workspace role is below the one the operation requires.
    InsufficientWorkspaceRole { workspace: &'a str },
    /// The operation spans workspaces and requires a platform admin.
    PlatformAdminRequired,
    /// The operation requires a verified mTLS operator.
    OperatorRequired,
}

impl AuthzDenial<'_> {
    fn category(self) -> &'static str {
        match self {
            Self::MethodNotPermitted => "method_not_permitted",
            Self::UnknownMethod => "unknown_method",
            Self::MissingRole => "missing_role",
            Self::MissingScope => "missing_scope",
            Self::CrossSandbox { .. } | Self::CrossSandboxName { .. } => "cross_sandbox",
            Self::NotWorkspaceMember { .. } => "not_workspace_member",
            Self::InsufficientWorkspaceRole { .. } => "insufficient_workspace_role",
            Self::PlatformAdminRequired => "platform_admin_required",
            Self::OperatorRequired => "operator_required",
        }
    }

    fn resource(self) -> Option<ResourceDetails> {
        match self {
            Self::CrossSandbox { sandbox_id } => {
                Some(ResourceDetails::new("sandbox", bounded(sandbox_id)))
            }
            Self::CrossSandboxName { name } => {
                Some(ResourceDetails::named("sandbox", bounded(name)))
            }
            Self::NotWorkspaceMember { workspace }
            | Self::InsufficientWorkspaceRole { workspace } => {
                Some(ResourceDetails::named("workspace", bounded(workspace)))
            }
            _ => None,
        }
    }

    /// A sandbox principal is the supervisor, which never attempts these on
    /// its own: one that does is compromised or impersonated.
    fn is_boundary_violation(self, principal: &Principal) -> bool {
        matches!(principal, Principal::Sandbox(_))
            && matches!(
                self,
                Self::MethodNotPermitted
                    | Self::CrossSandbox { .. }
                    | Self::CrossSandboxName { .. }
                    | Self::PlatformAdminRequired
            )
    }
}

/// Longest request-supplied identifier recorded on an event.
const MAX_REQUESTED_ID_LEN: usize = 128;

/// Cap a request-supplied identifier so a caller cannot inflate events.
fn bounded(value: &str) -> String {
    if value.len() <= MAX_REQUESTED_ID_LEN {
        return value.to_string();
    }
    let mut end = MAX_REQUESTED_ID_LEN;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}

/// The principal as an OCSF user, identified but never with credentials.
fn principal_user(principal: &Principal) -> User {
    match principal {
        Principal::User(user) => User::new(&user.identity.subject, UserTypeId::User),
        Principal::Operator(operator) => User::new(&operator.identity.subject, UserTypeId::Admin),
        Principal::Sandbox(sandbox) => User::other(&sandbox.sandbox_id, "Sandbox"),
        Principal::Peer(peer) => User::other(&peer.replica_id, "Gateway Peer"),
        Principal::Anonymous => User::unidentified(),
    }
}

/// Emit an authorization denial raised by a handler for the current request.
pub fn emit_authorization_denial(principal: &Principal, denial: AuthzDenial<'_>) {
    let request = REQUEST.try_with(Clone::clone).ok();
    let (path, origin) = request
        .map(|request| (request.path, request.origin))
        .unwrap_or_default();
    emit_authorization_denial_for(&path, &origin, principal, denial);
}

/// Emit an API Activity denial for a gRPC request to `path`, paired with a
/// Detection Finding when a sandbox principal crossed its boundary.
pub fn emit_authorization_denial_for(
    path: &str,
    origin: &RequestOrigin,
    principal: &Principal,
    denial: AuthzDenial<'_>,
) {
    let ctx = crate::gateway_ocsf::context("", "");
    let category = denial.category();
    let finding = denial.is_boundary_violation(principal);
    // Both events of a pair must share an identifier even when the request
    // has no usable `x-request-id`.
    let correlation_uid = origin
        .request_id
        .clone()
        .or_else(|| finding.then(|| uuid::Uuid::new_v4().to_string()));
    let (service, operation) = path
        .strip_prefix('/')
        .and_then(|path| path.split_once('/'))
        .unwrap_or(("", "unknown"));

    let mut builder = ApiActivityBuilder::new(&ctx, operation)
        .actor_user(principal_user(principal))
        .src_endpoint(origin.source.map_or_else(
            || Endpoint::from_name("unknown"),
            ConnectionSource::endpoint,
        ))
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Medium)
        .status(StatusId::Failure)
        .status_detail(category)
        .message(format!("authorization denied: {category}"));
    if !service.is_empty() {
        builder = builder
            .api_service(Service::new(service))
            .http_request(HttpRequest {
                http_method: HttpMethod::Post,
                url: Some(Url::from_path(path)),
            });
    }
    if let Some(resource) = denial.resource() {
        builder = builder.resource(resource);
    }
    if let Some(uid) = &correlation_uid {
        builder = builder.correlation_uid(uid);
    }
    ocsf_emit!(builder.build());

    if let (true, Principal::Sandbox(sandbox)) = (finding, principal) {
        let mut evidence = vec![
            ("sandbox_id", sandbox.sandbox_id.as_str()),
            ("reason", category),
        ];
        if !path.is_empty() {
            evidence.push(("operation", path));
        }
        let requested = match denial {
            AuthzDenial::CrossSandbox { sandbox_id } => {
                Some(("requested_sandbox_id", bounded(sandbox_id)))
            }
            AuthzDenial::CrossSandboxName { name } => {
                Some(("requested_sandbox_name", bounded(name)))
            }
            _ => None,
        };
        if let Some((key, value)) = &requested {
            evidence.push((key, value));
        }
        let mut finding = DetectionFindingBuilder::new(&ctx)
            .activity(ActivityId::Open)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::High)
            .is_alert(true)
            .confidence(ConfidenceId::High)
            .finding_info(
                FindingInfo::new(
                    "sandbox-authorization-boundary",
                    "Sandbox Principal Exceeded Its Authorization",
                )
                .with_desc(
                    "A sandbox credential was used for an operation outside its own sandbox. \
                     The supervisor never does this, so the credential may be compromised.",
                ),
            )
            .evidence_pairs(&evidence)
            .message(format!(
                "sandbox authorization boundary violation: {category}"
            ));
        if let Some(uid) = &correlation_uid {
            finding = finding.correlation_uid(uid);
        }
        ocsf_emit!(finding.build());
    }
}
