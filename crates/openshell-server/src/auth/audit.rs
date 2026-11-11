// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF security events for gateway authentication and authorization
//! outcomes, and for the state changes users and operators request.
//!
//! Events carry a low-cardinality reason category, never presented
//! credentials, raw verification errors, or request bodies.

use openshell_ocsf::{
    ActionId, ActivityId, ApiActivityBuilder, AuthProtocolId, AuthenticationBuilder, ConfidenceId,
    DetectionFindingBuilder, DispositionId, Endpoint, EventContext, FindingInfo, HttpMethod,
    HttpRequest, ResourceDetails, Service, SeverityId, StatusId, Url, User, UserTypeId, ocsf_emit,
};
use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tonic::{Code, Status};

use super::identity::IdentityProvider;
use super::principal::{Principal, SandboxIdentitySource};

pub mod catalog;
#[cfg(test)]
pub mod test_support;

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

use super::authenticator::{AuthFailureReason, AuthMechanism, AuthRejection, bearer_credential};

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

/// The request to `path` as an OCSF HTTP request; gRPC calls are POSTs.
fn post(path: &str) -> HttpRequest {
    HttpRequest {
        http_method: HttpMethod::Post,
        url: Some(Url::from_path(path)),
    }
}

/// An Authentication event for `user`'s request to `path` from `origin`,
/// naming the protocol of `mechanism` when known.
fn authentication<'a>(
    ctx: &'a EventContext,
    path: &str,
    origin: &RequestOrigin,
    user: User,
    mechanism: Option<AuthMechanism>,
) -> AuthenticationBuilder<'a> {
    let mut builder = AuthenticationBuilder::new(ctx, user, Service::new("openshell-gateway"))
        .http_request(post(path));
    match mechanism {
        Some(AuthMechanism::Oidc) => builder = builder.auth_protocol(AuthProtocolId::OpenId),
        Some(mechanism) => builder = builder.auth_protocol_other(mechanism.as_str()),
        None => {}
    }
    if let Some(source) = origin.source {
        builder = builder.src_endpoint(source.endpoint());
    }
    if let Some(request_id) = &origin.request_id {
        builder = builder.correlation_uid(request_id);
    }
    builder
}

/// Emit an Authentication failure event for a gRPC request to `path`.
pub fn emit_authentication_failure(
    path: &str,
    origin: &RequestOrigin,
    mechanism: Option<AuthMechanism>,
    reason: AuthFailureReason,
) {
    authentication_failure(path, origin, User::unidentified(), mechanism, reason);
}

/// Emit an Authentication failure event for a credential that a handler
/// verifies itself, returning the status that refuses the current request.
///
/// The event names `principal`, the caller the router established from a
/// separate credential, or leaves the user unidentified when the rejected
/// credential is the one that named the caller.
pub fn reject_credential(principal: Option<&Principal>, rejection: AuthRejection) -> Status {
    let (path, origin) = current_request();
    authentication_failure(
        &path,
        &origin,
        principal.map_or_else(User::unidentified, principal_user),
        Some(rejection.mechanism),
        rejection.reason,
    );
    rejection.status
}

fn authentication_failure(
    path: &str,
    origin: &RequestOrigin,
    user: User,
    mechanism: Option<AuthMechanism>,
    reason: AuthFailureReason,
) {
    let ctx = crate::gateway_ocsf::context("", "");
    let builder = authentication(&ctx, path, origin, user, mechanism)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(severity(reason))
        .status(StatusId::Failure)
        .status_detail(reason.as_str())
        .message(format!("authentication failed: {}", reason.as_str()));
    ocsf_emit!(builder.build());
}

/// How long a credential stays logged on before its next use records a new
/// logon.
const LOGON_WINDOW: Duration = Duration::from_hours(1);

/// Credentials tracked at once. When full, the oldest logon is forgotten
/// early, so a busy gateway records some credentials more than once an hour.
const MAX_LOGONS: usize = 16_384;

/// Credentials that have recently authenticated, shared by every connection
/// to this gateway replica.
///
/// Every request authenticates, so recording each one would bury user logons
/// under supervisor polling. A credential instead records one logon when the
/// replica first accepts it, and again after [`LOGON_WINDOW`] if still in use.
#[derive(Debug, Clone, Default)]
pub struct Logons(Arc<Mutex<LogonState>>);

#[derive(Debug, Default)]
struct LogonState {
    active: HashSet<[u8; 32]>,
    by_age: VecDeque<([u8; 32], Instant)>,
}

impl Logons {
    /// Record a logon for `credential` at `now`, returning whether it is new.
    fn log_on(&self, credential: [u8; 32], now: Instant) -> bool {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let LogonState { active, by_age } = &mut *state;
        while let Some(&(oldest, at)) = by_age.front() {
            if now.saturating_duration_since(at) < LOGON_WINDOW {
                break;
            }
            by_age.pop_front();
            active.remove(&oldest);
        }
        if active.contains(&credential) {
            return false;
        }
        // Only a new credential makes room, so polling a full record of
        // credentials that are still logged on records nothing.
        if by_age.len() >= MAX_LOGONS
            && let Some((oldest, _)) = by_age.pop_front()
        {
            active.remove(&oldest);
        }
        active.insert(credential);
        by_age.push_back((credential, now));
        true
    }
}

/// Whether the gateway verified a credential to establish `principal`.
fn authenticated(principal: &Principal) -> bool {
    match principal {
        Principal::User(user) => user.identity.provider != IdentityProvider::LocalDev,
        Principal::Anonymous => false,
        Principal::Operator(_)
        | Principal::Sandbox(_)
        | Principal::Peer(_)
        | Principal::Supervisor(_) => true,
    }
}

/// The mechanism that established `principal`, when it has an audit label.
fn mechanism(principal: &Principal) -> Option<AuthMechanism> {
    match principal {
        Principal::Operator(_) => Some(AuthMechanism::Mtls),
        Principal::User(user) => match user.identity.provider {
            IdentityProvider::Oidc => Some(AuthMechanism::Oidc),
            IdentityProvider::Mtls => Some(AuthMechanism::Mtls),
            IdentityProvider::CloudflareAccess | IdentityProvider::LocalDev => None,
        },
        Principal::Sandbox(sandbox) => Some(match sandbox.source {
            SandboxIdentitySource::BootstrapJwt { .. } => AuthMechanism::SandboxJwt,
            SandboxIdentitySource::ComputeDriver { .. } => AuthMechanism::ComputeDriver,
        }),
        Principal::Peer(_) => Some(AuthMechanism::GatewayPeer),
        Principal::Supervisor(_) => Some(AuthMechanism::SupervisorToken),
        Principal::Anonymous => None,
    }
}

/// A digest identifying the credential that established `principal`: the
/// operator's or mTLS user's certificate, or the bearer token.
///
/// Only verified material goes in, so headers the authenticator ignored
/// cannot make a new logon.
fn credential_digest(
    principal: &Principal,
    headers: &http::HeaderMap,
    peer_certificate_sha256: Option<&str>,
) -> Option<[u8; 32]> {
    let credential = match principal {
        Principal::Operator(operator) => operator.certificate_sha256.as_str(),
        Principal::User(user) if user.identity.provider == IdentityProvider::Mtls => {
            peer_certificate_sha256.unwrap_or_default()
        }
        _ => bearer_credential(headers).unwrap_or_default(),
    };
    digest(principal, None, credential)
}

/// A digest of `principal`, the mechanism when it is not the principal's
/// own, and the credential, kept apart by separators.
fn digest(
    principal: &Principal,
    mechanism: Option<AuthMechanism>,
    credential: &str,
) -> Option<[u8; 32]> {
    let mut material = principal.audit_actor().into_bytes();
    material.push(0);
    if let Some(mechanism) = mechanism {
        material.extend_from_slice(mechanism.as_str().as_bytes());
        material.push(0);
    }
    material.extend_from_slice(credential.as_bytes());
    openshell_crypto::sha256(&material).ok()
}

/// Whether the handler for `path` finishes verifying `principal`'s
/// credential, and so records its logon itself once it accepts it: the
/// recorded runtime of a compute-driver credential on `IssueSandboxToken`,
/// and the lineage of a gateway JWT on `RefreshSandboxToken`. Other
/// credentials are fully verified by the router.
fn handler_verifies(path: &str, principal: &Principal) -> bool {
    let Principal::Sandbox(sandbox) = principal else {
        return false;
    };
    match sandbox.source {
        SandboxIdentitySource::ComputeDriver { .. } => {
            path == super::compute_driver::ISSUE_SANDBOX_TOKEN_PATH
        }
        SandboxIdentitySource::BootstrapJwt { .. } => {
            path == super::sandbox_jwt::REFRESH_SANDBOX_TOKEN_PATH
        }
    }
}

/// Emit an Authentication logon event for a request to `path` that
/// authenticated as `principal`, unless its credential is already logged on
/// or the handler finishes verifying it.
///
/// `peer_certificate_sha256` fingerprints the connection's verified client
/// certificate, which identifies an mTLS user's credential.
pub fn emit_logon(
    logons: &Logons,
    path: &str,
    origin: &RequestOrigin,
    principal: &Principal,
    headers: &http::HeaderMap,
    peer_certificate_sha256: Option<&str>,
) {
    if authenticated(principal)
        && !handler_verifies(path, principal)
        && logs_on(
            logons,
            credential_digest(principal, headers, peer_certificate_sha256),
        )
    {
        logon(path, origin, principal, mechanism(principal));
    }
}

/// Emit an Authentication logon event for the current request once its
/// handler has finished verifying `principal`'s credential, unless the
/// credential is already logged on.
pub fn emit_handler_logon(logons: &Logons, principal: &Principal, headers: &http::HeaderMap) {
    if logs_on(logons, credential_digest(principal, headers, None)) {
        let (path, origin) = current_request();
        logon(&path, &origin, principal, mechanism(principal));
    }
}

/// Emit an Authentication logon event for the SSH session `token` that a
/// handler accepted from `principal`, unless it is already logged on.
pub fn emit_ssh_session_logon(logons: &Logons, principal: &Principal, token: &str) {
    let mechanism = AuthMechanism::SshSessionToken;
    if logs_on(logons, digest(principal, Some(mechanism), token)) {
        let (path, origin) = current_request();
        logon(&path, &origin, principal, Some(mechanism));
    }
}

/// Whether the credential with `digest` makes a new logon. Without a digest
/// the credential cannot be deduplicated, so it logs on.
fn logs_on(logons: &Logons, digest: Option<[u8; 32]>) -> bool {
    digest.is_none_or(|digest| logons.log_on(digest, Instant::now()))
}

fn logon(
    path: &str,
    origin: &RequestOrigin,
    principal: &Principal,
    mechanism: Option<AuthMechanism>,
) {
    let ctx = crate::gateway_ocsf::context("", "");
    let builder = authentication(&ctx, path, origin, principal_user(principal), mechanism)
        .action(ActionId::Allowed)
        .disposition(DispositionId::Allowed)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message("authentication succeeded");
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
    /// Set once a handler has emitted the request's authorization denial.
    denied: Arc<AtomicBool>,
    mutation: Arc<Mutex<Mutation>>,
}

impl RequestContext {
    fn new(path: String, origin: RequestOrigin) -> Self {
        Self {
            path,
            origin,
            denied: Arc::default(),
            mutation: Arc::default(),
        }
    }
}

/// What a state-changing request acted on and, when it succeeded without a
/// plain change, how it ended.
#[derive(Debug, Default)]
struct Mutation {
    resources: Vec<ResourceDetails>,
    outcome: Option<&'static str>,
}

/// Record that the current request's change acts on `resource`.
pub fn record_target(resource: ResourceDetails) {
    let _ = REQUEST.try_with(|request| {
        lock(&request.mutation).resources.push(resource);
    });
}

/// Change the resources recorded for the current request.
pub fn amend_targets(amend: impl FnOnce(&mut Vec<ResourceDetails>)) {
    let _ = REQUEST.try_with(|request| amend(&mut lock(&request.mutation).resources));
}

/// Record how the current request's change ended when it succeeded without
/// a plain change, such as `no_op:already_absent`.
pub fn record_outcome(outcome: &'static str) {
    let _ = REQUEST.try_with(|request| lock(&request.mutation).outcome = Some(outcome));
}

/// A resource of `type_label` named by the caller, bounded in length.
pub fn requested(type_label: &str, name: &str) -> ResourceDetails {
    ResourceDetails::named(type_label, bounded(name))
}

fn lock(mutation: &Mutex<Mutation>) -> std::sync::MutexGuard<'_, Mutation> {
    mutation.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Run a request handler so the authorization denials it raises are
/// recorded against `path` and `origin`.
///
/// The scope covers the handler future only. Wrap work the handler spawns in
/// [`in_current_request`]; denials raised while a streaming response body is
/// polled are recorded without the request's path and origin.
pub async fn with_request<F: Future>(path: String, origin: RequestOrigin, handler: F) -> F::Output {
    REQUEST
        .scope(RequestContext::new(path, origin), handler)
        .await
}

/// Run a request handler as [`with_request`] does, then record the state
/// change a user or operator `principal` attempted, unless the handler
/// already recorded it as an authorization denial. A streamed response is
/// recorded when its body ends, with the status in its trailers.
pub async fn with_audited_request<E, F>(
    path: String,
    origin: RequestOrigin,
    principal: &Principal,
    handler: F,
) -> Result<http::Response<tonic::body::Body>, E>
where
    F: Future<Output = Result<http::Response<tonic::body::Body>, E>>,
{
    let audited = matches!(principal, Principal::User(_) | Principal::Operator(_))
        && catalog::lookup(&path).is_some();
    if !audited {
        return with_request(path, origin, handler).await;
    }
    let request = RequestContext::new(path, origin);
    let pending = PendingMutation {
        request: request.clone(),
        principal: principal.clone(),
        recorded: false,
    };
    match REQUEST.scope(request, handler).await {
        Ok(response) => Ok(pending.follow(response)),
        Err(error) => {
            pending.record(Some(Code::Unknown));
            Err(error)
        }
    }
}

/// The record of a mutation, emitted once when the call ends, or as
/// unfinished when it is dropped first, such as when its client
/// disconnected. The change it started may still apply.
struct PendingMutation {
    request: RequestContext,
    principal: Principal,
    recorded: bool,
}

impl PendingMutation {
    /// Record the call now when `response` ends it, or when its body does.
    fn follow(
        self,
        response: http::Response<tonic::body::Body>,
    ) -> http::Response<tonic::body::Body> {
        if let Some(status) = Status::from_header_map(response.headers()) {
            self.record(Some(status.code()));
            return response;
        }
        if http_body::Body::is_end_stream(response.body()) {
            self.record(Some(Code::Ok));
            return response;
        }
        response.map(|body| {
            tonic::body::Body::new(AuditedBody {
                inner: body,
                pending: Some(self),
            })
        })
    }

    fn record(mut self, code: Option<Code>) {
        self.record_once(code);
    }

    fn record_once(&mut self, code: Option<Code>) {
        if !std::mem::replace(&mut self.recorded, true)
            && !self.request.denied.load(Ordering::Relaxed)
        {
            emit_mutation(&self.request, &self.principal, code);
        }
    }
}

impl Drop for PendingMutation {
    fn drop(&mut self) {
        self.record_once(None);
    }
}

/// A streamed response body that records its mutation when it ends.
struct AuditedBody {
    inner: tonic::body::Body,
    pending: Option<PendingMutation>,
}

impl AuditedBody {
    fn record(&mut self, code: Code) {
        if let Some(pending) = self.pending.take() {
            pending.record(Some(code));
        }
    }
}

impl http_body::Body for AuditedBody {
    type Data = bytes::Bytes;
    type Error = Status;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let polled = std::pin::Pin::new(&mut self.inner).poll_frame(cx);
        let code = match &polled {
            std::task::Poll::Ready(Some(Ok(frame))) => frame
                .trailers_ref()
                .and_then(Status::from_header_map)
                .map(|status| status.code()),
            std::task::Poll::Ready(Some(Err(status))) => Some(status.code()),
            std::task::Poll::Ready(None) => Some(Code::Ok),
            std::task::Poll::Pending => None,
        };
        if let Some(code) = code {
            self.record(code);
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for AuditedBody {
    fn drop(&mut self) {
        if http_body::Body::is_end_stream(&self.inner) {
            self.record(Code::Ok);
        }
    }
}

/// The path and origin of the request a handler is serving, or empty
/// values outside one.
fn current_request() -> (String, RequestOrigin) {
    REQUEST
        .try_with(|request| (request.path.clone(), request.origin.clone()))
        .unwrap_or_default()
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
    /// A sandbox requested a credential for an extension service its policy
    /// does not select.
    ExtensionServiceNotSelected { service: &'a str },
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
            Self::ExtensionServiceNotSelected { .. } => "extension_service_not_selected",
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
            Self::ExtensionServiceNotSelected { service } => Some(ResourceDetails::named(
                "extension_service",
                bounded(service),
            )),
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
        Principal::Supervisor(supervisor) => {
            User::other(&supervisor.identity.subject, "Supervisor")
        }
        Principal::Anonymous => User::unidentified(),
    }
}

/// Emit an authorization denial raised by a handler for the current request,
/// naming the targets the request recorded.
pub fn emit_authorization_denial(principal: &Principal, denial: AuthzDenial<'_>) {
    let (path, origin) = current_request();
    let targets = REQUEST
        .try_with(|request| {
            request.denied.store(true, Ordering::Relaxed);
            lock(&request.mutation).resources.clone()
        })
        .unwrap_or_default();
    emit_denial(&path, &origin, principal, denial, targets);
}

/// Emit an authorization denial raised by a handler for the current request,
/// returning the status that refuses it with `message`.
pub fn deny(principal: &Principal, denial: AuthzDenial<'_>, message: impl Into<String>) -> Status {
    emit_authorization_denial(principal, denial);
    Status::permission_denied(message)
}

/// Emit an API Activity denial for a gRPC request to `path`, paired with a
/// Detection Finding when a sandbox principal crossed its boundary.
pub fn emit_authorization_denial_for(
    path: &str,
    origin: &RequestOrigin,
    principal: &Principal,
    denial: AuthzDenial<'_>,
) {
    emit_denial(path, origin, principal, denial, Vec::new());
}

fn emit_denial(
    path: &str,
    origin: &RequestOrigin,
    principal: &Principal,
    denial: AuthzDenial<'_>,
    mut resources: Vec<ResourceDetails>,
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
    let mut builder = api_activity(&ctx, path, origin, principal)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Medium)
        .status(StatusId::Failure)
        .status_detail(category)
        .message(format!("authorization denied: {category}"));
    if let Some(resource) = denial.resource().filter(|r| !resources.contains(r)) {
        resources.push(resource);
    }
    for resource in resources {
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

/// An API Activity event for `principal`'s request to `path` from `origin`,
/// naming the activity of a cataloged method.
fn api_activity<'a>(
    ctx: &'a EventContext,
    path: &str,
    origin: &RequestOrigin,
    principal: &Principal,
) -> ApiActivityBuilder<'a> {
    let (service, operation) = path
        .strip_prefix('/')
        .and_then(|path| path.split_once('/'))
        .unwrap_or(("", "unknown"));
    let mut builder = ApiActivityBuilder::new(ctx, operation)
        .actor_user(principal_user(principal))
        .src_endpoint(origin.source.map_or_else(
            || Endpoint::from_name("unknown"),
            ConnectionSource::endpoint,
        ));
    if !service.is_empty() {
        builder = builder
            .api_service(Service::new(service))
            .http_request(post(path));
    }
    if let Some(activity) = catalog::lookup(path) {
        builder = builder.activity(activity);
    }
    builder
}

/// Emit the record of a mutation that ended with `code`, or that never
/// finished when `code` is `None`.
fn emit_mutation(request: &RequestContext, principal: &Principal, code: Option<Code>) {
    let RequestContext { path, origin, .. } = request;
    let mutation = std::mem::take(&mut *lock(&request.mutation));
    let ctx = crate::gateway_ocsf::context("", "");
    let mut builder = api_activity(&ctx, path, origin, principal);
    for resource in mutation.resources {
        builder = builder.resource(resource);
    }
    builder = match code.map(failure) {
        None => builder
            .severity(SeverityId::Medium)
            .status(StatusId::Unknown)
            .message("mutation did not finish")
            .status_detail("unknown:cancelled"),
        Some(None) => {
            builder = builder
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .message("mutation succeeded");
            match mutation.outcome {
                Some(outcome) => builder.status_detail(outcome),
                None => builder,
            }
        }
        Some(Some(failure)) => builder
            .severity(if failure.starts_with("rejected:") {
                SeverityId::Low
            } else {
                SeverityId::Medium
            })
            .status(StatusId::Failure)
            .message(format!("mutation failed: {failure}"))
            .status_detail(failure),
    };
    if let Some(request_id) = &origin.request_id {
        builder = builder.correlation_uid(request_id);
    }
    ocsf_emit!(builder.build());
}

/// The failure category for a gRPC `code`: `rejected:` when the gateway
/// refused the request, `error:` when it could not complete it.
fn failure(code: Code) -> Option<String> {
    let (kind, name) = match code {
        Code::Ok => return None,
        Code::InvalidArgument => ("rejected", "invalid_argument"),
        Code::NotFound => ("rejected", "not_found"),
        Code::AlreadyExists => ("rejected", "already_exists"),
        Code::PermissionDenied => ("rejected", "permission_denied"),
        Code::FailedPrecondition => ("rejected", "failed_precondition"),
        Code::Aborted => ("rejected", "aborted"),
        Code::OutOfRange => ("rejected", "out_of_range"),
        Code::Unauthenticated => ("rejected", "unauthenticated"),
        Code::ResourceExhausted => ("rejected", "resource_exhausted"),
        Code::Cancelled => ("error", "cancelled"),
        Code::Unknown => ("error", "unknown"),
        Code::DeadlineExceeded => ("error", "deadline_exceeded"),
        Code::Unimplemented => ("error", "unimplemented"),
        Code::Internal => ("error", "internal"),
        Code::Unavailable => ("error", "unavailable"),
        Code::DataLoss => ("error", "data_loss"),
    };
    Some(format!("{kind}:{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_logs_on_again_after_the_window() {
        let logons = Logons::default();
        let start = Instant::now();

        assert!(logons.log_on([1; 32], start));
        assert!(!logons.log_on([1; 32], start + Duration::from_mins(59)));
        assert!(logons.log_on([1; 32], start + LOGON_WINDOW));
    }

    #[test]
    fn oldest_credential_is_forgotten_when_full() {
        let logons = Logons::default();
        let now = Instant::now();
        let credential = |n: usize| {
            let mut digest = [0; 32];
            digest[..8].copy_from_slice(&n.to_le_bytes());
            digest
        };
        for n in 0..MAX_LOGONS {
            assert!(logons.log_on(credential(n), now));
        }
        // Polling every credential in turn while full is not a new logon.
        for n in 0..MAX_LOGONS {
            assert!(!logons.log_on(credential(n), now), "credential {n}");
        }

        assert!(logons.log_on(credential(MAX_LOGONS), now));
        assert!(logons.log_on(credential(0), now), "oldest was evicted");
        assert!(
            !logons.log_on(credential(MAX_LOGONS), now),
            "newest was kept"
        );
    }
}
