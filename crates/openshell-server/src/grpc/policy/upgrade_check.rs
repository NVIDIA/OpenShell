// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway upgrade check over registered middleware and stored policies.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;

use openshell_core::proto::{
    CheckGatewayUpgradeRequest, CheckGatewayUpgradeResponse, GatewayUpgradeFinding,
    GatewayUpgradeFindingKind, GatewayUpgradeFindingScope, GatewayUpgradeFindingSeverity, Sandbox,
    SandboxPolicy as ProtoSandboxPolicy,
};
use openshell_ocsf::{ConfigStateChangeBuilder, OcsfEvent, SeverityId, StateId, StatusId};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::ServerState;
use crate::middleware_audit::{
    Finding, FindingKind, MiddlewareCatalog, Severity, UpgradeTarget, check_policy,
    driver_keeps_supervisors,
};
use crate::persistence::{ObjectId, ObjectListQuery, ObjectName, ObjectWorkspace};
use crate::provider_profile_sources::EffectiveProviderProfileCatalog;

/// Findings listed in one response. The counts always cover every finding.
const MAX_LISTED_FINDINGS: usize = 1000;
const SANDBOX_PAGE_SIZE: u32 = 1000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Subject {
    MiddlewareService,
    GlobalPolicy,
    Sandbox { workspace: String, name: String },
}

#[derive(Debug, Default)]
struct UpgradeCheck {
    findings: Vec<(Subject, Finding)>,
    checked_sandboxes: u32,
    global_policy_active: bool,
}

impl UpgradeCheck {
    fn extend(&mut self, subject: &Subject, findings: impl IntoIterator<Item = Finding>) {
        self.findings.extend(
            findings
                .into_iter()
                .map(|finding| (subject.clone(), finding)),
        );
    }

    fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|(_, finding)| finding.severity == severity)
            .count()
    }

    fn into_response(mut self, target: UpgradeTarget) -> CheckGatewayUpgradeResponse {
        let blocking_count = saturating_u32(self.count(Severity::Blocking));
        let warning_count = saturating_u32(self.count(Severity::Warning));
        self.findings
            .sort_by(|(left_subject, left), (right_subject, right)| {
                listing_order(left_subject, left).cmp(&listing_order(right_subject, right))
            });
        self.findings.truncate(MAX_LISTED_FINDINGS);
        CheckGatewayUpgradeResponse {
            target_version: target.as_str().to_string(),
            gateway_version: openshell_core::VERSION.to_string(),
            findings: self
                .findings
                .into_iter()
                .map(|(subject, finding)| proto_finding(subject, finding))
                .collect(),
            blocking_count,
            warning_count,
            checked_sandbox_count: self.checked_sandboxes,
            global_policy_active: self.global_policy_active,
        }
    }
}

/// Blocking first, then by subject. A subject's entry findings precede the
/// findings about the subject as a whole.
fn listing_order<'a>(
    subject: &'a Subject,
    finding: &'a Finding,
) -> (Reverse<Severity>, &'a Subject, bool, &'a str, FindingKind) {
    (
        Reverse(finding.severity),
        subject,
        finding.config_name.is_empty(),
        &finding.config_name,
        finding.kind,
    )
}

fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn proto_finding(subject: Subject, finding: Finding) -> GatewayUpgradeFinding {
    let (scope, workspace, sandbox) = match subject {
        Subject::MiddlewareService => (
            GatewayUpgradeFindingScope::MiddlewareService,
            String::new(),
            String::new(),
        ),
        Subject::GlobalPolicy => (
            GatewayUpgradeFindingScope::GlobalPolicy,
            String::new(),
            String::new(),
        ),
        Subject::Sandbox { workspace, name } => {
            (GatewayUpgradeFindingScope::Sandbox, workspace, name)
        }
    };
    GatewayUpgradeFinding {
        kind: proto_kind(finding.kind).into(),
        severity: match finding.severity {
            Severity::Warning => GatewayUpgradeFindingSeverity::Warning,
            Severity::Blocking => GatewayUpgradeFindingSeverity::Blocking,
        }
        .into(),
        scope: scope.into(),
        workspace,
        sandbox,
        config_name: finding.config_name,
        middleware_name: finding.middleware_name,
        message: finding.message,
    }
}

fn proto_kind(kind: FindingKind) -> GatewayUpgradeFindingKind {
    match kind {
        FindingKind::LegacyHttpService => GatewayUpgradeFindingKind::LegacyHttpService,
        FindingKind::UnregisteredMiddleware => GatewayUpgradeFindingKind::UnregisteredMiddleware,
        FindingKind::LegacyHttpMiddleware => GatewayUpgradeFindingKind::LegacyHttpMiddleware,
        FindingKind::FailOpenNotApplied => GatewayUpgradeFindingKind::FailOpenNotApplied,
        FindingKind::HttpFailOpen => GatewayUpgradeFindingKind::HttpFailOpen,
        FindingKind::OnUninspectableFallback => GatewayUpgradeFindingKind::OnUninspectableFallback,
        FindingKind::OnUninspectableNeedsCurrentSupervisor => {
            GatewayUpgradeFindingKind::OnUninspectableNeedsCurrentSupervisor
        }
        FindingKind::SandboxKeepsSupervisor => GatewayUpgradeFindingKind::SandboxKeepsSupervisor,
        FindingKind::PolicyUnchecked => GatewayUpgradeFindingKind::PolicyUnchecked,
        FindingKind::FailOpenOnHttpV2Only => GatewayUpgradeFindingKind::FailOpenOnHttpV2Only,
    }
}

pub(in crate::grpc) async fn handle_check_gateway_upgrade(
    state: &Arc<ServerState>,
    request: Request<CheckGatewayUpgradeRequest>,
) -> Result<Response<CheckGatewayUpgradeResponse>, Status> {
    let target = UpgradeTarget::parse(&request.get_ref().target_version)
        .map_err(Status::invalid_argument)?;
    let check = check_gateway_upgrade(state).await?;
    Ok(Response::new(check.into_response(target)))
}

/// Check registered middleware, the global policy, and every sandbox's
/// effective policy. Reads only; a stored policy that cannot be resolved
/// becomes a finding instead of failing the check.
async fn check_gateway_upgrade(state: &ServerState) -> Result<UpgradeCheck, Status> {
    let catalog = MiddlewareCatalog::from_registry(&state.middleware_registry).await?;
    let mut check = UpgradeCheck::default();
    check.extend(&Subject::MiddlewareService, catalog.service_findings());

    let driver = state.compute.configured_driver_name();
    let keeps_supervisors = driver_keeps_supervisors(driver);
    // Only drivers that keep supervisors across gateway upgrades can still
    // run supervisors that predate `on_uninspectable`.
    let check_policy = |policy: &ProtoSandboxPolicy| {
        check_policy(policy, &catalog)
            .into_iter()
            .filter(|finding| {
                keeps_supervisors
                    || finding.kind != FindingKind::OnUninspectableNeedsCurrentSupervisor
            })
    };

    let global_settings = super::load_global_settings(state.store.as_ref()).await?;
    let global_policy = super::decode_policy_from_global_settings(&global_settings).transpose();
    check.global_policy_active = global_policy.is_some();
    let global_uses_middleware = match &global_policy {
        Some(Ok(policy)) => {
            check.extend(&Subject::GlobalPolicy, check_policy(policy));
            !policy.network_middlewares.is_empty()
        }
        Some(Err(error)) => {
            check.extend(&Subject::GlobalPolicy, [Finding::policy_unchecked(error)]);
            false
        }
        None => false,
    };

    let mut provider_catalogs = HashMap::new();
    let mut cursor = None;
    loop {
        let page = state
            .store
            .list_message_page::<Sandbox>(
                ObjectListQuery::AllWorkspaces,
                cursor.as_ref(),
                SANDBOX_PAGE_SIZE,
            )
            .await
            .map_err(|error| Status::internal(format!("list sandboxes failed: {error}")))?;
        for sandbox in page.messages {
            check.checked_sandboxes = check.checked_sandboxes.saturating_add(1);
            let subject = Subject::Sandbox {
                workspace: sandbox.object_workspace().to_string(),
                name: sandbox.object_name().to_string(),
            };
            let uses_middleware = if global_policy.is_some() {
                global_uses_middleware
            } else {
                match effective_sandbox_policy(state, &sandbox, &mut provider_catalogs).await {
                    Ok(policy) => {
                        check.extend(&subject, check_policy(&policy));
                        !policy.network_middlewares.is_empty()
                    }
                    Err(error) => {
                        check.extend(&subject, [Finding::policy_unchecked(&error)]);
                        false
                    }
                }
            };
            if uses_middleware && keeps_supervisors {
                check.extend(&subject, [Finding::sandbox_keeps_supervisor(driver)]);
            }
        }
        let Some(next_cursor) = page.next_cursor else {
            return Ok(check);
        };
        cursor = Some(next_cursor);
    }
}

/// Log the upgrade check once at startup. Startup never waits for the check
/// or depends on its outcome.
pub async fn log_gateway_upgrade_check(state: Arc<ServerState>) {
    let check = match check_gateway_upgrade(&state).await {
        Ok(check) => check,
        Err(error) => {
            warn!(error = %error.message(), "Gateway upgrade check failed at startup");
            return;
        }
    };
    for (subject, finding) in &check.findings {
        if *subject == Subject::MiddlewareService {
            warn!(middleware = %finding.middleware_name, "{}", finding.message);
            openshell_ocsf::ocsf_emit!(legacy_service_event(finding));
        }
    }
    let upgrade_target = UpgradeTarget::NEXT.as_str();
    let blocking = check.count(Severity::Blocking);
    let warnings = check.count(Severity::Warning);
    if blocking > 0 {
        warn!(
            upgrade_target,
            blocking,
            warnings,
            "Registered middleware or stored policies are not ready for OpenShell \
             {upgrade_target}; run `openshell gateway upgrade-check` for details"
        );
    } else if warnings > 0 {
        info!(
            upgrade_target,
            warnings,
            "OpenShell {upgrade_target} changes how stored middleware policies behave; run \
             `openshell gateway upgrade-check` for details"
        );
    }
}

fn legacy_service_event(finding: &Finding) -> OcsfEvent {
    let ctx = crate::gateway_ocsf::context("", "");
    ConfigStateChangeBuilder::new(&ctx)
        .state(StateId::Enabled, "deprecated")
        .severity(SeverityId::Medium)
        .status(StatusId::Success)
        .unmapped("middleware", finding.middleware_name.clone())
        .message(finding.message.clone())
        .build()
}

/// The effective policy `GetSandboxConfig` would serve, without the lazy
/// policy-history backfill that serving it performs.
async fn effective_sandbox_policy(
    state: &ServerState,
    sandbox: &Sandbox,
    provider_catalogs: &mut HashMap<String, Result<EffectiveProviderProfileCatalog, Status>>,
) -> Result<ProtoSandboxPolicy, Status> {
    let has_providers = sandbox
        .spec
        .as_ref()
        .is_some_and(|spec| !spec.providers.is_empty());
    if !has_providers {
        return super::current_base_policy_for_sandbox(state.store.as_ref(), sandbox).await;
    }
    let workspace = sandbox.object_workspace();
    if !provider_catalogs.contains_key(workspace) {
        let catalog = state
            .provider_profile_sources
            .snapshot_catalog(state.store.as_ref(), workspace)
            .await;
        provider_catalogs.insert(workspace.to_string(), catalog);
    }
    let catalog = provider_catalogs[workspace]
        .as_ref()
        .map_err(Clone::clone)?;
    super::current_effective_policy_for_sandbox(
        state,
        catalog,
        workspace,
        sandbox,
        sandbox.object_id(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::test_support::{authed_request, test_server_state};
    use crate::middleware_audit::RevalidationMode;
    use crate::policy_store::PolicyStoreExt as _;
    use openshell_core::extension_protocol::{
        ExtensionFamily, SUPERVISOR_MIDDLEWARE_HTTP_V2, extension_metadata,
        extension_metadata_with_requirements, peer_supports,
    };
    use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
        SupervisorMiddleware, SupervisorMiddlewareServer,
    };
    use openshell_core::proto::{
        GetSandboxConfigRequest, GetSandboxConfigResponse, HttpBodyMode, HttpRequestEvaluation,
        HttpRequestResult, MiddlewareBinding, MiddlewareDescribeRequest,
        MiddlewareEndpointSelector, MiddlewareManifest, NetworkEndpoint, NetworkMiddlewareConfig,
        NetworkPolicyRule, NetworkTlsMode, SupervisorMiddlewareOperation,
        SupervisorMiddlewarePhase, SupervisorMiddlewareService, UpdateConfigRequest,
        ValidateConfigRequest, ValidateConfigResponse, WebSocketSessionEvent,
        WebSocketSessionEventResult,
    };
    use openshell_supervisor_middleware::{HttpProtocol, MiddlewareRegistry};
    use prost::Message as _;
    use std::net::SocketAddr;
    use tokio_stream::wrappers::TcpListenerStream;

    const MAX_PAYLOAD_BYTES: u64 = 64 * 1024;

    /// External middleware that only describes itself.
    #[derive(Clone)]
    struct DescribedService {
        http_protocol_version: u32,
        websocket: bool,
        /// Serve version 2 HTTP bindings to callers that advertise `http-v2`
        /// and legacy bindings otherwise.
        dual: bool,
        /// Require `http-v2` from callers, as a version 2-only build does.
        required: bool,
    }

    type WebSocketResults = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<WebSocketSessionEventResult, Status>> + Send>,
    >;

    #[tonic::async_trait]
    impl SupervisorMiddleware for DescribedService {
        type EvaluateWebSocketSessionStream = WebSocketResults;

        async fn describe(
            &self,
            request: Request<MiddlewareDescribeRequest>,
        ) -> Result<Response<MiddlewareManifest>, Status> {
            let caller_supports_http_v2 = request
                .into_inner()
                .gateway
                .is_some_and(|gateway| peer_supports(&gateway, SUPERVISOR_MIDDLEWARE_HTTP_V2));
            let http_protocol_version = if self.dual {
                if caller_supports_http_v2 { 2 } else { 0 }
            } else {
                self.http_protocol_version
            };
            let mut bindings = vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: MAX_PAYLOAD_BYTES,
                http_protocol_version,
                supported_http_body_modes: if http_protocol_version == 2 {
                    vec![HttpBodyMode::Buffered as i32]
                } else {
                    Vec::new()
                },
                ..Default::default()
            }];
            if self.websocket {
                bindings.push(MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::WebsocketMessage as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: MAX_PAYLOAD_BYTES,
                    ..Default::default()
                });
            }
            Ok(Response::new(MiddlewareManifest {
                name: "example/test-service".to_string(),
                bindings,
                extension: Some(if self.required {
                    extension_metadata_with_requirements(
                        ExtensionFamily::SupervisorMiddleware,
                        "example/test-service",
                        "test",
                        [],
                        [SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string()],
                    )
                } else {
                    extension_metadata(
                        ExtensionFamily::SupervisorMiddleware,
                        "example/test-service",
                        "test",
                        self.dual.then(|| SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string()),
                    )
                }),
                ..Default::default()
            }))
        }

        async fn validate_config(
            &self,
            _request: Request<ValidateConfigRequest>,
        ) -> Result<Response<ValidateConfigResponse>, Status> {
            Ok(Response::new(ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            }))
        }

        async fn evaluate_http_request(
            &self,
            _request: Request<HttpRequestEvaluation>,
        ) -> Result<Response<HttpRequestResult>, Status> {
            Err(Status::unimplemented("describe-only test middleware"))
        }

        async fn evaluate_web_socket_session(
            &self,
            _request: Request<tonic::Streaming<WebSocketSessionEvent>>,
        ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
            Err(Status::unimplemented("describe-only test middleware"))
        }
    }

    async fn serve(service: DescribedService) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test middleware");
        let address = listener.local_addr().expect("test middleware address");
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(SupervisorMiddlewareServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        address
    }

    async fn registration(name: &str, service: DescribedService) -> SupervisorMiddlewareService {
        let address = serve(service).await;
        SupervisorMiddlewareService {
            name: name.to_string(),
            grpc_endpoint: format!("http://{address}"),
            max_payload_bytes: MAX_PAYLOAD_BYTES,
            ..Default::default()
        }
    }

    /// Built-ins plus `example/legacy` (legacy HTTP), `example/v2` (version 2
    /// HTTP), `example/v2-ws` (version 2 HTTP and WebSocket), and
    /// `example/v2-only-ws` (version 2 HTTP and WebSocket, requiring
    /// `http-v2`), described the way the gateway describes them at startup.
    async fn upgrade_registry() -> MiddlewareRegistry {
        let mut registrations = Vec::new();
        for (name, http_protocol_version, websocket, required) in [
            ("example/legacy", 0, false, false),
            ("example/v2", 2, false, false),
            ("example/v2-ws", 2, true, false),
            ("example/v2-only-ws", 2, true, true),
        ] {
            let service = DescribedService {
                http_protocol_version,
                websocket,
                dual: false,
                required,
            };
            registrations.push(registration(name, service).await);
        }
        MiddlewareRegistry::connect_services(
            openshell_supervisor_middleware_builtins::services(),
            registrations,
        )
        .await
        .expect("upgrade check registry")
    }

    async fn upgrade_state() -> Arc<ServerState> {
        let mut state = test_server_state().await;
        Arc::get_mut(&mut state)
            .expect("test state is uniquely owned")
            .middleware_registry = Arc::new(upgrade_registry().await);
        state
    }

    /// A policy with one middleware entry selecting `*.example.com`, and a
    /// `tls: skip` endpoint for `api.example.com` when `tls_skip` is set.
    fn middleware_policy(
        middleware: &str,
        on_error: &str,
        on_uninspectable: &str,
        tls_skip: bool,
    ) -> ProtoSandboxPolicy {
        let mut policy = openshell_policy::restrictive_default_policy();
        policy.network_middlewares.insert(
            "guard".to_string(),
            NetworkMiddlewareConfig {
                middleware: middleware.to_string(),
                on_error: on_error.to_string(),
                on_uninspectable: on_uninspectable.to_string(),
                endpoints: Some(MiddlewareEndpointSelector {
                    include: vec!["*.example.com".to_string()],
                    exclude: Vec::new(),
                }),
                ..Default::default()
            },
        );
        if tls_skip {
            policy.network_policies.insert(
                "skip".to_string(),
                NetworkPolicyRule {
                    name: "skip".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "api.example.com".to_string(),
                        port: 443,
                        tls: NetworkTlsMode::Skip as i32,
                        ..Default::default()
                    }],
                    binaries: Vec::new(),
                },
            );
        }
        policy
    }

    async fn store_sandbox(state: &ServerState, name: &str, policy: ProtoSandboxPolicy) {
        state
            .store
            .put_message(&crate::grpc::policy::tests::test_sandbox(
                &format!("sb-{name}"),
                name,
                policy,
                Vec::new(),
            ))
            .await
            .expect("store sandbox");
    }

    async fn check(state: &Arc<ServerState>, target_version: &str) -> CheckGatewayUpgradeResponse {
        handle_check_gateway_upgrade(
            state,
            Request::new(CheckGatewayUpgradeRequest {
                target_version: target_version.to_string(),
            }),
        )
        .await
        .expect("upgrade check")
        .into_inner()
    }

    type Row = (
        GatewayUpgradeFindingSeverity,
        GatewayUpgradeFindingScope,
        String,
        GatewayUpgradeFindingKind,
    );

    fn rows(response: &CheckGatewayUpgradeResponse) -> Vec<Row> {
        response
            .findings
            .iter()
            .map(|finding| {
                (
                    finding.severity(),
                    finding.scope(),
                    finding.sandbox.clone(),
                    finding.kind(),
                )
            })
            .collect()
    }

    fn row(
        severity: GatewayUpgradeFindingSeverity,
        scope: GatewayUpgradeFindingScope,
        sandbox: &str,
        kind: GatewayUpgradeFindingKind,
    ) -> Row {
        (severity, scope, sandbox.to_string(), kind)
    }

    #[tokio::test]
    async fn upgrade_check_reports_every_finding_category_without_side_effects() {
        use GatewayUpgradeFindingKind as Kind;
        use GatewayUpgradeFindingScope::{MiddlewareService, Sandbox as SandboxScope};
        use GatewayUpgradeFindingSeverity::{Blocking, Warning};

        let state = upgrade_state().await;
        store_sandbox(
            &state,
            "clean",
            middleware_policy("example/v2", "fail_closed", "", false),
        )
        .await;
        store_sandbox(
            &state,
            "stale",
            middleware_policy("example/v2", "fail_open", "deny", false),
        )
        .await;
        store_sandbox(
            &state,
            "legacy",
            middleware_policy("example/legacy", "fail_open", "", false),
        )
        .await;
        store_sandbox(
            &state,
            "fallback",
            middleware_policy("example/v2-ws", "fail_open", "", true),
        )
        .await;
        store_sandbox(
            &state,
            "allow",
            middleware_policy("example/v2", "", "allow", true),
        )
        .await;
        store_sandbox(
            &state,
            "gone",
            middleware_policy("example/gone", "", "", false),
        )
        .await;
        store_sandbox(
            &state,
            "builtin",
            middleware_policy(
                openshell_supervisor_middleware_builtins::BUILTIN_REGEX,
                "fail_open",
                "deny",
                false,
            ),
        )
        .await;
        store_sandbox(
            &state,
            "invalid",
            middleware_policy("example/v2", "", "sometimes", false),
        )
        .await;
        store_sandbox(
            &state,
            "plain",
            openshell_policy::restrictive_default_policy(),
        )
        .await;
        store_sandbox(
            &state,
            "v2-only",
            middleware_policy("example/v2-only-ws", "fail_open", "allow", false),
        )
        .await;

        let response = check(&state, "0.2").await;

        assert_eq!(response.target_version, "0.2");
        assert_eq!(response.gateway_version, openshell_core::VERSION);
        assert_eq!(response.checked_sandbox_count, 10);
        assert!(!response.global_policy_active);
        let keeps = |sandbox| row(Warning, SandboxScope, sandbox, Kind::SandboxKeepsSupervisor);
        assert_eq!(
            rows(&response),
            [
                row(Blocking, MiddlewareService, "", Kind::LegacyHttpService),
                row(
                    Blocking,
                    SandboxScope,
                    "fallback",
                    Kind::OnUninspectableFallback
                ),
                row(Blocking, SandboxScope, "gone", Kind::UnregisteredMiddleware),
                row(Blocking, SandboxScope, "legacy", Kind::LegacyHttpMiddleware),
                row(Blocking, SandboxScope, "legacy", Kind::HttpFailOpen),
                row(Blocking, SandboxScope, "stale", Kind::FailOpenNotApplied),
                row(
                    Blocking,
                    SandboxScope,
                    "v2-only",
                    Kind::FailOpenOnHttpV2Only
                ),
                row(
                    Warning,
                    SandboxScope,
                    "allow",
                    Kind::OnUninspectableNeedsCurrentSupervisor
                ),
                keeps("allow"),
                row(Warning, SandboxScope, "builtin", Kind::HttpFailOpen),
                keeps("builtin"),
                keeps("clean"),
                keeps("fallback"),
                keeps("gone"),
                row(Warning, SandboxScope, "invalid", Kind::PolicyUnchecked),
                row(
                    Warning,
                    SandboxScope,
                    "legacy",
                    Kind::OnUninspectableFallback
                ),
                keeps("legacy"),
                keeps("stale"),
                keeps("v2-only"),
            ]
        );
        assert_eq!(response.blocking_count, 7);
        assert_eq!(response.warning_count, 12);

        let service = &response.findings[0];
        assert_eq!(service.middleware_name, "example/legacy");
        assert!(service.workspace.is_empty() && service.sandbox.is_empty());
        let stale_finding = response
            .findings
            .iter()
            .find(|finding| finding.kind() == Kind::FailOpenNotApplied)
            .expect("stale fail_open finding");
        assert_eq!(
            (
                stale_finding.workspace.as_str(),
                stale_finding.config_name.as_str(),
                stale_finding.middleware_name.as_str(),
            ),
            ("default", "guard", "example/v2")
        );
        assert!(
            stale_finding
                .message
                .contains("remove on_error or set it to fail_closed")
        );

        for name in ["clean", "stale", "legacy"] {
            assert!(
                state
                    .store
                    .get_latest_policy(&format!("sb-{name}"))
                    .await
                    .expect("policy history lookup")
                    .is_none(),
                "the check must not backfill policy history for {name}"
            );
        }
    }

    #[tokio::test]
    async fn upgrade_check_covers_an_active_global_policy_instead_of_sandbox_policies() {
        use GatewayUpgradeFindingKind as Kind;
        use GatewayUpgradeFindingScope::{
            GlobalPolicy, MiddlewareService, Sandbox as SandboxScope,
        };
        use GatewayUpgradeFindingSeverity::{Blocking, Warning};

        let state = upgrade_state().await;
        store_sandbox(
            &state,
            "dormant",
            middleware_policy("example/v2", "fail_open", "deny", false),
        )
        .await;
        let mut settings = super::super::load_global_settings(state.store.as_ref())
            .await
            .expect("global settings");
        settings.settings.insert(
            super::super::POLICY_SETTING_KEY.to_string(),
            super::super::StoredSettingValue::Bytes(hex::encode(
                middleware_policy("example/gone", "", "", false).encode_to_vec(),
            )),
        );
        super::super::save_global_settings(state.store.as_ref(), &settings)
            .await
            .expect("store global policy");

        let response = check(&state, "").await;

        assert!(response.global_policy_active);
        assert_eq!(response.checked_sandbox_count, 1);
        assert_eq!(
            rows(&response),
            [
                row(Blocking, MiddlewareService, "", Kind::LegacyHttpService),
                row(Blocking, GlobalPolicy, "", Kind::UnregisteredMiddleware),
                row(
                    Warning,
                    SandboxScope,
                    "dormant",
                    Kind::SandboxKeepsSupervisor
                ),
            ]
        );
    }

    #[tokio::test]
    async fn upgrade_check_rejects_unsupported_targets() {
        let state = upgrade_state().await;
        let error = handle_check_gateway_upgrade(
            &state,
            Request::new(CheckGatewayUpgradeRequest {
                target_version: "0.3".to_string(),
            }),
        )
        .await
        .expect_err("0.3 rules are unknown");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("this gateway can check 0.2"));
    }

    /// The gateway advertises `http-v2` when it describes registered services
    /// at startup, so a service that serves both protocols describes version 2
    /// HTTP bindings to it. Only services that serve legacy HTTP to this
    /// gateway, and the entries that use them, block the upgrade.
    #[tokio::test]
    async fn upgrade_check_reports_legacy_only_services_but_not_dual_protocol_ones() {
        use GatewayUpgradeFindingKind as Kind;
        use GatewayUpgradeFindingScope::{MiddlewareService, Sandbox as SandboxScope};
        use GatewayUpgradeFindingSeverity::Blocking;

        let registry = MiddlewareRegistry::connect_services(
            Vec::new(),
            vec![
                registration(
                    "example/legacy",
                    DescribedService {
                        http_protocol_version: 0,
                        websocket: false,
                        dual: false,
                        required: false,
                    },
                )
                .await,
                registration(
                    "example/dual",
                    DescribedService {
                        http_protocol_version: 0,
                        websocket: false,
                        dual: true,
                        required: false,
                    },
                )
                .await,
            ],
        )
        .await
        .expect("registry");
        let summaries = registry.binding_summaries().await.expect("summaries");
        let protocols = |name: &str| {
            summaries
                .iter()
                .find(|summary| summary.name == name)
                .map(|summary| summary.http_protocols.clone())
        };
        assert_eq!(protocols("example/dual"), Some(vec![HttpProtocol::V2]));
        assert_eq!(
            protocols("example/legacy"),
            Some(vec![HttpProtocol::Legacy])
        );

        let mut state = crate::grpc::test_support::test_server_state_with_driver("docker").await;
        Arc::get_mut(&mut state)
            .expect("test state is uniquely owned")
            .middleware_registry = Arc::new(registry);
        for (name, middleware) in [("legacy", "example/legacy"), ("dual", "example/dual")] {
            store_sandbox(
                &state,
                name,
                middleware_policy(middleware, "fail_closed", "", false),
            )
            .await;
        }

        let response = check(&state, "0.2").await;

        assert_eq!(
            rows(&response),
            [
                row(Blocking, MiddlewareService, "", Kind::LegacyHttpService),
                row(Blocking, SandboxScope, "legacy", Kind::LegacyHttpMiddleware),
            ]
        );
        assert_eq!(response.findings[0].middleware_name, "example/legacy");
        assert_eq!(response.findings[1].middleware_name, "example/legacy");
        assert_eq!((response.blocking_count, response.warning_count), (2, 0));
    }

    #[tokio::test]
    async fn upgrade_check_skips_supervisor_advice_where_the_gateway_refreshes_supervisors() {
        let mut state = crate::grpc::test_support::test_server_state_with_driver("docker").await;
        Arc::get_mut(&mut state)
            .expect("test state is uniquely owned")
            .middleware_registry = Arc::new(upgrade_registry().await);
        store_sandbox(
            &state,
            "allow",
            middleware_policy("example/v2", "", "allow", true),
        )
        .await;

        let response = check(&state, "0.2").await;

        assert_eq!(
            rows(&response),
            [row(
                GatewayUpgradeFindingSeverity::Blocking,
                GatewayUpgradeFindingScope::MiddlewareService,
                "",
                GatewayUpgradeFindingKind::LegacyHttpService
            )]
        );
    }

    #[tokio::test]
    async fn upgrade_check_includes_provider_policy_layers() {
        use GatewayUpgradeFindingKind as Kind;
        use GatewayUpgradeFindingScope::Sandbox as SandboxScope;
        use GatewayUpgradeFindingSeverity::{Blocking, Warning};

        let state = upgrade_state().await;
        state
            .store
            .put_message(&crate::storage_proto::StoredProviderProfile {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "profile-tls-skip".to_string(),
                    name: "tls-skip".to_string(),
                    workspace: "default".to_string(),
                    ..Default::default()
                }),
                profile: Some(openshell_core::proto::ProviderProfile {
                    id: "tls-skip".to_string(),
                    display_name: "TLS skip".to_string(),
                    category: openshell_core::proto::ProviderProfileCategory::Other as i32,
                    endpoints: vec![NetworkEndpoint {
                        host: "api.example.com".to_string(),
                        port: 443,
                        tls: NetworkTlsMode::Skip as i32,
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            })
            .await
            .expect("store provider profile");
        state
            .store
            .put_message(&crate::grpc::policy::tests::test_provider(
                "work-tls-skip",
                "tls-skip",
            ))
            .await
            .expect("store provider");
        state
            .store
            .put_message(&crate::grpc::policy::tests::test_sandbox(
                "sb-provider",
                "provider",
                middleware_policy("example/v2-ws", "fail_open", "", false),
                vec!["work-tls-skip".to_string()],
            ))
            .await
            .expect("store sandbox");

        let response = check(&state, "0.2").await;

        assert_eq!(
            rows(&response)[1..],
            [
                row(
                    Blocking,
                    SandboxScope,
                    "provider",
                    Kind::OnUninspectableFallback
                ),
                row(
                    Warning,
                    SandboxScope,
                    "provider",
                    Kind::SandboxKeepsSupervisor
                ),
            ],
            "the provider's tls: skip endpoint makes the fallback blocking"
        );
    }

    #[tokio::test]
    async fn upgrade_check_reports_an_invalid_global_policy() {
        let state = upgrade_state().await;
        let mut settings = super::super::load_global_settings(state.store.as_ref())
            .await
            .expect("global settings");
        settings.settings.insert(
            super::super::POLICY_SETTING_KEY.to_string(),
            super::super::StoredSettingValue::Bytes(hex::encode(
                middleware_policy("example/v2", "", "sometimes", false).encode_to_vec(),
            )),
        );
        super::super::save_global_settings(state.store.as_ref(), &settings)
            .await
            .expect("store global policy");

        let response = check(&state, "").await;

        assert!(response.global_policy_active);
        let global = response
            .findings
            .iter()
            .find(|finding| finding.scope() == GatewayUpgradeFindingScope::GlobalPolicy)
            .expect("global policy finding");
        assert_eq!(global.kind(), GatewayUpgradeFindingKind::PolicyUnchecked);
        assert_eq!(global.severity(), GatewayUpgradeFindingSeverity::Warning);
    }

    #[test]
    fn listed_findings_are_bounded_but_counts_are_complete() {
        let finding = Finding::sandbox_keeps_supervisor("kubernetes");
        let mut check = UpgradeCheck::default();
        for index in 0..MAX_LISTED_FINDINGS + 5 {
            check.extend(
                &Subject::Sandbox {
                    workspace: "default".to_string(),
                    name: format!("sandbox-{index:04}"),
                },
                [finding.clone()],
            );
        }
        let response = check.into_response(UpgradeTarget::V0_2);
        assert_eq!(response.findings.len(), MAX_LISTED_FINDINGS);
        assert_eq!(response.warning_count, 1005);
        assert_eq!(response.findings[0].sandbox, "sandbox-0000");
    }

    /// A state that enforces 0.2 admission, with `fail_closed`, `stale`, and
    /// `gone` sandboxes and `retain_last_valid` failure handling.
    async fn admission_state() -> Arc<ServerState> {
        let mut state = upgrade_state().await;
        let inner = Arc::get_mut(&mut state).expect("test state is uniquely owned");
        inner.middleware_revalidation = RevalidationMode::Admission;
        inner.config.policy_validation_failure_mode =
            openshell_core::PolicyValidationFailureMode::RetainLastValid;
        store_sandbox(
            &state,
            "clean",
            middleware_policy("example/v2", "fail_closed", "", false),
        )
        .await;
        store_sandbox(
            &state,
            "stale",
            middleware_policy("example/v2", "fail_open", "deny", false),
        )
        .await;
        store_sandbox(
            &state,
            "gone",
            middleware_policy("example/gone", "", "", false),
        )
        .await;
        state
    }

    async fn sandbox_config(state: &Arc<ServerState>, name: &str) -> GetSandboxConfigResponse {
        super::super::handle_get_sandbox_config(
            state,
            crate::grpc::policy::tests::with_sandbox(
                Request::new(GetSandboxConfigRequest {
                    name: name.to_string(),
                    workspace_scope: None,
                }),
                &format!("sb-{name}"),
            ),
        )
        .await
        .expect("sandbox config")
        .into_inner()
    }

    async fn user_sandbox_config(
        state: &Arc<ServerState>,
        name: &str,
    ) -> Result<GetSandboxConfigResponse, Status> {
        super::super::handle_get_sandbox_config(
            state,
            authed_request(GetSandboxConfigRequest {
                name: name.to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
            }),
        )
        .await
        .map(Response::into_inner)
    }

    #[tokio::test]
    async fn admission_refuses_only_sandboxes_whose_policy_0_2_rejects() {
        let state = admission_state().await;

        let clean = sandbox_config(&state, "clean").await;
        assert!(
            clean.configuration_admitted,
            "{}",
            clean.configuration_error
        );

        let stale_config = sandbox_config(&state, "stale").await;
        assert!(!stale_config.configuration_admitted);
        assert!(
            stale_config
                .configuration_error
                .starts_with("OpenShell 0.2 rejects this policy: middleware config 'guard' sets on_error: fail_open"),
            "{}",
            stale_config.configuration_error
        );
        assert_eq!(
            stale_config.policy_validation_failure_mode,
            "retain_last_valid"
        );
        assert!(stale_config.policy.is_some());

        for config in [
            sandbox_config(&state, "gone").await,
            user_sandbox_config(&state, "gone")
                .await
                .expect("unregistered middleware is refused through admission"),
        ] {
            assert!(!config.configuration_admitted);
            assert!(config.configuration_error.contains("is not registered"));
            assert_eq!(config.policy_validation_failure_mode, "retain_last_valid");
        }
    }

    #[tokio::test]
    async fn audit_mode_keeps_serving_stored_policies_unchanged() {
        let mut state = admission_state().await;
        Arc::get_mut(&mut state)
            .expect("test state is uniquely owned")
            .middleware_revalidation = RevalidationMode::Audit;

        let stale_config = sandbox_config(&state, "stale").await;
        assert!(
            stale_config.configuration_admitted,
            "{}",
            stale_config.configuration_error
        );
        let error = user_sandbox_config(&state, "gone")
            .await
            .expect_err("unregistered middleware stays an RPC error");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn admission_findings_do_not_block_startup_checks() {
        let state = admission_state().await;
        super::super::validate_provider_composition_startup_preflight(&state)
            .await
            .expect("stored offenders do not fail the startup preflight");
        log_gateway_upgrade_check(state.clone()).await;
        assert_eq!(
            check_gateway_upgrade(&state)
                .await
                .expect("upgrade check")
                .count(Severity::Blocking),
            3
        );
    }

    #[tokio::test]
    async fn policy_set_repairs_a_refused_sandbox_policy() {
        let state = admission_state().await;
        super::super::handle_update_config(
            &state,
            authed_request(UpdateConfigRequest {
                sandbox: "stale".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                policy: Some(middleware_policy(
                    "example/v2",
                    "fail_closed",
                    "deny",
                    false,
                )),
                ..Default::default()
            }),
        )
        .await
        .expect("policy set validates the replacement, not the stored policy");

        let repaired = sandbox_config(&state, "stale").await;
        assert!(
            repaired.configuration_admitted,
            "{}",
            repaired.configuration_error
        );
    }

    #[tokio::test]
    async fn global_policy_set_repairs_a_refused_global_policy() {
        let state = admission_state().await;
        let global = |policy: ProtoSandboxPolicy| UpdateConfigRequest {
            global: true,
            policy: Some(policy),
            ..Default::default()
        };
        let mut settings = super::super::load_global_settings(state.store.as_ref())
            .await
            .expect("global settings");
        settings.settings.insert(
            super::super::POLICY_SETTING_KEY.to_string(),
            super::super::StoredSettingValue::Bytes(hex::encode(
                middleware_policy("example/v2", "fail_open", "deny", false).encode_to_vec(),
            )),
        );
        super::super::save_global_settings(state.store.as_ref(), &settings)
            .await
            .expect("store a global policy that 0.2 rejects");
        assert!(!sandbox_config(&state, "clean").await.configuration_admitted);

        super::super::handle_update_config(
            &state,
            authed_request(global(middleware_policy(
                "example/v2",
                "fail_closed",
                "deny",
                false,
            ))),
        )
        .await
        .expect("global policy set validates the replacement");

        let repaired = sandbox_config(&state, "clean").await;
        assert!(
            repaired.configuration_admitted,
            "{}",
            repaired.configuration_error
        );
    }
}
