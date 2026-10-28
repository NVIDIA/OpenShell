// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::policy_identity::deterministic_policy_hash;
use openshell_ocsf::ActionId;
use openshell_policy_cedar::IpNet;

use super::l7::{UNREGISTERED_PERSISTED_QUERY, staged_audit_event};
use super::routes::{AliasTarget, BinaryAliases, RequestRoute, UNMATCHED_PATH};
use super::*;
use crate::l7::L7RequestInfo;
use crate::l7::relay::L7EvalContext;
use crate::policy_types::{DnsRecord, EndpointProtocol, TlsSetting};

const POLICY: &str = r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when {
    context.binary_path == "/usr/bin/curl"
};

permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when {
    context.binary_path == "/usr/bin/curl"
    && context.method == "GET"
    && context.path == "/v1/status"
};
"#;

fn ctx() -> L7EvalContext {
    L7EvalContext {
        host: "api.example.com".to_string(),
        port: 443,
        binary_path: "/usr/bin/curl".to_string(),
        ..Default::default()
    }
}

fn request(action: &str, target: &str) -> L7RequestInfo {
    L7RequestInfo {
        action: action.to_string(),
        target: target.to_string(),
        query_params: HashMap::new(),
        graphql: None,
        jsonrpc: None,
    }
}

#[test]
fn authorize_egress_populates_endpoint_configs_for_an_l7_endpoint() {
    // Without this, query_l7_route_snapshot (proxy.rs) always sees an
    // empty endpoint_configs and routes every allowed CONNECT to
    // unconditional passthrough — the HttpRequest permit above would
    // then never actually be consulted for a real connection.
    let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
    let input = NetworkInput {
        host: "api.example.com".to_string(),
        port: 443,
        binary_path: "/usr/bin/curl".into(),
        binary_sha256: "deadbeef".to_string(),
        ancestors: Vec::new(),
        cmdline_paths: Vec::new(),
    };
    let authorization = engine.authorize_egress(&input).expect("request evaluates");
    assert!(
        matches!(authorization.action, NetworkAction::Allow { .. }),
        "{:?}",
        authorization.action
    );
    assert_eq!(authorization.endpoint_configs.len(), 1);
    let config =
        crate::l7::parse_l7_config(&authorization.endpoint_configs[0]).expect("config must parse");
    assert_eq!(config.protocol, openshell_policy::L7Protocol::Rest);
}

#[test]
fn loading_an_audit_only_path_beside_enforced_policies_keeps_the_warning() {
    // `LoadedPolicy::from_proto` logs every analysis warning as an OCSF
    // config event. Tracing callsite interest is process-wide, so the
    // emission is not captured here; this checks that the loaded engine
    // carries exactly the warning the loader iterates over.
    const AUDIT_PATH_POLICY: &str = r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.binary_path == "/usr/bin/curl" };

permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.method == "GET" && context.path like("/v1/**", "/") };

@path("/admin/**")
@enforcement("audit")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.path like("/admin/**", "/") };
"#;
    let engine =
        CedarOnlyEngine::from_policy_str(AUDIT_PATH_POLICY).expect("policy loads with a warning");
    assert_eq!(
        engine.warnings_for_tests(),
        [
            openshell_policy_cedar::AnalysisWarning::AuditPathOnEnforcedEndpoint {
                endpoint: "api.example.com:443".to_string(),
                path: "/admin/**".to_string(),
            }
        ]
    );

    let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
    assert_eq!(engine.warnings_for_tests(), []);
}

#[test]
fn authorize_egress_omits_endpoint_configs_for_a_connect_only_endpoint() {
    const CONNECT_ONLY_POLICY: &str = r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"pypi.org:443"
)
when { context.binary_path == "/usr/bin/curl" };
"#;
    let engine = CedarOnlyEngine::from_policy_str(CONNECT_ONLY_POLICY).expect("policy parses");
    let input = NetworkInput {
        host: "pypi.org".to_string(),
        port: 443,
        binary_path: "/usr/bin/curl".into(),
        binary_sha256: "deadbeef".to_string(),
        ancestors: Vec::new(),
        cmdline_paths: Vec::new(),
    };
    let authorization = engine.authorize_egress(&input).expect("request evaluates");
    assert!(
        matches!(authorization.action, NetworkAction::Allow { .. }),
        "{:?}",
        authorization.action
    );
    assert!(authorization.endpoint_configs.is_empty());
}

#[test]
fn l7_override_allows_the_permitted_request() {
    let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
    let generation = engine.current_generation();
    let handle = engine.l7_handle(generation);
    let (allowed, _) = handle
        .evaluate_request(&ctx(), &request("GET", "/v1/status"))
        .expect("request evaluates");
    assert!(allowed);
}

#[test]
fn l7_override_denies_a_different_path() {
    let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
    let generation = engine.current_generation();
    let handle = engine.l7_handle(generation);
    let (allowed, reason) = handle
        .evaluate_request(&ctx(), &request("GET", "/v1/admin"))
        .expect("request evaluates");
    assert!(!allowed);
    assert!(!reason.is_empty());
}

#[test]
fn l7_override_fails_closed_when_tunnel_generation_is_stale() {
    let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
    let captured_generation = engine.current_generation();
    let handle = engine.l7_handle(captured_generation);
    // A reload with genuinely different policy text must still advance
    // the generation — only a byte-identical reload is a no-op.
    let changed_policy = format!("{POLICY}\n// a trailing comment to change the source\n");
    engine
        .reload_from_policy_str(&changed_policy)
        .expect("reload with changed policy advances the generation");

    let result = handle.evaluate_request(&ctx(), &request("GET", "/v1/status"));
    assert!(
        result.is_err(),
        "stale tunnel must fail closed, not silently re-evaluate"
    );
}

#[test]
fn reload_with_identical_policy_source_is_a_no_op() {
    // An unconditional generation bump here would invalidate every
    // in-flight L7 tunnel whenever a policy poll reconciliation pass
    // fires for a reason unrelated to this sandbox's Cedar policy (e.g.
    // middleware registry reconciliation) — not just a real change.
    let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
    let generation_before = engine.current_generation();
    engine
        .reload_from_policy_str(POLICY)
        .expect("reload succeeds");
    assert_eq!(
        engine.current_generation(),
        generation_before,
        "reloading byte-identical policy text must not advance the generation"
    );
}

#[test]
fn tunnel_engine_delegates_l7_decisions_to_cedar() {
    let cedar = Arc::new(CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses"));
    let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));

    let tunnel = engine
        .tunnel_engine(cedar.current_generation())
        .expect("tunnel builds");

    let (allowed, _) = tunnel
        .evaluate_request(&ctx(), &request("GET", "/v1/status"))
        .expect("request evaluates");
    assert!(allowed, "Cedar must decide the request");
}

#[tokio::test]
async fn cedar_mcp_routes_observe_the_configured_inventory_identity() {
    use openshell_core::endpoint_status::{
        EndpointConfigVersion, EndpointInventoryEntry, EndpointResult, endpoint_id,
        endpoint_status_channel,
    };
    use openshell_core::proto::NetworkEndpoint;
    let source = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
@protocol("mcp") @path("/mcp/**")
permit (principal, action == Sandbox::Action::"HttpRequest", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
@protocol("rest") @path("/rest/**")
permit (principal, action == Sandbox::Action::"HttpRequest", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
"#;
    let provider = NetworkEndpoint {
        host: "*.example.com".to_string(),
        ports: vec![8443, 443],
        path: "/mcp/provider/**".to_string(),
        provider_credentialed: true,
        ..Default::default()
    };
    let setting = NetworkEndpoint {
        host: "api.example.com".to_string(),
        port: 443,
        path: "/mcp/scoped".to_string(),
        allow_encoded_slash: true,
        ..Default::default()
    };
    let mut policy = provider_policy(source, vec![provider.clone()]);
    policy.endpoint_settings.push(setting.clone());
    let policy = openshell_policy::validate_and_canonicalize_sandbox_policy(policy)
        .expect("canonical policy");
    let engine = CedarOnlyEngine::from_proto(&policy).expect("policy loads");
    let descriptors =
        openshell_policy::endpoint_status::configured_mcp_endpoints(&policy).expect("inventory");
    let (sender, mut receiver) = endpoint_status_channel();
    let mut tracker = receiver.tracker();
    sender
        .reset(
            EndpointConfigVersion {
                policy_hash: deterministic_policy_hash(&policy),
                provider_env_revision: 1,
            },
            descriptors
                .iter()
                .map(|endpoint| EndpointInventoryEntry {
                    endpoint_id: endpoint_id(endpoint),
                    uses_provider_credentials: endpoint.provider_credentialed,
                })
                .collect(),
        )
        .await
        .expect("reset");
    assert!(tracker.apply(receiver.recv().await.expect("reset received")));
    let base = NetworkEndpoint {
        host: "*.example.com".to_string(),
        port: 443,
        path: "/mcp/**".to_string(),
        ..Default::default()
    };
    for (host, path, expected) in [
        ("api.example.com", "/mcp/item", &base),
        ("other.example.com", "/mcp/item", &base),
        ("api.example.com", "/mcp/provider/item", &provider),
        ("other.example.com", "/mcp/provider/item", &provider),
        ("api.example.com", "/mcp/scoped", &setting),
    ] {
        let loaded = engine.read_engine().expect("lock");
        let config = loaded.request_config(host, 443, path).expect("route");
        let selected = crate::l7::parse_l7_config(&config).expect("MCP config");
        assert_eq!(selected.endpoint_id, endpoint_id(expected), "{host}{path}");
        let observer = crate::l7::EndpointObserver::begin(Some(&sender), &selected)
            .expect("observation starts");
        observer.observe(EndpointResult::HttpResponseReceived);
    }
    let rest = engine
        .read_engine()
        .expect("lock")
        .request_config("api.example.com", 443, "/rest/item")
        .expect("REST route");
    let rest = crate::l7::parse_l7_config(&rest).expect("REST config");
    assert!(crate::l7::EndpointObserver::begin(Some(&sender), &rest).is_none());
    while let Ok(command) = receiver.try_recv() {
        tracker.apply(command);
    }
    let snapshot = tracker.snapshot().expect("snapshot");
    for expected in [&base, &provider, &setting] {
        assert!(
            snapshot
                .endpoints
                .iter()
                .any(|endpoint| endpoint.endpoint_id == endpoint_id(expected)
                    && endpoint.result == EndpointResult::HttpResponseReceived)
        );
    }
}

#[tokio::test]
async fn websocket_admission_is_shared_across_forward_tunnels_and_reload() {
    use crate::l7::websocket::{WebSocketAssemblyAdmissionOutcome, WebSocketAssemblyBudget};
    let mut cedar = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
    cedar.websocket_assembly_budget = WebSocketAssemblyBudget::new(1, 1);
    let cedar = Arc::new(cedar);
    let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
    let first = engine
        .tunnel_engine(cedar.current_generation())
        .expect("first tunnel");
    let second = engine
        .tunnel_engine(cedar.current_generation())
        .expect("second tunnel");
    let active = first
        .websocket_assembly_budget()
        .reserve()
        .await
        .expect("reserve");
    assert!(matches!(
        active,
        WebSocketAssemblyAdmissionOutcome::Admitted(_)
    ));
    let waiting_budget = second.websocket_assembly_budget();
    let waiting = waiting_budget.reserve();
    tokio::pin!(waiting);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), &mut waiting)
            .await
            .is_err()
    );
    assert!(matches!(
        engine
            .websocket_assembly_budget()
            .reserve()
            .await
            .expect("forward admission"),
        WebSocketAssemblyAdmissionOutcome::QueueExhausted
    ));
    cedar
        .reload_from_policy_str(&POLICY.replace("/v1/status", "/v2/status"))
        .expect("reload");
    assert!(
        first.generation_guard().is_stale(),
        "the reload changed policy"
    );
    let reloaded = engine
        .tunnel_engine(cedar.current_generation())
        .expect("new tunnel");
    assert!(matches!(
        reloaded
            .websocket_assembly_budget()
            .reserve()
            .await
            .expect("reloaded admission"),
        WebSocketAssemblyAdmissionOutcome::QueueExhausted
    ));
    drop(active);
    assert!(matches!(
        waiting.await.expect("waiter admitted"),
        WebSocketAssemblyAdmissionOutcome::Admitted(_)
    ));
}

#[test]
fn tunnel_engine_tracks_the_cedar_generation() {
    let cedar = Arc::new(CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses"));
    let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
    let tunnel = engine
        .tunnel_engine(cedar.current_generation())
        .expect("tunnel builds");

    // A middleware registry swap advances the middleware generation, not
    // Cedar's, so it must not close a Cedar tunnel.
    engine
        .replace_middleware_registry(MiddlewareRegistry::default())
        .expect("registry swap");
    assert!(!tunnel.is_stale());

    // A Cedar reload must.
    cedar
        .reload_from_policy_str(&format!("{POLICY}\n// changed\n"))
        .expect("reload");
    assert!(tunnel.is_stale());
}

#[test]
fn tunnel_engine_rejects_a_stale_cedar_generation() {
    let cedar = Arc::new(CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses"));
    let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
    let decided_at = cedar.current_generation();
    cedar
        .reload_from_policy_str(&format!("{POLICY}\n// changed\n"))
        .expect("reload");

    assert!(engine.tunnel_engine(decided_at).is_err());
}

fn middleware_policy(include: &str) -> ProtoSandboxPolicy {
    let mut policy = policy_from_source(POLICY);
    policy.network_middlewares.insert(
        "redactor".to_string(),
        openshell_core::proto::NetworkMiddlewareConfig {
            middleware: "openshell/regex".to_string(),
            order: 10,
            endpoints: Some(openshell_core::proto::MiddlewareEndpointSelector {
                include: vec![include.to_string()],
                exclude: Vec::new(),
            }),
            ..Default::default()
        },
    );
    policy
}

fn middleware_input(host: &str) -> NetworkInput {
    NetworkInput {
        host: host.to_string(),
        port: 443,
        binary_path: "/usr/bin/curl".into(),
        binary_sha256: String::new(),
        ancestors: Vec::new(),
        cmdline_paths: Vec::new(),
    }
}

/// Registry reconciliation keeps the Cedar generation and open tunnels; a
/// middleware-only reload publishes the new chain and advances the Cedar
/// generation, as one OPA generation does for YAML, so existing tunnels
/// close before they can run the old middleware again.
#[test]
fn middleware_only_reload_advances_the_cedar_generation_and_closes_tunnels() {
    let cedar = Arc::new(
        CedarOnlyEngine::from_proto(&middleware_policy("api.example.com")).expect("policy loads"),
    );
    let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
    let policy_generation = cedar.current_generation();
    let middleware_generation = engine.middleware_generation();
    let tunnel = engine
        .tunnel_engine(policy_generation)
        .expect("tunnel builds");
    let selected = |chain: Vec<openshell_supervisor_middleware::ChainEntry>| {
        chain
            .into_iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        selected(
            tunnel
                .query_middleware_chain(&middleware_input("api.example.com"))
                .expect("tunnel chain")
        ),
        vec!["redactor"]
    );

    let unchanged = cedar
        .stage(&middleware_policy("api.example.com"), 0)
        .expect("stage");
    cedar
        .commit_configuration(unchanged, Some(MiddlewareRegistry::default()), || {})
        .expect("reconcile");
    assert_eq!(cedar.current_generation(), policy_generation);
    assert!(!tunnel.is_stale(), "registry reconciliation keeps tunnels");

    let staged = cedar
        .stage(&middleware_policy("other.example.com"), 0)
        .expect("stage");
    let mut credentials_committed = false;
    let guard = cedar
        .commit_configuration(staged, None, || credentials_committed = true)
        .expect("commit");

    assert!(credentials_committed);
    assert_eq!(cedar.current_generation(), policy_generation + 1);
    assert!(tunnel.is_stale());
    assert_eq!(guard.captured_generation(), middleware_generation + 2);
    let (chain, generation) = engine
        .query_middleware_chain_with_generation(&middleware_input("api.example.com"))
        .expect("chain");
    assert!(chain.is_empty());
    assert_eq!(generation, middleware_generation + 2);
    assert!(
        tunnel
            .evaluate_request(&ctx(), &request("GET", "/v1/status"))
            .is_err()
    );
}

/// Existing Cedar guards become stale before credentials change, as the
/// YAML reload guarantees.
#[test]
fn commit_configuration_invalidates_policy_guards_before_credentials_change() {
    let cedar = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
    let policy_guard = cedar
        .generation_guard(cedar.current_generation())
        .expect("policy guard");
    let middleware_guard = cedar
        .middleware()
        .generation_guard(cedar.middleware().current_generation())
        .expect("middleware guard");
    let staged = cedar
        .stage(&policy_from_source(&format!("{POLICY}\n// changed\n")), 0)
        .expect("stage");
    let mut stale_at_credential_commit = None;
    cedar
        .commit_configuration(staged, None, || {
            stale_at_credential_commit =
                Some((policy_guard.is_stale(), middleware_guard.is_stale()));
        })
        .expect("commit");
    assert_eq!(stale_at_credential_commit, Some((true, true)));
}

fn chain_names(chain: Vec<openshell_supervisor_middleware::ChainEntry>) -> Vec<String> {
    chain.into_iter().map(|entry| entry.name).collect()
}

/// A quarantine is a configuration change: the guard the policy poll
/// loop pins (the middleware generation) goes stale when the quarantine
/// starts and when it ends, as the single-counter YAML guard does.
#[test]
fn quarantine_entry_and_exit_stale_the_configuration_guard() {
    let cedar = Arc::new(CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses"));
    let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
    let policy_generation = cedar.current_generation();
    let before = engine
        .configuration_generation_guard()
        .expect("configuration guard");

    let quarantined = cedar
        .enter_fail_closed("invalid candidate")
        .expect("quarantine");
    assert_eq!(quarantined, policy_generation + 1);
    assert!(before.is_stale(), "entering a quarantine stales the guard");
    assert!(cedar.fail_closed_reason().is_some());

    let during = engine
        .configuration_generation_guard()
        .expect("configuration guard");
    assert_eq!(
        cedar.exit_fail_closed().expect("exit"),
        policy_generation + 2
    );
    assert!(during.is_stale(), "ending a quarantine stales the guard");
    assert!(cedar.fail_closed_reason().is_none());

    // Without a quarantine to end, nothing changes.
    let after = engine
        .configuration_generation_guard()
        .expect("configuration guard");
    assert_eq!(
        cedar.exit_fail_closed().expect("exit"),
        policy_generation + 2
    );
    assert!(!after.is_stale());
}

/// A commit whose binary resolution fails changes nothing: the policy,
/// the middleware, and the credentials all stay on the previous
/// revision, and no guard becomes stale.
#[test]
fn a_commit_that_fails_to_resolve_changes_nothing() {
    const PID: u32 = 4242;
    let cedar = Arc::new(
        CedarOnlyEngine::from_proto(&middleware_policy("api.example.com")).expect("policy loads"),
    );
    let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
    let input = middleware_input("api.example.com");

    // A changed policy with changed middleware, staged before the
    // entrypoint process is known, so the commit has to resolve it.
    let mut candidate = middleware_policy("other.example.com");
    candidate.cedar_policy_source.push_str("\n// changed\n");
    let mut staged = cedar.stage(&candidate, 0).expect("stage");
    staged.fail_binary_resolution_for_tests();
    cedar.resolve_binary_symlinks(PID).expect("resolves");

    let policy_generation = cedar.current_generation();
    let policy_guard = cedar
        .generation_guard(policy_generation)
        .expect("policy guard");
    let configuration = engine
        .configuration_generation_guard()
        .expect("configuration guard");
    let mut credentials_committed = false;

    let error = cedar
        .commit_configuration(staged, None, || credentials_committed = true)
        .expect_err("resolution fails");

    assert!(
        error.to_string().contains("injected test failure"),
        "{error}"
    );
    assert!(
        !credentials_committed,
        "credentials stay on the previous revision"
    );
    assert!(!policy_guard.is_stale());
    assert!(!configuration.is_stale());
    assert_eq!(cedar.current_generation(), policy_generation);
    assert_eq!(
        cedar.read_inputs().expect("lock").source,
        POLICY,
        "the active policy is unchanged"
    );
    let (chain, generation) = engine
        .query_middleware_chain_with_generation(&input)
        .expect("chain");
    assert_eq!(chain_names(chain), vec!["redactor"]);
    assert_eq!(generation, configuration.captured_generation());

    // The engine is still usable: the same candidate commits once it resolves.
    let staged = cedar.stage(&candidate, 0).expect("stage");
    cedar
        .commit_configuration(staged, None, || credentials_committed = true)
        .expect("commit");
    assert!(credentials_committed);
    assert!(policy_guard.is_stale());
    assert!(configuration.is_stale());
}

/// A passthrough tunnel closes at the next request after a middleware
/// config change, which advances the Cedar generation its guard pins.
#[test]
fn passthrough_middleware_closes_after_a_middleware_only_reload() {
    let cedar = Arc::new(
        CedarOnlyEngine::from_proto(&middleware_policy("api.example.com")).expect("policy loads"),
    );
    let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
    let guard = engine
        .generation_guard(cedar.current_generation())
        .expect("tunnel guard");
    let passthrough = engine.passthrough_middleware().expect("snapshot");
    let input = middleware_input("api.example.com");
    let (chain, _) = passthrough
        .select(&input, &guard)
        .expect("select")
        .expect("tunnel open");
    assert_eq!(chain_names(chain), vec!["redactor"]);

    let staged = cedar
        .stage(&middleware_policy("other.example.com"), 0)
        .expect("stage");
    cedar.commit(staged).expect("commit");

    let (live, _) = engine
        .query_middleware_chain_with_generation(&input)
        .expect("chain");
    assert!(live.is_empty(), "new tunnels select the new middleware");
    assert!(guard.is_stale(), "a middleware-only reload closes tunnels");
    assert!(
        passthrough
            .select(&input, &guard)
            .expect("select")
            .is_none()
    );
}

/// `from_proto` and `stage` validate the policy as `OpaEngine::from_proto`
/// validates a YAML policy, so no caller can build an unvalidated engine.
#[test]
fn engines_validate_the_policy_as_yaml_engines_do() {
    let mut invalid = middleware_policy("api.example.com");
    invalid
        .network_middlewares
        .get_mut("redactor")
        .expect("middleware")
        .on_error = "maybe".to_string();

    let error = CedarOnlyEngine::from_proto(&invalid).expect_err("invalid middleware");
    assert!(
        error
            .to_string()
            .contains("invalid middleware configuration"),
        "{error}"
    );
    let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy loads");
    let error = engine.stage(&invalid, 0).expect_err("invalid middleware");
    assert!(
        error
            .to_string()
            .contains("invalid middleware configuration"),
        "{error}"
    );

    let error = CedarOnlyEngine::from_proto(&policy_from_source("not cedar {{{"))
        .expect_err("invalid Cedar text");
    assert!(
        error.to_string().contains("invalid Cedar policy"),
        "{error}"
    );
}

const CONNECT_ONLY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
"#;

fn provider_policy(
    cedar: &str,
    endpoints: Vec<openshell_core::proto::NetworkEndpoint>,
) -> ProtoSandboxPolicy {
    let mut policy = policy_from_source(cedar);
    policy.provider_credential_rules.insert(
        "_provider_work".to_string(),
        NetworkPolicyRule {
            name: "_provider_work".to_string(),
            endpoints,
            ..Default::default()
        },
    );
    policy
}

fn credentialed_endpoint() -> openshell_core::proto::NetworkEndpoint {
    openshell_core::proto::NetworkEndpoint {
        host: "api.example.com".to_string(),
        port: 443,
        protocol: "rest".to_string(),
        access: openshell_core::proto::NetworkAccessPreset::ReadOnly as i32,
        provider_credentialed: true,
        request_body_credential_rewrite: true,
        ..Default::default()
    }
}

fn curl_input(host: &str) -> NetworkInput {
    NetworkInput {
        host: host.to_string(),
        port: 443,
        binary_path: "/usr/bin/curl".into(),
        binary_sha256: String::new(),
        ancestors: Vec::new(),
        cmdline_paths: Vec::new(),
    }
}

#[test]
fn provider_settings_apply_with_cedar_inspection() {
    let engine =
        CedarOnlyEngine::from_proto(&provider_policy(POLICY, vec![credentialed_endpoint()]))
            .expect("policy loads");
    let authorization = engine
        .authorize_egress(&curl_input("api.example.com"))
        .expect("request evaluates");
    assert_eq!(authorization.endpoint_configs.len(), 1);
    let config =
        crate::l7::parse_l7_config(&authorization.endpoint_configs[0]).expect("config must parse");
    assert_eq!(config.protocol, openshell_policy::L7Protocol::Rest);
    assert!(config.provider_credentialed);
    assert!(config.request_body_credential_rewrite);
    assert_eq!(
        authorization.endpoint_configs[0].access,
        crate::policy_types::AccessSetting::None,
        "provider L7 rules must not apply on a Cedar sandbox"
    );
}

#[test]
fn uninspected_credentialed_endpoint_is_refused_at_connect() {
    // Cedar allows the connection but has no HttpRequest policy for it,
    // so it would be relayed without inspection.
    let engine = CedarOnlyEngine::from_proto(&provider_policy(
        CONNECT_ONLY,
        vec![credentialed_endpoint()],
    ))
    .expect("policy loads");
    let guards = engine
        .credential_guards("api.example.com", 443)
        .expect("guards evaluate");
    assert_eq!(guards.len(), 1);
    let guard = crate::l7::parse_endpoint_credential_guard(&guards[0]);
    assert!(guard.provider_credentialed);
    assert!(guard.blocks_connect());
}

#[test]
fn provider_rules_grant_no_access() {
    let mut other = credentialed_endpoint();
    other.host = "other.example.com".to_string();
    let engine =
        CedarOnlyEngine::from_proto(&provider_policy(POLICY, vec![other])).expect("policy loads");
    let authorization = engine
        .authorize_egress(&curl_input("other.example.com"))
        .expect("request evaluates");
    assert!(
        matches!(authorization.action, NetworkAction::Deny { .. }),
        "{:?}",
        authorization.action
    );
    assert!(authorization.endpoint_configs.is_empty());
}

#[test]
fn provider_allowed_ips_narrow_addresses_and_hostless_endpoints_match_nothing() {
    let mut ranged = credentialed_endpoint();
    ranged.allowed_ips = vec!["10.0.0.0/8".to_string()];
    let hostless = openshell_core::proto::NetworkEndpoint {
        host: String::new(),
        port: 8443,
        allowed_ips: vec!["10.0.0.0/8".to_string()],
        provider_credentialed: true,
        ..Default::default()
    };
    let cedar = format!(
        r#"{POLICY}
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {{ resource.port == 8443 }};
"#
    );
    let engine = CedarOnlyEngine::from_proto(&provider_policy(&cedar, vec![ranged, hostless]))
        .expect("policy loads");

    let authorization = engine
        .authorize_egress(&curl_input("api.example.com"))
        .expect("request evaluates");
    assert_eq!(authorization.endpoint_configs.len(), 1);
    assert!(
        authorization.endpoint_configs[0].allowed_ips.is_empty(),
        "{:?}",
        authorization.endpoint_configs[0]
    );
    let destination = authorization
        .cedar_destination
        .expect("the connection is allowed");
    assert_eq!(
        destination.provider_ranges(),
        [Ok(vec!["10.0.0.0/8".parse::<IpNet>().unwrap()])],
        "the ranges travel with the destination rules, not the config"
    );

    let guards = engine
        .credential_guards("anything.example.com", 8443)
        .expect("guards evaluate");
    assert!(
        guards.is_empty(),
        "a host-less provider endpoint lends no credentials"
    );
}

const ADDRESS_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"db.corp.net:5432")
when {
    context.binary_path == "/usr/bin/curl"
    && context has destination_ip
    && context.destination_ip.isInRange(ip("10.2.0.0/16"))
};
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.corp.net:443")
when { context.binary_path == "/usr/bin/wget" };
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.corp.net", ".") && resource.port == 443 };
"#;

#[test]
fn allowed_connections_carry_their_destination_rules() {
    let engine = CedarOnlyEngine::from_policy_str(ADDRESS_POLICY).expect("policy loads");
    let mut input = curl_input("db.corp.net");
    input.port = 5432;
    let authorization = engine.authorize_egress(&input).expect("request evaluates");
    assert!(matches!(authorization.action, NetworkAction::Allow { .. }));
    assert!(authorization.exact_declared_endpoint_host);
    let destination = authorization
        .cedar_destination
        .expect("an allowed connection carries its destination rules");
    assert_eq!(
        destination.address_conditions(),
        [vec!["10.2.0.0/16".parse::<IpNet>().unwrap()]]
    );
    assert!(!destination.unconstrained_permit());
    assert_eq!(destination.allows("10.2.3.4".parse().unwrap()), Ok(true));
    assert_eq!(destination.allows("10.3.3.4".parse().unwrap()), Ok(false));

    input.port = 5433;
    let denied = engine.authorize_egress(&input).expect("request evaluates");
    assert!(matches!(denied.action, NetworkAction::Deny { .. }));
    assert!(denied.cedar_destination.is_none());
}

#[test]
fn exact_host_counts_only_permits_that_allow_the_connection() {
    let engine = CedarOnlyEngine::from_policy_str(ADDRESS_POLICY).expect("policy loads");
    let curl = engine
        .authorize_egress(&curl_input("api.corp.net"))
        .expect("request evaluates");
    assert!(matches!(curl.action, NetworkAction::Allow { .. }));
    assert!(
        !curl.exact_declared_endpoint_host,
        "the exact permit is for another binary"
    );
    let mut wget = curl_input("api.corp.net");
    wget.binary_path = "/usr/bin/wget".into();
    let wget = engine.authorize_egress(&wget).expect("request evaluates");
    assert!(wget.exact_declared_endpoint_host);
}

#[test]
fn dns_records_carry_destination_ranges_as_allowed_ips() {
    let engine = CedarOnlyEngine::from_policy_str(ADDRESS_POLICY).expect("policy loads");
    let snapshot = engine
        .policy_dns_eligibility_snapshot()
        .expect("snapshot builds");
    let db = snapshot
        .endpoints
        .iter()
        .map(|record| &record.endpoint)
        .find(|record| record.host == "db.corp.net")
        .expect("db.corp.net is eligible");
    assert_eq!(db.allowed_ips, ["10.2.0.0/16"]);
}

#[test]
fn path_scoped_provider_endpoint_keeps_other_paths_inspected() {
    let mut scoped = credentialed_endpoint();
    scoped.path = "/v1/**".to_string();
    let engine =
        CedarOnlyEngine::from_proto(&provider_policy(POLICY, vec![scoped])).expect("policy loads");
    let configs = engine
        .credential_guards("api.example.com", 443)
        .expect("configs build");
    assert_eq!(configs.len(), 2, "path-scoped config plus a path-less one");
    assert!(configs.iter().all(|config| {
        crate::l7::parse_l7_config(config)
            .is_some_and(|config| config.protocol == openshell_policy::L7Protocol::Rest)
    }));
}

#[test]
fn reload_tracks_provider_rule_changes() {
    let engine =
        CedarOnlyEngine::from_proto(&provider_policy(POLICY, vec![credentialed_endpoint()]))
            .expect("policy loads");
    let generation = engine.current_generation();

    let unchanged = engine
        .stage(&provider_policy(POLICY, vec![credentialed_endpoint()]), 0)
        .expect("stage");
    engine.commit(unchanged).expect("commit");
    assert_eq!(engine.current_generation(), generation);

    let changed = engine.stage(&policy_from_source(POLICY), 0).expect("stage");
    engine.commit(changed).expect("commit");
    assert_eq!(engine.current_generation(), generation + 1);
    assert_eq!(
        engine
            .credential_guards("api.example.com", 443)
            .expect("configs")
            .len(),
        1,
        "only Cedar's own inspection config remains"
    );
}

#[test]
fn exact_declared_host_follows_the_permit_scope() {
    let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
    assert!(
        engine
            .authorize_egress(&curl_input("api.example.com"))
            .expect("request evaluates")
            .exact_declared_endpoint_host
    );

    let glob = CedarOnlyEngine::from_policy_str(
        r#"permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
               when { resource.host like "*.example.com" };"#,
    )
    .expect("policy parses");
    let authorization = glob
        .authorize_egress(&curl_input("api.example.com"))
        .expect("request evaluates");
    assert!(matches!(authorization.action, NetworkAction::Allow { .. }));
    assert!(!authorization.exact_declared_endpoint_host);
}

const HOST_GLOB_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
"#;

#[test]
fn delimited_host_glob_is_eligible_for_policy_dns() {
    let engine = CedarOnlyEngine::from_policy_str(HOST_GLOB_POLICY).expect("policy parses");
    let snapshot = engine.policy_dns_eligibility_snapshot().expect("snapshot");
    let hosts: Vec<_> = snapshot
        .endpoints
        .iter()
        .map(|endpoint| endpoint.endpoint.host.clone())
        .collect();
    assert_eq!(hosts, ["*.example.com"]);

    let selector =
        openshell_core::host_pattern::HostSelector::new(&["*.example.com".to_string()], &[])
            .expect("policy DNS accepts the glob");
    assert!(selector.matches("api.example.com"));
    assert!(!selector.matches("a.b.example.com"));
}

#[test]
fn host_glob_never_counts_as_an_exact_declared_host() {
    let engine = CedarOnlyEngine::from_policy_str(HOST_GLOB_POLICY).expect("policy parses");
    for host in ["api.example.com", "*.example.com"] {
        let authorization = engine
            .authorize_egress(&curl_input(host))
            .expect("request evaluates");
        assert!(
            matches!(authorization.action, NetworkAction::Allow { .. }),
            "{host}"
        );
        assert!(!authorization.exact_declared_endpoint_host, "{host}");
    }
}

const NATIVE_TCP_POLICY: &str = r#"
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"db.example.com:5432")
when { context.binary_path == "/usr/bin/curl" };
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
"#;

#[test]
fn dns_snapshot_marks_native_tcp_records() {
    let engine = CedarOnlyEngine::from_policy_str(NATIVE_TCP_POLICY).expect("policy parses");
    let snapshot = engine.policy_dns_eligibility_snapshot().expect("snapshot");
    let records: Vec<_> = snapshot
        .endpoints
        .iter()
        .map(|record| {
            (
                record.policy_name.as_str(),
                record.endpoint_index,
                record.endpoint.clone(),
            )
        })
        .collect();
    let record = |host: &str, port: u16, protocol: EndpointProtocol| DnsRecord {
        host: host.to_string(),
        ports: vec![port],
        protocol,
        allowed_ips: Vec::new(),
    };
    assert_eq!(
        records,
        [
            (
                "cedar",
                0,
                record("*.example.com", 443, EndpointProtocol::None)
            ),
            (
                "cedar",
                1,
                record("api.example.com", 443, EndpointProtocol::None)
            ),
            (
                "cedar",
                2,
                record("db.example.com", 5432, EndpointProtocol::Tcp)
            ),
        ]
    );
}

/// Regression: `matched_endpoints` was always empty, so the transparent
/// TCP listener, which requires a decision endpoint that the dialed
/// policy DNS mapping also names, refused every Cedar-allowed connection.
#[test]
fn matched_endpoints_are_the_dns_records_covering_the_connection() {
    let engine = CedarOnlyEngine::from_policy_str(NATIVE_TCP_POLICY).expect("policy parses");
    let snapshot = engine.policy_dns_eligibility_snapshot().expect("snapshot");
    let matched = |host: &str, port: u16| {
        let authorization = engine
            .authorize_egress(&NetworkInput {
                port,
                ..curl_input(host)
            })
            .expect("request evaluates");
        authorization
            .matched_endpoints
            .iter()
            .map(|record| {
                let published = &snapshot.endpoints[record.endpoint_index];
                assert_eq!(published.policy_name, record.policy_name);
                assert_eq!(published.endpoint, record.endpoint);
                record.endpoint_index
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(matched("db.example.com", 5432), [2]);
    // The exact host and the glob both cover it.
    assert_eq!(matched("API.example.com.", 443), [0, 1]);
    assert_eq!(matched("www.example.com", 443), [0]);
    // A denied connection matches nothing.
    assert!(matched("db.example.com", 80).is_empty());
    assert!(matched("other.example.org", 443).is_empty());
}

const AUDIT_POLICY: &str = r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
);

@enforcement("audit")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.method == "GET" };
"#;

#[test]
fn audit_endpoint_configs_use_audit_enforcement() {
    let engine = CedarOnlyEngine::from_proto(&provider_policy(
        AUDIT_POLICY,
        vec![credentialed_endpoint()],
    ))
    .expect("policy loads");
    let authorization = engine
        .authorize_egress(&curl_input("api.example.com"))
        .expect("request evaluates");
    assert!(!authorization.endpoint_configs.is_empty());
    for value in &authorization.endpoint_configs {
        let config = crate::l7::parse_l7_config(value).expect("config must parse");
        assert_eq!(config.enforcement, crate::l7::EnforcementMode::Audit);
    }
}

#[test]
fn audit_endpoint_reports_the_policy_decision_for_the_relay_to_log() {
    let engine = CedarOnlyEngine::from_policy_str(AUDIT_POLICY).expect("policy parses");
    let tunnel = engine.l7_handle(engine.current_generation());
    let (allowed, reason) = tunnel
        .evaluate_request(&ctx(), &request("DELETE", "/v1/items/1"))
        .expect("request evaluates");
    assert!(!allowed, "the relay logs and forwards an audit deny");
    assert!(!reason.is_empty());
    let (allowed, _) = tunnel
        .evaluate_request(&ctx(), &request("GET", "/v1/items/1"))
        .expect("request evaluates");
    assert!(allowed);
}

#[test]
fn staged_audit_event_reports_the_staged_outcome() {
    let staged = Decision::Deny {
        matched_policies: vec!["no-hooks".to_string()],
    };
    let event = staged_audit_event(&ctx(), &request("GET", "/v1/hooks"), true, &staged)
        .to_json()
        .expect("serialize");
    let message = event["message"].as_str().expect("message");
    assert_eq!(
        message,
        "L7_AUDIT staged deny GET api.example.com:443/v1/hooks policies=no-hooks"
    );
    assert_eq!(
        event["action_id"],
        serde_json::json!(ActionId::Allowed as u8)
    );
    assert_eq!(event["unmapped"]["cedar_audit"], "staged_deny");
    assert_eq!(event["unmapped"]["cedar_audit_policies"], "no-hooks");
}

#[test]
fn mcp_and_graphql_endpoint_configs_parse_for_the_relay() {
    for (protocol, expected) in [
        ("mcp", openshell_policy::L7Protocol::Mcp),
        ("graphql", openshell_policy::L7Protocol::Graphql),
    ] {
        let engine = CedarOnlyEngine::from_policy_str(&format!(
            r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
@protocol("{protocol}")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
"#
        ))
        .expect("policy parses");
        let authorization = engine
            .authorize_egress(&curl_input("api.example.com"))
            .expect("request evaluates");
        assert_eq!(authorization.endpoint_configs.len(), 1, "{protocol}");
        let config = crate::l7::parse_l7_config(&authorization.endpoint_configs[0])
            .unwrap_or_else(|| panic!("{protocol} config must parse"));
        assert_eq!(config.protocol, expected);
        assert_eq!(config.enforcement, crate::l7::EnforcementMode::Enforce);
    }
}

/// Token-grant reporting binds a request to the policy its endpoint was
/// selected under through `policy_hash`, for every protocol, as the YAML
/// engine's endpoint data does; a Cedar config without it would never
/// match the installed observation inventory.
#[test]
fn endpoint_configs_carry_the_policy_hash_for_every_protocol() {
    for protocol in ["rest", "mcp", "graphql", "json-rpc"] {
        let policy = policy_from_source(&protocol_policy(protocol));
        let canonical =
            crate::policy_validation::validate_sandbox_policy(&policy).expect("policy validates");
        let engine = CedarOnlyEngine::from_proto(&policy).expect("policy loads");
        let configs = parsed_configs(&engine, "api.example.com");
        assert_eq!(configs.len(), 1, "{protocol}");
        assert_eq!(
            configs[0].policy_hash,
            deterministic_policy_hash(&canonical),
            "{protocol}"
        );
    }

    // A provider endpoint's config is bound to the same policy.
    let engine = owner_engine(OWNER_POLICY);
    let configs = parsed_configs(&engine, "api.example.com");
    assert!(!configs.is_empty());
    let expected = engine
        .engine
        .read()
        .expect("engine lock")
        .policy_hash
        .clone();
    assert!(!expected.is_empty());
    assert!(
        configs.iter().all(|config| config.policy_hash == expected),
        "{configs:?}"
    );
}

const OWNER_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {
    (context.method == "GET" && context.path like("/a/**", "/"))
    || (context.method == "POST" && context.path like("/a/private/**", "/"))
};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.path == "/a/private/blocked" };
"#;

/// A provider endpoint stamped with `owner` whose own rule allows
/// `method` on `path`.
fn owned_endpoint(owner: &str, path: &str, method: &str) -> openshell_core::proto::NetworkEndpoint {
    openshell_core::proto::NetworkEndpoint {
        host: "api.example.com".to_string(),
        port: 443,
        path: path.to_string(),
        protocol: "rest".to_string(),
        token_grant_owner: owner.to_string(),
        rules: vec![openshell_core::proto::L7Rule {
            allow: Some(openshell_core::proto::L7Allow {
                method: method.to_string(),
                path: path.to_string(),
                ..Default::default()
            }),
        }],
        ..Default::default()
    }
}

fn owner_engine(cedar: &str) -> CedarOnlyEngine {
    let mut policy = provider_policy(
        cedar,
        vec![
            owned_endpoint("owner-broad", "/a/**", "GET"),
            owned_endpoint("owner-narrow", "/a/private/**", "POST"),
        ],
    );
    policy
        .provider_credential_rules
        .get_mut("_provider_work")
        .expect("provider rule")
        .binaries
        .push(openshell_core::proto::NetworkBinary {
            path: "/usr/bin/curl".to_string(),
        });
    CedarOnlyEngine::from_proto(&policy).expect("policy loads")
}

fn owners(engine: &CedarOnlyEngine, method: &str, target: &str) -> Vec<String> {
    let mut owners: Vec<_> = engine
        .l7_handle(engine.current_generation())
        .admitted_token_grant_owners(&ctx(), &request(method, target))
        .expect("owners evaluate")
        .into_iter()
        .collect();
    owners.sort();
    owners
}

#[test]
fn token_grant_owner_requires_its_own_provider_rules_to_allow() {
    let engine = owner_engine(OWNER_POLICY);
    // Both endpoints cover the path, but only the broad endpoint's own
    // rule allows GET: Cedar's allow does not lend the narrow grant.
    assert_eq!(owners(&engine, "GET", "/a/private/item"), ["owner-broad"]);
    assert_eq!(owners(&engine, "POST", "/a/private/item"), ["owner-narrow"]);
    assert!(owners(&engine, "GET", "/b/item").is_empty());
}

#[test]
fn token_grant_owner_requires_cedar_to_allow() {
    let engine = owner_engine(OWNER_POLICY);
    // The broad provider rule allows this request, but Cedar forbids it.
    assert!(owners(&engine, "GET", "/a/private/blocked").is_empty());
    // Provider rules never allow what Cedar does not permit.
    let narrow_cedar = OWNER_POLICY.replace(r#"context.method == "GET""#, "false");
    let engine = owner_engine(&narrow_cedar);
    assert!(owners(&engine, "GET", "/a/item").is_empty());
}

#[test]
fn token_grant_owner_needs_an_allowing_audit_decision() {
    let engine = owner_engine(AUDIT_POLICY);
    // Cedar's audit-only endpoint forwards a denied POST, but a denial
    // admits no grant.
    assert!(owners(&engine, "POST", "/a/private/item").is_empty());
    assert_eq!(owners(&engine, "GET", "/a/item"), ["owner-broad"]);
}

#[test]
fn token_grant_owners_are_empty_without_stamped_provider_endpoints() {
    let engine =
        CedarOnlyEngine::from_proto(&provider_policy(POLICY, vec![credentialed_endpoint()]))
            .expect("policy loads");
    assert!(owners(&engine, "GET", "/v1/status").is_empty());
}

#[test]
fn token_grant_owners_fail_closed_when_tunnel_generation_is_stale() {
    let engine = owner_engine(OWNER_POLICY);
    let handle = engine.l7_handle(engine.current_generation());
    engine
        .reload_from_policy_str(OWNER_POLICY)
        .expect("reload without provider rules advances the generation");
    assert!(
        handle
            .admitted_token_grant_owners(&ctx(), &request("GET", "/a/item"))
            .is_err()
    );
}

#[test]
fn tunnel_engine_delegates_token_grant_owners_to_cedar() {
    let cedar = Arc::new(owner_engine(OWNER_POLICY));
    let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
    let tunnel = engine
        .tunnel_engine(cedar.current_generation())
        .expect("tunnel builds");
    let owners = tunnel
        .admitted_token_grant_owners(&ctx(), &request("POST", "/a/private/item"))
        .expect("owners evaluate");
    assert_eq!(
        owners,
        std::collections::HashSet::from(["owner-narrow".to_string()])
    );
}

/// A Cedar policy with `settings` as its endpoint settings.
fn settings_policy(
    cedar: &str,
    settings: Vec<openshell_core::proto::NetworkEndpoint>,
) -> ProtoSandboxPolicy {
    let mut policy = policy_from_source(cedar);
    policy.endpoint_settings = settings;
    policy
}

fn setting(host: &str, path: &str) -> openshell_core::proto::NetworkEndpoint {
    openshell_core::proto::NetworkEndpoint {
        host: host.to_string(),
        port: 443,
        path: path.to_string(),
        ..Default::default()
    }
}

fn parsed_configs(engine: &CedarOnlyEngine, host: &str) -> Vec<crate::l7::L7EndpointConfig> {
    engine
        .authorize_egress(&curl_input(host))
        .expect("request evaluates")
        .endpoint_configs
        .iter()
        .map(|config| crate::l7::parse_l7_config(config).expect("config must parse"))
        .collect()
}

fn protocol_policy(protocol: &str) -> String {
    format!(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
@protocol("{protocol}")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
"#
    )
}

/// A connect permit and REST inspection for every host matching
/// `*.example.com` on port 443, allowing `GET`.
const GLOB_INSPECTED: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
permit (principal, action == Sandbox::Action::"HttpRequest", resource is Sandbox::NetworkEndpoint)
when {
    resource.host like("*.example.com", ".") && resource.port == 443
    && context.method == "GET"
};
"#;

#[test]
fn host_glob_selects_inspection_for_every_matching_host() {
    let engine = CedarOnlyEngine::from_policy_str(GLOB_INSPECTED).expect("policy loads");
    for host in ["api.example.com", "other.example.com"] {
        let configs = parsed_configs(&engine, host);
        assert_eq!(configs.len(), 1, "{host}: {configs:?}");
        assert_eq!(configs[0].protocol, openshell_policy::L7Protocol::Rest);
        assert_eq!(configs[0].path, "");
        let guards = engine.credential_guards(host, 443).expect("guards");
        assert_eq!(
            guards.len(),
            1,
            "{host}: the credential guard sees the inspection"
        );

        // Cedar evaluates the actual host, so the glob condition decides
        // each request on the inspected tunnel.
        let handle = engine.l7_handle(engine.current_generation());
        let ctx = L7EvalContext {
            host: host.to_string(),
            ..ctx()
        };
        let (allowed, _) = handle
            .evaluate_request(&ctx, &request("GET", "/x"))
            .expect("evaluates");
        assert!(allowed, "{host}: GET is allowed");
        let (allowed, _) = handle
            .evaluate_request(&ctx, &request("DELETE", "/x"))
            .expect("evaluates");
        assert!(!allowed, "{host}: DELETE is denied");
    }

    // A host outside the glob is not allowed to connect at all.
    let denied = engine
        .authorize_egress(&curl_input("deep.api.example.com"))
        .expect("evaluates");
    assert!(matches!(denied.action, NetworkAction::Deny { .. }));
    assert!(denied.endpoint_configs.is_empty());
}

#[test]
fn exact_endpoint_paths_join_the_matching_glob_paths() {
    let policy = format!(
        r#"{GLOB_INSPECTED}
@path("/api/**") @enforcement("audit")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {{ context.path like("/api/**", "/") }};
"#
    );
    let engine = CedarOnlyEngine::from_policy_str(&policy).expect("policy loads");

    // The exact host gets a config per path of both entries, and the
    // relay routes a request to the most specific one.
    let configs = parsed_configs(&engine, "api.example.com");
    let paths: Vec<(&str, crate::l7::EnforcementMode)> = configs
        .iter()
        .map(|config| (config.path.as_str(), config.enforcement))
        .collect();
    assert_eq!(
        paths,
        vec![
            ("", crate::l7::EnforcementMode::Enforce),
            ("/api/**", crate::l7::EnforcementMode::Audit),
        ]
    );
    let guard = engine.read_engine().expect("engine");
    assert_eq!(
        guard.route_request("api.example.com", 443, "/api/items"),
        RequestRoute::Routed {
            endpoint_path: "/api/**".to_string()
        }
    );
    assert_eq!(
        guard.route_request("api.example.com", 443, "/other"),
        RequestRoute::Routed {
            endpoint_path: String::new()
        }
    );
    // Another matching host has only the glob's path.
    assert_eq!(
        guard.route_request("other.example.com", 443, "/api/items"),
        RequestRoute::Routed {
            endpoint_path: String::new()
        }
    );
    drop(guard);
    assert_eq!(parsed_configs(&engine, "other.example.com").len(), 1);
}

#[test]
fn settings_merge_into_glob_inspected_configs() {
    let mut glob_setting = setting("*.example.com", "");
    glob_setting.allow_encoded_slash = true;
    let mut exact_setting = setting("api.example.com", "");
    exact_setting.tls = openshell_core::proto::NetworkTlsMode::Skip as i32;
    let engine = LoadedPolicy::from_proto(
        &settings_policy(GLOB_INSPECTED, vec![glob_setting, exact_setting]),
        None,
        0,
    )
    .expect("policy loads");

    let api = engine.endpoint_configs("api.example.com", 443);
    assert_eq!(api.len(), 1);
    let config = crate::l7::parse_l7_config(&api[0]).expect("inspected");
    assert!(
        config.allow_encoded_slash,
        "the glob setting applies: {config:?}"
    );
    assert_eq!(crate::l7::parse_tls_mode(&api[0]), crate::l7::TlsMode::Auto);

    let other = engine.endpoint_configs("other.example.com", 443);
    assert_eq!(other.len(), 1);
    let config = crate::l7::parse_l7_config(&other[0]).expect("inspected");
    assert!(
        config.allow_encoded_slash,
        "the glob setting applies: {config:?}"
    );
    assert_eq!(
        crate::l7::parse_tls_mode(&other[0]),
        crate::l7::TlsMode::Auto,
        "the exact-host setting does not reach another host"
    );
}

#[test]
fn mcp_settings_replace_the_default_revision() {
    let mut mcp = setting("*.example.com", "");
    mcp.mcp = Some(openshell_core::proto::McpOptions {
        versions: vec!["2026-07-28".to_string(), "2025-06-18".to_string()],
        strict_tool_names: Some(false),
        ..Default::default()
    });
    mcp.json_rpc_max_body_bytes = 4096;
    let engine = CedarOnlyEngine::from_proto(&settings_policy(&protocol_policy("mcp"), vec![mcp]))
        .expect("policy loads");
    let configs = parsed_configs(&engine, "api.example.com");
    assert_eq!(configs.len(), 1);
    assert_eq!(
        configs[0].mcp_versions,
        vec![
            openshell_core::mcp::McpProtocolVersion::V2025_06_18,
            openshell_core::mcp::McpProtocolVersion::V2026_07_28,
        ]
    );
    assert!(!configs[0].mcp_strict_tool_names);
    assert_eq!(configs[0].json_rpc_max_body_bytes, 4096);

    // Without settings, the pinned default applies.
    let default = CedarOnlyEngine::from_policy_str(&protocol_policy("mcp")).expect("loads");
    let configs = parsed_configs(&default, "api.example.com");
    assert_eq!(
        configs[0].mcp_versions,
        vec![openshell_policy_schema::DEFAULT_MCP_PROTOCOL_VERSION]
    );
    assert!(configs[0].mcp_strict_tool_names);
}

#[test]
fn protocol_settings_apply_only_to_their_protocol() {
    let mut graphql = setting("api.example.com", "");
    graphql.graphql_max_body_bytes = 1024;
    graphql.persisted_queries = "allow_registered".to_string();
    graphql.mcp = Some(openshell_core::proto::McpOptions {
        versions: vec!["2025-06-18".to_string()],
        ..Default::default()
    });
    let engine =
        CedarOnlyEngine::from_proto(&settings_policy(&protocol_policy("rest"), vec![graphql]))
            .expect("policy loads");
    let config = engine
        .authorize_egress(&curl_input("api.example.com"))
        .expect("evaluates")
        .endpoint_configs
        .remove(0);
    assert_eq!(
        config.graphql_max_body_bytes, 0,
        "graphql_max_body_bytes must not apply to REST: {config:?}"
    );
    assert!(
        config.persisted_queries.is_empty(),
        "persisted_queries must not apply to REST: {config:?}"
    );
    assert!(
        config.mcp_versions.is_empty(),
        "mcp_versions must not apply to REST: {config:?}"
    );
}

#[test]
fn tls_skip_setting_applies_to_a_connect_only_endpoint() {
    let mut skip = setting("api.example.com", "");
    skip.tls = openshell_core::proto::NetworkTlsMode::Skip as i32;
    let engine = CedarOnlyEngine::from_proto(&settings_policy(CONNECT_ONLY, vec![skip.clone()]))
        .expect("policy loads");
    let authorization = engine
        .authorize_egress(&curl_input("api.example.com"))
        .expect("evaluates");
    assert_eq!(authorization.endpoint_configs.len(), 1);
    assert!(crate::l7::parse_l7_config(&authorization.endpoint_configs[0]).is_none());
    assert_eq!(
        crate::l7::parse_tls_mode(&authorization.endpoint_configs[0]),
        crate::l7::TlsMode::Skip
    );

    // The setting reaches a provider config too, which the proxy reads
    // first, so the credential guard sees the skipped TLS.
    let mut policy = provider_policy(CONNECT_ONLY, vec![credentialed_endpoint()]);
    policy.endpoint_settings = vec![skip];
    let engine = CedarOnlyEngine::from_proto(&policy).expect("policy loads");
    let guards = engine
        .credential_guards("api.example.com", 443)
        .expect("guards");
    assert_eq!(guards.len(), 1);
    assert_eq!(
        crate::l7::parse_tls_mode(&guards[0]),
        crate::l7::TlsMode::Skip
    );

    // A denied connection gets no configs.
    let denied = engine
        .authorize_egress(&curl_input("other.example.com"))
        .expect("evaluates");
    assert!(denied.endpoint_configs.is_empty());
}

#[test]
fn path_setting_adds_a_scoped_config_with_cedar_inspection() {
    let mut slash = setting("api.example.com", "/repos/**");
    slash.allow_encoded_slash = true;
    let engine =
        CedarOnlyEngine::from_proto(&settings_policy(POLICY, vec![slash])).expect("policy loads");
    let configs = parsed_configs(&engine, "api.example.com");
    assert_eq!(configs.len(), 2);
    let scoped = configs
        .iter()
        .find(|config| config.path == "/repos/**")
        .expect("scoped config");
    assert!(scoped.allow_encoded_slash);
    assert_eq!(scoped.protocol, openshell_policy::L7Protocol::Rest);
    assert_eq!(scoped.enforcement, crate::l7::EnforcementMode::Enforce);
    let base = configs
        .iter()
        .find(|config| config.path.is_empty())
        .expect("path-less config");
    assert!(!base.allow_encoded_slash);
}

#[test]
fn later_settings_override_earlier_ones() {
    let mut glob = setting("*.example.com", "");
    glob.graphql_max_body_bytes = 1024;
    let mut exact = setting("api.example.com", "");
    exact.graphql_max_body_bytes = 2048;
    let engine = CedarOnlyEngine::from_proto(&settings_policy(
        &protocol_policy("graphql"),
        vec![glob, exact],
    ))
    .expect("policy loads");
    assert_eq!(
        parsed_configs(&engine, "api.example.com")[0].graphql_max_body_bytes,
        2048
    );
}

#[test]
fn reload_tracks_endpoint_setting_changes() {
    let mut slash = setting("api.example.com", "");
    slash.allow_encoded_slash = true;
    let engine = CedarOnlyEngine::from_proto(&settings_policy(POLICY, vec![slash.clone()]))
        .expect("policy loads");
    let generation = engine.current_generation();
    let unchanged = engine
        .stage(&settings_policy(POLICY, vec![slash]), 0)
        .expect("stage");
    engine.commit(unchanged).expect("commit");
    assert_eq!(engine.current_generation(), generation);

    let changed = engine.stage(&policy_from_source(POLICY), 0).expect("stage");
    engine.commit(changed).expect("commit");
    assert_eq!(engine.current_generation(), generation + 1);
    assert!(!parsed_configs(&engine, "api.example.com")[0].allow_encoded_slash);
}

const GRAPHQL_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
@protocol("graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {
    context.graphql_operation_type == "query"
    && ["viewer"].containsAll(context.graphql_fields)
};
"#;

fn registry_setting(mode: &str) -> openshell_core::proto::NetworkEndpoint {
    let mut registry = setting("api.example.com", "");
    registry.persisted_queries = mode.to_string();
    registry.graphql_persisted_queries.insert(
        "abc123".to_string(),
        openshell_core::proto::GraphqlOperation {
            operation_type: "query".to_string(),
            operation_name: "Viewer".to_string(),
            fields: vec!["viewer".to_string()],
        },
    );
    registry.graphql_persisted_queries.insert(
        "saved-admin".to_string(),
        openshell_core::proto::GraphqlOperation {
            operation_type: "query".to_string(),
            operation_name: "Admin".to_string(),
            fields: vec!["admin".to_string()],
        },
    );
    registry
}

fn persisted(hash: Option<&str>, id: Option<&str>) -> L7RequestInfo {
    L7RequestInfo {
        graphql: Some(crate::l7::graphql::GraphqlRequestInfo {
            operations: vec![crate::l7::graphql::GraphqlOperationInfo {
                operation_type: String::new(),
                operation_name: None,
                fields: Vec::new(),
                persisted_query: true,
                persisted_query_hash: hash.map(str::to_string),
                persisted_query_id: id.map(str::to_string),
            }],
            error: None,
        }),
        ..request("POST", "/graphql")
    }
}

fn evaluate(engine: &CedarOnlyEngine, request: &L7RequestInfo) -> (bool, String) {
    engine
        .l7_handle(engine.current_generation())
        .evaluate_request(&ctx(), request)
        .expect("request evaluates")
}

#[test]
fn hash_only_persisted_queries_resolve_through_the_registry() {
    let engine = CedarOnlyEngine::from_proto(&settings_policy(
        GRAPHQL_POLICY,
        vec![registry_setting("allow_registered")],
    ))
    .expect("policy loads");
    assert!(evaluate(&engine, &persisted(Some("abc123"), None)).0);
    // The registered operation, not an empty one, is what Cedar judges.
    assert!(!evaluate(&engine, &persisted(None, Some("saved-admin"))).0);
    // The hash is the key whenever it is present.
    let (allowed, reason) = evaluate(&engine, &persisted(Some("missing"), Some("abc123")));
    assert!(!allowed);
    assert_eq!(reason, UNREGISTERED_PERSISTED_QUERY);
}

#[test]
fn hash_only_persisted_queries_are_denied_without_allow_registered() {
    for settings in [vec![registry_setting("deny")], Vec::new()] {
        let engine = CedarOnlyEngine::from_proto(&settings_policy(GRAPHQL_POLICY, settings))
            .expect("policy loads");
        let (allowed, reason) = evaluate(&engine, &persisted(Some("abc123"), None));
        assert!(!allowed);
        assert_eq!(reason, UNREGISTERED_PERSISTED_QUERY);
    }
}

#[test]
fn invalid_provider_rules_with_owners_fail_to_load() {
    let mut endpoint = owned_endpoint("owner", "/a/**", "GET");
    endpoint.protocol = "not-a-protocol".to_string();
    assert!(CedarOnlyEngine::from_proto(&provider_policy(OWNER_POLICY, vec![endpoint])).is_err());
}

/// REST under `/api/**`, GraphQL-over-WebSocket at `/ws`, and audited
/// GraphQL at `/graphql`, all on `api.example.com:443`.
const PATHS_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
@path("/api/**")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.method == "GET" && context.path like("/api/**", "/") };
@path("/ws") @protocol("websocket-graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {
    context.path == "/ws"
    && (context.method == "GET"
        || (context.method == "WEBSOCKET_TEXT"
            && context.graphql_operation_type == "subscription"))
};
@path("/graphql") @protocol("graphql") @enforcement("audit")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.path == "/graphql" && context.graphql_operation_type == "query" };
"#;

#[test]
fn each_cedar_path_gets_its_own_endpoint_config() {
    use crate::l7::EnforcementMode::{Audit, Enforce};
    use openshell_policy::L7Protocol::{Graphql, Rest, Websocket};

    let engine = CedarOnlyEngine::from_policy_str(PATHS_POLICY).expect("policy loads");
    let mut configs: Vec<_> = parsed_configs(&engine, "api.example.com")
        .into_iter()
        .map(|config| {
            (
                config.path,
                config.protocol,
                config.enforcement,
                config.websocket_graphql_policy,
            )
        })
        .collect();
    configs.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(
        configs,
        vec![
            ("/api/**".to_string(), Rest, Enforce, false),
            ("/graphql".to_string(), Graphql, Audit, false),
            ("/ws".to_string(), Websocket, Enforce, true),
        ],
        "no path-less config: no policy lacks @path"
    );
}

#[test]
fn requests_take_the_inspection_of_their_routed_path() {
    let engine = CedarOnlyEngine::from_policy_str(PATHS_POLICY).expect("policy loads");
    let evaluate = |request: &L7RequestInfo| {
        engine
            .l7_handle(engine.current_generation())
            .evaluate_request(&ctx_for("api.example.com"), request)
            .expect("request evaluates")
    };
    assert!(evaluate(&request("GET", "/api/items")).0);
    assert_eq!(
        evaluate(&request("GET", "/other")),
        (false, UNMATCHED_PATH.to_string()),
        "no inspected path matches, as the relay denies it"
    );
    assert!(evaluate(&request("GET", "/ws")).0, "the upgrade");
    let message = |operation_type: &str| L7RequestInfo {
        graphql: Some(crate::l7::graphql::GraphqlRequestInfo {
            operations: vec![crate::l7::graphql::GraphqlOperationInfo {
                operation_type: operation_type.to_string(),
                operation_name: None,
                fields: vec!["messageAdded".to_string()],
                persisted_query: false,
                persisted_query_hash: None,
                persisted_query_id: None,
            }],
            error: None,
        }),
        ..request("WEBSOCKET_TEXT", "/ws")
    };
    assert!(evaluate(&message("subscription")).0);
    assert!(!evaluate(&message("mutation")).0);
    // Routed to the audit path, the denial is reported for the relay to
    // log and forward.
    let mutation = L7RequestInfo {
        graphql: message("mutation").graphql,
        ..request("POST", "/graphql")
    };
    assert!(!evaluate(&mutation).0);
}

fn ctx_for(host: &str) -> L7EvalContext {
    L7EvalContext {
        host: host.to_string(),
        ..ctx()
    }
}

#[test]
fn provider_endpoints_take_the_inspection_of_their_path() {
    let mut ws = credentialed_endpoint();
    ws.path = "/ws".to_string();
    let mut unrelated = credentialed_endpoint();
    unrelated.path = "/elsewhere/**".to_string();
    let engine = CedarOnlyEngine::from_proto(&provider_policy(PATHS_POLICY, vec![ws, unrelated]))
        .expect("policy loads");
    let configs = engine
        .credential_guards("api.example.com", 443)
        .expect("configs build");
    let provider = |path: &str| {
        configs
            .iter()
            .find(|config| {
                config.path == path
                    && crate::l7::parse_endpoint_credential_guard(config).provider_credentialed
            })
            .expect("provider config")
    };
    let ws = crate::l7::parse_l7_config(provider("/ws")).expect("inspected");
    assert_eq!(ws.protocol, openshell_policy::L7Protocol::Websocket);
    assert!(ws.websocket_graphql_policy);
    // No Cedar path covers the provider path, so its config is not an L7
    // config and the relay never routes requests to it.
    assert!(crate::l7::parse_l7_config(provider("/elsewhere/**")).is_none());
    assert_eq!(
        configs.len(),
        4,
        "two provider configs plus /api/** and /graphql"
    );
}

#[test]
fn path_settings_follow_cedar_inspection() {
    let mut registry = setting("api.example.com", "/ws");
    registry.persisted_queries = "allow_registered".to_string();
    let mut uninspected = setting("api.example.com", "/elsewhere/**");
    uninspected.allow_encoded_slash = true;
    let mut nested = setting("api.example.com", "/api/v2/**");
    nested.allow_encoded_slash = true;
    let engine = CedarOnlyEngine::from_proto(&settings_policy(
        PATHS_POLICY,
        vec![registry, uninspected, nested],
    ))
    .expect("policy loads");
    let configs = parsed_configs(&engine, "api.example.com");
    let paths: Vec<&str> = configs.iter().map(|config| config.path.as_str()).collect();
    assert_eq!(paths, ["/api/**", "/graphql", "/ws", "/api/v2/**"]);
    let nested = &configs[3];
    assert_eq!(nested.protocol, openshell_policy::L7Protocol::Rest);
    assert!(nested.allow_encoded_slash);
}

#[test]
fn plain_websocket_endpoints_take_no_graphql_settings() {
    let mut registry = setting("api.example.com", "");
    registry.persisted_queries = "allow_registered".to_string();
    let engine = CedarOnlyEngine::from_proto(&settings_policy(
        &protocol_policy("websocket"),
        vec![registry],
    ))
    .expect("policy loads");
    let configs = parsed_configs(&engine, "api.example.com");
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].protocol, openshell_policy::L7Protocol::Websocket);
    assert!(
        !configs[0].websocket_graphql_policy,
        "a persisted-query setting must not turn on GraphQL message policy"
    );
}

const QUERY_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.query.hasTag("tag") && context.query.getTag("tag") like "foo-*" };
"#;

fn with_query(query: &[(&str, &[&str])]) -> L7RequestInfo {
    L7RequestInfo {
        query_params: query
            .iter()
            .map(|(key, values)| {
                (
                    (*key).to_string(),
                    values.iter().map(ToString::to_string).collect(),
                )
            })
            .collect(),
        ..request("GET", "/download")
    }
}

#[test]
fn query_params_reach_cedar_decoded() {
    let engine = CedarOnlyEngine::from_policy_str(QUERY_POLICY).expect("policy parses");
    let tunnel = engine.l7_handle(engine.current_generation());
    let decide = |query: &[(&str, &[&str])]| {
        tunnel
            .evaluate_request(&ctx(), &with_query(query))
            .expect("request evaluates")
    };
    assert!(decide(&[("tag", &["foo-a", "foo-b"])]).0);
    assert!(!decide(&[("tag", &["foo-a", "evil"])]).0);
    assert!(!decide(&[]).0);

    // Through the relay's parser, which decodes keys and values.
    let (_, parsed) = crate::l7::rest::parse_target_query("/download?t%61g=foo%2Da&tag=foo-x+y")
        .expect("target parses");
    let mut request = request("GET", "/download");
    request.query_params = parsed;
    assert!(tunnel.evaluate_request(&ctx(), &request).unwrap().0);
}

#[test]
fn query_over_the_combination_cap_is_denied_with_a_reason() {
    let engine = CedarOnlyEngine::from_policy_str(QUERY_POLICY).expect("policy parses");
    let tunnel = engine.l7_handle(engine.current_generation());
    let values: Vec<String> = (0..=openshell_policy_cedar::MAX_QUERY_COMBINATIONS)
        .map(|value| format!("foo-{value}"))
        .collect();
    let values: Vec<&str> = values.iter().map(String::as_str).collect();
    let (allowed, reason) = tunnel
        .evaluate_request(&ctx(), &with_query(&[("tag", &values)]))
        .expect("an over-cap query is a decision, not an error");
    assert!(!allowed);
    assert!(reason.contains("value combinations"), "{reason}");
    let (allowed, _) = tunnel
        .evaluate_request(&ctx(), &with_query(&[("tag", &values[1..])]))
        .unwrap();
    assert!(allowed, "the cap itself is evaluated");
}

/// A connect permit and an HTTP forbid that name `/usr/bin/python3`
/// through its symlink aliases only.
const ALIAS_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.binary_aliases.contains("/usr/bin/python3") };

permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");

forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.binary_aliases.contains("/usr/bin/python3") && context.method == "DELETE" };
"#;

fn alias_set(entries: &[(&str, &str)]) -> BinaryAliases {
    BinaryAliases(
        entries
            .iter()
            .map(|(path, target)| ((*path).to_string(), AliasTarget::new((*target).to_string())))
            .collect(),
    )
}

#[test]
fn aliases_match_the_binary_or_an_ancestor_exactly() {
    let aliases = alias_set(&[
        ("/usr/bin/python3", "/usr/bin/python3.11"),
        ("/usr/bin/node", "/opt/node/bin/node"),
    ]);
    let matching = |binary: &str, ancestors: &[&str]| {
        let ancestors: Vec<String> = ancestors.iter().map(ToString::to_string).collect();
        aliases.matching(binary, &ancestors).expect("matches")
    };
    assert_eq!(matching("/usr/bin/python3.11", &[]), ["/usr/bin/python3"]);
    assert_eq!(
        matching("/usr/bin/curl", &["/bin/bash", "/opt/node/bin/node"]),
        ["/usr/bin/node"]
    );
    // The symlink itself and near misses are not aliases.
    assert!(matching("/usr/bin/python3", &[]).is_empty());
    assert!(matching("/usr/bin/python3.1", &["/usr/bin/python3.11x"]).is_empty());
}

#[test]
fn a_glob_target_matches_as_the_rego_rules_match_it() {
    let aliases = alias_set(&[("/usr/bin/tool", "/opt/*/tool")]);
    let matching = |binary: &str| aliases.matching(binary, &[]).expect("matches");
    assert_eq!(matching("/opt/v2/tool"), ["/usr/bin/tool"]);
    // `*` does not cross `/`, as in `glob.match(path, ["/"], p)`.
    assert!(matching("/opt/v2/bin/tool").is_empty());

    let invalid = alias_set(&[("/usr/bin/tool", "/opt/[*/tool")]);
    assert!(invalid.matching("/opt/v2/tool", &[]).is_err());
}

#[test]
fn requests_carry_the_aliases_of_their_binary() {
    let engine = CedarOnlyEngine::from_policy_str(ALIAS_POLICY).expect("policy loads");
    let python = NetworkInput {
        binary_path: "/usr/bin/python3.11".into(),
        ..curl_input("api.example.com")
    };
    let allowed = |engine: &CedarOnlyEngine| {
        matches!(
            engine.authorize_egress(&python).expect("evaluates").action,
            NetworkAction::Allow { .. }
        )
    };
    assert!(!allowed(&engine), "no alias before resolution");

    engine.write_engine().expect("lock").binary_aliases =
        alias_set(&[("/usr/bin/python3", "/usr/bin/python3.11")]);
    assert!(allowed(&engine));
    let python_ctx = L7EvalContext {
        binary_path: "/usr/bin/python3.11".to_string(),
        ..ctx()
    };
    let evaluate = |method: &str| {
        engine
            .l7_handle(engine.current_generation())
            .evaluate_request(&python_ctx, &request(method, "/v1/status"))
            .expect("evaluates")
            .0
    };
    assert!(evaluate("GET"));
    assert!(!evaluate("DELETE"), "the forbid reaches the alias");
    let curl = engine
        .l7_handle(engine.current_generation())
        .evaluate_request(&ctx(), &request("DELETE", "/v1/status"))
        .expect("evaluates")
        .0;
    assert!(curl, "another binary has no alias");
}

/// A connect permit and an HTTP forbid for the YAML binary glob
/// `/usr/lib/node_modules/@openai/**`.
const GLOB_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.binary_globs.contains("/usr/lib/node_modules/@openai/**") };

permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");

forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.binary_globs.contains("/opt/*/tool") && context.method == "DELETE" };
"#;

#[test]
fn binary_globs_match_the_binary_or_an_ancestor_as_the_rego_rules_do() {
    let engine = CedarOnlyEngine::from_policy_str(GLOB_POLICY).expect("policy loads");
    let globs = &engine.read_engine().expect("lock").binary_globs;
    let matching = |binary: &str, ancestors: &[&str]| {
        let ancestors: Vec<String> = ancestors.iter().map(ToString::to_string).collect();
        globs.matching(binary, &ancestors).expect("matches")
    };
    assert_eq!(
        matching("/usr/lib/node_modules/@openai/codex/bin/codex.js", &[]),
        ["/usr/lib/node_modules/@openai/**"]
    );
    assert_eq!(
        matching(
            "/usr/bin/node",
            &["/bin/sh", "/usr/lib/node_modules/@openai/codex"]
        ),
        ["/usr/lib/node_modules/@openai/**"]
    );
    // `*` does not cross `/`, as in `glob.match(path, ["/"], p)`.
    assert_eq!(matching("/opt/v2/tool", &[]), ["/opt/*/tool"]);
    assert!(matching("/opt/v2/bin/tool", &[]).is_empty());
    assert!(matching("/usr/lib/node_modules/@other/x", &["/usr/bin/node"]).is_empty());
}

#[test]
fn requests_carry_the_globs_matching_their_binary() {
    let engine = CedarOnlyEngine::from_policy_str(GLOB_POLICY).expect("policy loads");
    let connect = |binary: &str, ancestors: &[&str]| {
        let input = NetworkInput {
            binary_path: binary.into(),
            ancestors: ancestors.iter().map(std::path::PathBuf::from).collect(),
            ..curl_input("api.example.com")
        };
        matches!(
            engine.authorize_egress(&input).expect("evaluates").action,
            NetworkAction::Allow { .. }
        )
    };
    assert!(connect(
        "/usr/bin/node",
        &["/usr/lib/node_modules/@openai/codex/bin/codex.js"]
    ));
    assert!(!connect("/usr/bin/node", &["/usr/bin/bash"]));

    let tool_ctx = L7EvalContext {
        binary_path: "/usr/bin/curl".to_string(),
        ancestors: vec!["/opt/v1/tool".to_string()],
        ..ctx()
    };
    let evaluate = |ctx: &L7EvalContext, method: &str| {
        engine
            .l7_handle(engine.current_generation())
            .evaluate_request(ctx, &request(method, "/v1/status"))
            .expect("evaluates")
            .0
    };
    assert!(evaluate(&tool_ctx, "GET"));
    assert!(
        !evaluate(&tool_ctx, "DELETE"),
        "the forbid reaches the ancestor"
    );
    assert!(
        evaluate(&ctx(), "DELETE"),
        "another process matches no glob"
    );
}

#[test]
fn token_grant_binary_globs_match_ancestors() {
    // The provider rule names a binary glob; a YAML sandbox admits the
    // owner for a process whose ancestor the glob matches.
    let mut policy = provider_policy(
        OWNER_POLICY,
        vec![owned_endpoint("owner-broad", "/a/**", "GET")],
    );
    policy
        .provider_credential_rules
        .get_mut("_provider_work")
        .expect("provider rule")
        .binaries
        .push(openshell_core::proto::NetworkBinary {
            path: "/opt/tools/*".to_string(),
        });
    let engine = CedarOnlyEngine::from_proto(&policy).expect("policy loads");
    assert_eq!(
        engine
            .read_engine()
            .expect("lock")
            .binary_globs
            .matching("/usr/bin/curl", &["/opt/tools/run".to_string()])
            .expect("matches"),
        ["/opt/tools/*"]
    );
    let owners = |ancestors: &[&str]| {
        let ctx = L7EvalContext {
            ancestors: ancestors.iter().map(ToString::to_string).collect(),
            ..ctx()
        };
        engine
            .l7_handle(engine.current_generation())
            .admitted_token_grant_owners(&ctx, &request("GET", "/a/item"))
            .expect("owners evaluate")
            .into_iter()
            .collect::<Vec<_>>()
    };
    assert_eq!(owners(&["/opt/tools/run"]), ["owner-broad"]);
    assert!(owners(&["/usr/bin/bash"]).is_empty());
}

#[test]
fn requests_parsed_as_graphql_are_flagged_for_cedar() {
    // A broad REST permit never allows a GraphQL operation on the
    // GraphQL path, as a YAML GraphQL endpoint is authoritative for the
    // requests it parses; the same request without GraphQL inspection
    // sees the REST permit.
    let engine = CedarOnlyEngine::from_policy_str(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
@path("/**")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.method == "GET" };
@path("/graphql") @protocol("graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.path == "/graphql" && context.graphql_operation_type == "query" };
"#,
    )
    .expect("policy loads");
    let evaluate = |request: &L7RequestInfo| {
        engine
            .l7_handle(engine.current_generation())
            .evaluate_request(&ctx(), request)
            .expect("evaluates")
            .0
    };
    let operation = |operation_type: &str| L7RequestInfo {
        graphql: Some(crate::l7::graphql::GraphqlRequestInfo {
            operations: vec![crate::l7::graphql::GraphqlOperationInfo {
                operation_type: operation_type.to_string(),
                operation_name: None,
                fields: vec!["viewer".to_string()],
                persisted_query: false,
                persisted_query_hash: None,
                persisted_query_id: None,
            }],
            error: None,
        }),
        ..request("GET", "/graphql")
    };
    assert!(evaluate(&operation("query")));
    assert!(
        !evaluate(&operation("mutation")),
        "the REST permit is left out"
    );
    assert!(
        evaluate(&request("GET", "/graphql")),
        "not parsed as GraphQL"
    );
    assert!(evaluate(&request("GET", "/other")));
}

#[test]
fn audit_policies_decide_requests_routed_to_an_enforced_path() {
    // YAML applies the rules of every matching endpoint and the selected
    // endpoint's enforcement decides whether a denial blocks: the audit
    // path's forbid blocks on the enforced path and is forwarded on its
    // own path.
    let engine = CedarOnlyEngine::from_policy_str(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
@path("/**") @enforcement("audit")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.method == "GET" };
@path("/**") @enforcement("audit")
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.method == "DELETE" };
@path("/api/**")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { ["DELETE", "POST"].contains(context.method) && context.path like("/api/**", "/") };
@path("/api/**") @enforcement("staged")
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.method == "POST" };
"#,
    )
    .expect("policy loads");
    let configs: HashMap<String, crate::l7::EnforcementMode> =
        parsed_configs(&engine, "api.example.com")
            .into_iter()
            .map(|config| (config.path, config.enforcement))
            .collect();
    assert_eq!(configs["/**"], crate::l7::EnforcementMode::Audit);
    assert_eq!(configs["/api/**"], crate::l7::EnforcementMode::Enforce);
    let evaluate = |method: &str, target: &str| {
        engine
            .l7_handle(engine.current_generation())
            .evaluate_request(&ctx(), &request(method, target))
            .expect("evaluates")
            .0
    };
    assert!(!evaluate("DELETE", "/api/item"), "the audit forbid decides");
    assert!(evaluate("GET", "/api/item"), "the audit permit decides");
    assert!(
        evaluate("POST", "/api/item"),
        "the staged forbid never decides"
    );
    assert!(
        !evaluate("DELETE", "/other"),
        "forwarded by the relay on the audit path"
    );
}

#[test]
fn the_entrypoint_pid_is_kept_across_reloads() {
    const PID: u32 = 4242;
    let engine = CedarOnlyEngine::from_policy_str(ALIAS_POLICY).expect("policy loads");
    let generation = engine.current_generation();
    engine.resolve_binary_symlinks(0).expect("resolves");
    assert_eq!(engine.current_generation(), generation, "0 is a no-op");

    engine.resolve_binary_symlinks(PID).expect("resolves");
    assert_eq!(engine.current_generation(), generation + 1);
    engine.resolve_binary_symlinks(PID).expect("resolves");
    assert_eq!(engine.current_generation(), generation + 1, "same pid");

    // A reload that does not know the pid resolves for the known one.
    engine
        .reload_from_policy_str(POLICY)
        .expect("reload succeeds");
    assert_eq!(engine.read_engine().expect("lock").entrypoint_pid, PID);
}

#[test]
fn a_policy_staged_before_the_pid_is_resolved_on_commit() {
    const PID: u32 = 4242;
    let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy loads");
    let changed = engine
        .stage(&policy_from_source(ALIAS_POLICY), 0)
        .expect("stage");
    engine.resolve_binary_symlinks(PID).expect("resolves");
    engine.commit(changed).expect("commit");
    assert_eq!(engine.read_engine().expect("lock").entrypoint_pid, PID);

    // An unchanged policy staged with a new pid resolves the active one.
    let other = CedarOnlyEngine::from_policy_str(ALIAS_POLICY).expect("policy loads");
    let generation = other.current_generation();
    let unchanged = other
        .stage(&policy_from_source(ALIAS_POLICY), PID)
        .expect("stage");
    other.commit(unchanged).expect("commit");
    assert_eq!(other.read_engine().expect("lock").entrypoint_pid, PID);
    assert_eq!(other.current_generation(), generation + 1);
}

#[test]
fn a_policy_prepared_before_startup_keeps_the_resolved_pid() {
    let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy loads");
    let staged = engine
        .stage(&policy_from_source(ALIAS_POLICY), 0)
        .expect("stage");
    let prepared = engine
        .prepare_policy(staged.policy, staged.entrypoint_pid)
        .expect("prepare");
    engine
        .resolve_binary_symlinks(std::process::id())
        .expect("startup resolves");
    let (locks, prepared) = engine
        .prepare_publication(prepared)
        .expect("prepare publication");
    engine.publish_policy(locks, prepared, false);
    assert_eq!(
        engine.read_engine().expect("engine").entrypoint_pid,
        std::process::id()
    );
}

#[test]
fn provider_tls_skip_cannot_bypass_cedar_inspection_on_another_path() {
    let mut endpoint = credentialed_endpoint();
    endpoint.path = "/uninspected/**".into();
    endpoint.tls = openshell_core::proto::NetworkTlsMode::Skip as i32;
    for source in [POLICY, PATHS_POLICY] {
        let engine =
            LoadedPolicy::from_proto(&provider_policy(source, vec![endpoint.clone()]), None, 0)
                .expect("policy loads");
        let configs = engine.endpoint_configs("api.example.com", 443);
        assert!(configs.iter().all(|config| config.tls == TlsSetting::Auto));
        assert!(
            configs
                .iter()
                .any(|config| crate::l7::parse_l7_config(config).is_some())
        );
    }
    let engine = LoadedPolicy::from_proto(&provider_policy(CONNECT_ONLY, vec![endpoint]), None, 0)
        .expect("policy loads");
    assert_eq!(
        engine.endpoint_configs("api.example.com", 443)[0].tls,
        TlsSetting::Skip
    );
}

/// Resolves a real symlink through `/proc/<pid>/root`, as for YAML.
#[cfg(target_os = "linux")]
#[test]
fn resolution_finds_symlinked_policy_binaries() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("python3.11");
    let link = dir.path().join("python3");
    std::fs::write(&target, b"python").expect("target");
    symlink(&target, &link).expect("symlink");
    let pid = std::process::id();
    if crate::binary_resolution::resolve_policy_binary(&link.to_string_lossy(), pid).is_none() {
        eprintln!("Skipping: /proc/<pid>/root/ not accessible in this environment");
        return;
    }

    let policy = ALIAS_POLICY.replace("/usr/bin/python3", &link.to_string_lossy());
    let engine = CedarOnlyEngine::from_policy_str(&policy).expect("policy loads");
    let allowed = |binary: &std::path::Path| {
        let input = NetworkInput {
            binary_path: binary.to_path_buf(),
            ..curl_input("api.example.com")
        };
        matches!(
            engine.authorize_egress(&input).expect("evaluates").action,
            NetworkAction::Allow { .. }
        )
    };
    assert!(!allowed(&target), "denied before the pid is known");
    engine.resolve_binary_symlinks(pid).expect("resolves");
    assert!(allowed(&target), "allowed once the symlink resolves");

    // A reload of the same policy resolves the link again, as a YAML
    // reload does, so a retargeted link loses its old alias.
    let retarget = dir.path().join("python3.12");
    std::fs::write(&retarget, b"python").expect("new target");
    std::fs::remove_file(&link).expect("remove link");
    symlink(&retarget, &link).expect("symlink");
    let generation = engine.current_generation();
    let unchanged = engine
        .stage(&policy_from_source(&policy), pid)
        .expect("stage");
    engine.commit(unchanged).expect("commit");
    assert_eq!(engine.current_generation(), generation + 1);
    assert!(!allowed(&target), "the old target is no longer an alias");
    assert!(allowed(&retarget), "the new target is");
}
