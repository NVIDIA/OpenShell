// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks that load-time analysis derives inspection and warnings from what
//! a policy set enforces: staged policies never change inspection, audit
//! warnings consider every entry that can route a request, forbids cannot
//! deny before resolution because the address is absent, identity
//! attributes that requests do not carry and tests of which process the
//! principal is are rejected, and host overlap analysis stays bounded.

use std::time::{Duration, Instant};

use openshell_policy_cedar::{
    AnalysisWarning, CedarEngine, CedarEngineError, HttpRequestInput, L7Enforcement, L7Protocol,
    NetworkConnectRequest,
};

/// The largest Cedar policy source the gateway accepts.
const MAX_POLICY_BYTES: usize = 262_144;

fn engine(policy: &str) -> CedarEngine {
    CedarEngine::from_policy_str(policy).expect("policy must load")
}

fn rejection(policy: &str) -> CedarEngineError {
    CedarEngine::from_policy_str(policy).expect_err("policy must be rejected")
}

/// An `HttpRequest` policy on `host:443`, named in its scope.
fn http_policy(annotations: &str, effect: &str, host: &str, condition: &str) -> String {
    format!(
        r#"{annotations}
{effect} (principal, action == Sandbox::Action::"HttpRequest",
          resource == Sandbox::NetworkEndpoint::"{host}:443")
when {{ {condition} }};
"#
    )
}

/// An `HttpRequest` policy on the hosts `glob` matches on port 443.
fn glob_policy(annotations: &str, effect: &str, glob: &str, condition: &str) -> String {
    format!(
        r#"{annotations}
{effect} (principal, action == Sandbox::Action::"HttpRequest",
          resource is Sandbox::NetworkEndpoint)
when {{ resource.host like("{glob}", ".") && resource.port == 443 && {condition} }};
"#
    )
}

/// A `NetworkConnect` permit for `host:443`.
fn connect_permit(host: &str) -> String {
    format!(
        r#"permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"{host}:443");
"#
    )
}

fn request(host: &str, method: &str, path: &str, endpoint_path: &str) -> HttpRequestInput {
    HttpRequestInput {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        binary_path: "/usr/bin/curl".to_string(),
        host: host.to_string(),
        port: 443,
        method: method.to_string(),
        path: path.to_string(),
        endpoint_path: endpoint_path.to_string(),
        ..Default::default()
    }
}

fn connect(host: &str, ip: Option<&str>) -> NetworkConnectRequest {
    NetworkConnectRequest {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        host: host.to_string(),
        port: 443,
        binary_path: "/usr/bin/curl".to_string(),
        ancestors: Vec::new(),
        binary_aliases: Vec::new(),
        binary_globs: Vec::new(),
        destination_ip: ip.map(|ip| ip.parse().expect("test address parses")),
    }
}

/// Every configured inspection, without the staged comparison flag.
fn inspection(engine: &CedarEngine) -> Vec<(String, u16, String, L7Protocol, L7Enforcement)> {
    engine
        .configured_l7_endpoints()
        .map(|(host, port, path, endpoint)| {
            (host, port, path, endpoint.protocol, endpoint.enforcement)
        })
        .collect()
}

// ── Staged policies never change inspection (F6) ──────────────────────────

/// Asserts that adding `staged` to `base` leaves inspection, `HttpRequest`
/// decisions, and `NetworkConnect` decisions unchanged, and returns the
/// engine with the staged policies.
fn assert_staged_changes_nothing(
    base: &str,
    staged: &str,
    requests: &[HttpRequestInput],
) -> CedarEngine {
    let without = engine(base);
    let with = engine(&format!("{base}{staged}"));
    assert_eq!(inspection(&with), inspection(&without), "inspection");
    for request in requests {
        assert_eq!(
            with.l7_endpoints(&request.host, request.port)
                .map(|(path, endpoint)| (path, endpoint.protocol, endpoint.enforcement))
                .collect::<Vec<_>>(),
            without
                .l7_endpoints(&request.host, request.port)
                .map(|(path, endpoint)| (path, endpoint.protocol, endpoint.enforcement))
                .collect::<Vec<_>>(),
            "{} paths",
            request.host
        );
        assert_eq!(
            with.evaluate_l7(request).unwrap().decision,
            without.evaluate_l7(request).unwrap().decision,
            "{} {} {}",
            request.method,
            request.host,
            request.path
        );
        let connection = connect(&request.host, None);
        assert_eq!(
            with.evaluate_network(&connection).unwrap(),
            without.evaluate_network(&connection).unwrap(),
            "connect {}",
            request.host
        );
    }
    with
}

#[test]
fn a_staged_policy_does_not_make_a_connect_only_endpoint_inspected() {
    let base = connect_permit("api.github.com");
    let staged = http_policy(
        r#"@enforcement("staged") @id("no-delete")"#,
        "forbid",
        "api.github.com",
        r#"context.method == "DELETE""#,
    );
    let with = assert_staged_changes_nothing(
        &base,
        &staged,
        &[request("api.github.com", "GET", "/repos/a/b", "")],
    );
    assert!(inspection(&with).is_empty());
    assert_eq!(with.l7_endpoint("api.github.com", 443), None);
    assert_eq!(
        with.warnings(),
        [AnalysisWarning::StagedPolicyNotEvaluated {
            policy_id: "no-delete".to_string(),
            endpoint: "api.github.com:443".to_string(),
        }]
    );
    assert!(
        with.warnings()[0]
            .to_string()
            .contains("never evaluated until a deciding HttpRequest policy names the endpoint"),
        "{}",
        with.warnings()[0]
    );
}

#[test]
fn staged_path_and_protocol_annotations_do_not_change_inspection() {
    let base = format!(
        "{}{}",
        connect_permit("api.github.com"),
        http_policy("", "permit", "api.github.com", r#"context.method == "GET""#),
    );
    let staged = format!(
        "{}{}",
        http_policy(
            r#"@enforcement("staged") @path("/graphql") @protocol("graphql") @id("gql")"#,
            "permit",
            "api.github.com",
            r#"context.graphql_operation_type == "query""#,
        ),
        http_policy(
            r#"@enforcement("staged") @protocol("websocket") @id("ws")"#,
            "forbid",
            "api.github.com",
            r#"context.method == "WEBSOCKET_TEXT""#,
        ),
    );
    let with = assert_staged_changes_nothing(
        &base,
        &staged,
        &[
            request("api.github.com", "GET", "/repos/a/b", ""),
            request("api.github.com", "POST", "/graphql", ""),
        ],
    );
    assert_eq!(
        inspection(&with),
        [(
            "api.github.com".to_string(),
            443,
            String::new(),
            L7Protocol::Rest,
            L7Enforcement::Enforce
        )]
    );
    assert_eq!(
        with.warnings(),
        [
            AnalysisWarning::StagedPolicyInspectionIgnored {
                policy_id: "gql".to_string(),
                endpoint: "api.github.com:443".to_string(),
                path: "/graphql".to_string(),
                protocol: Some(L7Protocol::Graphql),
            },
            AnalysisWarning::StagedPolicyInspectionIgnored {
                policy_id: "ws".to_string(),
                endpoint: "api.github.com:443".to_string(),
                path: String::new(),
                protocol: Some(L7Protocol::Websocket),
            },
        ]
    );
    let warning = with.warnings()[0].to_string();
    assert!(
        warning.starts_with(
            "staged policy \"gql\" declares @path(\"/graphql\") @protocol(\"graphql\") on \
             api.github.com:443"
        ),
        "{warning}"
    );
}

#[test]
fn a_staged_protocol_that_differs_from_a_deciding_one_loads() {
    // Two deciding policies declaring different protocols for one path are
    // rejected; a staged one never declares a protocol, so it only warns.
    let base = http_policy(
        r#"@protocol("graphql")"#,
        "permit",
        "api.github.com",
        r#"context.graphql_operation_type == "query""#,
    );
    let staged = http_policy(
        r#"@enforcement("staged") @protocol("rest") @id("rest")"#,
        "forbid",
        "api.github.com",
        r#"context.method == "DELETE""#,
    );
    let with = assert_staged_changes_nothing(
        &base,
        &staged,
        &[request("api.github.com", "POST", "/graphql", "")],
    );
    assert_eq!(
        with.warnings(),
        [AnalysisWarning::StagedPolicyInspectionIgnored {
            policy_id: "rest".to_string(),
            endpoint: "api.github.com:443".to_string(),
            path: String::new(),
            protocol: Some(L7Protocol::Rest),
        }]
    );
    let enforced = format!(
        "{base}{}",
        http_policy(
            r#"@protocol("rest")"#,
            "forbid",
            "api.github.com",
            r#"context.method == "DELETE""#
        )
    );
    assert!(matches!(
        rejection(&enforced),
        CedarEngineError::ConflictingL7Protocol { .. }
    ));
}

#[test]
fn a_staged_policy_matching_the_deciding_inspection_does_not_warn() {
    let base = http_policy(
        r#"@path("/repos/**")"#,
        "permit",
        "api.github.com",
        r#"context.method == "GET""#,
    );
    let staged = http_policy(
        r#"@enforcement("staged") @path("/repos/**") @protocol("rest")"#,
        "forbid",
        "api.github.com",
        r#"context.path like("/repos/*/*/hooks", "/")"#,
    );
    let with = assert_staged_changes_nothing(
        &base,
        &staged,
        &[request(
            "api.github.com",
            "GET",
            "/repos/a/b/hooks",
            "/repos/**",
        )],
    );
    assert_eq!(with.warnings(), []);
    let hooks = with
        .evaluate_l7(&request(
            "api.github.com",
            "GET",
            "/repos/a/b/hooks",
            "/repos/**",
        ))
        .unwrap();
    assert!(hooks.is_allow());
    assert!(hooks.staged.is_some_and(|staged| !staged.is_allow()));
}

#[test]
fn a_staged_policy_is_compared_on_every_entry_that_selects_its_host() {
    // The deciding policy is a glob; the staged forbid names one host it
    // matches, so requests to that host are compared through the glob entry.
    let base = glob_policy("", "permit", "*.github.com", r#"context.method == "GET""#);
    let staged = format!(
        "{}{}",
        http_policy(
            r#"@enforcement("staged") @id("no-hooks")"#,
            "forbid",
            "api.github.com",
            r#"context.path like("/repos/*/*/hooks", "/")"#,
        ),
        glob_policy(
            r#"@enforcement("staged") @id("gitlab")"#,
            "forbid",
            "*.gitlab.com",
            "true",
        ),
    );
    let with = assert_staged_changes_nothing(
        &base,
        &staged,
        &[
            request("api.github.com", "GET", "/repos/a/b/hooks", ""),
            request("www.github.com", "GET", "/repos/a/b/hooks", ""),
        ],
    );
    assert_eq!(
        with.warnings(),
        [AnalysisWarning::StagedPolicyNotEvaluated {
            policy_id: "gitlab".to_string(),
            endpoint: "*.gitlab.com:443".to_string(),
        }]
    );
    let hooks = with
        .evaluate_l7(&request("api.github.com", "GET", "/repos/a/b/hooks", ""))
        .unwrap();
    assert!(hooks.is_allow(), "a staged forbid never denies");
    assert!(
        hooks.staged.is_some_and(|staged| !staged.is_allow()),
        "the staged forbid is compared through the glob entry"
    );
    let other = with
        .evaluate_l7(&request("www.github.com", "GET", "/repos/a/b/hooks", ""))
        .unwrap();
    assert_eq!(other.staged, None, "the staged forbid names another host");
}

#[test]
fn a_staged_glob_is_compared_on_an_exact_entry_that_declares_the_routed_path() {
    // The exact entry declares the path requests to api.github.com are
    // routed to, so its inspection, not the glob's, decides them.
    let exact = http_policy(
        r#"@path("/repos/**")"#,
        "permit",
        "api.github.com",
        r#"context.method == "GET""#,
    );
    let staged = glob_policy(
        r#"@enforcement("staged") @id("no-hooks")"#,
        "forbid",
        "*.github.com",
        r#"context.path like("/repos/*/*/hooks", "/")"#,
    );
    let hooks = request("api.github.com", "GET", "/repos/a/b/hooks", "/repos/**");
    for base in [
        exact.clone(),
        format!(
            "{exact}{}",
            glob_policy("", "permit", "*.github.com", r#"context.method == "POST""#)
        ),
    ] {
        let with = assert_staged_changes_nothing(&base, &staged, std::slice::from_ref(&hooks));
        let evaluation = with.evaluate_l7(&hooks).unwrap();
        assert!(evaluation.is_allow(), "a staged forbid never denies");
        assert!(
            evaluation.staged.is_some_and(|staged| !staged.is_allow()),
            "the staged glob is compared through the exact entry: {base}"
        );
    }
}

// ── Audit warnings over every entry that can route a request (F5) ─────────

#[test]
fn an_audit_path_beside_an_enforced_glob_warns() {
    // DELETE /repos/o/r on api.github.com routes to the audit path, so the
    // glob's enforced forbid is only logged, as RFC 0020 specifies; the
    // author is warned.
    let policy = format!(
        "{}{}{}",
        glob_policy(
            r#"@id("no-delete")"#,
            "forbid",
            "*.github.com",
            r#"context.method == "DELETE""#
        ),
        glob_policy("", "permit", "*.github.com", r#"context.method == "GET""#),
        http_policy(
            r#"@enforcement("audit") @path("/repos/**")"#,
            "permit",
            "api.github.com",
            r#"context.path like("/repos/**", "/")"#,
        ),
    );
    let engine = engine(&policy);
    assert_eq!(
        engine.warnings(),
        [AnalysisWarning::AuditPathOnEnforcedEndpoint {
            endpoint: "api.github.com:443".to_string(),
            path: "/repos/**".to_string(),
        }]
    );
    let routed = engine
        .l7_endpoint_at("api.github.com", 443, "/repos/**")
        .expect("the audit path is inspected");
    assert_eq!(routed.enforcement, L7Enforcement::Audit);
    assert!(
        !engine
            .evaluate_l7(&request(
                "api.github.com",
                "DELETE",
                "/repos/o/r",
                "/repos/**"
            ))
            .unwrap()
            .is_allow(),
        "the enforced forbid still decides; the audit path logs and forwards"
    );
}

#[test]
fn an_audit_glob_path_beside_an_enforced_exact_host_warns() {
    let policy = format!(
        "{}{}",
        glob_policy(
            r#"@enforcement("audit") @path("/admin/**")"#,
            "permit",
            "*.github.com",
            "true"
        ),
        http_policy("", "permit", "api.github.com", r#"context.method == "GET""#),
    );
    assert_eq!(
        engine(&policy).warnings(),
        [AnalysisWarning::AuditPathOnEnforcedEndpoint {
            endpoint: "*.github.com:443".to_string(),
            path: "/admin/**".to_string(),
        }]
    );
}

#[test]
fn an_audit_path_beside_enforced_policies_of_unrelated_entries_does_not_warn() {
    for (enforced, port) in [("*.gitlab.com", 443), ("*.github.com", 8443)] {
        let policy = format!(
            r#"permit (principal, action == Sandbox::Action::"HttpRequest",
          resource is Sandbox::NetworkEndpoint)
when {{ resource.host like("{enforced}", ".") && resource.port == {port}
       && context.method == "GET" }};
{}"#,
            http_policy(
                r#"@enforcement("audit") @path("/repos/**")"#,
                "permit",
                "api.github.com",
                "true",
            ),
        );
        assert_eq!(engine(&policy).warnings(), [], "{enforced}:{port}");
    }
}

// ── Forbids that read destination_ip (F11) ────────────────────────────────

const SVC_PERMIT: &str = r#"permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"svc.corp.net:443");
"#;

fn address_forbid(conditions: &str) -> String {
    format!(
        r#"{SVC_PERMIT}forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
{conditions};"#
    )
}

#[test]
fn forbids_that_could_hold_because_the_address_is_absent_are_rejected() {
    for conditions in [
        r#"unless { context has destination_ip && context.destination_ip.isInRange(ip("10.0.0.0/8")) }"#,
        r#"when { !(context has destination_ip && context.destination_ip.isInRange(ip("10.0.0.0/8"))) }"#,
        r#"when { if context has destination_ip then context.destination_ip.isInRange(ip("10.0.0.0/8")) else true }"#,
        r#"when { context.binary_path == "/usr/bin/curl" } unless { context has destination_ip }"#,
        "when { (context has destination_ip) == false }",
    ] {
        let error = rejection(&address_forbid(conditions));
        assert!(
            matches!(&error, CedarEngineError::InvalidDestinationIp { reason, .. }
                if reason.contains("only in `when` conditions")),
            "{conditions}: {error}"
        );
    }
}

#[test]
fn forbids_whose_address_reads_are_guarded_load_and_deny_only_once_resolved() {
    for conditions in [
        r#"when { context has destination_ip && !context.destination_ip.isInRange(ip("10.0.0.0/8")) }"#,
        r#"when { context.binary_path == "/usr/bin/curl" && context has destination_ip && !context.destination_ip.isInRange(ip("10.0.0.0/8")) }"#,
        r#"when { context.binary_path == "/usr/bin/wget" || (context has destination_ip && !context.destination_ip.isInRange(ip("10.0.0.0/8"))) }"#,
        r#"when { context has destination_ip } when { !context.destination_ip.isInRange(ip("10.0.0.0/8")) }"#,
        r#"when { context has destination_ip } unless { context.destination_ip.isInRange(ip("10.0.0.0/8")) }"#,
    ] {
        let engine = CedarEngine::from_policy_str(&address_forbid(conditions))
            .unwrap_or_else(|error| panic!("{conditions}: {error}"));
        let unresolved = connect("svc.corp.net", None);
        assert!(
            engine.evaluate_network(&unresolved).unwrap().is_allow(),
            "{conditions}: allowed before resolution"
        );
        let inside = connect("svc.corp.net", Some("10.1.2.3"));
        assert!(
            engine.evaluate_network(&inside).unwrap().is_allow(),
            "{conditions}"
        );
        let outside = connect("svc.corp.net", Some("8.8.8.8"));
        assert!(
            !engine.evaluate_network(&outside).unwrap().is_allow(),
            "{conditions}"
        );
    }
}

// ── Process identity (F14) and principal constraints ──────────────────────

#[test]
fn policies_reading_principal_user_or_group_are_rejected() {
    for policy in [
        r#"forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
unless { principal.user == Sandbox::User::"sandbox" };"#,
        r#"permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"pypi.org:443")
when { principal.group == Sandbox::Group::"sandbox" };"#,
        r#"permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"pypi.org:443")
when { principal.user in [Sandbox::User::"root", Sandbox::User::"sandbox"] };"#,
        // Receivers that evaluate to the principal or another process.
        r#"permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"pypi.org:443")
when { (if context.binary_path == "/usr/bin/curl" then principal else principal).user
    == Sandbox::User::"sandbox" };"#,
        r#"permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"pypi.org:443")
when { { p: principal }.p.group == Sandbox::Group::"sandbox" };"#,
        r#"permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"pypi.org:443")
when { Sandbox::Process::"sandbox".user == Sandbox::User::"sandbox" };"#,
    ] {
        let error = rejection(policy);
        assert!(
            matches!(&error, CedarEngineError::UnsupportedPolicy { reason, .. }
                if reason.contains("sandbox identity attributes are not yet available to policies")),
            "{policy}: {error}"
        );
    }
}

#[test]
fn a_principal_has_test_still_loads() {
    // `principal has user` always holds; it does not read the placeholder.
    engine(
        r#"permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"pypi.org:443")
when { principal has user && principal has group };"#,
    );
    // A record field named `user` is not the principal's.
    engine(
        r#"permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"pypi.org:443")
when { { user: context.binary_path }.user == "/usr/bin/curl" };"#,
    );
}

#[test]
fn policies_testing_which_process_the_principal_is_are_rejected() {
    for policy in [
        // Scope constraints.
        r#"forbid (principal == Sandbox::Process::"curl",
        action == Sandbox::Action::"NetworkConnect", resource);"#,
        r#"forbid (principal == Sandbox::Process::"current",
        action == Sandbox::Action::"NetworkConnect", resource);"#,
        r#"forbid (principal in Sandbox::Process::"curl",
        action == Sandbox::Action::"HttpRequest", resource);"#,
        r#"forbid (principal in Sandbox::Group::"sandbox",
        action == Sandbox::Action::"NetworkConnect", resource);"#,
        r#"forbid (principal is Sandbox::Process in Sandbox::Process::"curl",
        action == Sandbox::Action::"NetworkConnect", resource);"#,
        // Conditions.
        r#"forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { principal == Sandbox::Process::"curl" };"#,
        r#"forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
unless { principal != Sandbox::Process::"curl" };"#,
        r#"forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { principal in Sandbox::Group::"sandbox" };"#,
        r#"forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { principal in [Sandbox::Process::"a", Sandbox::Process::"b"] };"#,
        r#"forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { principal == resource };"#,
        r#"forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { [Sandbox::Process::"curl"].contains(principal) };"#,
        r#"forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { principal is Sandbox::Process in Sandbox::Process::"curl" };"#,
        r#"forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { principal is Sandbox::User };"#,
        // Operands that evaluate to the principal.
        r#"forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { (if context.binary_path == "/usr/bin/curl" then principal else principal)
    == Sandbox::Process::"curl" };"#,
        r#"forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { { p: principal } == { p: Sandbox::Process::"curl" } };"#,
    ] {
        let error = rejection(policy);
        assert!(
            matches!(&error, CedarEngineError::UnsupportedPolicy { reason, .. }
                if reason.contains("tests which process the principal is")),
            "{policy}: {error}"
        );
    }
}

#[test]
fn an_unconstrained_principal_still_loads() {
    engine(
        r#"permit (principal is Sandbox::Process, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"pypi.org:443")
when { principal is Sandbox::Process && principal has user };
forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { context.binary_path == "/usr/bin/nc" };"#,
    );
}

// ── Host overlap analysis stays bounded (F4) ──────────────────────────────

/// A policy set of `HttpRequest` globs on port 443, each from `glob(i)`,
/// as large as fits in [`MAX_POLICY_BYTES`].
fn many_globs(glob: impl Fn(usize) -> String) -> (String, usize) {
    let mut policy = String::new();
    for index in 0.. {
        let next = glob_policy("", "permit", &glob(index), "true");
        if policy.len() + next.len() > MAX_POLICY_BYTES {
            return (policy, index);
        }
        policy.push_str(&next);
    }
    unreachable!()
}

/// Load time a debug build stays under for a policy set of the largest
/// size; before the overlap budget, such sets took minutes even in release.
const LOAD_TIME_BOUND: Duration = Duration::from_secs(90);

/// A 253-byte glob `<first>.*.*. ... .*.<last>`.
fn long_glob(first: &str, last: &str) -> String {
    let mut glob = first.to_string();
    while glob.len() + ".*".len() + 1 + last.len() <= 253 {
        glob.push_str(".*");
    }
    format!("{glob}.{last}")
}

/// A 253-byte glob distinct for each index, sharing its literal ends with
/// the others, so every pair is compared in full.
fn long_similar_glob(index: usize) -> String {
    long_glob(&format!("*{index:x}*"), "com")
}

/// A 253-byte glob that differs from the others in its literal suffix.
fn long_distinct_glob(index: usize) -> String {
    let mut glob = format!("*.svc{index}");
    while glob.len() + ".a".len() + ".com".len() <= 253 {
        glob.push_str(".a");
    }
    glob.push_str(".com");
    glob
}

#[test]
fn many_long_similar_host_globs_are_rejected_within_the_work_budget() {
    let (policy, globs) = many_globs(long_similar_glob);
    assert!(globs > 500, "{globs} globs");
    let started = Instant::now();
    let error = rejection(&policy);
    let elapsed = started.elapsed();
    assert!(
        matches!(error, CedarEngineError::HostOverlapBudgetExceeded { .. }),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("use fewer host globs on one port")
    );
    assert!(elapsed < LOAD_TIME_BOUND, "{elapsed:?}");
}

#[test]
fn many_long_host_globs_with_distinct_literal_ends_load_within_the_work_budget() {
    // Each pair is told apart by its literal suffix without a full match.
    let (policy, globs) = many_globs(long_distinct_glob);
    assert!(globs > 500, "{globs} globs");
    let started = Instant::now();
    let loaded = engine(&policy);
    let elapsed = started.elapsed();
    assert_eq!(inspection(&loaded).len(), globs);
    assert!(elapsed < LOAD_TIME_BOUND, "{elapsed:?}");

    // Different last labels are never compared, however similar the rest.
    let (policy, globs) = many_globs(|index| long_glob("*0*", &format!("t{index:x}")));
    assert!(globs > 500, "{globs} globs");
    let started = Instant::now();
    assert_eq!(inspection(&engine(&policy)).len(), globs);
    let elapsed = started.elapsed();
    assert!(elapsed < LOAD_TIME_BOUND, "{elapsed:?}");
}
