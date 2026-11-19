// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Token-grant owner parity for provider rules compiled to Cedar.
//!
//! A Cedar sandbox selects token-grant owners by evaluating its provider
//! rules compiled to Cedar, where a YAML sandbox evaluates them with Rego.
//! These tests load every shipped provider profile as the gateway composes
//! it, give the Cedar sandbox a policy that allows every probed request, and
//! require both engines to admit the same owners. A sweep of glob, query,
//! and deny matchers checks the translated matcher semantics against Rego.

use super::*;

use openshell_core::proto::{
    L7Allow, L7DenyRule, L7QueryMatcher, L7Rule, NetworkBinary, NetworkEndpoint, NetworkPolicyRule,
};

/// The binary no shipped profile lists.
const UNLISTED: &str = "/usr/bin/unlisted-client";
/// A host no shipped profile names.
const OTHER_HOST: &str = "other.example.test";

/// Loads every shipped provider profile, keyed by file name.
fn shipped_profiles() -> Vec<(String, openshell_providers::ProviderTypeProfile)> {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../providers");
    let mut profiles: Vec<_> = std::fs::read_dir(&directory)
        .expect("providers directory")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .map(|path| {
            let text = std::fs::read_to_string(&path).expect("profile reads");
            let profile = openshell_providers::parse_profile_yaml(&text)
                .unwrap_or_else(|error| panic!("{}: profile parses: {error}", path.display()));
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, profile)
        })
        .collect();
    profiles.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(profiles.len() >= 10, "shipped profiles load");
    profiles
}

/// The provider rule the gateway composes for `profile`, with each
/// endpoint stamped with its token-grant owner.
pub(super) fn composed_rule(
    profile: &openshell_providers::ProviderTypeProfile,
) -> NetworkPolicyRule {
    let rule_name = openshell_policy::provider_rule_name(&profile.id);
    let mut rule = profile.network_policy_rule(&rule_name);
    let provider_id = format!("provider-{}", profile.id);
    let owners = openshell_core::policy_identity::provider_token_grant_owners(&provider_id, &rule);
    for (endpoint, owner) in rule.endpoints.iter_mut().zip(owners) {
        endpoint.token_grant_owner = owner;
    }
    rule
}

/// A concrete host an endpoint host or host glob matches.
fn concrete_host(host: &str) -> String {
    host.replace("**", "x")
        .replace('*', "x")
        .to_ascii_lowercase()
}

/// A Cedar policy allowing every request to each `host:port`, inspecting
/// `graphql` paths as GraphQL.
fn allow_all(endpoints: &[(String, u16)], graphql: &[(String, u16, String)]) -> String {
    let mut cedar = String::new();
    for (host, port) in endpoints {
        let _ = write!(
            cedar,
            r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"{host}:{port}");
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{host}:{port}");
"#
        );
    }
    for (host, port, path) in graphql {
        let _ = write!(
            cedar,
            r#"
@path("{path}") @protocol("graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{host}:{port}");
"#
        );
    }
    cedar
}

/// The Cedar endpoints that allow a profile's probes, and the probes.
struct ProfileProbes {
    /// `host:port` pairs to allow.
    endpoints: Vec<(String, u16)>,
    /// `host:port` and path of each GraphQL endpoint.
    graphql_paths: Vec<(String, u16, String)>,
    cases: Vec<Case>,
}

/// The owner probes for one profile.
fn profile_probes(
    profile: &openshell_providers::ProviderTypeProfile,
    rule: &NetworkPolicyRule,
) -> ProfileProbes {
    let binary = rule
        .binaries
        .iter()
        .map(|binary| binary.path.as_str())
        .find(|path| !path.contains('*'))
        .unwrap_or(BINARY)
        .to_string();
    let mut endpoints = vec![(OTHER_HOST.to_string(), 443)];
    let mut graphql_paths = Vec::new();
    let mut cases = Vec::new();
    let mut probe = |name: String, ctx: L7EvalContext, request: L7RequestInfo| {
        cases.push(same_probe(
            format!("{}/{name}", profile.id),
            owners_in(ctx, request),
        ));
    };
    for endpoint in &rule.endpoints {
        if endpoint.host.is_empty() {
            continue;
        }
        let host = concrete_host(&endpoint.host);
        let port = endpoint.ports.first().copied().unwrap_or(endpoint.port);
        let port = u16::try_from(port).expect("port");
        if !endpoints.contains(&(host.clone(), port)) {
            endpoints.push((host.clone(), port));
        }
        let ctx = || l7_ctx(&host, port, &binary);
        if endpoint.protocol == "graphql" {
            graphql_paths.push((host.clone(), port, endpoint.path.clone()));
            let request = |operations| L7RequestInfo {
                target: endpoint.path.clone(),
                ..graphql(operations)
            };
            for (name, operations) in [
                (
                    "query",
                    vec![operation("query", Some("Viewer"), &["viewer"])],
                ),
                (
                    "mutation",
                    vec![operation("mutation", None, &["createIssue"])],
                ),
                (
                    "query and mutation",
                    vec![
                        operation("query", None, &["viewer"]),
                        operation("mutation", None, &["createIssue"]),
                    ],
                ),
                (
                    "subscription",
                    vec![operation("subscription", None, &["x"])],
                ),
            ] {
                probe(
                    format!("{host}{} graphql {name}", endpoint.path),
                    ctx(),
                    request(operations),
                );
            }
            continue;
        }
        let mut paths = vec![
            "/".to_string(),
            "/v1/messages".to_string(),
            "/o/r/git-upload-pack".to_string(),
            "/openai/v1/chat".to_string(),
        ];
        if !endpoint.path.is_empty() {
            paths.push(endpoint.path.replace("/**", "/x"));
        }
        for path in &paths {
            for method in ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] {
                probe(format!("{host} {method} {path}"), ctx(), rest(method, path));
            }
        }
        probe(
            format!("{host} GET from an unlisted binary"),
            l7_ctx(&host, port, UNLISTED),
            rest("GET", "/"),
        );
        let mut child = l7_ctx(&host, port, "/bin/sh");
        child.ancestors = vec![binary.clone()];
        probe(
            format!("{host} GET from a child of the binary"),
            child,
            rest("GET", "/"),
        );
        probe(
            format!("{host} GET to another host"),
            l7_ctx(OTHER_HOST, 443, &binary),
            rest("GET", "/"),
        );
    }
    ProfileProbes {
        endpoints,
        graphql_paths,
        cases,
    }
}

#[test]
fn shipped_provider_profiles_select_the_same_owners() {
    let mut probes = 0;
    let mut admitted = 0;
    let mut report = String::new();
    let mut failures = Vec::new();
    for (file, profile) in shipped_profiles() {
        let rule = composed_rule(&profile);
        let ProfileProbes {
            endpoints,
            graphql_paths,
            cases,
        } = profile_probes(&profile, &rule);
        let cedar = allow_all(&endpoints, &graphql_paths);
        let scenario = ProviderScenario {
            name: &file,
            host: OTHER_HOST,
            rules: vec![rule.clone()],
            cedar: &cedar,
            cases,
        };
        let engines = Engines::load_providers(&scenario);
        for case in &scenario.cases {
            let (yaml, cedar) = engines.outcomes(OTHER_HOST, &case.probe);
            probes += 1;
            if yaml != "none" {
                admitted += 1;
            }
            if yaml != cedar {
                failures.push(format!(
                    "{file} / {}: YAML {yaml} but Cedar {cedar}",
                    case.name
                ));
            }
        }
        // Only binary globs, which Cedar cannot match against ancestors,
        // are compiled other than exactly.
        let rules = HashMap::from([(rule.name.clone(), rule.clone())]);
        if let Some(compiled) =
            crate::cedar_provider_rules::compile(&rules, 0).expect("provider rules compile")
        {
            assert!(compiled.fail_closed_reason().is_none(), "{file}");
            for note in compiled.untranslated() {
                assert_eq!(
                    note.location,
                    openshell_policy_cedar::RuleLocation::Binaries,
                    "{file}: {note}"
                );
                let _ = writeln!(report, "{file}: {note}");
            }
        }
    }
    println!("{probes} owner probes, {admitted} admitting an owner\n{report}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(
        admitted > 100,
        "the probes admit owners: {admitted} of {probes}"
    );
}

const HOST: &str = "api.example.test";

fn owned(rules: Vec<L7Rule>, deny_rules: Vec<L7DenyRule>) -> NetworkPolicyRule {
    NetworkPolicyRule {
        name: "owner".to_string(),
        endpoints: vec![NetworkEndpoint {
            host: HOST.to_string(),
            port: 443,
            protocol: "rest".to_string(),
            token_grant_owner: "owner".to_string(),
            rules,
            deny_rules,
            ..Default::default()
        }],
        binaries: vec![NetworkBinary {
            path: BINARY.to_string(),
        }],
    }
}

fn get(path: &str) -> L7Rule {
    L7Rule {
        allow: Some(L7Allow {
            method: "GET".to_string(),
            path: path.to_string(),
            ..Default::default()
        }),
    }
}

/// Runs owner probes for `requests` against one provider rule set.
fn sweep(
    name: &str,
    rules: Vec<NetworkPolicyRule>,
    requests: Vec<(String, L7RequestInfo)>,
) -> usize {
    let cedar = allow_all(&[(HOST.to_string(), 443)], &[]);
    let cases: Vec<Case> = requests
        .into_iter()
        .map(|(label, request)| {
            same_probe(
                format!("{name}/{label}"),
                owners_in(l7_ctx(HOST, 443, BINARY), request),
            )
        })
        .collect();
    let count = cases.len();
    assert_provider_parity(&ProviderScenario {
        name,
        host: HOST,
        rules,
        cedar: &cedar,
        cases,
    });
    count
}

const PATHS: &[&str] = &[
    "/",
    "/a",
    "/a/",
    "/ab",
    "/a/b",
    "/a/b/c",
    "/a/b/c/d",
    "/x/a/b",
    "/a.b",
    "/a/git-upload-pack",
    "/a/b/git-upload-pack",
    "/git-upload-pack",
    "/a//b",
];

const PATTERNS: &[&str] = &[
    "**",
    "/**",
    "/a/**",
    "/a/*",
    "/a*",
    "/a**",
    "/a/**b",
    "/a/**/b",
    "/**/git-upload-pack",
    "**/b",
    "/*/b",
    "/a/*/c",
    "/a/**/c/**",
    "/a.*",
];

#[test]
fn rule_path_globs_match_as_in_rego() {
    let mut probes = 0;
    for pattern in PATTERNS {
        let requests = PATHS
            .iter()
            .map(|path| ((*path).to_string(), rest("GET", path)))
            .collect();
        probes += sweep(
            &format!("allow {pattern}"),
            vec![owned(vec![get(pattern)], Vec::new())],
            requests,
        );
        let deny = L7DenyRule {
            method: "GET".to_string(),
            path: (*pattern).to_string(),
            ..Default::default()
        };
        let requests = PATHS
            .iter()
            .map(|path| ((*path).to_string(), rest("GET", path)))
            .collect();
        probes += sweep(
            &format!("deny {pattern}"),
            vec![owned(vec![get("**")], vec![deny])],
            requests,
        );
    }
    println!("{probes} path glob probes");
}

#[test]
fn endpoint_paths_match_as_in_rego() {
    for endpoint_path in ["/a/**", "/a/*", "/a", "/a*/b", "**", "/a.b/**"] {
        let mut rule = owned(vec![get("**")], Vec::new());
        rule.endpoints[0].path = endpoint_path.to_string();
        let requests = PATHS
            .iter()
            .map(|path| ((*path).to_string(), rest("GET", path)))
            .collect();
        sweep(
            &format!("endpoint path {endpoint_path}"),
            vec![rule],
            requests,
        );
    }
}

fn with_query(path: &str, query: &[(&str, &[&str])]) -> L7RequestInfo {
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
        ..rest("GET", path)
    }
}

#[test]
fn query_matchers_match_as_in_rego() {
    let matcher = |glob: &str, any: &[&str]| L7QueryMatcher {
        glob: glob.to_string(),
        any: any.iter().map(ToString::to_string).collect(),
    };
    let queries: Vec<(String, L7RequestInfo)> = [
        &[][..],
        &[("env", &["prod"][..])],
        &[("env", &["prod-a"][..])],
        &[("env", &["prod-a", "prod-b"][..])],
        &[("env", &["prod-a", "dev"][..])],
        &[("env", &["prod.a"][..])],
        &[("env", &["staging"][..])],
        &[("env", &["prod-a"][..]), ("force", &["true"][..])],
        &[("env", &["prod-a"][..]), ("force", &["no", "true"][..])],
        &[("force", &["false"][..])],
    ]
    .iter()
    .map(|query| (format!("{query:?}"), with_query("/a", query)))
    .collect();
    for (label, allow) in [
        ("glob", matcher("prod-*", &[])),
        ("any", matcher("", &["prod-*", "staging"])),
    ] {
        let mut rule = get("/a");
        rule.allow
            .as_mut()
            .unwrap()
            .query
            .insert("env".to_string(), allow);
        let deny = L7DenyRule {
            method: "*".to_string(),
            path: "**".to_string(),
            query: HashMap::from([("force".to_string(), matcher("true", &[]))]),
            ..Default::default()
        };
        sweep(
            &format!("query {label}"),
            vec![owned(vec![rule], vec![deny])],
            queries.clone(),
        );
    }
}

#[test]
fn methods_and_global_denies_match_as_in_rego() {
    let methods = [
        "GET", "get", "HEAD", "POST", "post", "PUT", "OPTIONS", "DELETE",
    ];
    let requests: Vec<_> = methods
        .iter()
        .map(|method| ((*method).to_string(), rest(method, "/a")))
        .collect();
    let rule = |method: &str| L7Rule {
        allow: Some(L7Allow {
            method: method.to_string(),
            path: "**".to_string(),
            ..Default::default()
        }),
    };
    for method in ["GET", "post", "*", "DELETE"] {
        sweep(
            &format!("method {method}"),
            vec![owned(vec![rule(method)], Vec::new())],
            requests.clone(),
        );
    }
    // A deny rule of another provider, without an owner, removes every owner.
    let mut other = owned(
        vec![get("/elsewhere")],
        vec![L7DenyRule {
            method: "POST".to_string(),
            path: "/a".to_string(),
            ..Default::default()
        }],
    );
    other.name = "other".to_string();
    other.endpoints[0].token_grant_owner = String::new();
    sweep(
        "global deny",
        vec![owned(vec![rule("*")], Vec::new()), other],
        requests,
    );
}

/// Untranslatable globs: an allow rule admits less, a deny rule denies more,
/// and a glob Rego could fail to compile admits no owner at all.
#[test]
fn untranslatable_globs_never_admit_more_than_rego() {
    let cedar = allow_all(&[(HOST.to_string(), 443)], &[]);
    let mut narrower = 0;
    for (pattern, deny) in [
        ("/a/?", false),
        ("/a/[bc]", false),
        ("/a/?", true),
        ("/a/[bc]", true),
    ] {
        let rule = if deny {
            owned(
                vec![get("**")],
                vec![L7DenyRule {
                    method: "GET".to_string(),
                    path: pattern.to_string(),
                    ..Default::default()
                }],
            )
        } else {
            owned(vec![get(pattern)], Vec::new())
        };
        let engines = Engines::load_providers(&ProviderScenario {
            name: pattern,
            host: HOST,
            rules: vec![rule],
            cedar: &cedar,
            cases: Vec::new(),
        });
        for path in PATHS.iter().chain(&["/a/c", "/a/bc"]) {
            let probe = owners_in(l7_ctx(HOST, 443, BINARY), rest("GET", path));
            let (yaml, cedar) = engines.outcomes(HOST, &probe);
            assert!(
                cedar == "none" || cedar == yaml,
                "{pattern} (deny: {deny}) {path}: YAML {yaml} but Cedar {cedar}"
            );
            if cedar != yaml {
                narrower += 1;
            }
        }
    }
    assert!(narrower > 0, "untranslatable globs admit fewer owners");
}
