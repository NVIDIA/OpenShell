// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks that no policy text within [`MAX_POLICY_SOURCE_BYTES`] and no
//! request exhausts the stack of a 2 MiB thread, the stack of a Tokio
//! worker: deep policy text is rejected before Cedar parses it, accepted
//! policies load and evaluate on a stack sized for them, and over-long
//! request strings are denied before evaluation. Without these bounds the
//! process aborts, which fails the whole test binary.
//!
//! Also checks that a policy with many GraphQL paths loads in time linear
//! in its size.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use openshell_policy_cedar::{
    CedarEngine, CedarEngineError, Decision, HttpRequestInput, MAX_POLICY_EXPRESSION_DEPTH,
    MAX_POLICY_NESTING, MAX_POLICY_SOURCE_BYTES, MAX_REQUEST_FIELD_BYTES, NetworkConnectRequest,
};

const HOST: &str = "api.example.com";

/// The stack of a Tokio worker thread.
const WORKER_STACK: usize = 2 * 1024 * 1024;

/// Runs `f` on a thread with a Tokio worker's stack.
fn on_worker_stack<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(WORKER_STACK)
            .spawn_scoped(scope, f)
            .expect("thread spawns")
            .join()
            .expect("thread does not panic")
    })
}

fn load(policy: &str) -> Result<CedarEngine, CedarEngineError> {
    on_worker_stack(|| CedarEngine::from_policy_str(policy))
}

/// An `HttpRequest` permit on the test endpoint whose `when` clause is
/// `condition`.
///
/// Its expression depth bound is that of `condition` plus 2: the scope's
/// and the `when` clause's brackets.
fn http_permit(condition: &str) -> String {
    format!(
        r#"permit (principal, action == Sandbox::Action::"HttpRequest", resource == Sandbox::NetworkEndpoint::"{HOST}:443") when {{ {condition} }};
"#
    )
}

fn request(path: &str) -> HttpRequestInput {
    HttpRequestInput {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        binary_path: "/usr/bin/curl".to_string(),
        host: HOST.to_string(),
        port: 443,
        method: "GET".to_string(),
        path: path.to_string(),
        ..Default::default()
    }
}

/// A path of `len` bytes, `/a/a/...`, that delimited path globs walk one
/// segment at a time.
fn long_path(len: usize) -> String {
    let mut path = "/a".repeat(len / 2);
    if len % 2 == 1 {
        path.push('/');
    }
    path
}

/// `count` copies of `term` joined with `op`.
fn chain(term: &str, op: &str, count: usize) -> String {
    vec![term; count].join(op)
}

#[test]
fn deeply_nested_brackets_are_rejected_before_parsing() {
    // About 150 levels abort Cedar's parser on a 2 MiB stack.
    for nesting in [MAX_POLICY_NESTING + 1, 150, 100_000] {
        let condition = format!("{}true{}", "(".repeat(nesting), ")".repeat(nesting));
        let error = load(&http_permit(&condition)).expect_err("nesting is rejected");
        assert!(
            matches!(
                error,
                CedarEngineError::PolicyNestingTooDeep { line: 1, limit } if limit == MAX_POLICY_NESTING
            ),
            "{nesting}: {error}"
        );
    }
    // Every bracket kind counts, and unbalanced text is still bounded.
    let mixed = "[{(".repeat(30);
    assert!(matches!(
        load(&http_permit(&mixed)),
        Err(CedarEngineError::PolicyNestingTooDeep { .. })
    ));
}

#[test]
fn nesting_at_the_limit_loads_and_evaluates() {
    // The `when` clause's brace is the first level.
    let nesting = MAX_POLICY_NESTING - 1;
    let condition = format!(
        "{}context.method == \"GET\"{}",
        "(".repeat(nesting),
        ")".repeat(nesting)
    );
    let engine = load(&http_permit(&condition)).expect("policy loads");
    let allowed = on_worker_stack(|| engine.evaluate_l7(&request("/x")))
        .expect("evaluates")
        .is_allow();
    assert!(allowed);
}

#[test]
fn brackets_in_strings_and_comments_do_not_count() {
    let brackets = "(".repeat(MAX_POLICY_NESTING * 2);
    let policy = format!(
        "// {brackets}\n{}",
        http_permit(&format!(r#"context.path == "{brackets}\"{brackets}""#))
    );
    let engine = load(&policy).expect("policy loads");
    let path = format!("{brackets}\"{brackets}");
    assert!(
        on_worker_stack(|| engine.evaluate_l7(&request(&path)))
            .expect("evaluates")
            .is_allow()
    );
}

#[test]
fn long_flat_chains_at_the_size_limit_are_rejected_cleanly() {
    // A flat chain parses without nesting, but Cedar converts, validates,
    // and evaluates it recursively, one level per operator: about 4,000
    // `&&` terms abort `Policy::to_json` on a 2 MiB stack.
    let fill = |head: &str, term: &str, op: &str, tail: &str| {
        let empty = http_permit(&format!("{head}{term}{tail}")).len();
        let count = (MAX_POLICY_SOURCE_BYTES - empty) / (term.len() + op.len()) + 1;
        let policy = http_permit(&format!("{head}{}{tail}", chain(term, op, count)));
        assert!(policy.len() <= MAX_POLICY_SOURCE_BYTES);
        assert!(policy.len() > MAX_POLICY_SOURCE_BYTES - 64);
        policy
    };
    for policy in [
        fill("", "true", "&&", ""),
        fill("", "true", "||", ""),
        fill("", "1", "+", " == 1"),
        fill("context", ".path", "", r#" == """#),
        fill("", "if true then true else ", "", "true"),
        fill("", r#"context.method == "GET""#, " && ", ""),
    ] {
        let error = load(&policy).expect_err("chain is rejected");
        assert!(
            matches!(
                error,
                CedarEngineError::PolicyExpressionTooDeep { line: 1, depth, limit }
                    if depth > limit && limit == MAX_POLICY_EXPRESSION_DEPTH
            ),
            "{error}"
        );
    }
}

#[test]
fn chains_at_the_depth_limit_load_and_evaluate() {
    // `when { 1 + ... + 1 == count }`: `count - 1` additions, one `==`, and
    // the two brackets of `http_permit`.
    let count = MAX_POLICY_EXPRESSION_DEPTH - 2;
    let sum = format!("{} == {count}", chain("1", "+", count));
    let engine = load(&http_permit(&sum)).expect("policy at the limit loads");
    let evaluation =
        on_worker_stack(|| engine.evaluate_l7(&request("/x"))).expect("evaluates on 2 MiB");
    assert!(evaluation.is_allow());
    let over = format!("{} == {}", chain("1", "+", count + 1), count + 1);
    assert!(matches!(
        load(&http_permit(&over)),
        Err(CedarEngineError::PolicyExpressionTooDeep { depth, .. })
            if depth == MAX_POLICY_EXPRESSION_DEPTH + 1
    ));

    // Three per term: `.`, `==`, and `&&`, less the last `&&`.
    let terms = (MAX_POLICY_EXPRESSION_DEPTH - 1) / 3;
    let methods = chain(r#"context.method == "GET""#, " && ", terms);
    let engine = load(&http_permit(&methods)).expect("policy at the limit loads");
    assert!(
        on_worker_stack(|| engine.evaluate_l7(&request("/x")))
            .expect("evaluates on 2 MiB")
            .is_allow()
    );
}

#[test]
fn many_shallow_policies_do_not_add_up() {
    let policy: String = (0..400)
        .map(|index| http_permit(&format!(r#"context.path == "/{index}""#)))
        .collect();
    assert!(policy.len() < MAX_POLICY_SOURCE_BYTES);
    let engine = load(&policy).expect("policies load");
    assert!(
        on_worker_stack(|| engine.evaluate_l7(&request("/399")))
            .expect("evaluates")
            .is_allow()
    );
}

#[test]
fn source_over_the_size_limit_is_rejected() {
    let policy = format!(
        "{}{}",
        http_permit("true"),
        " ".repeat(MAX_POLICY_SOURCE_BYTES)
    );
    assert!(matches!(
        load(&policy),
        Err(CedarEngineError::PolicyTooLarge { size, limit })
            if size == policy.len() && limit == MAX_POLICY_SOURCE_BYTES
    ));
}

/// Asserts that `request` is denied for its over-long `field`.
fn assert_too_long<T: std::fmt::Debug>(result: Result<T, CedarEngineError>, field: &str) {
    match result {
        Err(CedarEngineError::RequestFieldTooLong {
            field: actual,
            length,
            limit,
        }) => {
            assert_eq!(actual, field);
            assert_eq!(length, MAX_REQUEST_FIELD_BYTES + 1);
            assert_eq!(limit, MAX_REQUEST_FIELD_BYTES);
        }
        other => panic!("{field}: expected RequestFieldTooLong, got {other:?}"),
    }
}

#[test]
fn delimited_like_on_request_fields_is_bounded() {
    // Cedar's delimited `like` recurses once per character: about 24,000
    // path characters abort it on a 2 MiB stack. A long pattern adds to the
    // recursion too.
    let long_pattern = format!("/a{}/**", "/*".repeat(4000));
    let policy = format!(
        "{}{}{}{}{}",
        http_permit(r#"context.path like("/**", "/")"#),
        http_permit(&format!(r#"context.path like("{long_pattern}", "/")"#)),
        http_permit(r#"context.jsonrpc_method like("tools/**", "/")"#),
        http_permit(r#"context.mcp_tool like("**", ".")"#),
        http_permit(
            r#"context.graphql_operation_name like("**", ".") && context.query.hasTag("q") && context.query.getTag("q") like("**", "/")"#
        ),
    );
    let engine = load(&policy).expect("policy loads");
    let at_limit = long_path(MAX_REQUEST_FIELD_BYTES);
    let over_limit = long_path(MAX_REQUEST_FIELD_BYTES + 1);
    let mut query = BTreeMap::new();
    query.insert("q".to_string(), vec![at_limit.clone()]);
    let requests = [
        request(&at_limit),
        HttpRequestInput {
            jsonrpc_method: format!("tools{}", &at_limit[..MAX_REQUEST_FIELD_BYTES - 5]),
            ..request("/")
        },
        HttpRequestInput {
            mcp_tool: "a".repeat(MAX_REQUEST_FIELD_BYTES),
            ..request("/")
        },
        HttpRequestInput {
            graphql_operation_name: "a".repeat(MAX_REQUEST_FIELD_BYTES),
            query,
            ..request("/")
        },
    ];
    on_worker_stack(|| {
        for request in &requests {
            let evaluation = engine.evaluate_l7(request).expect("evaluates on 2 MiB");
            assert!(evaluation.is_allow(), "{evaluation:?}");
        }
    });

    let over = "a".repeat(MAX_REQUEST_FIELD_BYTES + 1);
    let mut query = BTreeMap::new();
    query.insert("q".to_string(), vec![over.clone()]);
    let mut long_key = BTreeMap::new();
    long_key.insert(over.clone(), vec![String::new()]);
    let cases = [
        ("path", request(&over_limit)),
        (
            "method",
            HttpRequestInput {
                method: over.clone(),
                ..request("/")
            },
        ),
        (
            "jsonrpc_method",
            HttpRequestInput {
                jsonrpc_method: over.clone(),
                ..request("/")
            },
        ),
        (
            "mcp_tool",
            HttpRequestInput {
                mcp_tool: over.clone(),
                ..request("/")
            },
        ),
        (
            "graphql_operation_name",
            HttpRequestInput {
                graphql_operation_name: over.clone(),
                ..request("/")
            },
        ),
        (
            "graphql_fields",
            HttpRequestInput {
                graphql_fields: vec![over.clone()],
                ..request("/")
            },
        ),
        (
            "query value",
            HttpRequestInput {
                query,
                ..request("/")
            },
        ),
        (
            "query key",
            HttpRequestInput {
                query: long_key,
                ..request("/")
            },
        ),
        (
            "host",
            HttpRequestInput {
                host: over.clone(),
                ..request("/")
            },
        ),
        (
            "binary_path",
            HttpRequestInput {
                binary_path: over,
                ..request("/")
            },
        ),
    ];
    on_worker_stack(|| {
        for (field, request) in &cases {
            assert_too_long(engine.evaluate_l7(request), field);
        }
    });
}

#[test]
fn network_requests_are_bounded() {
    let policy = r#"permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("**.example.com", ".") && resource.port == 443
    && context.binary_path like("/**", "/")
};
"#;
    let engine = load(policy).expect("policy loads");
    let host = format!(
        "{}example.com",
        "a.".repeat((MAX_REQUEST_FIELD_BYTES - "example.com".len()) / 2)
    );
    let connect = |host: &str, binary_path: &str| NetworkConnectRequest {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        host: host.to_string(),
        port: 443,
        binary_path: binary_path.to_string(),
        ancestors: Vec::new(),
        binary_aliases: Vec::new(),
        binary_globs: Vec::new(),
        destination_ip: None,
    };
    on_worker_stack(|| {
        let decision = engine
            .evaluate_network(&connect(&host, &long_path(MAX_REQUEST_FIELD_BYTES)))
            .expect("evaluates on 2 MiB");
        assert!(decision.is_allow(), "{decision:?}");
        let over = "a".repeat(MAX_REQUEST_FIELD_BYTES + 1);
        assert_too_long(engine.evaluate_network(&connect(&over, "/bin/sh")), "host");
        assert_too_long(
            engine.evaluate_network(&connect(HOST, &over)),
            "binary_path",
        );
        let mut request = connect(HOST, "/bin/sh");
        request.ancestors = vec![over];
        assert_too_long(engine.authorize_network(&request), "ancestors");
    });
}

#[test]
fn many_graphql_paths_load_in_linear_time() {
    // Each GraphQL path is decided without the REST permit, which used to
    // copy the policy set twice per path: 1,470 paths took 27 s and 5 GB.
    let graphql = |index: usize| {
        format!(
            r#"@path("/g{index}") @protocol("graphql")
permit (principal, action == Sandbox::Action::"HttpRequest", resource == Sandbox::NetworkEndpoint::"{HOST}:443") when {{ context.graphql_operation_type == "query" }};
"#
        )
    };
    let rest = format!(
        r#"@path("/**") @id("rest")
permit (principal, action == Sandbox::Action::"HttpRequest", resource == Sandbox::NetworkEndpoint::"{HOST}:443") when {{ context.method == "POST" }};
"#
    );
    let paths = 1_000;
    let policy: String = std::iter::once(rest)
        .chain((0..paths).map(graphql))
        .collect();
    assert!(policy.len() <= MAX_POLICY_SOURCE_BYTES);
    let started = Instant::now();
    let engine = load(&policy).expect("policy loads");
    let elapsed = started.elapsed();
    // A generous bound for loaded CI runners; the structure is pinned by
    // `graphql_exclusions_share_one_host_set_per_endpoint` in the crate.
    assert!(
        elapsed < Duration::from_mins(1),
        "{paths} GraphQL paths took {elapsed:?}"
    );
    assert_eq!(engine.l7_endpoints(HOST, 443).count(), paths + 1);

    let operation = |kind: &str, path: &str| HttpRequestInput {
        method: "POST".to_string(),
        graphql_operation_type: kind.to_string(),
        graphql_request: true,
        endpoint_path: path.to_string(),
        ..request(path)
    };
    let mutation = engine
        .evaluate_l7(&operation("mutation", "/g999"))
        .expect("evaluates");
    assert_eq!(
        mutation.decision,
        Decision::Deny {
            matched_policies: Vec::new()
        },
        "the REST permit is left out of GraphQL decisions"
    );
    assert!(
        engine
            .evaluate_l7(&operation("query", "/g0"))
            .expect("evaluates")
            .is_allow()
    );
    let rest_request = HttpRequestInput {
        method: "POST".to_string(),
        endpoint_path: "/**".to_string(),
        ..request("/other")
    };
    assert!(
        engine
            .evaluate_l7(&rest_request)
            .expect("evaluates")
            .is_allow()
    );
}
