// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks `context.binary_globs`: which binary glob patterns a policy set
//! asks the supervisor to match, the forms it accepts, and how the set
//! decides requests on both network actions.

use openshell_policy_cedar::{
    CedarEngine, CedarEngineError, HttpRequestInput, NetworkConnectRequest,
};

fn load(policy: &str) -> Result<CedarEngine, CedarEngineError> {
    CedarEngine::from_policy_str(policy)
}

fn connect(binary: &str, globs: &[&str]) -> NetworkConnectRequest {
    NetworkConnectRequest {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        host: "api.openai.com".to_string(),
        port: 443,
        binary_path: binary.to_string(),
        ancestors: Vec::new(),
        binary_aliases: Vec::new(),
        binary_globs: globs.iter().map(ToString::to_string).collect(),
        destination_ip: None,
    }
}

/// The Cedar form of the YAML binary glob `/usr/lib/node_modules/@openai/**`.
const CODEX: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.openai.com:443")
when { context.binary_globs.contains("/usr/lib/node_modules/@openai/**") };
"#;

#[test]
fn glob_patterns_are_collected_from_every_accepted_form() {
    let policy = format!(
        r#"{CODEX}
forbid (principal, action in [Sandbox::Action::"NetworkConnect", Sandbox::Action::"HttpRequest"],
        resource == Sandbox::NetworkEndpoint::"api.openai.com:443")
when {{
    context.binary_globs.containsAny(["/opt/*/bin/tool", "/usr/lib/node_modules/@openai/**"])
    || context.binary_globs.containsAll(["/tmp/*"])
}};
"#
    );
    let engine = load(&policy).expect("policy loads");
    assert_eq!(
        engine.binary_glob_patterns().collect::<Vec<_>>(),
        [
            "/opt/*/bin/tool",
            "/tmp/*",
            "/usr/lib/node_modules/@openai/**"
        ]
    );
    assert_eq!(
        load(
            r#"permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { context.binary_path == "/x" };"#
        )
        .expect("policy loads")
        .binary_glob_patterns()
        .count(),
        0
    );
}

#[test]
fn unsupported_glob_forms_are_rejected() {
    let policy = |condition: &str| {
        format!(
            r#"permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {{ {condition} }};"#
        )
    };
    for condition in [
        // Not a glob: an exact path belongs in binary_path and binary_aliases.
        r#"context.binary_globs.contains("/usr/bin/curl")"#,
        // Not absolute.
        r#"context.binary_globs.contains("node_modules/**")"#,
        // Not a valid glob.
        r#"context.binary_globs.contains("/opt/[*/tool")"#,
        // Computed and non-literal elements.
        r"context.binary_globs.contains(context.binary_path)",
        r"context.binary_globs.containsAny([context.binary_path])",
        r"context.binary_globs.containsAll(context.ancestors)",
        // Other uses of the set.
        r"context.binary_globs.isEmpty()",
        r#"context.binary_globs == ["/opt/*"]"#,
    ] {
        let error = load(&policy(condition)).expect_err(condition);
        assert!(
            matches!(error, CedarEngineError::InvalidBinaryGlob { .. }),
            "{condition}: {error}"
        );
    }
    // The whole context record includes both binary sets; the alias check
    // reports it first.
    let error = load(&policy("context == context")).expect_err("whole context");
    assert!(
        matches!(error, CedarEngineError::InvalidBinaryAlias { .. }),
        "{error}"
    );
}

#[test]
fn a_glob_matches_a_connection_like_the_yaml_binary_glob() {
    // The supervisor lists the patterns matching the binary or an ancestor;
    // Cedar only tests membership, so a matched pattern allows whichever
    // process it matched through.
    let engine = load(CODEX).expect("policy loads");
    let allows = |request| engine.evaluate_network(&request).unwrap().is_allow();
    assert!(allows(connect(
        "/usr/lib/node_modules/@openai/codex/bin/codex.js",
        &["/usr/lib/node_modules/@openai/**"]
    )));
    assert!(allows(connect(
        "/usr/bin/node",
        &["/usr/lib/node_modules/@openai/**"]
    )));
    assert!(!allows(connect("/usr/bin/node", &[])));
    assert!(!allows(connect(
        "/usr/bin/node",
        &["/usr/lib/node_modules/@other/**"]
    )));
}

#[test]
fn a_glob_reaches_a_forbid_on_requests() {
    let policy = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.openai.com:443");
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.openai.com:443");
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.openai.com:443")
when { context.binary_globs.contains("/tmp/**") && context.method == "DELETE" };
"#;
    let engine = load(policy).expect("policy loads");
    let allows = |globs: &[&str]| {
        engine
            .evaluate_l7(&HttpRequestInput {
                user: "sandbox".to_string(),
                group: "sandbox".to_string(),
                binary_path: "/usr/bin/curl".to_string(),
                ancestors: vec!["/tmp/run.sh".to_string()],
                binary_globs: globs.iter().map(ToString::to_string).collect(),
                host: "api.openai.com".to_string(),
                port: 443,
                method: "DELETE".to_string(),
                path: "/v1/files/1".to_string(),
                ..Default::default()
            })
            .unwrap()
            .is_allow()
    };
    assert!(allows(&[]));
    assert!(!allows(&["/tmp/**"]));
}
