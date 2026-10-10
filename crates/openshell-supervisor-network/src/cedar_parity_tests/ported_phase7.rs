// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ported YAML tests for symlinked binary paths (Cedar parity plan, phase 7).
//!
//! Once the entrypoint process is known, YAML resolves each exact binary path
//! through `/proc/<pid>/root` and adds a symlink's target as another binary
//! entry, which matches the process's binary or an ancestor. A Cedar policy
//! reads the same expansion as `context.binary_aliases`, so an exact YAML
//! binary `B` is translated as
//! `context.binary_path == B || context.ancestors.contains(B) ||
//! context.binary_aliases.contains(B)`. A glob binary is never resolved by
//! either format.
//!
//! Like the originals, these tests resolve symlinks in a temporary directory
//! through this test process's own `/proc/<pid>/root`, so they run on Linux
//! only and skip where that root is not traversable. Both engines resolve
//! either at load (YAML `from_proto_with_pid`, Cedar
//! `resolve_binary_symlinks`) or on a reload with the pid (YAML
//! `reload_from_proto_with_pid`, Cedar `stage` with the pid and `commit`).

use std::os::unix::fs::symlink;

use super::*;

/// The Cedar condition for a YAML binary entry with an exact path.
fn binary(path: &str) -> String {
    format!(
        "(context.binary_path == \"{path}\" || context.ancestors.contains(\"{path}\") \
         || context.binary_aliases.contains(\"{path}\"))"
    )
}

/// The Cedar condition for a YAML binary entry with a glob path.
fn binary_glob(pattern: &str) -> String {
    format!("context.binary_path like(\"{pattern}\", \"/\")")
}

/// A symlink `link` to the file `target`, in temporary directories that live
/// as long as this value.
struct Symlink {
    _dirs: Vec<tempfile::TempDir>,
    link: String,
    target: String,
}

impl Symlink {
    /// Creates `link_name` in one directory pointing at `target_name` in
    /// `target_dir`, or in the same directory when `target_dir` is `false`.
    ///
    /// Returns `None` where `/proc/<pid>/root` does not resolve it, as the
    /// originals skip.
    fn new(link_name: &str, target_name: &str, separate_dirs: bool) -> Option<Self> {
        let link_dir = tempfile::tempdir().expect("tempdir");
        let target_dir = separate_dirs.then(|| tempfile::tempdir().expect("tempdir"));
        let target = target_dir
            .as_ref()
            .unwrap_or(&link_dir)
            .path()
            .join(target_name);
        let link = link_dir.path().join(link_name);
        std::fs::write(&target, b"binary").expect("target");
        symlink(&target, &link).expect("symlink");
        let symlink = Self {
            link: link.to_string_lossy().into_owned(),
            target: target.to_string_lossy().into_owned(),
            _dirs: std::iter::once(link_dir).chain(target_dir).collect(),
        };
        if crate::opa::resolve_policy_binary(&symlink.link, std::process::id()).is_none() {
            eprintln!("Skipping: /proc/<pid>/root/ not accessible in this environment");
            return None;
        }
        Some(symlink)
    }

    /// The directory holding the link.
    fn link_dir(&self) -> &str {
        self.link
            .rsplit_once('/')
            .map_or("", |(directory, _)| directory)
    }
}

/// When the engines learn the entrypoint process.
enum Resolution {
    /// At load.
    AtLoad,
    /// On a reload of the same policy; `before` runs first, on engines loaded
    /// without it.
    OnReload { before: Vec<Case> },
}

/// Runs `scenario` with both engines resolving binary symlinks in this test
/// process's root filesystem.
fn assert_symlink_parity(scenario: &Scenario<'_>, resolution: Resolution) {
    let pid = std::process::id();
    let yaml = openshell_policy::parse_sandbox_policy(scenario.yaml)
        .unwrap_or_else(|error| panic!("{}: YAML policy parses: {error:?}", scenario.name));
    let cedar = openshell_core::proto::SandboxPolicy {
        cedar_policy_source: scenario.cedar.to_string(),
        ..Default::default()
    };
    let load = |pid: u32| {
        let opa = OpaEngine::from_proto_with_pid(&yaml, pid)
            .unwrap_or_else(|error| panic!("{}: YAML policy loads: {error}", scenario.name));
        let cedar_engine = CedarOnlyEngine::from_proto(&cedar)
            .unwrap_or_else(|error| panic!("{}: Cedar policy loads: {error}", scenario.name));
        cedar_engine
            .resolve_binary_symlinks(pid)
            .unwrap_or_else(|error| panic!("{}: Cedar resolves: {error}", scenario.name));
        Engines::new(opa, cedar_engine)
    };
    match resolution {
        Resolution::AtLoad => {
            let engines = load(pid);
            report_parity(run(scenario.name, scenario.host, &engines, &scenario.cases));
        }
        Resolution::OnReload { before } => {
            let engines = load(0);
            let startup = format!("{} (before pid)", scenario.name);
            let (mut report, mut failures) = run(&startup, scenario.host, &engines, &before);
            engines
                .opa
                .reload_from_proto_with_pid(&yaml, pid)
                .unwrap_or_else(|error| panic!("{}: YAML policy reloads: {error}", scenario.name));
            let staged = engines
                .cedar
                .stage(&cedar, pid)
                .unwrap_or_else(|error| panic!("{}: Cedar policy stages: {error}", scenario.name));
            engines
                .cedar
                .commit(staged)
                .unwrap_or_else(|error| panic!("{}: Cedar policy commits: {error}", scenario.name));
            let reload = format!("{} (reload with pid)", scenario.name);
            let (reloaded, reload_failures) =
                run(&reload, scenario.host, &engines, &scenario.cases);
            report.push_str(&reloaded);
            failures.extend(reload_failures);
            report_parity((report, failures));
        }
    }
}

/// A connection-only YAML policy for `host:443` and the binary `path`, and
/// its Cedar translation.
fn connect_policy(name: &str, host: &str, path: &str) -> (String, String) {
    let yaml = format!(
        r#"
version: 1
network_policies:
  {name}:
    name: {name}
    endpoints:
      - host: {host}
        port: 443
    binaries:
      - path: "{path}"
"#
    );
    let cedar = format!(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"{host}:443")
when {{ {} }};
"#,
        binary(path)
    );
    (yaml, cedar)
}

// ---------------------------------------------------------------------------
// opa.rs::from_proto_with_pid_expands_symlinks_in_container
// ---------------------------------------------------------------------------

#[test]
fn ported_from_proto_with_pid_expands_symlinks() {
    const NAME: &str = "opa.rs::from_proto_with_pid_expands_symlinks_in_container";
    let Some(node) = Symlink::new("node", "node22", false) else {
        return;
    };
    let (yaml, cedar) = connect_policy("test", "example.com", &node.link);
    let connect = |binary: &str, ancestors: &[&str]| {
        Probe::Connect(network_with_ancestors(
            "example.com",
            443,
            binary,
            ancestors,
        ))
    };
    assert_symlink_parity(
        &Scenario {
            name: "Symlinked binary resolved at load",
            host: "example.com",
            yaml: &yaml,
            cedar: &cedar,
            cases: vec![
                same_probe(format!("{NAME} target"), connect(&node.target, &[]))
                    .asserting_yaml("allow"),
                same_probe(format!("{NAME} link"), connect(&node.link, &[])),
                // The added entry matches an ancestor like any exact entry.
                same_probe(
                    format!("{NAME} target as ancestor"),
                    connect(BINARY, &[&node.target]),
                )
                .asserting_yaml("allow"),
                same_probe(format!("{NAME} other binary"), connect(BINARY, &[]))
                    .asserting_yaml("deny"),
            ],
        },
        Resolution::AtLoad,
    );
}

// ---------------------------------------------------------------------------
// opa.rs::reload_from_proto_with_pid_resolves_symlinks
// ---------------------------------------------------------------------------

#[test]
fn ported_reload_with_pid_resolves_symlinks() {
    const NAME: &str = "opa.rs::reload_from_proto_with_pid_resolves_symlinks";
    let Some(python) = Symlink::new("python3", "python3.11", false) else {
        return;
    };
    let (yaml, cedar) = connect_policy("python", "pypi.org", &python.link);
    let connect = |binary: &str| Probe::Connect(network("pypi.org", 443, binary));
    assert_symlink_parity(
        &Scenario {
            name: "Symlinked binary resolved on reload",
            host: "pypi.org",
            yaml: &yaml,
            cedar: &cedar,
            cases: vec![
                same_probe(format!("{NAME} target after"), connect(&python.target))
                    .asserting_yaml("allow"),
                same_probe(format!("{NAME} link after"), connect(&python.link))
                    .asserting_yaml("allow"),
            ],
        },
        Resolution::OnReload {
            before: vec![
                same_probe(format!("{NAME} target before"), connect(&python.target))
                    .asserting_yaml("deny"),
                same_probe(format!("{NAME} link before"), connect(&python.link))
                    .asserting_yaml("allow"),
            ],
        },
    );
}

// ---------------------------------------------------------------------------
// opa.rs::exact_deny_symlink_expands_but_glob_deny_does_not
// ---------------------------------------------------------------------------

/// The original's policy, with the `deny` policy's binary `deny_binary`, and
/// its Cedar translation with the `deny` binary condition `deny_condition`.
fn deny_policy(target: &str, deny_binary: &str, deny_condition: &str) -> (String, String) {
    let yaml = format!(
        r#"
version: 1
network_policies:
  grant:
    endpoints:
      - host: example.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules: [{{ allow: {{ method: GET, path: "/**" }} }}]
    binaries: [{{ path: "{target}" }}]
  deny:
    endpoints:
      - host: example.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules: [{{ allow: {{ method: GET, path: "/**" }} }}]
        deny_rules: [{{ method: "*", path: "/**" }}]
    binaries: [{{ path: "{deny_binary}" }}]
filesystem_policy:
  include_workdir: false
  read_only: []
  read_write: []
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
"#
    );
    let grant = binary(target);
    let cedar = format!(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"example.com:443")
when {{ {grant} || {deny_condition} }};
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"example.com:443")
when {{
    ({grant} || {deny_condition})
    && ["GET", "HEAD"].contains(context.method)
    && context.path like("/**", "/")
}};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"example.com:443")
when {{ {deny_condition} && context.path like("/**", "/") }};
"#
    );
    (yaml, cedar)
}

#[test]
fn ported_exact_deny_symlink_expands_but_glob_deny_does_not() {
    const NAME: &str = "opa.rs::exact_deny_symlink_expands_but_glob_deny_does_not";
    let Some(python) = Symlink::new("python", "python3", true) else {
        return;
    };
    let get_from = |binary: &str| request_in(l7_ctx("example.com", 443, binary), rest("GET", "/"));

    // The maximum policy denies through the link, which resolves to the
    // target the grant names.
    let (yaml, cedar) = deny_policy(&python.target, &python.link, &binary(&python.link));
    assert_symlink_parity(
        &Scenario {
            name: "Exact deny binary through a symlink",
            host: "example.com",
            yaml: &yaml,
            cedar: &cedar,
            cases: vec![
                same_probe(format!("{NAME} maximum"), get_from(&python.target))
                    .asserting_yaml("deny"),
                same_probe(
                    format!("{NAME} maximum connect"),
                    Probe::Connect(network("example.com", 443, &python.target)),
                )
                .asserting_yaml("allow"),
                same_probe(format!("{NAME} maximum other binary"), get_from(BINARY))
                    .asserting_yaml("deny"),
            ],
        },
        Resolution::AtLoad,
    );

    // The candidate policy's glob covers the link's directory, not the
    // target's, and is never resolved.
    let glob = format!("{}/*", python.link_dir());
    let (yaml, cedar) = deny_policy(&python.target, &glob, &binary_glob(&glob));
    assert_symlink_parity(
        &Scenario {
            name: "Glob deny binary over a symlink's directory",
            host: "example.com",
            yaml: &yaml,
            cedar: &cedar,
            cases: vec![
                same_probe(format!("{NAME} candidate"), get_from(&python.target))
                    .asserting_yaml("allow"),
                same_probe(format!("{NAME} candidate link"), get_from(&python.link))
                    .asserting_yaml("deny"),
            ],
        },
        Resolution::AtLoad,
    );
}
