// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Parity of the repository's example YAML policies with their Cedar versions.
//!
//! Each example YAML policy has a `.cedar` file beside it (and a middleware
//! file when the YAML has `network_middlewares`, endpoint settings, or a
//! `process` section). These tests load both from
//! disk the way the CLI loads them, rendering templates with the sample values
//! their scripts substitute, so a broken example fails here.
//!
//! The network probes are generated from the YAML structure: for every
//! endpoint, connections from each listed binary (directly and as an
//! ancestor), from an unlisted binary, to another port and an unlisted host,
//! policy DNS eligibility and answers, destination address checks, the
//! selected inspection and endpoint settings, and for inspected endpoints a
//! request for every method on paths derived from each rule's path glob, plus
//! a relayed exchange. The tests also compare the effective Landlock grants,
//! Landlock compatibility, process identity, and the middleware chain each
//! engine selects.

use std::collections::BTreeSet;

use openshell_core::proto::SandboxPolicy;

use super::*;

/// The workdir `include_workdir` grants in the default sandbox image.
const WORKDIR: &str = "/sandbox";

/// A binary no example policy lists.
const UNLISTED_BINARY: &str = "/usr/bin/unlisted-tool";

/// A process that no example lists by name, used as the child of a listed
/// binary to exercise ancestor matching.
const CHILD_BINARY: &str = "/usr/bin/child-process";

/// A host no example policy lists.
const UNLISTED_HOST: &str = "unlisted.example.net";

/// Methods every inspected endpoint is probed with. The lowercase spelling
/// checks that both engines compare methods case-insensitively.
const METHODS: &[&str] = &[
    "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "get",
];

/// Read-only and read-write baseline paths the supervisor adds for proxy-mode
/// sandboxes; `PROXY_BASELINE_READ_ONLY` and `PROXY_BASELINE_READ_WRITE` in
/// `openshell-supervisor`, which depends on this crate.
const BASELINE_READ_ONLY: &[&str] = &[
    "/usr",
    "/lib",
    "/etc",
    "/app",
    "/var/log",
    "/proc",
    "/dev/urandom",
];
const BASELINE_READ_WRITE: &[&str] = &["/tmp", "/dev/null"];

/// Sample values the multi-agent notepad demo substitutes into its template.
const NOTEPAD_VALUES: &[(&str, &str)] = &[
    ("__OWNER__", "octo-org"),
    ("__REPO__", "notepad"),
    ("__RUN_ID__", "20260101-120000"),
];

// Known differences. Each matches a difference documented in
// docs/how-it-works/policies/cedar.mdx.

/// Cedar has no `process` section; a middleware file may set one.
const PROCESS_IDENTITY: &str = "a Cedar policy carries no process section and the example's middleware \
     file does not set one; the compute driver selects the identity, as for a YAML policy that \
     omits it";

/// One example: its YAML policy, its Cedar version, and its middleware file.
struct Example {
    name: &'static str,
    yaml: String,
    cedar: String,
    middleware: Option<String>,
    /// The sandbox workdir, which YAML `include_workdir` grants.
    workdir: &'static str,
    /// A provider profile the example attaches. The gateway adds its rules
    /// to a YAML policy's network policies, and gives them to a Cedar
    /// sandbox as credential rules only.
    provider: Option<&'static str>,
}

impl Example {
    fn new(name: &'static str, yaml: &str, cedar: &str) -> Self {
        Self {
            name,
            yaml: yaml.to_string(),
            cedar: cedar.to_string(),
            middleware: None,
            workdir: WORKDIR,
            provider: None,
        }
    }

    fn with_middleware(self, middleware: &str) -> Self {
        Self {
            middleware: Some(middleware.to_string()),
            ..self
        }
    }

    /// Renders every file of a template, replacing each `from` with `to`,
    /// as its script does.
    fn rendered(self, values: &[(&str, &str)]) -> Self {
        let render = |text: &str| {
            values
                .iter()
                .fold(text.to_string(), |text, (from, to)| text.replace(from, to))
        };
        let example = Self {
            yaml: render(&self.yaml),
            cedar: render(&self.cedar),
            middleware: self.middleware.as_deref().map(render),
            ..self
        };
        let unrendered = |text: &str| {
            text.lines().any(|line| {
                let line = line.trim_start();
                !line.starts_with("//")
                    && !line.starts_with('#')
                    && (line.contains("__") || line.contains("${"))
            })
        };
        assert!(
            !unrendered(&example.yaml)
                && !unrendered(&example.cedar)
                && !example.middleware.as_deref().is_some_and(unrendered),
            "{}: every placeholder is rendered",
            example.name
        );
        example
    }
}

/// Both policies of an example, loaded as the CLI loads them.
struct Loaded {
    yaml: SandboxPolicy,
    cedar: SandboxPolicy,
    engines: Engines,
}

impl Loaded {
    fn new(example: &Example) -> Self {
        let mut yaml = openshell_policy::parse_sandbox_policy(&example.yaml)
            .unwrap_or_else(|error| panic!("{}: YAML policy parses: {error:?}", example.name));
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("policy.cedar");
        std::fs::write(&path, &example.cedar).expect("write Cedar policy");
        // The CLI's client-side loader validates the Cedar policy.
        let mut cedar = openshell_policy::parse_sandbox_policy_file_auto(&path)
            .unwrap_or_else(|error| panic!("{}: Cedar policy loads: {error:?}", example.name));
        assert_eq!(cedar.cedar_policy_source, example.cedar);
        if let Some(middleware) = &example.middleware {
            let path = dir.path().join("middleware.yaml");
            std::fs::write(&path, middleware).expect("write middleware file");
            openshell_policy::apply_middleware_file(&mut cedar, &path).unwrap_or_else(|error| {
                panic!("{}: middleware file applies: {error:?}", example.name)
            });
            openshell_policy::validate_sandbox_policy(&cedar).unwrap_or_else(|errors| {
                panic!(
                    "{}: policy with middleware validates: {errors:?}",
                    example.name
                )
            });
        }
        if let Some(profile) = example.provider {
            let profile = openshell_providers::parse_profile_yaml(profile)
                .unwrap_or_else(|error| panic!("{}: profile parses: {error}", example.name));
            let rule = provider_rules::composed_rule(&profile);
            yaml.network_policies
                .insert(rule.name.clone(), rule.clone());
            cedar
                .provider_credential_rules
                .insert(rule.name.clone(), rule);
        }
        let opa = OpaEngine::from_proto(&yaml)
            .unwrap_or_else(|error| panic!("{}: YAML engine loads: {error}", example.name));
        let engine = CedarOnlyEngine::from_proto(&cedar)
            .unwrap_or_else(|error| panic!("{}: Cedar engine loads: {error}", example.name));
        Self {
            yaml,
            cedar,
            engines: Engines::new(opa, engine),
        }
    }
}

/// One YAML endpoint, flattened with its policy's binaries.
struct Endpoint {
    policy: String,
    host: String,
    ports: Vec<u16>,
    protocol: String,
    /// The endpoint `path`, which selects the requests it inspects.
    path: String,
    allowed_ips: Vec<String>,
    binaries: Vec<String>,
    /// The path glob of each allow rule and deny rule, with access presets
    /// expanded as the YAML engine expands them. Requests probe each with
    /// every method in [`METHODS`].
    rule_paths: Vec<String>,
}

/// Reads every endpoint of a YAML policy.
fn endpoints(name: &str, yaml: &str) -> Vec<Endpoint> {
    let mut data: serde_json::Value = serde_yml::from_str(yaml).expect("YAML parses as data");
    let warnings = crate::l7::expand_access_presets(&mut data);
    assert!(warnings.is_empty(), "{name}: {warnings:?}");
    let Some(policies) = data["network_policies"].as_object() else {
        return Vec::new();
    };
    let strings = |value: &serde_json::Value| -> Vec<String> {
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect()
    };
    let mut keys: Vec<&String> = policies.keys().collect();
    keys.sort();
    let mut endpoints = Vec::new();
    for key in keys {
        let policy = &policies[key];
        let binaries: Vec<String> = policy["binaries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|binary| binary["path"].as_str().map(str::to_string))
            .collect();
        for endpoint in policy["endpoints"].as_array().into_iter().flatten() {
            let mut ports: Vec<u16> = endpoint["ports"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|port| port.as_u64().and_then(|port| u16::try_from(port).ok()))
                .collect();
            if let Some(port) = endpoint["port"].as_u64() {
                ports.push(u16::try_from(port).expect("port fits in u16"));
            }
            let protocol = endpoint["protocol"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            assert!(
                ["", "tcp", "rest", "mcp"].contains(&protocol.as_str()),
                "{name}: add probes for protocol {protocol}"
            );
            let mut rule_paths = Vec::new();
            for rule in endpoint["rules"].as_array().into_iter().flatten() {
                assert!(
                    rule["allow"].get("query").is_none(),
                    "{name}: add query probes"
                );
                rule_paths.push(rule["allow"]["path"].as_str().unwrap_or("**").to_string());
            }
            for rule in endpoint["deny_rules"].as_array().into_iter().flatten() {
                assert!(rule.get("query").is_none(), "{name}: add query probes");
                rule_paths.push(rule["path"].as_str().unwrap_or("**").to_string());
            }
            endpoints.push(Endpoint {
                policy: key.clone(),
                host: endpoint["host"].as_str().unwrap_or_default().to_string(),
                ports,
                protocol,
                path: endpoint["path"].as_str().unwrap_or_default().to_string(),
                allowed_ips: strings(&endpoint["allowed_ips"]),
                binaries: binaries.clone(),
                rule_paths,
            });
        }
    }
    endpoints
}

/// A binary path a YAML binary glob matches, or the path itself.
fn binary_sample(binary: &str) -> String {
    binary.replace("**", "sample/bin").replace('*', "sample")
}

/// A request path a YAML rule path glob matches.
fn path_inside(pattern: &str) -> String {
    if pattern == "**" {
        "/any/deep/path".to_string()
    } else {
        pattern.replace("**", "deep/er").replace('*', "seg")
    }
}

/// Request paths inside and just outside a YAML rule path glob.
fn path_samples(pattern: &str) -> BTreeSet<String> {
    let mut samples = BTreeSet::from([path_inside(pattern)]);
    if pattern == "**" {
        return samples;
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        samples.insert(prefix.to_string());
        samples.insert(format!("{prefix}/"));
        samples.insert(format!("{prefix}-sibling"));
        samples.insert(format!("{prefix}/a/b/c"));
    } else if pattern.contains('*') {
        // An empty match, and a match that would cross a segment.
        samples.insert(pattern.replace('*', ""));
        samples.insert(pattern.replace('*', "seg/extra"));
    } else {
        samples.insert(format!("{pattern}/extra"));
        samples.insert(format!("{pattern}x"));
        if let Some((parent, _)) = pattern.rsplit_once('/')
            && !parent.is_empty()
        {
            samples.insert(parent.to_string());
        }
    }
    samples
}

/// An address inside `range`, a few hosts past its network address.
fn address_in(range: &str) -> IpAddr {
    let net: ipnet::IpNet = range.parse().expect("allowed_ips entry is a CIDR range");
    net.hosts().nth(4).expect("range has hosts")
}

fn public_address() -> IpAddr {
    IpAddr::from([8, 8, 8, 8])
}

fn private_address() -> IpAddr {
    IpAddr::from([100, 64, 0, 9])
}

fn metadata_address() -> IpAddr {
    IpAddr::from([169, 254, 169, 254])
}

fn loopback_address() -> IpAddr {
    IpAddr::from([127, 0, 0, 1])
}

/// A raw HTTP/1 request that closes the connection.
fn http_request(method: &str, path: &str, host: &str) -> String {
    format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

/// Cases being generated, with the example's known differences.
struct Cases<'a> {
    known: &'a dyn Fn(&str) -> Option<&'static str>,
    list: Vec<Case>,
}

impl Cases<'_> {
    /// Adds a case, recording the known difference for its name, if any.
    fn add(&mut self, name: String, probe: Probe) {
        let reason = (self.known)(&name);
        self.add_known(name, probe, reason);
    }

    fn add_known(&mut self, name: String, probe: Probe, reason: Option<&'static str>) {
        self.list.push(match reason {
            Some(reason) => diverges_probe(name, probe, reason),
            None => same_probe(name, probe),
        });
    }
}

/// Generates the network cases of one endpoint.
fn endpoint_cases(endpoint: &Endpoint, cases: &mut Cases<'_>) {
    let host = endpoint.host.as_str();
    let samples: Vec<String> = endpoint
        .binaries
        .iter()
        .map(|binary| binary_sample(binary))
        .collect();
    // A process every engine should treat as allowed, if any binary is listed.
    let allowed = samples
        .first()
        .cloned()
        .unwrap_or_else(|| BINARY.to_string());
    let answers: Vec<IpAddr> = vec![
        endpoint
            .allowed_ips
            .first()
            .map_or_else(|| TRANSPARENT_UPSTREAM.into(), |range| address_in(range)),
    ];
    for &port in &endpoint.ports {
        let at = format!("{}: {host}:{port}", endpoint.policy);
        for sample in &samples {
            cases.add(
                format!("{at} connect from {sample}"),
                Probe::Connect(network(host, port, sample)),
            );
            cases.add(
                format!("{at} connect from a child of {sample}"),
                Probe::Connect(network_with_ancestors(host, port, CHILD_BINARY, &[sample])),
            );
        }
        let input = || network(host, port, &allowed);
        cases.add(
            format!("{at} connect from an unlisted binary"),
            Probe::Connect(network(host, port, UNLISTED_BINARY)),
        );
        cases.add(
            format!("{at} other port"),
            Probe::Connect(network(host, port.wrapping_add(1), &allowed)),
        );
        cases.add(
            format!("{at} unlisted host"),
            Probe::Connect(network(UNLISTED_HOST, port, &allowed)),
        );
        cases.add(format!("{at} exact host"), Probe::ExactHost(input()));
        cases.add(format!("{at} inspection"), Probe::Inspection(input()));
        cases.add(format!("{at} endpoint configs"), Probe::Configs(input()));
        cases.add(format!("{at} TLS mode"), Probe::TlsMode(input()));
        cases.add(
            format!("{at} matched DNS records"),
            Probe::MatchedEndpoints(input()),
        );
        cases.add(
            format!("{at} DNS eligible"),
            Probe::DnsEligible {
                name: host.to_string(),
                port,
            },
        );
        cases.add(
            format!("{at} DNS eligible on another port"),
            Probe::DnsEligible {
                name: host.to_string(),
                port: port.wrapping_add(1),
            },
        );
        let mut addresses = vec![
            ("public", public_address()),
            ("private", private_address()),
            ("metadata", metadata_address()),
            ("loopback", loopback_address()),
        ];
        for range in &endpoint.allowed_ips {
            addresses.push(("in allowed_ips", address_in(range)));
        }
        for (kind, address) in addresses {
            cases.add(
                format!("{at} destination {kind} {address}"),
                Probe::Destination {
                    input: input(),
                    addresses: vec![address],
                },
            );
            cases.add(
                format!("{at} DNS answer {kind} {address}"),
                Probe::DnsAnswers {
                    name: host.to_string(),
                    port,
                    answers: vec![address],
                },
            );
        }
        cases.add(
            format!("{at} transparent open"),
            Probe::TransparentOpen {
                name: host.to_string(),
                port,
                binary: allowed.clone(),
                answers: answers.clone(),
            },
        );
        cases.add(
            format!("{at} transparent open from an unlisted binary"),
            Probe::TransparentOpen {
                name: host.to_string(),
                port,
                binary: UNLISTED_BINARY.to_string(),
                answers: answers.clone(),
            },
        );
        match endpoint.protocol.as_str() {
            "rest" => request_cases(endpoint, port, &allowed, cases),
            "mcp" => mcp_cases(endpoint, port, &allowed, cases),
            _ => {}
        }
    }
}

/// Generates the request cases of an inspected REST endpoint on `port`.
fn request_cases(endpoint: &Endpoint, port: u16, allowed: &str, cases: &mut Cases<'_>) {
    let host = endpoint.host.as_str();
    let at = format!("{}: {host}:{port}", endpoint.policy);
    let mut paths: BTreeSet<String> = endpoint
        .rule_paths
        .iter()
        .flat_map(|pattern| path_samples(pattern))
        .collect();
    paths.insert("/".to_string());
    paths.insert("/unlisted/path".to_string());
    for path in &paths {
        for method in METHODS {
            cases.add(
                format!("{at} {method} {path}"),
                request_in(l7_ctx(host, port, allowed), rest(method, path)),
            );
        }
    }
    let first = endpoint
        .rule_paths
        .first()
        .map_or_else(|| "/".to_string(), |pattern| path_inside(pattern));
    for binary in &endpoint.binaries {
        let sample = binary_sample(binary);
        cases.add(
            format!("{at} GET {first} from {sample}"),
            request_in(l7_ctx(host, port, &sample), rest("GET", &first)),
        );
        let child = L7EvalContext {
            ancestors: vec![sample.clone()],
            ..l7_ctx(host, port, CHILD_BINARY)
        };
        cases.add(
            format!("{at} GET {first} from a child of {sample}"),
            request_in(child, rest("GET", &first)),
        );
    }
    cases.add(
        format!("{at} GET {first} from an unlisted binary"),
        request_in(l7_ctx(host, port, UNLISTED_BINARY), rest("GET", &first)),
    );
    // Token-grant owners: attached providers' credentials apply only where
    // both engines admit the provider's endpoint.
    for method in ["GET", "POST", "DELETE"] {
        cases.add(
            format!("{at} token-grant owners for {method} {first}"),
            owners_in(l7_ctx(host, port, allowed), rest(method, &first)),
        );
    }
    for (method, path) in [("GET", first.as_str()), ("DELETE", "/unlisted/path")] {
        cases.add(
            format!("{at} relayed {method} {path}"),
            Probe::Relay(Box::new(RelayExchange {
                ctx: l7_ctx(host, port, allowed),
                route_selected: false,
                request: http_request(method, path, host),
                upstream_response: NO_CONTENT.to_string(),
                marker: None,
            })),
        );
    }
}

/// Generates the request cases of an inspected MCP endpoint on `port`.
fn mcp_cases(endpoint: &Endpoint, port: u16, allowed: &str, cases: &mut Cases<'_>) {
    use McpMethodClassification::{Available, Extension};
    let host = endpoint.host.as_str();
    let at = format!("{}: {host}:{port}", endpoint.policy);
    let path = endpoint.path.as_str();
    assert!(
        !path.is_empty() && !path.contains('*'),
        "{at}: add probes for MCP path {path:?}"
    );
    let calls = |method: &str, tool: Option<&str>, class| {
        jsonrpc_request(path, vec![call(method, tool, Some(class))])
    };
    let frames = |receive_stream, has_response, method: &str| L7RequestInfo {
        jsonrpc: Some(JsonRpcRequestInfo {
            receive_stream,
            has_response,
            ..jsonrpc_info(Vec::new())
        }),
        ..rest(method, path)
    };
    let requests = [
        ("initialize", calls("initialize", None, Available)),
        ("tools/list", calls("tools/list", None, Available)),
        ("tools/call", calls("tools/call", Some("echo"), Available)),
        ("resources/read", calls("resources/read", None, Available)),
        ("an extension method", calls("x/custom", None, Extension)),
        (
            "tools/call sent with GET",
            L7RequestInfo {
                action: "GET".to_string(),
                ..calls("tools/call", Some("echo"), Available)
            },
        ),
        (
            "initialize on another path",
            jsonrpc_request(
                "/elsewhere",
                vec![call("initialize", None, Some(Available))],
            ),
        ),
        ("the receive stream", frames(true, false, "GET")),
        ("a response frame", frames(false, true, "POST")),
        ("a response frame sent with GET", frames(false, true, "GET")),
        ("a plain GET", rest("GET", path)),
        ("a plain DELETE", rest("DELETE", path)),
    ];
    for (what, request) in requests {
        cases.add(
            format!("{at} {what}"),
            request_in(l7_ctx(host, port, allowed), request),
        );
    }
    for binary in &endpoint.binaries {
        let sample = binary_sample(binary);
        cases.add(
            format!("{at} initialize from {sample}"),
            request_in(
                l7_ctx(host, port, &sample),
                calls("initialize", None, Available),
            ),
        );
        let child = L7EvalContext {
            ancestors: vec![sample.clone()],
            ..l7_ctx(host, port, CHILD_BINARY)
        };
        cases.add(
            format!("{at} initialize from a child of {sample}"),
            request_in(child, calls("initialize", None, Available)),
        );
    }
    cases.add(
        format!("{at} initialize from an unlisted binary"),
        request_in(
            l7_ctx(host, port, UNLISTED_BINARY),
            calls("initialize", None, Available),
        ),
    );
}

/// Effective Landlock grants as sorted `ro:<path>` and `rw:<path>` entries.
type Grants = BTreeSet<String>;

/// Adds the proxy-mode baseline, as the supervisor's enrichment does: a
/// baseline path already granted either way is left alone.
fn add_baseline(read_only: &mut Vec<String>, read_write: &mut Vec<String>) {
    for path in BASELINE_READ_ONLY {
        if !read_only.iter().any(|p| p == path) && !read_write.iter().any(|p| p == path) {
            read_only.push((*path).to_string());
        }
    }
    for path in BASELINE_READ_WRITE {
        if !read_only.iter().any(|p| p == path) && !read_write.iter().any(|p| p == path) {
            read_write.push((*path).to_string());
        }
    }
}

fn grants(read_only: &[String], read_write: &[String]) -> Grants {
    read_only
        .iter()
        .map(|path| format!("ro:{path}"))
        .chain(read_write.iter().map(|path| format!("rw:{path}")))
        .collect()
}

/// The Landlock grants a YAML sandbox applies, in gateway mode.
///
/// The supervisor adds the baseline (and an `include_workdir` filesystem
/// section when none is given) only when the policy has network policies,
/// then Landlock adds the workdir when `include_workdir` is set.
fn yaml_grants(policy: &SandboxPolicy, workdir: &str) -> Grants {
    let mut filesystem = policy.filesystem.clone();
    if !policy.network_policies.is_empty() {
        let filesystem =
            filesystem.get_or_insert_with(|| openshell_core::proto::FilesystemPolicy {
                include_workdir: true,
                ..Default::default()
            });
        add_baseline(&mut filesystem.read_only, &mut filesystem.read_write);
    }
    // An absent section converts to `include_workdir: true` with no paths.
    let (read_only, mut read_write, include_workdir) = filesystem.map_or_else(
        || (Vec::new(), Vec::new(), true),
        |filesystem| {
            (
                filesystem.read_only,
                filesystem.read_write,
                filesystem.include_workdir,
            )
        },
    );
    if include_workdir && !read_write.iter().any(|path| path == workdir) {
        read_write.push(workdir.to_string());
    }
    if read_only.is_empty() && read_write.is_empty() {
        // Landlock applies no ruleset at all.
        return Grants::new();
    }
    grants(&read_only, &read_write)
}

/// The Landlock grants a Cedar sandbox applies: Cedar's grants, with the
/// baseline when a policy can permit `NetworkConnect` (as YAML adds it only
/// to a policy with network policies), and no workdir.
fn cedar_grants(policy: &SandboxPolicy) -> Grants {
    let filesystem = openshell_policy::cedar_filesystem_grants(&policy.cedar_policy_source)
        .expect("Cedar filesystem grants load");
    assert!(!filesystem.include_workdir);
    let (mut read_only, mut read_write) = (filesystem.read_only, filesystem.read_write);
    let has_network_permits = CedarOnlyEngine::from_proto(policy)
        .expect("Cedar engine loads")
        .has_network_permits()
        .expect("engine lock");
    if has_network_permits {
        add_baseline(&mut read_only, &mut read_write);
    }
    if read_only.is_empty() && read_write.is_empty() {
        // Landlock applies no ruleset at all.
        return Grants::new();
    }
    grants(&read_only, &read_write)
}

/// A comparison outside the probe table, reported in the same format.
fn row(
    report: &mut String,
    failures: &mut Vec<String>,
    name: &str,
    case: &str,
    (yaml, cedar): (String, String),
    known: Option<&str>,
) {
    let outcome = match (known, yaml == cedar) {
        (None, true) => "same".to_string(),
        (Some(reason), false) => format!("known difference: {reason}"),
        (None, false) => {
            failures.push(format!("{name} / {case}: YAML {yaml} but Cedar {cedar}"));
            "MISMATCH".to_string()
        }
        (Some(reason), true) => {
            failures.push(format!(
                "{name} / {case}: expected a difference ({reason}) but both {yaml}"
            ));
            "UNEXPECTEDLY SAME".to_string()
        }
    };
    let _ = writeln!(report, "| {name} | {case} | {yaml} | {cedar} | {outcome} |");
}

/// The middleware chain an engine selects for `host`, as names and settings.
fn chain(engine: crate::policy_engine::PolicyEngine, host: &str, port: u16) -> String {
    match engine.query_middleware_chain_with_generation(&network(host, port, BINARY)) {
        Ok((entries, _)) if entries.is_empty() => "none".to_string(),
        Ok((entries, _)) => entries
            .iter()
            .map(|entry| {
                format!(
                    "{}/{}/{}/{:?}/{:?}",
                    entry.name, entry.implementation, entry.order, entry.on_error, entry.config
                )
            })
            .collect::<Vec<_>>()
            .join(";"),
        Err(error) => format!("error: {}", error_line(&error)),
    }
}

/// Compares filesystem, Landlock, process, and middleware configuration.
fn configuration_rows(
    example: &Example,
    loaded: &Loaded,
    endpoints: &[Endpoint],
    known: &dyn Fn(&str) -> Option<&'static str>,
) -> (String, Vec<String>) {
    let (mut report, mut failures) = (String::new(), Vec::new());
    let name = example.name;
    let join = |grants: Grants| {
        if grants.is_empty() {
            "no Landlock ruleset".to_string()
        } else {
            grants.into_iter().collect::<Vec<_>>().join(",")
        }
    };
    let case = "Landlock grants";
    row(
        &mut report,
        &mut failures,
        name,
        case,
        (
            join(yaml_grants(&loaded.yaml, example.workdir)),
            join(cedar_grants(&loaded.cedar)),
        ),
        known(case),
    );
    let compatibility = |policy: &SandboxPolicy| {
        let value = policy
            .landlock
            .as_ref()
            .map_or("", |landlock| landlock.compatibility.as_str());
        if value.is_empty() {
            "best_effort"
        } else {
            value
        }
        .to_string()
    };
    let case = "Landlock compatibility";
    row(
        &mut report,
        &mut failures,
        name,
        case,
        (compatibility(&loaded.yaml), compatibility(&loaded.cedar)),
        known(case),
    );
    let process = |policy: &SandboxPolicy| {
        policy.process.as_ref().map_or_else(
            || "driver default".to_string(),
            |process| format!("{}:{}", process.run_as_user, process.run_as_group),
        )
    };
    let case = "process identity";
    let identity = (process(&loaded.yaml), process(&loaded.cedar));
    let reason = (identity.0 != identity.1).then_some(PROCESS_IDENTITY);
    row(&mut report, &mut failures, name, case, identity, reason);
    if example.middleware.is_some() || !loaded.yaml.network_middlewares.is_empty() {
        let mut targets: Vec<(String, u16)> = endpoints
            .iter()
            .flat_map(|endpoint| {
                endpoint
                    .ports
                    .iter()
                    .map(|port| (endpoint.host.clone(), *port))
            })
            .collect();
        targets.push((UNLISTED_HOST.to_string(), 443));
        for (host, port) in targets {
            let case = format!("middleware chain for {host}:{port}");
            row(
                &mut report,
                &mut failures,
                name,
                &case,
                (
                    chain(Arc::clone(&loaded.engines.opa).into(), &host, port),
                    chain(Arc::clone(&loaded.engines.cedar).into(), &host, port),
                ),
                known(&case),
            );
        }
    }
    (report, failures)
}

/// Runs every comparison for one example.
///
/// `known` maps a case name to its known difference.
fn check(example: &Example, known: &dyn Fn(&str) -> Option<&'static str>) {
    let loaded = Loaded::new(example);
    // Probe the composed policy, which includes provider endpoints.
    let composed = openshell_policy::serialize_sandbox_policy(&loaded.yaml)
        .unwrap_or_else(|error| panic!("{}: YAML policy serializes: {error:?}", example.name));
    let endpoints = endpoints(example.name, &composed);
    let mut cases = Cases {
        known,
        list: Vec::new(),
    };
    for endpoint in &endpoints {
        endpoint_cases(endpoint, &mut cases);
    }
    cases.add("policy DNS records".to_string(), Probe::DnsRecords);
    let host = endpoints
        .first()
        .map_or(UNLISTED_HOST, |endpoint| endpoint.host.as_str());
    let (mut report, mut failures) = run(example.name, host, &loaded.engines, &cases.list);
    let (rows, row_failures) = configuration_rows(example, &loaded, &endpoints, known);
    report.push_str(&rows);
    failures.extend(row_failures);
    let known_count = report.matches("| known difference:").count();
    let total = report.lines().count();
    println!(
        "{}: {total} cases, {} same, {known_count} known differences",
        example.name,
        total - known_count - failures.len()
    );
    report_parity((report, failures));
}

/// No known differences beyond the generated ones.
fn none(_: &str) -> Option<&'static str> {
    None
}

#[test]
fn example_sandbox_policy_quickstart() {
    check(
        &Example::new(
            "sandbox-policy-quickstart",
            include_str!("../../../../examples/sandbox-policy-quickstart/policy.yaml"),
            include_str!("../../../../examples/sandbox-policy-quickstart/policy.cedar"),
        ),
        &none,
    );
}

#[test]
fn example_governance_interceptor() {
    check(
        &Example::new(
            "governance-interceptor",
            include_str!("../../../../examples/governance-interceptor/policy.yaml"),
            include_str!("../../../../examples/governance-interceptor/policy.cedar"),
        ),
        &none,
    );
}

/// The example always attaches its `nvidia-inference` provider. With YAML
/// the provider adds the NVIDIA endpoint; the Cedar policy grants it itself.
#[test]
fn example_local_inference() {
    check(
        &Example {
            provider: Some(include_str!(
                "../../../../examples/local-inference/nvidia-inference.yaml"
            )),
            ..Example::new(
                "local-inference",
                include_str!("../../../../examples/local-inference/sandbox-policy.yaml"),
                include_str!("../../../../examples/local-inference/sandbox-policy.cedar"),
            )
        },
        &none,
    );
}

#[test]
fn example_policy_advisor() {
    check(
        &Example::new(
            "policy-advisor",
            include_str!("../../../../examples/policy-advisor/sandbox-policy.yaml"),
            include_str!("../../../../examples/policy-advisor/sandbox-policy.cedar"),
        ),
        &none,
    );
}

#[test]
fn example_supervisor_middleware_content_guard() {
    check(
        &Example::new(
            "supervisor-middleware-content-guard",
            include_str!("../../../../examples/supervisor-middleware-content-guard/policy.yaml"),
            include_str!("../../../../examples/supervisor-middleware-content-guard/policy.cedar"),
        )
        .with_middleware(include_str!(
            "../../../../examples/supervisor-middleware-content-guard/middleware.yaml"
        )),
        &none,
    );
}

#[test]
fn example_transparent_tcp_redis() {
    check(
        &Example::new(
            "transparent-tcp-redis",
            include_str!("../../../../examples/transparent-tcp-redis/policy.yaml"),
            include_str!("../../../../examples/transparent-tcp-redis/policy.cedar"),
        ),
        &none,
    );
}

#[test]
fn example_agent_driven_policy_management() {
    check(
        &Example::new(
            "agent-driven-policy-management",
            include_str!(
                "../../../../examples/agent-driven-policy-management/policy.template.yaml"
            ),
            include_str!(
                "../../../../examples/agent-driven-policy-management/policy.template.cedar"
            ),
        ),
        &none,
    );
}

#[test]
fn example_multi_agent_notepad() {
    check(
        &Example::new(
            "multi-agent-notepad",
            include_str!("../../../../examples/multi-agent-notepad/policy.template.yaml"),
            include_str!("../../../../examples/multi-agent-notepad/policy.template.cedar"),
        )
        .rendered(NOTEPAD_VALUES),
        &none,
    );
}

#[test]
fn example_e2e_policy_advisor() {
    check(
        &Example::new(
            "e2e/policy-advisor",
            include_str!("../../../../e2e/policy-advisor/policy.template.yaml"),
            include_str!("../../../../e2e/policy-advisor/policy.template.cedar"),
        )
        .with_middleware(include_str!(
            "../../../../e2e/policy-advisor/middleware.yaml"
        )),
        &none,
    );
}

#[test]
fn example_gator() {
    check(
        &Example::new(
            "gator",
            include_str!("../../../../scripts/agents/gator/policy.yaml"),
            include_str!("../../../../scripts/agents/gator/policy.cedar"),
        )
        .with_middleware(include_str!(
            "../../../../scripts/agents/gator/middleware.yaml"
        )),
        &none,
    );
}

#[test]
fn example_mxc_fs_empty() {
    check(
        &Example::new(
            "mxc fs-empty",
            include_str!("../../../openshell-driver-mxc/examples/e2e-policies/fs-empty.yaml"),
            include_str!("../../../openshell-driver-mxc/examples/e2e-policies/fs-empty.cedar"),
        ),
        &none,
    );
}

/// Values `e2e/mcp-conformance/render-policy.py` substitutes for a server URL
/// on `host`, port 41234, path `/mcp`, and the default MCP revision.
///
/// Like Python's `string.Template`, `$$` escapes a `$`, so an escaped
/// placeholder is set aside before the others are replaced.
fn mcp_values(host: &str) -> Vec<(String, String)> {
    let placeholder = |name: &str| format!("${{{name}}}");
    let escaped = ["$$", "{"].concat();
    let set_aside = "\u{0}{".to_string();
    vec![
        (escaped, set_aside.clone()),
        (placeholder("host_spec"), format!("host: \"{host}\"")),
        (placeholder("port_spec"), "        port: 41234".to_string()),
        (placeholder("host_json"), format!("\"{host}\"")),
        (placeholder("host"), host.to_string()),
        (placeholder("port"), "41234".to_string()),
        (placeholder("path"), "\"/mcp\"".to_string()),
        (placeholder("mcp_version"), "\"2025-11-25\"".to_string()),
        (set_aside, ["$", "{"].concat()),
    ]
}

fn mcp_conformance(name: &'static str, host: &str) -> Example {
    let values = mcp_values(host);
    let values: Vec<(&str, &str)> = values
        .iter()
        .map(|(from, to)| (from.as_str(), to.as_str()))
        .collect();
    Example {
        // The client image's WORKDIR.
        workdir: "/opt/mcp-conformance",
        ..Example::new(
            name,
            include_str!("../../../../e2e/mcp-conformance/policy-template.yaml"),
            include_str!("../../../../e2e/mcp-conformance/policy-template.cedar"),
        )
    }
    .with_middleware(include_str!(
        "../../../../e2e/mcp-conformance/middleware-template.yaml"
    ))
    .rendered(&values)
}

/// The client sandbox reaches a runner container by IP on the e2e network.
#[test]
fn example_mcp_conformance_runner_address() {
    check(
        &mcp_conformance("e2e/mcp-conformance (IP)", "172.18.0.3"),
        &none,
    );
}

/// A `localhost` server URL is rewritten to the host gateway alias.
#[test]
fn example_mcp_conformance_host_alias() {
    check(
        &mcp_conformance(
            "e2e/mcp-conformance (host alias)",
            "host.openshell.internal",
        ),
        &none,
    );
}

/// `policy.yaml` does not load: its explicit `run_as_user: jovyan` fails
/// process identity validation, so the engines cannot be compared. The Cedar
/// version omits the identity, which lets the driver use the image user, and
/// grants the same paths with the image workdir in place of
/// `include_workdir`.
#[test]
fn example_jupyter_sandbox() {
    const YAML: &str = include_str!("../../../../examples/jupyter-sandbox/policy.yaml");
    const CEDAR: &str = include_str!("../../../../examples/jupyter-sandbox/policy.cedar");
    let yaml = openshell_policy::parse_sandbox_policy(YAML).expect("YAML policy parses");
    assert!(
        OpaEngine::from_proto(&yaml).is_err(),
        "policy.yaml loads now; compare it with the engines like the other examples"
    );
    assert!(yaml.network_policies.is_empty());
    let dir = tempfile::tempdir().expect("temporary directory");
    let path = dir.path().join("policy.cedar");
    std::fs::write(&path, CEDAR).expect("write Cedar policy");
    let cedar =
        openshell_policy::parse_sandbox_policy_file_auto(&path).expect("Cedar policy loads");
    let engine = CedarOnlyEngine::from_proto(&cedar).expect("Cedar engine loads");
    let records = engine
        .policy_dns_eligibility_snapshot()
        .expect("DNS snapshot");
    assert!(records.endpoints.is_empty(), "no network access");
    assert_eq!(
        yaml_grants(&yaml, "/home/jovyan"),
        cedar_grants(&cedar),
        "Landlock grants"
    );
}
