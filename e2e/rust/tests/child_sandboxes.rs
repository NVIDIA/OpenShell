// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-child-sandboxes")]

//! E2E tests for child sandboxes and the MCP tools (RFC 0021).
//!
//! Needs a gateway with `experimental_enable_child_sandboxes` on. Run with
//! `mise run e2e:rust:child-sandboxes`, which sets
//! `OPENSHELL_E2E_CHILD_SANDBOXES=1` for the Docker gateway wrapper. Each test
//! shares one root, since every sandbox start is slow. Sandboxes are deleted
//! by guards, children before their roots, even when a test fails.

use std::io::Write as _;
use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const TEST_SERVER_HOST: &str = "host.openshell.internal";
const PRIVATE_ALLOWED_IPS: &str = r#"        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7""#;

async fn cli(args: &[&str]) -> (String, bool) {
    let output = openshell_cmd()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("spawn openshell");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (strip_ansi(&text), output.status.success())
}

/// A policy that lets any binary reach the host test server on `allow_port`,
/// or nothing when `None`. `/tmp` is writable unless `writable_tmp` is false;
/// then it is listed read-only, since the supervisor adds a writable `/tmp`
/// to any policy that does not name it.
fn policy(allow_port: Option<u16>, writable_tmp: bool) -> NamedTempFile {
    let (tmp, read_only_tmp) = if writable_tmp {
        ("\n    - /tmp", "")
    } else {
        ("", "\n    - /tmp")
    };
    let network = allow_port.map_or_else(String::new, |port| {
        format!(
            r#"network_policies:
  host_server:
    name: host_server
    endpoints:
      - host: {TEST_SERVER_HOST}
        port: {port}
{PRIVATE_ALLOWED_IPS}
    binaries:
      - path: "/**"
"#
        )
    });
    let text = format!(
        r"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log{read_only_tmp}
  read_write:
    - /sandbox{tmp}
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

{network}"
    );
    let mut file = NamedTempFile::new().expect("create policy file");
    file.write_all(text.as_bytes()).expect("write policy file");
    file.flush().expect("flush policy file");
    file
}

fn path(file: &NamedTempFile) -> String {
    file.path().to_string_lossy().into_owned()
}

/// An HTTP server on the host that answers every request with 200.
async fn start_host_server() -> u16 {
    let listener = TcpListener::bind(("0.0.0.0", 0))
        .await
        .expect("bind host server");
    let port = listener.local_addr().expect("host server address").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0_u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    port
}

/// The HTTP status a request from inside `sandbox` to the host server gets:
/// 200 when its policy allows it; anything else, such as `000` for a refused
/// connection, when not.
async fn probe(sandbox: &SandboxGuard, port: u16) -> String {
    let script = format!(
        "curl -s -o /dev/null -w '%{{http_code}}' --max-time 10 http://{TEST_SERVER_HOST}:{port}/; true"
    );
    let output = sandbox
        .exec(&["sh", "-c", &script])
        .await
        .unwrap_or_else(|error| panic!("probe exec in {} failed: {error}", sandbox.name));
    output.trim().to_string()
}

/// Probe until the host server is reachable or not, as `reachable` says, for
/// at most a minute: a parent's policy reaches its children a few seconds
/// after the parent loads it.
async fn probe_until(sandbox: &SandboxGuard, port: u16, reachable: bool) {
    let mut last = String::new();
    for _ in 0..30 {
        last = probe(sandbox, port).await;
        if (last == "200") == reachable {
            return;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!(
        "{} never became {} the host server; last answer {last}",
        sandbox.name,
        if reachable {
            "able to reach"
        } else {
            "unable to reach"
        }
    );
}

/// Make the CLI's user a member of the default workspace, so roots it
/// creates can create children through MCP. A local development gateway's
/// built-in user needs no membership.
async fn ensure_workspace_member() {
    let (whoami, ok) = cli(&["whoami", "-o", "json"]).await;
    assert!(ok, "whoami failed: {whoami}");
    let identity: Value = serde_json::from_str(whoami.trim()).expect("whoami JSON");
    if identity["identity_provider"] == "local_dev" {
        return;
    }
    let subject = identity["subject"].as_str().expect("whoami subject");
    // An existing membership is fine.
    let _ = cli(&[
        "workspace",
        "member",
        "add",
        "--workspace",
        "default",
        "--subject",
        subject,
        "--role",
        "user",
    ])
    .await;
}

/// Call one MCP tool from inside `root`, through `http://openshell.local/mcp`,
/// and return the tool result (`structuredContent` and `isError`).
async fn mcp(root: &SandboxGuard, tool: &str, arguments: Value) -> Value {
    mcp_request(
        root,
        "tools/call",
        json!({"name": tool, "arguments": arguments}),
    )
    .await["result"]
        .clone()
}

/// Send one JSON-RPC request from inside `root` to `http://openshell.local/mcp`
/// and return the whole reply.
async fn mcp_request(root: &SandboxGuard, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let output = root
        .exec(&[
            "curl",
            "-s",
            "--max-time",
            "90",
            "-X",
            "POST",
            "http://openshell.local/mcp",
            "-H",
            "content-type: application/json",
            "-d",
            &body,
        ])
        .await
        .unwrap_or_else(|error| panic!("MCP {method} failed: {error}"));
    let reply = output
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or_else(|| panic!("no JSON reply to {method}: {output}"));
    serde_json::from_str(reply).expect("MCP reply JSON")
}

fn content(result: &Value) -> &Value {
    &result["structuredContent"]
}

/// Deletes a provider when dropped, also when a test fails halfway.
struct ProviderGuard(String);

impl Drop for ProviderGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new(openshell_e2e::harness::binary::openshell_bin())
            .args(["provider", "delete", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[tokio::test]
async fn children_are_created_listed_and_deleted_from_the_cli() {
    let mut root = SandboxGuard::create(&[]).await.expect("create root");
    let mut child = SandboxGuard::create(&["--parent", &root.name])
        .await
        .expect("create child");

    let grandchild = SandboxGuard::create(&["--parent", &child.name]).await;
    let error = grandchild.err().expect("a child of a child is refused");
    assert!(
        error.contains("only one level of child sandboxes is supported"),
        "{error}"
    );

    let (listed, ok) = cli(&["sandbox", "list", "--parent", &root.name]).await;
    assert!(ok, "{listed}");
    assert!(listed.contains(&child.name), "{listed}");
    assert!(
        !listed
            .lines()
            .any(|line| line.starts_with(&format!("{} ", root.name))),
        "only children are listed: {listed}"
    );
    let (all, ok) = cli(&["sandbox", "list"]).await;
    assert!(ok && all.contains("PARENT"), "{all}");

    let (refused, ok) = cli(&["sandbox", "delete", &root.name]).await;
    assert!(!ok, "deleting a parent with a child must fail: {refused}");
    assert!(
        refused.contains(&format!(
            "sandbox '{}' has 1 child sandbox; delete them first",
            root.name
        )),
        "{refused}"
    );

    child.delete().await.expect("delete child");
    root.delete().await.expect("delete parent");
}

#[tokio::test]
async fn a_child_follows_its_parents_policy_on_the_network() {
    let port = start_host_server().await;
    let closed = policy(None, true);
    let open = policy(Some(port), true);
    let root = SandboxGuard::create(&["--policy", &path(&closed)])
        .await
        .expect("create root");
    let child = SandboxGuard::create(&["--parent", &root.name])
        .await
        .expect("create child");

    assert_ne!(probe(&child, port).await, "200", "the child starts closed");

    let (set, ok) = cli(&[
        "policy",
        "set",
        &root.name,
        "--policy",
        &path(&open),
        "--wait",
    ])
    .await;
    assert!(ok, "policy set on the root failed: {set}");
    assert_eq!(probe(&root, port).await, "200", "the root is open");
    probe_until(&child, port, true).await;

    let (set, ok) = cli(&[
        "policy",
        "set",
        &root.name,
        "--policy",
        &path(&closed),
        "--wait",
    ])
    .await;
    assert!(ok, "closing the root failed: {set}");
    probe_until(&child, port, false).await;

    drop(child);
    drop(root);
}

#[tokio::test]
async fn a_child_loses_a_provider_its_parent_loses() {
    let provider = format!("e2e-child-provider-{}", std::process::id());
    // Any provider type the gateway has a profile for will do.
    let (profiles, _) = cli(&["provider", "profile", "list"]).await;
    let (provider_type, key) = [
        ("openai", "OPENAI_API_KEY"),
        ("anthropic", "ANTHROPIC_API_KEY"),
    ]
    .into_iter()
    .find(|(name, _)| {
        profiles
            .lines()
            .any(|line| line.starts_with(&format!("{name} ")))
    })
    .unwrap_or(("openai", "OPENAI_API_KEY"));
    let credential = format!("{key}=sk-e2e-child-sandboxes");
    let (created, ok) = cli(&[
        "provider",
        "create",
        "--name",
        &provider,
        "--type",
        provider_type,
        "--credential",
        &credential,
    ])
    .await;
    assert!(ok, "provider create failed: {created}");
    // Declared before the sandboxes, so it is dropped after them.
    let _provider_guard = ProviderGuard(provider.clone());

    let root = SandboxGuard::create(&["--provider", &provider])
        .await
        .expect("create root");
    let child = SandboxGuard::create(&["--parent", &root.name])
        .await
        .expect("create child");
    let (listed, ok) = cli(&["sandbox", "provider", "list", &child.name]).await;
    assert!(
        ok && listed.contains(&provider),
        "child has the provider: {listed}"
    );

    let (detached, ok) = cli(&["sandbox", "provider", "detach", &root.name, &provider]).await;
    assert!(ok, "detach from the root failed: {detached}");
    let (listed, ok) = cli(&["sandbox", "provider", "list", &child.name]).await;
    assert!(
        ok && !listed.contains(&provider),
        "child lost the provider: {listed}"
    );

    drop(child);
    drop(root);
}

#[tokio::test]
async fn an_agent_in_a_root_manages_its_children_through_mcp() {
    ensure_workspace_member().await;
    let root = SandboxGuard::create(&[]).await.expect("create root");
    let other_root = SandboxGuard::create(&[]).await.expect("create other root");
    let worker = format!("{}-w", root.name);

    let created = mcp(&root, "create_sandbox", json!({"name": worker})).await;
    // Dropped before the roots, so a failed test still deletes the child
    // first and then its root.
    let _worker_guard = SandboxGuard::manage_existing(worker.clone());
    assert_eq!(created["isError"], false, "{created}");
    assert_eq!(content(&created)["already_existed"], false, "{created}");
    let again = mcp(&root, "create_sandbox", json!({"name": worker})).await;
    assert_eq!(content(&again)["already_existed"], true, "{again}");

    let ran = mcp(
        &root,
        "exec",
        json!({"name": worker, "command": ["sh", "-c", "echo hello; exit 3"]}),
    )
    .await;
    assert_eq!(content(&ran)["exit_code"], 3, "{ran}");
    assert_eq!(content(&ran)["stdout"], "hello\n", "{ran}");

    let started = mcp(
        &root,
        "exec",
        json!({"name": worker, "command": ["sh", "-c", "sleep 20; echo done"], "background": true}),
    )
    .await;
    let job = content(&started)["job"]
        .as_str()
        .unwrap_or_else(|| panic!("no job id: {started}"))
        .to_string();
    let mut waited = Value::Null;
    for _ in 0..4 {
        waited = mcp(
            &root,
            "wait",
            json!({"name": worker, "job": job, "timeout_s": 30}),
        )
        .await;
        if content(&waited)["state"] != "running" {
            break;
        }
    }
    assert_eq!(content(&waited)["state"], "completed", "{waited}");
    assert_eq!(content(&waited)["exit_code"], 0, "{waited}");
    assert_eq!(content(&waited)["stdout"], "done\n", "{waited}");

    // Another root, and the caller itself, read as missing.
    for name in [other_root.name.as_str(), root.name.as_str()] {
        let refused = mcp(&root, "exec", json!({"name": name, "command": ["true"]})).await;
        assert_eq!(content(&refused)["error"], "not_found", "{refused}");
    }

    assert_job_audit_events(&job);

    let deleted = mcp(&root, "delete", json!({"name": worker})).await;
    assert_eq!(content(&deleted)["deleting"], true, "{deleted}");
}

/// The gateway's OCSF events for the job's start and wait carry its id and
/// state. The e2e wrapper always writes the gateway's JSONL, so under it a
/// missing directory fails the test; against a gateway started by hand the
/// check is skipped.
fn assert_job_audit_events(job: &str) {
    let Ok(dir) = std::env::var("OPENSHELL_E2E_GATEWAY_OCSF_DIR") else {
        assert_ne!(
            std::env::var("OPENSHELL_E2E_CHILD_SANDBOXES").as_deref(),
            Ok("1"),
            "the e2e wrapper ran but OPENSHELL_E2E_GATEWAY_OCSF_DIR is not set"
        );
        eprintln!("skipping the audit check: OPENSHELL_E2E_GATEWAY_OCSF_DIR is not set");
        return;
    };
    let mut events = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read the gateway OCSF dir") {
        let text =
            std::fs::read_to_string(entry.expect("OCSF dir entry").path()).unwrap_or_default();
        events.extend(
            text.lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok()),
        );
    }
    let tool_event = |tool: &str| {
        events
            .iter()
            .find(|event| event["api"]["operation"] == tool && event["unmapped"]["job"] == job)
    };
    let start = tool_event("exec").unwrap_or_else(|| panic!("no exec event for job {job}"));
    assert_eq!(start["unmapped"]["state"], "running", "{start}");
    assert_eq!(start["unmapped"]["background"], "true", "{start}");
    assert!(
        events
            .iter()
            .any(|event| event["api"]["operation"] == "wait"
                && event["unmapped"]["job"] == job
                && event["unmapped"]["state"] == "completed"),
        "no wait event with state completed for job {job}"
    );
}

/// Deletes a sandbox template when dropped, also when a test fails halfway.
struct TemplateGuard(String);

impl Drop for TemplateGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new(openshell_e2e::harness::binary::openshell_bin())
            .args(["sandbox", "template", "delete", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Create a template whose sandboxes get `E2E_TEMPLATE_MARK=<mark>`, labelled
/// for agents when `agent_usable` is true.
async fn create_template(name: &str, mark: &str, agent_usable: bool) -> TemplateGuard {
    let env = format!("E2E_TEMPLATE_MARK={mark}");
    let mut args = vec!["sandbox", "template", "create", name, "--env", &env];
    if agent_usable {
        args.extend(["--label", "openshell.ai/agent-usable=true"]);
    }
    let (created, ok) = cli(&args).await;
    assert!(ok, "template create {name} failed: {created}");
    TemplateGuard(name.to_string())
}

#[tokio::test]
async fn an_agent_creates_children_only_from_templates_marked_for_agents() {
    ensure_workspace_member().await;
    let id = std::process::id();
    let approved = format!("e2e-agent-tpl-{id}");
    let unlabelled = format!("e2e-plain-tpl-{id}");
    let mark = format!("from-template-{id}");
    // Declared before the sandboxes, so they are dropped after them.
    let _approved_guard = create_template(&approved, &mark, true).await;
    let _unlabelled_guard = create_template(&unlabelled, &mark, false).await;

    let root = SandboxGuard::create(&[]).await.expect("create root");

    // The agent learns the templates it may use from the tool list.
    let tools = mcp_request(&root, "tools/list", json!({})).await;
    let create = tools["result"]["tools"]
        .as_array()
        .and_then(|tools| tools.iter().find(|tool| tool["name"] == "create_sandbox"))
        .unwrap_or_else(|| panic!("no create_sandbox tool: {tools}"));
    let offered = &create["inputSchema"]["properties"]["template"]["enum"];
    assert!(
        offered.as_array().is_some_and(
            |names| names.contains(&json!(approved)) && !names.contains(&json!(unlabelled))
        ),
        "{create}"
    );

    let worker = format!("{}-t", root.name);
    let created = mcp(
        &root,
        "create_sandbox",
        json!({"name": worker, "template": approved}),
    )
    .await;
    let _worker_guard = SandboxGuard::manage_existing(worker.clone());
    assert_eq!(created["isError"], false, "{created}");

    // The child runs with the template's settings, not a copy of its parent's.
    let ran = mcp(
        &root,
        "exec",
        json!({"name": worker, "command": ["sh", "-c", "printf %s \"$E2E_TEMPLATE_MARK\""]}),
    )
    .await;
    assert_eq!(content(&ran)["exit_code"], 0, "{ran}");
    assert_eq!(content(&ran)["stdout"], mark, "{ran}");

    // An unlabelled template and a missing one get the same answer, so an
    // agent cannot learn which templates exist.
    let missing = format!("e2e-missing-tpl-{id}");
    for template in [&unlabelled, &missing] {
        let refused = mcp(
            &root,
            "create_sandbox",
            json!({"name": format!("{}-x", root.name), "template": template}),
        )
        .await;
        assert_eq!(refused["isError"], true, "{refused}");
        assert_eq!(
            content(&refused)["message"],
            format!("template '{template}' is not available to agents"),
            "{refused}"
        );
    }
}

#[tokio::test]
async fn a_background_job_needs_a_writable_tmp() {
    ensure_workspace_member().await;
    let no_tmp = policy(None, false);
    let root = SandboxGuard::create(&["--policy", &path(&no_tmp)])
        .await
        .expect("create root");
    let worker = format!("{}-w", root.name);
    let created = mcp(&root, "create_sandbox", json!({"name": worker})).await;
    let _worker_guard = SandboxGuard::manage_existing(worker.clone());
    assert_eq!(created["isError"], false, "{created}");

    let refused = mcp(
        &root,
        "exec",
        json!({"name": worker, "command": ["true"], "background": true}),
    )
    .await;
    assert_eq!(
        content(&refused)["error"],
        "failed_precondition",
        "{refused}"
    );
    // Only the /tmp cause: /proc and stat are present, so the job is refused
    // for the reason the test names.
    let message = content(&refused)["message"].as_str().unwrap_or_default();
    assert!(message.contains("need a writable /tmp"), "{message}");
    assert!(
        !message.contains("/proc") && !message.contains("stat"),
        "{message}"
    );
}

/// Talk to `openshell mcp serve` over stdio, as a host MCP client does.
struct Bridge {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    next_id: u64,
}

impl Bridge {
    fn start(command: tokio::process::Command) -> Self {
        let mut command = command;
        command
            .args(["mcp", "serve"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let mut child = command.spawn().expect("spawn openshell mcp serve");
        let stdin = child.stdin.take().expect("bridge stdin");
        let stdout = BufReader::new(child.stdout.take().expect("bridge stdout")).lines();
        Self {
            child,
            stdin,
            stdout,
            next_id: 0,
        }
    }

    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let line =
            json!({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params});
        self.stdin
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("write to the bridge");
        let reply = tokio::time::timeout(Duration::from_mins(2), self.stdout.next_line())
            .await
            .expect("the bridge answers")
            .expect("read from the bridge")
            .expect("the bridge is still running");
        serde_json::from_str(&reply).unwrap_or_else(|_| panic!("not JSON-RPC: {reply}"))
    }

    async fn tool(&mut self, name: &str, arguments: Value) -> Value {
        self.call("tools/call", json!({"name": name, "arguments": arguments}))
            .await["result"]
            .clone()
    }
}

#[tokio::test]
async fn a_host_client_uses_the_tools_through_mcp_serve() {
    let mut bridge = Bridge::start(openshell_cmd());
    let init = bridge
        .call("initialize", json!({"protocolVersion": "2025-06-18"}))
        .await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18", "{init}");

    let name = format!("e2e-bridge-{}", std::process::id());
    let created = bridge.tool("create_sandbox", json!({"name": name})).await;
    let guard = SandboxGuard::manage_existing(name.clone());
    assert_eq!(created["isError"], false, "{created}");

    let mut ran = Value::Null;
    // A sandbox still starting is reported as such; wait for it.
    for _ in 0..12 {
        ran = bridge
            .tool(
                "exec",
                json!({"name": name, "command": ["echo", "from the host"]}),
            )
            .await;
        if content(&ran)["exit_code"] == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    assert_eq!(content(&ran)["stdout"], "from the host\n", "{ran}");

    let refused = bridge
        .tool(
            "exec",
            json!({"name": name, "command": ["true"], "env": {"A": "1"}}),
        )
        .await;
    assert_eq!(
        content(&refused)["message"],
        "'env' is not available over MCP; users can set it with the CLI",
        "{refused}"
    );

    drop(bridge.stdin);
    let _ = bridge.child.wait().await;
    drop(guard);
}
