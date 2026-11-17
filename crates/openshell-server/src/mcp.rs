// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MCP endpoint for agents in root sandboxes (RFC 0021).
//!
//! `POST /mcp` carries one JSON-RPC message and gets one JSON reply; there are
//! no MCP sessions. Each tool is a thin wrapper over an existing RPC, sent
//! through the connection's own gRPC stack, so authentication, authorization,
//! rate limits and interceptors apply exactly as for a direct gRPC call. The
//! request carries [`McpOrigin`], which is the only way a sandbox caller can
//! reach the user-facing methods in [`SANDBOX_TOOL_METHODS`].

use crate::auth::audit::{self, RequestOrigin};
use crate::auth::principal::Principal;
use crate::multiplex::CallerAuthenticator;
use axum::Extension;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_core::proto::{
    CreateSandboxRequest, DeleteSandboxRequest, ExecSandboxRequest, ListSandboxTemplatesRequest,
    ListSandboxesRequest, Sandbox, SandboxPhase, SandboxSpec, SandboxWorkloadTemplate,
};
use openshell_core::{ObjectId, ObjectName};
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::sync::Arc;
use tower::util::BoxCloneSyncService;
use tracing::warn;

mod jobs;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type GrpcStack = BoxCloneSyncService<
    http::Request<tonic::body::Body>,
    http::Response<tonic::body::Body>,
    BoxError,
>;

const MCP_PATH: &str = "/mcp";
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18"];
/// Largest request body read, checked only after the caller is authenticated.
const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;

/// Methods a sandbox caller may reach, and only with [`McpOrigin`].
const SANDBOX_TOOL_METHODS: [&str; 6] = [
    "/openshell.v1.OpenShell/CreateSandbox",
    "/openshell.v1.OpenShell/ListSandboxes",
    "/openshell.v1.OpenShell/ListSandboxTemplates",
    "/openshell.v1.OpenShell/ExecSandbox",
    "/openshell.v1.OpenShell/DeleteSandbox",
    "/openshell.v1.OpenShell/GetSandboxLogs",
];

/// Marks a gRPC request the `/mcp` endpoint built in process. Only Rust code
/// can set request extensions, so a network caller can never carry it.
#[derive(Clone, Copy, Debug)]
pub struct McpOrigin;

pub fn is_sandbox_tool_method(path: &str) -> bool {
    SANDBOX_TOOL_METHODS.contains(&path)
}

/// One gateway connection's caller resolution and gRPC stack.
#[derive(Clone)]
pub struct McpConnection {
    auth: CallerAuthenticator,
    grpc: GrpcStack,
    create_wait: CreateWait,
    /// Read only to record, in audit events, the user a sandbox caller acts for.
    store: Option<Arc<crate::persistence::Store>>,
}

/// How long `create_sandbox` waits for a child to become ready, and how often
/// it looks.
#[derive(Clone, Copy)]
struct CreateWait {
    limit: std::time::Duration,
    first_poll: std::time::Duration,
    poll: std::time::Duration,
}

impl Default for CreateWait {
    fn default() -> Self {
        Self {
            limit: std::time::Duration::from_secs(45),
            first_poll: std::time::Duration::from_secs(1),
            poll: std::time::Duration::from_secs(2),
        }
    }
}

impl McpConnection {
    pub fn new<S>(auth: CallerAuthenticator, grpc: S) -> Self
    where
        S: tower::Service<
                http::Request<tonic::body::Body>,
                Response = http::Response<tonic::body::Body>,
            > + Clone
            + Send
            + Sync
            + 'static,
        S::Error: Into<BoxError>,
        S::Future: Send + 'static,
    {
        use tower::ServiceExt;
        Self {
            auth,
            grpc: BoxCloneSyncService::new(grpc.map_err(Into::into)),
            create_wait: CreateWait::default(),
            store: None,
        }
    }

    /// Let audit events record the user each sandbox caller acts for.
    #[must_use]
    pub fn with_store(mut self, store: Arc<crate::persistence::Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Shorten the create wait so tests need not sleep for real.
    #[cfg(test)]
    pub fn with_short_create_wait(mut self) -> Self {
        self.create_wait = CreateWait {
            limit: std::time::Duration::from_millis(50),
            first_poll: std::time::Duration::from_millis(5),
            poll: std::time::Duration::from_millis(10),
        };
        self
    }
}

pub fn router() -> Router {
    Router::new().route(
        MCP_PATH,
        post(handle).get(|| async { StatusCode::METHOD_NOT_ALLOWED }),
    )
}

async fn handle(
    Extension(connection): Extension<McpConnection>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // Browsers always send Origin on a cross-site POST; the CLI bridge and the
    // sandbox door never do. So no web page can drive /mcp with a user's
    // session (DNS rebinding included).
    if headers.contains_key(http::header::ORIGIN) {
        return (
            StatusCode::FORBIDDEN,
            "requests with an Origin header are refused",
        )
            .into_response();
    }
    if let Some(version) = headers.get("mcp-protocol-version")
        && !version
            .to_str()
            .is_ok_and(|v| SUPPORTED_PROTOCOL_VERSIONS.contains(&v))
    {
        return (StatusCode::BAD_REQUEST, "unsupported MCP-Protocol-Version").into_response();
    }
    // Authenticate from the headers before reading the body.
    let Ok(principal) = connection.auth.authenticate(&headers, MCP_PATH).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // A user acts in the workspace the bridge names, like the CLI; a sandbox
    // always acts in its own, which its handlers read from its record.
    let workspace = match &principal {
        Principal::Sandbox(_) => None,
        Principal::User(_) => match headers.get(WORKSPACE_HEADER).map(|value| value.to_str()) {
            None => Some(DEFAULT_WORKSPACE.to_string()),
            Some(Ok(workspace)) => Some(workspace.to_string()),
            Some(Err(_)) => {
                return (StatusCode::BAD_REQUEST, "invalid workspace header").into_response();
            }
        },
        Principal::Anonymous => return StatusCode::UNAUTHORIZED.into_response(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                "MCP is available to users and sandboxes only",
            )
                .into_response();
        }
    };
    let Ok(body) = axum::body::to_bytes(body, MAX_REQUEST_BYTES).await else {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body is larger than the 2 MiB /mcp accepts",
        )
            .into_response();
    };

    let Ok(message) = serde_json::from_slice::<Value>(&body) else {
        return rpc_error(&Value::Null, -32700, "parse error");
    };
    if message.is_array() {
        return rpc_error(&Value::Null, -32600, "batch requests are not supported");
    }
    // Notifications (no id) get no response body.
    let Some(id) = message.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    match message
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "initialize" => rpc_ok(
            &id,
            json!({
                "protocolVersion": negotiate_protocol_version(
                    params.get("protocolVersion").and_then(Value::as_str),
                ),
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "openshell-gateway", "version": openshell_core::VERSION},
                "instructions": "Create and manage OpenShell sandboxes: a sandbox manages its own child sandboxes, a user the sandboxes in their workspace.",
            }),
        ),
        "ping" => rpc_ok(&id, json!({})),
        "tools/list" => {
            let templates = match &principal {
                Principal::Sandbox(_) => {
                    let call = Call {
                        connection: &connection,
                        headers: &headers,
                        workspace,
                    };
                    match agent_templates(&call).await {
                        Ok(templates) => templates,
                        Err(ToolError::Unauthenticated) => {
                            return StatusCode::UNAUTHORIZED.into_response();
                        }
                        // The tools still work without the list; a create
                        // names its template either way.
                        Err(ToolError::Refused(error)) => {
                            warn!(error = %error.message, "could not list templates for the MCP tool list");
                            Vec::new()
                        }
                    }
                }
                _ => Vec::new(),
            };
            rpc_ok(&id, json!({"tools": tool_definitions(&templates)}))
        }
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !TOOLS.iter().any(|tool| tool.name == name) {
                return rpc_error(&id, -32602, &format!("unknown tool '{name}'"));
            }
            let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
            let call = Call {
                connection: &connection,
                headers: &headers,
                workspace,
            };
            let result = match name {
                "create_sandbox" => create_child(&call, &arguments).await,
                "exec" => exec_in_child(&call, &arguments).await,
                "wait" => jobs::wait(&call, &arguments).await,
                "delete" => delete_child(&call, &arguments).await,
                "logs" => child_logs(&call, &arguments).await,
                "list" => list_sandboxes(&call, &arguments).await,
                _ => unreachable!("tool names are checked against TOOLS above"),
            };
            let origin = RequestOrigin::new(connection.auth.connection_source(), &headers);
            let mut details = tool_call_details(name, &arguments, &result);
            if let Principal::Sandbox(sandbox) = &principal {
                details.push((
                    "acting_for",
                    acting_for(&connection, &sandbox.sandbox_id).await,
                ));
            }
            let details = capped_audit_details(details);
            match result {
                Ok(content) => {
                    audit::emit_mcp_tool_call(
                        &origin,
                        &principal,
                        name,
                        audit::McpOutcome::Allowed,
                        &details,
                    );
                    rpc_ok(&id, tool_result(&content, false))
                }
                Err(ToolError::Unauthenticated) => StatusCode::UNAUTHORIZED.into_response(),
                Err(ToolError::Refused(error)) => {
                    audit::emit_mcp_tool_call(
                        &origin,
                        &principal,
                        name,
                        audit_outcome(error.code),
                        &details,
                    );
                    rpc_ok(&id, tool_result(&error.to_json(), true))
                }
            }
        }
        _ => rpc_error(&id, -32601, "method not found"),
    }
}

struct Tool {
    name: &'static str,
    description: &'static str,
}

const TOOLS: &[Tool] = &[
    Tool {
        name: "create_sandbox",
        description: "Create a sandbox. Called from a sandbox, it creates a child of that sandbox; called by a user, a root, or a child of `parent`. A child never contacts its parent on its own: results come only from exec and wait. Delete a child when its work is done.",
    },
    Tool {
        name: "list",
        description: "List sandboxes: a sandbox's own children, or the sandboxes in a user's workspace.",
    },
    Tool {
        name: "exec",
        description: "Run a command in a sandbox (from a sandbox: one of its children) and return its output. If it times out, the command may still be running; delete the sandbox to stop everything. Work longer than 45 seconds needs background: true: the command runs as the sandbox's one background job, and this returns its job id at once; collect it with wait. A sandbox runs one background job at a time, so parallel work needs more children.",
    },
    Tool {
        name: "wait",
        description: "Wait for a background job and return its exit code and output. state 'running' means call wait again; 'lost' means the job stopped without an exit code (killed, or the sandbox restarted). A job's result can be read until the next job starts in that sandbox. Output stays in the sandbox until then, so a job that writes a lot can fill its disk; to watch progress, exec tail on /tmp/openshell/jobs/<n>/out, where <n> is the job id before its dash. Job output is the sandbox's data.",
    },
    Tool {
        name: "delete",
        description: "Delete a sandbox (from a sandbox: one of its children) and everything running in it. Deletion finishes in the background; a later not_found for the same name means it is gone.",
    },
    Tool {
        name: "logs",
        description: "Read a sandbox's own recent log lines (its output and policy denials), newest kept. From a sandbox: one of its children.",
    },
];

/// The templates a sandbox caller may create children from, as the gateway
/// lists them for it: only those made available to agents, in its workspace.
async fn agent_templates(call: &Call<'_>) -> Result<Vec<SandboxWorkloadTemplate>, ToolError> {
    let mut client = OpenShellClient::new(call.connection.grpc.clone());
    // Boxed so the handler future is provably `Send`, as in `caller_children`.
    let pending: futures::future::BoxFuture<'_, _> = Box::pin(
        client.list_sandbox_templates(call.request(ListSandboxTemplatesRequest::default())),
    );
    Ok(pending
        .await
        .map_err(ToolError::from_status)?
        .into_inner()
        .templates)
}

/// The tool list. `templates` are the ones a sandbox caller may use; they are
/// offered on `create_sandbox` so an agent need not be told their names.
fn tool_definitions(templates: &[SandboxWorkloadTemplate]) -> Vec<Value> {
    TOOLS
        .iter()
        .map(|tool| {
            let mut description = tool.description.to_string();
            let schema = match tool.name {
                "create_sandbox" => {
                    let mut template = json!({"type": "string", "description": "(sandboxes only) Sandbox template made available to agents."});
                    if !templates.is_empty() {
                        let names: Vec<&str> =
                            templates.iter().map(ObjectName::object_name).collect();
                        template["enum"] = json!(names);
                        let offered: Vec<String> = templates
                            .iter()
                            .map(|template| {
                                let image = template
                                    .spec
                                    .as_ref()
                                    .and_then(|spec| spec.workload.as_ref())
                                    .map(|workload| workload.image.as_str())
                                    .filter(|image| !image.is_empty())
                                    .unwrap_or("the gateway default");
                                format!("{} (image {image})", template.object_name())
                            })
                            .collect();
                        let _ = write!(
                            description,
                            " Templates you may create a child from: {}. Without a template the child copies your image.",
                            offered.join(", ")
                        );
                    }
                    json!({
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "Name of the new sandbox."},
                            "parent": {"type": "string", "description": "(users only) Root sandbox to create a child of; a root when omitted."},
                            "image": {"type": "string", "description": "(users only) Container image; the gateway default when omitted."},
                            "template": template,
                            "providers": {"type": "array", "items": {"type": "string"}, "description": "Providers to attach; for a child, a subset of its parent's, all of them when omitted."},
                        },
                        "required": ["name"],
                        "additionalProperties": false,
                    })
                }
                "exec" => json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Sandbox to run in."},
                        "command": {"type": "array", "items": {"type": "string"}, "description": "Program and arguments; not a shell string."},
                        "workdir": {"type": "string"},
                        "stdin": {"type": "string", "description": "Text passed on stdin."},
                        "stdin_base64": {"type": "string", "description": "Bytes passed on stdin, base64-encoded."},
                        "timeout_s": {"type": "integer", "minimum": 1, "maximum": MAX_EXEC_TIMEOUT_S, "description": "Foreground only; a background job runs until it ends or the child is deleted."},
                        "background": {"type": "boolean", "description": "Start the command as the child's background job and return its job id."},
                    },
                    "required": ["name", "command"],
                    "additionalProperties": false,
                }),
                "wait" => json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Sandbox the job runs in."},
                        "job": {"type": "string", "description": "Job id returned by exec."},
                        "timeout_s": {"type": "integer", "minimum": 1, "maximum": jobs::MAX_WAIT_S},
                    },
                    "required": ["name", "job"],
                    "additionalProperties": false,
                }),
                "delete" => json!({
                    "type": "object",
                    "properties": {"name": {"type": "string", "description": "Sandbox to delete."}},
                    "required": ["name"],
                    "additionalProperties": false,
                }),
                "logs" => json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Sandbox to read."},
                        "lines": {"type": "integer", "minimum": 1, "maximum": MAX_LOG_LINES},
                        "since": {"type": "string", "description": "Only lines at or after this RFC 3339 time."},
                    },
                    "required": ["name"],
                    "additionalProperties": false,
                }),
                "list" => json!({
                    "type": "object",
                    "properties": {"parent": {"type": "string", "description": "(users only) List only this root's children."}},
                    "additionalProperties": false,
                }),
                _ => json!({"type": "object"}),
            };
            json!({"name": tool.name, "description": description, "inputSchema": schema})
        })
        .collect()
}

const DEFAULT_EXEC_TIMEOUT_S: u64 = 30;
const MAX_EXEC_TIMEOUT_S: u64 = 45;
/// How long past `timeout_s` the tool waits for the gateway's exit event.
const EXEC_EXIT_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_STDIN_BYTES: usize = 512 * 1024;
/// Bytes kept from each end of each output stream.
const OUTPUT_EDGE_BYTES: usize = 16 * 1024;
/// Exit code the gateway reports when `execution_timeout` fires.
const GATEWAY_TIMEOUT_EXIT_CODE: i32 = 124;
/// Largest argument list recorded in the audit event.
const MAX_AUDIT_ARGV_BYTES: usize = 1024;
/// Largest working directory an audit event records.
const MAX_AUDIT_WORKDIR_BYTES: usize = 512;
/// Largest value of any other audit field.
const MAX_AUDIT_FIELD_BYTES: usize = 256;

struct ExecArgs {
    name: String,
    command: Vec<String>,
    workdir: String,
    stdin: Vec<u8>,
    timeout: std::time::Duration,
    background: bool,
}

fn parse_exec_args(arguments: &Value) -> Result<ExecArgs, ToolError> {
    let args = arguments_object(arguments)?;
    for key in args.keys() {
        if key == "env" {
            return Err(cli_only("env"));
        }
        if ![
            "name",
            "command",
            "workdir",
            "stdin",
            "stdin_base64",
            "timeout_s",
            "background",
        ]
        .contains(&key.as_str())
        {
            return Err(ToolError::invalid(&format!("unknown argument '{key}'")));
        }
    }
    let background = match args.get("background") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| ToolError::invalid("'background' must be true or false"))?,
    };
    if background && args.contains_key("timeout_s") {
        return Err(ToolError::invalid(
            "a background job has no timeout; omit 'timeout_s' and use wait",
        ));
    }
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| ToolError::invalid("'name' is required"))?;
    let command = args
        .get("command")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .map(|item| item.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
        })
        .filter(|command| !command.is_empty())
        .ok_or_else(|| ToolError::invalid("'command' must be a nonempty list of strings"))?;
    let workdir = args
        .get("workdir")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let stdin = match (args.get("stdin"), args.get("stdin_base64")) {
        (Some(_), Some(_)) => {
            return Err(ToolError::invalid(
                "send 'stdin' or 'stdin_base64', not both",
            ));
        }
        (Some(text), None) => text
            .as_str()
            .ok_or_else(|| ToolError::invalid("'stdin' must be a string"))?
            .as_bytes()
            .to_vec(),
        (None, Some(encoded)) => {
            use base64::Engine;
            encoded
                .as_str()
                .and_then(|encoded| {
                    base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .ok()
                })
                .ok_or_else(|| ToolError::invalid("'stdin_base64' must be base64"))?
        }
        (None, None) => Vec::new(),
    };
    if stdin.len() > MAX_STDIN_BYTES {
        return Err(ToolError::invalid("stdin is larger than 512 KiB"));
    }
    let timeout_s = match args.get("timeout_s") {
        None => DEFAULT_EXEC_TIMEOUT_S,
        Some(value) => value
            .as_u64()
            .filter(|timeout| (1..=MAX_EXEC_TIMEOUT_S).contains(timeout))
            .ok_or_else(|| ToolError::invalid("'timeout_s' must be between 1 and 45"))?,
    };
    Ok(ExecArgs {
        name: name.to_string(),
        command,
        workdir: workdir.to_string(),
        stdin,
        timeout: std::time::Duration::from_secs(timeout_s),
        background,
    })
}

/// Run a command in one of the caller's children and collect its output, for
/// at most `timeout_s` plus a short grace for the gateway's exit event; or
/// start it as the child's background job.
async fn exec_in_child(call: &Call<'_>, arguments: &Value) -> Result<Value, ToolError> {
    let args = parse_exec_args(arguments)?;
    if args.background {
        return jobs::start(call, args).await;
    }
    let request = ExecSandboxRequest {
        sandbox: args.name,
        command: args.command,
        workdir: args.workdir,
        stdin: args.stdin,
        ..Default::default()
    };
    let ExecOutcome {
        stdout,
        stderr,
        exit,
    } = run_in_child(call, request, args.timeout, EXEC_EXIT_GRACE).await?;
    let exit_code = command_exit_code(exit, args.timeout);
    let (stdout, stdout_truncated, stdout_binary) = stdout.render();
    let (stderr, stderr_truncated, stderr_binary) = stderr.render();
    let mut reply = json!({
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "binary_output": stdout_binary || stderr_binary,
        "timed_out": exit_code.is_none(),
    });
    if exit_code.is_none() {
        reply["message"] = json!(
            "the command may still be running in the child; for long work use background: true and wait, or delete the child to stop everything"
        );
    }
    Ok(reply)
}

/// What one exec in a child produced.
struct ExecOutcome {
    stdout: CapturedOutput,
    stderr: CapturedOutput,
    /// The exit code and when it came, or `None` if none came in time.
    exit: Option<(i32, std::time::Duration)>,
}

/// Send one `ExecSandbox` with `timeout` and collect its output until it
/// exits, or until `timeout` plus `grace` has passed.
async fn run_in_child(
    call: &Call<'_>,
    mut request: ExecSandboxRequest,
    timeout: std::time::Duration,
    grace: std::time::Duration,
) -> Result<ExecOutcome, ToolError> {
    use openshell_core::proto::exec_sandbox_event::Payload;

    request.execution_timeout = Some(prost_types::Duration {
        seconds: i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX),
        nanos: 0,
    });
    let started = tokio::time::Instant::now();
    let deadline = started + timeout + grace;
    let mut client = OpenShellClient::new(call.connection.grpc.clone());
    let pending: futures::future::BoxFuture<'_, _> =
        Box::pin(client.exec_sandbox(call.request(request)));
    let mut events = pending.await.map_err(ToolError::from_status)?.into_inner();
    let (mut stdout, mut stderr) = (CapturedOutput::default(), CapturedOutput::default());
    let mut exit = None;
    loop {
        let next: futures::future::BoxFuture<'_, _> = Box::pin(events.message());
        let Ok(event) = tokio::time::timeout_at(deadline, next).await else {
            warn!("mcp: exec did not end at its timeout");
            break;
        };
        match event.map_err(ToolError::from_status)? {
            None => break,
            Some(event) => match event.payload {
                Some(Payload::Stdout(out)) => stdout.push(&out.data),
                Some(Payload::Stderr(err)) => stderr.push(&err.data),
                Some(Payload::Exit(code)) => {
                    exit = Some((code.exit_code, started.elapsed()));
                    break;
                }
                None => {}
            },
        }
    }
    Ok(ExecOutcome {
        stdout,
        stderr,
        exit,
    })
}

/// The command's own exit code, or `None` when it timed out. The gateway
/// reports its timeout as 124; a command can exit 124 too, but only earlier
/// than one second before the timeout.
fn command_exit_code(
    exit: Option<(i32, std::time::Duration)>,
    timeout: std::time::Duration,
) -> Option<i32> {
    match exit {
        Some((GATEWAY_TIMEOUT_EXIT_CODE, elapsed))
            if elapsed + std::time::Duration::from_secs(1) >= timeout =>
        {
            None
        }
        Some((code, _)) => Some(code),
        None => None,
    }
}

/// One output stream: its first and last bytes, and how many there were.
#[derive(Default)]
struct CapturedOutput {
    head: Vec<u8>,
    tail: Vec<u8>,
    total: usize,
}

impl CapturedOutput {
    /// A stream of `total` bytes of which only `edges` arrived: all of it, or
    /// its first and last [`OUTPUT_EDGE_BYTES`].
    fn from_edges(edges: &[u8], total: usize) -> Self {
        let split = edges.len().min(OUTPUT_EDGE_BYTES);
        Self {
            head: edges[..split].to_vec(),
            tail: edges[split..].to_vec(),
            // A file that grew after its size was read still renders.
            total: total.max(edges.len()),
        }
    }

    /// The kept bytes, for output short enough to be kept whole.
    fn into_bytes(mut self) -> Vec<u8> {
        self.head.append(&mut self.tail);
        self.head
    }

    fn push(&mut self, data: &[u8]) {
        self.total += data.len();
        let into_head = OUTPUT_EDGE_BYTES
            .saturating_sub(self.head.len())
            .min(data.len());
        self.head.extend_from_slice(&data[..into_head]);
        self.tail.extend_from_slice(&data[into_head..]);
        if self.tail.len() > OUTPUT_EDGE_BYTES {
            self.tail.drain(..self.tail.len() - OUTPUT_EDGE_BYTES);
        }
    }

    /// The kept text, whether bytes were omitted, and whether the kept bytes
    /// held invalid UTF-8. Cuts fall on character boundaries.
    fn render(&self) -> (String, bool, bool) {
        if self.head.len() + self.tail.len() == self.total {
            let mut all = self.head.clone();
            all.extend_from_slice(&self.tail);
            let text = String::from_utf8_lossy(&all);
            let binary = matches!(text, std::borrow::Cow::Owned(_));
            return (text.into_owned(), false, binary);
        }
        let head = &self.head[..utf8_end_before_partial(&self.head)];
        let tail = &self.tail[utf8_start_after_partial(&self.tail)..];
        let omitted = self.total - head.len() - tail.len();
        let (head, tail) = (String::from_utf8_lossy(head), String::from_utf8_lossy(tail));
        let binary = matches!(head, std::borrow::Cow::Owned(_))
            || matches!(tail, std::borrow::Cow::Owned(_));
        (
            format!("{head}\n… [{omitted} bytes omitted] …\n{tail}"),
            true,
            binary,
        )
    }
}

/// Length of `bytes` without a multi-byte character cut off at its end.
fn utf8_end_before_partial(bytes: &[u8]) -> usize {
    let len = bytes.len();
    for back in 1..=len.min(4) {
        let byte = bytes[len - back];
        if byte & 0xC0 == 0x80 {
            continue;
        }
        let width = match byte {
            0xF0..=0xF7 => 4,
            0xE0..=0xEF => 3,
            0xC0..=0xDF => 2,
            _ => 1,
        };
        return if width > back { len - back } else { len };
    }
    len
}

/// Offset past continuation bytes left at the start of `bytes` by a cut.
fn utf8_start_after_partial(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take(3)
        .take_while(|byte| *byte & 0xC0 == 0x80)
        .count()
}

/// A refusal is a policy or request decision; anything else the call could
/// not finish is a failure, not a denial.
fn audit_outcome(code: &str) -> audit::McpOutcome<'_> {
    match code {
        "internal" | "unavailable" | "timed_out" => audit::McpOutcome::Failed(code),
        _ => audit::McpOutcome::Refused(code),
    }
}

/// The user a sandbox caller acts for: its own record's creator. A failed
/// read is recorded as `unknown` and never fails the call.
pub async fn acting_for(connection: &McpConnection, sandbox_id: &str) -> String {
    let Some(store) = connection.store.as_ref() else {
        return "unknown".to_string();
    };
    match store.get_message::<Sandbox>(sandbox_id).await {
        Ok(Some(sandbox)) if !sandbox.created_by.is_empty() => sandbox.created_by,
        _ => "unknown".to_string(),
    }
}

/// Every field the audit event records about a tool call beyond its caller
/// and outcome: fields of the arguments, then of the reply. Never stdin,
/// environment values, output, log lines or any reply body.
fn tool_call_details(
    tool: &str,
    arguments: &Value,
    result: &Result<Value, ToolError>,
) -> Vec<(&'static str, String)> {
    let mut details = audit_details(tool, arguments);
    let content = match result {
        Ok(content) => content,
        Err(ToolError::Refused(Refusal {
            withheld: Some(withheld),
            ..
        })) => {
            details.push(("request_id", withheld.request_id.clone()));
            details.push(("error_detail", withheld.detail.clone()));
            return details;
        }
        Err(_) => return details,
    };
    let flag = |key: &str| content.get(key).and_then(Value::as_bool);
    match tool {
        "create_sandbox" => {
            details.push(("sandbox_id", json_text(&content["id"])));
            if let Some(already_existed) = flag("already_existed") {
                details.push(("already_existed", already_existed.to_string()));
            }
            if let Some(timed_out) = flag("timed_out") {
                details.push(("timed_out", timed_out.to_string()));
            }
        }
        "list" => {
            let count = content["sandboxes"].as_array().map_or(0, Vec::len);
            details.push(("count", count.to_string()));
        }
        "exec" if content.get("job").is_some() => {
            details.push(("job", json_text(&content["job"])));
            details.push(("state", json_text(&content["state"])));
        }
        "exec" => {
            details.push(("exit_code", json_text(&content["exit_code"])));
            details.push(("timed_out", flag("timed_out").unwrap_or(false).to_string()));
        }
        "wait" => {
            details.push(("state", json_text(&content["state"])));
            if !content["exit_code"].is_null() {
                details.push(("exit_code", json_text(&content["exit_code"])));
            }
        }
        _ => {}
    }
    details
}

/// What the audit event records from a tool call's arguments.
fn audit_details(tool: &str, arguments: &Value) -> Vec<(&'static str, String)> {
    let text = |key| arguments.get(key).map(json_text).unwrap_or_default();
    let given = |key: &'static str| {
        arguments
            .get(key)
            .filter(|value| !value.is_null())
            .map(|value| (key, json_text(value)))
    };
    match tool {
        "create_sandbox" => {
            let mut details = vec![("target", text("name"))];
            details.extend(
                ["template", "parent", "image"]
                    .into_iter()
                    .filter_map(given),
            );
            if let Some(providers) = arguments.get("providers").and_then(Value::as_array) {
                let names: Vec<_> = providers.iter().map(json_text).collect();
                details.push(("providers", names.join(",")));
            }
            details
        }
        "list" => given("parent").into_iter().collect(),
        "delete" => vec![("target", text("name"))],
        "wait" => vec![("target", text("name")), ("job", text("job"))],
        "logs" => {
            let lines = arguments
                .get("lines")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_LOG_LINES);
            vec![("target", text("name")), ("lines", lines.to_string())]
        }
        "exec" => {
            let argv = arguments
                .get("command")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            let mut details = vec![
                ("target", text("name")),
                ("argv", argv),
                ("workdir", text("workdir")),
                (
                    "background",
                    (arguments.get("background") == Some(&Value::Bool(true))).to_string(),
                ),
            ];
            details.extend(given("timeout_s"));
            details
        }
        _ => Vec::new(),
    }
}

/// A JSON value as audit text: a string as is, anything else encoded.
fn json_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Marks a value cut at its cap.
const AUDIT_CUT_MARKER: &str = "…[cut]";

/// Cut every field to its cap on a character boundary, marking a cut. With
/// the fixed field set this keeps an event's details under 4 KiB.
fn capped_audit_details(details: Vec<(&'static str, String)>) -> Vec<(&'static str, String)> {
    details
        .into_iter()
        .map(|(key, value)| {
            let cap = match key {
                "argv" => MAX_AUDIT_ARGV_BYTES,
                "workdir" => MAX_AUDIT_WORKDIR_BYTES,
                _ => MAX_AUDIT_FIELD_BYTES,
            };
            if value.len() <= cap {
                return (key, value);
            }
            let kept = truncate_at_char_boundary(&value, cap - AUDIT_CUT_MARKER.len());
            (key, format!("{kept}{AUDIT_CUT_MARKER}"))
        })
        .collect()
}

fn truncate_at_char_boundary(text: &str, max_bytes: usize) -> &str {
    let mut end = text.len().min(max_bytes);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn arguments_object(arguments: &Value) -> Result<serde_json::Map<String, Value>, ToolError> {
    match arguments {
        Value::Null => Ok(serde_json::Map::new()),
        Value::Object(args) => Ok(args.clone()),
        _ => Err(ToolError::invalid("arguments must be an object")),
    }
}

/// Delete one of the caller's children. Returns at once; deletion finishes in
/// the background.
async fn delete_child(call: &Call<'_>, arguments: &Value) -> Result<Value, ToolError> {
    let name = required_name(&arguments_object(arguments)?, &["name"])?;
    let request = DeleteSandboxRequest {
        name: name.clone(),
        ..Default::default()
    };
    let mut client = OpenShellClient::new(call.connection.grpc.clone());
    let pending: futures::future::BoxFuture<'_, _> =
        Box::pin(client.delete_sandbox(call.request(request)));
    pending.await.map_err(ToolError::from_status)?;
    Ok(json!({"name": name, "deleting": true}))
}

const DEFAULT_LOG_LINES: u64 = 200;
const MAX_LOG_LINES: u64 = 2000;
/// Largest log reply; the newest lines are kept.
const MAX_LOG_BYTES: usize = 64 * 1024;

/// A child's own recent output, newest lines kept within the reply cap.
async fn child_logs(call: &Call<'_>, arguments: &Value) -> Result<Value, ToolError> {
    let args = arguments_object(arguments)?;
    let name = required_name(&args, &["name", "lines", "since"])?;
    let lines = match args.get("lines") {
        None => DEFAULT_LOG_LINES,
        Some(value) => value
            .as_u64()
            .filter(|lines| (1..=MAX_LOG_LINES).contains(lines))
            .ok_or_else(|| ToolError::invalid("'lines' must be between 1 and 2000"))?,
    };
    let since_time = match args.get("since") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .and_then(|since| since.parse::<prost_types::Timestamp>().ok())
                .ok_or_else(|| ToolError::invalid("'since' must be an RFC 3339 time"))?,
        ),
    };
    let request = openshell_core::proto::GetSandboxLogsRequest {
        sandbox: name,
        lines: u32::try_from(lines).unwrap_or(u32::MAX),
        since_time,
        ..Default::default()
    };
    let mut client = OpenShellClient::new(call.connection.grpc.clone());
    let pending: futures::future::BoxFuture<'_, _> =
        Box::pin(client.get_sandbox_logs(call.request(request)));
    let logs = pending
        .await
        .map_err(ToolError::from_status)?
        .into_inner()
        .logs;
    let (lines, truncated) = newest_log_lines(&logs);
    Ok(json!({"lines": lines, "truncated": truncated}))
}

/// The newest lines that fit in the reply cap, oldest first. A single line
/// over the cap keeps its start, cut on a character boundary.
fn newest_log_lines(logs: &[openshell_core::proto::SandboxLogLine]) -> (Vec<Value>, bool) {
    let mut kept = Vec::new();
    let mut bytes = 0;
    let mut truncated = false;
    for log in logs.iter().rev() {
        let room = MAX_LOG_BYTES.saturating_sub(bytes);
        if room == 0 {
            truncated = true;
            break;
        }
        let message = truncate_at_char_boundary(&log.message, room);
        truncated |= message.len() < log.message.len();
        bytes += message.len();
        let time = log.event_time.as_ref().map(ToString::to_string);
        kept.push(json!({"time": time, "level": log.level, "message": message}));
    }
    kept.reverse();
    (kept, truncated)
}

/// Refuse arguments outside `allowed`, and return the required `name`.
fn required_name(
    args: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<String, ToolError> {
    if let Some(key) = args.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(ToolError::invalid(&format!("unknown argument '{key}'")));
    }
    args.get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .ok_or_else(|| ToolError::invalid("'name' is required"))
}

/// `create_sandbox` arguments only a user may send.
const USER_CREATE_ARGUMENTS: [&str; 2] = ["parent", "image"];
/// `create_sandbox` arguments only a sandbox may send.
const SANDBOX_CREATE_ARGUMENTS: [&str; 1] = ["template"];
/// Create options of the CLI that MCP does not take yet.
const CLI_ONLY_CREATE_ARGUMENTS: [&str; 6] =
    ["cpu", "memory", "env", "labels", "command", "policy"];

struct CreateArgs {
    name: String,
    parent: String,
    image: String,
    template: String,
    providers: Vec<String>,
}

fn parse_create_args(arguments: &Value, user: bool) -> Result<CreateArgs, ToolError> {
    let args = arguments_object(arguments)?;
    for key in args.keys().map(String::as_str) {
        if CLI_ONLY_CREATE_ARGUMENTS.contains(&key)
            || (user && SANDBOX_CREATE_ARGUMENTS.contains(&key))
        {
            return Err(cli_only(key));
        }
        if !user && USER_CREATE_ARGUMENTS.contains(&key) {
            return Err(ToolError::invalid(&format!(
                "'{key}' is only available to users"
            )));
        }
        if !["name", "providers"].contains(&key)
            && !USER_CREATE_ARGUMENTS.contains(&key)
            && !SANDBOX_CREATE_ARGUMENTS.contains(&key)
        {
            return Err(ToolError::invalid(&format!("unknown argument '{key}'")));
        }
    }
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| ToolError::invalid("'name' is required"))?;
    let text = |key: &str| match args.get(key) {
        None => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(ToolError::invalid(&format!("'{key}' must be a string"))),
    };
    let (parent, image, template) = (text("parent")?, text("image")?, text("template")?);
    let providers = match args.get("providers") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| ToolError::invalid("'providers' must be a list of names"))?,
        Some(_) => return Err(ToolError::invalid("'providers' must be a list of names")),
    };
    Ok(CreateArgs {
        name: name.to_string(),
        parent,
        image,
        template,
        providers,
    })
}

/// Refuse a create or exec option that only the CLI offers for now.
fn cli_only(key: &str) -> ToolError {
    ToolError::invalid(&format!(
        "'{key}' is not available over MCP; users can set it with the CLI"
    ))
}

/// Create a sandbox, or return the caller's existing one of that name, then
/// wait for it. The name is looked up first so a retry still works when the
/// parent is at its child limit.
async fn create_child(call: &Call<'_>, arguments: &Value) -> Result<Value, ToolError> {
    let args = parse_create_args(arguments, call.is_user())?;
    if find_child(call, &args.name).await?.is_some() {
        return wait_until_ready(call, &args.name, true).await;
    }
    let template = (!args.image.is_empty()).then(|| openshell_core::proto::SandboxTemplate {
        image: args.image,
        ..Default::default()
    });
    let request = CreateSandboxRequest {
        name: args.name.clone(),
        parent: args.parent,
        workload_template: args.template,
        spec: Some(SandboxSpec {
            providers: args.providers,
            template,
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut client = OpenShellClient::new(call.connection.grpc.clone());
    let pending: futures::future::BoxFuture<'_, _> =
        Box::pin(client.create_sandbox(call.request(request)));
    match pending.await {
        Ok(_) => wait_until_ready(call, &args.name, false).await,
        // A create racing the lookup above.
        Err(status) if status.code() == tonic::Code::AlreadyExists => {
            if find_child(call, &args.name).await?.is_some() {
                wait_until_ready(call, &args.name, true).await
            } else {
                Err(ToolError::Refused(Refusal {
                    code: "already_exists",
                    message: format!(
                        "a sandbox named '{}' already exists in this workspace",
                        args.name
                    ),
                    retryable: false,
                    withheld: None,
                }))
            }
        }
        Err(status) => Err(ToolError::from_status(status)),
    }
}

/// Poll the caller's children until `name` is ready or failed, for at most
/// the create wait. Still provisioning at the end is not an error.
async fn wait_until_ready(
    call: &Call<'_>,
    name: &str,
    already_existed: bool,
) -> Result<Value, ToolError> {
    let wait = call.connection.create_wait;
    let deadline = tokio::time::Instant::now() + wait.limit;
    let mut pause = wait.first_poll;
    loop {
        let Some(child) = find_child(call, name).await? else {
            return Err(ToolError::Refused(Refusal {
                code: "not_found",
                message: format!("sandbox '{name}' not found"),
                retryable: false,
                withheld: None,
            }));
        };
        let mut reply = child_summary(&child);
        reply["already_existed"] = json!(already_existed);
        match SandboxPhase::try_from(child.phase()).unwrap_or(SandboxPhase::Unknown) {
            SandboxPhase::Ready => return Ok(reply),
            SandboxPhase::Error => {
                return Err(ToolError::Refused(Refusal {
                    code: "failed_precondition",
                    message: format!("sandbox '{name}' failed: {}", failure_message(&child)),
                    retryable: false,
                    withheld: None,
                }));
            }
            _ => {}
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            reply["ready"] = json!(false);
            reply["timed_out"] = json!(true);
            reply["message"] =
                json!("call create_sandbox again with the same name to keep waiting");
            return Ok(reply);
        }
        tokio::time::sleep(pause.min(deadline - now)).await;
        pause = wait.poll;
    }
}

fn failure_message(sandbox: &Sandbox) -> String {
    sandbox
        .status
        .as_ref()
        .and_then(|status| {
            status
                .conditions
                .iter()
                .find(|condition| condition.r#type == "Ready")
        })
        .map(|condition| condition.message.clone())
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| "no reason was recorded".to_string())
}

/// The caller's sandbox of this name: a sandbox's child, or for a user any
/// sandbox in the workspace.
async fn find_child(call: &Call<'_>, name: &str) -> Result<Option<Sandbox>, ToolError> {
    Ok(caller_children(call, "")
        .await?
        .into_iter()
        .find(|child| child.object_name() == name))
}

async fn list_sandboxes(call: &Call<'_>, arguments: &Value) -> Result<Value, ToolError> {
    let args = arguments_object(arguments)?;
    if let Some(key) = args.keys().find(|key| key.as_str() != "parent") {
        return Err(ToolError::invalid(&format!("unknown argument '{key}'")));
    }
    let parent = match args.get("parent") {
        None => "",
        Some(_) if !call.is_user() => {
            return Err(ToolError::invalid("'parent' is only available to users"));
        }
        Some(Value::String(parent)) => parent,
        Some(_) => return Err(ToolError::invalid("'parent' must be a string")),
    };
    let sandboxes = caller_children(call, parent).await?;
    Ok(json!({"sandboxes": sandboxes.iter().map(child_summary).collect::<Vec<_>>()}))
}

/// Every sandbox the caller lists, following page tokens to the end: a
/// sandbox's own children, or the user's workspace, narrowed to `parent`'s
/// children when it is set.
async fn caller_children(call: &Call<'_>, parent: &str) -> Result<Vec<Sandbox>, ToolError> {
    let mut client = OpenShellClient::new(call.connection.grpc.clone());
    let mut children = Vec::new();
    let mut page_token = String::new();
    loop {
        let request = ListSandboxesRequest {
            page_size: i32::try_from(crate::pagination::MAX_PAGE_SIZE).unwrap_or(i32::MAX),
            page_token,
            parent: parent.to_string(),
            ..Default::default()
        };
        // Boxed so the handler future is provably `Send`; tonic's generic
        // error bound otherwise trips a higher-ranked lifetime check.
        let pending: futures::future::BoxFuture<'_, _> =
            Box::pin(client.list_sandboxes(call.request(request)));
        let page = pending.await.map_err(ToolError::from_status)?.into_inner();
        children.extend(page.sandboxes);
        if page.next_page_token.is_empty() {
            break;
        }
        page_token = page.next_page_token;
    }
    Ok(children)
}

fn child_summary(sandbox: &Sandbox) -> Value {
    let phase = SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown);
    let created_at = sandbox
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.created_time.as_ref())
        .map(ToString::to_string);
    let mut summary = json!({
        "id": sandbox.object_id(),
        "name": sandbox.object_name(),
        "state": phase.as_str_name().trim_start_matches("SANDBOX_PHASE_").to_ascii_lowercase(),
        "created_at": created_at,
    });
    if let Some(parent) = &sandbox.parent {
        summary["parent"] = json!(parent.name);
    }
    summary
}

/// The workspace a user's bridge names; sandboxes never send it.
const WORKSPACE_HEADER: &str = "x-openshell-workspace";
/// A user's workspace when the bridge names none, as in the CLI.
const DEFAULT_WORKSPACE: &str = "default";

/// One tool call: the connection, the caller's headers and, for a user, the
/// workspace to act in. A sandbox caller has no workspace here; its handlers
/// read it from the caller's own record.
struct Call<'a> {
    connection: &'a McpConnection,
    headers: &'a HeaderMap,
    workspace: Option<String>,
}

impl Call<'_> {
    fn is_user(&self) -> bool {
        self.workspace.is_some()
    }

    /// A gRPC request for the in-process stack: the caller's own credential,
    /// the `/mcp` marker and, for a user, the workspace.
    fn request<T: WorkspaceScoped>(&self, mut message: T) -> tonic::Request<T> {
        if let Some(workspace) = &self.workspace {
            *message.workspace_scope() =
                Some(openshell_core::proto::workspace_selector(workspace.clone()));
        }
        mcp_request(message, self.headers)
    }
}

/// The requests the tools send, each with its workspace selector.
trait WorkspaceScoped {
    fn workspace_scope(&mut self) -> &mut Option<openshell_core::proto::WorkspaceSelector>;
}

macro_rules! workspace_scoped {
    ($($request:ty),*) => {$(
        impl WorkspaceScoped for $request {
            fn workspace_scope(
                &mut self,
            ) -> &mut Option<openshell_core::proto::WorkspaceSelector> {
                &mut self.workspace_scope
            }
        }
    )*};
}

workspace_scoped!(
    CreateSandboxRequest,
    ListSandboxesRequest,
    ListSandboxTemplatesRequest,
    ExecSandboxRequest,
    DeleteSandboxRequest,
    openshell_core::proto::GetSandboxLogsRequest
);

/// A gRPC request for the in-process stack: the caller's own credential and
/// the `/mcp` marker.
fn mcp_request<T>(message: T, headers: &HeaderMap) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    for name in [http::header::AUTHORIZATION.as_str(), "x-request-id"] {
        if let Some(value) = headers
            .get(name)
            .and_then(|value| tonic::metadata::AsciiMetadataValue::try_from(value.as_bytes()).ok())
        {
            request.metadata_mut().insert(name, value);
        }
    }
    request.extensions_mut().insert(McpOrigin);
    request
}

enum ToolError {
    /// The caller's credential stopped working mid-call; answered with HTTP 401.
    Unauthenticated,
    Refused(Refusal),
}

struct Refusal {
    code: &'static str,
    message: String,
    retryable: bool,
    /// What the agent is not shown, for the gateway log and the audit event.
    withheld: Option<Withheld>,
}

/// An error's own text, withheld from the agent, and the request id that
/// matches the agent's message to the gateway log and the audit event.
struct Withheld {
    request_id: String,
    detail: String,
}

impl Refusal {
    fn to_json(&self) -> Value {
        json!({"error": self.code, "message": self.message, "retryable": self.retryable})
    }
}

impl ToolError {
    fn invalid(message: &str) -> Self {
        Self::Refused(Refusal {
            code: "invalid_argument",
            message: message.to_string(),
            retryable: false,
            withheld: None,
        })
    }

    /// A retryable error whose text is logged and audited, not returned:
    /// internal and unavailable errors can carry store or driver detail.
    fn withheld(code: &'static str, summary: &str, status: &tonic::Status) -> Self {
        let request_id = uuid::Uuid::new_v4().to_string();
        warn!(%request_id, code, error = %status.message(), "mcp: tool call failed");
        Self::Refused(Refusal {
            code,
            message: format!(
                "{summary} (request {request_id}); the operator can find it in the gateway logs"
            ),
            retryable: true,
            withheld: Some(Withheld {
                request_id,
                detail: status.message().to_string(),
            }),
        })
    }

    /// Map a gRPC status to the agent-facing error. Internal, unknown and
    /// unavailable errors are withheld; the rest are written for agents.
    fn from_status(status: tonic::Status) -> Self {
        use tonic::Code;
        let (code, retryable) = match status.code() {
            Code::Unauthenticated => return Self::Unauthenticated,
            Code::InvalidArgument => ("invalid_argument", false),
            Code::NotFound => ("not_found", false),
            Code::AlreadyExists => ("already_exists", false),
            Code::FailedPrecondition => ("failed_precondition", false),
            Code::PermissionDenied => ("permission_denied", false),
            Code::ResourceExhausted if is_rate_limit(&status) => ("rate_limited", true),
            Code::ResourceExhausted => ("limit_reached", false),
            Code::Aborted => ("unavailable", true),
            Code::DeadlineExceeded => ("timed_out", true),
            Code::Unavailable => {
                return Self::withheld("unavailable", "gateway unavailable", &status);
            }
            _ => return Self::withheld("internal", "internal error", &status),
        };
        Self::Refused(Refusal {
            code,
            message: status.message().to_string(),
            retryable,
            withheld: None,
        })
    }
}

/// Whether the gateway's rate limiter refused the call, the one
/// `ResourceExhausted` worth retrying.
fn is_rate_limit(status: &tonic::Status) -> bool {
    openshell_core::rpc_error::decode_details(status)
        .and_then(|details| details.error_info().cloned())
        .is_some_and(|info| {
            info.reason == "RATE_LIMITED" && info.domain == openshell_core::rpc_error::ERROR_DOMAIN
        })
}

fn tool_result(content: &Value, is_error: bool) -> Value {
    let text = content
        .get("message")
        .filter(|_| is_error)
        .and_then(Value::as_str)
        .map_or_else(|| content.to_string(), str::to_string);
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": content,
        "isError": is_error,
    })
}

/// Echo a supported protocol version, otherwise offer the newest one.
fn negotiate_protocol_version(requested: Option<&str>) -> &'static str {
    requested
        .and_then(|v| SUPPORTED_PROTOCOL_VERSIONS.iter().find(|s| **s == v))
        .copied()
        .unwrap_or(SUPPORTED_PROTOCOL_VERSIONS[0])
}

fn rpc_ok(id: &Value, result: Value) -> Response {
    axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Response {
    axum::Json(json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}))
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::authenticator::test_support::MockAuthenticator;
    use crate::auth::authenticator::{Authentication, AuthenticatorChain};
    use crate::auth::identity::Identity;
    use crate::auth::identity::IdentityProvider;
    use crate::auth::principal::{SandboxIdentitySource, SandboxPrincipal, UserPrincipal};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn sandbox_principal(sandbox_id: &str) -> Principal {
        Principal::Sandbox(SandboxPrincipal {
            sandbox_id: sandbox_id.to_string(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "openshell-gateway:test".to_string(),
                auth_epoch: None,
            },
            trust_domain: Some("openshell".to_string()),
        })
    }

    fn user(provider: IdentityProvider) -> Principal {
        Principal::User(UserPrincipal {
            identity: Identity {
                subject: "user".to_string(),
                display_name: None,
                roles: vec!["openshell-user".to_string()],
                scopes: Vec::new(),
                provider,
            },
        })
    }

    /// A connection whose callers resolve to `caller` (or are refused) and
    /// whose gRPC stack must never be reached.
    fn connection(caller: Option<Principal>) -> McpConnection {
        let outcome = caller.map_or(Ok(Authentication::NotApplicable), |principal| {
            Ok(Authentication::Accepted(principal))
        });
        let chain = AuthenticatorChain::new(vec![Arc::new(MockAuthenticator::returning(outcome))]);
        let unreachable = tower::service_fn(|_: http::Request<tonic::body::Body>| async {
            panic!("the gRPC stack must not be called");
            #[allow(unreachable_code)]
            Ok::<_, std::convert::Infallible>(http::Response::new(tonic::body::Body::empty()))
        });
        let auth = crate::multiplex::AuthGrpcRouter::new(unreachable, Some(chain), None)
            .caller_authenticator();
        McpConnection::new(auth, unreachable)
    }

    async fn post_mcp(
        connection: McpConnection,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> (StatusCode, Option<Value>) {
        let mut request = http::Request::post(MCP_PATH).header("content-type", "application/json");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = router()
            .layer(Extension(connection))
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).ok())
    }

    fn rpc(method: &str, params: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .unwrap()
    }

    #[tokio::test]
    async fn users_and_sandboxes_are_served_and_anonymous_callers_are_not() {
        let initialize = || rpc("initialize", json!({"protocolVersion": "2025-06-18"}));
        for (caller, expected) in [
            (None, StatusCode::UNAUTHORIZED),
            (Some(Principal::Anonymous), StatusCode::UNAUTHORIZED),
            (Some(user(IdentityProvider::LocalDev)), StatusCode::OK),
            (Some(user(IdentityProvider::Oidc)), StatusCode::OK),
            (Some(user(IdentityProvider::Mtls)), StatusCode::OK),
            (Some(sandbox_principal("lead")), StatusCode::OK),
        ] {
            let (status, _) = post_mcp(connection(caller), &[], initialize()).await;
            assert_eq!(status, expected);
        }
    }

    #[tokio::test]
    async fn any_origin_header_is_refused_from_every_caller() {
        for caller in [user(IdentityProvider::Oidc), sandbox_principal("lead")] {
            for origin in [
                "http://attacker.example",
                "http://localhost:8080",
                "http://openshell.local",
                "null",
            ] {
                let (status, _) = post_mcp(
                    connection(Some(caller.clone())),
                    &[("origin", origin)],
                    rpc("ping", json!({})),
                )
                .await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{origin}");
            }
        }
    }

    #[tokio::test]
    async fn a_users_tool_list_offers_no_templates() {
        // The connection's gRPC stack panics if called.
        let (status, reply) = post_mcp(
            connection(Some(user(IdentityProvider::Oidc))),
            &[],
            rpc("tools/list", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let reply = reply.unwrap();
        let create = reply["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "create_sandbox")
            .unwrap();
        assert!(
            create["inputSchema"]["properties"]["template"]
                .get("enum")
                .is_none(),
            "{create}"
        );
    }

    #[tokio::test]
    async fn initialize_negotiates_a_supported_version() {
        for (requested, answered) in [("2025-06-18", "2025-06-18"), ("1999-01-01", "2025-11-25")] {
            let (status, reply) = post_mcp(
                connection(Some(sandbox_principal("lead"))),
                &[],
                rpc("initialize", json!({"protocolVersion": requested})),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(reply.unwrap()["result"]["protocolVersion"], answered);
        }
    }

    #[tokio::test]
    async fn the_endpoint_refuses_what_it_does_not_serve() {
        let lead = || connection(Some(sandbox_principal("lead")));
        // A foreign browser origin, before anything else.
        let (status, _) = post_mcp(
            connection(None),
            &[("origin", "http://attacker.example")],
            rpc("ping", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = post_mcp(lead(), &[], vec![b' '; MAX_REQUEST_BYTES + 1]).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

        let (_, reply) = post_mcp(lead(), &[], b"[]".to_vec()).await;
        assert_eq!(reply.unwrap()["error"]["code"], -32600);

        let (_, reply) = post_mcp(lead(), &[], rpc("tools/call", json!({"name": "rm"}))).await;
        assert_eq!(reply.unwrap()["error"]["code"], -32602);
    }

    #[test]
    fn the_audit_event_is_valid_and_carries_no_token_or_stdin() {
        let headers = HeaderMap::from_iter([(
            http::header::AUTHORIZATION,
            "Bearer canary-secret-token-7d1e".parse().unwrap(),
        )]);
        let details = audit_details(
            "exec",
            &json!({"name": "w1", "command": ["ls", "-l"], "workdir": "/tmp", "stdin": "secret-stdin"}),
        );
        let event = audit::mcp_tool_call_event(
            &RequestOrigin::new(None, &headers),
            &sandbox_principal("lead"),
            "exec",
            audit::McpOutcome::Refused("not_found"),
            &details,
        );
        let event = serde_json::to_value(event).unwrap();
        assert_eq!(event["api"]["operation"], "exec");
        assert_eq!(event["status_detail"], "not_found");
        assert_eq!(event["unmapped"]["argv"], "ls -l");
        assert_eq!(event["unmapped"]["workdir"], "/tmp");
        let text = event.to_string();
        assert!(!text.contains("canary-secret-token") && !text.contains("secret-stdin"));
        openshell_ocsf_validate::validate_event(&event).unwrap_or_else(|e| panic!("{e}"));
    }

    fn recorded(
        tool: &str,
        arguments: Value,
        result: Result<Value, ToolError>,
    ) -> std::collections::HashMap<&'static str, String> {
        capped_audit_details(tool_call_details(tool, &arguments, &result))
            .into_iter()
            .collect()
    }

    #[test]
    fn each_tool_records_its_fields_and_keeps_the_existing_keys() {
        let create = recorded(
            "create_sandbox",
            json!({"name": "w1", "parent": "lead", "image": "img:1", "providers": ["gh", "oa"]}),
            Ok(json!({"id": "id-1", "name": "w1", "already_existed": false})),
        );
        assert_eq!(create["target"], "w1");
        assert_eq!(create["parent"], "lead");
        assert_eq!(create["image"], "img:1");
        assert_eq!(create["providers"], "gh,oa");
        assert_eq!(create["sandbox_id"], "id-1");
        assert_eq!(create["already_existed"], "false");
        assert!(!create.contains_key("template") && !create.contains_key("timed_out"));

        let list = recorded(
            "list",
            json!({"parent": "lead"}),
            Ok(json!({"sandboxes": [{}, {}]})),
        );
        assert_eq!(list["parent"], "lead");
        assert_eq!(list["count"], "2");

        let exec = recorded(
            "exec",
            json!({"name": "w1", "command": ["ls"], "timeout_s": 10, "stdin": "secret"}),
            Ok(json!({"exit_code": 0, "timed_out": false, "stdout": "out"})),
        );
        assert_eq!(exec["target"], "w1");
        assert_eq!(exec["argv"], "ls");
        assert_eq!(exec["background"], "false");
        assert_eq!(exec["timeout_s"], "10");
        assert_eq!(exec["exit_code"], "0");
        assert_eq!(exec["timed_out"], "false");

        let started = recorded(
            "exec",
            json!({"name": "w1", "command": ["sleep", "9"], "background": true}),
            Ok(json!({"job": "1-ab", "state": "running"})),
        );
        assert_eq!(started["job"], "1-ab");
        assert_eq!(started["state"], "running");
        assert_eq!(started["background"], "true");

        let waited = recorded(
            "wait",
            json!({"name": "w1", "job": "1-ab"}),
            Ok(json!({"job": "1-ab", "state": "completed", "exit_code": 3, "stdout": "x"})),
        );
        assert_eq!(waited["job"], "1-ab");
        assert_eq!(waited["state"], "completed");
        assert_eq!(waited["exit_code"], "3");

        assert_eq!(
            recorded("delete", json!({"name": "w1"}), Ok(json!({})))["target"],
            "w1"
        );
        let logs = recorded("logs", json!({"name": "w1"}), Ok(json!({"lines": ["l"]})));
        assert_eq!(logs["lines"], DEFAULT_LOG_LINES.to_string());

        // Nothing from stdin, output, log lines or reply bodies.
        for fields in [&create, &list, &exec, &started, &waited, &logs] {
            for value in fields.values() {
                assert!(!value.contains("secret") && value != "out" && value != "x");
            }
        }
    }

    #[test]
    fn long_values_are_cut_at_their_cap_with_a_marker() {
        let long = "é".repeat(4096);
        let fields = recorded(
            "exec",
            json!({"name": long, "command": [long], "workdir": long, "timeout_s": 1}),
            Ok(json!({"exit_code": 0, "timed_out": false})),
        );
        for (key, cap) in [
            ("argv", MAX_AUDIT_ARGV_BYTES),
            ("workdir", MAX_AUDIT_WORKDIR_BYTES),
            ("target", MAX_AUDIT_FIELD_BYTES),
        ] {
            assert!(fields[key].len() <= cap, "{key}");
            assert!(fields[key].ends_with(AUDIT_CUT_MARKER), "{key}");
            assert!(fields[key].starts_with("éé"), "{key}");
        }

        // The largest event any tool can produce stays under 4 KiB.
        let mut worst = capped_audit_details(tool_call_details(
            "exec",
            &json!({"name": long, "command": [long], "workdir": long, "timeout_s": long}),
            &Ok(json!({"job": long, "state": long})),
        ));
        worst.push(("acting_for", long.clone()));
        let worst = capped_audit_details(worst);
        let total: usize = worst
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum();
        assert!(total <= 4096, "{total}");

        // So does a failed call, which records the withheld error instead.
        let mut worst = capped_audit_details(tool_call_details(
            "exec",
            &json!({"name": long, "command": [long], "workdir": long, "timeout_s": long}),
            &Err(ToolError::from_status(tonic::Status::internal(
                long.clone(),
            ))),
        ));
        worst.push(("acting_for", long));
        let worst = capped_audit_details(worst);
        let total: usize = worst
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum();
        assert!(total <= 4096, "{total}");
    }

    #[test]
    fn a_failure_is_not_recorded_as_a_denial() {
        let event = |code| {
            serde_json::to_value(audit::mcp_tool_call_event(
                &RequestOrigin::new(None, &HeaderMap::new()),
                &sandbox_principal("lead"),
                "exec",
                audit_outcome(code),
                &[],
            ))
            .unwrap()
        };
        for code in ["internal", "unavailable", "timed_out"] {
            let failed = event(code);
            assert_eq!(failed["action_id"], 1, "{code}: allowed, not denied");
            assert_eq!(failed["status_id"], 2, "{code}");
            assert_eq!(failed["status_detail"], code);
            assert_eq!(
                failed["message"],
                format!("mcp tool call exec: failed ({code})")
            );
            openshell_ocsf_validate::validate_event(&failed).unwrap_or_else(|e| panic!("{e}"));
        }
        for code in ["not_found", "failed_precondition", "limit_reached"] {
            let refused = event(code);
            assert_eq!(refused["action_id"], 2, "{code}: denied");
            assert_eq!(refused["disposition_id"], 2, "{code}: blocked");
            assert_eq!(
                refused["message"],
                format!("mcp tool call exec: refused ({code})")
            );
        }
    }

    /// Internal, unknown and unavailable errors can carry store or driver
    /// detail: the agent gets a request id instead, and keeps its retry hint.
    #[test]
    fn internal_detail_never_reaches_the_agent() {
        let detail = "store pool exhausted at 10.0.0.3:5432";
        for (status, code) in [
            (tonic::Status::internal(detail), "internal"),
            (tonic::Status::unknown(detail), "internal"),
            (tonic::Status::unavailable(detail), "unavailable"),
        ] {
            let ToolError::Refused(refusal) = ToolError::from_status(status) else {
                panic!("not a refusal");
            };
            assert_eq!((refusal.code, refusal.retryable), (code, true));
            assert!(!refusal.message.contains("10.0.0.3"), "{}", refusal.message);
            // The audit event keeps the detail, under the id the agent sees.
            let message = refusal.message.clone();
            let fields = recorded("list", json!({}), Err(ToolError::Refused(refusal)));
            assert_eq!(fields["error_detail"], detail);
            assert!(
                message.contains(&format!("(request {})", fields["request_id"])),
                "{message}"
            );
        }
        let fields = recorded(
            "list",
            json!({}),
            Err(ToolError::from_status(tonic::Status::internal(
                "é".repeat(400),
            ))),
        );
        assert!(fields["error_detail"].len() <= MAX_AUDIT_FIELD_BYTES);
        assert!(fields["error_detail"].ends_with(AUDIT_CUT_MARKER));
        // Messages written for agents are kept.
        for status in [
            tonic::Status::failed_precondition("parent sandbox 'lead' is being deleted"),
            tonic::Status::invalid_argument("name must be at most 63 characters"),
        ] {
            let message = status.message().to_string();
            let ToolError::Refused(refusal) = ToolError::from_status(status) else {
                panic!("not a refusal");
            };
            assert_eq!(refusal.message, message);
        }
    }

    /// Only a rate limit is worth retrying: a full child limit, even one
    /// waiting on deletes, and an oversized message are not.
    #[test]
    fn only_a_rate_limit_is_retryable() {
        use openshell_core::rpc_error::{ERROR_DOMAIN, ErrorDetails, StatusExt};
        let refusal = |status| match ToolError::from_status(status) {
            ToolError::Refused(refusal) => refusal,
            ToolError::Unauthenticated => panic!("not a refusal"),
        };
        let rate_limited = refusal(tonic::Status::with_error_details(
            tonic::Code::ResourceExhausted,
            "gRPC rate limit exceeded",
            ErrorDetails::with_error_info(
                "RATE_LIMITED",
                ERROR_DOMAIN,
                std::collections::HashMap::new(),
            ),
        ));
        assert_eq!(
            (rate_limited.code, rate_limited.retryable),
            ("rate_limited", true)
        );
        assert_eq!(rate_limited.message, "gRPC rate limit exceeded");
        for message in [
            "sandbox 'lead' has reached its limit of 2 children, 1 of them still being deleted; try again shortly",
            "gRPC message exceeds u32",
        ] {
            let other = refusal(tonic::Status::resource_exhausted(message));
            assert_eq!((other.code, other.retryable), ("limit_reached", false));
        }
    }

    #[test]
    fn a_late_124_is_a_timeout_and_an_early_one_is_the_commands() {
        let timeout = std::time::Duration::from_secs(10);
        let at = std::time::Duration::from_millis;
        assert_eq!(command_exit_code(Some((124, at(9_000))), timeout), None);
        assert_eq!(command_exit_code(Some((124, at(10_200))), timeout), None);
        assert_eq!(
            command_exit_code(Some((124, at(8_900))), timeout),
            Some(124)
        );
        assert_eq!(command_exit_code(Some((0, at(10_200))), timeout), Some(0));
        assert_eq!(command_exit_code(None, timeout), None);
    }

    #[tokio::test]
    async fn create_sandbox_refuses_user_only_and_unknown_arguments() {
        for (arguments, message) in [
            (
                json!({"name": "w", "image": "x"}),
                "'image' is only available to users",
            ),
            (
                json!({"name": "w", "parent": "x"}),
                "'parent' is only available to users",
            ),
            (json!({"name": "w", "size": 3}), "unknown argument 'size'"),
            (json!({}), "'name' is required"),
        ] {
            let (_, reply) = post_mcp(
                connection(Some(sandbox_principal("lead"))),
                &[],
                rpc(
                    "tools/call",
                    json!({"name": "create_sandbox", "arguments": arguments}),
                ),
            )
            .await;
            let result = &reply.unwrap()["result"];
            assert_eq!(result["isError"], true);
            assert_eq!(result["structuredContent"]["error"], "invalid_argument");
            assert_eq!(result["structuredContent"]["message"], message);
        }
    }

    #[test]
    fn create_arguments_depend_on_the_caller() {
        let refusal = |arguments: Value, user: bool| match parse_create_args(&arguments, user) {
            Ok(_) => String::new(),
            Err(ToolError::Refused(refusal)) => refusal.message,
            Err(ToolError::Unauthenticated) => unreachable!(),
        };
        let user_args = json!({"name": "w", "parent": "lead", "image": "img", "providers": ["p"]});
        let args = parse_create_args(&user_args, true).ok().unwrap();
        assert_eq!(
            (
                args.parent.as_str(),
                args.image.as_str(),
                args.providers.len()
            ),
            ("lead", "img", 1)
        );
        let sandbox_args = json!({"name": "w", "template": "t", "providers": ["p"]});
        assert_eq!(refusal(sandbox_args, false), "");
        for (arguments, user, message) in [
            (
                json!({"name": "w", "parent": "x"}),
                false,
                "'parent' is only available to users",
            ),
            (
                json!({"name": "w", "image": "x"}),
                false,
                "'image' is only available to users",
            ),
            (
                json!({"name": "w", "template": "t"}),
                true,
                "'template' is not available over MCP; users can set it with the CLI",
            ),
            (
                json!({"name": "w", "policy": "x"}),
                true,
                "'policy' is not available over MCP; users can set it with the CLI",
            ),
            (
                json!({"name": "w", "env": {}}),
                false,
                "'env' is not available over MCP; users can set it with the CLI",
            ),
            (
                json!({"name": "w", "size": 3}),
                true,
                "unknown argument 'size'",
            ),
        ] {
            assert_eq!(refusal(arguments, user), message);
        }
    }

    #[tokio::test]
    async fn only_users_may_list_by_parent() {
        let (_, reply) = post_mcp(
            connection(Some(sandbox_principal("lead"))),
            &[],
            rpc(
                "tools/call",
                json!({"name": "list", "arguments": {"parent": "other"}}),
            ),
        )
        .await;
        let result = &reply.unwrap()["result"];
        assert_eq!(
            result["structuredContent"]["message"],
            "'parent' is only available to users"
        );
    }

    #[test]
    fn tool_call_details_add_a_jobs_id_and_state_from_the_reply() {
        let field = |details: &[(&str, String)], key: &str| {
            details
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| value.clone())
        };
        let start = json!({"name": "w", "command": ["sleep", "9"], "background": true});
        let details = tool_call_details(
            "exec",
            &start,
            &Ok(json!({"job": "1-0a1b2c3d", "state": "running"})),
        );
        assert_eq!(field(&details, "argv").as_deref(), Some("sleep 9"));
        assert_eq!(field(&details, "background").as_deref(), Some("true"));
        assert_eq!(field(&details, "job").as_deref(), Some("1-0a1b2c3d"));
        assert_eq!(field(&details, "state").as_deref(), Some("running"));

        let wait = json!({"name": "w", "job": "1-0a1b2c3d"});
        let details = tool_call_details(
            "wait",
            &wait,
            &Ok(json!({"job": "1-0a1b2c3d", "state": "completed", "stdout": "secret output"})),
        );
        assert_eq!(field(&details, "target").as_deref(), Some("w"));
        assert_eq!(field(&details, "job").as_deref(), Some("1-0a1b2c3d"));
        assert_eq!(field(&details, "state").as_deref(), Some("completed"));
        assert_eq!(details.iter().filter(|(name, _)| *name == "job").count(), 1);
        assert!(details.iter().all(|(_, value)| !value.contains("secret")));

        // A refused call records only what its arguments say.
        let refused = Err(ToolError::invalid(
            "'job' must be a job id returned by exec",
        ));
        let details = tool_call_details("wait", &wait, &refused);
        assert_eq!(field(&details, "state"), None);
    }

    #[test]
    fn output_keeps_both_ends_and_cuts_on_character_boundaries() {
        let mut small = CapturedOutput::default();
        small.push(b"hello");
        assert_eq!(small.render(), ("hello".to_string(), false, false));

        // "é" is two bytes; one straddles the head's 16 KiB edge and one the
        // tail's, so neither may turn into a replacement character.
        let mut text = "a".repeat(OUTPUT_EDGE_BYTES - 1);
        text.push('é');
        text.push_str(&"b".repeat(40_000));
        text.push('é');
        text.push_str(&"c".repeat(OUTPUT_EDGE_BYTES - 2));
        let mut output = CapturedOutput::default();
        for chunk in text.as_bytes().chunks(1000) {
            output.push(chunk);
        }
        let (rendered, truncated, binary) = output.render();
        assert!(truncated);
        assert!(!binary, "a cut character is not binary output");
        assert!(!rendered.contains('\u{FFFD}'));
        assert!(rendered.starts_with(&"a".repeat(OUTPUT_EDGE_BYTES - 1)));
        assert!(rendered.ends_with(&"c".repeat(OUTPUT_EDGE_BYTES - 2)));
        assert!(rendered.contains("bytes omitted"));

        let mut binary = CapturedOutput::default();
        binary.push(&[0xff, 0xfe, b'x']);
        assert!(binary.render().2);
    }

    #[test]
    fn a_jobs_output_rebuilt_from_its_edges_renders_like_execs() {
        let small = CapturedOutput::from_edges(b"done\n", 5);
        assert_eq!(small.render(), ("done\n".to_string(), false, false));

        // 100 KB of output of which the child sent only both 16 KiB edges.
        let text = format!(
            "{}{}{}",
            "a".repeat(OUTPUT_EDGE_BYTES),
            "b".repeat(100_000 - 2 * OUTPUT_EDGE_BYTES),
            "c".repeat(OUTPUT_EDGE_BYTES)
        );
        let mut whole = CapturedOutput::default();
        whole.push(text.as_bytes());
        let mut edges = "a".repeat(OUTPUT_EDGE_BYTES);
        edges.push_str(&"c".repeat(OUTPUT_EDGE_BYTES));
        let rebuilt = CapturedOutput::from_edges(edges.as_bytes(), 100_000);
        assert_eq!(rebuilt.render(), whole.render());
        assert!(rebuilt.render().1);

        // A size read before the file grew never makes the count negative.
        assert!(!CapturedOutput::from_edges(b"abc", 1).render().1);
    }

    #[test]
    fn the_audit_argument_list_is_capped_on_a_character_boundary() {
        let details = capped_audit_details(audit_details(
            "exec",
            &json!({"name": "w", "command": ["echo", "é".repeat(1000)], "stdin": "secret"}),
        ));
        let argv = &details.iter().find(|(key, _)| *key == "argv").unwrap().1;
        assert!(argv.len() <= MAX_AUDIT_ARGV_BYTES);
        assert!(argv.starts_with("echo é"));
        assert!(details.iter().all(|(_, value)| !value.contains("secret")));
    }

    #[tokio::test]
    async fn exec_refuses_bad_arguments_before_calling_the_gateway() {
        let big = "x".repeat(MAX_STDIN_BYTES + 1);
        let invalid = "invalid_argument";
        for (arguments, error, message) in [
            (
                json!({"name": "w", "command": ["ls"], "background": true, "timeout_s": 5}),
                invalid,
                "a background job has no timeout; omit 'timeout_s' and use wait",
            ),
            (
                json!({"name": "w", "command": ["ls"], "background": "yes"}),
                invalid,
                "'background' must be true or false",
            ),
            (
                json!({"name": "w", "command": ["ls"], "stdin": big}),
                invalid,
                "stdin is larger than 512 KiB",
            ),
            (
                json!({"name": "w", "command": ["ls"], "stdin": "a", "stdin_base64": "YQ=="}),
                invalid,
                "send 'stdin' or 'stdin_base64', not both",
            ),
            (
                json!({"name": "w", "command": ["ls"], "timeout_s": 46}),
                invalid,
                "'timeout_s' must be between 1 and 45",
            ),
            (
                json!({"name": "w", "command": ["ls"], "env": {}}),
                invalid,
                "'env' is not available over MCP; users can set it with the CLI",
            ),
            (
                json!({"name": "w", "command": ["ls"], "size": 3}),
                invalid,
                "unknown argument 'size'",
            ),
            (
                json!({"name": "w", "command": "ls"}),
                invalid,
                "'command' must be a nonempty list of strings",
            ),
        ] {
            let (_, reply) = post_mcp(
                connection(Some(sandbox_principal("lead"))),
                &[],
                rpc(
                    "tools/call",
                    json!({"name": "exec", "arguments": arguments}),
                ),
            )
            .await;
            let result = &reply.unwrap()["result"];
            assert_eq!(result["isError"], true);
            assert_eq!(result["structuredContent"]["error"], error);
            assert_eq!(result["structuredContent"]["message"], message);
        }
    }

    #[tokio::test]
    async fn delete_refuses_unknown_arguments() {
        for (arguments, message) in [
            (
                json!({"name": "w", "force": true}),
                "unknown argument 'force'",
            ),
            (json!({}), "'name' is required"),
        ] {
            let (_, reply) = post_mcp(
                connection(Some(sandbox_principal("lead"))),
                &[],
                rpc(
                    "tools/call",
                    json!({"name": "delete", "arguments": arguments}),
                ),
            )
            .await;
            let result = &reply.unwrap()["result"];
            assert_eq!(result["structuredContent"]["error"], "invalid_argument");
            assert_eq!(result["structuredContent"]["message"], message);
        }
    }

    #[test]
    fn logs_keep_the_newest_lines_within_the_cap() {
        let line = |message: String| openshell_core::proto::SandboxLogLine {
            message,
            ..Default::default()
        };
        let small: Vec<_> = (0..3).map(|i| line(format!("line {i}"))).collect();
        let (kept, truncated) = newest_log_lines(&small);
        assert_eq!(kept.len(), 3);
        assert!(!truncated);

        // Three 30 KiB lines: only the newest two fit, the second-newest cut.
        let big: Vec<_> = (0..3)
            .map(|i| line(format!("{i}{}", "x".repeat(30 * 1024))))
            .collect();
        let (kept, truncated) = newest_log_lines(&big);
        assert!(truncated);
        assert_eq!(kept.len(), 3);
        assert!(
            kept.last().unwrap()["message"]
                .as_str()
                .unwrap()
                .starts_with('2')
        );
        let total: usize = kept
            .iter()
            .map(|l| l["message"].as_str().unwrap().len())
            .sum();
        assert!(total <= MAX_LOG_BYTES);

        // One line over the cap made of two-byte characters is cut on a
        // character boundary.
        let (kept, truncated) = newest_log_lines(&[line("é".repeat(MAX_LOG_BYTES))]);
        assert!(truncated);
        let message = kept[0]["message"].as_str().unwrap();
        assert!(message.len() <= MAX_LOG_BYTES && message.chars().all(|c| c == 'é'));
    }

    #[tokio::test]
    async fn logs_refuses_unknown_arguments() {
        for (arguments, message) in [
            (
                json!({"name": "w", "sources": ["gateway"]}),
                "unknown argument 'sources'",
            ),
            (
                json!({"name": "w", "lines": 2001}),
                "'lines' must be between 1 and 2000",
            ),
            (
                json!({"name": "w", "since": "yesterday"}),
                "'since' must be an RFC 3339 time",
            ),
        ] {
            let (_, reply) = post_mcp(
                connection(Some(sandbox_principal("lead"))),
                &[],
                rpc(
                    "tools/call",
                    json!({"name": "logs", "arguments": arguments}),
                ),
            )
            .await;
            let result = &reply.unwrap()["result"];
            assert_eq!(result["structuredContent"]["error"], "invalid_argument");
            assert_eq!(result["structuredContent"]["message"], message);
        }
    }

    #[test]
    fn internal_errors_do_not_reach_the_agent() {
        let ToolError::Refused(refusal) =
            ToolError::from_status(tonic::Status::internal("fetch parent sandbox failed: db"))
        else {
            panic!("an internal error is a tool error");
        };
        assert_eq!(refusal.code, "internal");
        // The request id is random hex, so check for the hidden text itself.
        assert!(
            !refusal.message.contains("fetch parent sandbox failed"),
            "{}",
            refusal.message
        );
        assert!(matches!(
            ToolError::from_status(tonic::Status::unauthenticated("expired")),
            ToolError::Unauthenticated
        ));
    }
}
