//! Interactive CLI agent for Navigator cluster operations.
//!
//! Runs a REPL loop that communicates with an LLM through the gateway's Chat
//! gRPC service and executes tools by shelling out to `nav` CLI commands.

use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, Result};
use navigator_core::proto::{
    ChatMessage, ChatStreamRequest, Tool, ToolCall, chat_stream_event::Event,
};
use owo_colors::OwoColorize;
use tokio_stream::StreamExt;

use crate::tls::{TlsOptions, grpc_chat_client};

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

struct ToolDef {
    name: &'static str,
    description: &'static str,
    parameters_schema: &'static str,
    /// Build CLI arguments from parsed JSON parameters.
    build_args: fn(&serde_json::Map<String, serde_json::Value>) -> Vec<String>,
}

fn tool_definitions() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "cluster_status",
            description: "Check the cluster health, connectivity, and version.",
            parameters_schema: r#"{"type":"object","properties":{}}"#,
            build_args: |_| vec!["cluster".into(), "status".into()],
        },
        ToolDef {
            name: "sandbox_list",
            description: "List all sandboxes in the cluster with their name, namespace, creation time, and phase.",
            parameters_schema: r#"{"type":"object","properties":{}}"#,
            build_args: |_| vec!["sandbox".into(), "list".into()],
        },
        ToolDef {
            name: "sandbox_get",
            description: "Get detailed information about a specific sandbox by name.",
            parameters_schema: r#"{"type":"object","properties":{"name":{"type":"string","description":"Sandbox name"}},"required":["name"]}"#,
            build_args: |args| {
                let mut v = vec!["sandbox".into(), "get".into()];
                if let Some(name) = args.get("name").and_then(|n| n.as_str()) {
                    v.push(name.to_string());
                }
                v
            },
        },
        ToolDef {
            name: "sandbox_create",
            description: "Create a new sandbox. Optionally specify a container image and/or a command to run.",
            parameters_schema: r#"{"type":"object","properties":{"name":{"type":"string","description":"Optional sandbox name"},"image":{"type":"string","description":"Container image (e.g. ubuntu:24.04, python:3.12-slim)"},"command":{"type":"string","description":"Command to run in the sandbox"}}}"#,
            build_args: |args| {
                let mut v = vec!["sandbox".into(), "create".into()];
                if let Some(name) = args.get("name").and_then(|n| n.as_str()) {
                    v.push("--name".into());
                    v.push(name.to_string());
                }
                if let Some(image) = args.get("image").and_then(|n| n.as_str()) {
                    v.push("--image".into());
                    v.push(image.to_string());
                }
                if let Some(cmd) = args.get("command").and_then(|n| n.as_str()) {
                    v.push("--keep".into());
                    v.push("--".into());
                    // Split command on whitespace for the trailing args.
                    for part in cmd.split_whitespace() {
                        v.push(part.to_string());
                    }
                }
                v
            },
        },
        ToolDef {
            name: "sandbox_delete",
            description: "Delete a sandbox by name.",
            parameters_schema: r#"{"type":"object","properties":{"name":{"type":"string","description":"Sandbox name"}},"required":["name"]}"#,
            build_args: |args| {
                let mut v = vec!["sandbox".into(), "delete".into()];
                if let Some(name) = args.get("name").and_then(|n| n.as_str()) {
                    v.push(name.to_string());
                }
                v
            },
        },
        ToolDef {
            name: "sandbox_logs",
            description: "View recent logs for a sandbox. Returns the latest log lines from the gateway and sandbox.",
            parameters_schema: r#"{"type":"object","properties":{"name":{"type":"string","description":"Sandbox name"},"lines":{"type":"integer","description":"Number of log lines to return (default: 50)"}},"required":["name"]}"#,
            build_args: |args| {
                let mut v = vec!["sandbox".into(), "logs".into()];
                if let Some(name) = args.get("name").and_then(|n| n.as_str()) {
                    v.push(name.to_string());
                }
                if let Some(lines) = args.get("lines").and_then(serde_json::Value::as_u64) {
                    v.push("-n".into());
                    v.push(lines.to_string());
                }
                v
            },
        },
        ToolDef {
            name: "provider_list",
            description: "List all configured providers in the cluster.",
            parameters_schema: r#"{"type":"object","properties":{}}"#,
            build_args: |_| vec!["provider".into(), "list".into()],
        },
        ToolDef {
            name: "provider_get",
            description: "Get details of a specific provider by name.",
            parameters_schema: r#"{"type":"object","properties":{"name":{"type":"string","description":"Provider name"}},"required":["name"]}"#,
            build_args: |args| {
                let mut v = vec!["provider".into(), "get".into()];
                if let Some(name) = args.get("name").and_then(|n| n.as_str()) {
                    v.push(name.to_string());
                }
                v
            },
        },
        ToolDef {
            name: "inference_route_list",
            description: "List all inference routes configured in the cluster.",
            parameters_schema: r#"{"type":"object","properties":{}}"#,
            build_args: |_| vec!["inference".into(), "list".into()],
        },
    ]
}

/// Convert tool definitions to proto Tool messages.
fn to_proto_tools(defs: &[ToolDef]) -> Vec<Tool> {
    defs.iter()
        .map(|d| Tool {
            name: d.name.to_string(),
            description: d.description.to_string(),
            parameters_schema: d.parameters_schema.to_string(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Binary resolution
// ---------------------------------------------------------------------------

/// Resolve the navigator CLI binary path.
///
/// Priority:
/// 1. `NAV_AGENT_CLI` environment variable (for dev — set to `nav`)
/// 2. `std::env::current_exe()` (the running binary itself)
fn resolve_cli_binary() -> Result<PathBuf> {
    if let Ok(override_path) = std::env::var("NAV_AGENT_CLI") {
        return Ok(PathBuf::from(override_path));
    }
    std::env::current_exe()
        .into_diagnostic()
        .map_err(|e| miette::miette!("failed to resolve navigator binary path: {e}"))
}

// ---------------------------------------------------------------------------
// Tool execution
// ---------------------------------------------------------------------------

/// Execute a tool call by shelling out to the navigator CLI.
async fn execute_tool(
    binary: &Path,
    cluster: &str,
    tool_defs: &[ToolDef],
    tool_call: &ToolCall,
) -> String {
    let Some(tool_def) = tool_defs.iter().find(|d| d.name == tool_call.name) else {
        return format!("Unknown tool: {}", tool_call.name);
    };

    let args_map: serde_json::Map<String, serde_json::Value> =
        match serde_json::from_str(&tool_call.arguments) {
            Ok(v) => v,
            Err(e) => return format!("Failed to parse tool arguments: {e}"),
        };

    let cli_args = (tool_def.build_args)(&args_map);

    eprintln!(
        "  {} {} {}",
        "tool:".dimmed(),
        tool_call.name.cyan(),
        cli_args.join(" ").dimmed(),
    );

    let result = tokio::process::Command::new(binary)
        .arg("--cluster")
        .arg(cluster)
        .args(&cli_args)
        .output()
        .await;

    match result {
        Ok(output) => {
            let mut text = String::from_utf8_lossy(&output.stdout).to_string();
            if !output.stderr.is_empty() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Skip empty stderr or lines that are just whitespace.
                let stderr_trimmed = stderr.trim();
                if !stderr_trimmed.is_empty() {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(stderr_trimmed);
                }
            }
            if !output.status.success() {
                let _ = write!(
                    text,
                    "\nCommand exited with code: {}",
                    output.status.code().unwrap_or(-1)
                );
            }
            if text.is_empty() {
                "Command completed successfully (no output).".to_string()
            } else {
                text
            }
        }
        Err(e) => format!("Failed to execute tool: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Default system prompt
// ---------------------------------------------------------------------------

const DEFAULT_SYSTEM_PROMPT: &str = "\
You are a Navigator cluster operations assistant. You help users manage and \
operate their Navigator cluster through available tools.

You have access to tools that interact with the Navigator cluster. Use them \
to answer questions about the cluster state, manage sandboxes, view logs, \
and inspect configuration.

When the user asks about the cluster, sandboxes, providers, or inference \
routes, use the appropriate tools to get current information rather than \
guessing. Be concise and direct in your responses.

If a tool call fails, explain the error to the user and suggest how to fix it.";

// ---------------------------------------------------------------------------
// Agent loop
// ---------------------------------------------------------------------------

/// Run the interactive agent REPL.
pub async fn run_agent(
    server: &str,
    cluster_name: &str,
    routing_hint: &str,
    system_prompt: Option<&str>,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_chat_client(server, tls).await?;
    let binary = resolve_cli_binary()?;
    let tool_defs = tool_definitions();
    let proto_tools = to_proto_tools(&tool_defs);

    let system_text = system_prompt.unwrap_or(DEFAULT_SYSTEM_PROMPT);

    let mut messages: Vec<ChatMessage> = vec![ChatMessage {
        role: "system".to_string(),
        content: system_text.to_string(),
        tool_calls: vec![],
        tool_call_id: String::new(),
    }];

    eprintln!(
        "{}\n",
        "Navigator Agent (type 'exit' or Ctrl-D to quit)"
            .cyan()
            .bold()
    );

    let mut rl = rustyline::DefaultEditor::new().into_diagnostic()?;

    loop {
        let input = match rl.readline("> ") {
            Ok(line) => line,
            Err(
                rustyline::error::ReadlineError::Interrupted | rustyline::error::ReadlineError::Eof,
            ) => {
                eprintln!("\n{}", "Goodbye.".dimmed());
                break;
            }
            Err(e) => return Err(miette::miette!("readline error: {e}")),
        };

        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "exit" || trimmed == "quit" {
            eprintln!("{}", "Goodbye.".dimmed());
            break;
        }

        let _ = rl.add_history_entry(trimmed);

        messages.push(ChatMessage {
            role: "user".to_string(),
            content: trimmed.to_string(),
            tool_calls: vec![],
            tool_call_id: String::new(),
        });

        // Tool-calling loop: keep calling the LLM until it responds without tool calls.
        loop {
            let request = ChatStreamRequest {
                messages: messages.clone(),
                tools: proto_tools.clone(),
                routing_hint: routing_hint.to_string(),
            };

            let response = client
                .chat_stream(request)
                .await
                .into_diagnostic()
                .map_err(|e| miette::miette!("chat stream failed: {e}"))?;

            let mut stream = response.into_inner();
            let mut final_message: Option<ChatMessage> = None;
            let mut had_content = false;

            while let Some(event) = stream.next().await {
                let event = event.into_diagnostic()?;
                match event.event {
                    Some(Event::ContentDelta(delta)) => {
                        print!("{}", delta.text);
                        std::io::stdout().flush().ok();
                        had_content = true;
                    }
                    Some(Event::Message(msg)) => {
                        final_message = Some(msg);
                    }
                    Some(Event::Error(e)) => {
                        eprintln!("\n{} {}", "Error:".red().bold(), e.message);
                        break;
                    }
                    None => {}
                }
            }

            if had_content {
                println!();
            }

            let Some(msg) = final_message else {
                break;
            };

            let has_tool_calls = !msg.tool_calls.is_empty();
            messages.push(msg.clone());

            if !has_tool_calls {
                break;
            }

            // Execute all tool calls and feed results back.
            for tc in &msg.tool_calls {
                let result = execute_tool(&binary, cluster_name, &tool_defs, tc).await;
                messages.push(ChatMessage {
                    role: "tool".to_string(),
                    content: result,
                    tool_calls: vec![],
                    tool_call_id: tc.id.clone(),
                });
            }

            // Continue the loop to send tool results back to the LLM.
        }

        println!();
    }

    Ok(())
}
