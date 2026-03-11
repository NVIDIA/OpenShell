// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod app;
mod event;
pub mod theme;
mod ui;

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{DisableMouseCapture, EnableMouseCapture, MouseEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use miette::{IntoDiagnostic, Result};
use navigator_core::proto::navigator_client::NavigatorClient;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::sync::mpsc;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use app::{App, Focus, GatewayEntry, LogLine, Screen};
use event::{Event, EventHandler};

/// Duration to show the splash screen before auto-dismissing.
const SPLASH_DURATION: Duration = Duration::from_secs(3);

/// Launch the OpenShell TUI.
///
/// `channel` must be a connected gRPC channel to the OpenShell gateway.
pub async fn run(channel: Channel, gateway_name: &str, endpoint: &str) -> Result<()> {
    let client = NavigatorClient::new(channel);
    let mut app = App::new(client, gateway_name.to_string(), endpoint.to_string());

    enable_raw_mode().into_diagnostic()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).into_diagnostic()?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).into_diagnostic()?;
    terminal.clear().into_diagnostic()?;

    let mut events = EventHandler::new(Duration::from_secs(2));

    refresh_gateway_list(&mut app);
    refresh_data(&mut app).await;

    while app.running {
        terminal
            .draw(|frame| ui::draw(frame, &mut app))
            .into_diagnostic()?;

        match events.next().await {
            Some(Event::Key(key)) => {
                app.handle_key(key);
                // Handle async actions triggered by key presses.
                if app.pending_gateway_switch.is_some() {
                    handle_gateway_switch(&mut app).await;
                }
                if app.pending_log_fetch {
                    app.pending_log_fetch = false;
                    spawn_log_stream(&mut app, events.sender());
                }
                if app.pending_sandbox_delete {
                    app.pending_sandbox_delete = false;
                    handle_sandbox_delete(&mut app).await;
                }
                if app.pending_create_sandbox {
                    app.pending_create_sandbox = false;
                    spawn_create_sandbox(&mut app, events.sender());
                    start_anim_ticker(&mut app, events.sender());
                }
                // --- Provider CRUD ---
                if app.pending_provider_create {
                    app.pending_provider_create = false;
                    spawn_create_provider(&app, events.sender());
                    start_anim_ticker(&mut app, events.sender());
                }
                if app.pending_provider_get {
                    app.pending_provider_get = false;
                    spawn_get_provider(&app, events.sender());
                }
                if app.pending_provider_update {
                    app.pending_provider_update = false;
                    spawn_update_provider(&app, events.sender());
                }
                if app.pending_provider_delete {
                    app.pending_provider_delete = false;
                    spawn_delete_provider(&app, events.sender());
                }
                if app.pending_sandbox_detail {
                    app.pending_sandbox_detail = false;
                    fetch_sandbox_detail(&mut app).await;
                }
                if app.pending_shell_connect {
                    app.pending_shell_connect = false;
                    handle_shell_connect(&mut app, &mut terminal, &events).await;
                    refresh_data(&mut app).await;
                }
                // --- Draft actions ---
                if app.pending_draft_approve {
                    app.pending_draft_approve = false;
                    spawn_draft_approve(&app, events.sender());
                }
                if app.pending_draft_reject {
                    app.pending_draft_reject = false;
                    spawn_draft_reject(&app, events.sender());
                }
                if app.pending_draft_approve_all {
                    app.pending_draft_approve_all = false;
                    spawn_draft_approve_all(&app, events.sender());
                }
            }
            Some(Event::LogLines(lines)) => {
                app.sandbox_log_lines.extend(lines);
                if app.log_autoscroll {
                    app.sandbox_log_scroll = app.log_autoscroll_offset();
                    // Pin cursor to the last visible line during autoscroll.
                    let filtered_len = app.filtered_log_lines().len();
                    let visible = filtered_len
                        .saturating_sub(app.sandbox_log_scroll)
                        .min(app.log_viewport_height);
                    app.log_cursor = visible.saturating_sub(1);
                }
            }
            Some(Event::CreateResult(result)) => {
                // Buffer the result — don't close yet. The Redraw handler
                // will finalize once MIN_CREATING_DISPLAY has elapsed.
                if let Some(form) = app.create_form.as_mut() {
                    form.create_result = Some(result);
                }
            }
            Some(Event::ProviderCreateResult(result)) => {
                // Buffer the result for min-display handling in Redraw.
                if let Some(form) = app.create_provider_form.as_mut() {
                    form.create_result = Some(result);
                }
            }
            Some(Event::ProviderDetailFetched(result)) => match result {
                Ok(provider) => {
                    let cred_key = provider
                        .credentials
                        .keys()
                        .next()
                        .cloned()
                        .unwrap_or_default();
                    let masked = if let Some(val) = provider.credentials.values().next() {
                        mask_secret(val)
                    } else {
                        "-".to_string()
                    };
                    app.provider_detail = Some(app::ProviderDetailView {
                        name: provider.name.clone(),
                        provider_type: provider.r#type.clone(),
                        credential_key: cred_key,
                        masked_value: masked,
                    });
                }
                Err(msg) => {
                    app.status_text = format!("get provider failed: {msg}");
                }
            },
            Some(Event::ProviderUpdateResult(result)) => match result {
                Ok(name) => {
                    app.update_provider_form = None;
                    app.status_text = format!("Updated provider: {name}");
                    refresh_providers(&mut app).await;
                }
                Err(msg) => {
                    if let Some(form) = app.update_provider_form.as_mut() {
                        form.status = Some(format!("Failed: {msg}"));
                    }
                }
            },
            Some(Event::ProviderDeleteResult(result)) => match result {
                Ok(true) => {
                    app.status_text = "Provider deleted.".to_string();
                    refresh_providers(&mut app).await;
                }
                Ok(false) => {
                    app.status_text = "Provider not found.".to_string();
                }
                Err(msg) => {
                    app.status_text = format!("delete provider failed: {msg}");
                }
            },
            Some(Event::DraftActionResult(result)) => {
                match result {
                    Ok(msg) => {
                        app.status_text = msg;
                    }
                    Err(msg) => {
                        app.status_text = format!("draft action failed: {msg}");
                    }
                }
                // Refresh draft chunks + counts immediately after any action.
                refresh_draft_chunks(&mut app).await;
                refresh_sandbox_draft_counts(&mut app).await;
            }
            Some(Event::Mouse(mouse)) => match mouse.kind {
                MouseEventKind::ScrollUp if app.focus == Focus::SandboxLogs => {
                    app.scroll_logs(-3);
                }
                MouseEventKind::ScrollDown if app.focus == Focus::SandboxLogs => {
                    app.scroll_logs(3);
                }
                MouseEventKind::ScrollUp if app.focus == Focus::SandboxPolicy => {
                    app.scroll_policy(-3);
                }
                MouseEventKind::ScrollDown if app.focus == Focus::SandboxPolicy => {
                    app.scroll_policy(3);
                }
                _ => {}
            },
            Some(Event::Tick) => {
                // Auto-dismiss splash after SPLASH_DURATION.
                if app.screen == Screen::Splash {
                    if let Some(start) = app.splash_start {
                        if start.elapsed() >= SPLASH_DURATION {
                            app.dismiss_splash();
                        }
                    }
                }

                refresh_gateway_list(&mut app);
                refresh_data(&mut app).await;

                // Refresh per-sandbox draft counts for badges (dashboard + detail).
                refresh_sandbox_draft_counts(&mut app).await;

                // Auto-refresh the policy view when a new version is detected.
                if app.screen == Screen::Sandbox {
                    let displayed = app.sandbox_policy.as_ref().map_or(0, |p| p.version);
                    let listed = app
                        .sandbox_policy_versions
                        .get(app.sandbox_selected)
                        .copied()
                        .unwrap_or(0);
                    if listed > 0 && listed != displayed {
                        refresh_sandbox_policy(&mut app).await;
                    }

                    // Refresh draft chunks when on sandbox screen.
                    refresh_draft_chunks(&mut app).await;
                }
            }
            Some(Event::Redraw) => {
                // Check if a buffered sandbox CreateResult is ready to finalize.
                if let Some(form) = app.create_form.as_ref() {
                    if form.create_result.is_some() {
                        let elapsed = form
                            .anim_start
                            .map_or(app::MIN_CREATING_DISPLAY, |s| s.elapsed());
                        if elapsed >= app::MIN_CREATING_DISPLAY {
                            let result = app
                                .create_form
                                .as_mut()
                                .and_then(|f| f.create_result.take());
                            if let Some(h) = app.anim_handle.take() {
                                h.abort();
                            }
                            match result {
                                Some(Ok(name)) => {
                                    app.create_form = None;
                                    let ports = std::mem::take(&mut app.pending_forward_ports);
                                    let command = std::mem::take(&mut app.pending_exec_command);
                                    let port_info = if ports.is_empty() {
                                        String::new()
                                    } else {
                                        let list = ports
                                            .iter()
                                            .map(|p| p.to_string())
                                            .collect::<Vec<_>>()
                                            .join(", ");
                                        format!(" (forwarding port(s) {list})")
                                    };
                                    app.status_text = format!("Created sandbox: {name}{port_info}");
                                    refresh_sandboxes(&mut app).await;

                                    // If a command was specified, suspend TUI and exec it.
                                    if !command.is_empty() {
                                        handle_exec_command(
                                            &mut app,
                                            &mut terminal,
                                            &events,
                                            &name,
                                            &command,
                                        )
                                        .await;
                                    }
                                }
                                Some(Err(msg)) => {
                                    if let Some(form) = app.create_form.as_mut() {
                                        form.phase = app::CreatePhase::Form;
                                        form.anim_start = None;
                                        form.status = Some(format!("Create failed: {msg}"));
                                    }
                                }
                                None => {}
                            }
                        }
                    }
                }
                // Check if a buffered provider CreateResult is ready to finalize.
                if let Some(form) = app.create_provider_form.as_ref() {
                    if form.create_result.is_some() {
                        let elapsed = form
                            .anim_start
                            .map_or(app::MIN_CREATING_DISPLAY, |s| s.elapsed());
                        if elapsed >= app::MIN_CREATING_DISPLAY {
                            let result = app
                                .create_provider_form
                                .as_mut()
                                .and_then(|f| f.create_result.take());
                            if let Some(h) = app.anim_handle.take() {
                                h.abort();
                            }
                            match result {
                                Some(Ok(name)) => {
                                    app.create_provider_form = None;
                                    app.status_text = format!("Created provider: {name}");
                                    refresh_providers(&mut app).await;
                                }
                                Some(Err(msg)) => {
                                    if let Some(form) = app.create_provider_form.as_mut() {
                                        form.phase = app::CreateProviderPhase::EnterKey;
                                        form.anim_start = None;
                                        form.status = Some(format!("Create failed: {msg}"));
                                    }
                                }
                                None => {}
                            }
                        }
                    }
                }
            }
            Some(Event::Resize(_, _)) => {} // ratatui handles resize on next draw
            None => break,
        }
    }

    // Cancel any running background tasks.
    app.cancel_log_stream();
    app.stop_anim();

    disable_raw_mode().into_diagnostic()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .into_diagnostic()?;
    terminal.show_cursor().into_diagnostic()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Gateway discovery and switching
// ---------------------------------------------------------------------------

/// Refresh the list of known gateways from disk.
fn refresh_gateway_list(app: &mut App) {
    if let Ok(gateways) = navigator_bootstrap::list_gateways() {
        app.gateways = gateways
            .into_iter()
            .map(|m| GatewayEntry {
                name: m.name,
                endpoint: m.gateway_endpoint,
                is_remote: m.is_remote,
            })
            .collect();

        // Keep selection in bounds.
        if app.gateway_selected >= app.gateways.len() && !app.gateways.is_empty() {
            app.gateway_selected = app.gateways.len() - 1;
        }

        // If the active gateway appears in the list, move cursor to it on first load.
        if let Some(idx) = app.gateways.iter().position(|g| g.name == app.gateway_name) {
            // Only snap the cursor when it's still at 0 (initial state).
            if app.gateway_selected == 0 {
                app.gateway_selected = idx;
            }
        }
    }
}

/// Handle a pending gateway switch requested by the user.
async fn handle_gateway_switch(app: &mut App) {
    let Some(name) = app.pending_gateway_switch.take() else {
        return;
    };

    // Look up the endpoint from the gateway list.
    let endpoint = match app.gateways.iter().find(|g| g.name == name) {
        Some(g) => g.endpoint.clone(),
        None => return,
    };

    match connect_to_gateway(&name, &endpoint).await {
        Ok(channel) => {
            app.client = NavigatorClient::new(channel);
            app.gateway_name = name;
            app.endpoint = endpoint;
            app.reset_sandbox_state();
            // Immediately refresh data for the new gateway.
            refresh_data(app).await;
        }
        Err(e) => {
            app.status_text = format!("switch failed: {e}");
        }
    }
}

/// Build a gRPC channel to a gateway using its mTLS certs on disk.
async fn connect_to_gateway(name: &str, endpoint: &str) -> Result<Channel> {
    let mtls_dir = gateway_mtls_dir(name)
        .ok_or_else(|| miette::miette!("cannot determine config directory for gateway {name}"))?;

    let ca = std::fs::read(mtls_dir.join("ca.crt"))
        .into_diagnostic()
        .map_err(|_| miette::miette!("missing CA cert for gateway {name}"))?;
    let cert = std::fs::read(mtls_dir.join("tls.crt"))
        .into_diagnostic()
        .map_err(|_| miette::miette!("missing client cert for gateway {name}"))?;
    let key = std::fs::read(mtls_dir.join("tls.key"))
        .into_diagnostic()
        .map_err(|_| miette::miette!("missing client key for gateway {name}"))?;

    let tls_config = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(cert, key));

    let channel = Endpoint::from_shared(endpoint.to_string())
        .into_diagnostic()?
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .tls_config(tls_config)
        .into_diagnostic()?
        .connect()
        .await
        .into_diagnostic()?;

    Ok(channel)
}

/// Resolve the mTLS cert directory for a gateway.
fn gateway_mtls_dir(name: &str) -> Option<PathBuf> {
    let config_dir = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok()?;
    Some(
        config_dir
            .join("openshell")
            .join("gateways")
            .join(name)
            .join("mtls"),
    )
}

// ---------------------------------------------------------------------------
// Sandbox actions
// ---------------------------------------------------------------------------

/// Spawn a background task that streams logs for the currently selected sandbox.
///
/// Uses `WatchSandbox` with `follow_logs: true` for live streaming. Initial
/// history is fetched via `GetSandboxLogs`, then live events are appended.
fn spawn_log_stream(app: &mut App, tx: mpsc::UnboundedSender<Event>) {
    // Cancel any previous stream.
    app.cancel_log_stream();

    let sandbox_id = match app.selected_sandbox_id() {
        Some(id) => id.to_string(),
        None => return,
    };

    let mut client = app.client.clone();

    let handle = tokio::spawn(async move {
        // Phase 1: Fetch initial history via unary RPC.
        let req = navigator_core::proto::GetSandboxLogsRequest {
            sandbox_id: sandbox_id.clone(),
            lines: 500,
            since_ms: 0,
            sources: vec![],
            min_level: String::new(),
        };

        match tokio::time::timeout(Duration::from_secs(5), client.get_sandbox_logs(req)).await {
            Ok(Ok(resp)) => {
                let logs = resp.into_inner().logs;
                let lines: Vec<LogLine> = logs.into_iter().map(proto_to_log_line).collect();
                if !lines.is_empty() {
                    let _ = tx.send(Event::LogLines(lines));
                }
            }
            Ok(Err(e)) => {
                let _ = tx.send(Event::LogLines(vec![LogLine {
                    timestamp_ms: 0,
                    level: "ERROR".into(),
                    source: String::new(),
                    target: String::new(),
                    message: format!("Failed to fetch logs: {}", e.message()),
                    fields: Default::default(),
                }]));
                return;
            }
            Err(_) => {
                let _ = tx.send(Event::LogLines(vec![LogLine {
                    timestamp_ms: 0,
                    level: "ERROR".into(),
                    source: String::new(),
                    target: String::new(),
                    message: "Timed out fetching logs.".into(),
                    fields: Default::default(),
                }]));
                return;
            }
        }

        // Phase 2: Stream live logs via WatchSandbox.
        let req = navigator_core::proto::WatchSandboxRequest {
            id: sandbox_id,
            follow_status: false,
            follow_logs: true,
            follow_events: false,
            log_tail_lines: 0, // Don't re-fetch tail, we already have history.
            ..Default::default()
        };

        let resp =
            match tokio::time::timeout(Duration::from_secs(5), client.watch_sandbox(req)).await {
                Ok(Ok(r)) => r,
                Ok(Err(_)) | Err(_) => return, // Silently stop — user can re-enter logs.
            };

        let mut stream = resp.into_inner();
        loop {
            match stream.message().await {
                Ok(Some(event)) => {
                    if let Some(navigator_core::proto::sandbox_stream_event::Payload::Log(log)) =
                        event.payload
                    {
                        let line = proto_to_log_line(log);
                        let _ = tx.send(Event::LogLines(vec![line]));
                    }
                }
                _ => break, // Stream ended or error.
            }
        }
    });

    app.log_stream_handle = Some(handle);
}

/// Convert a proto `SandboxLogLine` to our display `LogLine`.
fn proto_to_log_line(log: navigator_core::proto::SandboxLogLine) -> LogLine {
    let source = if log.source.is_empty() {
        "gateway".to_string()
    } else {
        log.source
    };
    LogLine {
        timestamp_ms: log.timestamp_ms,
        level: log.level,
        source,
        target: log.target,
        message: log.message,
        fields: log.fields,
    }
}

/// Delete the currently selected sandbox.
async fn handle_sandbox_delete(app: &mut App) {
    let sandbox_name = match app.selected_sandbox_name() {
        Some(n) => n.to_string(),
        None => return,
    };

    // Stop any active port forwards before deleting (mirrors CLI behavior).
    if let Ok(stopped) = navigator_core::forward::stop_forwards_for_sandbox(&sandbox_name) {
        for port in &stopped {
            tracing::info!("stopped forward of port {port} for sandbox {sandbox_name}");
        }
    }

    let req = navigator_core::proto::DeleteSandboxRequest { name: sandbox_name };
    match app.client.delete_sandbox(req).await {
        Ok(_) => {
            app.cancel_log_stream();
            app.screen = Screen::Dashboard;
            app.focus = Focus::Sandboxes;
            refresh_sandboxes(app).await;
        }
        Err(e) => {
            app.status_text = format!("delete failed: {}", e.message());
            app.screen = Screen::Dashboard;
            app.focus = Focus::Sandboxes;
        }
    }
}

// ---------------------------------------------------------------------------
// Sandbox detail + policy rendering
// ---------------------------------------------------------------------------

/// Fetch sandbox details (policy + providers) when entering the sandbox screen.
///
/// Uses `GetSandbox` for metadata/providers, then `GetSandboxPolicy` for the
/// current live policy (which may have been updated since creation).
async fn fetch_sandbox_detail(app: &mut App) {
    let sandbox_name = match app.selected_sandbox_name() {
        Some(n) => n.to_string(),
        None => return,
    };

    let req = navigator_core::proto::GetSandboxRequest {
        name: sandbox_name.clone(),
    };

    // Step 1: Fetch sandbox metadata (providers, sandbox ID).
    let sandbox_id =
        match tokio::time::timeout(Duration::from_secs(5), app.client.get_sandbox(req)).await {
            Ok(Ok(resp)) => {
                if let Some(sandbox) = resp.into_inner().sandbox {
                    if let Some(spec) = &sandbox.spec {
                        app.sandbox_providers_list = spec.providers.clone();
                    }
                    if sandbox.id.is_empty() {
                        None
                    } else {
                        Some(sandbox.id)
                    }
                } else {
                    None
                }
            }
            Ok(Err(e)) => {
                tracing::warn!("failed to fetch sandbox detail: {}", e.message());
                None
            }
            Err(_) => {
                tracing::warn!("sandbox detail request timed out");
                None
            }
        };

    // Step 2: Fetch the current live policy (includes updates since creation).
    if let Some(id) = sandbox_id {
        let policy_req = navigator_core::proto::GetSandboxPolicyRequest { sandbox_id: id };

        match tokio::time::timeout(
            Duration::from_secs(5),
            app.client.get_sandbox_policy(policy_req),
        )
        .await
        {
            Ok(Ok(resp)) => {
                let inner = resp.into_inner();
                if let Some(mut policy) = inner.policy {
                    // Use the version from the policy history, not from the
                    // policy proto's own version field (which is always 1).
                    policy.version = inner.version;
                    app.policy_lines = render_policy_lines(&policy);
                    app.sandbox_policy = Some(policy);
                }
            }
            Ok(Err(e)) => {
                let msg = e.message().to_string();
                tracing::warn!("failed to fetch sandbox policy: {msg}");
            }
            Err(_) => {
                tracing::warn!("sandbox policy request timed out");
            }
        }
    }

    app.policy_scroll = 0;
}

// ---------------------------------------------------------------------------
// Shell connect (suspend TUI, launch SSH, resume)
// ---------------------------------------------------------------------------

/// Suspend the TUI, launch an interactive SSH shell to the sandbox, resume on exit.
///
/// This replicates the `openshell sandbox connect` flow but uses `Command::status()`
/// instead of `exec()` so the TUI process survives.
async fn handle_shell_connect(
    app: &mut App,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    events: &EventHandler,
) {
    let sandbox_name = match app.selected_sandbox_name() {
        Some(n) => n.to_string(),
        None => return,
    };

    // Step 1: Get sandbox ID.
    let sandbox_id = {
        let req = navigator_core::proto::GetSandboxRequest {
            name: sandbox_name.clone(),
        };
        match tokio::time::timeout(Duration::from_secs(5), app.client.get_sandbox(req)).await {
            Ok(Ok(resp)) => match resp.into_inner().sandbox {
                Some(s) => s.id,
                None => {
                    app.status_text = "sandbox not found".to_string();
                    return;
                }
            },
            Ok(Err(e)) => {
                app.status_text = format!("failed to get sandbox: {}", e.message());
                return;
            }
            Err(_) => {
                app.status_text = "get sandbox timed out".to_string();
                return;
            }
        }
    };

    // Step 2: Create SSH session.
    let session = {
        let req = navigator_core::proto::CreateSshSessionRequest {
            sandbox_id: sandbox_id.clone(),
        };
        match tokio::time::timeout(Duration::from_secs(5), app.client.create_ssh_session(req)).await
        {
            Ok(Ok(resp)) => resp.into_inner(),
            Ok(Err(e)) => {
                app.status_text = format!("SSH session failed: {}", e.message());
                return;
            }
            Err(_) => {
                app.status_text = "SSH session request timed out".to_string();
                return;
            }
        }
    };

    // Step 3: Resolve gateway address (handle loopback override).
    #[allow(clippy::cast_possible_truncation)]
    let gateway_port_u16 = session.gateway_port as u16;
    let (gateway_host, gateway_port) =
        resolve_ssh_gateway(&session.gateway_host, gateway_port_u16, &app.endpoint);
    let gateway_url = format!(
        "{}://{}:{gateway_port}{}",
        session.gateway_scheme, gateway_host, session.connect_path
    );

    // Step 4: Build the ProxyCommand using our own binary.
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            app.status_text = format!("failed to find executable: {e}");
            return;
        }
    };
    let exe_str = shell_escape(&exe.to_string_lossy());
    let gateway = shell_escape(&app.gateway_name);
    let proxy_command = format!(
        "{exe_str} ssh-proxy --gateway-endpoint {gateway_url} --sandbox-id {} --token {} --gateway-name {gateway}",
        session.sandbox_id, session.token,
    );
    // Step 5: Build the SSH command.
    let mut command = std::process::Command::new("ssh");
    command
        .arg("-o")
        .arg(format!("ProxyCommand={proxy_command}"))
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("-tt")
        .arg("-o")
        .arg("RequestTTY=force")
        .arg("-o")
        .arg("SetEnv=TERM=xterm-256color")
        .arg("sandbox")
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    // Step 6: Cancel log stream and pause event handler before suspending.
    app.cancel_log_stream();
    events.pause();
    // Wait for the reader task to finish its current poll cycle (tick_rate = 2s max).
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Step 7: Suspend TUI — leave alternate screen, disable raw mode.
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let _ = disable_raw_mode();

    // Step 8: Spawn SSH as child process and wait.
    let status = tokio::task::spawn_blocking(move || command.status()).await;
    match &status {
        Ok(Ok(s)) if !s.success() => {
            app.status_text = format!("ssh exited with status {s}");
        }
        Ok(Err(e)) => {
            app.status_text = format!("failed to launch ssh: {e}");
        }
        Err(e) => {
            app.status_text = format!("shell task failed: {e}");
        }
        _ => {
            app.status_text = format!("Disconnected from {sandbox_name}");
        }
    }

    // Step 9: Resume TUI — re-enter alternate screen, enable raw mode, unpause events.
    let _ = enable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        EnterAlternateScreen,
        EnableMouseCapture
    );
    let _ = terminal.clear();
    events.resume();
}

/// Suspend the TUI, execute a command on a sandbox via SSH, then resume.
///
/// Mirrors `handle_shell_connect` but passes the user's command to SSH
/// instead of opening an interactive shell.  The TUI is suspended while
/// the command runs; press Ctrl-C to stop and return to the TUI.
async fn handle_exec_command(
    app: &mut App,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    events: &EventHandler,
    sandbox_name: &str,
    command: &str,
) {
    // Step 1: Resolve sandbox → SSH session (same as handle_shell_connect).
    let sandbox_id = {
        let req = navigator_core::proto::GetSandboxRequest {
            name: sandbox_name.to_string(),
        };
        match tokio::time::timeout(Duration::from_secs(5), app.client.get_sandbox(req)).await {
            Ok(Ok(resp)) => match resp.into_inner().sandbox {
                Some(s) => s.id,
                None => {
                    app.status_text = format!("exec: sandbox {sandbox_name} not found");
                    return;
                }
            },
            Ok(Err(e)) => {
                app.status_text = format!("exec: failed to get sandbox: {}", e.message());
                return;
            }
            Err(_) => {
                app.status_text = "exec: get sandbox timed out".to_string();
                return;
            }
        }
    };

    let session = {
        let req = navigator_core::proto::CreateSshSessionRequest {
            sandbox_id: sandbox_id.clone(),
        };
        match tokio::time::timeout(Duration::from_secs(5), app.client.create_ssh_session(req)).await
        {
            Ok(Ok(resp)) => resp.into_inner(),
            Ok(Err(e)) => {
                app.status_text = format!("exec: SSH session failed: {}", e.message());
                return;
            }
            Err(_) => {
                app.status_text = "exec: SSH session timed out".to_string();
                return;
            }
        }
    };

    // Step 2: Resolve gateway and build ProxyCommand (same as handle_shell_connect).
    #[allow(clippy::cast_possible_truncation)]
    let gateway_port_u16 = session.gateway_port as u16;
    let (gateway_host, gateway_port) =
        resolve_ssh_gateway(&session.gateway_host, gateway_port_u16, &app.endpoint);
    let gateway_url = format!(
        "{}://{}:{gateway_port}{}",
        session.gateway_scheme, gateway_host, session.connect_path
    );

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            app.status_text = format!("exec: failed to find executable: {e}");
            return;
        }
    };
    let exe_str = shell_escape(&exe.to_string_lossy());
    let gateway = shell_escape(&app.gateway_name);
    let proxy_command = format!(
        "{exe_str} ssh-proxy --gateway-endpoint {gateway_url} --sandbox-id {} --token {} --gateway-name {gateway}",
        session.sandbox_id, session.token,
    );

    // Step 3: Build SSH command — same flags as handle_shell_connect but with
    // the user's command appended.  Each word is escaped individually so the
    // remote shell parses it correctly.
    let command_str = command
        .split_whitespace()
        .map(|word| shell_escape(word))
        .collect::<Vec<_>>()
        .join(" ");
    let mut ssh = std::process::Command::new("ssh");
    ssh.arg("-o")
        .arg(format!("ProxyCommand={proxy_command}"))
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("-tt")
        .arg("-o")
        .arg("RequestTTY=force")
        .arg("-o")
        .arg("SetEnv=TERM=xterm-256color")
        .arg("sandbox")
        .arg(command_str)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    // Step 4: Suspend TUI.
    app.cancel_log_stream();
    events.pause();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let _ = disable_raw_mode();

    // Step 5: Run command — blocks until user Ctrl-C's or command exits.
    let status = tokio::task::spawn_blocking(move || ssh.status()).await;
    match &status {
        Ok(Ok(s)) if !s.success() => {
            app.status_text = format!("command exited with status {s}");
        }
        Ok(Err(e)) => {
            app.status_text = format!("failed to launch command: {e}");
        }
        Err(e) => {
            app.status_text = format!("exec task failed: {e}");
        }
        _ => {
            app.status_text = format!("Command finished on {sandbox_name}");
        }
    }

    // Step 6: Resume TUI.
    let _ = enable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        EnterAlternateScreen,
        EnableMouseCapture
    );
    let _ = terminal.clear();
    events.resume();
}

// SSH utility functions are shared via navigator_core::forward.
use navigator_core::forward::{resolve_ssh_gateway, shell_escape};

/// Convert a `SandboxPolicy` proto into styled ratatui lines for the policy viewer.
fn render_policy_lines(
    policy: &navigator_core::proto::SandboxPolicy,
) -> Vec<ratatui::text::Line<'static>> {
    use crate::theme::styles;
    use ratatui::text::{Line, Span};

    let mut lines: Vec<Line<'static>> = Vec::new();

    // --- Filesystem Access ---
    if let Some(fs) = &policy.filesystem {
        lines.push(Line::from(Span::styled(
            "Filesystem Access",
            styles::HEADING,
        )));

        if !fs.read_only.is_empty() {
            let paths = fs.read_only.join(", ");
            lines.push(Line::from(vec![
                Span::styled("  Read-only:  ", styles::MUTED),
                Span::styled(paths, styles::TEXT),
            ]));
        }

        if !fs.read_write.is_empty() {
            let paths = fs.read_write.join(", ");
            lines.push(Line::from(vec![
                Span::styled("  Read-write: ", styles::MUTED),
                Span::styled(paths, styles::TEXT),
            ]));
        }

        lines.push(Line::from(""));
    }

    // --- Network Rules ---
    if !policy.network_policies.is_empty() {
        // Sort keys for deterministic display.
        let mut rule_names: Vec<&String> = policy.network_policies.keys().collect();
        rule_names.sort();

        let header = format!("Network Rules ({})", rule_names.len());
        lines.push(Line::from(Span::styled(header, styles::HEADING)));
        lines.push(Line::from(""));

        for name in rule_names {
            let Some(rule) = policy.network_policies.get(name) else {
                continue;
            };

            // Skip rules with no endpoints (useless policies).
            if rule.endpoints.is_empty() {
                continue;
            }

            // Rule header — include L7/TLS/allowed_ips annotation if any endpoint has it.
            let has_l7 = rule.endpoints.iter().any(|e| !e.protocol.is_empty());
            let has_tls_term = rule.endpoints.iter().any(|e| e.tls == "terminate");
            let has_allowed_ips = rule.endpoints.iter().any(|e| !e.allowed_ips.is_empty());
            let mut annotations = Vec::new();
            if has_l7 {
                // Use the first L7 endpoint's protocol for the label.
                if let Some(proto) = rule
                    .endpoints
                    .iter()
                    .find(|e| !e.protocol.is_empty())
                    .map(|e| e.protocol.to_uppercase())
                {
                    annotations.push(format!("L7 {proto}"));
                }
            }
            if has_tls_term {
                annotations.push("TLS terminate".to_string());
            }
            if has_allowed_ips {
                annotations.push("private IP".to_string());
            }

            let title = if annotations.is_empty() {
                format!("  {name}")
            } else {
                format!("  {name} ({})", annotations.join(", "))
            };
            lines.push(Line::from(Span::styled(title, styles::ACCENT)));

            // Endpoints.
            for ep in &rule.endpoints {
                // Render address: host:port, *:port (hostless), host, or *
                let addr = if !ep.host.is_empty() && ep.port > 0 {
                    format!("    {}:{}", ep.host, ep.port)
                } else if !ep.host.is_empty() {
                    format!("    {}", ep.host)
                } else if ep.port > 0 {
                    format!("    *:{}", ep.port)
                } else {
                    "    *".to_string()
                };
                lines.push(Line::from(Span::styled(addr, styles::TEXT)));

                // Allowed IPs (CIDR allowlist for private IP access).
                if !ep.allowed_ips.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("      Allowed IPs: ", styles::MUTED),
                        Span::styled(ep.allowed_ips.join(", "), styles::TEXT),
                    ]));
                }

                // L7 allow rules.
                for l7 in &ep.rules {
                    if let Some(allow) = &l7.allow {
                        let method = if allow.method.is_empty() {
                            "*"
                        } else {
                            &allow.method
                        };
                        let target = if !allow.path.is_empty() {
                            &allow.path
                        } else if !allow.command.is_empty() {
                            &allow.command
                        } else {
                            "*"
                        };
                        lines.push(Line::from(vec![
                            Span::styled("      Allow: ", styles::MUTED),
                            Span::styled(format!("{:<6} {}", method, target), styles::TEXT),
                        ]));
                    }
                }

                // Access preset (if set instead of explicit rules).
                if !ep.access.is_empty() && ep.rules.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("      Access: ", styles::MUTED),
                        Span::styled(ep.access.clone(), styles::TEXT),
                    ]));
                }
            }

            // Binaries.
            let binary_paths: Vec<&str> = rule.binaries.iter().map(|b| b.path.as_str()).collect();
            if !binary_paths.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("    Binaries: ", styles::MUTED),
                    Span::styled(binary_paths.join(", "), styles::TEXT),
                ]));
            }

            lines.push(Line::from(""));
        }
    }

    // If nothing was rendered, add a placeholder.
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "No policy data available.",
            styles::MUTED,
        )));
    }

    lines
}

// ---------------------------------------------------------------------------
// Animation helper
// ---------------------------------------------------------------------------

/// Spawn a fast animation ticker (~7 fps) and store the handle on the app.
fn start_anim_ticker(app: &mut App, tx: mpsc::UnboundedSender<Event>) {
    let anim_tx = tx;
    app.anim_handle = Some(tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(140)).await;
            if anim_tx.send(Event::Redraw).is_err() {
                break;
            }
        }
    }));
}

// ---------------------------------------------------------------------------
// Create sandbox (simplified — uses pre-selected provider names)
// ---------------------------------------------------------------------------

fn spawn_create_sandbox(app: &mut App, tx: mpsc::UnboundedSender<Event>) {
    let mut client = app.client.clone();
    let Some((name, image, command, selected_providers, ports)) = app.create_form_data() else {
        return;
    };

    // Stash command so we can exec after sandbox creation + Ready.
    app.pending_exec_command = command;
    // Stash ports so we can include them in the status text.
    app.pending_forward_ports = ports.clone();

    let endpoint = app.endpoint.clone();
    let gateway_name = app.gateway_name.clone();
    let need_ready = !ports.is_empty() || !app.pending_exec_command.is_empty();

    tokio::spawn(async move {
        let has_custom_image = !image.is_empty();
        let template = if has_custom_image {
            Some(navigator_core::proto::SandboxTemplate {
                image,
                ..Default::default()
            })
        } else {
            None
        };

        // For custom images, provide a restrictive default policy so the
        // server has a baseline. The server ensures process identity is set
        // to "sandbox". For the default image, let the server apply the
        // sandbox's own default policy.
        let policy = if has_custom_image {
            Some(navigator_policy::restrictive_default_policy())
        } else {
            None
        };

        let req = navigator_core::proto::CreateSandboxRequest {
            name,
            spec: Some(navigator_core::proto::SandboxSpec {
                providers: selected_providers,
                template,
                policy,
                ..Default::default()
            }),
        };

        let sandbox_name =
            match tokio::time::timeout(Duration::from_secs(30), client.create_sandbox(req)).await {
                Ok(Ok(resp)) => resp
                    .into_inner()
                    .sandbox
                    .map_or_else(|| "unknown".to_string(), |s| s.name),
                Ok(Err(e)) => {
                    let _ = tx.send(Event::CreateResult(Err(e.message().to_string())));
                    return;
                }
                Err(_) => {
                    let _ = tx.send(Event::CreateResult(Err("request timed out".to_string())));
                    return;
                }
            };

        // If ports or command are set, wait for Ready before finishing.
        if need_ready {
            let mut attempts = 0;
            let sandbox_id = loop {
                attempts += 1;
                if attempts > 60 {
                    let _ = tx.send(Event::CreateResult(Err(
                        "timed out waiting for sandbox to be ready".to_string(),
                    )));
                    return;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;

                let req = navigator_core::proto::GetSandboxRequest {
                    name: sandbox_name.clone(),
                };
                match client.get_sandbox(req).await {
                    Ok(resp) => {
                        if let Some(sandbox) = resp.into_inner().sandbox {
                            if sandbox.phase == 2 {
                                break sandbox.id;
                            }
                            if sandbox.phase == 3 {
                                let _ = tx.send(Event::CreateResult(Err(
                                    "sandbox entered error state".to_string(),
                                )));
                                return;
                            }
                        }
                    }
                    Err(_) => {} // Retry on transient errors.
                }
            };

            // Start port forwards if requested.
            if !ports.is_empty() {
                start_port_forwards(
                    &mut client,
                    &endpoint,
                    &gateway_name,
                    &sandbox_name,
                    &sandbox_id,
                    &ports,
                )
                .await;
            }
        }

        let _ = tx.send(Event::CreateResult(Ok(sandbox_name)));
    });
}

/// Start SSH port forwards for a sandbox that is already Ready.
///
/// This is called from within the create-sandbox task so the pacman animation
/// keeps running while forwards are being established.
async fn start_port_forwards(
    client: &mut NavigatorClient<Channel>,
    endpoint: &str,
    gateway_name: &str,
    sandbox_name: &str,
    sandbox_id: &str,
    ports: &[u16],
) {
    // Create SSH session.
    let session = {
        let req = navigator_core::proto::CreateSshSessionRequest {
            sandbox_id: sandbox_id.to_string(),
        };
        match tokio::time::timeout(Duration::from_secs(10), client.create_ssh_session(req)).await {
            Ok(Ok(resp)) => resp.into_inner(),
            Ok(Err(e)) => {
                tracing::warn!("SSH session failed for forwards: {}", e.message());
                return;
            }
            Err(_) => {
                tracing::warn!("SSH session timed out for forwards");
                return;
            }
        }
    };

    // Resolve gateway address.
    #[allow(clippy::cast_possible_truncation)]
    let gateway_port_u16 = session.gateway_port as u16;
    let (gateway_host, gateway_port) =
        resolve_ssh_gateway(&session.gateway_host, gateway_port_u16, endpoint);
    let gateway_url = format!(
        "{}://{}:{gateway_port}{}",
        session.gateway_scheme, gateway_host, session.connect_path
    );

    // Build ProxyCommand.
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("failed to find executable for forwards: {e}");
            return;
        }
    };
    let exe_str = shell_escape(&exe.to_string_lossy());
    let gateway = shell_escape(gateway_name);
    let proxy_command = format!(
        "{exe_str} ssh-proxy --gateway-endpoint {gateway_url} --sandbox-id {} --token {} --gateway-name {gateway}",
        session.sandbox_id, session.token,
    );

    // Start a forward for each port.
    for port in ports {
        let mut command = std::process::Command::new("ssh");
        command
            .arg("-o")
            .arg(format!("ProxyCommand={proxy_command}"))
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("-o")
            .arg("GlobalKnownHostsFile=/dev/null")
            .arg("-o")
            .arg("LogLevel=ERROR")
            .arg("-o")
            .arg("ConnectTimeout=15")
            .arg("-N")
            .arg("-f")
            .arg("-L")
            .arg(format!("{port}:127.0.0.1:{port}"))
            .arg("sandbox")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        let port_val = *port;
        let sid = session.sandbox_id.clone();
        let name = sandbox_name.to_string();

        // Use spawn (not status) so we don't block if SSH hangs during auth.
        // SSH with -f forks to background after auth, but if auth stalls the
        // parent process blocks indefinitely.  We use spawn + wait_with_timeout
        // to avoid freezing the create flow.
        let result = tokio::task::spawn_blocking(move || {
            match command.spawn() {
                Ok(mut child) => {
                    // Wait up to 20 seconds for SSH to authenticate and fork.
                    let deadline = std::time::Instant::now() + Duration::from_secs(20);
                    loop {
                        match child.try_wait() {
                            Ok(Some(status)) => return Ok(status.success()),
                            Ok(None) => {
                                if std::time::Instant::now() >= deadline {
                                    let _ = child.kill();
                                    return Err("timed out".to_string());
                                }
                                std::thread::sleep(Duration::from_millis(200));
                            }
                            Err(e) => return Err(e.to_string()),
                        }
                    }
                }
                Err(e) => Err(e.to_string()),
            }
        })
        .await;

        match result {
            Ok(Ok(true)) => {
                if let Some(pid) = navigator_core::forward::find_ssh_forward_pid(&sid, port_val) {
                    let _ = navigator_core::forward::write_forward_pid(&name, port_val, pid, &sid);
                }
            }
            Ok(Ok(false)) => {
                tracing::warn!("SSH forward exited with error for port {port_val}");
            }
            Ok(Err(e)) => {
                tracing::warn!("forward failed for port {port_val}: {e}");
            }
            Err(e) => {
                tracing::warn!("forward task panicked for port {port_val}: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Provider CRUD
// ---------------------------------------------------------------------------

/// Create a provider on the gateway.
fn spawn_create_provider(app: &App, tx: mpsc::UnboundedSender<Event>) {
    let mut client = app.client.clone();
    let Some(form) = &app.create_provider_form else {
        return;
    };

    let ptype = form
        .types
        .get(form.type_cursor)
        .cloned()
        .unwrap_or_default();
    let name = if form.name.is_empty() {
        ptype.clone()
    } else {
        form.name.clone()
    };
    let credentials = form.discovered_credentials.clone().unwrap_or_default();

    tokio::spawn(async move {
        // Try with the chosen name, retry with suffix on collision.
        for attempt in 0..5u32 {
            let provider_name = if attempt == 0 {
                name.clone()
            } else {
                format!("{name}-{attempt}")
            };

            let req = navigator_core::proto::CreateProviderRequest {
                provider: Some(navigator_core::proto::Provider {
                    id: String::new(),
                    name: provider_name.clone(),
                    r#type: ptype.clone(),
                    credentials: credentials.clone(),
                    config: Default::default(),
                }),
            };

            match client.create_provider(req).await {
                Ok(resp) => {
                    let final_name = resp.into_inner().provider.map_or(provider_name, |p| p.name);
                    let _ = tx.send(Event::ProviderCreateResult(Ok(final_name)));
                    return;
                }
                Err(status) if status.code() == tonic::Code::AlreadyExists => {
                    // Retry with a different name.
                }
                Err(e) => {
                    let _ = tx.send(Event::ProviderCreateResult(Err(e.message().to_string())));
                    return;
                }
            }
        }
        let _ = tx.send(Event::ProviderCreateResult(Err(
            "name collision after 5 attempts".to_string(),
        )));
    });
}

/// Fetch a single provider's details.
fn spawn_get_provider(app: &App, tx: mpsc::UnboundedSender<Event>) {
    let mut client = app.client.clone();
    let name = match app.selected_provider_name() {
        Some(n) => n.to_string(),
        None => return,
    };

    tokio::spawn(async move {
        let req = navigator_core::proto::GetProviderRequest { name };
        match tokio::time::timeout(Duration::from_secs(5), client.get_provider(req)).await {
            Ok(Ok(resp)) => {
                if let Some(provider) = resp.into_inner().provider {
                    let _ = tx.send(Event::ProviderDetailFetched(Ok(Box::new(provider))));
                } else {
                    let _ = tx.send(Event::ProviderDetailFetched(Err(
                        "provider not found in response".to_string(),
                    )));
                }
            }
            Ok(Err(e)) => {
                let _ = tx.send(Event::ProviderDetailFetched(Err(e.message().to_string())));
            }
            Err(_) => {
                let _ = tx.send(Event::ProviderDetailFetched(Err(
                    "request timed out".to_string()
                )));
            }
        }
    });
}

/// Update a provider's credentials.
fn spawn_update_provider(app: &App, tx: mpsc::UnboundedSender<Event>) {
    let mut client = app.client.clone();
    let Some(form) = &app.update_provider_form else {
        return;
    };

    let name = form.provider_name.clone();
    let ptype = form.provider_type.clone();
    let cred_key = form.credential_key.clone();
    let new_value = form.new_value.clone();

    tokio::spawn(async move {
        let mut credentials = std::collections::HashMap::new();
        credentials.insert(cred_key, new_value);

        let req = navigator_core::proto::UpdateProviderRequest {
            provider: Some(navigator_core::proto::Provider {
                id: String::new(),
                name: name.clone(),
                r#type: ptype,
                credentials,
                config: Default::default(),
            }),
        };

        match tokio::time::timeout(Duration::from_secs(5), client.update_provider(req)).await {
            Ok(Ok(_)) => {
                let _ = tx.send(Event::ProviderUpdateResult(Ok(name)));
            }
            Ok(Err(e)) => {
                let _ = tx.send(Event::ProviderUpdateResult(Err(e.message().to_string())));
            }
            Err(_) => {
                let _ = tx.send(Event::ProviderUpdateResult(Err(
                    "request timed out".to_string()
                )));
            }
        }
    });
}

/// Delete a provider by name.
fn spawn_delete_provider(app: &App, tx: mpsc::UnboundedSender<Event>) {
    let mut client = app.client.clone();
    let name = match app.selected_provider_name() {
        Some(n) => n.to_string(),
        None => return,
    };

    tokio::spawn(async move {
        let req = navigator_core::proto::DeleteProviderRequest { name };
        match tokio::time::timeout(Duration::from_secs(5), client.delete_provider(req)).await {
            Ok(Ok(resp)) => {
                let _ = tx.send(Event::ProviderDeleteResult(Ok(resp.into_inner().deleted)));
            }
            Ok(Err(e)) => {
                let _ = tx.send(Event::ProviderDeleteResult(Err(e.message().to_string())));
            }
            Err(_) => {
                let _ = tx.send(Event::ProviderDeleteResult(Err(
                    "request timed out".to_string()
                )));
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Draft approval / rejection
// ---------------------------------------------------------------------------

/// Approve the currently selected draft chunk.
fn spawn_draft_approve(app: &App, tx: mpsc::UnboundedSender<Event>) {
    let mut client = app.client.clone();
    let name = match app.selected_sandbox_name() {
        Some(n) => n.to_string(),
        None => return,
    };
    let abs = app.draft_scroll + app.draft_selected;
    let chunk_id = match app.draft_chunks.get(abs) {
        Some(c) => c.id.clone(),
        None => return,
    };
    let rule_name = app
        .draft_chunks
        .get(abs)
        .map_or_else(String::new, |c| c.rule_name.clone());

    tokio::spawn(async move {
        let req = navigator_core::proto::ApproveDraftChunkRequest { name, chunk_id };
        match tokio::time::timeout(Duration::from_secs(5), client.approve_draft_chunk(req)).await {
            Ok(Ok(resp)) => {
                let inner = resp.into_inner();
                let _ = tx.send(Event::DraftActionResult(Ok(format!(
                    "Approved '{}' -> policy v{}",
                    rule_name, inner.policy_version
                ))));
            }
            Ok(Err(e)) => {
                let _ = tx.send(Event::DraftActionResult(Err(e.message().to_string())));
            }
            Err(_) => {
                let _ = tx.send(Event::DraftActionResult(Err(
                    "approve timed out".to_string()
                )));
            }
        }
    });
}

/// Reject the currently selected draft chunk.
fn spawn_draft_reject(app: &App, tx: mpsc::UnboundedSender<Event>) {
    let mut client = app.client.clone();
    let name = match app.selected_sandbox_name() {
        Some(n) => n.to_string(),
        None => return,
    };
    let abs = app.draft_scroll + app.draft_selected;
    let chunk_id = match app.draft_chunks.get(abs) {
        Some(c) => c.id.clone(),
        None => return,
    };
    let rule_name = app
        .draft_chunks
        .get(abs)
        .map_or_else(String::new, |c| c.rule_name.clone());

    tokio::spawn(async move {
        let req = navigator_core::proto::RejectDraftChunkRequest {
            name,
            chunk_id,
            reason: String::new(),
        };
        match tokio::time::timeout(Duration::from_secs(5), client.reject_draft_chunk(req)).await {
            Ok(Ok(_)) => {
                let _ = tx.send(Event::DraftActionResult(Ok(format!(
                    "Rejected '{rule_name}'"
                ))));
            }
            Ok(Err(e)) => {
                let _ = tx.send(Event::DraftActionResult(Err(e.message().to_string())));
            }
            Err(_) => {
                let _ = tx.send(Event::DraftActionResult(
                    Err("reject timed out".to_string()),
                ));
            }
        }
    });
}

/// Approve all pending draft chunks.
fn spawn_draft_approve_all(app: &App, tx: mpsc::UnboundedSender<Event>) {
    let mut client = app.client.clone();
    let name = match app.selected_sandbox_name() {
        Some(n) => n.to_string(),
        None => return,
    };

    tokio::spawn(async move {
        let req = navigator_core::proto::ApproveAllDraftChunksRequest {
            name,
            include_security_flagged: false,
        };
        match tokio::time::timeout(
            Duration::from_secs(10),
            client.approve_all_draft_chunks(req),
        )
        .await
        {
            Ok(Ok(resp)) => {
                let inner = resp.into_inner();
                let mut msg = format!(
                    "Approved {} chunks -> policy v{}",
                    inner.chunks_approved, inner.policy_version
                );
                if inner.chunks_skipped > 0 {
                    use std::fmt::Write;
                    let _ = write!(msg, " ({} security-flagged skipped)", inner.chunks_skipped);
                }
                let _ = tx.send(Event::DraftActionResult(Ok(msg)));
            }
            Ok(Err(e)) => {
                let _ = tx.send(Event::DraftActionResult(Err(e.message().to_string())));
            }
            Err(_) => {
                let _ = tx.send(Event::DraftActionResult(Err(
                    "approve-all timed out".to_string()
                )));
            }
        }
    });
}

/// Mask a secret value, showing only the first and last 2 chars.
fn mask_secret(value: &str) -> String {
    let len = value.len();
    if len <= 6 {
        "*".repeat(len)
    } else {
        let start: String = value.chars().take(2).collect();
        let end: String = value.chars().skip(len - 2).collect();
        format!("{start}{}…{end}", "*".repeat(len.saturating_sub(4).min(20)))
    }
}

// ---------------------------------------------------------------------------
// Data refresh
// ---------------------------------------------------------------------------

async fn refresh_data(app: &mut App) {
    refresh_health(app).await;
    refresh_providers(app).await;
    refresh_sandboxes(app).await;
}

async fn refresh_providers(app: &mut App) {
    let req = navigator_core::proto::ListProvidersRequest {
        limit: 100,
        offset: 0,
    };
    let result = tokio::time::timeout(Duration::from_secs(5), app.client.list_providers(req)).await;
    match result {
        Ok(Err(e)) => {
            tracing::warn!("failed to list providers: {}", e.message());
        }
        Err(_) => {
            tracing::warn!("list providers timed out");
        }
        Ok(Ok(resp)) => {
            let providers = resp.into_inner().providers;
            app.provider_count = providers.len();
            app.provider_names = providers.iter().map(|p| p.name.clone()).collect();
            app.provider_types = providers.iter().map(|p| p.r#type.clone()).collect();
            app.provider_cred_keys = providers
                .iter()
                .map(|p| {
                    p.credentials
                        .keys()
                        .next()
                        .cloned()
                        .unwrap_or_else(|| "-".to_string())
                })
                .collect();
            if app.provider_selected >= app.provider_count && app.provider_count > 0 {
                app.provider_selected = app.provider_count - 1;
            }
        }
    }
}

async fn refresh_health(app: &mut App) {
    let req = navigator_core::proto::HealthRequest {};
    let result = tokio::time::timeout(Duration::from_secs(5), app.client.health(req)).await;
    match result {
        Ok(Ok(resp)) => {
            let status = resp.into_inner().status;
            app.status_text = match status {
                1 => "Healthy".to_string(),
                2 => "Degraded".to_string(),
                3 => "Unhealthy".to_string(),
                _ => format!("Unknown ({status})"),
            };
        }
        Ok(Err(e)) => {
            app.status_text = format!("error: {}", e.message());
        }
        Err(_) => {
            app.status_text = "timeout".to_string();
        }
    }
}

async fn refresh_sandboxes(app: &mut App) {
    let req = navigator_core::proto::ListSandboxesRequest {
        limit: 100,
        offset: 0,
    };
    let result = tokio::time::timeout(Duration::from_secs(5), app.client.list_sandboxes(req)).await;
    match result {
        Ok(Err(e)) => {
            tracing::warn!("failed to list sandboxes: {}", e.message());
        }
        Err(_) => {
            tracing::warn!("list sandboxes timed out");
        }
        Ok(Ok(resp)) => {
            let sandboxes = resp.into_inner().sandboxes;
            app.sandbox_count = sandboxes.len();
            app.sandbox_ids = sandboxes.iter().map(|s| s.id.clone()).collect();
            app.sandbox_names = sandboxes.iter().map(|s| s.name.clone()).collect();
            app.sandbox_phases = sandboxes.iter().map(|s| phase_label(s.phase)).collect();
            app.sandbox_images = sandboxes
                .iter()
                .map(|s| {
                    s.spec
                        .as_ref()
                        .and_then(|spec| spec.template.as_ref())
                        .map(|t| t.image.as_str())
                        .filter(|img| !img.is_empty())
                        .unwrap_or("-")
                        .to_string()
                })
                .collect();
            app.sandbox_ages = sandboxes
                .iter()
                .map(|s| format_age(s.created_at_ms))
                .collect();
            app.sandbox_created = sandboxes
                .iter()
                .map(|s| format_timestamp(s.created_at_ms))
                .collect();

            app.sandbox_policy_versions =
                sandboxes.iter().map(|s| s.current_policy_version).collect();

            // Build NOTES column from active port forwards.
            let forwards = navigator_core::forward::list_forwards().unwrap_or_default();
            app.sandbox_notes = sandboxes
                .iter()
                .map(|s| navigator_core::forward::build_sandbox_notes(&s.name, &forwards))
                .collect();

            if app.sandbox_selected >= app.sandbox_count && app.sandbox_count > 0 {
                app.sandbox_selected = app.sandbox_count - 1;
            }
        }
    }
}

/// Re-fetch only the sandbox policy when a version change is detected.
///
/// Unlike `fetch_sandbox_detail()`, this skips the `GetSandbox` metadata call
/// and preserves the current scroll position so the user isn't disrupted.
async fn refresh_sandbox_policy(app: &mut App) {
    let sandbox_id = match app.selected_sandbox_id() {
        Some(id) => id.to_string(),
        None => return,
    };

    let policy_req = navigator_core::proto::GetSandboxPolicyRequest { sandbox_id };

    match tokio::time::timeout(
        Duration::from_secs(5),
        app.client.get_sandbox_policy(policy_req),
    )
    .await
    {
        Ok(Ok(resp)) => {
            let inner = resp.into_inner();
            if let Some(mut policy) = inner.policy {
                // Use the version from the policy history, not from the
                // policy proto's own version field (which is always 1).
                policy.version = inner.version;
                app.policy_lines = render_policy_lines(&policy);
                app.sandbox_policy = Some(policy);
            }
        }
        Ok(Err(e)) => {
            tracing::warn!("failed to refresh sandbox policy: {}", e.message());
        }
        Err(_) => {
            tracing::warn!("sandbox policy refresh timed out");
        }
    }
}

async fn refresh_draft_chunks(app: &mut App) {
    let sandbox_name = match app.selected_sandbox_name() {
        Some(name) => name.to_string(),
        None => return,
    };

    let req = navigator_core::proto::GetDraftPolicyRequest {
        name: sandbox_name,
        status_filter: String::new(),
    };

    match tokio::time::timeout(Duration::from_secs(5), app.client.get_draft_policy(req)).await {
        Ok(Ok(resp)) => {
            let inner = resp.into_inner();
            app.draft_chunks = inner.chunks;
            app.draft_version = inner.draft_version;
            if app.draft_selected >= app.draft_chunks.len() && !app.draft_chunks.is_empty() {
                app.draft_selected = app.draft_chunks.len() - 1;
            }
        }
        Ok(Err(e)) => {
            tracing::debug!("draft chunks refresh: {}", e.message());
        }
        Err(_) => {
            tracing::debug!("draft chunks refresh timed out");
        }
    }
}

/// Fetch the count of pending draft recommendations for every sandbox.
///
/// This runs on the Dashboard tick so the sandbox list can show notification
/// badges without entering the sandbox detail view.
async fn refresh_sandbox_draft_counts(app: &mut App) {
    let names: Vec<String> = app.sandbox_names.clone();
    let mut counts = vec![0usize; names.len()];
    for (i, name) in names.iter().enumerate() {
        let req = navigator_core::proto::GetDraftPolicyRequest {
            name: name.clone(),
            status_filter: "pending".to_string(),
        };
        if let Ok(Ok(resp)) =
            tokio::time::timeout(Duration::from_secs(2), app.client.get_draft_policy(req)).await
        {
            counts[i] = resp.into_inner().chunks.len();
        }
    }
    app.sandbox_draft_counts = counts;
}

fn phase_label(phase: i32) -> String {
    match phase {
        1 => "Provisioning",
        2 => "Ready",
        3 => "Error",
        4 => "Deleting",
        _ => "Unknown",
    }
    .to_string()
}

fn format_age(epoch_ms: i64) -> String {
    if epoch_ms <= 0 {
        return String::from("-");
    }
    let created_secs = epoch_ms / 1000;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().cast_signed());
    let diff = now - created_secs;
    if diff < 0 {
        return String::from("-");
    }
    let diff = diff.cast_unsigned();
    if diff < 60 {
        format!("{diff}s")
    } else if diff < 3600 {
        format!("{}m", diff / 60)
    } else if diff < 86400 {
        format!("{}h {}m", diff / 3600, (diff % 3600) / 60)
    } else {
        format!("{}d {}h", diff / 86400, (diff % 86400) / 3600)
    }
}

/// Format epoch milliseconds as a human-readable UTC timestamp: `YYYY-MM-DD HH:MM`.
fn format_timestamp(epoch_ms: i64) -> String {
    if epoch_ms <= 0 {
        return String::from("-");
    }
    let secs = epoch_ms / 1000;
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;

    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}")
}

/// Convert days since Unix epoch (1970-01-01) to (year, month, day).
#[allow(clippy::unreadable_literal)]
fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
