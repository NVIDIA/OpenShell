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

use app::{App, ClusterEntry, Focus, LogLine, Screen};
use event::{Event, EventHandler};

/// Launch the Gator TUI.
///
/// `channel` must be a connected gRPC channel to the Navigator gateway.
pub async fn run(channel: Channel, cluster_name: &str, endpoint: &str) -> Result<()> {
    let client = NavigatorClient::new(channel);
    let mut app = App::new(client, cluster_name.to_string(), endpoint.to_string());

    enable_raw_mode().into_diagnostic()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).into_diagnostic()?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).into_diagnostic()?;
    terminal.clear().into_diagnostic()?;

    let mut events = EventHandler::new(Duration::from_secs(2));

    refresh_cluster_list(&mut app);
    refresh_data(&mut app).await;

    while app.running {
        terminal
            .draw(|frame| ui::draw(frame, &mut app))
            .into_diagnostic()?;

        match events.next().await {
            Some(Event::Key(key)) => {
                app.handle_key(key);
                // Handle async actions triggered by key presses.
                if app.pending_cluster_switch.is_some() {
                    handle_cluster_switch(&mut app).await;
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
                    spawn_create_sandbox(&app, events.sender());
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
                refresh_cluster_list(&mut app);
                refresh_data(&mut app).await;
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
                                    app.status_text = format!("Created sandbox: {name}");
                                    refresh_sandboxes(&mut app).await;
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
// Cluster discovery and switching
// ---------------------------------------------------------------------------

/// Refresh the list of known clusters from disk.
fn refresh_cluster_list(app: &mut App) {
    if let Ok(clusters) = navigator_bootstrap::list_clusters() {
        app.clusters = clusters
            .into_iter()
            .map(|m| ClusterEntry {
                name: m.name,
                endpoint: m.gateway_endpoint,
                is_remote: m.is_remote,
            })
            .collect();

        // Keep selection in bounds.
        if app.cluster_selected >= app.clusters.len() && !app.clusters.is_empty() {
            app.cluster_selected = app.clusters.len() - 1;
        }

        // If the active cluster appears in the list, move cursor to it on first load.
        if let Some(idx) = app.clusters.iter().position(|c| c.name == app.cluster_name) {
            // Only snap the cursor when it's still at 0 (initial state).
            if app.cluster_selected == 0 {
                app.cluster_selected = idx;
            }
        }
    }
}

/// Handle a pending cluster switch requested by the user.
async fn handle_cluster_switch(app: &mut App) {
    let Some(name) = app.pending_cluster_switch.take() else {
        return;
    };

    // Look up the endpoint from the cluster list.
    let endpoint = match app.clusters.iter().find(|c| c.name == name) {
        Some(c) => c.endpoint.clone(),
        None => return,
    };

    match connect_to_cluster(&name, &endpoint).await {
        Ok(channel) => {
            app.client = NavigatorClient::new(channel);
            app.cluster_name = name;
            app.endpoint = endpoint;
            app.reset_sandbox_state();
            // Immediately refresh data for the new cluster.
            refresh_data(app).await;
        }
        Err(e) => {
            app.status_text = format!("switch failed: {e}");
        }
    }
}

/// Build a gRPC channel to a cluster using its mTLS certs on disk.
async fn connect_to_cluster(name: &str, endpoint: &str) -> Result<Channel> {
    let mtls_dir = cluster_mtls_dir(name)
        .ok_or_else(|| miette::miette!("cannot determine config directory for cluster {name}"))?;

    let ca = std::fs::read(mtls_dir.join("ca.crt"))
        .into_diagnostic()
        .map_err(|_| miette::miette!("missing CA cert for cluster {name}"))?;
    let cert = std::fs::read(mtls_dir.join("tls.crt"))
        .into_diagnostic()
        .map_err(|_| miette::miette!("missing client cert for cluster {name}"))?;
    let key = std::fs::read(mtls_dir.join("tls.key"))
        .into_diagnostic()
        .map_err(|_| miette::miette!("missing client key for cluster {name}"))?;

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

/// Resolve the mTLS cert directory for a cluster.
fn cluster_mtls_dir(name: &str) -> Option<PathBuf> {
    let config_dir = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok()?;
    Some(
        config_dir
            .join("navigator")
            .join("clusters")
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
async fn fetch_sandbox_detail(app: &mut App) {
    let sandbox_name = match app.selected_sandbox_name() {
        Some(n) => n.to_string(),
        None => return,
    };

    let req = navigator_core::proto::GetSandboxRequest { name: sandbox_name };

    match tokio::time::timeout(Duration::from_secs(5), app.client.get_sandbox(req)).await {
        Ok(Ok(resp)) => {
            if let Some(sandbox) = resp.into_inner().sandbox {
                if let Some(spec) = &sandbox.spec {
                    app.sandbox_providers_list = spec.providers.clone();
                    if let Some(policy) = &spec.policy {
                        app.policy_lines = render_policy_lines(policy);
                        app.sandbox_policy = Some(policy.clone());
                    }
                }
            }
        }
        Ok(Err(e)) => {
            tracing::warn!("failed to fetch sandbox detail: {}", e.message());
        }
        Err(_) => {
            tracing::warn!("sandbox detail request timed out");
        }
    }

    app.policy_scroll = 0;
}

// ---------------------------------------------------------------------------
// Shell connect (suspend TUI, launch SSH, resume)
// ---------------------------------------------------------------------------

/// Suspend the TUI, launch an interactive SSH shell to the sandbox, resume on exit.
///
/// This replicates the `nav sandbox connect` flow but uses `Command::status()`
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
    let proxy_command = format!(
        "{exe_str} ssh-proxy --gateway {gateway_url} --sandbox-id {} --token {}",
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

/// If the gateway host is a loopback address, override it with the host and port
/// from the cluster endpoint URL. Mirrors `resolve_ssh_gateway` in `ssh.rs`.
fn resolve_ssh_gateway(gateway_host: &str, gateway_port: u16, cluster_url: &str) -> (String, u16) {
    let is_loopback = gateway_host == "127.0.0.1"
        || gateway_host == "0.0.0.0"
        || gateway_host == "localhost"
        || gateway_host == "::1";

    if !is_loopback {
        return (gateway_host.to_string(), gateway_port);
    }

    if let Ok(url) = url::Url::parse(cluster_url) {
        if let Some(host) = url.host_str() {
            let cluster_port = url.port().unwrap_or(gateway_port);
            let cluster_is_loopback =
                host == "127.0.0.1" || host == "0.0.0.0" || host == "localhost" || host == "::1";
            if !cluster_is_loopback {
                return (host.to_string(), cluster_port);
            }
            // Both loopback — use cluster URL's port (Docker-mapped).
            return (gateway_host.to_string(), cluster_port);
        }
    }

    (gateway_host.to_string(), gateway_port)
}

/// Shell-escape a value for use inside a ProxyCommand string.
fn shell_escape(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    let safe = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'-' | b'_'));
    if safe {
        return value.to_string();
    }
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

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

    // --- Inference ---
    if let Some(inference) = &policy.inference {
        if !inference.allowed_routes.is_empty() {
            lines.push(Line::from(Span::styled("Inference", styles::HEADING)));
            let routes = inference.allowed_routes.join(", ");
            lines.push(Line::from(vec![
                Span::styled("  Allowed routes: ", styles::MUTED),
                Span::styled(routes, styles::TEXT),
            ]));
            lines.push(Line::from(""));
        }
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

            // Rule header — include L7/TLS annotation if any endpoint has it.
            let has_l7 = rule.endpoints.iter().any(|e| !e.protocol.is_empty());
            let has_tls_term = rule.endpoints.iter().any(|e| e.tls == "terminate");
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

            let title = if annotations.is_empty() {
                format!("  {name}")
            } else {
                format!("  {name} ({})", annotations.join(", "))
            };
            lines.push(Line::from(Span::styled(title, styles::ACCENT)));

            // Endpoints.
            for ep in &rule.endpoints {
                let addr = if ep.port > 0 {
                    format!("    {}:{}", ep.host, ep.port)
                } else {
                    format!("    {}", ep.host)
                };
                lines.push(Line::from(Span::styled(addr, styles::TEXT)));

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

fn spawn_create_sandbox(app: &App, tx: mpsc::UnboundedSender<Event>) {
    let mut client = app.client.clone();
    let Some((name, image, _command, selected_providers)) = app.create_form_data() else {
        return;
    };

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

        let mut policy = navigator_policy::default_sandbox_policy();
        if has_custom_image {
            navigator_policy::clear_process_identity(&mut policy);
        }

        let req = navigator_core::proto::CreateSandboxRequest {
            name,
            spec: Some(navigator_core::proto::SandboxSpec {
                providers: selected_providers,
                template,
                policy: Some(policy),
                ..Default::default()
            }),
        };

        match tokio::time::timeout(Duration::from_secs(30), client.create_sandbox(req)).await {
            Ok(Ok(resp)) => {
                let sandbox_name = resp
                    .into_inner()
                    .sandbox
                    .map_or_else(|| "unknown".to_string(), |s| s.name);
                let _ = tx.send(Event::CreateResult(Ok(sandbox_name)));
            }
            Ok(Err(e)) => {
                let _ = tx.send(Event::CreateResult(Err(e.message().to_string())));
            }
            Err(_) => {
                let _ = tx.send(Event::CreateResult(Err("request timed out".to_string())));
            }
        }
    });
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
            if app.sandbox_selected >= app.sandbox_count && app.sandbox_count > 0 {
                app.sandbox_selected = app.sandbox_count - 1;
            }
        }
    }
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
