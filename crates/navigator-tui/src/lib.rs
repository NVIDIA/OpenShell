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
            Some(Event::ProviderDetailFetched(result)) => {
                match result {
                    Ok(provider) => {
                        let cred_key = provider.credentials.keys().next().cloned().unwrap_or_default();
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
                }
            }
            Some(Event::ProviderUpdateResult(result)) => {
                match result {
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
                }
            }
            Some(Event::ProviderDeleteResult(result)) => {
                match result {
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
                }
            }
            Some(Event::Mouse(mouse)) => {
                if app.focus == Focus::SandboxLogs {
                    match mouse.kind {
                        MouseEventKind::ScrollUp => app.scroll_logs(-3),
                        MouseEventKind::ScrollDown => app.scroll_logs(3),
                        _ => {}
                    }
                }
            }
            Some(Event::Tick) => {
                refresh_cluster_list(&mut app);
                refresh_data(&mut app).await;
            }
            Some(Event::Redraw) => {
                // Check if a buffered sandbox CreateResult is ready to finalize.
                if let Some(form) = app.create_form.as_ref() {
                    if form.create_result.is_some() {
                        let elapsed = form.anim_start.map_or(
                            app::MIN_CREATING_DISPLAY,
                            |s| s.elapsed(),
                        );
                        if elapsed >= app::MIN_CREATING_DISPLAY {
                            let result = app.create_form.as_mut()
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
                        let elapsed = form.anim_start.map_or(
                            app::MIN_CREATING_DISPLAY,
                            |s| s.elapsed(),
                        );
                        if elapsed >= app::MIN_CREATING_DISPLAY {
                            let result = app.create_provider_form.as_mut()
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

    let ptype = form.types.get(form.type_cursor).cloned().unwrap_or_default();
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
                    let final_name = resp
                        .into_inner()
                        .provider
                        .map_or(provider_name, |p| p.name);
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
                    "request timed out".to_string(),
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
                    "request timed out".to_string(),
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
                    "request timed out".to_string(),
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
