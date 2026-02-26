mod app;
mod event;
pub mod theme;
mod ui;

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use miette::{IntoDiagnostic, Result};
use navigator_core::proto::navigator_client::NavigatorClient;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use app::{App, ClusterEntry};
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
            .draw(|frame| ui::draw(frame, &app))
            .into_diagnostic()?;

        match events.next().await {
            Some(Event::Key(key)) => {
                app.handle_key(key);
                if app.pending_cluster_switch.is_some() {
                    handle_cluster_switch(&mut app).await;
                }
            }
            Some(Event::Tick) => {
                refresh_cluster_list(&mut app);
                refresh_data(&mut app).await;
            }
            Some(Event::Resize(_, _)) => {} // ratatui handles resize on next draw
            None => break,
        }
    }

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
    let name = match app.pending_cluster_switch.take() {
        Some(n) => n,
        None => return,
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
// Data refresh
// ---------------------------------------------------------------------------

async fn refresh_data(app: &mut App) {
    refresh_health(app).await;
    refresh_sandboxes(app).await;
}

async fn refresh_health(app: &mut App) {
    let req = navigator_core::proto::HealthRequest {};
    match app.client.health(req).await {
        Ok(resp) => {
            let status = resp.into_inner().status;
            app.status_text = match status {
                1 => "Healthy".to_string(),
                2 => "Degraded".to_string(),
                3 => "Unhealthy".to_string(),
                _ => format!("Unknown ({status})"),
            };
        }
        Err(e) => {
            app.status_text = format!("error: {}", e.message());
        }
    }
}

async fn refresh_sandboxes(app: &mut App) {
    let req = navigator_core::proto::ListSandboxesRequest {
        limit: 100,
        offset: 0,
    };
    match app.client.list_sandboxes(req).await {
        Ok(resp) => {
            let sandboxes = resp.into_inner().sandboxes;
            app.sandbox_count = sandboxes.len();
            app.sandbox_names = sandboxes.iter().map(|s| s.name.clone()).collect();
            app.sandbox_phases = sandboxes.iter().map(|s| phase_label(s.phase)).collect();
            app.sandbox_images = sandboxes
                .iter()
                .map(|s| {
                    s.spec
                        .as_ref()
                        .and_then(|spec| spec.template.as_ref())
                        .map(|t| t.image.clone())
                        .unwrap_or_default()
                })
                .collect();
            app.sandbox_ages = sandboxes
                .iter()
                .map(|s| format_age(s.created_at_ms))
                .collect();
            if app.sandbox_selected >= app.sandbox_count && app.sandbox_count > 0 {
                app.sandbox_selected = app.sandbox_count - 1;
            }
        }
        Err(e) => {
            tracing::warn!("failed to list sandboxes: {}", e.message());
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
