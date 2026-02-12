//! CLI command implementations.

use crate::tls::{
    TlsOptions, build_rustls_config, grpc_client, grpc_inference_client, require_tls_materials,
};
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::Full;
use hyper::{Request, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use miette::{IntoDiagnostic, Result, WrapErr};
use navigator_bootstrap::{
    DeployOptions, RemoteOptions, clear_active_cluster, default_local_kubeconfig_path,
    get_cluster_metadata, list_clusters, load_active_cluster, print_kubeconfig,
    remove_cluster_metadata, save_active_cluster, update_local_kubeconfig,
};
use navigator_core::proto::{
    CreateInferenceRouteRequest, CreateSandboxRequest, DeleteInferenceRouteRequest,
    DeleteSandboxRequest, GetSandboxRequest, HealthRequest, InferenceRoute, InferenceRouteSpec,
    ListInferenceRoutesRequest, ListSandboxesRequest, NetworkBinary, NetworkEndpoint,
    NetworkPolicyRule, Sandbox, SandboxPhase, SandboxPolicy, SandboxSpec,
    UpdateInferenceRouteRequest, WatchSandboxRequest,
};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

// Re-export SSH functions for backward compatibility
pub use crate::ssh::{sandbox_connect, sandbox_exec, sandbox_rsync, sandbox_ssh_proxy};

/// Convert a sandbox phase integer to a human-readable string.
fn phase_name(phase: i32) -> &'static str {
    match SandboxPhase::try_from(phase) {
        Ok(SandboxPhase::Unspecified) => "Unspecified",
        Ok(SandboxPhase::Provisioning) => "Provisioning",
        Ok(SandboxPhase::Ready) => "Ready",
        Ok(SandboxPhase::Error) => "Error",
        Ok(SandboxPhase::Deleting) => "Deleting",
        Ok(SandboxPhase::Unknown) | Err(_) => "Unknown",
    }
}

/// Live-updating display showing spinner with phase and latest log line.
struct LogDisplay {
    mp: MultiProgress,
    spinner: ProgressBar,
    phase: String,
    latest_log: String,
}

impl LogDisplay {
    fn new() -> Self {
        let mp = MultiProgress::new();

        // Spinner for phase status + latest log
        let spinner = mp.add(ProgressBar::new_spinner());
        spinner.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        spinner.enable_steady_tick(Duration::from_millis(120));

        Self {
            mp,
            spinner,
            phase: String::new(),
            latest_log: String::new(),
        }
    }

    fn set_phase(&mut self, phase: &str) {
        self.phase = phase.to_string();
        self.update_spinner();
    }

    fn finish_phase(&mut self, phase: &str) {
        self.phase = phase.to_string();
        self.latest_log.clear();
        self.spinner
            .finish_with_message(format_phase_label(&self.phase));
    }

    fn shutdown(&self) {
        self.spinner.disable_steady_tick();
        self.spinner.finish_and_clear();
    }

    fn set_log(&mut self, line: String) {
        let line = line.trim().to_string();
        if line.is_empty() {
            return;
        }
        self.latest_log = line;
        self.update_spinner();
    }

    fn update_spinner(&self) {
        let msg = if self.latest_log.is_empty() {
            format_phase_label(&self.phase)
        } else {
            format!(
                "{} {}",
                format_phase_label(&self.phase),
                self.latest_log.dimmed()
            )
        };
        self.spinner.set_message(msg);
    }

    /// Print a line above the progress bars (for static header content).
    fn println(&self, msg: &str) {
        let _ = self.mp.println(msg);
    }
}

fn print_sandbox_header(sandbox: &Sandbox, display: Option<&LogDisplay>) {
    let lines = [
        format!("{}", "Created sandbox:".cyan().bold()),
        String::new(),
        format!("  {} {}", "Id:".dimmed(), sandbox.id),
        format!("  {} {}", "Name:".dimmed(), sandbox.name),
        format!("  {} {}", "Namespace:".dimmed(), sandbox.namespace),
    ];
    match display {
        Some(d) => {
            for line in lines {
                d.println(&line);
            }
        }
        None => {
            for line in lines {
                println!("{line}");
            }
        }
    }
}

fn format_phase_label(phase: &str) -> String {
    let colored = match phase {
        "Ready" => phase.green().to_string(),
        "Error" => phase.red().to_string(),
        "Provisioning" => phase.yellow().to_string(),
        _ => phase.dimmed().to_string(),
    };
    format!("{} {colored}", "Phase:".dimmed())
}

const CLUSTER_DEPLOY_LOG_LINES: usize = 15;

/// Return the current terminal width, falling back to 80 columns.
fn term_width() -> usize {
    crossterm::terminal::size()
        .map(|(w, _)| w as usize)
        .unwrap_or(80)
}

/// Build a horizontal rule of `─` characters with an optional centered label.
fn horizontal_rule(label: Option<&str>, width: usize) -> String {
    match label {
        Some(text) => {
            let text_with_pad = format!(" {text} ");
            let text_len = text_with_pad.len();
            if width <= text_len {
                return text_with_pad;
            }
            let remaining = width - text_len;
            let left = remaining / 2;
            let right = remaining - left;
            format!("{}{}{}", "─".repeat(left), text_with_pad, "─".repeat(right),)
        }
        None => "─".repeat(width),
    }
}

/// Truncate a string to fit within the given column width.
///
/// If the string is longer than `max_width`, it is cut and an ellipsis (`…`)
/// is appended so the total visible width equals `max_width`.
fn truncate_to_width(s: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    // Fast path: ASCII-only check via byte length (covers the vast majority of log lines).
    if s.len() <= max_width {
        return s.to_string();
    }
    // The string is longer than the budget. We need to truncate.
    // Walk by chars to handle multi-byte UTF-8 correctly.
    let mut end = 0;
    for (count, (idx, ch)) in s.char_indices().enumerate() {
        if count + 1 > max_width.saturating_sub(1) {
            break;
        }
        end = idx + ch.len_utf8();
    }
    format!("{}…", &s[..end])
}

struct ClusterDeployLogPanel {
    mp: MultiProgress,
    name: String,
    location: String,
    status: String,
    current_step: Option<String>,
    spinner: ProgressBar,
    completed_steps: Vec<ProgressBar>,
    top_border: Option<ProgressBar>,
    log_lines: Vec<ProgressBar>,
    bottom_border: Option<ProgressBar>,
    buffer: VecDeque<String>,
}

impl ClusterDeployLogPanel {
    fn new(name: &str, location: &str) -> Self {
        let mp = MultiProgress::new();

        let spinner = mp.add(ProgressBar::new_spinner());
        spinner.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        spinner.enable_steady_tick(Duration::from_millis(120));

        let panel = Self {
            mp,
            name: name.to_string(),
            location: location.to_string(),
            status: "Starting bootstrap".to_string(),
            current_step: None,
            spinner,
            completed_steps: Vec::new(),
            top_border: None,
            log_lines: Vec::with_capacity(CLUSTER_DEPLOY_LOG_LINES),
            bottom_border: None,
            buffer: VecDeque::with_capacity(CLUSTER_DEPLOY_LOG_LINES),
        };
        panel.update_spinner_message();
        panel
    }

    fn push_log(&mut self, line: String) {
        let line = line.trim().to_string();
        if line.is_empty() {
            return;
        }

        if let Some(status) = line.strip_prefix("[status] ") {
            self.handle_status(status.to_string());
            return;
        }

        self.ensure_log_panel();

        if self.buffer.len() == CLUSTER_DEPLOY_LOG_LINES {
            self.buffer.pop_front();
        }
        self.buffer.push_back(line);
        self.render();
    }

    fn handle_status(&mut self, status: String) {
        if is_progress_status(&status) {
            if let Some(step) = &self.current_step {
                self.status = format!("{step} ({status})");
            } else {
                self.status = status;
            }
            self.update_spinner_message();
            return;
        }

        if let Some(previous_step) = self.current_step.replace(status.clone()) {
            self.push_completed_step(&previous_step, true);
        }

        self.status = status;
        self.update_spinner_message();
    }

    fn ensure_log_panel(&mut self) {
        if self.top_border.is_some() {
            return;
        }

        let line_style =
            ProgressStyle::with_template("{msg}").unwrap_or_else(|_| ProgressStyle::default_bar());

        let width = term_width();

        let top_border = self.mp.add(ProgressBar::new(0));
        top_border.set_style(line_style.clone());
        top_border.set_message(
            horizontal_rule(Some("Container Logs"), width)
                .cyan()
                .to_string(),
        );

        for _ in 0..CLUSTER_DEPLOY_LOG_LINES {
            let line = self.mp.add(ProgressBar::new(0));
            line.set_style(line_style.clone());
            line.set_message(String::new());
            self.log_lines.push(line);
        }

        let bottom_border = self.mp.add(ProgressBar::new(0));
        bottom_border.set_style(line_style);
        bottom_border.set_message(horizontal_rule(None, width).cyan().to_string());

        self.top_border = Some(top_border);
        self.bottom_border = Some(bottom_border);
    }

    fn push_completed_step(&mut self, step: &str, success: bool) {
        if step.is_empty() {
            return;
        }

        let symbol = if success {
            "✓".green().bold().to_string()
        } else {
            "x".red().bold().to_string()
        };

        let line_style =
            ProgressStyle::with_template("{msg}").unwrap_or_else(|_| ProgressStyle::default_bar());
        let bar = self.mp.insert_before(&self.spinner, ProgressBar::new(0));
        bar.set_style(line_style);
        bar.set_message(format!("{symbol} {step}"));
        self.completed_steps.push(bar);
    }

    fn update_spinner_message(&self) {
        self.spinner.set_message(format!(
            "Bootstrapping {} cluster {}: {}",
            self.location,
            self.name,
            self.status.dimmed()
        ));
    }

    fn finish_success(&mut self) {
        if let Some(step) = self.current_step.take() {
            self.push_completed_step(&step, true);
        }
        self.finish_all_bars();
        self.spinner.finish_and_clear();
    }

    fn finish_failure(&mut self) {
        if let Some(step) = self.current_step.take() {
            self.push_completed_step(&step, false);
        }
        self.finish_all_bars();
        self.spinner.finish_and_clear();
    }

    /// Finish all progress bars so they are preserved when `MultiProgress` is dropped.
    fn finish_all_bars(&self) {
        for bar in &self.completed_steps {
            bar.finish();
        }
        if let Some(top_border) = &self.top_border {
            top_border.finish();
        }
        for bar in &self.log_lines {
            bar.finish();
        }
        if let Some(bottom_border) = &self.bottom_border {
            bottom_border.finish();
        }
    }

    fn render(&self) {
        let width = term_width();
        for (idx, bar) in self.log_lines.iter().enumerate() {
            let line = self.buffer.get(idx).map(String::as_str).unwrap_or_default();
            bar.set_message(truncate_to_width(line, width));
        }
    }
}

fn is_progress_status(status: &str) -> bool {
    status.starts_with("Exported ")
        || status.starts_with("Downloading:")
        || status.starts_with("Extracting:")
}

/// Show cluster status.
#[allow(clippy::branches_sharing_code)]
pub async fn cluster_status(server: &str, tls: &TlsOptions) -> Result<()> {
    println!("{}", "Server Status".cyan().bold());
    println!();
    println!("  {} {}", "Server:".dimmed(), server);

    // Try to connect and get health
    match grpc_client(server, tls).await {
        Ok(mut client) => match client.health(HealthRequest {}).await {
            Ok(response) => {
                let health = response.into_inner();
                println!("  {} {}", "Status:".dimmed(), "Connected".green());
                println!("  {} {}", "Version:".dimmed(), health.version);
            }
            Err(e) => {
                if let Some(status) = http_health_check(server, tls).await? {
                    if status.is_success() {
                        println!("  {} {}", "Status:".dimmed(), "Connected (HTTP)".yellow());
                        println!("  {} {}", "HTTP: ".dimmed(), status);
                        println!("  {} {}", "gRPC error:".dimmed(), e);
                    } else {
                        println!("  {} {}", "Status:".dimmed(), "Error".red());
                        println!("  {} {}", "HTTP:".dimmed(), status);
                        println!("  {} {}", "gRPC error:".dimmed(), e);
                    }
                } else {
                    println!("  {} {}", "Status:".dimmed(), "Error".red());
                    println!("  {} {}", "Error:".dimmed(), e);
                }
            }
        },
        Err(e) => {
            if let Some(status) = http_health_check(server, tls).await? {
                if status.is_success() {
                    println!("  {} {}", "Status:".dimmed(), "Connected (HTTP)".yellow());
                    println!("  {} {}", "HTTP:".dimmed(), status);
                    println!("  {} {}", "gRPC error:".dimmed(), e);
                } else {
                    println!("  {} {}", "Status:".dimmed(), "Disconnected".red());
                    println!("  {} {}", "HTTP:".dimmed(), status);
                    println!("  {} {}", "Error:".dimmed(), e);
                }
            } else {
                println!("  {} {}", "Status:".dimmed(), "Disconnected".red());
                println!("  {} {}", "Error:".dimmed(), e);
            }
        }
    }

    Ok(())
}

/// Set the active cluster.
pub fn cluster_use(name: &str) -> Result<()> {
    // Verify the cluster exists
    get_cluster_metadata(name).ok_or_else(|| {
        miette::miette!(
            "No cluster metadata found for '{name}'.\n\
             Deploy a cluster first with: nav cluster admin deploy --name {name}\n\
             Or list available clusters: nav cluster list"
        )
    })?;

    save_active_cluster(name)?;
    eprintln!("{} Active cluster set to '{name}'", "✓".green().bold());
    Ok(())
}

/// List all provisioned clusters.
pub fn cluster_list() -> Result<()> {
    let clusters = list_clusters()?;
    let active = load_active_cluster();

    if clusters.is_empty() {
        println!("No clusters found.");
        println!();
        println!(
            "Deploy a cluster with: {}",
            "nav cluster admin deploy".dimmed()
        );
        return Ok(());
    }

    // Calculate column widths
    let name_width = clusters
        .iter()
        .map(|c| c.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let endpoint_width = clusters
        .iter()
        .map(|c| c.gateway_endpoint.len())
        .max()
        .unwrap_or(8)
        .max(8);

    // Print header
    println!(
        "  {:<name_width$}  {:<endpoint_width$}  {}",
        "NAME".bold(),
        "ENDPOINT".bold(),
        "TYPE".bold(),
    );

    // Print rows
    for cluster in &clusters {
        let is_active = active.as_deref() == Some(&cluster.name);
        let marker = if is_active { "*" } else { " " };
        let cluster_type = if cluster.is_remote { "remote" } else { "local" };
        let line = format!(
            "{marker} {:<name_width$}  {:<endpoint_width$}  {cluster_type}",
            cluster.name, cluster.gateway_endpoint,
        );
        if is_active {
            println!("{}", line.green());
        } else {
            println!("{line}");
        }
    }

    Ok(())
}

async fn http_health_check(server: &str, tls: &TlsOptions) -> Result<Option<StatusCode>> {
    let base = server.trim_end_matches('/');
    let uri: hyper::Uri = format!("{base}/healthz").parse().into_diagnostic()?;
    if uri.scheme_str() == Some("https") {
        let materials = require_tls_materials(server, tls)?;
        let tls_config = build_rustls_config(&materials)?;
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only()
            .enable_http1()
            .build();
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Full::new(Bytes::new()))
            .into_diagnostic()?;
        let resp = client.request(req).await.into_diagnostic()?;
        return Ok(Some(resp.status()));
    }

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .into_diagnostic()?;
    let resp = client.request(req).await.into_diagnostic()?;
    Ok(Some(resp.status()))
}

/// Prompt the user to choose how to handle an existing cluster deployment.
///
/// Returns `true` to recreate (destroy and start fresh), `false` to reuse.
fn prompt_existing_cluster(
    name: &str,
    info: &navigator_bootstrap::ExistingClusterInfo,
) -> Result<bool> {
    let status = if info.container_running {
        "running"
    } else if info.container_exists {
        "stopped"
    } else {
        "volume only"
    };

    eprintln!("• Existing cluster '{name}' detected ({status})");
    if let Some(image) = &info.container_image {
        eprintln!("  {} {}", "Image:".dimmed(), image);
    }
    eprintln!();

    eprint!("Destroy and recreate from scratch? [y/N] ");
    std::io::stderr().flush().ok();

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .into_diagnostic()
        .wrap_err("failed to read user input")?;

    let choice = input.trim().to_lowercase();
    Ok(choice == "y" || choice == "yes")
}

/// Deploy a cluster with the rich progress panel (interactive) or simple
/// logging (non-interactive). Returns the [`ClusterHandle`] on success.
///
/// This is the shared deploy UX used by both `cluster admin deploy` and
/// the auto-bootstrap path in `sandbox create`.
pub(crate) async fn deploy_cluster_with_panel(
    options: DeployOptions,
    name: &str,
    location: &str,
) -> Result<navigator_bootstrap::ClusterHandle> {
    let interactive = std::io::stderr().is_terminal();

    if interactive {
        let panel = std::sync::Arc::new(std::sync::Mutex::new(ClusterDeployLogPanel::new(
            name, location,
        )));
        let panel_clone = std::sync::Arc::clone(&panel);
        let result = navigator_bootstrap::deploy_cluster_with_logs(options, move |line| {
            if let Ok(mut p) = panel_clone.lock() {
                p.push_log(line);
            }
        })
        .await;

        let mut panel = std::sync::Arc::try_unwrap(panel)
            .ok()
            .expect("panel arc should have single owner after deploy")
            .into_inner()
            .expect("panel mutex should not be poisoned");
        match result {
            Ok(handle) => {
                panel.finish_success();
                Ok(handle)
            }
            Err(err) => {
                panel.finish_failure();
                eprintln!(
                    "{} {} {name}",
                    "x".red().bold(),
                    "Cluster failed:".red().bold(),
                );
                Err(err)
            }
        }
    } else {
        eprintln!("Deploying {location} cluster {name}...");
        let handle = navigator_bootstrap::deploy_cluster_with_logs(options, |line| {
            if let Some(status) = line.strip_prefix("[status] ") {
                eprintln!("  {status}");
            } else {
                eprintln!("  {line}");
            }
        })
        .await?;
        eprintln!("Cluster {name} ready.");
        Ok(handle)
    }
}

/// Print post-deploy summary showing the cluster name and gateway endpoint.
pub(crate) fn print_deploy_summary(name: &str, handle: &navigator_bootstrap::ClusterHandle) {
    eprintln!(
        "{} {} {name}",
        "✓".green().bold(),
        "Cluster ready:".green().bold(),
    );
    eprintln!(
        "  {} {}",
        "Gateway endpoint:".dimmed(),
        handle.gateway_endpoint()
    );
    eprintln!();
}

/// Provision or start a cluster (local or remote).
pub async fn cluster_admin_deploy(
    name: &str,
    update_kube_config: bool,
    get_kubeconfig: bool,
    remote: Option<&str>,
    ssh_key: Option<&str>,
) -> Result<()> {
    let is_remote = remote.is_some();
    let location = if is_remote { "remote" } else { "local" };

    let mut options = DeployOptions::new(name);
    if let Some(dest) = remote {
        let mut remote_opts = RemoteOptions::new(dest);
        if let Some(key) = ssh_key {
            remote_opts = remote_opts.with_ssh_key(key);
        }
        options = options.with_remote(remote_opts);
    }

    let interactive = std::io::stderr().is_terminal();

    // Check for existing cluster and prompt user if found
    if interactive {
        let remote_opts = remote.map(|dest| {
            let mut opts = RemoteOptions::new(dest);
            if let Some(key) = ssh_key {
                opts = opts.with_ssh_key(key);
            }
            opts
        });
        if let Some(info) =
            navigator_bootstrap::check_existing_deployment(name, remote_opts.as_ref()).await?
        {
            let recreate = prompt_existing_cluster(name, &info)?;
            if recreate {
                eprintln!("• Destroying existing cluster...");
                let handle = navigator_bootstrap::cluster_handle(name, remote_opts.as_ref())?;
                handle.destroy().await?;
                eprintln!("{} Cluster destroyed, starting fresh.", "✓".green().bold());
                eprintln!();
            }
            // If reusing, the deploy flow will handle stale node cleanup automatically
        }
    }

    let handle = deploy_cluster_with_panel(options, name, location).await?;

    if update_kube_config {
        let target_path = default_local_kubeconfig_path()?;
        // For remote clusters, the name includes "-remote" suffix
        let kubeconfig_name = if is_remote {
            format!("{name}-remote")
        } else {
            name.to_string()
        };
        update_local_kubeconfig(&kubeconfig_name, &target_path)?;
        eprintln!(
            "{} Updated kubeconfig at {}",
            "✓".green().bold(),
            target_path.display()
        );
    }

    if get_kubeconfig {
        let kubeconfig_name = if is_remote {
            format!("{name}-remote")
        } else {
            name.to_string()
        };
        print_kubeconfig(&kubeconfig_name)?;
    }

    print_deploy_summary(name, &handle);

    // Auto-activate: set this cluster as the active cluster.
    save_active_cluster(name)?;
    eprintln!("{} Active cluster set to '{name}'", "✓".green().bold());

    Ok(())
}

/// Resolve the remote SSH destination for a cluster.
///
/// If `remote_override` is provided, use it. Otherwise, look up the remote
/// host from stored cluster metadata. Returns `None` for local clusters.
fn resolve_remote(name: &str, remote_override: Option<&str>) -> Option<String> {
    if let Some(r) = remote_override {
        return Some(r.to_string());
    }
    let metadata = get_cluster_metadata(name)?;
    if metadata.is_remote {
        metadata.remote_host
    } else {
        None
    }
}

/// Stop a cluster.
pub async fn cluster_admin_stop(
    name: &str,
    remote: Option<&str>,
    ssh_key: Option<&str>,
) -> Result<()> {
    let resolved_remote = resolve_remote(name, remote);
    let remote_opts = resolved_remote.as_deref().map(|dest| {
        let mut opts = RemoteOptions::new(dest);
        if let Some(key) = ssh_key {
            opts = opts.with_ssh_key(key);
        }
        opts
    });

    eprintln!("• Stopping cluster {name}...");
    let handle = navigator_bootstrap::cluster_handle(name, remote_opts.as_ref())?;
    handle.stop().await?;
    eprintln!("{} Cluster {name} stopped.", "✓".green().bold());
    Ok(())
}

/// Destroy a cluster and its state.
pub async fn cluster_admin_destroy(
    name: &str,
    remote: Option<&str>,
    ssh_key: Option<&str>,
) -> Result<()> {
    let resolved_remote = resolve_remote(name, remote);
    let remote_opts = resolved_remote.as_deref().map(|dest| {
        let mut opts = RemoteOptions::new(dest);
        if let Some(key) = ssh_key {
            opts = opts.with_ssh_key(key);
        }
        opts
    });

    eprintln!("• Destroying cluster {name}...");
    let handle = navigator_bootstrap::cluster_handle(name, remote_opts.as_ref())?;
    handle.destroy().await?;

    // Clean up metadata and active cluster reference
    if let Err(err) = remove_cluster_metadata(name) {
        tracing::debug!("failed to remove cluster metadata: {err}");
    }
    if load_active_cluster().as_deref() == Some(name)
        && let Err(err) = clear_active_cluster()
    {
        tracing::debug!("failed to clear active cluster: {err}");
    }

    eprintln!("{} Cluster {name} destroyed.", "✓".green().bold());
    Ok(())
}

/// Show cluster deployment details.
pub fn cluster_admin_info(name: &str) -> Result<()> {
    let metadata = get_cluster_metadata(name).ok_or_else(|| {
        miette::miette!(
            "No cluster metadata found for '{name}'.\n\
             Deploy a cluster first with: nav cluster admin deploy --name {name}"
        )
    })?;

    let kubeconfig_path = navigator_bootstrap::stored_kubeconfig_path(name)?;

    println!("{}", "Cluster Info".cyan().bold());
    println!();
    println!("  {} {}", "Cluster:".dimmed(), metadata.name);
    println!(
        "  {} {}",
        "Gateway endpoint:".dimmed(),
        metadata.gateway_endpoint
    );
    println!(
        "  {} {}",
        "Stored kubeconfig:".dimmed(),
        kubeconfig_path.display()
    );

    if metadata.is_remote {
        if let Some(ref host) = metadata.remote_host {
            println!("  {} {host}", "Remote host:".dimmed());
        }
        if let Some(ref resolved) = metadata.resolved_host {
            println!("  {} {resolved}", "Resolved host:".dimmed());
        }

        if let Some(ref host) = metadata.remote_host {
            println!();
            println!("{}", "SSH tunnel for kubectl access:".dimmed());
            println!("  nav cluster admin tunnel --name {name}");
            println!("Or manually:");
            println!("  ssh -L 6443:127.0.0.1:6443 {host}");
        }
    }

    Ok(())
}

/// Print or start an SSH tunnel for kubectl access to a remote cluster.
pub fn cluster_admin_tunnel(
    name: &str,
    remote_override: Option<&str>,
    ssh_key: Option<&str>,
    print_command: bool,
) -> Result<()> {
    let remote = resolve_remote(name, remote_override).ok_or_else(|| {
        miette::miette!(
            "Cluster '{name}' is not a remote cluster (no SSH destination found).\n\
             SSH tunnels are only needed for remote clusters."
        )
    })?;

    let ssh_cmd = ssh_key.map_or_else(
        || format!("ssh -L 6443:127.0.0.1:6443 -N {remote}"),
        |key| format!("ssh -i {key} -L 6443:127.0.0.1:6443 -N {remote}"),
    );

    if print_command {
        println!("{ssh_cmd}");
        return Ok(());
    }

    eprintln!("Starting SSH tunnel to {remote}...");
    eprintln!("Press Ctrl+C to stop the tunnel.");
    eprintln!();

    let status = Command::new("sh")
        .arg("-c")
        .arg(&ssh_cmd)
        .status()
        .into_diagnostic()
        .wrap_err("failed to start SSH tunnel")?;

    if !status.success() {
        return Err(miette::miette!("SSH tunnel exited with status: {}", status));
    }

    Ok(())
}

/// Create a sandbox when no cluster is configured.
///
/// Offers to bootstrap a new cluster first, then delegates to [`sandbox_create`].
pub async fn sandbox_create_with_bootstrap(
    sync: bool,
    keep: bool,
    remote: Option<&str>,
    ssh_key: Option<&str>,
    command: &[String],
) -> Result<()> {
    if !crate::bootstrap::confirm_bootstrap()? {
        return Err(miette::miette!(
            "No active cluster.\n\
             Set one with: nav cluster use <name>\n\
             Or deploy a new cluster: nav cluster admin deploy"
        ));
    }
    let (tls, server) = crate::bootstrap::run_bootstrap(remote, ssh_key).await?;
    sandbox_create(&server, sync, keep, remote, ssh_key, command, &tls).await
}

/// Create a sandbox with default settings.
pub async fn sandbox_create(
    server: &str,
    sync: bool,
    keep: bool,
    remote: Option<&str>,
    ssh_key: Option<&str>,
    command: &[String],
    tls: &TlsOptions,
) -> Result<()> {
    // Try connecting to the cluster. If it fails due to an unreachable cluster,
    // offer to bootstrap a local one and retry.
    let (mut client, effective_server, effective_tls) = match grpc_client(server, tls).await {
        Ok(c) => (c, server.to_string(), tls.clone()),
        Err(err) => {
            if !crate::bootstrap::should_attempt_bootstrap(&err, tls) {
                return Err(err);
            }
            if !crate::bootstrap::confirm_bootstrap()? {
                return Err(err);
            }
            let (new_tls, new_server) = crate::bootstrap::run_bootstrap(remote, ssh_key).await?;
            let c = grpc_client(&new_server, &new_tls)
                .await
                .wrap_err("bootstrap succeeded but failed to connect to cluster")?;
            (c, new_server, new_tls)
        }
    };

    let policy = load_dev_sandbox_policy()?;
    let request = CreateSandboxRequest {
        spec: Some(SandboxSpec {
            policy: Some(policy),
            ..SandboxSpec::default()
        }),
    };

    let response = client.create_sandbox(request).await.into_diagnostic()?;
    let sandbox = response
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox missing from response"))?;

    let interactive = std::io::stdout().is_terminal();
    let sandbox_id = sandbox.id.clone();

    // Set up display
    let mut display = if interactive {
        Some(LogDisplay::new())
    } else {
        None
    };

    // Print header
    print_sandbox_header(&sandbox, display.as_ref());

    // Set initial phase
    if let Some(d) = display.as_mut() {
        d.set_phase(phase_name(sandbox.phase));
    } else {
        println!("  {}", format_phase_label(phase_name(sandbox.phase)));
    }

    let mut stream = client
        .watch_sandbox(WatchSandboxRequest {
            id: sandbox.id.clone(),
            follow_status: true,
            follow_logs: true,
            follow_events: true,
            log_tail_lines: 200,
            event_tail: 0,
            stop_on_terminal: true,
        })
        .await
        .into_diagnostic()?
        .into_inner();

    let mut last_phase = sandbox.phase;
    let mut last_error_reason = String::new();
    let start_time = Instant::now();
    let provision_timeout = Duration::from_secs(120);

    while let Some(item) = stream.next().await {
        // Check for timeout
        if start_time.elapsed() > provision_timeout {
            if let Some(d) = display.as_mut() {
                d.finish_phase(phase_name(last_phase));
            }
            println!();
            return Err(miette::miette!(
                "sandbox provisioning timed out after {:?}",
                provision_timeout
            ));
        }

        let evt = item.into_diagnostic()?;
        match evt.payload {
            Some(navigator_core::proto::sandbox_stream_event::Payload::Sandbox(s)) => {
                last_phase = s.phase;
                // Capture error reason from conditions only when phase is Error
                // to avoid showing stale transient error reasons
                if SandboxPhase::try_from(s.phase) == Ok(SandboxPhase::Error)
                    && let Some(status) = &s.status
                {
                    for condition in &status.conditions {
                        if condition.r#type == "Ready"
                            && condition.status.eq_ignore_ascii_case("false")
                        {
                            last_error_reason =
                                format!("{}: {}", condition.reason, condition.message);
                        }
                    }
                }
                if let Some(d) = display.as_mut() {
                    d.set_phase(phase_name(s.phase));
                } else {
                    println!("  {}", format_phase_label(phase_name(s.phase)));
                }
            }
            Some(navigator_core::proto::sandbox_stream_event::Payload::Log(line)) => {
                if let Some(d) = display.as_mut() {
                    d.set_log(line.message);
                }
            }
            Some(navigator_core::proto::sandbox_stream_event::Payload::Event(ev)) => {
                let reason = if ev.reason.is_empty() {
                    "Event"
                } else {
                    &ev.reason
                };
                let msg = if ev.message.is_empty() {
                    ""
                } else {
                    &ev.message
                };
                let line = format!("{} {} {}", "EVENT".dimmed(), reason, msg);
                if let Some(d) = display.as_mut() {
                    d.set_log(line);
                }
            }
            Some(navigator_core::proto::sandbox_stream_event::Payload::Warning(w)) => {
                let line = format!("{} {}", "WARN".yellow(), w.message);
                if let Some(d) = display.as_mut() {
                    d.set_log(line);
                }
            }
            None => {}
        }
    }

    // Finish up - check final phase
    if let Some(d) = display.as_mut() {
        d.finish_phase(phase_name(last_phase));
        d.shutdown();
    }
    drop(display);
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    println!();

    match SandboxPhase::try_from(last_phase) {
        Ok(SandboxPhase::Ready) => {
            drop(stream);
            drop(client);

            if sync {
                let repo_root = git_repo_root()?;
                let files = git_sync_files(&repo_root)?;
                if !files.is_empty() {
                    sandbox_rsync(
                        &effective_server,
                        &sandbox_id,
                        &repo_root,
                        &files,
                        &effective_tls,
                    )
                    .await?;
                }
            }

            if command.is_empty() {
                return sandbox_connect(&effective_server, &sandbox_id, &effective_tls).await;
            }

            let exec_result = sandbox_exec(
                &effective_server,
                &sandbox_id,
                command,
                interactive,
                &effective_tls,
            )
            .await;

            if !interactive
                && !keep
                && let Err(err) = sandbox_delete(
                    &effective_server,
                    std::slice::from_ref(&sandbox_id),
                    &effective_tls,
                )
                .await
            {
                if exec_result.is_ok() {
                    return Err(err);
                }
                eprintln!("Failed to delete sandbox {sandbox_id}: {err}");
            }

            exec_result
        }
        Ok(SandboxPhase::Error) => {
            if last_error_reason.is_empty() {
                Err(miette::miette!(
                    "sandbox entered error phase while provisioning"
                ))
            } else {
                Err(miette::miette!(
                    "sandbox entered error phase while provisioning: {}",
                    last_error_reason
                ))
            }
        }
        _ => Err(miette::miette!(
            "sandbox provisioning stream ended before reaching terminal phase"
        )),
    }
}

/// Default sandbox policy YAML, baked in at compile time.
const DEFAULT_SANDBOX_POLICY_YAML: &str = include_str!("../../../dev-sandbox-policy.yaml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevSandboxPolicyFile {
    version: u32,
    #[serde(default)]
    inference: Option<DevInferencePolicy>,
    #[serde(default)]
    filesystem: Option<DevFilesystemPolicy>,
    #[serde(default)]
    landlock: Option<DevLandlockPolicy>,
    #[serde(default)]
    process: Option<DevProcessPolicy>,
    #[serde(default)]
    network_policies: std::collections::HashMap<String, DevNetworkPolicyRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevFilesystemPolicy {
    #[serde(default)]
    include_workdir: bool,
    #[serde(default)]
    read_only: Vec<String>,
    #[serde(default)]
    read_write: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevLandlockPolicy {
    #[serde(default)]
    compatibility: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevProcessPolicy {
    #[serde(default)]
    run_as_user: String,
    #[serde(default)]
    run_as_group: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevInferencePolicy {
    #[serde(default)]
    allowed_routing_hints: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevNetworkPolicyRule {
    #[serde(default)]
    name: String,
    #[serde(default)]
    endpoints: Vec<DevNetworkEndpoint>,
    #[serde(default)]
    binaries: Vec<DevNetworkBinary>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevNetworkEndpoint {
    host: String,
    port: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevNetworkBinary {
    path: String,
}

fn load_dev_sandbox_policy() -> Result<SandboxPolicy> {
    let contents = match std::env::var("NAVIGATOR_SANDBOX_POLICY") {
        Ok(policy_path) => {
            let path = Path::new(&policy_path);
            std::fs::read_to_string(path)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!("failed to read sandbox policy from {}", path.display())
                })?
        }
        Err(_) => DEFAULT_SANDBOX_POLICY_YAML.to_string(),
    };
    let raw: DevSandboxPolicyFile = serde_yaml::from_str(&contents)
        .into_diagnostic()
        .wrap_err("failed to parse sandbox policy yaml")?;

    let network_policies = raw
        .network_policies
        .into_iter()
        .map(|(key, rule)| {
            let proto_rule = NetworkPolicyRule {
                name: if rule.name.is_empty() {
                    key.clone()
                } else {
                    rule.name
                },
                endpoints: rule
                    .endpoints
                    .into_iter()
                    .map(|e| NetworkEndpoint {
                        host: e.host,
                        port: e.port,
                    })
                    .collect(),
                binaries: rule
                    .binaries
                    .into_iter()
                    .map(|b| NetworkBinary { path: b.path })
                    .collect(),
            };
            (key, proto_rule)
        })
        .collect();

    Ok(SandboxPolicy {
        version: raw.version,
        filesystem: raw
            .filesystem
            .map(|fs| navigator_core::proto::FilesystemPolicy {
                include_workdir: fs.include_workdir,
                read_only: fs.read_only,
                read_write: fs.read_write,
            }),
        landlock: raw
            .landlock
            .map(|ll| navigator_core::proto::LandlockPolicy {
                compatibility: ll.compatibility,
            }),
        process: raw.process.map(|p| navigator_core::proto::ProcessPolicy {
            run_as_user: p.run_as_user,
            run_as_group: p.run_as_group,
        }),
        network_policies,
        inference: raw
            .inference
            .map(|inf| navigator_core::proto::InferencePolicy {
                allowed_routing_hints: inf.allowed_routing_hints,
            }),
    })
}

/// Fetch a sandbox by id.
pub async fn sandbox_get(server: &str, id: &str, tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .get_sandbox(GetSandboxRequest { id: id.to_string() })
        .await
        .into_diagnostic()?;
    let sandbox = response
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox missing from response"))?;

    println!("{}", "Sandbox:".cyan().bold());
    println!();
    println!("  {} {}", "Id:".dimmed(), sandbox.id);
    println!("  {} {}", "Name:".dimmed(), sandbox.name);
    println!("  {} {}", "Namespace:".dimmed(), sandbox.namespace);
    println!("  {} {}", "Phase:".dimmed(), phase_name(sandbox.phase));

    if let Some(spec) = &sandbox.spec
        && let Some(policy) = &spec.policy
    {
        println!();
        print_sandbox_policy(policy);
    }

    Ok(())
}

/// Serializable policy structure for YAML output.
#[derive(Serialize)]
struct PolicyYaml {
    version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    inference: Option<InferenceYaml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filesystem: Option<FilesystemYaml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    landlock: Option<LandlockYaml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process: Option<ProcessYaml>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    network_policies: std::collections::BTreeMap<String, NetworkPolicyRuleYaml>,
}

#[derive(Serialize)]
struct InferenceYaml {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allowed_routing_hints: Vec<String>,
}

#[derive(Serialize)]
struct FilesystemYaml {
    include_workdir: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    read_only: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    read_write: Vec<String>,
}

#[derive(Serialize)]
struct LandlockYaml {
    compatibility: String,
}

#[derive(Serialize)]
struct ProcessYaml {
    #[serde(skip_serializing_if = "String::is_empty")]
    run_as_user: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    run_as_group: String,
}

#[derive(Serialize)]
struct NetworkPolicyRuleYaml {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    endpoints: Vec<NetworkEndpointYaml>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    binaries: Vec<NetworkBinaryYaml>,
}

#[derive(Serialize)]
struct NetworkEndpointYaml {
    host: String,
    port: u32,
}

#[derive(Serialize)]
struct NetworkBinaryYaml {
    path: String,
}

/// Convert proto policy to serializable YAML structure.
fn policy_to_yaml(policy: &SandboxPolicy) -> PolicyYaml {
    let inference = policy.inference.as_ref().map(|inf| InferenceYaml {
        allowed_routing_hints: inf.allowed_routing_hints.clone(),
    });

    let filesystem = policy.filesystem.as_ref().map(|fs| FilesystemYaml {
        include_workdir: fs.include_workdir,
        read_only: fs.read_only.clone(),
        read_write: fs.read_write.clone(),
    });

    let landlock = policy.landlock.as_ref().map(|ll| LandlockYaml {
        compatibility: ll.compatibility.clone(),
    });

    let process = policy.process.as_ref().and_then(|p| {
        if p.run_as_user.is_empty() && p.run_as_group.is_empty() {
            None
        } else {
            Some(ProcessYaml {
                run_as_user: p.run_as_user.clone(),
                run_as_group: p.run_as_group.clone(),
            })
        }
    });

    let network_policies = policy
        .network_policies
        .iter()
        .map(|(key, rule)| {
            let yaml_rule = NetworkPolicyRuleYaml {
                endpoints: rule
                    .endpoints
                    .iter()
                    .map(|e| NetworkEndpointYaml {
                        host: e.host.clone(),
                        port: e.port,
                    })
                    .collect(),
                binaries: rule
                    .binaries
                    .iter()
                    .map(|b| NetworkBinaryYaml {
                        path: b.path.clone(),
                    })
                    .collect(),
            };
            (key.clone(), yaml_rule)
        })
        .collect();

    PolicyYaml {
        version: policy.version,
        inference,
        filesystem,
        landlock,
        process,
        network_policies,
    }
}

/// Print a single YAML line with dimmed keys and regular values.
fn print_yaml_line(line: &str) {
    // Find leading whitespace
    let trimmed = line.trim_start();
    let indent = &line[..line.len() - trimmed.len()];

    // Handle list items
    if let Some(rest) = trimmed.strip_prefix("- ") {
        print!("{indent}");
        print!("{}", "- ".dimmed());
        print!("{rest}");
        println!();
        return;
    }

    // Handle key: value pairs
    if let Some(colon_pos) = trimmed.find(':') {
        let key = &trimmed[..colon_pos];
        let after_colon = &trimmed[colon_pos + 1..];

        print!("{indent}");
        print!("{}", key.dimmed());
        print!("{}", ":".dimmed());

        if after_colon.is_empty() {
            // Key with nested content (no value on this line)
        } else if let Some(value) = after_colon.strip_prefix(' ') {
            // Key: value
            print!(" {value}");
        } else {
            // Shouldn't happen in valid YAML, but handle it
            print!("{after_colon}");
        }
        println!();
        return;
    }

    // Plain line (shouldn't happen often in YAML)
    println!("{line}");
}

/// Print sandbox policy as YAML with dimmed keys.
fn print_sandbox_policy(policy: &SandboxPolicy) {
    println!("{}", "Policy:".cyan().bold());
    println!();
    let policy_yaml = policy_to_yaml(policy);
    if let Ok(yaml_str) = serde_yaml::to_string(&policy_yaml) {
        // Indent the YAML output and skip the initial "---" line
        for line in yaml_str.lines() {
            if line == "---" {
                continue;
            }
            print!("  ");
            print_yaml_line(line);
        }
    }
}

/// List sandboxes.
pub async fn sandbox_list(
    server: &str,
    limit: u32,
    offset: u32,
    ids_only: bool,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .list_sandboxes(ListSandboxesRequest { limit, offset })
        .await
        .into_diagnostic()?;

    let sandboxes = response.into_inner().sandboxes;
    if sandboxes.is_empty() {
        if !ids_only {
            println!("No sandboxes found.");
        }
        return Ok(());
    }

    if ids_only {
        for sandbox in sandboxes {
            println!("{}", sandbox.id);
        }
        return Ok(());
    }

    // Calculate column widths
    let id_width = sandboxes
        .iter()
        .map(|s| s.id.len())
        .max()
        .unwrap_or(2)
        .max(2);
    let name_width = sandboxes
        .iter()
        .map(|s| s.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let ns_width = sandboxes
        .iter()
        .map(|s| s.namespace.len())
        .max()
        .unwrap_or(9)
        .max(9);

    // Print header
    println!(
        "{:<id_width$}  {:<name_width$}  {:<ns_width$}  {}",
        "ID".bold(),
        "NAME".bold(),
        "NAMESPACE".bold(),
        "PHASE".bold(),
    );

    // Print rows
    for sandbox in sandboxes {
        let phase = phase_name(sandbox.phase);
        let phase_colored = match SandboxPhase::try_from(sandbox.phase) {
            Ok(SandboxPhase::Ready) => phase.green().to_string(),
            Ok(SandboxPhase::Error) => phase.red().to_string(),
            Ok(SandboxPhase::Provisioning) => phase.yellow().to_string(),
            Ok(SandboxPhase::Deleting) => phase.dimmed().to_string(),
            _ => phase.to_string(),
        };
        println!(
            "{:<id_width$}  {:<name_width$}  {:<ns_width$}  {}",
            sandbox.id, sandbox.name, sandbox.namespace, phase_colored,
        );
    }

    Ok(())
}

/// Delete a sandbox by id.
pub async fn sandbox_delete(server: &str, ids: &[String], tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    for id in ids {
        let response = client
            .delete_sandbox(DeleteSandboxRequest { id: id.clone() })
            .await
            .into_diagnostic()?;

        let deleted = response.into_inner().deleted;
        if deleted {
            println!("{} Deleted sandbox {id}", "✓".green().bold());
        } else {
            println!("{} Sandbox {id} not found", "!".yellow());
        }
    }

    Ok(())
}

pub async fn inference_route_create(
    server: &str,
    routing_hint: &str,
    base_url: &str,
    protocol: &str,
    api_key: &str,
    model_id: &str,
    enabled: bool,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_inference_client(server, tls).await?;
    let response = client
        .create_inference_route(CreateInferenceRouteRequest {
            route: Some(InferenceRouteSpec {
                routing_hint: routing_hint.to_string(),
                base_url: base_url.to_string(),
                protocol: protocol.to_string(),
                api_key: api_key.to_string(),
                model_id: model_id.to_string(),
                enabled,
            }),
        })
        .await
        .into_diagnostic()?;

    if let Some(route) = response.into_inner().route {
        println!("{} Created route {}", "✓".green().bold(), route.id);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn inference_route_update(
    server: &str,
    id: &str,
    routing_hint: &str,
    base_url: &str,
    protocol: &str,
    api_key: &str,
    model_id: &str,
    enabled: bool,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_inference_client(server, tls).await?;
    let response = client
        .update_inference_route(UpdateInferenceRouteRequest {
            id: id.to_string(),
            route: Some(InferenceRouteSpec {
                routing_hint: routing_hint.to_string(),
                base_url: base_url.to_string(),
                protocol: protocol.to_string(),
                api_key: api_key.to_string(),
                model_id: model_id.to_string(),
                enabled,
            }),
        })
        .await
        .into_diagnostic()?;

    if let Some(route) = response.into_inner().route {
        println!("{} Updated route {}", "✓".green().bold(), route.id);
    }
    Ok(())
}

pub async fn inference_route_delete(server: &str, ids: &[String], tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_inference_client(server, tls).await?;
    for id in ids {
        let response = client
            .delete_inference_route(DeleteInferenceRouteRequest { id: id.clone() })
            .await
            .into_diagnostic()?;
        if response.into_inner().deleted {
            println!("{} Deleted route {id}", "✓".green().bold());
        } else {
            println!("{} Route {id} not found", "!".yellow());
        }
    }
    Ok(())
}

pub async fn inference_route_list(
    server: &str,
    limit: u32,
    offset: u32,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_inference_client(server, tls).await?;
    let response = client
        .list_inference_routes(ListInferenceRoutesRequest { limit, offset })
        .await
        .into_diagnostic()?;
    let routes = response.into_inner().routes;

    if routes.is_empty() {
        println!("No inference routes found");
        return Ok(());
    }

    println!(
        "{:<36}  {:<16}  {:<40}  {:<30}  {:<8}",
        "ID".bold(),
        "HINT".bold(),
        "BASE URL".bold(),
        "MODEL".bold(),
        "ENABLED".bold()
    );
    for route in routes {
        print_route_row(&route);
    }

    Ok(())
}

fn print_route_row(route: &InferenceRoute) {
    let Some(spec) = route.spec.as_ref() else {
        println!(
            "{:<36}  {:<16}  {:<40}  {:<30}  {:<8}",
            route.id, "<missing>", "", "", "false"
        );
        return;
    };
    println!(
        "{:<36}  {:<16}  {:<40}  {:<30}  {:<8}",
        route.id, spec.routing_hint, spec.base_url, spec.model_id, spec.enabled
    );
}

fn git_repo_root() -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .into_diagnostic()
        .wrap_err("failed to run git rev-parse")?;

    if !output.status.success() {
        return Err(miette::miette!(
            "git rev-parse --show-toplevel failed with status {}",
            output.status
        ));
    }

    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if root.is_empty() {
        return Err(miette::miette!(
            "git rev-parse returned empty repository root"
        ));
    }

    Ok(PathBuf::from(root))
}

fn git_sync_files(repo_root: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args(["ls-files", "-co", "--exclude-standard", "-z"])
        .current_dir(repo_root)
        .output()
        .into_diagnostic()
        .wrap_err("failed to run git ls-files")?;

    if !output.status.success() {
        return Err(miette::miette!(
            "git ls-files failed with status {}",
            output.status
        ));
    }

    let mut files = Vec::new();
    for entry in output.stdout.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        let path = String::from_utf8_lossy(entry).to_string();
        files.push(path);
    }

    Ok(files)
}
