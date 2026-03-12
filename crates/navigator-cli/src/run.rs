// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI command implementations.

use crate::tls::{
    TlsOptions, build_rustls_config, grpc_client, grpc_inference_client, require_tls_materials,
};
use bytes::Bytes;
use dialoguer::{Confirm, Select, theme::ColorfulTheme};
use futures::StreamExt;
use http_body_util::Full;
use hyper::{Request, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use miette::{IntoDiagnostic, Result, WrapErr};
use navigator_bootstrap::{
    DeployOptions, GatewayMetadata, RemoteOptions, clear_active_gateway, container_name,
    get_gateway_metadata, list_gateways, load_active_gateway, remove_gateway_metadata,
    save_active_gateway, save_last_sandbox, store_gateway_metadata,
};
use navigator_core::proto::{
    CreateProviderRequest, CreateSandboxRequest, DeleteProviderRequest, DeleteSandboxRequest,
    GetClusterInferenceRequest, GetProviderRequest, GetSandboxLogsRequest,
    GetSandboxPolicyStatusRequest, GetSandboxRequest, HealthRequest, ListProvidersRequest,
    ListSandboxPoliciesRequest, ListSandboxesRequest, PolicyStatus, Provider, Sandbox,
    SandboxPhase, SandboxPolicy, SandboxSpec, SandboxTemplate, SetClusterInferenceRequest,
    UpdateProviderRequest, UpdateSandboxPolicyRequest, WatchSandboxRequest,
};
use navigator_providers::{
    ProviderRegistry, detect_provider_from_command, normalize_provider_type,
};
use owo_colors::OwoColorize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tonic::Code;

// Re-export SSH functions for backward compatibility
pub use crate::ssh::{Editor, print_ssh_config};
pub use crate::ssh::{
    sandbox_connect, sandbox_connect_editor, sandbox_exec, sandbox_forward, sandbox_ssh_proxy,
    sandbox_ssh_proxy_by_name, sandbox_sync_down, sandbox_sync_up, sandbox_sync_up_files,
};
pub use navigator_core::forward::{list_forwards, stop_forward, stop_forwards_for_sandbox};

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

/// Format milliseconds since Unix epoch as a `YYYY-MM-DD HH:MM:SS` UTC string.
fn format_epoch_ms(ms: i64) -> String {
    use std::time::UNIX_EPOCH;

    let Ok(ms_u64) = u64::try_from(ms) else {
        return "-".to_string();
    };
    let Ok(time) = UNIX_EPOCH
        .checked_add(Duration::from_millis(ms_u64))
        .ok_or(())
    else {
        return "-".to_string();
    };
    let Ok(dur) = time.duration_since(UNIX_EPOCH) else {
        return "-".to_string();
    };

    let secs = dur.as_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Convert days since epoch to year-month-day using a basic civil calendar algorithm.
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {hours:02}:{minutes:02}:{seconds:02}")
}

/// Convert days since 1970-01-01 to (year, month, day).
/// Algorithm from Howard Hinnant's `chrono`-compatible date library.
fn civil_from_days(days: u64) -> (i64, u64, u64) {
    let z = days.cast_signed() + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097).cast_unsigned();
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe.cast_signed() + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Known provisioning steps derived from Kubernetes events and sandbox lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProvisioningStep {
    /// Sandbox CRD created, waiting for pod to be scheduled.
    RequestingSandbox,
    /// Pulling the sandbox container image (the user-facing image, not init containers).
    PullingSandboxImage,
    /// Container is starting up.
    StartingSandbox,
}

impl ProvisioningStep {
    /// Human-readable label for a completed step.
    fn completed_label(self) -> &'static str {
        match self {
            Self::RequestingSandbox => "Sandbox allocated",
            Self::PullingSandboxImage => "Image pulled",
            Self::StartingSandbox => "Sandbox ready",
        }
    }

    /// Human-readable label for an in-progress step (shown on the spinner).
    fn active_label(self) -> &'static str {
        match self {
            Self::RequestingSandbox => "Requesting sandbox...",
            Self::PullingSandboxImage => "Pulling image...",
            Self::StartingSandbox => "Starting sandbox...",
        }
    }
}

/// Kubernetes event reason codes we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KubeEventReason {
    Scheduled,
    Pulling,
    Pulled,
    Started,
}

/// Map a Kubernetes event reason string to an enum.
fn parse_kube_event_reason(reason: &str) -> Option<KubeEventReason> {
    match reason {
        "Scheduled" => Some(KubeEventReason::Scheduled),
        "Pulling" => Some(KubeEventReason::Pulling),
        "Pulled" => Some(KubeEventReason::Pulled),
        "Started" => Some(KubeEventReason::Started),
        _ => None,
    }
}

/// Live-updating display showing a provisioning step checklist with spinner.
///
/// Completed steps are printed as static `✓ Step` lines.  The current
/// in-progress step is shown on a spinner with elapsed time.
struct ProvisioningDisplay {
    mp: MultiProgress,
    spinner: ProgressBar,
    /// Blank line below the spinner so progress doesn't sit flush against
    /// the bottom of the terminal.
    spacer: ProgressBar,
    /// Steps that have been completed, in order.
    completed_steps: Vec<ProvisioningStep>,
    /// Progress bars for completed steps (so they can be cleared).
    completed_bars: Vec<ProgressBar>,
    /// The currently active step label (shown on the spinner).
    active_label: String,
    /// Detail text shown next to the active step (e.g. image name).
    active_detail: String,
    /// When the current active step started (for elapsed time).
    step_start: Instant,
}

impl ProvisioningDisplay {
    fn new() -> Self {
        let mp = MultiProgress::new();

        let spinner = mp.add(ProgressBar::new_spinner());
        spinner.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg} ({elapsed})")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        spinner.enable_steady_tick(Duration::from_millis(120));

        // Always keep a blank line below the spinner so the progress area
        // doesn't sit flush against the bottom of the terminal.
        let spacer = mp.add(ProgressBar::new(0));
        spacer.set_style(
            ProgressStyle::with_template("{msg}").unwrap_or_else(|_| ProgressStyle::default_bar()),
        );
        spacer.set_message("");

        let now = Instant::now();
        Self {
            mp,
            spinner,
            spacer,
            completed_steps: Vec::new(),
            completed_bars: Vec::new(),
            active_label: ProvisioningStep::RequestingSandbox
                .active_label()
                .to_string(),
            active_detail: String::new(),
            step_start: now,
        }
    }

    /// Record a completed provisioning step.
    ///
    /// The step is printed as a static `✓` line and the spinner advances
    /// to the next expected state.
    fn complete_step(&mut self, step: ProvisioningStep) {
        self.complete_step_with_label(step, step.completed_label());
    }

    /// Record a completed provisioning step with a custom label.
    fn complete_step_with_label(&mut self, step: ProvisioningStep, label: &str) {
        // Don't duplicate steps we've already printed.
        if self.completed_steps.contains(&step) {
            return;
        }
        self.completed_steps.push(step);

        let elapsed = self.step_start.elapsed();
        let elapsed_str = format_elapsed(elapsed);

        // Use a progress bar instead of println so we can clear it later.
        let bar = self.mp.insert_before(&self.spinner, ProgressBar::new(0));
        bar.set_style(
            ProgressStyle::with_template("{msg}").unwrap_or_else(|_| ProgressStyle::default_bar()),
        );
        bar.set_message(format!(
            "{} {} {}",
            "\u{2713}".green().bold(),
            label,
            elapsed_str.dimmed()
        ));
        bar.finish();
        self.completed_bars.push(bar);

        // Reset step timer for the next step.
        self.step_start = Instant::now();
        self.spinner.reset_elapsed();
        self.active_detail.clear();
    }

    /// Set the active (in-progress) step shown on the spinner.
    fn set_active(&mut self, label: &str) {
        self.active_label = label.to_string();
        self.active_detail.clear();
        // Reset the spinner's elapsed time for the new step.
        self.spinner.reset_elapsed();
        self.step_start = Instant::now();
        self.update_spinner();
    }

    /// Set the active step from a known provisioning step enum.
    fn set_active_step(&mut self, step: ProvisioningStep) {
        self.set_active(step.active_label());
    }

    /// Set detail text shown alongside the active step (e.g. image name).
    fn set_active_detail(&mut self, detail: &str) {
        self.active_detail = detail.to_string();
        self.update_spinner();
    }

    fn update_spinner(&self) {
        let msg = if self.active_detail.is_empty() {
            self.active_label.clone()
        } else {
            format!("{} {}", self.active_label, self.active_detail.dimmed())
        };
        self.spinner.set_message(msg);
    }

    /// Finish with an error message shown on the last step line.
    fn finish_error(&self, msg: &str) {
        let _ = self
            .mp
            .println(format!("{} {}", "\u{2717}".red().bold(), msg.red()));
        self.spinner.finish_and_clear();
    }

    /// Print a line above the progress bars (for static header content).
    fn println(&self, msg: &str) {
        let _ = self.mp.println(msg);
    }

    /// Return a description of the current active step for error messages.
    fn current_step_description(&self) -> &str {
        &self.active_label
    }

    /// Clear all progress output (spinner, spacer, and completed step lines).
    fn clear(&mut self) {
        self.spacer.finish_and_clear();
        self.spinner.finish_and_clear();
        for bar in &self.completed_bars {
            bar.finish_and_clear();
        }
    }
}

/// Format a duration as a compact elapsed time string, e.g. `(3s)` or `(1m 12s)`.
fn format_elapsed(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("({secs}s)")
    } else {
        let mins = secs / 60;
        let rem = secs % 60;
        format!("({mins}m {rem}s)")
    }
}

/// Format a total elapsed time for non-interactive mode timestamps.
fn format_timestamp(d: Duration) -> String {
    let secs = d.as_secs_f64();
    format!("[{secs:.1}s]")
}

/// Extract image size in bytes from a Kubernetes Pulled event message.
/// Example: "Successfully pulled image ... Image size: 620405524 bytes."
fn extract_image_size(message: &str) -> Option<u64> {
    let size_prefix = "Image size: ";
    let start = message.find(size_prefix)? + size_prefix.len();
    let rest = &message[start..];
    let end = rest.find(' ')?;
    rest[..end].parse().ok()
}

/// Format bytes as a human-readable string (e.g., "620 MB").
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{} MB", bytes / MB)
    } else if bytes >= KB {
        format!("{} KB", bytes / KB)
    } else {
        format!("{} B", bytes)
    }
}

fn print_sandbox_header(sandbox: &Sandbox, display: Option<&ProvisioningDisplay>) {
    let lines = [
        String::new(),
        format!(
            "{} {}",
            "Created sandbox:".cyan().bold(),
            sandbox.name.bold()
        ),
        String::new(),
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

struct GatewayDeployLogPanel {
    mp: MultiProgress,
    status: String,
    progress: Option<String>,
    current_step: Option<String>,
    spinner: ProgressBar,
    /// Blank line below the spinner so progress doesn't sit flush against the
    /// bottom of the terminal.
    spacer: ProgressBar,
    completed_steps: Vec<ProgressBar>,
    top_border: Option<ProgressBar>,
    log_lines: Vec<ProgressBar>,
    bottom_border: Option<ProgressBar>,
    buffer: VecDeque<String>,
}

impl GatewayDeployLogPanel {
    fn new(_name: &str, _location: &str) -> Self {
        let mp = MultiProgress::new();

        let spinner = mp.add(ProgressBar::new_spinner());
        spinner.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        spinner.enable_steady_tick(Duration::from_millis(120));

        // Keep a blank line below the spinner so it doesn't sit flush
        // against the bottom of the terminal.
        let spacer = mp.add(ProgressBar::new(0));
        spacer.set_style(
            ProgressStyle::with_template("{msg}").unwrap_or_else(|_| ProgressStyle::default_bar()),
        );
        spacer.set_message("");

        let panel = Self {
            mp,
            status: "Starting".to_string(),
            progress: None,
            current_step: None,
            spinner,
            spacer,
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

        if let Some(detail) = line.strip_prefix("[progress] ") {
            self.handle_progress(detail.to_string());
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
            self.handle_progress(status);
            return;
        }

        if let Some(previous_step) = self.current_step.replace(status.clone()) {
            self.push_completed_step(&previous_step, true);
        }

        self.status = status;
        self.progress = None;
        self.update_spinner_message();
    }

    fn handle_progress(&mut self, detail: String) {
        self.progress = Some(detail);
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
            horizontal_rule(Some("Gateway Logs"), width)
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
        let msg = if let Some(detail) = &self.progress {
            format!("{} ({})", self.status, detail.dimmed())
        } else {
            self.status.clone()
        };
        self.spinner.set_message(msg);
    }

    fn finish_success(&mut self) {
        if let Some(step) = self.current_step.take() {
            self.push_completed_step(&step, true);
        }
        // Keep completed step checkmarks visible, clear the log panel.
        for bar in &self.completed_steps {
            bar.finish();
        }
        self.clear_log_panel();
        self.spinner.finish_and_clear();
        self.spacer.finish_and_clear();
    }

    fn finish_failure(&mut self) {
        if let Some(step) = self.current_step.take() {
            self.push_completed_step(&step, false);
        }
        // On failure, preserve everything (including logs) for debugging.
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
        self.spinner.finish_and_clear();
        self.spacer.finish_and_clear();
    }

    /// Clear the container log panel from the terminal output.
    fn clear_log_panel(&self) {
        if let Some(top_border) = &self.top_border {
            top_border.finish_and_clear();
        }
        for bar in &self.log_lines {
            bar.finish_and_clear();
        }
        if let Some(bottom_border) = &self.bottom_border {
            bottom_border.finish_and_clear();
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

/// Show gateway status.
#[allow(clippy::branches_sharing_code)]
pub async fn gateway_status(gateway_name: &str, server: &str, tls: &TlsOptions) -> Result<()> {
    println!("{}", "Server Status".cyan().bold());
    println!();
    println!("  {} {}", "Gateway:".dimmed(), gateway_name);
    println!("  {} {}", "Server:".dimmed(), server);
    if tls.is_bearer_auth() {
        println!("  {} Edge (bearer token)", "Auth:".dimmed());
    }

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

/// Set the active gateway.
pub fn gateway_use(name: &str) -> Result<()> {
    // Verify the gateway exists
    get_gateway_metadata(name).ok_or_else(|| {
        miette::miette!(
            "No gateway metadata found for '{name}'.\n\
              Deploy a gateway first with: openshell gateway start --name {name}\n\
              Or list available gateways: openshell gateway select"
        )
    })?;

    save_active_gateway(name)?;
    eprintln!("{} Active gateway set to '{name}'", "✓".green().bold());
    Ok(())
}

pub fn gateway_select(name: Option<&str>, gateway_flag: &Option<String>) -> Result<()> {
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    gateway_select_with(name, gateway_flag, interactive, |gateways, default| {
        let prompt = format!(
            "Select a gateway\n{}",
            format_gateway_select_header(gateways)
        );
        let items = format_gateway_select_items(gateways);
        Select::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .items(&items)
            .default(default)
            .report(false)
            .interact_opt()
            .into_diagnostic()
            .map(|selection| selection.map(|index| gateways[index].name.clone()))
    })
}

fn format_gateway_select_header(gateways: &[GatewayMetadata]) -> String {
    let (name_width, endpoint_width) = gateway_select_column_widths(gateways);
    format!(
        "  {:<name_width$}  {:<endpoint_width$}  {}",
        "NAME".bold(),
        "ENDPOINT".bold(),
        "TYPE".bold(),
    )
}

fn format_gateway_select_items(gateways: &[GatewayMetadata]) -> Vec<String> {
    let (name_width, endpoint_width) = gateway_select_column_widths(gateways);

    gateways
        .iter()
        .map(|gateway| {
            format!(
                "{:<name_width$}  {:<endpoint_width$}  {}",
                gateway.name,
                gateway.gateway_endpoint,
                gateway_type_label(gateway),
            )
        })
        .collect()
}

fn gateway_select_column_widths(gateways: &[GatewayMetadata]) -> (usize, usize) {
    let name_width = gateways
        .iter()
        .map(|gateway| gateway.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let endpoint_width = gateways
        .iter()
        .map(|gateway| gateway.gateway_endpoint.len())
        .max()
        .unwrap_or(8)
        .max(8);

    (name_width, endpoint_width)
}

fn gateway_type_label(gateway: &GatewayMetadata) -> &'static str {
    match gateway.auth_mode.as_deref() {
        Some("cloudflare_jwt") => "edge",
        _ if gateway.is_remote => "remote",
        _ => "local",
    }
}

fn gateway_select_with<F>(
    name: Option<&str>,
    gateway_flag: &Option<String>,
    interactive: bool,
    choose_gateway: F,
) -> Result<()>
where
    F: FnOnce(&[GatewayMetadata], usize) -> Result<Option<String>>,
{
    if let Some(name) = name {
        return gateway_use(name);
    }

    let gateways = list_gateways()?;
    if gateways.is_empty() || !interactive {
        gateway_list(gateway_flag)?;
        if !gateways.is_empty() {
            eprintln!();
            eprintln!(
                "Select a gateway with: {}",
                "openshell gateway select <name>".dimmed()
            );
        }
        return Ok(());
    }

    let active = gateway_flag.clone().or_else(load_active_gateway);
    let default = active
        .as_deref()
        .and_then(|name| gateways.iter().position(|gateway| gateway.name == name))
        .unwrap_or(0);

    if let Some(name) = choose_gateway(&gateways, default)? {
        gateway_use(&name)?;
    } else {
        eprintln!("{} Gateway selection cancelled", "!".yellow());
    }

    Ok(())
}

/// Register an external edge-authenticated gateway.
///
/// Creates local metadata for the given endpoint so it appears in
/// `gateway select`. When `no_auth` is false, opens a browser for
/// authentication and stores the bearer token locally.
pub async fn gateway_add(endpoint: &str, name: Option<&str>, no_auth: bool) -> Result<()> {
    // Normalise the endpoint: ensure it has a scheme.
    let endpoint = if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("https://{endpoint}")
    };

    // Derive a gateway name from the hostname when none is provided.
    let derived_name;
    let name = if let Some(n) = name {
        n
    } else {
        // Parse out just the host portion of the URL.
        derived_name = url::Url::parse(&endpoint)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| endpoint.clone());
        &derived_name
    };

    // Build metadata for an edge-authenticated remote gateway.
    let metadata = GatewayMetadata {
        name: name.to_string(),
        gateway_endpoint: endpoint.clone(),
        is_remote: true,
        gateway_port: 0,
        remote_host: None,
        resolved_host: None,
        auth_mode: Some("cloudflare_jwt".to_string()),
        edge_team_domain: None,
        edge_auth_url: None,
    };

    store_gateway_metadata(name, &metadata)?;
    save_active_gateway(name)?;

    if no_auth {
        eprintln!(
            "{} Gateway '{}' added and set as active",
            "✓".green().bold(),
            name,
        );
        eprintln!("  {} {}", "Endpoint:".dimmed(), endpoint,);
        eprintln!();
        eprintln!("Authenticate with: {}", "openshell gateway login".dimmed(),);
        return Ok(());
    }

    // Run the browser-based auth flow.
    eprintln!(
        "{} Gateway '{}' added and set as active",
        "✓".green().bold(),
        name,
    );
    eprintln!("  {} {}", "Endpoint:".dimmed(), endpoint,);
    eprintln!();

    match crate::auth::browser_auth_flow(&endpoint).await {
        Ok(token) => {
            navigator_bootstrap::edge_token::store_edge_token(name, &token)?;
            eprintln!("{} Authenticated successfully", "✓".green().bold(),);
        }
        Err(e) => {
            eprintln!("{} Authentication skipped: {e}", "!".yellow(),);
            eprintln!(
                "  Authenticate later with: {}",
                "openshell gateway login".dimmed(),
            );
        }
    }

    Ok(())
}

/// Re-authenticate with an edge-authenticated gateway.
///
/// Opens a browser for edge proxy login and stores the updated token.
pub async fn gateway_login(name: &str) -> Result<()> {
    let metadata = navigator_bootstrap::load_gateway_metadata(name).map_err(|_| {
        miette::miette!(
            "Unknown gateway '{name}'.\n\
             List available gateways: openshell gateway select"
        )
    })?;

    if metadata.auth_mode.as_deref() != Some("cloudflare_jwt") {
        return Err(miette::miette!(
            "Gateway '{name}' does not use edge authentication.\n\
             Only edge-authenticated gateways support browser login."
        ));
    }

    let token = crate::auth::browser_auth_flow(&metadata.gateway_endpoint).await?;
    navigator_bootstrap::edge_token::store_edge_token(name, &token)?;

    eprintln!("{} Authenticated to gateway '{name}'", "✓".green().bold(),);

    Ok(())
}

/// List all provisioned gateways.
pub fn gateway_list(gateway_flag: &Option<String>) -> Result<()> {
    let gateways = list_gateways()?;
    let active = gateway_flag.clone().or_else(load_active_gateway);

    if gateways.is_empty() {
        println!("No gateways found.");
        println!();
        println!(
            "Deploy a gateway with: {}",
            "openshell gateway start".dimmed()
        );
        return Ok(());
    }

    // Calculate column widths
    let name_width = gateways
        .iter()
        .map(|g| g.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let endpoint_width = gateways
        .iter()
        .map(|g| g.gateway_endpoint.len())
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
    for gateway in &gateways {
        let is_active = active.as_deref() == Some(&gateway.name);
        let marker = if is_active { "*" } else { " " };
        let gateway_type = gateway_type_label(gateway);
        let line = format!(
            "{marker} {:<name_width$}  {:<endpoint_width$}  {gateway_type}",
            gateway.name, gateway.gateway_endpoint,
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

    let scheme = uri.scheme_str().unwrap_or("https");
    let https = if scheme.eq_ignore_ascii_case("http") || tls.is_bearer_auth() {
        HttpsConnectorBuilder::new()
            .with_native_roots()
            .into_diagnostic()?
            .https_or_http()
            .enable_http1()
            .build()
    } else {
        let materials = require_tls_materials(server, tls)?;
        let tls_config = build_rustls_config(&materials)?;
        HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only()
            .enable_http1()
            .build()
    };
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
    let mut req_builder = Request::builder().method("GET").uri(uri);
    // Inject edge authentication headers when an edge token is configured.
    if let Some(ref token) = tls.edge_token {
        req_builder = req_builder
            .header("Cf-Access-Jwt-Assertion", token.as_str())
            .header("Cookie", format!("CF_Authorization={token}"));
    }
    let req = req_builder
        .body(Full::new(Bytes::new()))
        .into_diagnostic()?;
    let resp = client.request(req).await.into_diagnostic()?;
    Ok(Some(resp.status()))
}

/// Prompt the user to choose how to handle an existing gateway deployment.
///
/// Returns `true` to recreate (destroy and start fresh), `false` to reuse.
fn prompt_existing_gateway(
    name: &str,
    info: &navigator_bootstrap::ExistingGatewayInfo,
) -> Result<bool> {
    let status = if info.container_running {
        "running"
    } else if info.container_exists {
        "stopped"
    } else {
        "volume only"
    };

    eprintln!("• Existing gateway '{name}' detected ({status})");
    if let Some(image) = &info.container_image {
        eprintln!("  {} {}", "Image:".dimmed(), image);
    }
    eprintln!();

    eprint!("Destroy and recreate gateway from scratch? [y/N] ");
    std::io::stderr().flush().ok();

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .into_diagnostic()
        .wrap_err("failed to read user input")?;

    let choice = input.trim().to_lowercase();
    Ok(choice == "y" || choice == "yes")
}

/// Deploy a gateway with the rich progress panel (interactive) or simple
/// logging (non-interactive). Returns the [`GatewayHandle`] on success.
///
/// This is the shared deploy UX used by both `gateway start` and
/// the auto-bootstrap path in `sandbox create`.
pub(crate) async fn deploy_gateway_with_panel(
    options: DeployOptions,
    name: &str,
    location: &str,
) -> Result<navigator_bootstrap::GatewayHandle> {
    let interactive = std::io::stderr().is_terminal();

    if interactive {
        let panel = std::sync::Arc::new(std::sync::Mutex::new(GatewayDeployLogPanel::new(
            name, location,
        )));
        let panel_clone = std::sync::Arc::clone(&panel);
        let result = navigator_bootstrap::deploy_gateway_with_logs(options, move |line| {
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
                    "Gateway failed:".red().bold(),
                );
                // Try to diagnose the failure and provide guidance
                let err_str = format!("{err:?}");
                if let Some(diagnosis) =
                    navigator_bootstrap::errors::diagnose_failure(name, &err_str, None)
                {
                    print_failure_diagnosis(&diagnosis);
                }
                Err(err)
            }
        }
    } else {
        eprintln!("Deploying {location} gateway {name}...");
        let handle = navigator_bootstrap::deploy_gateway_with_logs(options, |line| {
            if let Some(status) = line.strip_prefix("[status] ") {
                eprintln!("  {status}");
            } else if line.strip_prefix("[progress] ").is_some() {
                // Sub-step progress: skip in non-interactive mode
            } else {
                eprintln!("  {line}");
            }
        })
        .await?;
        eprintln!("Gateway {name} ready.");
        Ok(handle)
    }
}

/// Print post-deploy summary showing the gateway name and endpoint.
pub(crate) fn print_deploy_summary(name: &str, handle: &navigator_bootstrap::GatewayHandle) {
    eprintln!();
    eprintln!("{} Gateway ready", "✓".green().bold());
    eprintln!();
    eprintln!("  {} {name}", "Name:".bold());
    eprintln!("  {} {}", "Endpoint:".bold(), handle.gateway_endpoint());
    eprintln!();
}

/// Print a user-friendly failure diagnosis with recovery steps.
fn print_failure_diagnosis(diagnosis: &navigator_bootstrap::errors::GatewayFailureDiagnosis) {
    eprintln!();
    eprintln!("{}", diagnosis.summary.yellow().bold());
    eprintln!();
    eprintln!("  {}", diagnosis.explanation);
    eprintln!();

    if !diagnosis.recovery_steps.is_empty() {
        eprintln!("  {}:", "To fix".bold());
        for (i, step) in diagnosis.recovery_steps.iter().enumerate() {
            eprintln!();
            eprintln!("  {}. {}", i + 1, step.description);
            if let Some(cmd) = &step.command {
                eprintln!();
                eprintln!("     {}", cmd.cyan());
            }
        }
        eprintln!();
    }
}

/// Provision or start a gateway (local or remote).
pub async fn gateway_admin_deploy(
    name: &str,
    remote: Option<&str>,
    ssh_key: Option<&str>,
    port: u16,
    gateway_host: Option<&str>,
    recreate: bool,
    disable_tls: bool,
    disable_gateway_auth: bool,
    registry_token: Option<&str>,
    gpu: bool,
) -> Result<()> {
    let location = if remote.is_some() { "remote" } else { "local" };

    let mut options = DeployOptions::new(name)
        .with_port(port)
        .with_disable_tls(disable_tls)
        .with_disable_gateway_auth(disable_gateway_auth)
        .with_gpu(gpu);
    if let Some(dest) = remote {
        let mut remote_opts = RemoteOptions::new(dest);
        if let Some(key) = ssh_key {
            remote_opts = remote_opts.with_ssh_key(key);
        }
        options = options.with_remote(remote_opts);
    }
    if let Some(host) = gateway_host {
        options = options.with_gateway_host(host);
    }
    if let Some(token) = registry_token {
        options = options.with_registry_token(token);
    }

    let interactive = std::io::stderr().is_terminal();

    // Check for existing gateway and prompt user if found.
    // --recreate skips the prompt and always destroys.
    {
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
            let should_recreate = if recreate {
                true
            } else if interactive {
                prompt_existing_gateway(name, &info)?
            } else {
                false // non-interactive without --recreate: silently reuse
            };

            if should_recreate {
                eprintln!("• Destroying existing gateway...");
                let handle =
                    navigator_bootstrap::gateway_handle(name, remote_opts.as_ref()).await?;
                handle.destroy().await?;
                eprintln!("{} Gateway destroyed, starting fresh.", "✓".green().bold());
                eprintln!();
            }
            // If reusing, the deploy flow will handle stale node cleanup automatically
        }
    }

    let handle = deploy_gateway_with_panel(options, name, location).await?;

    print_deploy_summary(name, &handle);

    // Auto-activate: set this gateway as the active gateway.
    save_active_gateway(name)?;
    eprintln!("{} Active gateway set to '{name}'", "✓".green().bold());

    Ok(())
}

/// Resolve the remote SSH destination for a gateway.
///
/// If `remote_override` is provided, use it. Otherwise, look up the remote
/// host from stored gateway metadata.
enum GatewayControlTarget {
    Local,
    Remote(String),
    ExternalRegistration,
}

fn resolve_gateway_control_target(
    name: &str,
    remote_override: Option<&str>,
) -> GatewayControlTarget {
    resolve_gateway_control_target_from(get_gateway_metadata(name), remote_override)
}

fn resolve_gateway_control_target_from(
    metadata: Option<GatewayMetadata>,
    remote_override: Option<&str>,
) -> GatewayControlTarget {
    if let Some(r) = remote_override {
        return GatewayControlTarget::Remote(r.to_string());
    }

    match metadata {
        Some(metadata) if metadata.is_remote => metadata.remote_host.map_or(
            GatewayControlTarget::ExternalRegistration,
            GatewayControlTarget::Remote,
        ),
        _ => GatewayControlTarget::Local,
    }
}

fn gateway_control_target_options(
    name: &str,
    remote_override: Option<&str>,
    ssh_key: Option<&str>,
) -> Result<Option<RemoteOptions>> {
    match resolve_gateway_control_target(name, remote_override) {
        GatewayControlTarget::Local => Ok(None),
        GatewayControlTarget::Remote(dest) => {
            let mut opts = RemoteOptions::new(&dest);
            if let Some(key) = ssh_key {
                opts = opts.with_ssh_key(key);
            }
            Ok(Some(opts))
        }
        GatewayControlTarget::ExternalRegistration => Err(miette::miette!(
            "Gateway '{name}' is an external registration, not a managed Docker gateway.\n\
             `openshell gateway stop` is only supported for local or SSH-managed gateways."
        )),
    }
}

fn remove_gateway_registration(name: &str) {
    if let Err(err) = navigator_bootstrap::edge_token::remove_edge_token(name) {
        tracing::debug!("failed to remove edge token: {err}");
    }
    if let Err(err) = remove_gateway_metadata(name) {
        tracing::debug!("failed to remove gateway metadata: {err}");
    }
    if load_active_gateway().as_deref() == Some(name)
        && let Err(err) = clear_active_gateway()
    {
        tracing::debug!("failed to clear active gateway: {err}");
    }
}

fn cleanup_gateway_metadata(name: &str) {
    if let Err(err) = navigator_bootstrap::edge_token::remove_edge_token(name) {
        tracing::debug!("failed to remove edge token: {err}");
    }
    if let Err(err) = remove_gateway_metadata(name) {
        tracing::debug!("failed to remove gateway metadata: {err}");
    }
    if load_active_gateway().as_deref() == Some(name)
        && let Err(err) = clear_active_gateway()
    {
        tracing::debug!("failed to clear active gateway: {err}");
    }
}

/// Stop a gateway.
pub async fn gateway_admin_stop(
    name: &str,
    remote: Option<&str>,
    ssh_key: Option<&str>,
) -> Result<()> {
    let remote_opts = gateway_control_target_options(name, remote, ssh_key)?;

    eprintln!("• Stopping gateway {name}...");
    let handle = navigator_bootstrap::gateway_handle(name, remote_opts.as_ref()).await?;
    handle.stop().await?;
    eprintln!("{} Gateway {name} stopped.", "✓".green().bold());
    Ok(())
}

/// Destroy a gateway and its state.
pub async fn gateway_admin_destroy(
    name: &str,
    remote: Option<&str>,
    ssh_key: Option<&str>,
) -> Result<()> {
    match resolve_gateway_control_target(name, remote) {
        GatewayControlTarget::ExternalRegistration => {
            eprintln!("• Removing gateway registration {name}...");
            remove_gateway_registration(name);
            eprintln!(
                "{} Gateway registration {name} removed.",
                "✓".green().bold()
            );
            Ok(())
        }
        GatewayControlTarget::Local | GatewayControlTarget::Remote(_) => {
            let remote_opts = gateway_control_target_options(name, remote, ssh_key)?;

            eprintln!("• Destroying gateway {name}...");
            let handle = navigator_bootstrap::gateway_handle(name, remote_opts.as_ref()).await?;
            handle.destroy().await?;

            cleanup_gateway_metadata(name);

            eprintln!("{} Gateway {name} destroyed.", "✓".green().bold());
            Ok(())
        }
    }
}

/// Show gateway deployment details.
pub fn gateway_admin_info(name: &str) -> Result<()> {
    let metadata = get_gateway_metadata(name).ok_or_else(|| {
        miette::miette!(
            "No gateway metadata found for '{name}'.\n\
              Deploy a gateway first with: openshell gateway start --name {name}"
        )
    })?;

    println!("{}", "Gateway Info".cyan().bold());
    println!();
    println!("  {} {}", "Gateway:".dimmed(), metadata.name);
    println!(
        "  {} {}",
        "Gateway endpoint:".dimmed(),
        metadata.gateway_endpoint
    );

    if metadata.is_remote {
        if let Some(ref host) = metadata.remote_host {
            println!("  {} {host}", "Remote host:".dimmed());
        } else {
            println!("  {} External registration", "Type:".dimmed());
        }
        if let Some(ref resolved) = metadata.resolved_host {
            println!("  {} {resolved}", "Resolved host:".dimmed());
        }
    }

    Ok(())
}

/// Fetch logs from the gateway Docker container.
///
/// Connects to the Docker daemon (local or remote via SSH) and retrieves
/// logs from the `openshell-cluster-{name}` container.
pub async fn doctor_logs(
    name: &str,
    lines: Option<usize>,
    tail: bool,
    remote: Option<&str>,
    ssh_key: Option<&str>,
) -> Result<()> {
    // Build remote options: explicit --remote flag, or auto-resolve from metadata
    let remote_opts = if let Some(dest) = remote {
        let mut opts = RemoteOptions::new(dest);
        if let Some(key) = ssh_key {
            opts = opts.with_ssh_key(key);
        }
        Some(opts)
    } else if let Some(metadata) = get_gateway_metadata(name)
        && metadata.is_remote
        && let Some(ref host) = metadata.remote_host
    {
        let mut opts = RemoteOptions::new(host.clone());
        if let Some(key) = ssh_key {
            opts = opts.with_ssh_key(key);
        }
        Some(opts)
    } else {
        None
    };

    let stdout = std::io::stdout().lock();
    navigator_bootstrap::gateway_container_logs(remote_opts.as_ref(), name, lines, tail, stdout)
        .await
}

/// Run a command inside the gateway Docker container.
///
/// Spawns `docker exec` (or `ssh <host> docker exec` for remote gateways)
/// as a child process with the user's terminal attached, so interactive
/// tools like `k9s` and `kubectl` work natively.
pub fn doctor_exec(
    name: &str,
    remote: Option<&str>,
    ssh_key: Option<&str>,
    command: &[String],
) -> Result<()> {
    let container = container_name(name);
    let is_tty = std::io::stdin().is_terminal();

    // Wrap the user command with KUBECONFIG set
    let inner_cmd = if command.is_empty() {
        "KUBECONFIG=/etc/rancher/k3s/k3s.yaml sh".to_string()
    } else {
        let escaped: Vec<String> = command.iter().map(|a| shell_escape(a)).collect();
        format!("KUBECONFIG=/etc/rancher/k3s/k3s.yaml {}", escaped.join(" "))
    };

    // Resolve remote destination: explicit --remote flag, or auto-resolve from metadata
    let remote_host = if let Some(dest) = remote {
        Some(dest.to_string())
    } else if let Some(metadata) = get_gateway_metadata(name)
        && metadata.is_remote
    {
        metadata.remote_host.clone()
    } else {
        None
    };

    let mut cmd = if let Some(ref host) = remote_host {
        // Remote: ssh <host> docker exec [-it] <container> sh -lc '<inner_cmd>'
        let mut c = Command::new("ssh");
        if let Some(key) = ssh_key {
            c.args(["-i", key]);
        }
        // -t forces TTY allocation over SSH when we have a local TTY
        if is_tty {
            c.arg("-t");
        }
        c.arg(host);
        c.arg("docker");
        c.arg("exec");
        if is_tty {
            c.args(["-it"]);
        } else {
            c.arg("-i");
        }
        c.args([&container, "sh", "-lc", &inner_cmd]);
        c
    } else {
        // Local: docker exec [-it] <container> sh -lc '<inner_cmd>'
        let mut c = Command::new("docker");
        c.arg("exec");
        if is_tty {
            c.args(["-it"]);
        } else {
            c.arg("-i");
        }
        c.args([&container, "sh", "-lc", &inner_cmd]);
        c
    };

    let status = cmd
        .status()
        .into_diagnostic()
        .wrap_err("failed to execute docker exec")?;

    if !status.success() {
        let code = status.code().unwrap_or(1);
        std::process::exit(code);
    }

    Ok(())
}

/// Print the LLM diagnostic prompt to stdout.
///
/// Outputs a system prompt that a coding agent can use to autonomously
/// diagnose gateway issues using `openshell doctor logs` and
/// `openshell doctor exec`.
pub fn doctor_llm() -> Result<()> {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle
        .write_all(include_bytes!("doctor_llm_prompt.md"))
        .into_diagnostic()
        .wrap_err("failed to write LLM prompt to stdout")?;
    Ok(())
}

/// Shell-escape a single argument for safe inclusion in a `sh -c` string.
fn shell_escape(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    // If the string is clean (alphanumeric, hyphens, underscores, dots, slashes, colons, equals),
    // no quoting needed.
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./,:=@".contains(c))
    {
        return s.to_string();
    }
    // Otherwise, single-quote it (escaping embedded single quotes)
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Create a sandbox when no gateway is configured.
///
/// Offers to bootstrap a new gateway first, then delegates to [`sandbox_create`].
#[allow(clippy::too_many_arguments)]
pub async fn sandbox_create_with_bootstrap(
    name: Option<&str>,
    from: Option<&str>,
    upload: Option<&(String, Option<String>, bool)>,
    keep: bool,
    editor: Option<Editor>,
    remote: Option<&str>,
    ssh_key: Option<&str>,
    providers: &[String],
    policy: Option<&str>,
    forward: Option<u16>,
    command: &[String],
    tty_override: Option<bool>,
    bootstrap_override: Option<bool>,
    auto_providers_override: Option<bool>,
) -> Result<()> {
    if !crate::bootstrap::confirm_bootstrap(bootstrap_override)? {
        return Err(miette::miette!(
            "No active gateway.\n\
             Set one with: openshell gateway select <name>\n\
             Or deploy a new gateway: openshell gateway start"
        ));
    }
    let (tls, server) = crate::bootstrap::run_bootstrap(remote, ssh_key).await?;
    // The bootstrap flow always creates a gateway named "openshell".
    let gateway_name = "openshell";
    sandbox_create(
        &server,
        name,
        from,
        gateway_name,
        upload,
        keep,
        editor,
        remote,
        ssh_key,
        providers,
        policy,
        forward,
        command,
        tty_override,
        bootstrap_override,
        auto_providers_override,
        &tls,
    )
    .await
}

/// Create a sandbox with default settings.
#[allow(clippy::too_many_arguments)]
pub async fn sandbox_create(
    server: &str,
    name: Option<&str>,
    from: Option<&str>,
    gateway_name: &str,
    upload: Option<&(String, Option<String>, bool)>,
    keep: bool,
    editor: Option<Editor>,
    remote: Option<&str>,
    ssh_key: Option<&str>,
    providers: &[String],
    policy: Option<&str>,
    forward: Option<u16>,
    command: &[String],
    tty_override: Option<bool>,
    bootstrap_override: Option<bool>,
    auto_providers_override: Option<bool>,
    tls: &TlsOptions,
) -> Result<()> {
    if editor.is_some() && !command.is_empty() {
        return Err(miette::miette!(
            "--editor cannot be used with a trailing command; use `openshell sandbox connect <name> --editor ...` after the sandbox is ready"
        ));
    }

    // Try connecting to the gateway. If it fails due to an unreachable gateway,
    // offer to bootstrap a local one and retry.
    let (mut client, effective_server, effective_tls) = match grpc_client(server, tls).await {
        Ok(c) => (c, server.to_string(), tls.clone()),
        Err(err) => {
            if !crate::bootstrap::should_attempt_bootstrap(&err, tls) {
                return Err(err);
            }
            if !crate::bootstrap::confirm_bootstrap(bootstrap_override)? {
                return Err(err);
            }
            let (new_tls, new_server) = crate::bootstrap::run_bootstrap(remote, ssh_key).await?;
            let c = grpc_client(&new_server, &new_tls)
                .await
                .wrap_err("bootstrap succeeded but failed to connect to gateway")?;
            (c, new_server, new_tls)
        }
    };

    // Resolve the --from flag into a container image reference, building from
    // a Dockerfile first if necessary.
    let image: Option<String> = match from {
        Some(val) => {
            let resolved = resolve_from(val)?;
            match resolved {
                ResolvedSource::Image(img) => Some(img),
                ResolvedSource::Dockerfile {
                    dockerfile,
                    context,
                } => {
                    let tag = build_from_dockerfile(&dockerfile, &context, gateway_name).await?;
                    Some(tag)
                }
            }
        }
        None => None,
    };

    let inferred_types: Vec<String> = inferred_provider_type(command).into_iter().collect();
    let configured_providers = ensure_required_providers(
        &mut client,
        providers,
        &inferred_types,
        auto_providers_override,
    )
    .await?;

    let policy = load_sandbox_policy(policy)?;

    let template = image.map(|img| SandboxTemplate {
        image: img,
        ..SandboxTemplate::default()
    });

    let request = CreateSandboxRequest {
        spec: Some(SandboxSpec {
            policy,
            providers: configured_providers,
            template,
            ..SandboxSpec::default()
        }),
        name: name.unwrap_or_default().to_string(),
    };

    let response = client.create_sandbox(request).await.into_diagnostic()?;
    let sandbox = response
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox missing from response"))?;

    let interactive = std::io::stdout().is_terminal();
    let sandbox_name = sandbox.name.clone();

    // Record this sandbox as the last-used for the active gateway.
    if let Some(gateway) = effective_tls.gateway_name() {
        let _ = save_last_sandbox(gateway, &sandbox_name);
    }

    // Set up display — interactive terminals get a step-based checklist with
    // spinners; non-interactive (pipes / CI) get timestamped lines.
    let mut display = if interactive {
        Some(ProvisioningDisplay::new())
    } else {
        None
    };

    // Print header
    print_sandbox_header(&sandbox, display.as_ref());

    // Set initial active step on the spinner.
    if let Some(d) = display.as_mut() {
        d.set_active_step(ProvisioningStep::RequestingSandbox);
    } else {
        let ts = format_timestamp(Duration::ZERO);
        println!("  {} Requesting compute...", ts.dimmed());
    }

    // Non-interactive mode: track start time for timestamps.
    let provision_start = Instant::now();

    // Don't use stop_on_terminal on the server — the Kubernetes CRD may
    // briefly report a stale Ready status before the controller reconciles
    // a newly created sandbox.  Instead we handle termination client-side:
    // we wait until we have observed at least one non-Ready phase followed
    // by Ready (a genuine Provisioning → Ready transition).
    let mut stream = client
        .watch_sandbox(WatchSandboxRequest {
            id: sandbox.id.clone(),
            follow_status: true,
            follow_logs: true,
            follow_events: true,
            log_tail_lines: 200,
            event_tail: 0,
            stop_on_terminal: false,
            log_since_ms: 0,
            log_sources: vec!["gateway".to_string()],
            log_min_level: String::new(),
        })
        .await
        .into_diagnostic()?
        .into_inner();

    let mut last_phase = sandbox.phase;
    let mut last_error_reason = String::new();
    // Track whether we have seen a non-Ready phase during the watch.
    let mut saw_non_ready = SandboxPhase::try_from(sandbox.phase) != Ok(SandboxPhase::Ready);
    let start_time = Instant::now();
    let provision_timeout = Duration::from_secs(120);
    // Track whether we saw the gateway become ready (from log messages).
    let mut saw_gateway_ready = false;

    while let Some(item) = stream.next().await {
        // Check for timeout
        if start_time.elapsed() > provision_timeout {
            if let Some(d) = display.as_mut() {
                let step_desc = d.current_step_description().to_string();
                d.finish_error(&format!(
                    "Timed out after {}s (stuck at: {step_desc})",
                    provision_timeout.as_secs()
                ));
            }
            println!();
            return Err(miette::miette!(
                "sandbox provisioning timed out after {}s",
                provision_timeout.as_secs()
            ));
        }

        let evt = item.into_diagnostic()?;
        match evt.payload {
            Some(navigator_core::proto::sandbox_stream_event::Payload::Sandbox(s)) => {
                let phase = SandboxPhase::try_from(s.phase).unwrap_or(SandboxPhase::Unknown);
                last_phase = s.phase;

                if phase != SandboxPhase::Ready {
                    saw_non_ready = true;
                }

                // Capture error reason from conditions only when phase is Error
                // to avoid showing stale transient error reasons
                if phase == SandboxPhase::Error
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

                // Only accept Ready as terminal after we've observed a
                // non-Ready phase, proving the controller has reconciled.
                if saw_non_ready && phase == SandboxPhase::Ready {
                    if let Some(d) = display.as_mut() {
                        d.clear();
                    }
                    break;
                }
            }
            Some(navigator_core::proto::sandbox_stream_event::Payload::Log(line)) => {
                // Detect gateway readiness from log messages.
                if !saw_gateway_ready && line.message.contains("listening") {
                    saw_gateway_ready = true;
                }
            }
            Some(navigator_core::proto::sandbox_stream_event::Payload::Event(ev)) => {
                // Map Kubernetes events to provisioning steps.
                // We simplify the display to: Sandbox allocated -> Pulling image -> Ready
                // Init container events are ignored; we only show the user's sandbox image.
                if let Some(reason) = parse_kube_event_reason(&ev.reason) {
                    match reason {
                        KubeEventReason::Scheduled => {
                            if let Some(d) = display.as_mut() {
                                d.complete_step_with_label(
                                    ProvisioningStep::RequestingSandbox,
                                    "Sandbox allocated",
                                );
                                d.set_active_step(ProvisioningStep::PullingSandboxImage);
                            } else {
                                let ts = format_timestamp(provision_start.elapsed());
                                println!("{} Sandbox allocated", ts.dimmed());
                            }
                        }
                        KubeEventReason::Pulling => {
                            // Extract image name from the event message.
                            let image_name = ev
                                .message
                                .strip_prefix("Pulling image ")
                                .map_or("", |s| s.trim_matches('"'));
                            // Skip init container image pulls (openshell/sandbox).
                            // Only show progress for the user's sandbox image.
                            let is_init_container_image =
                                image_name.contains("/openshell/sandbox:");
                            if !is_init_container_image {
                                if let Some(d) = display.as_mut() {
                                    d.set_active("Pulling image...");
                                    if !image_name.is_empty() {
                                        d.set_active_detail(image_name);
                                    }
                                } else {
                                    let ts = format_timestamp(provision_start.elapsed());
                                    if image_name.is_empty() {
                                        println!("{} Pulling image...", ts.dimmed());
                                    } else {
                                        println!("{} Pulling image {image_name}", ts.dimmed());
                                    }
                                }
                            }
                        }
                        KubeEventReason::Pulled => {
                            // Skip init container pulls.
                            let is_init_container_image =
                                ev.message.contains("/openshell/sandbox:");
                            if !is_init_container_image {
                                // Extract image size from message like:
                                // "Successfully pulled image ... Image size: 620405524 bytes."
                                let size_label = extract_image_size(&ev.message)
                                    .map(format_bytes)
                                    .unwrap_or_default();
                                let label = if size_label.is_empty() {
                                    "Image pulled".to_string()
                                } else {
                                    format!("Image pulled ({})", size_label)
                                };
                                if let Some(d) = display.as_mut() {
                                    d.complete_step_with_label(
                                        ProvisioningStep::PullingSandboxImage,
                                        &label,
                                    );
                                    d.set_active_step(ProvisioningStep::StartingSandbox);
                                } else {
                                    let ts = format_timestamp(provision_start.elapsed());
                                    println!("{} {}", ts.dimmed(), label);
                                }
                            }
                        }
                        KubeEventReason::Started => {
                            // Started fires for both init and main containers.
                            // Only complete StartingSandbox if we've already completed
                            // PullingSandboxImage (meaning this is the main container starting).
                            if let Some(d) = display.as_mut()
                                && d.completed_steps
                                    .contains(&ProvisioningStep::PullingSandboxImage)
                            {
                                d.complete_step(ProvisioningStep::StartingSandbox);
                            }
                        }
                    }
                } else if let Some(d) = display.as_mut() {
                    // Unknown events: show as detail on the current spinner.
                    if !ev.message.is_empty() {
                        d.set_active_detail(&ev.message);
                    }
                }
            }
            Some(navigator_core::proto::sandbox_stream_event::Payload::Warning(w)) => {
                if let Some(d) = display.as_mut() {
                    d.println(&format!("  {} {}", "!".yellow().bold(), w.message.yellow()));
                } else {
                    let ts = format_timestamp(provision_start.elapsed());
                    eprintln!("  {} {} {}", ts.dimmed(), "WARN".yellow(), w.message);
                }
            }
            None => {}
        }
    }

    // If we exited the loop without hitting the Ready break, finish the display.
    let final_phase = SandboxPhase::try_from(last_phase).unwrap_or(SandboxPhase::Unknown);
    if final_phase != SandboxPhase::Ready
        && let Some(d) = display.as_mut()
    {
        if final_phase == SandboxPhase::Error {
            let msg = if last_error_reason.is_empty() {
                "Sandbox entered error phase".to_string()
            } else {
                format!("Error: {last_error_reason}")
            };
            d.finish_error(&msg);
        } else {
            d.finish_error("Provisioning stream ended unexpectedly");
        }
    }
    drop(display);
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    match final_phase {
        SandboxPhase::Ready => {
            drop(stream);
            drop(client);

            if let Some((local_path, sandbox_path, git_ignore)) = upload {
                let dest = sandbox_path.as_deref().unwrap_or("/sandbox");
                eprintln!("  {} Uploading files to {dest}...", "\u{2022}".dimmed(),);
                let local = Path::new(local_path);
                if *git_ignore && let Ok((base_dir, files)) = git_sync_files(local) {
                    sandbox_sync_up_files(
                        &effective_server,
                        &sandbox_name,
                        &base_dir,
                        &files,
                        dest,
                        &effective_tls,
                    )
                    .await?;
                } else if local.exists() {
                    sandbox_sync_up(
                        &effective_server,
                        &sandbox_name,
                        local,
                        dest,
                        &effective_tls,
                    )
                    .await?;
                }
                eprintln!("  {} Files uploaded", "\u{2713}".green().bold(),);
            }

            // If --forward was requested, start the background port forward
            // *before* running the command so that long-running processes
            // (e.g. `openclaw gateway`) are reachable immediately.
            if let Some(port) = forward {
                sandbox_forward(
                    &effective_server,
                    &sandbox_name,
                    port,
                    true, // background
                    &effective_tls,
                )
                .await?;
                eprintln!(
                    "  {} Forwarding port {port} to sandbox {sandbox_name} in the background\n",
                    "\u{2713}".green().bold(),
                );
                eprintln!("  Access at: http://127.0.0.1:{port}/");
                eprintln!("  Stop with: openshell forward stop {port} {sandbox_name}",);
            }

            if let Some(editor) = editor {
                let ssh_gateway_name = effective_tls.gateway_name().unwrap_or(gateway_name);
                sandbox_connect_editor(
                    &effective_server,
                    ssh_gateway_name,
                    &sandbox_name,
                    editor,
                    &effective_tls,
                )
                .await?;
                return Ok(());
            }

            if command.is_empty() {
                return sandbox_connect(&effective_server, &sandbox_name, &effective_tls).await;
            }

            // Resolve TTY mode: explicit --tty / --no-tty wins, otherwise
            // auto-detect from the local terminal.
            let tty = tty_override.unwrap_or_else(|| {
                std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
            });
            let exec_result = sandbox_exec(
                &effective_server,
                &sandbox_name,
                command,
                tty,
                &effective_tls,
            )
            .await;

            if forward.is_some() {
                exec_result?;
                return Ok(());
            }

            if !interactive
                && !keep
                && let Err(err) = sandbox_delete(
                    &effective_server,
                    std::slice::from_ref(&sandbox_name),
                    false,
                    &effective_tls,
                )
                .await
            {
                if exec_result.is_ok() {
                    return Err(err);
                }
                eprintln!("Failed to delete sandbox {sandbox_name}: {err}");
            }

            exec_result
        }
        SandboxPhase::Error => {
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

/// The default community sandbox registry prefix.
///
/// Bare sandbox names (e.g., `openclaw`) are expanded to
/// `{prefix}/{name}:latest` using this value.  Override with the
/// `OPENSHELL_COMMUNITY_REGISTRY` environment variable.
const DEFAULT_COMMUNITY_REGISTRY: &str = "ghcr.io/nvidia/openshell-community/sandboxes";

/// Resolved source for the `--from` flag on `sandbox create`.
enum ResolvedSource {
    /// A ready-to-use container image reference.
    Image(String),
    /// A Dockerfile that must be built and pushed before creating the sandbox.
    Dockerfile {
        dockerfile: PathBuf,
        context: PathBuf,
    },
}

/// Classify the `--from` value into an image reference or a Dockerfile that
/// needs building.
///
/// Resolution order:
/// 1. Existing file whose name contains "Dockerfile" → build from file.
/// 2. Existing directory that contains a `Dockerfile` → build from directory.
/// 3. Value contains `/`, `:`, or `.` → treat as a full image reference.
/// 4. Otherwise → community sandbox name, expanded via the registry prefix.
fn resolve_from(value: &str) -> Result<ResolvedSource> {
    let path = Path::new(value);

    // 1. Existing file that looks like a Dockerfile.
    if path.is_file() {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        let lower = name.to_lowercase();
        if lower.contains("dockerfile") || lower.ends_with(".dockerfile") {
            let dockerfile = path
                .canonicalize()
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to resolve path: {}", path.display()))?;
            let context = dockerfile
                .parent()
                .ok_or_else(|| miette::miette!("Dockerfile has no parent directory"))?
                .to_path_buf();
            return Ok(ResolvedSource::Dockerfile {
                dockerfile,
                context,
            });
        }
    }

    // 2. Existing directory containing a Dockerfile.
    if path.is_dir() {
        let candidate = path.join("Dockerfile");
        if candidate.is_file() {
            let context = path
                .canonicalize()
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to resolve path: {}", path.display()))?;
            let dockerfile = context.join("Dockerfile");
            return Ok(ResolvedSource::Dockerfile {
                dockerfile,
                context,
            });
        }
        return Err(miette::miette!(
            "No Dockerfile found in directory: {}",
            path.display()
        ));
    }

    // 3. Looks like a full image reference (contains / : or .).
    if value.contains('/') || value.contains(':') || value.contains('.') {
        return Ok(ResolvedSource::Image(value.to_string()));
    }

    // 4. Community sandbox name.
    let prefix = std::env::var("OPENSHELL_COMMUNITY_REGISTRY")
        .unwrap_or_else(|_| DEFAULT_COMMUNITY_REGISTRY.to_string());
    let prefix = prefix.trim_end_matches('/');
    Ok(ResolvedSource::Image(format!("{prefix}/{value}:latest")))
}

/// Build a Dockerfile and push the resulting image into the gateway.
///
/// Returns the image tag that was built so the caller can use it for sandbox
/// creation.
async fn build_from_dockerfile(
    dockerfile: &Path,
    context: &Path,
    gateway_name: &str,
) -> Result<String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let tag = format!("openshell/sandbox-from:{timestamp}");

    eprintln!(
        "Building image {} from {}",
        tag.cyan(),
        dockerfile.display()
    );
    eprintln!("  {} {}", "Context:".dimmed(), context.display());
    eprintln!("  {} {}", "Gateway:".dimmed(), gateway_name);
    eprintln!();

    let mut on_log = |msg: String| {
        eprintln!("  {msg}");
    };

    navigator_bootstrap::build::build_and_push_image(
        dockerfile,
        &tag,
        context,
        gateway_name,
        &HashMap::new(),
        &mut on_log,
    )
    .await?;

    eprintln!();
    eprintln!(
        "{} Image {} is available in the gateway.",
        "✓".green().bold(),
        tag.cyan(),
    );
    eprintln!();

    Ok(tag)
}

/// Load sandbox policy YAML.
///
/// Resolution order: `--policy` flag > `OPENSHELL_SANDBOX_POLICY` env var.
/// Returns `None` when no policy source is configured, allowing the server
/// to apply its own default.
fn load_sandbox_policy(cli_path: Option<&str>) -> Result<Option<SandboxPolicy>> {
    navigator_policy::load_sandbox_policy(cli_path)
}

/// Sync files to or from a sandbox.
///
/// Dispatches to `sandbox_sync_up` or `sandbox_sync_down` based on the
/// `--up` / `--down` flags.
pub async fn sandbox_sync_command(
    server: &str,
    name: &str,
    up: Option<&str>,
    down: Option<&str>,
    dest: Option<&str>,
    tls: &TlsOptions,
) -> Result<()> {
    match (up, down) {
        (Some(local_path), None) => {
            let sandbox_dest = dest.unwrap_or("/sandbox");
            let local = Path::new(local_path);
            if !local.exists() {
                return Err(miette::miette!(
                    "local path does not exist: {}",
                    local.display()
                ));
            }
            eprintln!("Syncing {} -> sandbox:{}", local.display(), sandbox_dest);
            sandbox_sync_up(server, name, local, sandbox_dest, tls).await?;
            eprintln!("{} Sync complete", "✓".green().bold());
        }
        (None, Some(sandbox_path)) => {
            let local_dest = Path::new(dest.unwrap_or("."));
            eprintln!(
                "Syncing sandbox:{} -> {}",
                sandbox_path,
                local_dest.display()
            );
            sandbox_sync_down(server, name, sandbox_path, local_dest, tls).await?;
            eprintln!("{} Sync complete", "✓".green().bold());
        }
        _ => {
            return Err(miette::miette!(
                "specify either --up <local-path> or --down <sandbox-path>"
            ));
        }
    }
    Ok(())
}

/// Fetch a sandbox by name.
pub async fn sandbox_get(server: &str, name: &str, tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
        })
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
    if let Ok(yaml_str) = navigator_policy::serialize_sandbox_policy(policy) {
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
    names_only: bool,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .list_sandboxes(ListSandboxesRequest { limit, offset })
        .await
        .into_diagnostic()?;

    let sandboxes = response.into_inner().sandboxes;
    if sandboxes.is_empty() {
        if !ids_only && !names_only {
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

    if names_only {
        for sandbox in sandboxes {
            println!("{}", sandbox.name);
        }
        return Ok(());
    }

    // Calculate column widths
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
    let created_width = 19; // "YYYY-MM-DD HH:MM:SS"

    // Print header
    println!(
        "{:<name_width$}  {:<ns_width$}  {:<created_width$}  {}",
        "NAME".bold(),
        "NAMESPACE".bold(),
        "CREATED".bold(),
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
        let created = format_epoch_ms(sandbox.created_at_ms);
        println!(
            "{:<name_width$}  {:<ns_width$}  {:<created_width$}  {}",
            sandbox.name, sandbox.namespace, created, phase_colored,
        );
    }

    Ok(())
}

/// Delete a sandbox by name, or all sandboxes when `all` is true.
pub async fn sandbox_delete(
    server: &str,
    names: &[String],
    all: bool,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let names_to_delete: Vec<String> = if all {
        // Fetch all sandboxes (use a large page size).
        let response = client
            .list_sandboxes(ListSandboxesRequest {
                limit: 1000,
                offset: 0,
            })
            .await
            .into_diagnostic()?;
        let sandboxes = response.into_inner().sandboxes;
        if sandboxes.is_empty() {
            println!("No sandboxes to delete.");
            return Ok(());
        }
        sandboxes.into_iter().map(|s| s.name).collect()
    } else {
        names.to_vec()
    };

    for name in &names_to_delete {
        // Stop any background port forwards for this sandbox before deleting.
        if let Ok(stopped) = stop_forwards_for_sandbox(name) {
            for port in stopped {
                eprintln!(
                    "{} Stopped forward of port {port} for sandbox {name}",
                    "✓".green().bold(),
                );
            }
        }

        let response = client
            .delete_sandbox(DeleteSandboxRequest { name: name.clone() })
            .await
            .into_diagnostic()?;

        let deleted = response.into_inner().deleted;
        if deleted {
            println!("{} Deleted sandbox {name}", "✓".green().bold());
        } else {
            println!("{} Sandbox {name} not found", "!".yellow());
        }
    }

    Ok(())
}

/// Return the provider type inferred from the trailing command, if any.
fn inferred_provider_type(command: &[String]) -> Option<String> {
    detect_provider_from_command(command).map(str::to_string)
}

/// Ensure all required providers exist.
///
/// `explicit_names` are provider **names** supplied via `--provider`. They are
/// passed through directly; the server validates they exist at sandbox creation.
///
/// `inferred_types` are provider **types** inferred from the trailing command
/// (e.g. `claude` → type `"claude"`). These are resolved to provider names via
/// a type→name lookup, and missing types may be auto-created interactively.
///
/// Returns a deduplicated list of provider **names** suitable for
/// `SandboxSpec.providers`.
pub async fn ensure_required_providers(
    client: &mut crate::tls::GrpcClient,
    explicit_names: &[String],
    inferred_types: &[String],
    auto_providers_override: Option<bool>,
) -> Result<Vec<String>> {
    if explicit_names.is_empty() && inferred_types.is_empty() {
        return Ok(Vec::new());
    }

    let mut configured_names: Vec<String> = Vec::new();
    let mut seen_names: HashSet<String> = HashSet::new();

    // ── Fetch all existing providers ─────────────────────────────────────
    // Build both a name set (for explicit --provider lookups) and a
    // type-to-name map (for inferred provider resolution).
    let mut known_names: HashSet<String> = HashSet::new();
    let mut type_to_name: HashMap<String, String> = HashMap::new();
    {
        let mut offset = 0_u32;
        let limit = 100_u32;
        loop {
            let response = client
                .list_providers(ListProvidersRequest { limit, offset })
                .await
                .into_diagnostic()?;
            let providers = response.into_inner().providers;
            for provider in &providers {
                known_names.insert(provider.name.clone());
                if !provider.r#type.is_empty() {
                    let type_lower = provider.r#type.to_ascii_lowercase();
                    type_to_name
                        .entry(type_lower)
                        .or_insert_with(|| provider.name.clone());
                }
            }
            if providers.len() < limit as usize {
                break;
            }
            offset = offset.saturating_add(limit);
        }
    }

    // ── Explicit provider names ──────────────────────────────────────────
    // If the name exists on the server, use it directly. Otherwise, if the
    // name matches a known provider type, auto-create a provider of that
    // type with the requested name.
    for name in explicit_names {
        if known_names.contains(name) {
            if seen_names.insert(name.clone()) {
                configured_names.push(name.clone());
            }
        } else if let Some(provider_type) = normalize_provider_type(name) {
            auto_create_provider(
                client,
                provider_type,
                Some(name),
                auto_providers_override,
                &mut seen_names,
                &mut configured_names,
            )
            .await?;
            // Record the type mapping so the inferred-types pass below
            // doesn't attempt to create a duplicate provider.
            type_to_name
                .entry(provider_type.to_ascii_lowercase())
                .or_insert_with(|| name.clone());
        } else {
            return Err(miette::miette!(
                "provider '{name}' not found and '{name}' is not a recognized provider type. \
                 Create it first with `openshell provider create --type <type> --name {name}`"
            ));
        }
    }

    // ── Resolve inferred provider types ──────────────────────────────────
    if !inferred_types.is_empty() {
        // Collect resolved names for types that already have a provider.
        for t in inferred_types {
            if let Some(name) = type_to_name.get(&t.to_ascii_lowercase())
                && seen_names.insert(name.clone())
            {
                configured_names.push(name.clone());
            }
        }

        let missing = inferred_types
            .iter()
            .filter(|t| !type_to_name.contains_key(&t.to_ascii_lowercase()))
            .cloned()
            .collect::<Vec<_>>();

        for provider_type in missing {
            auto_create_provider(
                client,
                &provider_type,
                None,
                auto_providers_override,
                &mut seen_names,
                &mut configured_names,
            )
            .await?;
        }
    }

    Ok(configured_names)
}

/// Prompt for (or auto-confirm) creation of a provider from local credentials.
///
/// When `preferred_name` is `Some`, the provider is created with that exact
/// name (used for explicit `--provider <name>` values). When `None`, the name
/// defaults to the type and retries with suffixes on conflict (used for
/// inferred provider types).
async fn auto_create_provider(
    client: &mut crate::tls::GrpcClient,
    provider_type: &str,
    preferred_name: Option<&str>,
    auto_providers_override: Option<bool>,
    seen_names: &mut HashSet<String>,
    configured_names: &mut Vec<String>,
) -> Result<()> {
    eprintln!("Missing provider: {provider_type}");

    // --no-auto-providers: skip silently.
    if auto_providers_override == Some(false) {
        eprintln!(
            "{} Skipping provider '{provider_type}' (--no-auto-providers)",
            "!".yellow(),
        );
        eprintln!();
        return Ok(());
    }

    // No override and non-interactive: error.
    if auto_providers_override.is_none() && !std::io::stdin().is_terminal() {
        return Err(miette::miette!(
            "missing required provider '{provider_type}'. Create it first with \
             `openshell provider create --type {provider_type} --name {provider_type} --from-existing`, \
             pass --auto-providers to auto-create, or set it up manually from inside the sandbox"
        ));
    }

    // --auto-providers: auto-confirm; otherwise prompt.
    let should_create = if auto_providers_override == Some(true) {
        true
    } else {
        Confirm::new()
            .with_prompt("Create from local credentials?")
            .default(true)
            .interact()
            .into_diagnostic()?
    };

    if !should_create {
        eprintln!("{} Skipping provider '{provider_type}'", "!".yellow());
        eprintln!();
        return Ok(());
    }

    let registry = ProviderRegistry::new();
    let discovered = registry
        .discover_existing(provider_type)
        .map_err(|err| miette::miette!("failed to discover provider '{provider_type}': {err}"))?;
    let Some(discovered) = discovered else {
        eprintln!(
            "{} No existing local credentials/config found for '{}'. You can configure it from inside the sandbox.",
            "!".yellow(),
            provider_type
        );
        eprintln!();
        return Ok(());
    };

    if let Some(exact_name) = preferred_name {
        // Explicit name: create with exactly that name, no retries.
        let request = CreateProviderRequest {
            provider: Some(Provider {
                id: String::new(),
                name: exact_name.to_string(),
                r#type: provider_type.to_string(),
                credentials: discovered.credentials.clone(),
                config: discovered.config.clone(),
            }),
        };

        let response = client.create_provider(request).await.map_err(|status| {
            miette::miette!("failed to create provider '{exact_name}': {status}")
        })?;
        let provider = response
            .into_inner()
            .provider
            .ok_or_else(|| miette::miette!("provider missing from response"))?;
        eprintln!(
            "{} Created provider {} ({}) from existing local state",
            "✓".green().bold(),
            provider.name,
            provider.r#type
        );
        if seen_names.insert(provider.name.clone()) {
            configured_names.push(provider.name);
        }
    } else {
        // Inferred type: try type as name, then suffixed variants.
        let mut created = false;
        for attempt in 0..5 {
            let name = if attempt == 0 {
                provider_type.to_string()
            } else {
                format!("{provider_type}-{attempt}")
            };

            let request = CreateProviderRequest {
                provider: Some(Provider {
                    id: String::new(),
                    name: name.clone(),
                    r#type: provider_type.to_string(),
                    credentials: discovered.credentials.clone(),
                    config: discovered.config.clone(),
                }),
            };

            match client.create_provider(request).await {
                Ok(response) => {
                    let provider = response
                        .into_inner()
                        .provider
                        .ok_or_else(|| miette::miette!("provider missing from response"))?;
                    eprintln!(
                        "{} Created provider {} ({}) from existing local state",
                        "✓".green().bold(),
                        provider.name,
                        provider.r#type
                    );
                    if seen_names.insert(provider.name.clone()) {
                        configured_names.push(provider.name);
                    }
                    created = true;
                    break;
                }
                Err(status) if status.code() == Code::AlreadyExists => {}
                Err(status) => {
                    return Err(miette::miette!(
                        "failed to create provider for type '{provider_type}': {status}"
                    ));
                }
            }
        }

        if !created {
            return Err(miette::miette!(
                "failed to create provider for type '{provider_type}' after name retries"
            ));
        }
    }

    eprintln!();
    Ok(())
}

fn parse_key_value_pairs(items: &[String], flag: &str) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();

    for item in items {
        let Some((key, value)) = item.split_once('=') else {
            return Err(miette::miette!("{flag} expects KEY=VALUE, got '{item}'"));
        };

        let key = key.trim();
        if key.is_empty() {
            return Err(miette::miette!("{flag} key cannot be empty"));
        }

        map.insert(key.to_string(), value.to_string());
    }

    Ok(map)
}

fn parse_credential_pairs(items: &[String]) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();

    for item in items {
        if let Some((key, value)) = item.split_once('=') {
            let key = key.trim();
            if key.is_empty() {
                return Err(miette::miette!("--credential key cannot be empty"));
            }
            map.insert(key.to_string(), value.to_string());
            continue;
        }

        let key = item.trim();
        if key.is_empty() {
            return Err(miette::miette!("--credential key cannot be empty"));
        }

        let value = std::env::var(key).map_err(|_| {
            miette::miette!(
                "--credential {key} requires local env var '{key}' to be set to a non-empty value"
            )
        })?;

        if value.trim().is_empty() {
            return Err(miette::miette!(
                "--credential {key} requires local env var '{key}' to be set to a non-empty value"
            ));
        }

        map.insert(key.to_string(), value);
    }

    Ok(map)
}

pub async fn provider_create(
    server: &str,
    name: &str,
    provider_type: &str,
    from_existing: bool,
    credentials: &[String],
    config: &[String],
    tls: &TlsOptions,
) -> Result<()> {
    if from_existing && !credentials.is_empty() {
        return Err(miette::miette!(
            "--from-existing cannot be combined with --credential"
        ));
    }

    let mut client = grpc_client(server, tls).await?;

    let provider_type = normalize_provider_type(provider_type)
        .ok_or_else(|| miette::miette!("unsupported provider type: {provider_type}"))?
        .to_string();

    let mut credential_map = parse_credential_pairs(credentials)?;
    let mut config_map = parse_key_value_pairs(config, "--config")?;

    if from_existing {
        let registry = ProviderRegistry::new();
        let discovered = registry
            .discover_existing(&provider_type)
            .map_err(|err| miette::miette!("failed to discover existing provider data: {err}"))?;
        let Some(discovered) = discovered else {
            return Err(miette::miette!(
                "no existing local credentials/config found for provider type '{provider_type}'"
            ));
        };

        for (key, value) in discovered.credentials {
            credential_map.entry(key).or_insert(value);
        }
        for (key, value) in discovered.config {
            config_map.entry(key).or_insert(value);
        }
    }

    if credential_map.is_empty() {
        return Err(miette::miette!(
            "no credentials resolved for provider type '{provider_type}'. \
             Use --credential KEY[=VALUE] or --from-existing with the appropriate env vars set."
        ));
    }

    let response = client
        .create_provider(CreateProviderRequest {
            provider: Some(Provider {
                id: String::new(),
                name: name.to_string(),
                r#type: provider_type,
                credentials: credential_map,
                config: config_map,
            }),
        })
        .await
        .into_diagnostic()?;

    let provider = response
        .into_inner()
        .provider
        .ok_or_else(|| miette::miette!("provider missing from response"))?;

    println!("{} Created provider {}", "✓".green().bold(), provider.name);
    Ok(())
}

pub async fn provider_get(server: &str, name: &str, tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_provider(GetProviderRequest {
            name: name.to_string(),
        })
        .await
        .into_diagnostic()?;

    let provider = response
        .into_inner()
        .provider
        .ok_or_else(|| miette::miette!("provider missing from response"))?;

    let credential_keys = provider.credentials.keys().cloned().collect::<Vec<_>>();
    let config_keys = provider.config.keys().cloned().collect::<Vec<_>>();

    println!("{}", "Provider:".cyan().bold());
    println!();
    println!("  {} {}", "Id:".dimmed(), provider.id);
    println!("  {} {}", "Name:".dimmed(), provider.name);
    println!("  {} {}", "Type:".dimmed(), provider.r#type);
    println!(
        "  {} {}",
        "Credential keys:".dimmed(),
        if credential_keys.is_empty() {
            "<none>".to_string()
        } else {
            credential_keys.join(", ")
        }
    );
    println!(
        "  {} {}",
        "Config keys:".dimmed(),
        if config_keys.is_empty() {
            "<none>".to_string()
        } else {
            config_keys.join(", ")
        }
    );

    Ok(())
}

pub async fn provider_list(
    server: &str,
    limit: u32,
    offset: u32,
    names_only: bool,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .list_providers(ListProvidersRequest { limit, offset })
        .await
        .into_diagnostic()?;
    let providers = response.into_inner().providers;

    if providers.is_empty() {
        if !names_only {
            println!("No providers found.");
        }
        return Ok(());
    }

    if names_only {
        for provider in providers {
            println!("{}", provider.name);
        }
        return Ok(());
    }

    let name_width = providers
        .iter()
        .map(|provider| provider.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let type_width = providers
        .iter()
        .map(|provider| provider.r#type.len())
        .max()
        .unwrap_or(4)
        .max(4);

    println!(
        "{:<name_width$}  {:<type_width$}  {:<16}  {}",
        "NAME".bold(),
        "TYPE".bold(),
        "CREDENTIAL_KEYS".bold(),
        "CONFIG_KEYS".bold(),
    );

    for provider in providers {
        println!(
            "{:<name_width$}  {:<type_width$}  {:<16}  {}",
            provider.name,
            provider.r#type,
            provider.credentials.len(),
            provider.config.len(),
        );
    }

    Ok(())
}

pub async fn provider_update(
    server: &str,
    name: &str,
    from_existing: bool,
    credentials: &[String],
    config: &[String],
    tls: &TlsOptions,
) -> Result<()> {
    if from_existing && !credentials.is_empty() {
        return Err(miette::miette!(
            "--from-existing cannot be combined with --credential"
        ));
    }

    let mut client = grpc_client(server, tls).await?;

    let mut credential_map = parse_credential_pairs(credentials)?;
    let mut config_map = parse_key_value_pairs(config, "--config")?;

    if from_existing {
        // Fetch the existing provider to discover its type for credential lookup.
        let existing = client
            .get_provider(GetProviderRequest {
                name: name.to_string(),
            })
            .await
            .into_diagnostic()?
            .into_inner()
            .provider
            .ok_or_else(|| miette::miette!("provider '{name}' not found"))?;

        let provider_type = existing.r#type;
        let registry = ProviderRegistry::new();
        let discovered = registry
            .discover_existing(&provider_type)
            .map_err(|err| miette::miette!("failed to discover existing provider data: {err}"))?;
        let Some(discovered) = discovered else {
            return Err(miette::miette!(
                "no existing local credentials/config found for provider type '{provider_type}'"
            ));
        };

        for (key, value) in discovered.credentials {
            credential_map.entry(key).or_insert(value);
        }
        for (key, value) in discovered.config {
            config_map.entry(key).or_insert(value);
        }
    }

    let response = client
        .update_provider(UpdateProviderRequest {
            provider: Some(Provider {
                id: String::new(),
                name: name.to_string(),
                r#type: String::new(),
                credentials: credential_map,
                config: config_map,
            }),
        })
        .await
        .into_diagnostic()?;

    let provider = response
        .into_inner()
        .provider
        .ok_or_else(|| miette::miette!("provider missing from response"))?;

    println!("{} Updated provider {}", "✓".green().bold(), provider.name);
    Ok(())
}

pub async fn provider_delete(server: &str, names: &[String], tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    for name in names {
        let response = client
            .delete_provider(DeleteProviderRequest { name: name.clone() })
            .await
            .into_diagnostic()?;
        if response.into_inner().deleted {
            println!("{} Deleted provider {name}", "✓".green().bold());
        } else {
            println!("{} Provider {name} not found", "!".yellow());
        }
    }
    Ok(())
}

pub async fn gateway_inference_set(
    server: &str,
    provider_name: &str,
    model_id: &str,
    route_name: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_inference_client(server, tls).await?;
    let response = client
        .set_cluster_inference(SetClusterInferenceRequest {
            provider_name: provider_name.to_string(),
            model_id: model_id.to_string(),
            route_name: route_name.to_string(),
        })
        .await
        .into_diagnostic()?;

    let configured = response.into_inner();
    let label = if configured.route_name == "sandbox-system" {
        "System inference configured:"
    } else {
        "Gateway inference configured:"
    };
    println!("{}", label.cyan().bold());
    println!();
    println!("  {} {}", "Route:".dimmed(), configured.route_name);
    println!("  {} {}", "Provider:".dimmed(), configured.provider_name);
    println!("  {} {}", "Model:".dimmed(), configured.model_id);
    println!("  {} {}", "Version:".dimmed(), configured.version);
    Ok(())
}

pub async fn gateway_inference_update(
    server: &str,
    provider_name: Option<&str>,
    model_id: Option<&str>,
    route_name: &str,
    tls: &TlsOptions,
) -> Result<()> {
    if provider_name.is_none() && model_id.is_none() {
        return Err(miette::miette!(
            "at least one of --provider or --model must be specified"
        ));
    }

    let mut client = grpc_inference_client(server, tls).await?;

    // Fetch current config to use as base for the partial update.
    let current = client
        .get_cluster_inference(GetClusterInferenceRequest {
            route_name: route_name.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner();

    let provider = provider_name.unwrap_or(&current.provider_name);
    let model = model_id.unwrap_or(&current.model_id);

    let response = client
        .set_cluster_inference(SetClusterInferenceRequest {
            provider_name: provider.to_string(),
            model_id: model.to_string(),
            route_name: route_name.to_string(),
        })
        .await
        .into_diagnostic()?;

    let configured = response.into_inner();
    let label = if configured.route_name == "sandbox-system" {
        "System inference updated:"
    } else {
        "Gateway inference updated:"
    };
    println!("{}", label.cyan().bold());
    println!();
    println!("  {} {}", "Route:".dimmed(), configured.route_name);
    println!("  {} {}", "Provider:".dimmed(), configured.provider_name);
    println!("  {} {}", "Model:".dimmed(), configured.model_id);
    println!("  {} {}", "Version:".dimmed(), configured.version);
    Ok(())
}

pub async fn gateway_inference_get(
    server: &str,
    route_name: Option<&str>,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_inference_client(server, tls).await?;

    if let Some(name) = route_name {
        // Show a single route (--system was specified).
        let response = client
            .get_cluster_inference(GetClusterInferenceRequest {
                route_name: name.to_string(),
            })
            .await
            .into_diagnostic()?;

        let configured = response.into_inner();
        let label = if name == "sandbox-system" {
            "System inference:"
        } else {
            "Gateway inference:"
        };
        println!("{}", label.cyan().bold());
        println!();
        println!("  {} {}", "Provider:".dimmed(), configured.provider_name);
        println!("  {} {}", "Model:".dimmed(), configured.model_id);
        println!("  {} {}", "Version:".dimmed(), configured.version);
    } else {
        // Show both routes by default.
        print_inference_route(&mut client, "Gateway inference", "").await;
        println!();
        print_inference_route(&mut client, "System inference", "sandbox-system").await;
    }
    Ok(())
}

async fn print_inference_route(
    client: &mut crate::tls::GrpcInferenceClient,
    label: &str,
    route_name: &str,
) {
    match client
        .get_cluster_inference(GetClusterInferenceRequest {
            route_name: route_name.to_string(),
        })
        .await
    {
        Ok(response) => {
            let configured = response.into_inner();
            println!("{}", format!("{label}:").cyan().bold());
            println!();
            println!("  {} {}", "Provider:".dimmed(), configured.provider_name);
            println!("  {} {}", "Model:".dimmed(), configured.model_id);
            println!("  {} {}", "Version:".dimmed(), configured.version);
        }
        Err(e) if e.code() == Code::NotFound => {
            println!("{}", format!("{label}:").cyan().bold());
            println!();
            println!("  {}", "Not configured".dimmed());
        }
        Err(e) => {
            println!("{}", format!("{label}:").cyan().bold());
            println!();
            println!("  {} {}", "Error:".red(), e.message());
        }
    }
}

pub fn git_repo_root(local_path: &Path) -> Result<PathBuf> {
    let git_dir = if local_path.is_dir() {
        local_path
    } else {
        local_path
            .parent()
            .ok_or_else(|| miette::miette!("path has no parent: {}", local_path.display()))?
    };
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(git_dir)
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

pub fn git_sync_files(local_path: &Path) -> Result<(PathBuf, Vec<String>)> {
    let repo_root = std::fs::canonicalize(git_repo_root(local_path)?)
        .into_diagnostic()
        .wrap_err("failed to canonicalize git repository root")?;
    let local_path = if local_path.is_absolute() {
        local_path.to_path_buf()
    } else {
        std::env::current_dir()
            .into_diagnostic()
            .wrap_err("failed to resolve current directory")?
            .join(local_path)
    };
    let local_path = std::fs::canonicalize(local_path)
        .into_diagnostic()
        .wrap_err("failed to canonicalize local upload path")?;
    let relative_path = local_path
        .strip_prefix(&repo_root)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "local path '{}' is not inside git repository '{}'",
                local_path.display(),
                repo_root.display()
            )
        })?;

    let is_file = local_path.is_file();
    let base_dir = if is_file {
        local_path
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| miette::miette!("path has no parent: {}", local_path.display()))?
    } else {
        local_path.clone()
    };
    let pathspec = if relative_path.as_os_str().is_empty() {
        None
    } else {
        Some(relative_path.to_string_lossy().into_owned())
    };

    let output = Command::new("git")
        .args(["ls-files", "-co", "--exclude-standard", "-z"])
        .args(pathspec.as_deref())
        .current_dir(&repo_root)
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
        let repo_relative = Path::new(std::str::from_utf8(entry).into_diagnostic()?);
        let path = if is_file {
            repo_relative
                .file_name()
                .map(PathBuf::from)
                .ok_or_else(|| {
                    miette::miette!("path has no file name: {}", repo_relative.display())
                })?
        } else if relative_path.as_os_str().is_empty() {
            repo_relative.to_path_buf()
        } else {
            repo_relative
                .strip_prefix(relative_path)
                .into_diagnostic()?
                .to_path_buf()
        };
        if path.as_os_str().is_empty() {
            continue;
        }
        files.push(path.to_string_lossy().into_owned());
    }

    Ok((base_dir, files))
}

// ---------------------------------------------------------------------------
// Sandbox policy commands
// ---------------------------------------------------------------------------

/// Parse a duration string like "5m", "1h", "30s" into milliseconds.
fn parse_duration_to_ms(s: &str) -> Result<i64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(miette::miette!("empty duration string"));
    }
    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: i64 = num_str
        .parse()
        .map_err(|_| miette::miette!("invalid duration: {s} (expected e.g. 5m, 1h, 30s)"))?;
    let multiplier = match unit {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        _ => {
            return Err(miette::miette!(
                "unknown duration unit: {unit} (use s, m, or h)"
            ));
        }
    };
    Ok(num * multiplier)
}

pub async fn sandbox_policy_set(
    server: &str,
    name: &str,
    policy_path: &str,
    wait: bool,
    timeout_secs: u64,
    tls: &TlsOptions,
) -> Result<()> {
    let policy = load_sandbox_policy(Some(policy_path))?
        .ok_or_else(|| miette::miette!("No policy loaded from {policy_path}"))?;

    let mut client = grpc_client(server, tls).await?;

    // Get current version so we can detect no-ops.
    let current_version = client
        .get_sandbox_policy_status(GetSandboxPolicyStatusRequest {
            name: name.to_string(),
            version: 0,
        })
        .await
        .ok()
        .and_then(|r| r.into_inner().revision)
        .map_or(0, |r| r.version);

    let response = client
        .update_sandbox_policy(UpdateSandboxPolicyRequest {
            name: name.to_string(),
            policy: Some(policy),
        })
        .await
        .into_diagnostic()?;

    let resp = response.into_inner();

    if resp.version == current_version {
        eprintln!(
            "{} Policy unchanged (version {}, hash: {})",
            "·".dimmed(),
            resp.version,
            &resp.policy_hash[..12]
        );
        return Ok(());
    }

    eprintln!(
        "{} Policy version {} submitted (hash: {})",
        "✓".green().bold(),
        resp.version,
        &resp.policy_hash[..12]
    );

    if !wait {
        return Ok(());
    }

    // Poll for status until loaded, failed, or timeout.
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if Instant::now() > deadline {
            eprintln!(
                "{} Timeout waiting for policy version {} to load",
                "✗".red().bold(),
                resp.version
            );
            std::process::exit(124);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;

        let status_resp = client
            .get_sandbox_policy_status(GetSandboxPolicyStatusRequest {
                name: name.to_string(),
                version: resp.version,
            })
            .await
            .into_diagnostic()?;

        let inner = status_resp.into_inner();
        if let Some(rev) = &inner.revision {
            let status = PolicyStatus::try_from(rev.status).unwrap_or(PolicyStatus::Unspecified);
            match status {
                PolicyStatus::Loaded => {
                    eprintln!(
                        "{} Policy version {} loaded (active version: {})",
                        "✓".green().bold(),
                        rev.version,
                        inner.active_version
                    );
                    return Ok(());
                }
                PolicyStatus::Failed => {
                    eprintln!(
                        "{} Policy version {} failed to load: {}",
                        "✗".red().bold(),
                        rev.version,
                        rev.load_error
                    );
                    std::process::exit(1);
                }
                PolicyStatus::Superseded => {
                    eprintln!(
                        "{} Policy version {} was superseded (active version: {})",
                        "⚠".yellow().bold(),
                        rev.version,
                        inner.active_version
                    );
                    return Ok(());
                }
                _ => {} // still pending, keep polling
            }
        }
    }
}

pub async fn sandbox_policy_get(
    server: &str,
    name: &str,
    version: u32,
    full: bool,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let status_resp = client
        .get_sandbox_policy_status(GetSandboxPolicyStatusRequest {
            name: name.to_string(),
            version,
        })
        .await
        .into_diagnostic()?;

    let inner = status_resp.into_inner();
    if let Some(rev) = inner.revision {
        let status = PolicyStatus::try_from(rev.status).unwrap_or(PolicyStatus::Unspecified);
        println!("Version:      {}", rev.version);
        println!("Hash:         {}", rev.policy_hash);
        println!("Status:       {status:?}");
        println!("Active:       {}", inner.active_version);
        if rev.created_at_ms > 0 {
            println!("Created:      {} ms", rev.created_at_ms);
        }
        if rev.loaded_at_ms > 0 {
            println!("Loaded:       {} ms", rev.loaded_at_ms);
        }
        if !rev.load_error.is_empty() {
            println!("Error:        {}", rev.load_error);
        }

        if full {
            if let Some(ref policy) = rev.policy {
                println!("---");
                let yaml_str = navigator_policy::serialize_sandbox_policy(policy)
                    .wrap_err("failed to serialize policy to YAML")?;
                print!("{yaml_str}");
            } else {
                eprintln!("Policy payload not available for this version");
            }
        }
    } else {
        eprintln!("No policy history found for sandbox '{name}'");
    }

    Ok(())
}

pub async fn sandbox_policy_list(
    server: &str,
    name: &str,
    limit: u32,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let resp = client
        .list_sandbox_policies(ListSandboxPoliciesRequest {
            name: name.to_string(),
            limit,
            offset: 0,
        })
        .await
        .into_diagnostic()?;

    let revisions = resp.into_inner().revisions;
    if revisions.is_empty() {
        eprintln!("No policy history found for sandbox '{name}'");
        return Ok(());
    }

    println!(
        "{:<8} {:<14} {:<12} {:<24} ERROR",
        "VERSION", "HASH", "STATUS", "CREATED"
    );
    for rev in &revisions {
        let status = PolicyStatus::try_from(rev.status).unwrap_or(PolicyStatus::Unspecified);
        let hash_short = if rev.policy_hash.len() >= 12 {
            &rev.policy_hash[..12]
        } else {
            &rev.policy_hash
        };
        let error_short = if rev.load_error.len() > 40 {
            format!("{}...", &rev.load_error[..40])
        } else {
            rev.load_error.clone()
        };
        println!(
            "{:<8} {:<14} {:<12} {:<24} {}",
            rev.version,
            hash_short,
            format!("{status:?}"),
            rev.created_at_ms,
            error_short,
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sandbox logs command
// ---------------------------------------------------------------------------

pub async fn sandbox_logs(
    server: &str,
    name: &str,
    lines: u32,
    tail: bool,
    since: Option<&str>,
    sources: &[String],
    level: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    // Resolve sandbox name to id.
    let sandbox = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox not found"))?;

    // Normalize "all" to empty list (server treats empty as "no filter").
    let source_filter: Vec<String> = sources
        .iter()
        .filter(|s| s.as_str() != "all")
        .cloned()
        .collect();

    let since_ms = if let Some(s) = since {
        let dur_ms = parse_duration_to_ms(s)?;
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .into_diagnostic()?
                .as_millis(),
        )
        .into_diagnostic()?;
        now_ms - dur_ms
    } else {
        0
    };

    if tail {
        // Streaming mode: use WatchSandbox.
        let mut stream = client
            .watch_sandbox(WatchSandboxRequest {
                id: sandbox.id.clone(),
                follow_status: false,
                follow_logs: true,
                follow_events: false,
                log_tail_lines: lines,
                event_tail: 0,
                stop_on_terminal: false,
                log_since_ms: since_ms,
                log_sources: source_filter,
                log_min_level: level.to_uppercase(),
            })
            .await
            .into_diagnostic()?
            .into_inner();

        while let Some(event) = stream.next().await {
            let event = event.into_diagnostic()?;
            if let Some(navigator_core::proto::sandbox_stream_event::Payload::Log(log)) =
                event.payload
            {
                print_log_line(&log);
            }
        }
    } else {
        // One-shot mode: use GetSandboxLogs.
        let resp = client
            .get_sandbox_logs(GetSandboxLogsRequest {
                sandbox_id: sandbox.id.clone(),
                lines,
                since_ms,
                sources: source_filter,
                min_level: level.to_uppercase(),
            })
            .await
            .into_diagnostic()?;

        let inner = resp.into_inner();

        if since_ms > 0 && inner.buffer_total > 0 {
            eprintln!(
                "Warning: log buffer contains only the last {} lines; --since results may be incomplete.",
                inner.buffer_total
            );
        }

        for log in &inner.logs {
            print_log_line(log);
        }
    }

    Ok(())
}

fn print_log_line(log: &navigator_core::proto::SandboxLogLine) {
    let source = if log.source.is_empty() {
        "gateway"
    } else {
        &log.source
    };
    let secs = log.timestamp_ms / 1000;
    let millis = log.timestamp_ms % 1000;
    if log.fields.is_empty() {
        println!(
            "[{secs}.{millis:03}] [{source:<7}] [{:<5}] [{}] {}",
            log.level, log.target, log.message
        );
    } else {
        let mut fields_str = String::new();
        let mut entries: Vec<_> = log.fields.iter().collect();
        entries.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in entries {
            if !fields_str.is_empty() {
                fields_str.push(' ');
            }
            fields_str.push_str(k);
            fields_str.push('=');
            fields_str.push_str(v);
        }
        println!(
            "[{secs}.{millis:03}] [{source:<7}] [{:<5}] [{}] {} {}",
            log.level, log.target, log.message, fields_str
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GatewayControlTarget, TlsOptions, format_gateway_select_header,
        format_gateway_select_items, gateway_select_with, gateway_type_label, git_sync_files,
        http_health_check, inferred_provider_type, parse_credential_pairs,
        resolve_gateway_control_target_from,
    };
    use crate::TEST_ENV_LOCK;
    use hyper::StatusCode;
    use navigator_bootstrap::{load_active_gateway, store_gateway_metadata};
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::Path;
    use std::process::Command;
    use std::thread;

    use navigator_bootstrap::GatewayMetadata;

    struct EnvVarGuard {
        key: &'static str,
        original: Option<String>,
    }

    #[allow(unsafe_code)]
    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, original }
        }

        fn unset(key: &'static str) -> Self {
            let original = std::env::var(key).ok();
            unsafe {
                std::env::remove_var(key);
            }
            Self { key, original }
        }
    }

    #[allow(unsafe_code)]
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                unsafe {
                    std::env::set_var(self.key, value);
                }
            } else {
                unsafe {
                    std::env::remove_var(self.key);
                }
            }
        }
    }

    fn with_tmp_xdg<F: FnOnce()>(tmp: &Path, f: F) {
        let _guard = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let guard = EnvVarGuard::set(
            "XDG_CONFIG_HOME",
            tmp.to_str().expect("temp path should be utf-8"),
        );
        f();
        drop(guard);
    }

    fn edge_registration(name: &str, endpoint: &str) -> GatewayMetadata {
        GatewayMetadata {
            name: name.to_string(),
            gateway_endpoint: endpoint.to_string(),
            is_remote: true,
            gateway_port: 0,
            remote_host: None,
            resolved_host: None,
            auth_mode: Some("cloudflare_jwt".to_string()),
            edge_team_domain: None,
            edge_auth_url: None,
        }
    }

    #[test]
    fn parse_credential_pairs_accepts_key_value_form() {
        let parsed = parse_credential_pairs(&["API_KEY=abc123".to_string()]).expect("parse");
        assert_eq!(parsed.get("API_KEY"), Some(&"abc123".to_string()));
    }

    #[test]
    fn parse_credential_pairs_reads_value_from_environment_for_key_only_form() {
        let _guard = EnvVarGuard::set("NAV_PARSE_CREDENTIAL_TEST_KEY", "from-env");

        let parsed =
            parse_credential_pairs(&["NAV_PARSE_CREDENTIAL_TEST_KEY".to_string()]).expect("parse");
        assert_eq!(
            parsed.get("NAV_PARSE_CREDENTIAL_TEST_KEY"),
            Some(&"from-env".to_string())
        );
    }

    #[test]
    fn parse_credential_pairs_rejects_missing_environment_for_key_only_form() {
        let _guard = EnvVarGuard::unset("NAV_PARSE_CREDENTIAL_MISSING");

        let err = parse_credential_pairs(&["NAV_PARSE_CREDENTIAL_MISSING".to_string()])
            .expect_err("missing env should error");
        assert!(err.to_string().contains(
            "requires local env var 'NAV_PARSE_CREDENTIAL_MISSING' to be set to a non-empty value"
        ));
    }

    #[test]
    fn parse_credential_pairs_rejects_empty_environment_for_key_only_form() {
        let _guard = EnvVarGuard::set("NAV_PARSE_CREDENTIAL_EMPTY", "");

        let err = parse_credential_pairs(&["NAV_PARSE_CREDENTIAL_EMPTY".to_string()])
            .expect_err("empty env should error");
        assert!(err.to_string().contains(
            "requires local env var 'NAV_PARSE_CREDENTIAL_EMPTY' to be set to a non-empty value"
        ));
    }

    #[test]
    fn inferred_provider_type_returns_type_for_known_command() {
        let result = inferred_provider_type(&["claude".to_string(), "--help".to_string()]);
        assert_eq!(result, Some("claude".to_string()));
    }

    #[test]
    fn inferred_provider_type_returns_none_for_unknown_command() {
        let result = inferred_provider_type(&["bash".to_string()]);
        assert_eq!(result, None);
    }

    #[test]
    fn inferred_provider_type_returns_none_for_empty_command() {
        let result = inferred_provider_type(&[]);
        assert_eq!(result, None);
    }

    #[test]
    fn inferred_provider_type_normalizes_aliases() {
        // `glab` should resolve to `gitlab`
        let result = inferred_provider_type(&["glab".to_string()]);
        assert_eq!(result, Some("gitlab".to_string()));

        // `gh` should resolve to `github`
        let result = inferred_provider_type(&["gh".to_string()]);
        assert_eq!(result, Some("github".to_string()));
    }

    #[test]
    fn inferred_provider_type_handles_full_path() {
        let result = inferred_provider_type(&["/usr/local/bin/claude".to_string()]);
        assert_eq!(result, Some("claude".to_string()));
    }

    fn init_git_repo(path: &Path) {
        let status = Command::new("git")
            .args(["init"])
            .current_dir(path)
            .status()
            .expect("git init");
        assert!(status.success(), "git init should succeed");
    }

    #[test]
    fn git_sync_files_scopes_single_file_to_requested_path() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let repo = tmpdir.path().join("repo");
        fs::create_dir_all(repo.join("nested")).expect("create repo");
        init_git_repo(&repo);

        fs::write(repo.join("tracked.txt"), "tracked").expect("write tracked.txt");
        fs::write(repo.join("nested/other.txt"), "other").expect("write other.txt");

        let result = git_sync_files(&repo.join("tracked.txt"));
        let (base_dir, files) = result.expect("git_sync_files should succeed");
        assert_eq!(
            base_dir,
            fs::canonicalize(&repo).expect("canonicalize repo path")
        );
        assert_eq!(files, vec!["tracked.txt"]);
    }

    #[test]
    fn git_sync_files_scopes_directory_to_requested_subtree() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let repo = tmpdir.path().join("repo");
        fs::create_dir_all(repo.join("nested/inner")).expect("create repo");
        init_git_repo(&repo);

        fs::write(repo.join("nested/file.txt"), "file").expect("write file.txt");
        fs::write(repo.join("nested/inner/child.txt"), "child").expect("write child.txt");
        fs::write(repo.join("top.txt"), "top").expect("write top.txt");

        let result = git_sync_files(&repo.join("nested"));
        let (base_dir, mut files) = result.expect("git_sync_files should succeed");
        files.sort();

        assert_eq!(
            base_dir,
            fs::canonicalize(repo.join("nested")).expect("canonicalize nested path")
        );
        assert_eq!(files, vec!["file.txt", "inner/child.txt"]);
    }

    #[test]
    fn resolve_gateway_control_target_marks_edge_registration_unmanaged() {
        let metadata = edge_registration("edge-gateway", "https://gw.example.com");
        let target = resolve_gateway_control_target_from(Some(metadata), None);
        assert!(matches!(target, GatewayControlTarget::ExternalRegistration));
    }

    #[test]
    fn resolve_gateway_control_target_prefers_explicit_remote_override() {
        let target = resolve_gateway_control_target_from(None, Some("user@host"));
        match target {
            GatewayControlTarget::Remote(dest) => assert_eq!(dest, "user@host"),
            GatewayControlTarget::Local | GatewayControlTarget::ExternalRegistration => {
                panic!("expected remote target")
            }
        }
    }

    #[test]
    fn gateway_select_uses_explicit_name_without_prompting() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        with_tmp_xdg(tmpdir.path(), || {
            store_gateway_metadata(
                "alpha",
                &edge_registration("alpha", "https://alpha.example.com"),
            )
            .expect("store gateway");

            let mut prompted = false;
            gateway_select_with(Some("alpha"), &None, true, |_, _| {
                prompted = true;
                Ok(None)
            })
            .expect("select explicit gateway");

            assert_eq!(load_active_gateway().as_deref(), Some("alpha"));
            assert!(!prompted, "explicit gateway should skip prompting");
        });
    }

    #[test]
    fn gateway_select_prefers_active_gateway_as_default_choice() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        with_tmp_xdg(tmpdir.path(), || {
            store_gateway_metadata(
                "alpha",
                &edge_registration("alpha", "https://alpha.example.com"),
            )
            .expect("store alpha");
            store_gateway_metadata(
                "beta",
                &edge_registration("beta", "https://beta.example.com"),
            )
            .expect("store beta");
            super::save_active_gateway("beta").expect("save active gateway");

            let mut seen_default = None;
            gateway_select_with(None, &None, true, |gateways, default| {
                seen_default = Some(default);
                Ok(Some(gateways[default].name.clone()))
            })
            .expect("interactive selection");

            assert_eq!(seen_default, Some(1));
            assert_eq!(load_active_gateway().as_deref(), Some("beta"));
        });
    }

    #[test]
    fn gateway_select_non_interactive_lists_gateways_without_prompting() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        with_tmp_xdg(tmpdir.path(), || {
            store_gateway_metadata(
                "alpha",
                &edge_registration("alpha", "https://alpha.example.com"),
            )
            .expect("store gateway");

            let mut prompted = false;
            gateway_select_with(None, &None, false, |_, _| {
                prompted = true;
                Ok(None)
            })
            .expect("non-interactive selection");

            assert!(!prompted, "non-interactive mode should not prompt");
            assert_eq!(load_active_gateway(), None);
        });
    }

    #[test]
    fn gateway_select_items_include_endpoint_and_type() {
        let gateways = vec![
            edge_registration("alpha", "https://edge.example.com"),
            GatewayMetadata {
                name: "local".to_string(),
                gateway_endpoint: "http://127.0.0.1:8080".to_string(),
                is_remote: false,
                gateway_port: 8080,
                remote_host: None,
                resolved_host: None,
                auth_mode: None,
                edge_team_domain: None,
                edge_auth_url: None,
            },
        ];

        let items = format_gateway_select_items(&gateways);
        let header = format_gateway_select_header(&gateways);

        assert_eq!(gateway_type_label(&gateways[0]), "edge");
        assert_eq!(gateway_type_label(&gateways[1]), "local");
        assert!(header.contains("NAME"));
        assert!(header.contains("ENDPOINT"));
        assert!(header.contains("TYPE"));
        assert!(items[0].contains("alpha"));
        assert!(items[0].contains("https://edge.example.com"));
        assert!(items[0].contains("edge"));
        assert!(items[1].contains("local"));
        assert!(items[1].contains("http://127.0.0.1:8080"));
    }

    #[tokio::test]
    async fn http_health_check_supports_plain_http_endpoints() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).expect("read request");
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Length: 2\r\n",
                "Content-Type: text/plain\r\n",
                "Connection: close\r\n\r\n",
                "ok"
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });

        let status = http_health_check(&format!("http://{addr}"), &TlsOptions::default())
            .await
            .expect("health check");

        server.join().expect("server thread");
        assert_eq!(status, Some(StatusCode::OK));
    }
}
