// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI command implementations.

use crate::policy_update::build_policy_update_plan;
use crate::tls::{
    TlsOptions, build_insecure_rustls_config, build_rustls_config, grpc_client,
    grpc_inference_client, require_tls_materials,
};
use bytes::Bytes;
use chrono::DateTime;
use dialoguer::{Confirm, Select, theme::ColorfulTheme};
use futures::StreamExt;
use http_body_util::Full;
use hyper::{Request, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use miette::{IntoDiagnostic, Result, WrapErr, miette};
use openshell_bootstrap::{
    GatewayMetadata, clear_active_gateway, clear_last_sandbox_if_matches,
    extract_host_from_ssh_destination, get_gateway_metadata, list_gateways, load_active_gateway,
    remove_gateway_metadata, resolve_ssh_hostname, save_active_gateway, save_last_sandbox,
    store_gateway_metadata,
};
use openshell_core::progress::{
    PROGRESS_ACTIVE_DETAIL_KEY, PROGRESS_ACTIVE_STEP_KEY, PROGRESS_COMPLETE_LABEL_KEY,
    PROGRESS_COMPLETE_STEP_KEY, PROGRESS_STEP_PULLING_IMAGE, PROGRESS_STEP_REQUESTING_SANDBOX,
    PROGRESS_STEP_STARTING_SANDBOX,
};
use openshell_core::proto::ProviderProfileCategory;
use openshell_core::proto::{
    ApproveAllDraftChunksRequest, ApproveDraftChunkRequest, AttachSandboxProviderRequest,
    ClearDraftChunksRequest, ConfigureProviderRefreshRequest, CreateProviderRequest,
    CreateSandboxRequest, CreateSshSessionRequest, DeleteProviderProfileRequest,
    DeleteProviderRefreshRequest, DeleteProviderRequest, DeleteSandboxRequest,
    DeleteServiceRequest, DetachSandboxProviderRequest, ExecSandboxRequest, ExposeServiceRequest,
    GetClusterInferenceRequest, GetDraftHistoryRequest, GetDraftPolicyRequest,
    GetGatewayConfigRequest, GetProviderProfileRequest, GetProviderRefreshStatusRequest,
    GetProviderRequest, GetSandboxConfigRequest, GetSandboxLogsRequest,
    GetSandboxPolicyStatusRequest, GetSandboxRequest, GetServiceRequest, HealthRequest,
    ImportProviderProfilesRequest, LintProviderProfilesRequest, ListProviderProfilesRequest,
    ListProvidersRequest, ListSandboxPoliciesRequest, ListSandboxProvidersRequest,
    ListSandboxesRequest, ListServicesRequest, PlatformEvent, PolicySource, PolicyStatus, Provider,
    ProviderCredentialRefreshStatus, ProviderCredentialRefreshStrategy, ProviderProfile,
    ProviderProfileDiagnostic, ProviderProfileImportItem, RejectDraftChunkRequest,
    RevokeSshSessionRequest, RotateProviderCredentialRequest, Sandbox, SandboxPhase, SandboxPolicy,
    SandboxSpec, SandboxTemplate, ServiceEndpointResponse, SetClusterInferenceRequest,
    SettingScope, SettingValue, TcpForwardFrame, TcpForwardInit, TcpRelayTarget,
    UpdateConfigRequest, UpdateProviderRequest, WatchSandboxRequest, exec_sandbox_event,
    setting_value, tcp_forward_init,
};
use openshell_core::settings::{self, SettingValueKind};
use openshell_core::{ObjectId, ObjectName};
use openshell_providers::{
    ProviderRegistry, ProviderTypeProfile, RealDiscoveryContext, detect_provider_from_command,
    discover_from_profile, normalize_provider_type, parse_profile_json, parse_profile_yaml,
    profile_to_json, profile_to_yaml, profiles_to_json, profiles_to_yaml,
};
use owo_colors::OwoColorize;
use std::collections::{HashMap, HashSet};
use std::io::{ErrorKind, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tonic::{Code, Status};

// Re-export SSH functions for backward compatibility
pub use crate::ssh::{Editor, print_ssh_config};
pub use crate::ssh::{
    sandbox_connect, sandbox_connect_editor, sandbox_exec, sandbox_forward, sandbox_ssh_proxy,
    sandbox_ssh_proxy_by_name, sandbox_sync_down, sandbox_sync_up, sandbox_sync_up_files,
};
pub use openshell_core::forward::{
    find_forward_by_port, list_forwards, stop_forward, stop_forwards_for_sandbox,
};

#[derive(Debug, PartialEq, Eq)]
enum SandboxUploadPlan {
    GitAware {
        base_dir: PathBuf,
        files: Vec<String>,
    },
    Regular,
}

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

fn ready_false_condition_message(
    status: Option<&openshell_core::proto::SandboxStatus>,
) -> Option<String> {
    let condition = status?.conditions.iter().find(|condition| {
        condition.r#type == "Ready" && condition.status.eq_ignore_ascii_case("false")
    })?;

    if condition.message.is_empty() {
        if condition.reason.is_empty() {
            None
        } else {
            Some(condition.reason.clone())
        }
    } else if condition.reason.is_empty() {
        Some(condition.message.clone())
    } else {
        Some(format!("{}: {}", condition.reason, condition.message))
    }
}

fn provisioning_timeout_message(
    timeout_secs: u64,
    requested_gpu: bool,
    condition_message: Option<&str>,
) -> String {
    let mut message = format!("sandbox provisioning timed out after {timeout_secs}s");

    if let Some(condition_message) = condition_message.filter(|msg| !msg.is_empty()) {
        message.push_str(". Last reported status: ");
        message.push_str(condition_message);
    }

    if requested_gpu {
        message.push_str(
            ". Hint: this may be because the available GPU is already in use by another sandbox.",
        );
    }

    message
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
    /// Pulling the sandbox container image.
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

    /// Clear all progress output (spinner, spacer, and completed step lines).
    fn clear(&self) {
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

fn progress_step_from_metadata(value: &str) -> Option<ProvisioningStep> {
    match value {
        PROGRESS_STEP_REQUESTING_SANDBOX => Some(ProvisioningStep::RequestingSandbox),
        PROGRESS_STEP_PULLING_IMAGE => Some(ProvisioningStep::PullingSandboxImage),
        PROGRESS_STEP_STARTING_SANDBOX => Some(ProvisioningStep::StartingSandbox),
        _ => None,
    }
}

fn noninteractive_active_label(step: ProvisioningStep) -> String {
    step.active_label().trim_end_matches('.').to_string()
}

fn handle_platform_progress_event(
    event: &PlatformEvent,
    display: &mut Option<ProvisioningDisplay>,
    provision_start: Instant,
) -> bool {
    let completed_step = event
        .metadata
        .get(PROGRESS_COMPLETE_STEP_KEY)
        .and_then(|step| progress_step_from_metadata(step));
    let active_step = event
        .metadata
        .get(PROGRESS_ACTIVE_STEP_KEY)
        .and_then(|step| progress_step_from_metadata(step));
    let active_detail = event
        .metadata
        .get(PROGRESS_ACTIVE_DETAIL_KEY)
        .filter(|detail| !detail.is_empty());

    let handled = completed_step.is_some() || active_step.is_some() || active_detail.is_some();
    if !handled {
        return false;
    }

    if let Some(step) = completed_step {
        let label = event
            .metadata
            .get(PROGRESS_COMPLETE_LABEL_KEY)
            .map_or_else(|| step.completed_label(), String::as_str);
        if let Some(d) = display.as_mut() {
            d.complete_step_with_label(step, label);
        } else {
            let ts = format_timestamp(provision_start.elapsed());
            println!("{} {}", ts.dimmed(), label);
        }
    }

    if let Some(step) = active_step
        && let Some(d) = display.as_mut()
    {
        d.set_active_step(step);
    }

    if let Some(detail) = active_detail {
        if let Some(d) = display.as_mut() {
            d.set_active_detail(detail);
        } else {
            let ts = format_timestamp(provision_start.elapsed());
            if let Some(step) = active_step {
                println!(
                    "{} {} {}",
                    ts.dimmed(),
                    noninteractive_active_label(step),
                    detail
                );
            } else {
                println!("{} {}", ts.dimmed(), detail);
            }
        }
    }

    true
}

fn is_provisioning_progress_event(event: &PlatformEvent) -> bool {
    if event.metadata.contains_key(PROGRESS_COMPLETE_STEP_KEY)
        || event.metadata.contains_key(PROGRESS_ACTIVE_STEP_KEY)
        || event.metadata.contains_key(PROGRESS_ACTIVE_DETAIL_KEY)
    {
        return true;
    }

    event.source == "vm"
        && matches!(
            event.reason.as_str(),
            "PullingLayer"
                | "ResolvingImage"
                | "AuthenticatingRegistry"
                | "FetchingManifest"
                | "CacheHit"
                | "CacheMiss"
                | "WaitingForImageCacheLock"
                | "ExportingRootfs"
                | "PreparingRootfs"
                | "CreatingRootDisk"
                | "PreparingOverlay"
                | "Started"
        )
}

fn print_sandbox_header(sandbox: &Sandbox, display: Option<&ProvisioningDisplay>) {
    let lines = [
        String::new(),
        format!(
            "{} {}",
            "Created sandbox:".cyan().bold(),
            sandbox.object_name().bold()
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
              Register it first with: openshell gateway add <endpoint> --name {name}\n\
              Or list available gateways: openshell gateway select"
        )
    })?;

    save_active_gateway(name)?;
    eprintln!("{} Active gateway set to '{name}'", "✓".green().bold());
    if let Some(warning) = gateway_env_override_warning(name) {
        eprintln!("{} {warning}", "⚠".yellow().bold());
    }
    Ok(())
}

fn gateway_env_override_warning(selected_name: &str) -> Option<String> {
    let env_name = std::env::var("OPENSHELL_GATEWAY").ok()?;
    if env_name.is_empty() || env_name == selected_name {
        return None;
    }

    Some(format!(
        "OPENSHELL_GATEWAY={env_name} is set and will override this selection.\n  Unset it or run: export OPENSHELL_GATEWAY={selected_name}"
    ))
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
    let (name_width, endpoint_width, type_width) = gateway_select_column_widths(gateways);
    format!(
        "  {:<name_width$}  {:<endpoint_width$}  {:<type_width$}  {}",
        "NAME".bold(),
        "ENDPOINT".bold(),
        "TYPE".bold(),
        "AUTH".bold(),
    )
}

fn format_gateway_select_items(gateways: &[GatewayMetadata]) -> Vec<String> {
    let (name_width, endpoint_width, type_width) = gateway_select_column_widths(gateways);

    gateways
        .iter()
        .map(|gateway| {
            format!(
                "{:<name_width$}  {:<endpoint_width$}  {:<type_width$}  {}",
                gateway.name,
                gateway.gateway_endpoint,
                gateway_type_label(gateway),
                gateway_auth_label(gateway),
            )
        })
        .collect()
}

fn gateway_select_column_widths(gateways: &[GatewayMetadata]) -> (usize, usize, usize) {
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
    let type_width = gateways
        .iter()
        .map(|gateway| gateway_type_label(gateway).len())
        .max()
        .unwrap_or(4)
        .max(4);

    (name_width, endpoint_width, type_width)
}

fn gateway_type_label(gateway: &GatewayMetadata) -> &'static str {
    match gateway.auth_mode.as_deref() {
        Some("cloudflare_jwt") => "cloud",
        _ if gateway.is_remote => "remote",
        _ => "local",
    }
}

fn gateway_auth_label(gateway: &GatewayMetadata) -> &str {
    match gateway.auth_mode.as_deref() {
        Some(auth_mode) => auth_mode,
        None if gateway.gateway_endpoint.starts_with("http://") => "plaintext",
        None => "mtls",
    }
}

fn is_loopback_gateway_endpoint(endpoint: &str) -> bool {
    let Ok(parsed) = url::Url::parse(endpoint) else {
        return false;
    };

    match parsed.host() {
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// Check whether mTLS client certs exist on disk for a gateway name.
fn mtls_certs_exist_for_gateway(name: &str) -> bool {
    openshell_core::paths::xdg_config_dir().is_ok_and(|d| {
        let mtls = d.join("openshell").join("gateways").join(name).join("mtls");
        mtls.join("ca.crt").is_file()
            && mtls.join("tls.crt").is_file()
            && mtls.join("tls.key").is_file()
    })
}

fn package_managed_tls_dirs() -> Vec<PathBuf> {
    if let Some(path) = std::env::var_os("OPENSHELL_LOCAL_TLS_DIR") {
        return vec![PathBuf::from(path)];
    }

    let mut dirs = Vec::new();

    if cfg!(target_os = "macos") {
        dirs.push(PathBuf::from("/opt/homebrew/var/openshell/tls"));
        dirs.push(PathBuf::from("/usr/local/var/openshell/tls"));
    }

    let state_dir = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")));
    if let Some(state_dir) = state_dir {
        dirs.push(state_dir.join("openshell/tls"));
    }

    dirs
}

fn import_local_package_mtls_bundle(name: &str) -> Result<Option<PathBuf>> {
    for dir in package_managed_tls_dirs() {
        let ca = dir.join("ca.crt");
        let cert = dir.join("client/tls.crt");
        let key = dir.join("client/tls.key");
        if !(ca.is_file() && cert.is_file() && key.is_file()) {
            continue;
        }

        let bundle = openshell_bootstrap::pki::PkiBundle {
            ca_cert_pem: std::fs::read_to_string(&ca)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read {}", ca.display()))?,
            ca_key_pem: String::new(),
            server_cert_pem: String::new(),
            server_key_pem: String::new(),
            client_cert_pem: std::fs::read_to_string(&cert)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read {}", cert.display()))?,
            client_key_pem: std::fs::read_to_string(&key)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read {}", key.display()))?,
            // CLI never holds the gateway's JWT signing material — only the
            // gateway needs it. Fill the JWT fields with placeholders.
            jwt_signing_key_pem: String::new(),
            jwt_public_key_pem: String::new(),
            jwt_key_id: String::new(),
        };
        openshell_bootstrap::mtls::store_pki_bundle(name, &bundle)
            .wrap_err_with(|| format!("failed to store mTLS bundle for gateway '{name}'"))?;

        return Ok(Some(dir));
    }

    Ok(None)
}

fn plaintext_gateway_is_remote(endpoint: &str, remote: Option<&str>, local: bool) -> bool {
    if local {
        return false;
    }
    if remote.is_some() {
        return true;
    }
    !is_loopback_gateway_endpoint(endpoint)
}

fn plaintext_gateway_metadata(
    name: &str,
    endpoint: &str,
    remote: Option<&str>,
    local: bool,
) -> GatewayMetadata {
    let (remote_host, resolved_host) = remote.map_or((None, None), |dest| {
        let ssh_host = extract_host_from_ssh_destination(dest);
        let resolved = resolve_ssh_hostname(&ssh_host);
        (Some(dest.to_string()), Some(resolved))
    });

    GatewayMetadata {
        name: name.to_string(),
        gateway_endpoint: endpoint.to_string(),
        is_remote: plaintext_gateway_is_remote(endpoint, remote, local),
        gateway_port: 0,
        remote_host,
        resolved_host,
        auth_mode: Some("plaintext".to_string()),
        ..Default::default()
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
        gateway_list(gateway_flag, "table")?;
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

/// Register an existing gateway.
///
/// An `http://...` endpoint is registered as a direct plaintext gateway with
/// no mTLS certificate lookup or browser authentication.
///
/// Without extra flags, an `https://...` endpoint is treated as an
/// edge-authenticated (cloud) gateway and a browser is opened for
/// authentication.
///
/// Pass `remote` (SSH destination) to register a remote mTLS gateway, or
/// `local = true` for a local mTLS gateway. In both cases mTLS certificates
/// must already exist in the gateway config directory.
///
/// An `ssh://` endpoint (e.g., `ssh://user@host:8080`) is shorthand for
/// `--remote user@host` with the gateway endpoint derived from the URL.
#[allow(clippy::too_many_arguments)]
pub async fn gateway_add(
    endpoint: &str,
    name: Option<&str>,
    remote: Option<&str>,
    local: bool,
    oidc_issuer: Option<&str>,
    oidc_client_id: &str,
    oidc_audience: Option<&str>,
    oidc_scopes: Option<&str>,
    gateway_insecure: bool,
) -> Result<()> {
    // If the endpoint starts with ssh://, parse it into an SSH destination
    // and a gateway endpoint automatically.  The host is resolved via
    // `ssh -G` so that SSH config aliases map to the real hostname/IP.
    // e.g. ssh://drew@spark:8080 -> remote="drew@spark", endpoint="https://<resolved>:8080"
    let (endpoint, remote) = if endpoint.starts_with("ssh://") {
        if local {
            return Err(miette::miette!(
                "Cannot use --local with an ssh:// endpoint.\n\
                 ssh:// implies a remote gateway."
            ));
        }
        if remote.is_some() {
            return Err(miette::miette!(
                "Cannot use --remote with an ssh:// endpoint.\n\
                 The SSH destination is already embedded in the URL."
            ));
        }
        let parsed = url::Url::parse(endpoint)
            .map_err(|e| miette::miette!("Invalid ssh:// URL '{endpoint}': {e}"))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| miette::miette!("ssh:// URL must include a hostname: {endpoint}"))?;
        let port = parsed
            .port()
            .ok_or_else(|| miette::miette!("ssh:// URL must include a port: {endpoint}"))?;

        let ssh_dest = if parsed.username().is_empty() {
            host.to_string()
        } else {
            format!("{}@{host}", parsed.username())
        };
        // Resolve the SSH host alias (e.g. ~/.ssh/config HostName) so the
        // endpoint uses the actual hostname/IP that matches the TLS certificate
        // SANs.
        let resolved = resolve_ssh_hostname(host);
        let https_endpoint = format!("https://{resolved}:{port}");

        (https_endpoint, Some(ssh_dest))
    } else {
        // Normalise the endpoint: ensure it has a scheme.
        let endpoint = if endpoint.contains("://") {
            endpoint.to_string()
        } else {
            format!("https://{endpoint}")
        };
        (endpoint, remote.map(String::from))
    };
    let remote = remote.as_deref();

    // Derive a gateway name from the hostname when none is provided.
    // Loopback endpoints use the canonical "openshell" name, matching the
    // convention in local cert generation and default_tls_dir.
    let derived_name;
    let name = if let Some(n) = name {
        n
    } else if is_loopback_gateway_endpoint(&endpoint) {
        derived_name = "openshell".to_string();
        &derived_name
    } else {
        // Parse out just the host portion of the URL.
        derived_name = url::Url::parse(&endpoint)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| endpoint.clone());
        &derived_name
    };

    // Fail if a gateway with this name already exists.
    if get_gateway_metadata(name).is_some() {
        return Err(miette::miette!(
            "Gateway '{}' already exists.\n\
             Remove it first with: openshell gateway remove {}\n\
             Or choose a different name with: --name <name>",
            name,
            name,
        ));
    }

    // OIDC takes precedence over plaintext/mTLS/edge detection — the user
    // explicitly opted in with --oidc-issuer regardless of scheme.
    if let Some(issuer) = oidc_issuer {
        let previous_active = load_active_gateway();
        let metadata = GatewayMetadata {
            name: name.to_string(),
            gateway_endpoint: endpoint.clone(),
            is_remote: !local,
            auth_mode: Some("oidc".to_string()),
            oidc_issuer: Some(issuer.to_string()),
            oidc_client_id: Some(oidc_client_id.to_string()),
            oidc_audience: oidc_audience.map(String::from),
            oidc_scopes: oidc_scopes.map(String::from),
            ..Default::default()
        };

        store_gateway_metadata(name, &metadata)?;
        save_active_gateway(name)?;

        eprintln!(
            "{} Gateway '{}' added and set as active",
            "✓".green().bold(),
            name,
        );
        eprintln!("  {} {}", "Endpoint:".dimmed(), endpoint);
        eprintln!("  {} oidc", "Auth:".dimmed());
        eprintln!();

        let auth_skipped = is_browser_suppressed();

        // Check for client_credentials env var (CI mode).
        let auth_ok = if std::env::var("OPENSHELL_OIDC_CLIENT_SECRET").is_ok() {
            match crate::oidc_auth::oidc_client_credentials_flow(
                issuer,
                oidc_client_id,
                oidc_audience,
                oidc_scopes,
                gateway_insecure,
            )
            .await
            {
                Ok(bundle) => {
                    openshell_bootstrap::oidc_token::store_oidc_token(name, &bundle)?;
                    eprintln!(
                        "{} Authenticated via client credentials",
                        "✓".green().bold()
                    );
                    true
                }
                Err(e) => {
                    eprintln!("{} Authentication failed: {e}", "!".yellow());
                    false
                }
            }
        } else {
            match crate::oidc_auth::oidc_browser_auth_flow(
                issuer,
                oidc_client_id,
                oidc_audience,
                oidc_scopes,
                gateway_insecure,
            )
            .await
            {
                Ok(bundle) => {
                    openshell_bootstrap::oidc_token::store_oidc_token(name, &bundle)?;
                    eprintln!("{} Authenticated successfully", "✓".green().bold());
                    true
                }
                Err(e) => {
                    eprintln!("{} Authentication failed: {e}", "!".yellow());
                    false
                }
            }
        };

        if !auth_ok && !auth_skipped {
            rollback_gateway_registration(name, previous_active.as_deref());
        }

        return Ok(());
    }

    if endpoint.starts_with("http://") {
        // Warn if mTLS certs exist for this gateway — the user likely
        // meant to use https:// instead of http://.
        let has_mtls_certs = mtls_certs_exist_for_gateway(name);

        if has_mtls_certs {
            let https_endpoint = endpoint.replacen("http://", "https://", 1);
            let suggestion = if is_loopback_gateway_endpoint(&endpoint) {
                format!("openshell gateway add --local {https_endpoint}")
            } else {
                format!("openshell gateway add {https_endpoint}")
            };
            eprintln!(
                "{} mTLS certificates found for gateway '{name}'. Did you mean to use https?",
                "⚠".yellow().bold(),
            );
            eprintln!("  Try: {suggestion}");
        }

        let metadata = plaintext_gateway_metadata(name, &endpoint, remote, local);
        let gateway_type = gateway_type_label(&metadata);
        let gateway_auth = gateway_auth_label(&metadata);

        store_gateway_metadata(name, &metadata)?;
        save_active_gateway(name)?;

        // Verify the gateway is reachable.
        let tls = TlsOptions::default();
        if !gateway_reachable(&endpoint, &tls).await {
            eprintln!(
                "{} Gateway is not reachable at {endpoint}",
                "⚠".yellow().bold(),
            );
            if !has_mtls_certs {
                eprintln!("  Verify the gateway is running and the endpoint is correct.");
            }
        }

        eprintln!(
            "{} Gateway '{}' added and set as active",
            "✓".green().bold(),
            name,
        );
        eprintln!("  {} {}", "Endpoint:".dimmed(), endpoint);
        eprintln!("  {} {}", "Type:".dimmed(), gateway_type);
        eprintln!("  {} {}", "Auth:".dimmed(), gateway_auth);

        return Ok(());
    }

    if remote.is_some() || local {
        // mTLS gateway (remote or local).
        let imported_mtls_dir = if local {
            import_local_package_mtls_bundle(name)?
        } else {
            None
        };
        let certs_on_disk = imported_mtls_dir.is_some() || mtls_certs_exist_for_gateway(name);
        if !certs_on_disk {
            return Err(miette::miette!(
                "mTLS certificates for gateway '{name}' were not found.\n\
                 Expected them under the default gateway config directory.\n\
                 Start the gateway package first so it provisions client TLS material, \
                 then retry: openshell gateway add {endpoint}{}",
                if local { " --local" } else { "" },
            ));
        }

        let (remote_host, resolved_host) = remote.map_or((None, None), |dest| {
            let ssh_host = extract_host_from_ssh_destination(dest);
            let resolved = resolve_ssh_hostname(&ssh_host);
            (Some(dest.to_string()), Some(resolved))
        });

        let metadata = GatewayMetadata {
            name: name.to_string(),
            gateway_endpoint: endpoint.clone(),
            is_remote: !local,
            gateway_port: 0,
            remote_host,
            resolved_host,
            auth_mode: Some("mtls".to_string()),
            ..Default::default()
        };

        store_gateway_metadata(name, &metadata)?;
        save_active_gateway(name)?;

        // Verify the gateway is reachable over mTLS.
        let tls = TlsOptions::default().with_gateway_name(name);
        if !gateway_reachable(&endpoint, &tls).await {
            eprintln!(
                "{} Gateway is not reachable at {endpoint}. Verify the gateway is running.",
                "⚠".yellow().bold(),
            );
        }

        eprintln!(
            "{} Gateway '{}' added and set as active",
            "✓".green().bold(),
            name,
        );
        eprintln!("  {} {}", "Endpoint:".dimmed(), endpoint);
        eprintln!(
            "  {} {}",
            "Type:".dimmed(),
            if local { "local" } else { "remote" },
        );
        eprintln!("{} TLS certificates present", "✓".green().bold());
    } else {
        // Cloud (edge-authenticated) gateway.
        let previous_active = load_active_gateway();
        let metadata = GatewayMetadata {
            name: name.to_string(),
            gateway_endpoint: endpoint.clone(),
            is_remote: true,
            auth_mode: Some("cloudflare_jwt".to_string()),
            ..Default::default()
        };

        store_gateway_metadata(name, &metadata)?;
        save_active_gateway(name)?;

        eprintln!(
            "{} Gateway '{}' added and set as active",
            "✓".green().bold(),
            name,
        );
        eprintln!("  {} {}", "Endpoint:".dimmed(), endpoint);
        eprintln!("  {} cloud", "Type:".dimmed());
        eprintln!();

        let auth_skipped = is_browser_suppressed();

        let auth_ok = match crate::auth::browser_auth_flow(&endpoint).await {
            Ok(token) => {
                openshell_bootstrap::edge_token::store_edge_token(name, &token)?;
                eprintln!("{} Authenticated successfully", "✓".green().bold());
                true
            }
            Err(e) => {
                eprintln!("{} Authentication failed: {e}", "!".yellow());
                false
            }
        };

        if !auth_ok && !auth_skipped {
            rollback_gateway_registration(name, previous_active.as_deref());
        }
    }

    Ok(())
}

/// Re-authenticate with an edge-authenticated or OIDC gateway.
///
/// Dispatches to the appropriate auth flow based on `auth_mode`.
pub async fn gateway_login(name: &str, gateway_insecure: bool) -> Result<()> {
    let metadata = openshell_bootstrap::load_gateway_metadata(name).map_err(|_| {
        miette::miette!(
            "Unknown gateway '{name}'.\n\
             List available gateways: openshell gateway select"
        )
    })?;

    match metadata.auth_mode.as_deref() {
        Some("cloudflare_jwt") => {
            let token = crate::auth::browser_auth_flow(&metadata.gateway_endpoint).await?;
            openshell_bootstrap::edge_token::store_edge_token(name, &token)?;
            eprintln!("{} Authenticated to gateway '{name}'", "✓".green().bold());
        }
        Some("oidc") => {
            let issuer = metadata.oidc_issuer.as_deref().ok_or_else(|| {
                miette::miette!("Gateway '{name}' has OIDC auth but no issuer URL in metadata")
            })?;
            let client_id = metadata
                .oidc_client_id
                .as_deref()
                .unwrap_or("openshell-cli");
            let audience = metadata.oidc_audience.as_deref();
            let scopes = metadata.oidc_scopes.as_deref();

            let bundle = if std::env::var("OPENSHELL_OIDC_CLIENT_SECRET").is_ok() {
                crate::oidc_auth::oidc_client_credentials_flow(
                    issuer,
                    client_id,
                    audience,
                    scopes,
                    gateway_insecure,
                )
                .await?
            } else {
                crate::oidc_auth::oidc_browser_auth_flow(
                    issuer,
                    client_id,
                    audience,
                    scopes,
                    gateway_insecure,
                )
                .await?
            };

            let username = jwt_preferred_username(&bundle.access_token);
            openshell_bootstrap::oidc_token::store_oidc_token(name, &bundle)?;

            if let Some(user) = username {
                eprintln!(
                    "{} Authenticated to gateway '{name}' as {user}",
                    "✓".green().bold(),
                );
            } else {
                eprintln!("{} Authenticated to gateway '{name}'", "✓".green().bold());
            }
        }
        _ => {
            return Err(miette::miette!(
                "Gateway '{name}' does not use edge or OIDC authentication.\n\
                 Only edge-authenticated and OIDC gateways support browser login."
            ));
        }
    }

    Ok(())
}

/// Extract `preferred_username` from a JWT payload without signature verification.
fn jwt_preferred_username(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    claims
        .get("preferred_username")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Clear stored authentication credentials for a gateway.
pub fn gateway_logout(name: &str) -> Result<()> {
    let metadata = openshell_bootstrap::load_gateway_metadata(name).map_err(|_| {
        miette::miette!(
            "Unknown gateway '{name}'.\n\
             List available gateways: openshell gateway select"
        )
    })?;

    match metadata.auth_mode.as_deref() {
        Some("oidc") => {
            openshell_bootstrap::oidc_token::remove_oidc_token(name)?;
        }
        Some("cloudflare_jwt") => {
            openshell_bootstrap::edge_token::remove_edge_token(name)?;
        }
        _ => {
            return Err(miette::miette!(
                "Gateway '{name}' uses {} authentication — no stored credentials to clear.",
                metadata.auth_mode.as_deref().unwrap_or("mtls")
            ));
        }
    }

    eprintln!("{} Logged out of gateway '{name}'", "✓".green().bold());
    Ok(())
}

/// List all registered gateways.
pub fn gateway_list(gateway_flag: &Option<String>, output: &str) -> Result<()> {
    let gateways = list_gateways()?;
    let active = gateway_flag.clone().or_else(load_active_gateway);

    match output {
        "json" => {
            let items: Vec<serde_json::Value> = gateways
                .iter()
                .map(|g| gateway_to_json(g, &active))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&items).into_diagnostic()?
            );
            return Ok(());
        }
        "yaml" => {
            let items: Vec<serde_json::Value> = gateways
                .iter()
                .map(|g| gateway_to_json(g, &active))
                .collect();
            print!("{}", serde_yml::to_string(&items).into_diagnostic()?);
            return Ok(());
        }
        "table" => {}
        _ => return Err(miette!("unsupported output format: {output}")),
    }

    if gateways.is_empty() {
        println!("No gateways found.");
        println!();
        println!(
            "Register a gateway with: {}",
            "openshell gateway add <endpoint>".dimmed()
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
    let type_width = gateways
        .iter()
        .map(|g| gateway_type_label(g).len())
        .max()
        .unwrap_or(4)
        .max(4);

    // Print header
    println!(
        "  {:<name_width$}  {:<endpoint_width$}  {:<type_width$}  {}",
        "NAME".bold(),
        "ENDPOINT".bold(),
        "TYPE".bold(),
        "AUTH".bold(),
    );

    // Print rows
    for gateway in &gateways {
        let is_active = active.as_deref() == Some(&gateway.name);
        let marker = if is_active { "*" } else { " " };
        let gw_type = gateway_type_label(gateway);
        let gw_auth = gateway_auth_label(gateway);
        let line = format!(
            "{marker} {:<name_width$}  {:<endpoint_width$}  {:<type_width$}  {gw_auth}",
            gateway.name, gateway.gateway_endpoint, gw_type,
        );
        if is_active {
            println!("{}", line.green());
        } else {
            println!("{line}");
        }
    }

    Ok(())
}

fn gateway_to_json(gateway: &GatewayMetadata, active: &Option<String>) -> serde_json::Value {
    serde_json::json!({
        "name": gateway.name,
        "endpoint": gateway.gateway_endpoint,
        "type": gateway_type_label(gateway),
        "auth": gateway_auth_label(gateway),
        "active": active.as_deref() == Some(&gateway.name),
    })
}

async fn http_health_check(server: &str, tls: &TlsOptions) -> Result<Option<StatusCode>> {
    let base = server.trim_end_matches('/');
    let uri: hyper::Uri = format!("{base}/healthz").parse().into_diagnostic()?;

    let scheme = uri.scheme_str().unwrap_or("https");
    let https = if tls.gateway_insecure && scheme.eq_ignore_ascii_case("https") {
        let insecure_config = build_insecure_rustls_config()?;
        HttpsConnectorBuilder::new()
            .with_tls_config(insecure_config)
            .https_or_http()
            .enable_http1()
            .build()
    } else if scheme.eq_ignore_ascii_case("http") || tls.is_bearer_auth() {
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

async fn gateway_reachable(server: &str, tls: &TlsOptions) -> bool {
    if let Ok(mut client) = grpc_client(server, tls).await
        && client.health(HealthRequest {}).await.is_ok()
    {
        return true;
    }

    matches!(http_health_check(server, tls).await, Ok(Some(status)) if status.is_success())
}

fn is_browser_suppressed() -> bool {
    std::env::var("OPENSHELL_NO_BROWSER").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn rollback_gateway_registration(name: &str, previous_active: Option<&str>) {
    remove_gateway_registration(name);
    if let Some(prev) = previous_active
        && let Err(e) = save_active_gateway(prev)
    {
        tracing::warn!("failed to restore previous active gateway '{prev}': {e}");
        eprintln!(
            "{} Failed to restore previous active gateway '{}': {e}",
            "!".yellow(),
            prev,
        );
    }
    eprintln!(
        "{} Registration for '{}' removed. Fix the issue and retry gateway add.",
        "!".yellow(),
        name,
    );
}

fn remove_gateway_registration(name: &str) {
    if let Err(err) = openshell_bootstrap::edge_token::remove_edge_token(name) {
        tracing::debug!("failed to remove edge token: {err}");
    }
    if let Err(err) = openshell_bootstrap::oidc_token::remove_oidc_token(name) {
        tracing::debug!("failed to remove oidc token: {err}");
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

/// Remove a local gateway registration without touching the gateway service.
pub fn gateway_remove(name: &str) -> Result<()> {
    if get_gateway_metadata(name).is_none() {
        return Err(miette::miette!(
            "No gateway metadata found for '{name}'.\n\
             List available gateways: openshell gateway select"
        ));
    }

    remove_gateway_registration(name);
    eprintln!(
        "{} Gateway registration '{name}' removed.",
        "✓".green().bold()
    );
    Ok(())
}

/// Show gateway registration details.
pub fn gateway_admin_info(name: &str) -> Result<()> {
    let metadata = get_gateway_metadata(name).ok_or_else(|| {
        miette::miette!(
            "No gateway metadata found for '{name}'.\n\
              Register it first: openshell gateway add <endpoint> --name {name}"
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

/// Validate system prerequisites for running a gateway.
///
/// Checks Docker connectivity and reports the result. Returns exit code 0
/// if all checks pass, 1 otherwise.
pub fn doctor_check() -> Result<()> {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();

    writeln!(stdout, "Checking system prerequisites...\n").into_diagnostic()?;

    // --- Docker connectivity ---
    write!(stdout, "  Docker ............. ").into_diagnostic()?;
    stdout.flush().into_diagnostic()?;

    let output = Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .into_diagnostic()
        .wrap_err("failed to execute docker info")?;

    if output.status.success() {
        let version = String::from_utf8_lossy(&output.stdout);
        let version_str = version.trim();
        writeln!(stdout, "ok (version {version_str})").into_diagnostic()?;

        // --- DOCKER_HOST ---
        write!(stdout, "  DOCKER_HOST ........ ").into_diagnostic()?;
        match std::env::var("DOCKER_HOST") {
            Ok(val) => writeln!(stdout, "{val}").into_diagnostic()?,
            Err(_) => writeln!(stdout, "(not set, using default socket)").into_diagnostic()?,
        }

        writeln!(stdout, "\nAll checks passed.").into_diagnostic()?;
        return Ok(());
    }

    writeln!(stdout, "FAILED").into_diagnostic()?;
    writeln!(stdout).into_diagnostic()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(miette::miette!("docker info failed: {}", stderr.trim()))
}

fn sandbox_should_persist(
    keep: bool,
    forward: Option<&openshell_core::forward::ForwardSpec>,
) -> bool {
    keep || forward.is_some()
}

fn build_sandbox_resource_limits(
    cpu: Option<&str>,
    memory: Option<&str>,
) -> Result<Option<prost_types::Struct>> {
    use prost_types::{Struct, Value, value::Kind};

    fn string_value(value: String) -> Value {
        Value {
            kind: Some(Kind::StringValue(value)),
        }
    }

    let mut limits = std::collections::BTreeMap::new();
    if let Some(cpu) = cpu {
        limits.insert("cpu".to_string(), string_value(validate_cpu_quantity(cpu)?));
    }
    if let Some(memory) = memory {
        limits.insert(
            "memory".to_string(),
            string_value(validate_memory_quantity(memory)?),
        );
    }

    if limits.is_empty() {
        return Ok(None);
    }

    let mut fields = std::collections::BTreeMap::new();
    fields.insert(
        "limits".to_string(),
        Value {
            kind: Some(Kind::StructValue(Struct { fields: limits })),
        },
    );
    Ok(Some(Struct { fields }))
}

fn parse_driver_config_json(value: &str) -> Result<prost_types::Struct> {
    let parsed: serde_json::Value = serde_json::from_str(value)
        .into_diagnostic()
        .wrap_err("--driver-config-json must be valid JSON")?;

    let serde_json::Value::Object(fields) = parsed else {
        return Err(miette!(
            "--driver-config-json must be a JSON object keyed by driver name"
        ));
    };

    Ok(prost_types::Struct {
        fields: fields
            .into_iter()
            .map(|(key, value)| json_to_protobuf_value(value).map(|value| (key, value)))
            .collect::<Result<_>>()?,
    })
}

fn json_to_protobuf_value(value: serde_json::Value) -> Result<prost_types::Value> {
    use prost_types::{ListValue, Struct, Value, value::Kind};

    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(value) => Kind::BoolValue(value),
        serde_json::Value::Number(value) => Kind::NumberValue(value.as_f64().ok_or_else(|| {
            miette!("--driver-config-json contains a number that cannot be represented")
        })?),
        serde_json::Value::String(value) => Kind::StringValue(value),
        serde_json::Value::Array(values) => Kind::ListValue(ListValue {
            values: values
                .into_iter()
                .map(json_to_protobuf_value)
                .collect::<Result<_>>()?,
        }),
        serde_json::Value::Object(fields) => Kind::StructValue(Struct {
            fields: fields
                .into_iter()
                .map(|(key, value)| json_to_protobuf_value(value).map(|value| (key, value)))
                .collect::<Result<_>>()?,
        }),
    };

    Ok(Value { kind: Some(kind) })
}

fn validate_cpu_quantity(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(miette!("--cpu must not be empty"));
    }

    if let Some(millicores) = value.strip_suffix('m') {
        if millicores.is_empty() || !millicores.bytes().all(|b| b.is_ascii_digit()) {
            return Err(miette!(
                "invalid --cpu value '{value}': expected positive cores or millicores, for example 2, 0.5, or 500m"
            ));
        }
        let millicores = millicores.parse::<u64>().into_diagnostic()?;
        if millicores == 0 {
            return Err(miette!("--cpu must be greater than zero"));
        }
        return Ok(value.to_string());
    }

    let cores = value.parse::<f64>().map_err(|_| {
        miette!(
            "invalid --cpu value '{value}': expected positive cores or millicores, for example 2, 0.5, or 500m"
        )
    })?;
    if !cores.is_finite() || cores <= 0.0 {
        return Err(miette!("--cpu must be greater than zero"));
    }
    Ok(value.to_string())
}

fn validate_memory_quantity(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(miette!("--memory must not be empty"));
    }

    let number_end = value
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, suffix) = value.split_at(number_end);
    if number.is_empty()
        || !matches!(
            suffix,
            "" | "Ki" | "Mi" | "Gi" | "Ti" | "Pi" | "Ei" | "K" | "M" | "G" | "T" | "P" | "E"
        )
    {
        return Err(miette!(
            "invalid --memory value '{value}': expected positive bytes or a quantity such as 512Mi, 4Gi, or 8G"
        ));
    }

    let amount = number.parse::<u128>().into_diagnostic()?;
    if amount == 0 {
        return Err(miette!("--memory must be greater than zero"));
    }
    Ok(value.to_string())
}

async fn finalize_sandbox_create_session(
    server: &str,
    sandbox_name: &str,
    persist: bool,
    session_result: Result<()>,
    tls: &TlsOptions,
    gateway: &str,
) -> Result<()> {
    if persist {
        return session_result;
    }

    let names = [sandbox_name.to_string()];
    if let Err(err) = sandbox_delete(server, &names, false, tls, gateway).await {
        if session_result.is_ok() {
            return Err(err);
        }
        eprintln!("Failed to delete sandbox {sandbox_name}: {err}");
    }

    session_result
}

/// Create a sandbox with default settings.
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)] // user-facing CLI command; default hasher is fine
pub async fn sandbox_create(
    server: &str,
    name: Option<&str>,
    from: Option<&str>,
    gateway_name: &str,
    uploads: &[(String, Option<String>, bool)],
    keep: bool,
    gpu: bool,
    gpu_device: Option<&str>,
    cpu: Option<&str>,
    memory: Option<&str>,
    driver_config_json: Option<&str>,
    editor: Option<Editor>,
    providers: &[String],
    policy: Option<&str>,
    forward: Option<openshell_core::forward::ForwardSpec>,
    command: &[String],
    tty_override: Option<bool>,
    auto_providers_override: Option<bool>,
    labels: &HashMap<String, String>,
    approval_mode: &str,
    tls: &TlsOptions,
) -> Result<()> {
    if editor.is_some() && !command.is_empty() {
        return Err(miette::miette!(
            "--editor cannot be used with a trailing command; use `openshell sandbox connect <name> --editor ...` after the sandbox is ready"
        ));
    }

    // Check port availability *before* creating the sandbox so we don't
    // leave an orphaned sandbox behind when the forward would fail.
    if let Some(ref spec) = forward {
        openshell_core::forward::check_port_available(spec)?;
    }

    let mut client = grpc_client(server, tls).await.wrap_err_with(|| {
        format!(
            "failed to connect to gateway '{gateway_name}' at {server}. \
                 Start the gateway service with the installed package manager, \
                 or register a different endpoint with `openshell gateway add <endpoint>`."
        )
    })?;
    let effective_server = server.to_string();
    let effective_tls = tls.clone();

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
    let requested_gpu = gpu || image.as_deref().is_some_and(image_requests_gpu);

    let providers_v2_enabled = gateway_providers_v2_enabled(&mut client).await?;
    let inferred_types: Vec<String> = if providers_v2_enabled {
        Vec::new()
    } else {
        inferred_provider_type(command).into_iter().collect()
    };
    let configured_providers = ensure_required_providers(
        &mut client,
        providers,
        &inferred_types,
        auto_providers_override,
    )
    .await?;

    let policy = load_sandbox_policy(policy)?;
    let resource_limits = build_sandbox_resource_limits(cpu, memory)?;
    let driver_config = driver_config_json
        .map(parse_driver_config_json)
        .transpose()?;

    let template = if image.is_some() || resource_limits.is_some() || driver_config.is_some() {
        Some(SandboxTemplate {
            image: image.unwrap_or_default(),
            resources: resource_limits,
            driver_config,
            ..SandboxTemplate::default()
        })
    } else {
        None
    };

    let request = CreateSandboxRequest {
        spec: Some(SandboxSpec {
            gpu: requested_gpu,
            gpu_device: gpu_device.unwrap_or_default().to_string(),
            policy,
            providers: configured_providers,
            template,
            ..SandboxSpec::default()
        }),
        name: name.unwrap_or_default().to_string(),
        labels: labels.clone(),
    };

    let response = match client.create_sandbox(request).await {
        Ok(resp) => resp,
        Err(status) if status.code() == Code::AlreadyExists => {
            return Err(miette::miette!(
                "{}\n\nhint: delete it first with: openshell sandbox delete <name>\n      or use a different name",
                status.message()
            ));
        }
        Err(status) => return Err(miette::miette!(status.to_string())),
    };
    let sandbox = response
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox missing from response"))?;

    let interactive = std::io::stdout().is_terminal();
    let persist = sandbox_should_persist(keep, forward.as_ref());
    let sandbox_name = if sandbox.object_name().is_empty() {
        "unknown".to_string()
    } else {
        sandbox.object_name().to_string()
    };

    // Record this sandbox as the last-used for the active gateway only when it
    // is expected to persist beyond the initial session.
    if persist && let Some(gateway) = effective_tls.gateway_name() {
        let _ = save_last_sandbox(gateway, &sandbox_name);
    }

    // Persist `--approval-mode` as a sandbox-scoped setting now that the
    // sandbox exists. `manual` is the implicit default (no setting needed);
    // any other value is written so it survives sandbox restarts and can be
    // flipped later via `openshell settings set <name> proposal_approval_mode`.
    // If the write fails the sandbox still runs in default `manual` — surface
    // the recovery command so the user can retry.
    if approval_mode != "manual" {
        let setting = parse_cli_setting_value(settings::PROPOSAL_APPROVAL_MODE_KEY, approval_mode)?;
        match client
            .update_config(UpdateConfigRequest {
                name: sandbox_name.clone(),
                policy: None,
                setting_key: settings::PROPOSAL_APPROVAL_MODE_KEY.to_string(),
                setting_value: Some(setting),
                delete_setting: false,
                global: false,
                merge_operations: vec![],
                expected_resource_version: 0,
            })
            .await
        {
            Ok(_) => {}
            Err(status) => {
                eprintln!(
                    "{} failed to set approval mode '{approval_mode}' on sandbox '{sandbox_name}': {}\n  retry with: openshell settings set {sandbox_name} proposal_approval_mode {approval_mode}",
                    "warning:".yellow().bold(),
                    status.message(),
                );
            }
        }
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
    let sandbox_id = if sandbox.object_id().is_empty() {
        "unknown".to_string()
    } else {
        sandbox.object_id().to_string()
    };
    let mut stream = client
        .watch_sandbox(WatchSandboxRequest {
            id: sandbox_id.clone(),
            follow_status: true,
            follow_logs: true,
            follow_events: true,
            log_tail_lines: 200,
            event_tail: 50,
            stop_on_terminal: false,
            log_since_ms: 0,
            log_sources: vec!["gateway".to_string()],
            log_min_level: String::new(),
        })
        .await
        .into_diagnostic()?
        .into_inner();

    let mut last_phase = sandbox.phase();
    let mut last_error_reason = String::new();
    let mut last_condition_message = ready_false_condition_message(sandbox.status.as_ref());
    // Track whether we have seen a non-Ready phase during the watch.
    let mut saw_non_ready = SandboxPhase::try_from(sandbox.phase()) != Ok(SandboxPhase::Ready);
    let provision_timeout = Duration::from_secs(
        std::env::var("OPENSHELL_PROVISION_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300),
    );
    let mut provisioning_idle_deadline = Instant::now() + provision_timeout;
    // Track whether we saw the gateway become ready (from log messages).
    let mut saw_gateway_ready = false;

    loop {
        // Timeout only when provisioning goes idle. VM first-create can spend
        // longer than the default timeout pulling and preparing large images,
        // but only recognized progress events extend the idle deadline. Logs
        // and generic status churn must not keep a stuck sandbox alive forever.
        let remaining = provisioning_idle_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let timeout_message = provisioning_timeout_message(
                provision_timeout.as_secs(),
                requested_gpu,
                last_condition_message.as_deref(),
            );
            if let Some(d) = display.as_mut() {
                d.finish_error(&timeout_message);
            }
            println!();
            return Err(miette::miette!(timeout_message));
        }

        let maybe_item = tokio::time::timeout(remaining, stream.next()).await;

        let item = match maybe_item {
            Ok(Some(item)) => item,
            Ok(None) => break, // stream ended
            Err(_elapsed) => {
                // Timeout fired — the stream was idle for too long.
                let timeout_message = provisioning_timeout_message(
                    provision_timeout.as_secs(),
                    requested_gpu,
                    last_condition_message.as_deref(),
                );
                if let Some(d) = display.as_mut() {
                    d.finish_error(&timeout_message);
                }
                println!();
                return Err(miette::miette!(timeout_message));
            }
        };

        let evt = item.into_diagnostic()?;
        match evt.payload {
            Some(openshell_core::proto::sandbox_stream_event::Payload::Sandbox(s)) => {
                let phase = SandboxPhase::try_from(s.phase()).unwrap_or(SandboxPhase::Unknown);
                last_phase = s.phase();
                if let Some(message) = ready_false_condition_message(s.status.as_ref()) {
                    last_condition_message = Some(message);
                }

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
                    break;
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
            Some(openshell_core::proto::sandbox_stream_event::Payload::Log(line)) => {
                // Detect gateway readiness from log messages.
                if !saw_gateway_ready && line.message.contains("listening") {
                    saw_gateway_ready = true;
                }
            }
            Some(openshell_core::proto::sandbox_stream_event::Payload::Event(ev)) => {
                let extends_timeout = is_provisioning_progress_event(&ev);
                if handle_platform_progress_event(&ev, &mut display, provision_start) {
                    if extends_timeout {
                        provisioning_idle_deadline = Instant::now() + provision_timeout;
                    }
                    continue;
                }
                if extends_timeout {
                    provisioning_idle_deadline = Instant::now() + provision_timeout;
                }

                if let Some(d) = display.as_mut() {
                    // Unknown events: show as detail on the current spinner.
                    if !ev.message.is_empty() {
                        d.set_active_detail(&ev.message);
                    }
                }
            }
            Some(openshell_core::proto::sandbox_stream_event::Payload::Warning(w)) => {
                if let Some(d) = display.as_mut() {
                    d.println(&format!("  {} {}", "!".yellow().bold(), w.message.yellow()));
                } else {
                    let ts = format_timestamp(provision_start.elapsed());
                    eprintln!("  {} {} {}", ts.dimmed(), "WARN".yellow(), w.message);
                }
            }
            Some(openshell_core::proto::sandbox_stream_event::Payload::DraftPolicyUpdate(_))
            | None => {
                // Draft policy updates are handled in the draft panel, not during provisioning.
            }
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

            let upload_count = uploads.len();
            for (idx, (local_path, sandbox_path, git_ignore)) in uploads.iter().enumerate() {
                let dest = sandbox_path.as_deref();
                let dest_display = dest.unwrap_or("~");
                if upload_count > 1 {
                    eprintln!(
                        "  {} Uploading [{}/{}] files to {dest_display}...",
                        "\u{2022}".dimmed(),
                        idx + 1,
                        upload_count,
                    );
                } else {
                    eprintln!(
                        "  {} Uploading files to {dest_display}...",
                        "\u{2022}".dimmed(),
                    );
                }
                let local = Path::new(local_path);
                match sandbox_upload_plan(local, *git_ignore)? {
                    SandboxUploadPlan::GitAware { base_dir, files } => {
                        sandbox_sync_up_files(
                            &effective_server,
                            &sandbox_name,
                            &base_dir,
                            &files,
                            local,
                            dest,
                            &effective_tls,
                        )
                        .await?;
                    }
                    SandboxUploadPlan::Regular => {
                        sandbox_sync_up(
                            &effective_server,
                            &sandbox_name,
                            local,
                            dest,
                            &effective_tls,
                        )
                        .await?;
                    }
                }
                eprintln!("  {} Files uploaded", "\u{2713}".green().bold());
            }

            // If --forward was requested, start the background port forward
            // *before* running the command so that long-running processes
            // (e.g. a web gateway) are reachable immediately.
            if let Some(ref spec) = forward {
                sandbox_forward(
                    &effective_server,
                    &sandbox_name,
                    spec,
                    true, // background
                    &effective_tls,
                )
                .await?;
                eprintln!(
                    "  {} Forwarding port {} to sandbox {sandbox_name} in the background\n",
                    "\u{2713}".green().bold(),
                    spec.port,
                );
                eprintln!("  Access at: {}", spec.access_url());
                eprintln!(
                    "  Stop with: openshell forward stop {} {sandbox_name}",
                    spec.port,
                );
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
                let connect_result = if persist {
                    sandbox_connect(&effective_server, &sandbox_name, &effective_tls).await
                } else {
                    crate::ssh::sandbox_connect_without_exec(
                        &effective_server,
                        &sandbox_name,
                        &effective_tls,
                    )
                    .await
                };

                return finalize_sandbox_create_session(
                    &effective_server,
                    &sandbox_name,
                    persist,
                    connect_result,
                    &effective_tls,
                    gateway_name,
                )
                .await;
            }

            // Resolve TTY mode: explicit --tty / --no-tty wins, otherwise
            // auto-detect from the local terminal.
            let tty = tty_override.unwrap_or_else(|| {
                std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
            });
            let exec_result = if persist {
                sandbox_exec(
                    &effective_server,
                    &sandbox_name,
                    command,
                    tty,
                    &effective_tls,
                )
                .await
            } else {
                crate::ssh::sandbox_exec_without_exec(
                    &effective_server,
                    &sandbox_name,
                    command,
                    tty,
                    &effective_tls,
                )
                .await
            };

            finalize_sandbox_create_session(
                &effective_server,
                &sandbox_name,
                persist,
                exec_result,
                &effective_tls,
                gateway_name,
            )
            .await
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

/// Resolved source for the `--from` flag on `sandbox create`.
#[derive(Debug)]
enum ResolvedSource {
    /// A ready-to-use container image reference.
    Image(String),
    /// A Dockerfile that must be built before creating the sandbox.
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
/// 3. Missing explicit local paths → local error, not image pull.
/// 4. Value contains `/`, `:`, or `.` → treat as a full image reference.
/// 5. Otherwise → community sandbox name, expanded via the registry prefix.
fn resolve_from(value: &str) -> Result<ResolvedSource> {
    let path = Path::new(value);

    // 1. Existing file that looks like a Dockerfile.
    if path.is_file() {
        if filename_looks_like_dockerfile(path) {
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

        if value_looks_like_local_source(value) {
            return Err(miette::miette!(
                "local --from file is not a Dockerfile: {}",
                path.display()
            ));
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

    if path.exists() {
        return Err(miette::miette!(
            "local --from path is not a regular file or directory: {}",
            path.display()
        ));
    }

    // 3. Missing explicit local paths should fail locally. Otherwise values
    // like `./Dockerfile` reach the gateway as image references and fail as
    // Docker pull errors.
    if value_looks_like_local_source(value) {
        return Err(miette::miette!(
            "local --from path does not exist: {}\n\
             Use an existing Dockerfile, a directory containing Dockerfile, or a container image reference.",
            path.display()
        ));
    }

    // 4. Full image reference or community sandbox name — delegate to shared
    //    resolution in openshell-core.
    Ok(ResolvedSource::Image(
        openshell_core::image::resolve_community_image(value),
    ))
}

fn filename_looks_like_dockerfile(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let lower = name.to_lowercase();
    lower.contains("dockerfile") || lower.ends_with(".dockerfile")
}

fn value_looks_like_local_source(value: &str) -> bool {
    value_is_explicit_local_path(value) || value_looks_like_bare_dockerfile_name(value)
}

fn value_is_explicit_local_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        || matches!(value, "." | "..")
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("~/")
}

fn value_looks_like_bare_dockerfile_name(value: &str) -> bool {
    !value.contains('/') && !value.contains(':') && filename_looks_like_dockerfile(Path::new(value))
}

fn image_requests_gpu(image: &str) -> bool {
    let image_name = image
        .rsplit('/')
        .next()
        .unwrap_or(image)
        .split([':', '@'])
        .next()
        .unwrap_or(image)
        .to_ascii_lowercase();

    image_name.contains("gpu")
}

fn dockerfile_sources_supported_for_gateway(metadata: Option<&GatewayMetadata>) -> bool {
    !metadata.is_some_and(|metadata| metadata.is_remote)
}

/// Build a Dockerfile and return the local Docker tag.
///
/// Package-managed local gateways use the same Docker daemon that the CLI
/// builds into, so the tag is passed through directly and the active compute
/// driver resolves it.
async fn build_from_dockerfile(
    dockerfile: &Path,
    context: &Path,
    gateway_name: &str,
) -> Result<String> {
    let metadata = get_gateway_metadata(gateway_name);
    if !dockerfile_sources_supported_for_gateway(metadata.as_ref()) {
        return Err(miette!(
            "local Dockerfile sources are only supported for local gateways; gateway '{}' is remote",
            gateway_name
        ));
    }

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

    openshell_bootstrap::build::build_local_image(
        dockerfile,
        &tag,
        context,
        &HashMap::new(),
        &mut on_log,
    )
    .await?;

    eprintln!();
    eprintln!(
        "{} Image {} is available in the local Docker daemon for gateway '{}'.",
        "✓".green().bold(),
        tag.cyan(),
        gateway_name,
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
    openshell_policy::load_sandbox_policy(cli_path)
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
            let local = Path::new(local_path);
            if !local.exists() {
                return Err(miette::miette!(
                    "local path does not exist: {}",
                    local.display()
                ));
            }
            let dest_display = dest.unwrap_or("~");
            eprintln!("Syncing {} -> sandbox:{}", local.display(), dest_display);
            sandbox_sync_up(server, name, local, dest, tls).await?;
            eprintln!("{} Sync complete", "✓".green().bold());
        }
        (None, Some(sandbox_path)) => {
            let local_dest = dest.unwrap_or(".");
            eprintln!("Syncing sandbox:{sandbox_path} -> {local_dest}");
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
///
/// Policy always comes from [`GetSandboxConfig`] (effective active policy, sandbox
/// or global). With `policy_only`, prints only that YAML to stdout; otherwise
/// prints sandbox metadata and the same policy with formatted YAML.
pub async fn sandbox_get(
    server: &str,
    name: &str,
    policy_only: bool,
    tls: &TlsOptions,
) -> Result<()> {
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

    let sandbox_id = if sandbox.object_id().is_empty() {
        return Err(miette::miette!("sandbox missing metadata"));
    } else {
        sandbox.object_id().to_string()
    };

    let config = client
        .get_sandbox_config(GetSandboxConfigRequest { sandbox_id })
        .await
        .into_diagnostic()?
        .into_inner();

    if policy_only {
        let Some(ref policy) = config.policy else {
            return Err(miette::miette!(
                "no active policy configured for this sandbox"
            ));
        };
        let yaml_str = openshell_policy::serialize_sandbox_policy(policy)
            .wrap_err("failed to serialize policy to YAML")?;
        print!("{yaml_str}");
        return Ok(());
    }

    println!("{}", "Sandbox:".cyan().bold());
    println!();
    let id = if sandbox.object_id().is_empty() {
        "unknown"
    } else {
        sandbox.object_id()
    };
    let name = if sandbox.object_name().is_empty() {
        "unknown"
    } else {
        sandbox.object_name()
    };
    println!("  {} {}", "Id:".dimmed(), id);
    println!("  {} {}", "Name:".dimmed(), name);
    println!("  {} {}", "Phase:".dimmed(), phase_name(sandbox.phase()));
    println!(
        "  {} {}",
        "Resource version:".dimmed(),
        sandbox.metadata.as_ref().map_or(0, |m| m.resource_version)
    );

    // Display labels if present
    if let Some(metadata) = &sandbox.metadata
        && !metadata.labels.is_empty()
    {
        println!("  {} ", "Labels:".dimmed());
        let mut labels: Vec<_> = metadata.labels.iter().collect();
        labels.sort_by_key(|(k, _)| *k);
        for (key, value) in labels {
            println!("    {key}: {value}");
        }
    }

    let policy_from_global = config.policy_source == PolicySource::Global as i32;
    println!(
        "  {} {}",
        "Policy source:".dimmed(),
        if policy_from_global {
            "global"
        } else {
            "sandbox"
        }
    );
    let revision = if policy_from_global {
        if config.global_policy_version > 0 {
            Some(config.global_policy_version)
        } else if config.version > 0 {
            Some(config.version)
        } else {
            None
        }
    } else if config.version > 0 {
        Some(config.version)
    } else {
        None
    };
    if let Some(rev) = revision {
        println!("  {} {}", "Revision:".dimmed(), rev);
    }

    if let Some(ref policy) = config.policy {
        println!();
        print_sandbox_policy(policy);
    }

    Ok(())
}

/// Maximum stdin payload size (4 MiB). Prevents the CLI from reading unbounded
/// data into memory before the server rejects an oversized message.
const MAX_STDIN_PAYLOAD: usize = 4 * 1024 * 1024;

/// Execute a command in a running sandbox via gRPC, streaming output to the terminal.
///
/// Returns the remote command's exit code.
pub async fn sandbox_exec_grpc(
    server: &str,
    name: &str,
    command: &[String],
    workdir: Option<&str>,
    timeout_seconds: u32,
    tty_override: Option<bool>,
    tls: &TlsOptions,
) -> Result<i32> {
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

    // Verify the sandbox is ready before issuing the exec.
    if SandboxPhase::try_from(sandbox.phase()) != Ok(SandboxPhase::Ready) {
        return Err(miette::miette!(
            "sandbox '{}' is not ready (phase: {}); wait for it to reach Ready state",
            name,
            phase_name(sandbox.phase())
        ));
    }

    // Read stdin if piped (not a TTY), using spawn_blocking to avoid blocking
    // the async runtime. Cap the read at MAX_STDIN_PAYLOAD + 1 so we never
    // buffer more than the limit into memory.
    let stdin_payload = if std::io::stdin().is_terminal() {
        Vec::new()
    } else {
        tokio::task::spawn_blocking(|| {
            let limit = (MAX_STDIN_PAYLOAD + 1) as u64;
            let mut buf = Vec::new();
            std::io::stdin()
                .take(limit)
                .read_to_end(&mut buf)
                .into_diagnostic()?;
            if buf.len() > MAX_STDIN_PAYLOAD {
                return Err(miette::miette!(
                    "stdin payload exceeds {} byte limit; pipe smaller inputs or use `sandbox upload`",
                    MAX_STDIN_PAYLOAD
                ));
            }
            Ok(buf)
        })
        .await
        .into_diagnostic()?? // first ? unwraps JoinError, second ? unwraps Result
    };

    // Resolve TTY mode: explicit --tty / --no-tty wins, otherwise auto-detect.
    let tty = tty_override
        .unwrap_or_else(|| std::io::stdin().is_terminal() && std::io::stdout().is_terminal());

    if tty_override == Some(true) && std::io::stdin().is_terminal() {
        return sandbox_exec_interactive_grpc(client, &sandbox, command, workdir, timeout_seconds)
            .await;
    }

    // Make the streaming gRPC call.
    let mut stream = client
        .exec_sandbox(ExecSandboxRequest {
            sandbox_id: sandbox.object_id().to_string(),
            command: command.to_vec(),
            workdir: workdir.unwrap_or_default().to_string(),
            environment: HashMap::new(),
            timeout_seconds,
            stdin: stdin_payload,
            tty,
            ..Default::default()
        })
        .await
        .into_diagnostic()?
        .into_inner();

    // Stream output to terminal in real-time.
    let mut exit_code = 0i32;
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();

    while let Some(event) = stream.next().await {
        let event = event.into_diagnostic()?;
        match event.payload {
            Some(exec_sandbox_event::Payload::Stdout(out)) => {
                let mut handle = stdout.lock();
                handle.write_all(&out.data).into_diagnostic()?;
                handle.flush().into_diagnostic()?;
            }
            Some(exec_sandbox_event::Payload::Stderr(err)) => {
                let mut handle = stderr.lock();
                handle.write_all(&err.data).into_diagnostic()?;
                handle.flush().into_diagnostic()?;
            }
            Some(exec_sandbox_event::Payload::Exit(exit)) => {
                exit_code = exit.exit_code;
            }
            None => {}
        }
    }

    Ok(exit_code)
}

pub async fn service_forward_tcp(
    server: &str,
    name: &str,
    local: Option<&str>,
    target_host: &str,
    target_port: u16,
    tls: &TlsOptions,
) -> Result<()> {
    let (bind_addr, bind_port) = parse_tcp_forward_spec(local, target_port)?;
    let mut client = grpc_client(server, tls).await?;

    let sandbox = fetch_ready_sandbox_for_forward(&mut client, name).await?;

    let listener = tokio::net::TcpListener::bind((bind_addr.as_str(), bind_port))
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to bind local forward on {bind_addr}:{bind_port}"))?;
    let local_addr = listener
        .local_addr()
        .into_diagnostic()
        .wrap_err("failed to read local forward address")?;
    eprintln!(
        "{} Forwarding {} -> {}:{} in sandbox {} via gRPC",
        "✓".green().bold(),
        local_addr,
        target_host,
        target_port,
        name,
    );

    let sandbox_id = sandbox.object_id().to_string();
    let (fatal_tx, mut fatal_rx) = tokio::sync::mpsc::channel::<String>(1);
    let mut health_check = tokio::time::interval(Duration::from_secs(2));
    health_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            Some(reason) = fatal_rx.recv() => {
                return Err(miette::miette!("service forward stopped: {reason}"));
            }

            _ = health_check.tick() => {
                fetch_ready_sandbox_for_forward(&mut client, name).await?;
            }

            accepted = listener.accept() => {
                let (socket, peer) = accepted
                    .into_diagnostic()
                    .wrap_err("failed to accept local forward connection")?;
                let mut client = client.clone();
                let sandbox_id = sandbox_id.clone();
                let target_host = target_host.to_string();
                let service_id = format!("service-forward:{name}:{target_host}:{target_port}");
                let fatal_tx = fatal_tx.clone();
                tokio::spawn(async move {
                    let token = match create_forward_session_token(&mut client, &sandbox_id).await {
                        Ok(token) => token,
                        Err(err) => {
                            tracing::warn!(peer = %peer, error = %err, "service forward session creation failed");
                            if err.fatal {
                                let _ = fatal_tx.send(err.message).await;
                            }
                            return;
                        }
                    };
                    if let Err(err) = forward_one_tcp_connection(
                        &mut client,
                        socket,
                        sandbox_id,
                        target_host,
                        target_port,
                        service_id,
                        token.clone(),
                    )
                    .await
                    {
                        tracing::warn!(peer = %peer, error = %err, "service forward connection failed");
                        if err.fatal {
                            let _ = fatal_tx.send(err.message).await;
                        }
                    }
                    let _ = client
                        .revoke_ssh_session(RevokeSshSessionRequest { token })
                        .await;
                });
            }
        }
    }
}

async fn create_forward_session_token(
    client: &mut crate::tls::GrpcClient,
    sandbox_id: &str,
) -> std::result::Result<String, ForwardTcpConnectionError> {
    let response = client
        .create_ssh_session(CreateSshSessionRequest {
            sandbox_id: sandbox_id.to_string(),
        })
        .await
        .map_err(ForwardTcpConnectionError::from_status)?;
    Ok(response.into_inner().token)
}

async fn fetch_ready_sandbox_for_forward(
    client: &mut crate::tls::GrpcClient,
    name: &str,
) -> Result<Sandbox> {
    let response = match client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
        })
        .await
    {
        Ok(response) => response,
        Err(status) if status.code() == Code::NotFound => {
            return Err(miette::miette!(
                "sandbox '{name}' no longer exists; stopping service forward"
            ));
        }
        Err(status) => return Err(status).into_diagnostic(),
    };

    let sandbox = response
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox '{name}' not found"))?;

    if SandboxPhase::try_from(sandbox.phase()) != Ok(SandboxPhase::Ready) {
        return Err(miette::miette!(
            "sandbox '{}' is no longer ready (phase: {}); stopping service forward",
            name,
            phase_name(sandbox.phase())
        ));
    }

    Ok(sandbox)
}

#[derive(Debug)]
struct ForwardTcpConnectionError {
    message: String,
    fatal: bool,
}

impl ForwardTcpConnectionError {
    fn transient(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fatal: false,
        }
    }

    fn from_status(status: Status) -> Self {
        let fatal = matches!(status.code(), Code::NotFound | Code::FailedPrecondition);
        Self {
            message: status.to_string(),
            fatal,
        }
    }
}

impl std::fmt::Display for ForwardTcpConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ForwardTcpConnectionError {}

fn parse_tcp_forward_spec(local: Option<&str>, default_port: u16) -> Result<(String, u16)> {
    let Some(spec) = local else {
        return Ok(("127.0.0.1".to_string(), default_port));
    };

    if let Some(pos) = spec.rfind(':') {
        let addr = &spec[..pos];
        let port_str = &spec[pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            if addr.is_empty() {
                return Err(miette::miette!("bind address is required before ':'"));
            }
            return Ok((addr.to_string(), port));
        }
    }

    let port: u16 = spec.parse().map_err(|_| {
        miette::miette!("invalid local forward spec '{spec}': expected [bind_address:]port")
    })?;
    Ok(("127.0.0.1".to_string(), port))
}

async fn forward_one_tcp_connection(
    client: &mut crate::tls::GrpcClient,
    socket: tokio::net::TcpStream,
    sandbox_id: String,
    target_host: String,
    target_port: u16,
    service_id: String,
    authorization_token: String,
) -> std::result::Result<(), ForwardTcpConnectionError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_stream::wrappers::ReceiverStream;

    let (tx, rx) = tokio::sync::mpsc::channel::<TcpForwardFrame>(16);
    tx.send(TcpForwardFrame {
        payload: Some(openshell_core::proto::tcp_forward_frame::Payload::Init(
            TcpForwardInit {
                sandbox_id,
                service_id,
                target: Some(tcp_forward_init::Target::Tcp(TcpRelayTarget {
                    host: target_host,
                    port: u32::from(target_port),
                })),
                authorization_token,
            },
        )),
    })
    .await
    .map_err(|_| ForwardTcpConnectionError::transient("failed to initialize forward stream"))?;

    let mut response = match client.forward_tcp(ReceiverStream::new(rx)).await {
        Ok(response) => response.into_inner(),
        Err(status) => {
            let err = ForwardTcpConnectionError::from_status(status);
            drain_and_shutdown_local_socket(socket).await;
            return Err(err);
        }
    };

    let (mut local_read, mut local_write) = socket.into_split();

    let to_gateway = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = local_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if tx
                .send(TcpForwardFrame {
                    payload: Some(openshell_core::proto::tcp_forward_frame::Payload::Data(
                        buf[..n].to_vec(),
                    )),
                })
                .await
                .is_err()
            {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    });

    while let Some(frame) = response
        .message()
        .await
        .map_err(ForwardTcpConnectionError::from_status)?
    {
        let Some(openshell_core::proto::tcp_forward_frame::Payload::Data(data)) = frame.payload
        else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        local_write
            .write_all(&data)
            .await
            .map_err(|err| ForwardTcpConnectionError::transient(err.to_string()))?;
    }

    let _ = local_write.shutdown().await;
    to_gateway.abort();
    Ok(())
}

async fn drain_and_shutdown_local_socket(mut socket: tokio::net::TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = [0u8; 4096];
    while matches!(
        tokio::time::timeout(Duration::from_millis(25), socket.read(&mut buf)).await,
        Ok(Ok(n)) if n != 0
    ) {}
    let _ = socket.shutdown().await;
}

struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

struct TaskGuard(tokio::task::JoinHandle<()>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn sandbox_exec_interactive_grpc(
    mut client: crate::tls::GrpcClient,
    sandbox: &Sandbox,
    command: &[String],
    workdir: Option<&str>,
    timeout_seconds: u32,
) -> Result<i32> {
    use openshell_core::proto::{ExecSandboxInput, ExecSandboxWindowResize, exec_sandbox_input};
    use tokio_stream::wrappers::ReceiverStream;

    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

    let (input_tx, input_rx) = tokio::sync::mpsc::channel::<ExecSandboxInput>(4096);

    // Send the start message with exec metadata.
    input_tx
        .send(ExecSandboxInput {
            payload: Some(exec_sandbox_input::Payload::Start(ExecSandboxRequest {
                sandbox_id: sandbox.object_id().to_string(),
                command: command.to_vec(),
                workdir: workdir.unwrap_or_default().to_string(),
                environment: HashMap::new(),
                timeout_seconds,
                stdin: Vec::new(),
                tty: true,
                cols: u32::from(cols),
                rows: u32::from(rows),
            })),
        })
        .await
        .into_diagnostic()?;

    let mut stream = client
        .exec_sandbox_interactive(ReceiverStream::new(input_rx))
        .await
        .into_diagnostic()?
        .into_inner();

    // Enable raw mode so keystrokes are forwarded immediately.
    crossterm::terminal::enable_raw_mode().into_diagnostic()?;
    let raw_guard = RawModeGuard;

    // Stdin reader on a detached OS thread. Using std::thread (not
    // spawn_blocking) so the tokio runtime shutdown doesn't wait for a
    // thread blocked on stdin.read(). The thread exits when the channel
    // closes (blocking_send returns Err) or stdin hits EOF.
    #[cfg(unix)]
    {
        let stdin_tx = input_tx.clone();
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut buf = [0u8; 4096];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stdin_tx
                            .blocking_send(ExecSandboxInput {
                                payload: Some(exec_sandbox_input::Payload::Stdin(
                                    buf[..n].to_vec(),
                                )),
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });
    }

    // SIGWINCH handler: forward terminal resize events.
    #[cfg(unix)]
    let resize_task = {
        let resize_tx = input_tx.clone();
        tokio::spawn(async move {
            let mut sig =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                    .expect("failed to register SIGWINCH handler");
            while sig.recv().await.is_some() {
                if let Ok((c, r)) = crossterm::terminal::size() {
                    let msg = ExecSandboxInput {
                        payload: Some(exec_sandbox_input::Payload::Resize(
                            ExecSandboxWindowResize {
                                cols: u32::from(c),
                                rows: u32::from(r),
                            },
                        )),
                    };
                    if resize_tx.send(msg).await.is_err() {
                        break;
                    }
                }
            }
        })
    };
    #[cfg(unix)]
    let _resize_guard = TaskGuard(resize_task);

    let mut exit_code = 0i32;
    let stdout = std::io::stdout();

    while let Some(event) = stream.next().await {
        let event = event.into_diagnostic()?;
        match event.payload {
            Some(exec_sandbox_event::Payload::Stdout(out)) => {
                let mut handle = stdout.lock();
                handle.write_all(&out.data).into_diagnostic()?;
                handle.flush().into_diagnostic()?;
            }
            Some(exec_sandbox_event::Payload::Stderr(err)) => {
                let mut handle = stdout.lock();
                handle.write_all(&err.data).into_diagnostic()?;
                handle.flush().into_diagnostic()?;
            }
            Some(exec_sandbox_event::Payload::Exit(exit)) => {
                exit_code = exit.exit_code;
                break;
            }
            None => {}
        }
    }

    drop(input_tx);

    // Drop the raw mode guard to restore the terminal before returning.
    drop(raw_guard);

    Ok(exit_code)
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
    if let Ok(yaml_str) = openshell_policy::serialize_sandbox_policy(policy) {
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
#[allow(clippy::too_many_arguments)]
pub async fn sandbox_list(
    server: &str,
    limit: u32,
    offset: u32,
    ids_only: bool,
    names_only: bool,
    label_selector: Option<&str>,
    output: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .list_sandboxes(ListSandboxesRequest {
            limit,
            offset,
            label_selector: label_selector.unwrap_or("").to_string(),
        })
        .await
        .into_diagnostic()?;

    let sandboxes = response.into_inner().sandboxes;

    match output {
        "json" => {
            let items: Vec<serde_json::Value> = sandboxes.iter().map(sandbox_to_json).collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&items).into_diagnostic()?
            );
            return Ok(());
        }
        "yaml" => {
            let items: Vec<serde_json::Value> = sandboxes.iter().map(sandbox_to_json).collect();
            print!("{}", serde_yml::to_string(&items).into_diagnostic()?);
            return Ok(());
        }
        "table" => {}
        _ => return Err(miette!("unsupported output format: {output}")),
    }

    if sandboxes.is_empty() {
        if !ids_only && !names_only {
            println!("No sandboxes found.");
        }
        return Ok(());
    }

    if ids_only {
        for sandbox in sandboxes {
            println!("{}", sandbox.object_id());
        }
        return Ok(());
    }

    if names_only {
        for sandbox in sandboxes {
            println!("{}", sandbox.object_name());
        }
        return Ok(());
    }

    // Calculate column widths
    let name_width = sandboxes
        .iter()
        .map(|s| s.object_name().len())
        .max()
        .unwrap_or(4)
        .max(4);
    let created_width = 19; // "YYYY-MM-DD HH:MM:SS"

    // Print header
    println!(
        "{:<name_width$}  {:<created_width$}  {}",
        "NAME".bold(),
        "CREATED".bold(),
        "PHASE".bold(),
    );

    // Print rows
    for sandbox in sandboxes {
        let phase = phase_name(sandbox.phase());
        let phase_colored = match SandboxPhase::try_from(sandbox.phase()) {
            Ok(SandboxPhase::Ready) => phase.green().to_string(),
            Ok(SandboxPhase::Error) => phase.red().to_string(),
            Ok(SandboxPhase::Provisioning) => phase.yellow().to_string(),
            Ok(SandboxPhase::Deleting) => phase.dimmed().to_string(),
            _ => phase.to_string(),
        };
        let created = format_epoch_ms(sandbox.metadata.as_ref().map_or(0, |m| m.created_at_ms));
        println!(
            "{:<name_width$}  {:<created_width$}  {}",
            sandbox.object_name().to_string(),
            created,
            phase_colored,
        );
    }

    Ok(())
}

fn sandbox_to_json(sandbox: &Sandbox) -> serde_json::Value {
    let meta = sandbox.metadata.as_ref();
    let labels = meta.map_or_else(|| serde_json::json!({}), |m| serde_json::json!(m.labels));
    serde_json::json!({
        "id": sandbox.object_id(),
        "name": sandbox.object_name(),
        "labels": labels,
        "resource_version": meta.map_or(0, |m| m.resource_version),
        "created_at": format_epoch_ms(meta.map_or(0, |m| m.created_at_ms)),
        "phase": phase_name(sandbox.phase()),
        "current_policy_version": sandbox.current_policy_version(),
    })
}

pub async fn sandbox_provider_list(server: &str, name: &str, tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .list_sandbox_providers(ListSandboxProvidersRequest {
            sandbox_name: name.to_string(),
        })
        .await
        .into_diagnostic()?;
    let providers = response.into_inner().providers;

    if providers.is_empty() {
        println!("No providers attached to sandbox {name}.");
        return Ok(());
    }

    print_provider_attachment_table(&providers);
    Ok(())
}

pub async fn sandbox_provider_attach(
    server: &str,
    name: &str,
    provider: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    // Fetch current sandbox to get resource_version for CAS
    let sandbox = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox not found"))?;

    let resource_version = sandbox.metadata.as_ref().map_or(0, |m| m.resource_version);

    let response = match client
        .attach_sandbox_provider(AttachSandboxProviderRequest {
            sandbox_name: name.to_string(),
            provider_name: provider.to_string(),
            expected_resource_version: resource_version,
        })
        .await
    {
        Ok(response) => response.into_inner(),
        Err(status) if status.code() == Code::Aborted => {
            return Err(miette::miette!(
                "Failed to attach provider: sandbox was modified by another operation.\n\
                 Please retry the command."
            )
            .with_source_code(status.message().to_string()));
        }
        Err(e) => return Err(e).into_diagnostic(),
    };

    if response.attached {
        println!(
            "{} Attached provider {} to sandbox {}",
            "✓".green().bold(),
            provider,
            name
        );
    } else {
        println!("Provider {provider} is already attached to sandbox {name}.");
    }
    Ok(())
}

pub async fn sandbox_provider_detach(
    server: &str,
    name: &str,
    provider: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    // Fetch current sandbox to get resource_version for CAS
    let sandbox = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox not found"))?;

    let resource_version = sandbox.metadata.as_ref().map_or(0, |m| m.resource_version);

    let response = match client
        .detach_sandbox_provider(DetachSandboxProviderRequest {
            sandbox_name: name.to_string(),
            provider_name: provider.to_string(),
            expected_resource_version: resource_version,
        })
        .await
    {
        Ok(response) => response.into_inner(),
        Err(status) if status.code() == Code::Aborted => {
            return Err(miette::miette!(
                "Failed to detach provider: sandbox was modified by another operation.\n\
                 Please retry the command."
            )
            .with_source_code(status.message().to_string()));
        }
        Err(e) => return Err(e).into_diagnostic(),
    };

    if response.detached {
        println!(
            "{} Detached provider {} from sandbox {}",
            "✓".green().bold(),
            provider,
            name
        );
    } else {
        println!("Provider {provider} was not attached to sandbox {name}.");
    }
    Ok(())
}

fn print_provider_attachment_table(providers: &[Provider]) {
    print!("{}", format_provider_attachment_table(providers, true));
}

fn format_provider_attachment_table(providers: &[Provider], color: bool) -> String {
    use std::fmt::Write as _;

    let name_width = providers
        .iter()
        .map(|provider| provider.object_name().len())
        .max()
        .unwrap_or(4)
        .max(4);
    let type_width = providers
        .iter()
        .map(|provider| provider.r#type.len())
        .max()
        .unwrap_or(4)
        .max(4);

    let name_header = if color {
        "NAME".bold().to_string()
    } else {
        "NAME".to_string()
    };
    let type_header = if color {
        "TYPE".bold().to_string()
    } else {
        "TYPE".to_string()
    };
    let credential_keys_header = if color {
        "CREDENTIAL_KEYS".bold().to_string()
    } else {
        "CREDENTIAL_KEYS".to_string()
    };
    let config_keys_header = if color {
        "CONFIG_KEYS".bold().to_string()
    } else {
        "CONFIG_KEYS".to_string()
    };

    let mut output = String::new();
    let _ = writeln!(
        output,
        "{name_header:<name_width$}  {type_header:<type_width$}  {credential_keys_header:<16}  {config_keys_header}",
    );

    for provider in providers {
        let provider_name = provider.object_name();
        let provider_type = &provider.r#type;
        let credential_keys = provider.credentials.len();
        let config_keys = provider.config.len();
        let _ = writeln!(
            output,
            "{provider_name:<name_width$}  {provider_type:<type_width$}  {credential_keys:<16}  {config_keys}",
        );
    }
    output
}

/// Delete a sandbox by name, or all sandboxes when `all` is true.
pub async fn sandbox_delete(
    server: &str,
    names: &[String],
    all: bool,
    tls: &TlsOptions,
    gateway: &str,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let names_to_delete: Vec<String> = if all {
        // Fetch all sandboxes (use a large page size).
        let response = client
            .list_sandboxes(ListSandboxesRequest {
                limit: 1000,
                offset: 0,
                label_selector: String::new(),
            })
            .await
            .into_diagnostic()?;
        let sandboxes = response.into_inner().sandboxes;
        if sandboxes.is_empty() {
            println!("No sandboxes to delete.");
            return Ok(());
        }
        sandboxes
            .into_iter()
            .map(|s| s.object_name().to_string())
            .collect()
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
            clear_last_sandbox_if_matches(gateway, name);
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
/// (e.g. `claude` -> type `"claude-code"`). These are resolved to provider names via
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
                known_names.insert(provider.object_name().to_string());
                if !provider.r#type.is_empty() {
                    let type_lower = provider.r#type.to_ascii_lowercase();
                    type_to_name
                        .entry(type_lower)
                        .or_insert_with(|| provider.object_name().to_string());
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

    let discovered = discover_existing_provider_data(client, provider_type)
        .await
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
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: exact_name.to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: provider_type.to_string(),
                credentials: discovered.credentials.clone(),
                config: discovered.config.clone(),
                credential_expires_at_ms: HashMap::new(),
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
            provider.object_name(),
            provider.r#type
        );
        if seen_names.insert(provider.object_name().to_string()) {
            configured_names.push(provider.object_name().to_string());
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
                    metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                        id: String::new(),
                        name: name.clone(),
                        created_at_ms: 0,
                        labels: HashMap::new(),
                        resource_version: 0,
                    }),
                    r#type: provider_type.to_string(),
                    credentials: discovered.credentials.clone(),
                    config: discovered.config.clone(),
                    credential_expires_at_ms: HashMap::new(),
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
                        provider.object_name(),
                        provider.r#type
                    );
                    if seen_names.insert(provider.object_name().to_string()) {
                        configured_names.push(provider.object_name().to_string());
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

pub fn parse_credential_expiry_cli_value(value: &str) -> std::result::Result<i64, String> {
    parse_credential_expiry_value(value, None).map_err(|err| err.to_string())
}

fn credential_expiry_value_error(key: Option<&str>, detail: &str) -> miette::Report {
    key.map_or_else(
        || miette::miette!("--credential-expires-at value {detail}"),
        |key| miette::miette!("--credential-expires-at value for '{key}' {detail}"),
    )
}

fn parse_credential_expiry_value(value: &str, key: Option<&str>) -> Result<i64> {
    let value = value.trim();
    if value.is_empty() {
        return Err(credential_expiry_value_error(key, "cannot be empty"));
    }

    if let Ok(value_ms) = value.parse::<i64>() {
        if value_ms < 0 {
            return Err(credential_expiry_value_error(
                key,
                "must be greater than or equal to 0",
            ));
        }
        return Ok(value_ms);
    }

    let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| {
        credential_expiry_value_error(
            key,
            "must be a Unix epoch millisecond timestamp or RFC3339 timestamp",
        )
    })?;
    let value_ms = parsed.timestamp_millis();
    if value_ms < 0 {
        return Err(credential_expiry_value_error(
            key,
            "must be greater than or equal to 0",
        ));
    }

    Ok(value_ms)
}

fn parse_credential_expiry_pairs(items: &[String]) -> Result<HashMap<String, i64>> {
    let mut map = HashMap::new();

    for item in items {
        let Some((key, value)) = item.split_once('=') else {
            return Err(miette::miette!(
                "--credential-expires-at expects KEY=TIMESTAMP, got '{item}'"
            ));
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(miette::miette!(
                "--credential-expires-at key cannot be empty"
            ));
        }
        let value = parse_credential_expiry_value(value, Some(key))?;
        map.insert(key.to_string(), value);
    }

    Ok(map)
}

pub async fn service_expose(
    server: &str,
    sandbox: &str,
    service: &str,
    target_port: u16,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .expose_service(ExposeServiceRequest {
            sandbox: sandbox.to_string(),
            service: service.to_string(),
            target_port: u32::from(target_port),
            domain: true,
        })
        .await
        .map_err(service_expose_status_error)?
        .into_inner();

    if service.is_empty() {
        println!(
            "{} Exposed sandbox {} -> 127.0.0.1:{}",
            "✓".green().bold(),
            sandbox.bold(),
            target_port,
        );
    } else {
        println!(
            "{} Exposed service {} on sandbox {} -> 127.0.0.1:{}",
            "✓".green().bold(),
            service.bold(),
            sandbox.bold(),
            target_port,
        );
    }
    if !response.url.is_empty() {
        let url = service_url_for_gateway(&response.url, server);
        println!("  URL: {}", url.cyan());
    }
    Ok(())
}

fn service_expose_status_error(status: Status) -> miette::Report {
    service_status_error("expose service", "sandbox:write", status)
}

pub async fn service_list(
    server: &str,
    sandbox: Option<&str>,
    limit: u32,
    offset: u32,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .list_services(ListServicesRequest {
            sandbox: sandbox.unwrap_or_default().to_string(),
            limit,
            offset,
        })
        .await
        .map_err(|status| service_status_error("list services", "sandbox:read", status))?
        .into_inner();

    if response.services.is_empty() {
        if let Some(sandbox) = sandbox {
            println!("No services exposed for sandbox {sandbox}.");
        } else {
            println!("No services exposed.");
        }
        return Ok(());
    }

    print_service_endpoint_table(&response.services, server);
    Ok(())
}

pub async fn service_get(
    server: &str,
    sandbox: &str,
    service: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_service(GetServiceRequest {
            sandbox: sandbox.to_string(),
            service: service.to_string(),
        })
        .await
        .map_err(|status| service_status_error("get service", "sandbox:read", status))?
        .into_inner();

    print_service_endpoint_table(&[response], server);
    Ok(())
}

pub async fn service_delete(
    server: &str,
    sandbox: &str,
    service: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .delete_service(DeleteServiceRequest {
            sandbox: sandbox.to_string(),
            service: service.to_string(),
        })
        .await
        .map_err(|status| service_status_error("delete service", "sandbox:write", status))?
        .into_inner();

    if !response.deleted {
        return Err(miette!("delete service failed: service endpoint not found"));
    }

    if service.is_empty() {
        println!(
            "{} Deleted exposed sandbox {}",
            "✓".green().bold(),
            sandbox.bold(),
        );
    } else {
        println!(
            "{} Deleted service {} on sandbox {}",
            "✓".green().bold(),
            service.bold(),
            sandbox.bold(),
        );
    }
    Ok(())
}

fn service_status_error(action: &str, required_scope: &str, status: Status) -> miette::Report {
    let message = status.message();
    match status.code() {
        Code::PermissionDenied => {
            miette!("{action} failed: permission denied (requires {required_scope})")
        }
        Code::Unauthenticated => miette!("{action} failed: authentication required"),
        Code::NotFound if message == "sandbox not found" => {
            miette!("{action} failed: sandbox not found")
        }
        Code::NotFound if message == "service endpoint not found" => {
            miette!("{action} failed: service endpoint not found")
        }
        Code::InvalidArgument if !message.is_empty() => {
            miette!("{action} failed: invalid request: {message}")
        }
        _ => miette!("{action} failed: {status}"),
    }
}

fn print_service_endpoint_table(services: &[ServiceEndpointResponse], gateway_endpoint: &str) {
    let rows = services
        .iter()
        .filter_map(|response| {
            let endpoint = response.endpoint.as_ref()?;
            let service = service_display_name(&endpoint.service_name).to_string();
            let target = format!("127.0.0.1:{}", endpoint.target_port);
            let url = if response.url.is_empty() {
                String::new()
            } else {
                service_url_for_gateway(&response.url, gateway_endpoint)
            };
            Some((endpoint.sandbox_name.clone(), service, target, url))
        })
        .collect::<Vec<_>>();

    if rows.is_empty() {
        return;
    }

    let sandbox_width = rows
        .iter()
        .map(|(sandbox, _, _, _)| sandbox.len())
        .max()
        .unwrap_or(7)
        .max(7);
    let service_width = rows
        .iter()
        .map(|(_, service, _, _)| service.len())
        .max()
        .unwrap_or(7)
        .max(7);
    let target_width = rows
        .iter()
        .map(|(_, _, target, _)| target.len())
        .max()
        .unwrap_or(6)
        .max(6);

    println!(
        "{:<sandbox_width$}  {:<service_width$}  {:<target_width$}  {}",
        "SANDBOX".bold(),
        "SERVICE".bold(),
        "TARGET".bold(),
        "URL".bold(),
    );

    for (sandbox, service, target, url) in rows {
        println!(
            "{sandbox:<sandbox_width$}  {service:<service_width$}  {target:<target_width$}  {url}"
        );
    }
}

fn service_display_name(service: &str) -> &str {
    if service.is_empty() { "-" } else { service }
}

/// Read gcloud Application Default Credentials from disk.
///
/// Returns `(client_id, client_secret, refresh_token)`.
///
/// Checks `GOOGLE_APPLICATION_CREDENTIALS` first; falls back to
/// `$CLOUDSDK_CONFIG/application_default_credentials.json` when set, then to
/// `~/.config/gcloud/application_default_credentials.json`.
fn read_gcloud_adc() -> Result<(String, String, String)> {
    let path = if let Some(env_path) = std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
        .ok()
        .filter(|v| !v.is_empty())
    {
        PathBuf::from(env_path)
    } else if let Some(config_dir) = std::env::var("CLOUDSDK_CONFIG")
        .ok()
        .filter(|v| !v.is_empty())
    {
        PathBuf::from(config_dir).join("application_default_credentials.json")
    } else {
        let home = std::env::var("HOME")
            .map_err(|_| miette::miette!("HOME is not set; cannot locate gcloud ADC file"))?;
        PathBuf::from(home)
            .join(".config")
            .join("gcloud")
            .join("application_default_credentials.json")
    };

    let content = std::fs::read_to_string(&path).map_err(|err| {
        miette::miette!(
            "failed to read gcloud ADC file at {}: {}. \
             Run: gcloud auth application-default login",
            path.display(),
            err
        )
    })?;

    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|err| miette::miette!("failed to parse gcloud ADC file: {err}"))?;

    let cred_type = json.get("type").and_then(|v| v.as_str());
    match cred_type {
        Some("service_account") => {
            return Err(miette::miette!(
                "Application Default Credentials are a service account key, not user credentials. \
                 To use a service account, create the provider with the service account JSON key \
                 and configure gateway-managed refresh for 'GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN'. \
                 See: openshell provider create --help"
            ));
        }
        Some("authorized_user") => {}
        Some(other) => {
            return Err(miette::miette!(
                "Application Default Credentials have unsupported type '{other}' \
                 (expected 'authorized_user'). \
                 Run: gcloud auth application-default login"
            ));
        }
        None => {
            return Err(miette::miette!(
                "gcloud ADC file is missing the 'type' field. \
                 The file may be malformed. \
                 Run: gcloud auth application-default login"
            ));
        }
    }

    let client_id = json
        .get("client_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| miette::miette!("gcloud ADC file is missing 'client_id'"))?
        .to_string();

    let client_secret = json
        .get("client_secret")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| miette::miette!("gcloud ADC file is missing 'client_secret'"))?
        .to_string();

    let refresh_token = json
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| miette::miette!("gcloud ADC file is missing 'refresh_token'"))?
        .to_string();

    Ok((client_id, client_secret, refresh_token))
}

async fn rollback_provider_create_after_vertex_adc_failure(
    client: &mut crate::tls::GrpcClient,
    provider_name: &str,
    stage: &str,
    source: &Status,
) -> Result<()> {
    match client
        .delete_provider(DeleteProviderRequest {
            name: provider_name.to_string(),
        })
        .await
    {
        Ok(_) => Err(miette!(
            "failed to {stage} Vertex AI credentials from gcloud ADC for provider '{provider_name}': {source}. \
             The provider was rolled back successfully."
        )),
        Err(cleanup_err) => {
            eprintln!(
                "{} Failed to clean up provider '{}' after {} failed: {}. \
                 Run 'openshell provider delete {}' to remove it manually.",
                "⚠".yellow(),
                provider_name,
                stage,
                cleanup_err,
                provider_name
            );
            Err(miette!(
                "failed to {stage} Vertex AI credentials from gcloud ADC for provider '{provider_name}': {source}. \
                 Cleanup also failed, so the provider may still exist. \
                 Run 'openshell provider delete {provider_name}' to remove it manually."
            ))
        }
    }
}

fn service_url_for_gateway(service_url: &str, gateway_endpoint: &str) -> String {
    let (Ok(mut service_url), Ok(gateway_endpoint)) = (
        url::Url::parse(service_url),
        url::Url::parse(gateway_endpoint),
    ) else {
        return service_url.to_string();
    };

    if service_url
        .set_port(gateway_endpoint.port_or_known_default())
        .is_err()
    {
        return service_url.to_string();
    }

    service_url.to_string()
}

async fn gateway_providers_v2_enabled(client: &mut crate::tls::GrpcClient) -> Result<bool> {
    let response = client
        .get_gateway_config(GetGatewayConfigRequest {})
        .await
        .into_diagnostic()?
        .into_inner();
    let Some(setting) = response.settings.get(settings::PROVIDERS_V2_ENABLED_KEY) else {
        return Ok(false);
    };
    match setting.value.as_ref() {
        Some(setting_value::Value::BoolValue(enabled)) => Ok(*enabled),
        None => Ok(false),
        Some(_) => Err(miette::miette!(
            "gateway setting '{}' has invalid value type; expected bool",
            settings::PROVIDERS_V2_ENABLED_KEY
        )),
    }
}

async fn fetch_provider_profile(
    client: &mut crate::tls::GrpcClient,
    provider_type: &str,
) -> Result<ProviderProfile> {
    let response = client
        .get_provider_profile(GetProviderProfileRequest {
            id: provider_type.to_string(),
        })
        .await
        .map_err(|status| {
            if status.code() == Code::NotFound {
                miette::miette!(
                    "provider profile '{provider_type}' not found; providers v2 discovery requires a provider profile"
                )
            } else {
                miette::miette!(status.to_string())
            }
        })?;

    response
        .into_inner()
        .profile
        .ok_or_else(|| miette::miette!("provider profile '{provider_type}' missing from response"))
}

async fn discover_existing_provider_data(
    client: &mut crate::tls::GrpcClient,
    provider_type: &str,
) -> Result<Option<openshell_providers::DiscoveredProvider>> {
    if gateway_providers_v2_enabled(client).await? {
        let profile = fetch_provider_profile(client, provider_type).await?;
        let profile = ProviderTypeProfile::from_proto(&profile);
        let mut discovered =
            discover_from_profile(&profile, &RealDiscoveryContext).map_err(|err| {
                miette::miette!("failed to discover existing provider data from profile: {err}")
            })?;

        // Vertex AI config keys (project ID, region, base URL, publisher) are not
        // declared in the profile's discovery.credentials list, so discover_from_profile
        // does not scan them. Scan them directly here so --from-existing captures them.
        if provider_type == VERTEX_AI_PROVIDER_TYPE {
            let discovered = discovered.get_or_insert_with(Default::default);
            for key in openshell_core::inference::VERTEX_AI_CONFIG_KEY_NAMES {
                if let Ok(val) = std::env::var(key) {
                    let val = val.trim().to_string();
                    if !val.is_empty() {
                        discovered.config.entry(key.to_string()).or_insert(val);
                    }
                }
            }
        }

        Ok(discovered)
    } else {
        let registry = ProviderRegistry::new();
        registry
            .discover_existing(provider_type)
            .map_err(|err| miette::miette!("failed to discover existing provider data: {err}"))
    }
}

/// Canonical provider type string for Google Vertex AI.
const VERTEX_AI_PROVIDER_TYPE: &str = "google-vertex-ai";

fn missing_credentials_error(provider_type: &str) -> miette::Report {
    if provider_type == VERTEX_AI_PROVIDER_TYPE {
        return miette::miette!(
            "no credentials resolved for provider type '{provider_type}'. \
             Set GOOGLE_VERTEX_AI_TOKEN, VERTEX_AI_TOKEN, \
             GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN, or VERTEX_AI_SERVICE_ACCOUNT_TOKEN; \
             or use --from-gcloud-adc / --from-existing with those env vars set."
        );
    }

    miette::miette!(
        "no credentials resolved for provider type '{provider_type}'. \
         Use --credential KEY[=VALUE] or --from-existing with the appropriate env vars set."
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn provider_create(
    server: &str,
    name: &str,
    provider_type: &str,
    from_existing: bool,
    credentials: &[String],
    from_gcloud_adc: bool,
    config: &[String],
    tls: &TlsOptions,
) -> Result<()> {
    if from_gcloud_adc && (from_existing || !credentials.is_empty()) {
        return Err(miette::miette!(
            "--from-gcloud-adc cannot be combined with --from-existing or --credential"
        ));
    }
    if from_existing && !credentials.is_empty() {
        return Err(miette::miette!(
            "--from-existing cannot be combined with --credential"
        ));
    }

    let mut client = grpc_client(server, tls).await?;

    let provider_type = if let Some(provider_type) = normalize_provider_type(provider_type) {
        provider_type.to_string()
    } else {
        let profile_id = provider_type.trim();
        if profile_id.is_empty() {
            return Err(miette::miette!("provider type is required"));
        }
        let response = client
            .get_provider_profile(GetProviderProfileRequest {
                id: profile_id.to_string(),
            })
            .await;
        match response {
            Ok(response) => response
                .into_inner()
                .profile
                .map(|profile| profile.id)
                .filter(|id| !id.trim().is_empty())
                .unwrap_or_else(|| profile_id.to_string()),
            Err(status) if status.code() == Code::NotFound => {
                return Err(miette::miette!(
                    "unsupported provider type or profile: {provider_type}"
                ));
            }
            Err(status) => return Err(status).into_diagnostic(),
        }
    };

    if from_gcloud_adc && provider_type != VERTEX_AI_PROVIDER_TYPE {
        return Err(miette::miette!(
            "--from-gcloud-adc is only valid for google-vertex-ai providers"
        ));
    }

    let mut credential_map = parse_credential_pairs(credentials)?;
    let mut config_map = parse_key_value_pairs(config, "--config")?;

    if from_existing {
        let discovered = discover_existing_provider_data(&mut client, &provider_type).await?;
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
        if from_existing {
            return Err(missing_credentials_error(&provider_type));
        }
        let allows_refresh_bootstrap = fetch_provider_profile(&mut client, &provider_type)
            .await
            .ok()
            .is_some_and(|profile| provider_profile_allows_refresh_bootstrap(&profile));
        if !allows_refresh_bootstrap {
            return Err(missing_credentials_error(&provider_type));
        }
    }

    // Validate and read the ADC file BEFORE creating the provider so that
    // a bad/missing ADC does not leave an orphan provider behind.
    let gcloud_adc_material = if from_gcloud_adc {
        let (client_id, client_secret, refresh_token) = read_gcloud_adc()?;
        Some((client_id, client_secret, refresh_token))
    } else {
        None
    };

    let response = client
        .create_provider(CreateProviderRequest {
            provider: Some(Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: name.to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: provider_type.clone(),
                credentials: credential_map,
                config: config_map,
                credential_expires_at_ms: HashMap::new(),
            }),
        })
        .await
        .into_diagnostic()?;

    let provider = response
        .into_inner()
        .provider
        .ok_or_else(|| miette::miette!("provider missing from response"))?;
    let provider_name = provider.object_name().to_string();

    if let Some((client_id, client_secret, refresh_token)) = gcloud_adc_material {
        let mut material = HashMap::new();
        material.insert("client_id".to_string(), client_id);
        material.insert("client_secret".to_string(), client_secret);
        material.insert("refresh_token".to_string(), refresh_token);

        if let Err(configure_err) = client
            .configure_provider_refresh(ConfigureProviderRefreshRequest {
                provider: provider_name.clone(),
                credential_key: openshell_core::inference::VERTEX_AI_ADC_TOKEN_KEY.to_string(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32,
                material,
                secret_material_keys: vec![
                    "client_secret".to_string(),
                    "refresh_token".to_string(),
                ],
                expires_at_ms: None,
            })
            .await
        {
            return rollback_provider_create_after_vertex_adc_failure(
                &mut client,
                &provider_name,
                "configure",
                &configure_err,
            )
            .await;
        }

        if let Err(rotate_err) = client
            .rotate_provider_credential(RotateProviderCredentialRequest {
                provider: provider_name.clone(),
                credential_key: openshell_core::inference::VERTEX_AI_ADC_TOKEN_KEY.to_string(),
            })
            .await
        {
            return rollback_provider_create_after_vertex_adc_failure(
                &mut client,
                &provider_name,
                "mint the initial access token for",
                &rotate_err,
            )
            .await;
        }

        println!("{} Created provider {}", "✓".green().bold(), provider_name);
        println!(
            "Configured Vertex AI credentials from gcloud ADC and minted the initial access token"
        );
        return Ok(());
    }

    println!("{} Created provider {}", "✓".green().bold(), provider_name);
    Ok(())
}

fn provider_profile_allows_refresh_bootstrap(profile: &ProviderProfile) -> bool {
    ProviderTypeProfile::from_proto(profile).allows_gateway_refresh_bootstrap()
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
    println!("  {} {}", "Id:".dimmed(), provider.object_id());
    println!("  {} {}", "Name:".dimmed(), provider.object_name());
    println!("  {} {}", "Type:".dimmed(), provider.r#type);
    println!(
        "  {} {}",
        "Resource version:".dimmed(),
        provider.metadata.as_ref().map_or(0, |m| m.resource_version)
    );
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
            println!("{}", provider.object_name());
        }
        return Ok(());
    }

    let name_width = providers
        .iter()
        .map(|provider| provider.object_name().len())
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
            provider.object_name().to_string(),
            provider.r#type,
            provider.credentials.len(),
            provider.config.len(),
        );
    }

    Ok(())
}

pub async fn provider_list_profiles(server: &str, output: &str, tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .list_provider_profiles(ListProviderProfilesRequest {
            limit: 100,
            offset: 0,
        })
        .await
        .into_diagnostic()?;
    let mut profiles = response.into_inner().profiles;
    profiles.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then_with(|| left.id.cmp(&right.id))
    });
    let dto_profiles = profiles
        .iter()
        .map(ProviderTypeProfile::from_proto)
        .collect::<Vec<_>>();

    match output {
        "yaml" => {
            print!("{}", profiles_to_yaml(&dto_profiles).into_diagnostic()?);
            return Ok(());
        }
        "json" => {
            println!("{}", profiles_to_json(&dto_profiles).into_diagnostic()?);
            return Ok(());
        }
        "table" => {}
        _ => return Err(miette!("unsupported output format: {output}")),
    }

    if profiles.is_empty() {
        println!("No provider profiles found.");
        return Ok(());
    }

    println!("{}", "Available Provider Profiles:".cyan().bold());
    let id_width = provider_profile_id_width(&profiles);
    let display_width = provider_profile_display_width(&profiles);
    let mut current_category = i32::MIN;
    for profile in profiles {
        if profile.category != current_category {
            current_category = profile.category;
            println!();
            println!("  {}", display_provider_category(current_category).bold());
        }
        print_provider_type_row(&profile, id_width, display_width);
    }

    Ok(())
}

pub async fn provider_profile_export(
    server: &str,
    id: &str,
    output: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_provider_profile(GetProviderProfileRequest { id: id.to_string() })
        .await
        .into_diagnostic()?;
    let profile = response
        .into_inner()
        .profile
        .ok_or_else(|| miette!("provider profile '{id}' not found"))?;
    let profile = ProviderTypeProfile::from_proto(&profile);

    match output {
        "yaml" => print!("{}", profile_to_yaml(&profile).into_diagnostic()?),
        "json" => println!("{}", profile_to_json(&profile).into_diagnostic()?),
        "table" => {
            return Err(miette!(
                "profile export supports '-o yaml' and '-o json'; table output is not supported"
            ));
        }
        _ => return Err(miette!("unsupported output format: {output}")),
    }
    Ok(())
}

pub async fn provider_profile_import(
    server: &str,
    file: Option<&Path>,
    from: Option<&Path>,
    tls: &TlsOptions,
) -> Result<()> {
    let (items, mut diagnostics) = load_profile_import_items(file, from)?;
    if items.is_empty() && diagnostics.is_empty() {
        return Err(miette!("no provider profile files found"));
    }
    if profile_diagnostics_have_errors(&diagnostics) {
        print_profile_diagnostics(&diagnostics);
        return Err(miette!("provider profile import failed"));
    }

    let mut client = grpc_client(server, tls).await?;
    if !items.is_empty() {
        let response = client
            .import_provider_profiles(ImportProviderProfilesRequest { profiles: items })
            .await
            .into_diagnostic()?
            .into_inner();
        diagnostics.extend(response.diagnostics);
        if response.imported {
            println!(
                "Imported {} provider profile{}.",
                response.profiles.len(),
                if response.profiles.len() == 1 {
                    ""
                } else {
                    "s"
                }
            );
            return Ok(());
        }
    }

    print_profile_diagnostics(&diagnostics);
    Err(miette!("provider profile import failed"))
}

pub async fn provider_profile_lint(
    server: &str,
    file: Option<&Path>,
    from: Option<&Path>,
    tls: &TlsOptions,
) -> Result<()> {
    let (items, mut diagnostics) = load_profile_import_items(file, from)?;
    if items.is_empty() && diagnostics.is_empty() {
        return Err(miette!("no provider profile files found"));
    }

    if !items.is_empty() {
        let mut client = grpc_client(server, tls).await?;
        let response = client
            .lint_provider_profiles(LintProviderProfilesRequest { profiles: items })
            .await
            .into_diagnostic()?
            .into_inner();
        diagnostics.extend(response.diagnostics);
    }

    if profile_diagnostics_have_errors(&diagnostics) {
        print_profile_diagnostics(&diagnostics);
        return Err(miette!("provider profile lint failed"));
    }

    println!("Provider profile lint passed.");
    Ok(())
}

pub async fn provider_profile_delete(server: &str, id: &str, tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .delete_provider_profile(DeleteProviderProfileRequest { id: id.to_string() })
        .await
        .into_diagnostic()?
        .into_inner();
    if response.deleted {
        println!("Deleted provider profile '{id}'.");
    } else {
        println!("Provider profile '{id}' was not deleted.");
    }
    Ok(())
}

pub async fn provider_refresh_status(
    server: &str,
    name: &str,
    credential_key: Option<&str>,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_provider_refresh_status(GetProviderRefreshStatusRequest {
            provider: name.to_string(),
            credential_key: credential_key.unwrap_or_default().to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner();

    if response.credentials.is_empty() {
        if let Some(credential_key) = credential_key {
            println!(
                "No refresh configuration found for provider '{name}' credential '{credential_key}'."
            );
        } else {
            println!("No refresh configurations found for provider '{name}'.");
        }
        return Ok(());
    }

    println!("{}", refresh_status_header());
    for status in response.credentials {
        print_refresh_status_row(&status);
    }
    Ok(())
}

fn refresh_status_header() -> String {
    format!(
        "{:<24}  {:<28}  {:<28}  {:<18}  {:<20}  {:<20}  {:<20}  {}",
        "PROVIDER".bold(),
        "CREDENTIAL_KEY".bold(),
        "STRATEGY".bold(),
        "STATUS".bold(),
        "EXPIRES_AT".bold(),
        "NEXT_REFRESH".bold(),
        "LAST_REFRESH".bold(),
        "LAST_ERROR".bold(),
    )
}

pub struct ProviderRefreshConfigInput<'a> {
    pub name: &'a str,
    pub credential_key: &'a str,
    pub strategy: &'a str,
    pub material: &'a [String],
    pub secret_material_keys: &'a [String],
    pub credential_expires_at_ms: Option<i64>,
}

pub async fn provider_refresh_config(
    server: &str,
    input: ProviderRefreshConfigInput<'_>,
    tls: &TlsOptions,
) -> Result<()> {
    let strategy = provider_refresh_strategy(input.strategy)?;
    let material = parse_key_value_pairs(input.material, "--material")?;
    let mut client = grpc_client(server, tls).await?;
    let status = client
        .configure_provider_refresh(ConfigureProviderRefreshRequest {
            provider: input.name.to_string(),
            credential_key: input.credential_key.to_string(),
            strategy: strategy as i32,
            material,
            secret_material_keys: input.secret_material_keys.to_vec(),
            expires_at_ms: input.credential_expires_at_ms,
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .status
        .ok_or_else(|| miette!("provider refresh status missing from response"))?;

    println!(
        "{} Configured refresh for {} {}",
        "✓".green().bold(),
        status.provider_name,
        status.credential_key
    );
    Ok(())
}

pub async fn provider_rotate(
    server: &str,
    name: &str,
    credential_key: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let status = client
        .rotate_provider_credential(RotateProviderCredentialRequest {
            provider: name.to_string(),
            credential_key: credential_key.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .status
        .ok_or_else(|| miette!("provider refresh status missing from response"))?;

    if status.last_error.is_empty() {
        println!(
            "{} Rotation requested for {} {} ({})",
            "✓".green().bold(),
            status.provider_name,
            status.credential_key,
            status.status
        );
    } else {
        println!(
            "Rotation request recorded for {} {} ({}): {}",
            status.provider_name, status.credential_key, status.status, status.last_error
        );
    }
    Ok(())
}

pub async fn provider_refresh_delete(
    server: &str,
    name: &str,
    credential_key: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .delete_provider_refresh(DeleteProviderRefreshRequest {
            provider: name.to_string(),
            credential_key: credential_key.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner();

    if response.deleted {
        println!(
            "{} Deleted refresh config for {} {}",
            "✓".green().bold(),
            name,
            credential_key
        );
    } else {
        println!("No refresh config found for provider '{name}' credential '{credential_key}'.");
    }
    Ok(())
}

fn provider_refresh_strategy(strategy: &str) -> Result<ProviderCredentialRefreshStrategy> {
    match strategy {
        "oauth2_refresh_token" => Ok(ProviderCredentialRefreshStrategy::Oauth2RefreshToken),
        "oauth2_client_credentials" => {
            Ok(ProviderCredentialRefreshStrategy::Oauth2ClientCredentials)
        }
        "google_service_account_jwt" => {
            Ok(ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt)
        }
        _ => Err(miette!("unsupported provider refresh strategy: {strategy}")),
    }
}

fn print_refresh_status_row(status: &ProviderCredentialRefreshStatus) {
    println!("{}", refresh_status_row(status));
}

fn refresh_status_row(status: &ProviderCredentialRefreshStatus) -> String {
    let strategy = ProviderCredentialRefreshStrategy::try_from(status.strategy)
        .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
    format!(
        "{:<24}  {:<28}  {:<28}  {:<18}  {:<20}  {:<20}  {:<20}  {}",
        status.provider_name,
        status.credential_key,
        provider_refresh_strategy_name(strategy),
        status.status,
        format_optional_epoch_ms(status.expires_at_ms),
        format_optional_epoch_ms(status.next_refresh_at_ms),
        format_optional_epoch_ms(status.last_refresh_at_ms),
        truncate_status_field(&status.last_error, 72),
    )
}

fn format_optional_epoch_ms(ms: i64) -> String {
    if ms > 0 {
        format_epoch_ms(ms)
    } else {
        "-".to_string()
    }
}

fn truncate_status_field(value: &str, max_chars: usize) -> String {
    if value.is_empty() {
        return "-".to_string();
    }
    let mut chars = value.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn provider_refresh_strategy_name(strategy: ProviderCredentialRefreshStrategy) -> &'static str {
    match strategy {
        ProviderCredentialRefreshStrategy::Static => "static",
        ProviderCredentialRefreshStrategy::External => "external",
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken => "oauth2_refresh_token",
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials => "oauth2_client_credentials",
        ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt => "google_service_account_jwt",
        ProviderCredentialRefreshStrategy::Unspecified => "unspecified",
    }
}

fn load_profile_import_items(
    file: Option<&Path>,
    from: Option<&Path>,
) -> Result<(
    Vec<ProviderProfileImportItem>,
    Vec<ProviderProfileDiagnostic>,
)> {
    let paths = profile_source_paths(file, from)?;
    let mut items = Vec::new();
    let mut diagnostics = Vec::new();
    for path in paths {
        match load_profile_import_item(&path) {
            Ok(item) => items.push(item),
            Err(diagnostic) => diagnostics.push(diagnostic),
        }
    }
    Ok((items, diagnostics))
}

fn profile_source_paths(file: Option<&Path>, from: Option<&Path>) -> Result<Vec<PathBuf>> {
    if let Some(file) = file {
        return Ok(vec![file.to_path_buf()]);
    }
    let Some(from) = from else {
        return Ok(Vec::new());
    };
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(from)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read profile directory {}", from.display()))?
    {
        let entry = entry.into_diagnostic()?;
        let path = entry.path();
        if path.is_file() && profile_extension_supported(&path) {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn profile_extension_supported(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("yaml" | "yml" | "json")
    )
}

fn load_profile_import_item(
    path: &Path,
) -> Result<ProviderProfileImportItem, ProviderProfileDiagnostic> {
    let source = path.display().to_string();
    let input = std::fs::read_to_string(path).map_err(|err| {
        profile_file_diagnostic(
            &source,
            format!("failed to read provider profile file: {err}"),
        )
    })?;
    let profile = match path.extension().and_then(|ext| ext.to_str()) {
        Some("yaml" | "yml") => parse_profile_yaml(&input),
        Some("json") => parse_profile_json(&input),
        _ => {
            return Err(profile_file_diagnostic(
                &source,
                "unsupported provider profile file format".to_string(),
            ));
        }
    }
    .map_err(|err| profile_file_diagnostic(&source, err.to_string()))?;

    Ok(ProviderProfileImportItem {
        profile: Some(profile.to_proto()),
        source,
    })
}

fn profile_file_diagnostic(source: &str, message: String) -> ProviderProfileDiagnostic {
    ProviderProfileDiagnostic {
        source: source.to_string(),
        profile_id: String::new(),
        field: "file".to_string(),
        message,
        severity: "error".to_string(),
    }
}

fn print_profile_diagnostics(diagnostics: &[ProviderProfileDiagnostic]) {
    if diagnostics.is_empty() {
        return;
    }
    eprintln!("{}", "Provider profile diagnostics:".red().bold());
    for diagnostic in diagnostics {
        let source = if diagnostic.source.is_empty() {
            "<input>"
        } else {
            &diagnostic.source
        };
        let profile = if diagnostic.profile_id.is_empty() {
            "-".to_string()
        } else {
            diagnostic.profile_id.clone()
        };
        eprintln!(
            "  {} {} profile={} field={} {}",
            diagnostic.severity.as_str().red(),
            source,
            profile,
            diagnostic.field,
            diagnostic.message
        );
    }
}

fn profile_diagnostics_have_errors(diagnostics: &[ProviderProfileDiagnostic]) -> bool {
    diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == "error")
}

fn display_provider_category(category: i32) -> &'static str {
    match ProviderProfileCategory::try_from(category).unwrap_or(ProviderProfileCategory::Other) {
        ProviderProfileCategory::Inference => "INFERENCE",
        ProviderProfileCategory::Agent => "AGENT",
        ProviderProfileCategory::SourceControl => "SOURCE CONTROL",
        ProviderProfileCategory::Messaging => "MESSAGING",
        ProviderProfileCategory::Data => "DATA",
        ProviderProfileCategory::Knowledge => "KNOWLEDGE",
        ProviderProfileCategory::Other | ProviderProfileCategory::Unspecified => "OTHER",
    }
}

const PROVIDER_PROFILE_ID_MAX_WIDTH: usize = 32;
const PROVIDER_PROFILE_DISPLAY_MAX_WIDTH: usize = 40;

fn provider_profile_id_width(profiles: &[ProviderProfile]) -> usize {
    profiles
        .iter()
        .map(|profile| {
            profile
                .id
                .chars()
                .count()
                .min(PROVIDER_PROFILE_ID_MAX_WIDTH)
        })
        .max()
        .unwrap_or(2)
        .max(2)
}

fn provider_profile_display_width(profiles: &[ProviderProfile]) -> usize {
    profiles
        .iter()
        .map(|profile| {
            profile
                .display_name
                .chars()
                .count()
                .min(PROVIDER_PROFILE_DISPLAY_MAX_WIDTH)
        })
        .max()
        .unwrap_or(4)
        .max(4)
}

fn print_provider_type_row(profile: &ProviderProfile, id_width: usize, display_width: usize) {
    let inference = if profile.inference_capable {
        " inference"
    } else {
        ""
    };
    let id = truncate_display(&profile.id, PROVIDER_PROFILE_ID_MAX_WIDTH);
    let display_name = truncate_display(&profile.display_name, PROVIDER_PROFILE_DISPLAY_MAX_WIDTH);
    println!(
        "    {id:<id_width$}  {display_name:<display_width$}  endpoints: {:<2}{}",
        profile.endpoints.len(),
        inference
    );
}

fn truncate_display(value: &str, max_width: usize) -> String {
    if value.chars().count() <= max_width {
        return value.to_string();
    }

    let keep = max_width.saturating_sub(3);
    let mut truncated = value.chars().take(keep).collect::<String>();
    truncated.push_str("...");
    truncated
}

pub async fn provider_update(
    server: &str,
    name: &str,
    from_existing: bool,
    credentials: &[String],
    config: &[String],
    credential_expires_at: &[String],
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
    let credential_expires_at_ms = parse_credential_expiry_pairs(credential_expires_at)?;

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
        let discovered = discover_existing_provider_data(&mut client, &provider_type).await?;
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
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: name.to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: String::new(),
                credentials: credential_map,
                config: config_map,
                credential_expires_at_ms: HashMap::new(),
            }),
            credential_expires_at_ms,
        })
        .await
        .into_diagnostic()?;

    let provider = response
        .into_inner()
        .provider
        .ok_or_else(|| miette::miette!("provider missing from response"))?;

    println!(
        "{} Updated provider {}",
        "✓".green().bold(),
        provider.object_name()
    );
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
    no_verify: bool,
    timeout_secs: u64,
    tls: &TlsOptions,
) -> Result<()> {
    let progress = if std::io::stdout().is_terminal() {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg} ({elapsed})")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        spinner.set_message("Configuring inference...");
        spinner.enable_steady_tick(Duration::from_millis(120));
        Some(spinner)
    } else {
        None
    };

    let mut client = grpc_inference_client(server, tls).await?;
    let response = client
        .set_cluster_inference(SetClusterInferenceRequest {
            provider_name: provider_name.to_string(),
            model_id: model_id.to_string(),
            route_name: route_name.to_string(),
            verify: false,
            no_verify,
            timeout_secs,
        })
        .await;

    if let Some(progress) = &progress {
        progress.finish_and_clear();
    }

    let response = response.map_err(format_inference_status)?;

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
    print_timeout(configured.timeout_secs);
    if configured.validation_performed {
        println!("  {}", "Validated Endpoints:".dimmed());
        for endpoint in configured.validated_endpoints {
            println!("    - {} ({})", endpoint.url, endpoint.protocol);
        }
    }
    Ok(())
}

pub async fn gateway_inference_update(
    server: &str,
    provider_name: Option<&str>,
    model_id: Option<&str>,
    route_name: &str,
    no_verify: bool,
    timeout_secs: Option<u64>,
    tls: &TlsOptions,
) -> Result<()> {
    if provider_name.is_none() && model_id.is_none() && timeout_secs.is_none() {
        return Err(miette::miette!(
            "at least one of --provider, --model, or --timeout must be specified"
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
    let timeout = timeout_secs.unwrap_or(current.timeout_secs);

    let progress = if std::io::stdout().is_terminal() {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg} ({elapsed})")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        spinner.set_message("Configuring inference...");
        spinner.enable_steady_tick(Duration::from_millis(120));
        Some(spinner)
    } else {
        None
    };

    let response = client
        .set_cluster_inference(SetClusterInferenceRequest {
            provider_name: provider.to_string(),
            model_id: model.to_string(),
            route_name: route_name.to_string(),
            verify: false,
            no_verify,
            timeout_secs: timeout,
        })
        .await;

    if let Some(progress) = &progress {
        progress.finish_and_clear();
    }

    let response = response.map_err(format_inference_status)?;

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
    print_timeout(configured.timeout_secs);
    if configured.validation_performed {
        println!("  {}", "Validated Endpoints:".dimmed());
        for endpoint in configured.validated_endpoints {
            println!("    - {} ({})", endpoint.url, endpoint.protocol);
        }
    }
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
        print_timeout(configured.timeout_secs);
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
            print_timeout(configured.timeout_secs);
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

fn print_timeout(timeout_secs: u64) {
    if timeout_secs == 0 {
        println!("  {} {}s (default)", "Timeout:".dimmed(), 60);
    } else {
        println!("  {} {}s", "Timeout:".dimmed(), timeout_secs);
    }
}

fn format_inference_status(status: Status) -> miette::Report {
    let message = status.message().trim();

    if message.is_empty() {
        return miette::miette!("inference configuration failed ({})", status.code());
    }

    miette::miette!("{message}")
}

pub fn git_repo_root(local_path: &Path) -> Result<PathBuf> {
    let git_dir = if local_path.is_dir() {
        local_path
    } else {
        local_path
            .parent()
            .ok_or_else(|| miette::miette!("path has no parent: {}", local_path.display()))?
    };
    let mut command = Command::new("git");
    scrub_git_env(&mut command);
    let output = command
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

    let mut command = Command::new("git");
    scrub_git_env(&mut command);
    let output = command
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

fn sandbox_upload_plan(local_path: &Path, git_ignore: bool) -> Result<SandboxUploadPlan> {
    let metadata = std::fs::symlink_metadata(local_path).map_err(|err| {
        if err.kind() == ErrorKind::NotFound {
            miette::miette!("local path does not exist: {}", local_path.display())
        } else {
            miette::miette!(
                "failed to inspect local upload path: {}",
                local_path.display()
            )
        }
    })?;

    if git_ignore
        && !metadata.file_type().is_symlink()
        && let Ok((base_dir, files)) = git_sync_files(local_path)
    {
        return Ok(SandboxUploadPlan::GitAware { base_dir, files });
    }

    Ok(SandboxUploadPlan::Regular)
}

fn scrub_git_env(command: &mut Command) -> &mut Command {
    for key in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_PREFIX",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ] {
        command.env_remove(key);
    }
    command
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

fn confirm_global_setting_takeover(key: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(miette::miette!(
            "global setting updates require confirmation; pass --yes in non-interactive mode"
        ));
    }

    let proceed = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Setting '{key}' globally will disable sandbox-level management for this key. Continue?"
        ))
        .default(false)
        .interact()
        .into_diagnostic()?;

    if !proceed {
        return Err(miette::miette!("aborted by user"));
    }

    Ok(())
}

fn confirm_global_setting_delete(key: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(miette::miette!(
            "global setting deletes require confirmation; pass --yes in non-interactive mode"
        ));
    }

    let proceed = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Deleting global setting '{key}' re-enables sandbox-level management for this key. Continue?"
        ))
        .default(false)
        .interact()
        .into_diagnostic()?;

    if !proceed {
        return Err(miette::miette!("aborted by user"));
    }

    Ok(())
}

fn parse_cli_setting_value(key: &str, raw_value: &str) -> Result<SettingValue> {
    let setting = settings::setting_for_key(key).ok_or_else(|| {
        miette::miette!(
            "unknown setting key '{}'. Allowed keys: {}",
            key,
            settings::registered_keys_csv()
        )
    })?;

    let value = match setting.kind {
        SettingValueKind::String => {
            // Reject typos client-side so `openshell settings set ...
            // proposal_approval_mode autom` errors immediately instead of
            // round-tripping through the server. The server enforces the
            // same check independently for non-CLI callers.
            setting
                .validate_string_value(raw_value)
                .map_err(|allowed| {
                    miette::miette!(
                        "invalid value '{}' for key '{}'; expected one of: {}",
                        raw_value,
                        key,
                        allowed.join(", ")
                    )
                })?;
            setting_value::Value::StringValue(raw_value.to_string())
        }
        SettingValueKind::Int => {
            let parsed = raw_value.trim().parse::<i64>().map_err(|_| {
                miette::miette!(
                    "invalid int value '{}' for key '{}'; expected base-10 integer",
                    raw_value,
                    key
                )
            })?;
            setting_value::Value::IntValue(parsed)
        }
        SettingValueKind::Bool => {
            let parsed = settings::parse_bool_like(raw_value).ok_or_else(|| {
                miette::miette!(
                    "invalid bool value '{}' for key '{}'; expected one of: true,false,yes,no,1,0",
                    raw_value,
                    key
                )
            })?;
            setting_value::Value::BoolValue(parsed)
        }
    };

    Ok(SettingValue { value: Some(value) })
}

fn format_setting_value(value: Option<&SettingValue>) -> String {
    let Some(value) = value.and_then(|v| v.value.as_ref()) else {
        return "<unset>".to_string();
    };
    match value {
        setting_value::Value::StringValue(v) => v.clone(),
        setting_value::Value::BoolValue(v) => v.to_string(),
        setting_value::Value::IntValue(v) => v.to_string(),
        setting_value::Value::BytesValue(v) => format!("<bytes:{}>", v.len()),
    }
}

fn short_hash(hash: &str) -> &str {
    if hash.len() >= 12 { &hash[..12] } else { hash }
}

fn print_policy_merge_warnings(warnings: &[openshell_policy::PolicyMergeWarning]) {
    for warning in warnings {
        eprintln!("{} {}", "!".yellow().bold(), warning);
    }
}

pub async fn sandbox_policy_set_global(
    server: &str,
    policy_path: &str,
    yes: bool,
    wait: bool,
    _timeout_secs: u64,
    tls: &TlsOptions,
) -> Result<()> {
    if wait {
        return Err(miette::miette!(
            "--wait is only supported for sandbox-scoped policy updates"
        ));
    }

    confirm_global_setting_takeover("policy", yes)?;

    let policy = load_sandbox_policy(Some(policy_path))?
        .ok_or_else(|| miette::miette!("No policy loaded from {policy_path}"))?;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .update_config(UpdateConfigRequest {
            name: String::new(),
            policy: Some(policy),
            setting_key: String::new(),
            setting_value: None,
            delete_setting: false,
            global: true,
            merge_operations: vec![],
            expected_resource_version: 0,
        })
        .await
        .into_diagnostic()?
        .into_inner();

    eprintln!(
        "{} Global policy configured (hash: {}, settings revision: {})",
        "✓".green().bold(),
        if response.policy_hash.len() >= 12 {
            &response.policy_hash[..12]
        } else {
            &response.policy_hash
        },
        response.settings_revision,
    );
    Ok(())
}

pub async fn sandbox_settings_get(
    server: &str,
    name: &str,
    json: bool,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let sandbox = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox not found"))?;

    let response = client
        .get_sandbox_config(GetSandboxConfigRequest {
            sandbox_id: sandbox.object_id().to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner();

    if json {
        let obj = settings_to_json_sandbox(name, &response);
        println!("{}", serde_json::to_string_pretty(&obj).into_diagnostic()?);
        return Ok(());
    }

    let policy_source = if response.policy_source == PolicySource::Global as i32 {
        "global"
    } else {
        "sandbox"
    };

    println!("Sandbox:       {name}");
    println!("Config Rev:    {}", response.config_revision);
    println!("Policy Source: {policy_source}");
    println!("Policy Hash:   {}", response.policy_hash);

    if response.settings.is_empty() {
        println!("Settings:      No settings available.");
        return Ok(());
    }

    println!("Settings:");
    let mut keys: Vec<_> = response.settings.keys().cloned().collect();
    keys.sort();
    for key in keys {
        if let Some(setting) = response.settings.get(&key) {
            let scope = match SettingScope::try_from(setting.scope) {
                Ok(SettingScope::Global) => "global",
                Ok(SettingScope::Sandbox) => "sandbox",
                _ => "unset",
            };
            println!(
                "  {} = {} ({})",
                key,
                format_setting_value(setting.value.as_ref()),
                scope
            );
        }
    }

    Ok(())
}

pub async fn gateway_settings_get(server: &str, json: bool, tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_gateway_config(GetGatewayConfigRequest {})
        .await
        .into_diagnostic()?
        .into_inner();

    if json {
        let obj = settings_to_json_global(&response);
        println!("{}", serde_json::to_string_pretty(&obj).into_diagnostic()?);
        return Ok(());
    }

    println!("Scope:         global");
    println!("Settings Rev:  {}", response.settings_revision);

    if response.settings.is_empty() {
        println!("Settings:      No settings available.");
        return Ok(());
    }

    println!("Settings:");
    let mut keys: Vec<_> = response.settings.keys().cloned().collect();
    keys.sort();
    for key in keys {
        if let Some(setting) = response.settings.get(&key) {
            println!("  {} = {}", key, format_setting_value(Some(setting)));
        }
    }
    Ok(())
}

fn settings_to_json_sandbox(
    name: &str,
    response: &openshell_core::proto::GetSandboxConfigResponse,
) -> serde_json::Value {
    let policy_source = if response.policy_source == PolicySource::Global as i32 {
        "global"
    } else {
        "sandbox"
    };

    let mut settings = serde_json::Map::new();
    let mut keys: Vec<_> = response.settings.keys().cloned().collect();
    keys.sort();
    for key in keys {
        if let Some(setting) = response.settings.get(&key) {
            let scope = match SettingScope::try_from(setting.scope) {
                Ok(SettingScope::Global) => "global",
                Ok(SettingScope::Sandbox) => "sandbox",
                _ => "unset",
            };
            settings.insert(
                key,
                serde_json::json!({
                    "value": format_setting_value(setting.value.as_ref()),
                    "scope": scope,
                }),
            );
        }
    }

    serde_json::json!({
        "sandbox": name,
        "config_revision": response.config_revision,
        "policy_source": policy_source,
        "policy_hash": response.policy_hash,
        "settings": settings,
    })
}

fn settings_to_json_global(
    response: &openshell_core::proto::GetGatewayConfigResponse,
) -> serde_json::Value {
    let mut settings = serde_json::Map::new();
    let mut keys: Vec<_> = response.settings.keys().cloned().collect();
    keys.sort();
    for key in keys {
        if let Some(setting) = response.settings.get(&key) {
            settings.insert(key, serde_json::json!(format_setting_value(Some(setting))));
        }
    }

    serde_json::json!({
        "scope": "global",
        "settings_revision": response.settings_revision,
        "settings": settings,
    })
}

pub async fn gateway_setting_set(
    server: &str,
    key: &str,
    value: &str,
    yes: bool,
    tls: &TlsOptions,
) -> Result<()> {
    let setting_value = parse_cli_setting_value(key, value)?;
    confirm_global_setting_takeover(key, yes)?;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .update_config(UpdateConfigRequest {
            name: String::new(),
            policy: None,
            setting_key: key.to_string(),
            setting_value: Some(setting_value),
            delete_setting: false,
            global: true,
            merge_operations: vec![],
            expected_resource_version: 0,
        })
        .await
        .into_diagnostic()?
        .into_inner();

    println!(
        "{} Set global setting {}={} (revision {})",
        "✓".green().bold(),
        key,
        value,
        response.settings_revision
    );
    Ok(())
}

pub async fn sandbox_setting_set(
    server: &str,
    name: &str,
    key: &str,
    value: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let setting_value = parse_cli_setting_value(key, value)?;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .update_config(UpdateConfigRequest {
            name: name.to_string(),
            policy: None,
            setting_key: key.to_string(),
            setting_value: Some(setting_value),
            delete_setting: false,
            global: false,
            merge_operations: vec![],
            expected_resource_version: 0,
        })
        .await
        .into_diagnostic()?
        .into_inner();

    println!(
        "{} Set sandbox setting {}={} for {} (revision {})",
        "✓".green().bold(),
        key,
        value,
        name,
        response.settings_revision
    );
    Ok(())
}

pub async fn gateway_setting_delete(
    server: &str,
    key: &str,
    yes: bool,
    tls: &TlsOptions,
) -> Result<()> {
    confirm_global_setting_delete(key, yes)?;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .update_config(UpdateConfigRequest {
            name: String::new(),
            policy: None,
            setting_key: key.to_string(),
            setting_value: None,
            delete_setting: true,
            global: true,
            merge_operations: vec![],
            expected_resource_version: 0,
        })
        .await
        .into_diagnostic()?
        .into_inner();

    if response.deleted {
        println!(
            "{} Deleted global setting {} (revision {})",
            "✓".green().bold(),
            key,
            response.settings_revision
        );
    } else {
        println!("{} Global setting {} not found", "!".yellow(), key);
    }
    Ok(())
}

pub async fn sandbox_setting_delete(
    server: &str,
    name: &str,
    key: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .update_config(UpdateConfigRequest {
            name: name.to_string(),
            policy: None,
            setting_key: key.to_string(),
            setting_value: None,
            delete_setting: true,
            global: false,
            merge_operations: vec![],
            expected_resource_version: 0,
        })
        .await
        .into_diagnostic()?
        .into_inner();

    if response.deleted {
        println!(
            "{} Deleted sandbox setting {} for {} (revision {})",
            "✓".green().bold(),
            key,
            name,
            response.settings_revision
        );
    } else {
        println!(
            "{} Sandbox setting {} not found for {}",
            "!".yellow(),
            key,
            name,
        );
    }
    Ok(())
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
            global: false,
        })
        .await
        .ok()
        .and_then(|r| r.into_inner().revision)
        .map_or(0, |r| r.version);

    let response = client
        .update_config(UpdateConfigRequest {
            name: name.to_string(),
            policy: Some(policy),
            setting_key: String::new(),
            setting_value: None,
            delete_setting: false,
            global: false,
            merge_operations: vec![],
            expected_resource_version: 0,
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
                global: false,
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

#[allow(clippy::too_many_arguments)]
pub async fn sandbox_policy_update(
    server: &str,
    name: &str,
    add_endpoints: &[String],
    remove_endpoints: &[String],
    add_deny: &[String],
    add_allow: &[String],
    remove_rules: &[String],
    binaries: &[String],
    rule_name: Option<&str>,
    dry_run: bool,
    wait: bool,
    timeout_secs: u64,
    tls: &TlsOptions,
) -> Result<()> {
    if dry_run && wait {
        return Err(miette!("--wait cannot be combined with --dry-run"));
    }

    let plan = build_policy_update_plan(
        add_endpoints,
        remove_endpoints,
        add_deny,
        add_allow,
        remove_rules,
        binaries,
        rule_name,
    )?;

    let mut client = grpc_client(server, tls).await?;
    let sandbox = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette!("sandbox not found"))?;

    let sandbox_id = if sandbox.object_id().is_empty() {
        return Err(miette!("sandbox missing metadata"));
    } else {
        sandbox.object_id().to_string()
    };

    let current = client
        .get_sandbox_config(GetSandboxConfigRequest { sandbox_id })
        .await
        .into_diagnostic()?
        .into_inner();

    if current.policy_source == PolicySource::Global as i32 {
        return Err(miette!(
            "policy is managed globally; delete the global policy before using `openshell policy update`"
        ));
    }

    let merged = openshell_policy::merge_policy(
        current.policy.clone().unwrap_or_default(),
        &plan.preview_operations,
    )
    .map_err(|error| miette!("{error}"))?;

    if dry_run {
        eprintln!(
            "{} Dry run preview for {} incremental policy operation(s)",
            "✓".green().bold(),
            plan.preview_operations.len()
        );
        print_policy_merge_warnings(&merged.warnings);
        print_sandbox_policy(&merged.policy);
        return Ok(());
    }

    let current_version = current.version;
    let current_hash = current.policy_hash.clone();
    let response = client
        .update_config(UpdateConfigRequest {
            name: name.to_string(),
            policy: None,
            setting_key: String::new(),
            setting_value: None,
            delete_setting: false,
            global: false,
            merge_operations: plan.merge_operations,
            expected_resource_version: 0,
        })
        .await
        .into_diagnostic()?
        .into_inner();

    print_policy_merge_warnings(&merged.warnings);

    if response.version == current_version && response.policy_hash == current_hash {
        eprintln!(
            "{} Policy unchanged (version {}, hash: {})",
            "·".dimmed(),
            response.version,
            short_hash(&response.policy_hash)
        );
        return Ok(());
    }

    eprintln!(
        "{} Policy version {} submitted (hash: {})",
        "✓".green().bold(),
        response.version,
        short_hash(&response.policy_hash)
    );

    if !wait {
        return Ok(());
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if Instant::now() > deadline {
            eprintln!(
                "{} Timeout waiting for policy version {} to load",
                "✗".red().bold(),
                response.version
            );
            std::process::exit(124);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;

        let status_resp = client
            .get_sandbox_policy_status(GetSandboxPolicyStatusRequest {
                name: name.to_string(),
                version: response.version,
                global: false,
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
                _ => {}
            }
        }
    }
}

pub async fn sandbox_policy_get(
    server: &str,
    name: &str,
    version: u32,
    full: bool,
    output: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    sandbox_policy_get_to_writer(
        server,
        name,
        version,
        full,
        output,
        tls,
        (&mut stdout, &mut stderr),
    )
    .await?;

    {
        let mut terminal_stdout = std::io::stdout().lock();
        terminal_stdout.write_all(&stdout).into_diagnostic()?;
    }
    {
        let mut terminal_stderr = std::io::stderr().lock();
        terminal_stderr.write_all(&stderr).into_diagnostic()?;
    }

    Ok(())
}

#[doc(hidden)]
pub async fn sandbox_policy_get_to_writer<W, E>(
    server: &str,
    name: &str,
    version: u32,
    full: bool,
    output: &str,
    tls: &TlsOptions,
    writers: (&mut W, &mut E),
) -> Result<()>
where
    W: Write + Send,
    E: Write + Send,
{
    if version == 0 {
        return sandbox_policy_get_effective_to_writer(server, name, full, output, tls, writers)
            .await;
    }

    let (stdout, stderr) = writers;
    let mut client = grpc_client(server, tls).await?;

    let status_resp = client
        .get_sandbox_policy_status(GetSandboxPolicyStatusRequest {
            name: name.to_string(),
            version,
            global: false,
        })
        .await
        .into_diagnostic()?;

    let inner = status_resp.into_inner();
    if let Some(rev) = inner.revision {
        let status = PolicyStatus::try_from(rev.status).unwrap_or(PolicyStatus::Unspecified);
        match output {
            "json" => {
                let obj = policy_revision_to_json(
                    "sandbox",
                    Some(name),
                    Some(inner.active_version),
                    &rev,
                    status,
                    full,
                )?;
                writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&obj).into_diagnostic()?
                )
                .into_diagnostic()?;
                return Ok(());
            }
            "table" => {}
            _ => return Err(miette!("unsupported output format: {output}")),
        }

        writeln!(stdout, "Version:      {}", rev.version).into_diagnostic()?;
        writeln!(stdout, "Hash:         {}", rev.policy_hash).into_diagnostic()?;
        writeln!(stdout, "Status:       {status:?}").into_diagnostic()?;
        writeln!(stdout, "Active:       {}", inner.active_version).into_diagnostic()?;
        if rev.created_at_ms > 0 {
            writeln!(stdout, "Created:      {} ms", rev.created_at_ms).into_diagnostic()?;
        }
        if rev.loaded_at_ms > 0 {
            writeln!(stdout, "Loaded:       {} ms", rev.loaded_at_ms).into_diagnostic()?;
        }
        if !rev.load_error.is_empty() {
            writeln!(stdout, "Error:        {}", rev.load_error).into_diagnostic()?;
        }

        if full {
            if let Some(ref policy) = rev.policy {
                writeln!(stdout, "---").into_diagnostic()?;
                let yaml_str = openshell_policy::serialize_sandbox_policy(policy)
                    .wrap_err("failed to serialize policy to YAML")?;
                write!(stdout, "{yaml_str}").into_diagnostic()?;
            } else {
                writeln!(stderr, "Policy payload not available for this version")
                    .into_diagnostic()?;
            }
        }
    } else {
        writeln!(stderr, "No policy history found for sandbox '{name}'").into_diagnostic()?;
    }

    Ok(())
}

async fn sandbox_policy_get_effective_to_writer<W, E>(
    server: &str,
    name: &str,
    full: bool,
    output: &str,
    tls: &TlsOptions,
    writers: (&mut W, &mut E),
) -> Result<()>
where
    W: Write + Send,
    E: Write + Send,
{
    let (stdout, _stderr) = writers;
    let mut client = grpc_client(server, tls).await?;

    let sandbox = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette!("sandbox missing from response"))?;
    let sandbox_id = sandbox.object_id();
    if sandbox_id.is_empty() {
        return Err(miette!("sandbox missing metadata"));
    }

    let config = client
        .get_sandbox_config(GetSandboxConfigRequest {
            sandbox_id: sandbox_id.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner();
    let policy = config
        .policy
        .as_ref()
        .ok_or_else(|| miette!("no active policy configured for sandbox '{name}'"))?;
    let policy_source =
        PolicySource::try_from(config.policy_source).unwrap_or(PolicySource::Sandbox);
    let policy_source_label = match policy_source {
        PolicySource::Global => "global",
        PolicySource::Sandbox => "sandbox",
        PolicySource::Unspecified => "unspecified",
    };
    let version = if policy_source == PolicySource::Global && config.global_policy_version > 0 {
        config.global_policy_version
    } else {
        config.version
    };

    match output {
        "json" => {
            let mut obj = serde_json::Map::new();
            obj.insert("scope".to_string(), serde_json::json!("sandbox"));
            obj.insert("sandbox".to_string(), serde_json::json!(name));
            obj.insert("version".to_string(), serde_json::json!(version));
            obj.insert("active_version".to_string(), serde_json::json!(version));
            obj.insert("hash".to_string(), serde_json::json!(config.policy_hash));
            obj.insert("status".to_string(), serde_json::json!("effective"));
            obj.insert(
                "config_revision".to_string(),
                serde_json::json!(config.config_revision),
            );
            obj.insert(
                "policy_source".to_string(),
                serde_json::json!(policy_source_label),
            );
            if config.global_policy_version > 0 {
                obj.insert(
                    "global_policy_version".to_string(),
                    serde_json::json!(config.global_policy_version),
                );
            }
            if full {
                obj.insert(
                    "policy".to_string(),
                    openshell_policy::sandbox_policy_to_json_value(policy)?,
                );
            }
            writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Object(obj)).into_diagnostic()?
            )
            .into_diagnostic()?;
        }
        "table" => {
            writeln!(stdout, "Version:      {version}").into_diagnostic()?;
            writeln!(stdout, "Hash:         {}", config.policy_hash).into_diagnostic()?;
            writeln!(stdout, "Status:       Effective").into_diagnostic()?;
            writeln!(stdout, "Source:       {policy_source_label}").into_diagnostic()?;
            writeln!(stdout, "Config rev:   {}", config.config_revision).into_diagnostic()?;
            if config.global_policy_version > 0 {
                writeln!(stdout, "Global:       {}", config.global_policy_version)
                    .into_diagnostic()?;
            }
            if full {
                writeln!(stdout, "---").into_diagnostic()?;
                let yaml_str = openshell_policy::serialize_sandbox_policy(policy)
                    .wrap_err("failed to serialize policy to YAML")?;
                write!(stdout, "{yaml_str}").into_diagnostic()?;
            }
        }
        _ => return Err(miette!("unsupported output format: {output}")),
    }

    Ok(())
}

pub async fn sandbox_policy_get_global(
    server: &str,
    version: u32,
    full: bool,
    output: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let status_resp = client
        .get_sandbox_policy_status(GetSandboxPolicyStatusRequest {
            name: String::new(),
            version,
            global: true,
        })
        .await
        .into_diagnostic()?;

    let inner = status_resp.into_inner();
    if let Some(rev) = inner.revision {
        let status = PolicyStatus::try_from(rev.status).unwrap_or(PolicyStatus::Unspecified);
        match output {
            "json" => {
                let obj = policy_revision_to_json("global", None, None, &rev, status, full)?;
                println!("{}", serde_json::to_string_pretty(&obj).into_diagnostic()?);
                return Ok(());
            }
            "table" => {}
            _ => return Err(miette!("unsupported output format: {output}")),
        }

        println!("Scope:        global");
        println!("Version:      {}", rev.version);
        println!("Hash:         {}", rev.policy_hash);
        println!("Status:       {status:?}");
        if rev.created_at_ms > 0 {
            println!("Created:      {} ms", rev.created_at_ms);
        }
        if rev.loaded_at_ms > 0 {
            println!("Loaded:       {} ms", rev.loaded_at_ms);
        }

        if full {
            if let Some(ref policy) = rev.policy {
                println!("---");
                let yaml_str = openshell_policy::serialize_sandbox_policy(policy)
                    .wrap_err("failed to serialize policy to YAML")?;
                print!("{yaml_str}");
            } else {
                eprintln!("Policy payload not available for this version");
            }
        }
    } else {
        eprintln!("No global policy history found");
    }

    Ok(())
}

fn policy_status_json_name(status: PolicyStatus) -> &'static str {
    match status {
        PolicyStatus::Unspecified => "unspecified",
        PolicyStatus::Pending => "pending",
        PolicyStatus::Loaded => "loaded",
        PolicyStatus::Failed => "failed",
        PolicyStatus::Superseded => "superseded",
    }
}

fn policy_revision_to_json(
    scope: &str,
    sandbox: Option<&str>,
    active_version: Option<u32>,
    rev: &openshell_core::proto::SandboxPolicyRevision,
    status: PolicyStatus,
    full: bool,
) -> Result<serde_json::Value> {
    let mut obj = serde_json::Map::new();
    obj.insert("scope".to_string(), serde_json::json!(scope));
    if let Some(sandbox) = sandbox {
        obj.insert("sandbox".to_string(), serde_json::json!(sandbox));
    }
    obj.insert("version".to_string(), serde_json::json!(rev.version));
    obj.insert("hash".to_string(), serde_json::json!(rev.policy_hash));
    obj.insert(
        "status".to_string(),
        serde_json::json!(policy_status_json_name(status)),
    );
    if let Some(active_version) = active_version {
        obj.insert(
            "active_version".to_string(),
            serde_json::json!(active_version),
        );
    }
    if rev.created_at_ms > 0 {
        obj.insert(
            "created_at_ms".to_string(),
            serde_json::json!(rev.created_at_ms),
        );
    }
    if rev.loaded_at_ms > 0 {
        obj.insert(
            "loaded_at_ms".to_string(),
            serde_json::json!(rev.loaded_at_ms),
        );
    }
    if !rev.load_error.is_empty() {
        obj.insert("load_error".to_string(), serde_json::json!(rev.load_error));
    }
    if full {
        let policy = match rev.policy.as_ref() {
            Some(policy) => openshell_policy::sandbox_policy_to_json_value(policy)?,
            None => serde_json::Value::Null,
        };
        obj.insert("policy".to_string(), policy);
    }
    Ok(serde_json::Value::Object(obj))
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
            global: false,
        })
        .await
        .into_diagnostic()?;

    let revisions = resp.into_inner().revisions;
    if revisions.is_empty() {
        eprintln!("No policy history found for sandbox '{name}'");
        return Ok(());
    }

    print_policy_revision_table(&revisions);
    Ok(())
}

pub async fn sandbox_policy_list_global(server: &str, limit: u32, tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let resp = client
        .list_sandbox_policies(ListSandboxPoliciesRequest {
            name: String::new(),
            limit,
            offset: 0,
            global: true,
        })
        .await
        .into_diagnostic()?;

    let revisions = resp.into_inner().revisions;
    if revisions.is_empty() {
        eprintln!("No global policy history found");
        return Ok(());
    }

    print_policy_revision_table(&revisions);
    Ok(())
}

fn print_policy_revision_table(revisions: &[openshell_core::proto::SandboxPolicyRevision]) {
    println!(
        "{:<8} {:<14} {:<12} {:<24} ERROR",
        "VERSION", "HASH", "STATUS", "CREATED"
    );
    for rev in revisions {
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
}

// ---------------------------------------------------------------------------
// Sandbox logs command
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)] // user-facing CLI command
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
                id: sandbox.object_id().to_string(),
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
            if let Some(openshell_core::proto::sandbox_stream_event::Payload::Log(log)) =
                event.payload
            {
                print_log_line(&log);
            }
        }
    } else {
        // One-shot mode: use GetSandboxLogs.
        let resp = client
            .get_sandbox_logs(GetSandboxLogsRequest {
                sandbox_id: sandbox.object_id().to_string(),
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

fn print_log_line(log: &openshell_core::proto::SandboxLogLine) {
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

// ---------------------------------------------------------------------------
// Network rule commands
// ---------------------------------------------------------------------------

/// Show network rules for a sandbox.
pub async fn sandbox_draft_get(
    server: &str,
    name: &str,
    status_filter: Option<&str>,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .get_draft_policy(GetDraftPolicyRequest {
            name: name.to_string(),
            status_filter: status_filter.unwrap_or("").to_string(),
        })
        .await
        .into_diagnostic()?;

    let inner = response.into_inner();

    if inner.chunks.is_empty() {
        println!("No network rules for sandbox '{name}'");
        return Ok(());
    }

    println!(
        "{}  (version {}, {} chunk{})",
        "Network Rules:".cyan().bold(),
        inner.draft_version,
        inner.chunks.len(),
        if inner.chunks.len() == 1 { "" } else { "s" }
    );
    println!();

    for chunk in &inner.chunks {
        let status_colored = match chunk.status.as_str() {
            "pending" => chunk.status.yellow().to_string(),
            "approved" => chunk.status.green().to_string(),
            "rejected" => chunk.status.red().to_string(),
            _ => chunk.status.clone(),
        };

        println!("  {} {}", "Chunk:".dimmed(), chunk.id);
        println!("  {} {}", "Status:".dimmed(), status_colored);
        println!("  {} {}", "Rule:".dimmed(), chunk.rule_name);
        if !chunk.binary.is_empty() {
            println!("  {} {}", "Binary:".dimmed(), chunk.binary);
        }
        println!(
            "  {} {:.0}%",
            "Confidence:".dimmed(),
            chunk.confidence * 100.0
        );
        println!("  {} {}", "Rationale:".dimmed(), chunk.rationale);

        if !chunk.security_notes.is_empty() {
            println!(
                "  {} {}",
                "Security:".dimmed(),
                chunk.security_notes.yellow()
            );
        }
        if !chunk.validation_result.is_empty() {
            println!(
                "  {} {}",
                "Validation:".dimmed(),
                chunk.validation_result.cyan()
            );
        }

        if let Some(ref rule) = chunk.proposed_rule {
            println!("  {} {}", "Endpoints:".dimmed(), format_endpoints(rule));
            if !rule.binaries.is_empty() {
                let bins: Vec<&str> = rule.binaries.iter().map(|b| b.path.as_str()).collect();
                println!("  {} {}", "Binaries:".dimmed(), bins.join(", "));
            }
        }

        if chunk.hit_count > 1 {
            println!(
                "  {} {} (first seen {}, last seen {})",
                "Hits:".dimmed(),
                chunk.hit_count,
                format_epoch_ms(chunk.first_seen_ms),
                format_epoch_ms(chunk.last_seen_ms),
            );
        }
        println!();
    }

    Ok(())
}

/// Approve a network rule.
pub async fn sandbox_draft_approve(
    server: &str,
    name: &str,
    chunk_id: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .approve_draft_chunk(ApproveDraftChunkRequest {
            name: name.to_string(),
            chunk_id: chunk_id.to_string(),
        })
        .await
        .into_diagnostic()?;

    let inner = response.into_inner();
    println!(
        "{} Chunk approved. Policy version: {}, hash: {}",
        "OK".green().bold(),
        inner.policy_version,
        &inner.policy_hash[..12.min(inner.policy_hash.len())]
    );

    Ok(())
}

/// Reject a network rule.
pub async fn sandbox_draft_reject(
    server: &str,
    name: &str,
    chunk_id: &str,
    reason: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    client
        .reject_draft_chunk(RejectDraftChunkRequest {
            name: name.to_string(),
            chunk_id: chunk_id.to_string(),
            reason: reason.to_string(),
        })
        .await
        .into_diagnostic()?;

    println!("{} Chunk rejected.", "OK".green().bold());

    Ok(())
}

/// Approve all pending network rules.
pub async fn sandbox_draft_approve_all(
    server: &str,
    name: &str,
    include_security_flagged: bool,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .approve_all_draft_chunks(ApproveAllDraftChunksRequest {
            name: name.to_string(),
            include_security_flagged,
        })
        .await
        .into_diagnostic()?;

    let inner = response.into_inner();
    println!(
        "{} {} chunk(s) approved, {} skipped. Policy version: {}",
        "OK".green().bold(),
        inner.chunks_approved,
        inner.chunks_skipped,
        inner.policy_version,
    );

    Ok(())
}

/// Clear all pending network rules.
pub async fn sandbox_draft_clear(server: &str, name: &str, tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .clear_draft_chunks(ClearDraftChunksRequest {
            name: name.to_string(),
        })
        .await
        .into_diagnostic()?;

    let inner = response.into_inner();
    println!(
        "{} {} pending chunk(s) cleared.",
        "OK".green().bold(),
        inner.chunks_cleared,
    );

    Ok(())
}

/// Show network rule history.
pub async fn sandbox_draft_history(server: &str, name: &str, tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .get_draft_history(GetDraftHistoryRequest {
            name: name.to_string(),
        })
        .await
        .into_diagnostic()?;

    let inner = response.into_inner();

    if inner.entries.is_empty() {
        println!("No rule history for sandbox '{name}'");
        return Ok(());
    }

    println!("{}", "Rule History:".cyan().bold());
    println!();

    for entry in &inner.entries {
        let event_colored = match entry.event_type.as_str() {
            "proposed" => entry.event_type.yellow().to_string(),
            "approved" => entry.event_type.green().to_string(),
            "rejected" => entry.event_type.red().to_string(),
            _ => entry.event_type.clone(),
        };

        println!(
            "  {} {} [{}] {}",
            format_timestamp_ms(entry.timestamp_ms).dimmed(),
            event_colored,
            entry.chunk_id.get(..8).unwrap_or(&entry.chunk_id),
            entry.description,
        );
    }

    Ok(())
}

/// Format a `NetworkPolicyRule`'s endpoints as a compact string.
fn format_endpoints(rule: &openshell_core::proto::NetworkPolicyRule) -> String {
    rule.endpoints
        .iter()
        .map(format_endpoint)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Render an endpoint as `host:port [layer, …allows…, …denies…]` so a reader
/// can tell L4-only access apart from a method/path-scoped L7 grant. The L7
/// fields (`protocol: rest`, `rules`, `access`) materially change what gets
/// allowed; surfacing them in the default text output is what makes
/// `openshell rule get` useful for approval review.
fn format_endpoint(endpoint: &openshell_core::proto::NetworkEndpoint) -> String {
    let host_port = if endpoint.port > 0 {
        format!("{}:{}", endpoint.host, endpoint.port)
    } else {
        endpoint.host.clone()
    };

    let mut tags: Vec<String> = Vec::new();
    let layer_tag = if endpoint.protocol.eq_ignore_ascii_case("rest") {
        "L7 rest"
    } else if endpoint.protocol.is_empty() {
        "L4"
    } else {
        endpoint.protocol.as_str()
    };
    tags.push(layer_tag.to_string());

    if !endpoint.access.is_empty() {
        tags.push(format!("access={}", endpoint.access));
    }

    for r in &endpoint.rules {
        if let Some(allow) = &r.allow {
            let method = non_empty_or(&allow.method, "*");
            let path = non_empty_or(&allow.path, "*");
            tags.push(format!("allow {method} {path}"));
        }
    }
    for r in &endpoint.deny_rules {
        let method = non_empty_or(&r.method, "*");
        let path = non_empty_or(&r.path, "*");
        tags.push(format!("deny {method} {path}"));
    }

    format!("{host_port} [{}]", tags.join(", "))
}

fn non_empty_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}

/// Format a millisecond timestamp into a readable string.
fn format_timestamp_ms(ms: i64) -> String {
    if ms <= 0 {
        return "-".to_string();
    }
    let secs = ms / 1000;
    let mins = (secs / 60) % 60;
    let hours = (secs / 3600) % 24;
    let days = secs / 86400;
    if days > 0 {
        format!("{days}d {hours:02}:{mins:02}")
    } else {
        format!("{hours:02}:{mins:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ProvisioningStep, TlsOptions, build_sandbox_resource_limits,
        dockerfile_sources_supported_for_gateway, format_endpoint, format_gateway_select_header,
        format_gateway_select_items, format_provider_attachment_table, gateway_add,
        gateway_auth_label, gateway_env_override_warning, gateway_select_with, gateway_type_label,
        git_sync_files, http_health_check, image_requests_gpu, import_local_package_mtls_bundle,
        inferred_provider_type, mtls_certs_exist_for_gateway, package_managed_tls_dirs,
        parse_cli_setting_value, parse_credential_expiry_cli_value, parse_credential_expiry_pairs,
        parse_credential_pairs, parse_driver_config_json, plaintext_gateway_is_remote,
        progress_step_from_metadata, provider_profile_allows_refresh_bootstrap,
        provisioning_timeout_message, ready_false_condition_message, refresh_status_header,
        refresh_status_row, resolve_from, sandbox_should_persist, sandbox_upload_plan,
        service_expose_status_error, service_url_for_gateway,
    };
    use crate::TEST_ENV_LOCK;
    use hyper::StatusCode;
    use openshell_bootstrap::{load_active_gateway, load_gateway_metadata, store_gateway_metadata};
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::thread;
    use tonic::Status;

    use openshell_bootstrap::GatewayMetadata;
    use openshell_core::progress::{
        PROGRESS_STEP_PULLING_IMAGE, PROGRESS_STEP_REQUESTING_SANDBOX,
        PROGRESS_STEP_STARTING_SANDBOX,
    };
    use openshell_core::proto::{
        Provider, ProviderCredentialRefresh, ProviderCredentialRefreshStatus,
        ProviderCredentialRefreshStrategy, ProviderProfile, ProviderProfileCredential,
        SandboxCondition, SandboxStatus, datamodel::v1::ObjectMeta,
    };

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
            auth_mode: Some("cloudflare_jwt".to_string()),
            ..Default::default()
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
    fn parse_credential_expiry_pairs_accepts_epoch_millis_and_rfc3339() {
        let parsed = parse_credential_expiry_pairs(&[
            "API_TOKEN=1767225600000".to_string(),
            "MS_GRAPH_ACCESS_TOKEN=2026-01-01T00:00:00Z".to_string(),
        ])
        .expect("parse");

        assert_eq!(parsed.get("API_TOKEN"), Some(&1_767_225_600_000));
        assert_eq!(
            parsed.get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&1_767_225_600_000)
        );
    }

    #[test]
    fn parse_credential_expiry_pairs_accepts_zero_to_clear_expiry() {
        let parsed =
            parse_credential_expiry_pairs(&["API_TOKEN=0".to_string()]).expect("parse zero");

        assert_eq!(parsed.get("API_TOKEN"), Some(&0));
    }

    #[test]
    fn parse_credential_expiry_rejects_invalid_timestamp() {
        let err = parse_credential_expiry_pairs(&["API_TOKEN=next-week".to_string()])
            .expect_err("invalid timestamp should error");

        assert!(
            err.to_string()
                .contains("must be a Unix epoch millisecond timestamp or RFC3339 timestamp")
        );
    }

    #[test]
    fn parse_credential_expiry_cli_value_accepts_rfc3339_offsets() {
        let parsed = parse_credential_expiry_cli_value("2026-01-01T01:00:00+01:00")
            .expect("parse RFC3339 with offset");

        assert_eq!(parsed, 1_767_225_600_000);
    }

    #[test]
    fn provider_attachment_table_formats_provider_counts() {
        let output = format_provider_attachment_table(
            &[Provider {
                metadata: Some(ObjectMeta {
                    name: "work-custom".to_string(),
                    ..Default::default()
                }),
                r#type: "custom-api".to_string(),
                credentials: [
                    ("CUSTOM_API_KEY".to_string(), "REDACTED".to_string()),
                    ("CUSTOM_API_SECRET".to_string(), "REDACTED".to_string()),
                ]
                .into_iter()
                .collect(),
                config: std::iter::once((
                    "BASE_URL".to_string(),
                    "https://api.custom.example".to_string(),
                ))
                .collect(),
                credential_expires_at_ms: std::collections::HashMap::new(),
            }],
            false,
        );

        assert!(output.contains("NAME"));
        assert!(output.contains("TYPE"));
        assert!(output.contains("CREDENTIAL_KEYS"));
        assert!(output.contains("CONFIG_KEYS"));
        assert!(output.contains("work-custom"));
        assert!(output.contains("custom-api"));
        assert!(output.contains('2'));
        assert!(output.contains('1'));
    }

    #[test]
    fn progress_step_metadata_values_map_to_cli_steps() {
        assert_eq!(
            progress_step_from_metadata(PROGRESS_STEP_REQUESTING_SANDBOX),
            Some(ProvisioningStep::RequestingSandbox)
        );
        assert_eq!(
            progress_step_from_metadata(PROGRESS_STEP_PULLING_IMAGE),
            Some(ProvisioningStep::PullingSandboxImage)
        );
        assert_eq!(
            progress_step_from_metadata(PROGRESS_STEP_STARTING_SANDBOX),
            Some(ProvisioningStep::StartingSandbox)
        );
        assert_eq!(progress_step_from_metadata("driver-private-step"), None);
    }

    #[test]
    fn refresh_status_table_includes_operational_fields() {
        let header = refresh_status_header();
        assert!(header.contains("NEXT_REFRESH"));
        assert!(header.contains("LAST_REFRESH"));
        assert!(header.contains("LAST_ERROR"));

        let row = refresh_status_row(&ProviderCredentialRefreshStatus {
            provider_name: "my-graph".to_string(),
            provider_id: "provider-id".to_string(),
            credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
            strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
            status: "error".to_string(),
            expires_at_ms: 1_767_225_600_000,
            next_refresh_at_ms: 1_767_225_660_000,
            last_refresh_at_ms: 1_767_225_000_000,
            last_error: "token endpoint returned a very long error message that should be truncated for table readability"
                .to_string(),
        });

        assert!(row.contains("my-graph"));
        assert!(row.contains("MS_GRAPH_ACCESS_TOKEN"));
        assert!(row.contains("oauth2_client_credentials"));
        assert!(row.contains("error"));
        assert!(row.contains("2026-01-01 00:00:00"));
        assert!(row.contains("..."));
    }

    #[test]
    fn refresh_bootstrap_requires_all_required_credentials_to_be_gateway_mintable() {
        let refresh_token_profile = ProviderProfile {
            credentials: vec![ProviderProfileCredential {
                name: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                required: true,
                refresh: Some(ProviderCredentialRefresh {
                    strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(provider_profile_allows_refresh_bootstrap(
            &refresh_token_profile
        ));

        let mixed_static_profile = ProviderProfile {
            credentials: vec![
                ProviderProfileCredential {
                    name: "ACCESS_TOKEN".to_string(),
                    required: true,
                    refresh: Some(ProviderCredentialRefresh {
                        strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ProviderProfileCredential {
                    name: "STATIC_API_KEY".to_string(),
                    required: true,
                    refresh: None,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert!(!provider_profile_allows_refresh_bootstrap(
            &mixed_static_profile
        ));

        let optional_refresh_profile = ProviderProfile {
            credentials: vec![ProviderProfileCredential {
                name: "OPTIONAL_TOKEN".to_string(),
                required: false,
                refresh: Some(ProviderCredentialRefresh {
                    strategy: ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(provider_profile_allows_refresh_bootstrap(
            &optional_refresh_profile
        ));
    }

    #[cfg(feature = "dev-settings")]
    #[test]
    fn parse_cli_setting_value_parses_bool_aliases() {
        let yes_value = parse_cli_setting_value("dummy_bool", "yes").expect("parse yes");
        assert_eq!(
            yes_value.value,
            Some(openshell_core::proto::setting_value::Value::BoolValue(true))
        );

        let zero_value = parse_cli_setting_value("dummy_bool", "0").expect("parse 0");
        assert_eq!(
            zero_value.value,
            Some(openshell_core::proto::setting_value::Value::BoolValue(
                false
            ))
        );
    }

    #[cfg(feature = "dev-settings")]
    #[test]
    fn parse_cli_setting_value_parses_int_key() {
        let int_value = parse_cli_setting_value("dummy_int", "42").expect("parse int");
        assert_eq!(
            int_value.value,
            Some(openshell_core::proto::setting_value::Value::IntValue(42))
        );
    }

    #[cfg(feature = "dev-settings")]
    #[test]
    fn parse_cli_setting_value_rejects_invalid_bool() {
        let err =
            parse_cli_setting_value("dummy_bool", "maybe").expect_err("invalid bool should fail");
        assert!(err.to_string().contains("invalid bool value"));
    }

    #[test]
    fn parse_cli_setting_value_rejects_unknown_key() {
        let err =
            parse_cli_setting_value("unknown_key", "value").expect_err("unknown key should fail");
        assert!(err.to_string().contains("unknown setting key"));
    }

    #[test]
    fn build_sandbox_resource_limits_sets_limits_only() {
        let resources = build_sandbox_resource_limits(Some("500m"), Some("2Gi"))
            .expect("resource limits should parse")
            .expect("resource limits should be present");

        let limits = resources
            .fields
            .get("limits")
            .and_then(|value| value.kind.as_ref())
            .and_then(|kind| match kind {
                prost_types::value::Kind::StructValue(inner) => Some(inner),
                _ => None,
            })
            .expect("limits should be a struct");

        assert_eq!(
            limits
                .fields
                .get("cpu")
                .and_then(|value| value.kind.as_ref())
                .and_then(|kind| match kind {
                    prost_types::value::Kind::StringValue(value) => Some(value.as_str()),
                    _ => None,
                }),
            Some("500m")
        );
        assert_eq!(
            limits
                .fields
                .get("memory")
                .and_then(|value| value.kind.as_ref())
                .and_then(|kind| match kind {
                    prost_types::value::Kind::StringValue(value) => Some(value.as_str()),
                    _ => None,
                }),
            Some("2Gi")
        );
        assert!(!resources.fields.contains_key("requests"));
    }

    #[test]
    fn build_sandbox_resource_limits_rejects_invalid_quantities() {
        assert!(build_sandbox_resource_limits(Some("0"), None).is_err());
        assert!(build_sandbox_resource_limits(Some("half"), None).is_err());
        assert!(build_sandbox_resource_limits(None, Some("0Gi")).is_err());
        assert!(build_sandbox_resource_limits(None, Some("1.5Gi")).is_err());
    }

    #[test]
    fn parse_driver_config_json_accepts_driver_keyed_object() {
        let config =
            parse_driver_config_json(r#"{"kubernetes":{"pod":{"node_selector":{"pool":"gpu"}}}}"#)
                .expect("driver config should parse");

        let kubernetes = config
            .fields
            .get("kubernetes")
            .and_then(|value| value.kind.as_ref())
            .and_then(|kind| match kind {
                prost_types::value::Kind::StructValue(inner) => Some(inner),
                _ => None,
            })
            .expect("kubernetes block should be a struct");
        let pod = kubernetes
            .fields
            .get("pod")
            .and_then(|value| value.kind.as_ref())
            .and_then(|kind| match kind {
                prost_types::value::Kind::StructValue(inner) => Some(inner),
                _ => None,
            })
            .expect("pod block should be a struct");

        assert!(pod.fields.contains_key("node_selector"));
    }

    #[test]
    fn parse_driver_config_json_rejects_non_object() {
        let err = parse_driver_config_json(r#"["kubernetes"]"#)
            .expect_err("top-level array should be rejected");

        assert!(
            err.to_string().contains("keyed by driver name"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_driver_config_json_rejects_invalid_json() {
        let err = parse_driver_config_json(r#"{"kubernetes":"#)
            .expect_err("invalid JSON should be rejected");

        assert!(
            err.to_string().contains("must be valid JSON"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn inferred_provider_type_returns_type_for_known_command() {
        let result = inferred_provider_type(&["claude".to_string(), "--help".to_string()]);
        assert_eq!(result, Some("claude-code".to_string()));
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
        assert_eq!(result, Some("claude-code".to_string()));
    }

    #[test]
    fn sandbox_should_persist_defaults_to_persistent() {
        assert!(sandbox_should_persist(true, None));
    }

    #[test]
    fn sandbox_should_not_persist_when_no_keep_is_set() {
        assert!(!sandbox_should_persist(false, None));
    }

    #[test]
    fn sandbox_should_persist_when_forward_is_requested() {
        let spec = openshell_core::forward::ForwardSpec::new(8080);
        assert!(sandbox_should_persist(false, Some(&spec)));
    }

    #[test]
    fn image_requests_gpu_matches_known_gpu_image_names() {
        for image in [
            "ghcr.io/nvidia/openshell-community/sandboxes/nvidia-gpu:latest",
            "registry.example.com/team/gpu:dev",
            "nvcr.io/example/my-gpu-image@sha256:deadbeef",
        ] {
            assert!(
                image_requests_gpu(image),
                "expected GPU detection for {image}"
            );
        }
    }

    #[test]
    fn image_requests_gpu_ignores_non_gpu_image_names() {
        for image in [
            "ghcr.io/nvidia/openshell-community/sandboxes/base:latest",
            "registry.example.com/gpu/team/base:latest",
            "registry.example.com/team/notebook:latest",
            "cuda-toolkit:latest",
            "registry.example.com/team/graphics:latest",
        ] {
            assert!(
                !image_requests_gpu(image),
                "did not expect GPU detection for {image}"
            );
        }
    }

    #[test]
    fn resolve_from_classifies_existing_dockerfile_path() {
        let temp = tempfile::tempdir().expect("failed to create tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\n").expect("failed to write Dockerfile");

        match resolve_from(dockerfile.to_str().expect("temp path is not UTF-8"))
            .expect("expected Dockerfile source")
        {
            super::ResolvedSource::Dockerfile {
                dockerfile: resolved,
                context,
            } => {
                assert_eq!(
                    resolved,
                    dockerfile
                        .canonicalize()
                        .expect("failed to canonicalize Dockerfile")
                );
                assert_eq!(
                    context,
                    temp.path()
                        .canonicalize()
                        .expect("failed to canonicalize context")
                );
            }
            super::ResolvedSource::Image(image) => {
                panic!("expected Dockerfile source, got image {image}");
            }
        }
    }

    #[test]
    fn resolve_from_rejects_missing_explicit_dockerfile_path() {
        let temp = tempfile::tempdir().expect("failed to create tempdir");
        let missing = temp.path().join("Dockerfile");

        let err = resolve_from(missing.to_str().expect("temp path is not UTF-8"))
            .expect_err("expected missing Dockerfile path to be rejected");

        assert!(
            err.to_string().contains("local --from path does not exist"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_from_keeps_dockerfile_named_image_refs_as_images() {
        let image_ref = "ghcr.io/acme/dockerfile-runner:latest";

        match resolve_from(image_ref).expect("expected image source") {
            super::ResolvedSource::Image(image) => assert_eq!(image, image_ref),
            super::ResolvedSource::Dockerfile { .. } => {
                panic!("expected image ref, got Dockerfile source");
            }
        }
    }

    #[test]
    fn dockerfile_sources_are_rejected_for_remote_gateways() {
        let metadata = GatewayMetadata {
            name: "remote".to_string(),
            gateway_endpoint: "https://gateway.example.com".to_string(),
            is_remote: true,
            gateway_port: 443,
            remote_host: Some("user@gateway.example.com".to_string()),
            resolved_host: Some("gateway.example.com".to_string()),
            auth_mode: None,
            edge_team_domain: None,
            edge_auth_url: None,
            vm_driver_state_dir: None,
            ..Default::default()
        };

        assert!(!dockerfile_sources_supported_for_gateway(Some(&metadata)));
    }

    #[test]
    fn dockerfile_sources_are_allowed_for_local_gateways() {
        let metadata = GatewayMetadata {
            name: "local".to_string(),
            gateway_endpoint: "http://127.0.0.1:8080".to_string(),
            is_remote: false,
            gateway_port: 8080,
            remote_host: None,
            resolved_host: None,
            auth_mode: None,
            edge_team_domain: None,
            edge_auth_url: None,
            vm_driver_state_dir: None,
            ..Default::default()
        };

        assert!(dockerfile_sources_supported_for_gateway(Some(&metadata)));
        assert!(dockerfile_sources_supported_for_gateway(None));
    }

    #[test]
    fn service_url_for_gateway_uses_external_gateway_port() {
        assert_eq!(
            service_url_for_gateway(
                "https://quiet-flamingo--notebook.navigator.openshell.localhost:8080/",
                "https://127.0.0.1:31886"
            ),
            "https://quiet-flamingo--notebook.navigator.openshell.localhost:31886/"
        );
    }

    #[test]
    fn service_url_for_gateway_omits_default_external_port() {
        assert_eq!(
            service_url_for_gateway(
                "https://quiet-flamingo--notebook.navigator.openshell.localhost:8080/",
                "https://gateway.example.com"
            ),
            "https://quiet-flamingo--notebook.navigator.openshell.localhost/"
        );
    }

    #[test]
    fn service_url_for_gateway_preserves_service_scheme() {
        assert_eq!(
            service_url_for_gateway(
                "http://quiet-flamingo--notebook.navigator.openshell.localhost:8080/",
                "https://127.0.0.1:31886"
            ),
            "http://quiet-flamingo--notebook.navigator.openshell.localhost:31886/"
        );
    }

    #[test]
    fn service_url_for_gateway_uses_gateway_default_port() {
        assert_eq!(
            service_url_for_gateway(
                "http://quiet-flamingo--notebook.navigator.openshell.localhost:8080/",
                "https://gateway.example.com"
            ),
            "http://quiet-flamingo--notebook.navigator.openshell.localhost:443/"
        );
    }

    #[test]
    fn service_expose_status_error_mentions_required_scope() {
        let report = service_expose_status_error(Status::permission_denied(
            "scope 'sandbox:write' required",
        ));

        assert_eq!(
            report.to_string(),
            "expose service failed: permission denied (requires sandbox:write)"
        );
    }

    #[test]
    fn ready_false_condition_message_prefers_reason_and_message() {
        let status = SandboxStatus {
            sandbox_name: "gpu".to_string(),
            agent_pod: "gpu-pod".to_string(),
            conditions: vec![SandboxCondition {
                r#type: "Ready".to_string(),
                status: "False".to_string(),
                reason: "Unschedulable".to_string(),
                message: "Another GPU sandbox may already be using the available GPU.".to_string(),
                last_transition_time: String::new(),
            }],
            ..Default::default()
        };

        assert_eq!(
            ready_false_condition_message(Some(&status)).as_deref(),
            Some("Unschedulable: Another GPU sandbox may already be using the available GPU.")
        );
    }

    #[test]
    fn ready_false_condition_message_ignores_non_ready_conditions() {
        let status = SandboxStatus {
            sandbox_name: "gpu".to_string(),
            agent_pod: "gpu-pod".to_string(),
            conditions: vec![SandboxCondition {
                r#type: "Scheduled".to_string(),
                status: "True".to_string(),
                reason: "Scheduled".to_string(),
                message: "Sandbox scheduled".to_string(),
                last_transition_time: String::new(),
            }],
            ..Default::default()
        };

        assert!(ready_false_condition_message(Some(&status)).is_none());
    }

    #[test]
    fn provisioning_timeout_message_includes_condition_and_gpu_hint() {
        let message = provisioning_timeout_message(
            120,
            true,
            Some("DependenciesNotReady: Pod exists with phase: Pending; Service Exists"),
        );

        assert!(message.contains("sandbox provisioning timed out after 120s"));
        assert!(message.contains("Last reported status: DependenciesNotReady: Pod exists with phase: Pending; Service Exists"));
        assert!(message.contains("available GPU is already in use by another sandbox"));
    }

    #[test]
    fn provisioning_timeout_message_omits_gpu_hint_for_non_gpu_requests() {
        let message = provisioning_timeout_message(120, false, None);

        assert_eq!(message, "sandbox provisioning timed out after 120s");
    }

    fn init_git_repo(path: &Path) {
        let mut command = Command::new("git");
        super::scrub_git_env(&mut command);
        let status = command
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
    fn sandbox_upload_plan_errors_for_missing_local_path() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let missing = tmpdir.path().join("missing");

        let err = sandbox_upload_plan(&missing, false).expect_err("missing path should error");

        assert!(
            err.to_string().contains("local path does not exist"),
            "expected missing-path error, got: {err}"
        );
    }

    #[test]
    fn sandbox_upload_plan_errors_for_missing_local_path_with_git_ignore() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let repo = tmpdir.path().join("repo");
        fs::create_dir_all(&repo).expect("create repo");
        init_git_repo(&repo);
        let missing = repo.join("missing");

        let err = sandbox_upload_plan(&missing, true).expect_err("missing path should error");

        assert!(
            err.to_string().contains("local path does not exist"),
            "expected missing-path error, got: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_upload_plan_uses_regular_upload_for_symlinks() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let repo = tmpdir.path().join("repo");
        fs::create_dir_all(repo.join("real-dir")).expect("create repo");
        init_git_repo(&repo);
        fs::write(repo.join("real-dir/file.txt"), "file").expect("write file.txt");
        std::os::unix::fs::symlink("real-dir", repo.join("link-dir")).expect("create symlink");

        let plan = sandbox_upload_plan(&repo.join("link-dir"), true)
            .expect("symlink upload should be planned");

        assert_eq!(plan, super::SandboxUploadPlan::Regular);
    }

    #[test]
    fn git_sync_files_ignores_inherited_git_env() {
        let _lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let repo = tmpdir.path().join("repo");
        fs::create_dir_all(repo.join("nested")).expect("create repo");
        init_git_repo(&repo);

        fs::write(repo.join("nested/file.txt"), "file").expect("write file.txt");
        fs::write(repo.join("top.txt"), "top").expect("write top.txt");

        let _git_dir = EnvVarGuard::set("GIT_DIR", "/tmp/not-the-test-repo/.git");
        let _git_work_tree = EnvVarGuard::set("GIT_WORK_TREE", "/tmp/not-the-test-repo");

        let result = git_sync_files(&repo.join("nested"));
        let (base_dir, files) = result.expect("git_sync_files should succeed");

        assert_eq!(
            base_dir,
            fs::canonicalize(repo.join("nested")).expect("canonicalize nested path")
        );
        assert_eq!(files, vec!["file.txt"]);
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
    fn gateway_env_override_warning_mentions_masked_selection() {
        let _guard = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _env = EnvVarGuard::set("OPENSHELL_GATEWAY", "openshell");

        let warning = gateway_env_override_warning("docker-dev").expect("env override should warn");

        assert!(
            warning.contains("OPENSHELL_GATEWAY=openshell"),
            "warning should name the overriding env var: {warning}"
        );
        assert!(
            warning.contains("export OPENSHELL_GATEWAY=docker-dev"),
            "warning should suggest updating the env var: {warning}"
        );
    }

    #[test]
    fn gateway_env_override_warning_skips_matching_gateway() {
        let _guard = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _env = EnvVarGuard::set("OPENSHELL_GATEWAY", "docker-dev");

        assert_eq!(gateway_env_override_warning("docker-dev"), None);
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
                gateway_port: 8080,
                ..Default::default()
            },
        ];

        let items = format_gateway_select_items(&gateways);
        let header = format_gateway_select_header(&gateways);

        assert_eq!(gateway_type_label(&gateways[0]), "cloud");
        assert_eq!(gateway_type_label(&gateways[1]), "local");
        assert_eq!(gateway_auth_label(&gateways[0]), "cloudflare_jwt");
        assert_eq!(gateway_auth_label(&gateways[1]), "plaintext");
        assert!(header.contains("NAME"));
        assert!(header.contains("ENDPOINT"));
        assert!(header.contains("TYPE"));
        assert!(header.contains("AUTH"));
        assert!(items[0].contains("alpha"));
        assert!(items[0].contains("https://edge.example.com"));
        assert!(items[0].contains("cloud"));
        assert!(items[0].contains("cloudflare_jwt"));
        assert!(items[1].contains("local"));
        assert!(items[1].contains("plaintext"));
        assert!(items[1].contains("http://127.0.0.1:8080"));
    }

    #[test]
    fn gateway_auth_label_defaults_https_gateways_to_mtls() {
        let gateway = GatewayMetadata {
            name: "local".to_string(),
            gateway_endpoint: "https://127.0.0.1:8080".to_string(),
            gateway_port: 8080,
            ..Default::default()
        };

        assert_eq!(gateway_auth_label(&gateway), "mtls");
    }

    #[test]
    fn package_managed_tls_dirs_respects_override() {
        let _guard = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _tls_dir = EnvVarGuard::set("OPENSHELL_LOCAL_TLS_DIR", "/tmp/openshell-test-tls");

        assert_eq!(
            package_managed_tls_dirs(),
            vec![PathBuf::from("/tmp/openshell-test-tls")],
        );
    }

    #[test]
    fn import_local_package_mtls_bundle_copies_client_materials() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let package_tls = tmpdir.path().join("package-tls");
        fs::create_dir_all(package_tls.join("client")).expect("create package tls dir");
        fs::write(package_tls.join("ca.crt"), "ca").expect("write ca");
        fs::write(package_tls.join("client/tls.crt"), "client cert").expect("write cert");
        fs::write(package_tls.join("client/tls.key"), "client key").expect("write key");

        with_tmp_xdg(tmpdir.path(), || {
            let _tls_dir = EnvVarGuard::set(
                "OPENSHELL_LOCAL_TLS_DIR",
                package_tls.to_str().expect("temp path should be utf-8"),
            );

            let imported =
                import_local_package_mtls_bundle("openshell").expect("import local bundle");

            assert_eq!(imported.as_deref(), Some(package_tls.as_path()));

            let mtls = tmpdir.path().join("openshell/gateways/openshell/mtls");
            assert_eq!(fs::read_to_string(mtls.join("ca.crt")).unwrap(), "ca");
            assert_eq!(
                fs::read_to_string(mtls.join("tls.crt")).unwrap(),
                "client cert",
            );
            assert_eq!(
                fs::read_to_string(mtls.join("tls.key")).unwrap(),
                "client key",
            );
        });
    }

    #[test]
    fn mtls_certs_exist_for_gateway_uses_explicit_name_for_loopback_endpoint() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let mtls = tmpdir.path().join("openshell/gateways/k8s/mtls");
        fs::create_dir_all(&mtls).expect("create mtls dir");
        fs::write(mtls.join("ca.crt"), "ca").expect("write ca");
        fs::write(mtls.join("tls.crt"), "client cert").expect("write cert");
        fs::write(mtls.join("tls.key"), "client key").expect("write key");

        with_tmp_xdg(tmpdir.path(), || {
            assert!(mtls_certs_exist_for_gateway("k8s"));
            assert!(!mtls_certs_exist_for_gateway("openshell"));
        });
    }

    #[test]
    fn plaintext_gateway_locality_infers_loopback_endpoints_as_local() {
        assert!(!plaintext_gateway_is_remote(
            "http://127.0.0.1:8080",
            None,
            false,
        ));
        assert!(!plaintext_gateway_is_remote(
            "http://localhost:8080",
            None,
            false,
        ));
        assert!(!plaintext_gateway_is_remote(
            "http://[::1]:8080",
            None,
            false,
        ));
    }

    #[test]
    fn plaintext_gateway_locality_treats_non_loopback_endpoints_as_remote_without_local_flag() {
        assert!(plaintext_gateway_is_remote(
            "http://gateway.example.com:8080",
            None,
            false,
        ));
        assert!(plaintext_gateway_is_remote(
            "http://10.0.0.5:8080",
            None,
            false,
        ));
    }

    #[test]
    fn gateway_add_registers_plaintext_loopback_gateway_without_local_flag() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        with_tmp_xdg(tmpdir.path(), || {
            let runtime = tokio::runtime::Runtime::new().expect("create runtime");
            runtime.block_on(async {
                gateway_add(
                    "http://127.0.0.1:8080",
                    None,
                    None,
                    false,
                    None,
                    "openshell-cli",
                    None,
                    None,
                    false,
                )
                .await
                .expect("register plaintext gateway");
            });

            // Loopback endpoints derive the canonical "openshell" gateway
            // name, matching local cert generation and default_tls_dir conventions.
            let metadata = load_gateway_metadata("openshell").expect("load stored gateway");
            assert_eq!(metadata.auth_mode.as_deref(), Some("plaintext"));
            assert!(!metadata.is_remote);
            assert_eq!(metadata.gateway_endpoint, "http://127.0.0.1:8080");
            assert_eq!(load_active_gateway().as_deref(), Some("openshell"));
        });
    }

    #[test]
    fn gateway_add_respects_local_flag_for_plaintext_registrations() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        with_tmp_xdg(tmpdir.path(), || {
            let runtime = tokio::runtime::Runtime::new().expect("create runtime");
            runtime.block_on(async {
                gateway_add(
                    "http://gateway.example.com:8080",
                    Some("dev-http"),
                    None,
                    true,
                    None,
                    "openshell-cli",
                    None,
                    None,
                    false,
                )
                .await
                .expect("register plaintext gateway");
            });

            let metadata = load_gateway_metadata("dev-http").expect("load stored gateway");
            assert_eq!(metadata.auth_mode.as_deref(), Some("plaintext"));
            assert!(!metadata.is_remote);
            assert_eq!(metadata.gateway_endpoint, "http://gateway.example.com:8080");
            assert_eq!(load_active_gateway().as_deref(), Some("dev-http"));
        });
    }

    #[tokio::test]
    async fn http_health_check_supports_plain_http_endpoints() {
        let _ = rustls::crypto::ring::default_provider().install_default();
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
    #[test]
    fn format_endpoint_distinguishes_l4_from_l7_rest() {
        use openshell_core::proto::{L7Allow, L7DenyRule, L7Rule, NetworkEndpoint};

        let l4 = NetworkEndpoint {
            host: "host.example.test".to_string(),
            port: 443,
            ..Default::default()
        };
        assert_eq!(format_endpoint(&l4), "host.example.test:443 [L4]");

        let l7_readonly = NetworkEndpoint {
            host: "host.example.test".to_string(),
            port: 443,
            protocol: "rest".to_string(),
            access: "read-only".to_string(),
            ..Default::default()
        };
        assert_eq!(
            format_endpoint(&l7_readonly),
            "host.example.test:443 [L7 rest, access=read-only]"
        );

        let l7_scoped = NetworkEndpoint {
            host: "host.example.test".to_string(),
            port: 443,
            protocol: "rest".to_string(),
            rules: vec![L7Rule {
                allow: Some(L7Allow {
                    method: "PUT".to_string(),
                    path: "/v1/example/resource".to_string(),
                    ..Default::default()
                }),
            }],
            deny_rules: vec![L7DenyRule {
                method: "DELETE".to_string(),
                path: "/v1/example/resource".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            format_endpoint(&l7_scoped),
            "host.example.test:443 [L7 rest, allow PUT /v1/example/resource, deny DELETE /v1/example/resource]"
        );
    }

    #[test]
    fn read_gcloud_adc_missing_file_errors() {
        let _lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _guard = EnvVarGuard::set(
            "GOOGLE_APPLICATION_CREDENTIALS",
            "/nonexistent/path/to/adc.json",
        );
        let err = super::read_gcloud_adc().expect_err("missing file should error");
        assert!(
            err.to_string().contains("failed to read gcloud ADC file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn read_gcloud_adc_wrong_type_errors() {
        let _lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let json = serde_json::json!({
            "type": "service_account",
            "project_id": "my-project",
            "private_key_id": "key123"
        });
        Write::write_all(&mut tmp.as_file(), json.to_string().as_bytes()).expect("write tempfile");
        let _guard = EnvVarGuard::set(
            "GOOGLE_APPLICATION_CREDENTIALS",
            tmp.path().to_str().expect("tempfile path"),
        );
        let err = super::read_gcloud_adc().expect_err("wrong type should error");
        // The service_account type gets a targeted message directing the user
        // to the real Vertex service-account credential flow instead of the
        // generic authorized_user hint.
        assert!(
            err.to_string()
                .contains("GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN"),
            "error should mention the service-account token key, got: {err}"
        );
    }

    #[test]
    fn read_gcloud_adc_parses_user_creds() {
        let _lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let json = serde_json::json!({
            "type": "authorized_user",
            "client_id": "test-client-id.apps.googleusercontent.com",
            "client_secret": "test-client-secret",
            "refresh_token": "test-refresh-token"
        });
        Write::write_all(&mut tmp.as_file(), json.to_string().as_bytes()).expect("write tempfile");
        let _guard = EnvVarGuard::set(
            "GOOGLE_APPLICATION_CREDENTIALS",
            tmp.path().to_str().expect("tempfile path"),
        );
        let (client_id, client_secret, refresh_token) =
            super::read_gcloud_adc().expect("valid ADC should parse");
        assert_eq!(client_id, "test-client-id.apps.googleusercontent.com");
        assert_eq!(client_secret, "test-client-secret");
        assert_eq!(refresh_token, "test-refresh-token");
    }

    #[test]
    fn read_gcloud_adc_uses_cloudsdk_config_fallback() {
        let _lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("tempdir");
        let adc_path = dir.path().join("application_default_credentials.json");
        let json = serde_json::json!({
            "type": "authorized_user",
            "client_id": "cloudsdk-client-id.apps.googleusercontent.com",
            "client_secret": "cloudsdk-client-secret",
            "refresh_token": "cloudsdk-refresh-token"
        });
        fs::write(&adc_path, json.to_string()).expect("write adc file");
        let _adc_guard = EnvVarGuard::unset("GOOGLE_APPLICATION_CREDENTIALS");
        let _cloudsdk_guard =
            EnvVarGuard::set("CLOUDSDK_CONFIG", dir.path().to_str().expect("config path"));

        let (client_id, client_secret, refresh_token) =
            super::read_gcloud_adc().expect("valid CLOUDSDK_CONFIG ADC should parse");
        assert_eq!(client_id, "cloudsdk-client-id.apps.googleusercontent.com");
        assert_eq!(client_secret, "cloudsdk-client-secret");
        assert_eq!(refresh_token, "cloudsdk-refresh-token");
    }

    #[test]
    fn read_gcloud_adc_malformed_json_errors() {
        let _lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        Write::write_all(&mut tmp.as_file(), b"not valid json at all {{{{")
            .expect("write tempfile");
        let _guard = EnvVarGuard::set(
            "GOOGLE_APPLICATION_CREDENTIALS",
            tmp.path().to_str().expect("tempfile path"),
        );
        let result = super::read_gcloud_adc();
        assert!(
            result.is_err(),
            "malformed JSON should produce an error, got: {result:?}"
        );
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("parse")
                || msg.contains("JSON")
                || msg.contains("json")
                || msg.contains("invalid")
                || msg.contains("failed"),
            "error message should mention parse/JSON failure, got: {msg}"
        );
    }

    #[test]
    fn refresh_bootstrap_allows_oauth2_refresh_token() {
        use openshell_core::proto::{
            ProviderCredentialRefresh, ProviderCredentialRefreshStrategy, ProviderProfile,
            ProviderProfileCredential,
        };

        let strategy = ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32;
        let profile = ProviderProfile {
            credentials: vec![ProviderProfileCredential {
                required: true,
                refresh: Some(ProviderCredentialRefresh {
                    strategy,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            provider_profile_allows_refresh_bootstrap(&profile),
            "Oauth2RefreshToken should be allowed for refresh bootstrap"
        );
    }

    #[test]
    fn gateway_add_oidc_rolls_back_on_auth_failure() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        with_tmp_xdg(tmpdir.path(), || {
            let runtime = tokio::runtime::Runtime::new().expect("create runtime");

            // Register a working plaintext gateway first so we can verify
            // the active gateway is restored after rollback.
            runtime.block_on(async {
                gateway_add(
                    "http://127.0.0.1:9999",
                    Some("existing-gw"),
                    None,
                    false,
                    None,
                    "openshell-cli",
                    None,
                    None,
                    false,
                )
                .await
                .expect("register seed gateway");
            });
            assert_eq!(load_active_gateway().as_deref(), Some("existing-gw"));

            // Attempt OIDC gateway add against an unreachable issuer.
            // Auth will fail (connection refused), triggering rollback.
            runtime.block_on(async {
                gateway_add(
                    "https://gateway.example.com",
                    Some("oidc-fail"),
                    None,
                    false,
                    Some("http://127.0.0.1:1/realms/nonexistent"),
                    "openshell-cli",
                    None,
                    None,
                    false,
                )
                .await
                .expect("gateway_add should not return Err on auth failure");
            });

            // The failed registration should have been rolled back.
            assert!(
                load_gateway_metadata("oidc-fail").is_err(),
                "failed OIDC gateway should be removed after auth failure"
            );
            // The previously active gateway should be restored.
            assert_eq!(
                load_active_gateway().as_deref(),
                Some("existing-gw"),
                "active gateway should be restored after rollback"
            );
        });
    }

    #[test]
    fn gateway_add_cloud_rolls_back_on_auth_failure() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        with_tmp_xdg(tmpdir.path(), || {
            let runtime = tokio::runtime::Runtime::new().expect("create runtime");

            // Register a working plaintext gateway first.
            runtime.block_on(async {
                gateway_add(
                    "http://127.0.0.1:9999",
                    Some("existing-gw"),
                    None,
                    false,
                    None,
                    "openshell-cli",
                    None,
                    None,
                    false,
                )
                .await
                .expect("register seed gateway");
            });
            assert_eq!(load_active_gateway().as_deref(), Some("existing-gw"));

            // Attempt cloud gateway add. The browser flow will fail because
            // OPENSHELL_NO_BROWSER is NOT set but the /auth/connect endpoint
            // is unreachable (connection refused), so the 120s timeout would
            // kick in. To keep the test fast, set OPENSHELL_NO_BROWSER=0
            // (explicitly not suppressed) and use a port that refuses connections.
            // The CF auth flow will fail quickly on connection refused.
            runtime.block_on(async {
                gateway_add(
                    "https://127.0.0.1:1",
                    Some("cloud-fail"),
                    None,
                    false,
                    None,
                    "openshell-cli",
                    None,
                    None,
                    false,
                )
                .await
                .expect("gateway_add should not return Err on auth failure");
            });

            // The failed registration should have been rolled back.
            assert!(
                load_gateway_metadata("cloud-fail").is_err(),
                "failed cloud gateway should be removed after auth failure"
            );
            assert_eq!(
                load_active_gateway().as_deref(),
                Some("existing-gw"),
                "active gateway should be restored after rollback"
            );
        });
    }
}
