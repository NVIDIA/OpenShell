// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers, types, and parsing utilities used across CLI command groups.

use chrono::DateTime;
use dialoguer::{Confirm, theme::ColorfulTheme};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use miette::{IntoDiagnostic, Result};
use openshell_core::progress::{
    PROGRESS_ACTIVE_DETAIL_KEY, PROGRESS_ACTIVE_STEP_KEY, PROGRESS_COMPLETE_LABEL_KEY,
    PROGRESS_COMPLETE_STEP_KEY, PROGRESS_STEP_PULLING_IMAGE, PROGRESS_STEP_REQUESTING_SANDBOX,
    PROGRESS_STEP_STARTING_SANDBOX,
};
use openshell_core::proto::{
    PlatformEvent, SandboxPhase, SandboxPolicy, SettingValue, setting_value,
};
use openshell_core::settings::{self, SettingValueKind};
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::io::IsTerminal;
use std::process::Command;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// View types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyGetView {
    Metadata,
    Base,
    Full,
}

impl PolicyGetView {
    pub fn from_flags(base: bool, full: bool) -> Self {
        match (base, full) {
            (true, _) => Self::Base,
            (false, true) => Self::Full,
            (false, false) => Self::Metadata,
        }
    }

    pub(crate) fn includes_policy(self) -> bool {
        matches!(self, Self::Base | Self::Full)
    }
}

// ---------------------------------------------------------------------------
// Formatting / display helpers
// ---------------------------------------------------------------------------

/// Convert a sandbox phase integer to a human-readable string.
pub fn phase_name(phase: i32) -> &'static str {
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
pub fn format_epoch_ms(ms: i64) -> String {
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

pub fn format_optional_epoch_ms(ms: i64) -> String {
    if ms > 0 {
        format_epoch_ms(ms)
    } else {
        "-".to_string()
    }
}

/// Format a duration as a compact elapsed time string, e.g. `(3s)` or `(1m 12s)`.
pub fn format_elapsed(d: Duration) -> String {
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
pub fn format_timestamp(d: Duration) -> String {
    let secs = d.as_secs_f64();
    format!("[{secs:.1}s]")
}

/// Format a millisecond timestamp into a readable string.
pub fn format_timestamp_ms(ms: i64) -> String {
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

pub fn truncate_status_field(value: &str, max_chars: usize) -> String {
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

pub fn truncate_display(value: &str, max_width: usize) -> String {
    if value.chars().count() <= max_width {
        return value.to_string();
    }

    let keep = max_width.saturating_sub(3);
    let mut truncated = value.chars().take(keep).collect::<String>();
    truncated.push_str("...");
    truncated
}

pub fn short_hash(hash: &str) -> &str {
    if hash.len() >= 12 { &hash[..12] } else { hash }
}

pub fn non_empty_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}

pub fn format_setting_value(value: Option<&SettingValue>) -> String {
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

// ---------------------------------------------------------------------------
// YAML / policy display
// ---------------------------------------------------------------------------

pub fn print_yaml_line(line: &str) {
    let trimmed = line.trim_start();
    let indent = &line[..line.len() - trimmed.len()];

    if let Some(rest) = trimmed.strip_prefix("- ") {
        print!("{indent}");
        print!("{}", "- ".dimmed());
        print!("{rest}");
        println!();
        return;
    }

    if let Some(colon_pos) = trimmed.find(':') {
        let key = &trimmed[..colon_pos];
        let after_colon = &trimmed[colon_pos + 1..];

        print!("{indent}");
        print!("{}", key.dimmed());
        print!("{}", ":".dimmed());

        if after_colon.is_empty() {
            // Key with nested content (no value on this line)
        } else if let Some(value) = after_colon.strip_prefix(' ') {
            print!(" {value}");
        } else {
            print!("{after_colon}");
        }
        println!();
        return;
    }

    println!("{line}");
}

/// Print sandbox policy as YAML with dimmed keys.
pub fn print_sandbox_policy(policy: &SandboxPolicy) {
    println!("{}", "Policy:".cyan().bold());
    println!();
    if let Ok(yaml_str) = openshell_policy::serialize_sandbox_policy(policy) {
        for line in yaml_str.lines() {
            if line == "---" {
                continue;
            }
            print!("  ");
            print_yaml_line(line);
        }
    }
}

pub fn print_policy_merge_warnings(warnings: &[openshell_policy::PolicyMergeWarning]) {
    for warning in warnings {
        eprintln!("{} {}", "!".yellow().bold(), warning);
    }
}

// ---------------------------------------------------------------------------
// Provisioning display
// ---------------------------------------------------------------------------

/// Known provisioning steps derived from Kubernetes events and sandbox lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProvisioningStep {
    /// Sandbox CRD created, waiting for pod to be scheduled.
    RequestingSandbox,
    /// Pulling the sandbox container image.
    PullingSandboxImage,
    /// Container is starting up.
    StartingSandbox,
}

impl ProvisioningStep {
    /// Human-readable label for a completed step.
    pub fn completed_label(self) -> &'static str {
        match self {
            Self::RequestingSandbox => "Sandbox allocated",
            Self::PullingSandboxImage => "Image pulled",
            Self::StartingSandbox => "Sandbox ready",
        }
    }

    /// Human-readable label for an in-progress step (shown on the spinner).
    pub fn active_label(self) -> &'static str {
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
pub struct ProvisioningDisplay {
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
    pub fn new() -> Self {
        let mp = MultiProgress::new();

        let spinner = mp.add(ProgressBar::new_spinner());
        spinner.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg} ({elapsed})")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        spinner.enable_steady_tick(Duration::from_millis(120));

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
    pub fn complete_step_with_label(&mut self, step: ProvisioningStep, label: &str) {
        if self.completed_steps.contains(&step) {
            return;
        }
        self.completed_steps.push(step);

        let elapsed = self.step_start.elapsed();
        let elapsed_str = format_elapsed(elapsed);

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

        self.step_start = Instant::now();
        self.spinner.reset_elapsed();
        self.active_detail.clear();
    }

    /// Set the active (in-progress) step shown on the spinner.
    pub fn set_active(&mut self, label: &str) {
        self.active_label = label.to_string();
        self.active_detail.clear();
        self.spinner.reset_elapsed();
        self.step_start = Instant::now();
        self.update_spinner();
    }

    /// Set the active step from a known provisioning step enum.
    pub fn set_active_step(&mut self, step: ProvisioningStep) {
        self.set_active(step.active_label());
    }

    /// Set detail text shown alongside the active step (e.g. image name).
    pub fn set_active_detail(&mut self, detail: &str) {
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
    pub fn finish_error(&self, msg: &str) {
        let _ = self
            .mp
            .println(format!("{} {}", "\u{2717}".red().bold(), msg.red()));
        self.spinner.finish_and_clear();
    }

    /// Print a line above the progress bars (for static header content).
    pub fn println(&self, msg: &str) {
        let _ = self.mp.println(msg);
    }

    /// Clear all progress output (spinner, spacer, and completed step lines).
    pub fn clear(&self) {
        self.spacer.finish_and_clear();
        self.spinner.finish_and_clear();
        for bar in &self.completed_bars {
            bar.finish_and_clear();
        }
    }
}

// ---------------------------------------------------------------------------
// Provisioning progress event handling
// ---------------------------------------------------------------------------

pub fn progress_step_from_metadata(value: &str) -> Option<ProvisioningStep> {
    match value {
        PROGRESS_STEP_REQUESTING_SANDBOX => Some(ProvisioningStep::RequestingSandbox),
        PROGRESS_STEP_PULLING_IMAGE => Some(ProvisioningStep::PullingSandboxImage),
        PROGRESS_STEP_STARTING_SANDBOX => Some(ProvisioningStep::StartingSandbox),
        _ => None,
    }
}

pub fn noninteractive_active_label(step: ProvisioningStep) -> String {
    step.active_label().trim_end_matches('.').to_string()
}

pub fn handle_platform_progress_event(
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

pub fn is_provisioning_progress_event(event: &PlatformEvent) -> bool {
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

// ---------------------------------------------------------------------------
// Sandbox header
// ---------------------------------------------------------------------------

pub fn print_sandbox_header(
    sandbox: &openshell_core::proto::Sandbox,
    display: Option<&ProvisioningDisplay>,
) {
    use openshell_core::ObjectName;

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

// ---------------------------------------------------------------------------
// Sandbox provisioning helpers
// ---------------------------------------------------------------------------

pub fn ready_false_condition_message(
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

pub fn provisioning_timeout_message(
    timeout_secs: u64,
    resource_requirements: Option<&openshell_core::proto::ResourceRequirements>,
    condition_message: Option<&str>,
) -> String {
    let mut message = format!("sandbox provisioning timed out after {timeout_secs}s");

    if let Some(condition_message) = condition_message.filter(|msg| !msg.is_empty()) {
        message.push_str(". Last reported status: ");
        message.push_str(condition_message);
    }

    if resource_requirements.is_some_and(|requirements| requirements.gpu.is_some()) {
        message.push_str(
            ". Hint: this may be because the available GPU is already in use by another sandbox.",
        );
    }

    message
}

// ---------------------------------------------------------------------------
// Settings helpers
// ---------------------------------------------------------------------------

pub fn parse_cli_setting_value(key: &str, raw_value: &str) -> Result<SettingValue> {
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

pub fn confirm_global_setting_takeover(key: &str, yes: bool) -> Result<()> {
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

pub fn confirm_global_setting_delete(key: &str, yes: bool) -> Result<()> {
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

/// Parse a duration string like "5m", "1h", "30s" into milliseconds.
pub fn parse_duration_to_ms(s: &str) -> Result<i64> {
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

// ---------------------------------------------------------------------------
// Parsing utilities
// ---------------------------------------------------------------------------

pub fn parse_key_value_pairs(items: &[String], flag: &str) -> Result<HashMap<String, String>> {
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

pub fn parse_env_pairs(items: &[String]) -> Result<HashMap<String, String>> {
    let map = parse_key_value_pairs(items, "--env")?;
    for key in map.keys() {
        if !is_valid_env_name(key) {
            return Err(miette::miette!(
                "--env key must match [A-Za-z_][A-Za-z0-9_]*; got '{key}'"
            ));
        }
        if key.starts_with("OPENSHELL_") {
            return Err(miette::miette!(
                "--env keys starting with OPENSHELL_ are reserved; got '{key}'"
            ));
        }
    }
    Ok(map)
}

/// Resolve `--secret-material-env KEY[=ENVVAR]` values from the CLI process
/// environment (`ENVVAR` defaults to `KEY`) so secrets never transit argv.
pub fn parse_secret_material_env_pairs(items: &[String]) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();

    for item in items {
        let (key, env_name) = match item.split_once('=') {
            Some((key, env_name)) => (key.trim(), env_name.trim()),
            None => (item.trim(), item.trim()),
        };
        if key.is_empty() {
            return Err(miette::miette!("--secret-material-env key cannot be empty"));
        }
        if env_name.is_empty() {
            return Err(miette::miette!(
                "--secret-material-env {key} names an empty environment variable"
            ));
        }

        let value = std::env::var(env_name).map_err(|_| {
            miette::miette!(
                "--secret-material-env {key} requires local env var '{env_name}' to be set to a non-empty value"
            )
        })?;
        if value.trim().is_empty() {
            return Err(miette::miette!(
                "--secret-material-env {key} requires local env var '{env_name}' to be set to a non-empty value"
            ));
        }

        if map.contains_key(key) {
            return Err(miette::miette!(
                "--secret-material-env key '{key}' supplied more than once"
            ));
        }
        map.insert(key.to_string(), value);
    }

    Ok(map)
}

pub fn is_valid_env_name(key: &str) -> bool {
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first == b'_' || first.is_ascii_alphabetic()) {
        return false;
    }
    bytes.all(|b| b == b'_' || b.is_ascii_alphanumeric())
}

pub fn parse_credential_pairs(items: &[String]) -> Result<HashMap<String, String>> {
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

pub fn parse_credential_expiry_value(value: &str, key: Option<&str>) -> Result<i64> {
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

pub fn parse_credential_expiry_pairs(items: &[String]) -> Result<HashMap<String, i64>> {
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

// ---------------------------------------------------------------------------
// Git environment helpers
// ---------------------------------------------------------------------------

pub fn scrub_git_env(command: &mut Command) -> &mut Command {
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
