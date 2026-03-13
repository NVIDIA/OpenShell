// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use openshell_core::proto::open_shell_client::OpenShellClient;
use tonic::transport::Channel;

// ---------------------------------------------------------------------------
// Screens & focus
// ---------------------------------------------------------------------------

/// Top-level screen (each is a full-screen layout with its own nav bar).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Splash / boot screen shown on startup.
    Splash,
    /// Cluster list + provider list + sandbox table.
    Dashboard,
    /// Single-sandbox view (detail + logs).
    Sandbox,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Command,
}

/// Which panel is focused within the current screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    // Dashboard screen
    Gateways,
    Providers,
    Sandboxes,
    // Sandbox screen — metadata pane is always visible (non-interactive);
    // the focused pane is always the bottom one (policy or logs).
    SandboxPolicy,
    SandboxLogs,
    SandboxDraft,
}

// ---------------------------------------------------------------------------
// Log data model
// ---------------------------------------------------------------------------

/// Structured log line stored from the server.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub timestamp_ms: i64,
    pub level: String,
    pub source: String, // "gateway" or "sandbox"
    pub target: String,
    pub message: String,
    pub fields: HashMap<String, String>,
}

/// Which log sources to display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSourceFilter {
    All,
    Gateway,
    Sandbox,
}

impl LogSourceFilter {
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Gateway,
            Self::Gateway => Self::Sandbox,
            Self::Sandbox => Self::All,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Gateway => "gateway",
            Self::Sandbox => "sandbox",
        }
    }
}

// ---------------------------------------------------------------------------
// Gateway entry
// ---------------------------------------------------------------------------

pub struct GatewayEntry {
    pub name: String,
    pub endpoint: String,
    pub is_remote: bool,
}

// ---------------------------------------------------------------------------
// Create sandbox form (simplified — providers chosen by name)
// ---------------------------------------------------------------------------

/// Data extracted from the create sandbox form:
/// `(name, image, command, selected_provider_names, forward_ports)`.
pub type CreateFormData = (String, String, String, Vec<String>, Vec<u16>);

/// Which field is focused in the create sandbox modal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateFormField {
    Name,
    Image,
    Command,
    Providers,
    Ports,
    Submit,
}

impl CreateFormField {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Image,
            Self::Image => Self::Command,
            Self::Command => Self::Providers,
            Self::Providers => Self::Ports,
            Self::Ports => Self::Submit,
            Self::Submit => Self::Name,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Name => Self::Submit,
            Self::Image => Self::Name,
            Self::Command => Self::Image,
            Self::Providers => Self::Command,
            Self::Ports => Self::Providers,
            Self::Submit => Self::Ports,
        }
    }
}

/// An existing provider entry for sandbox creation (select by name).
#[derive(Debug, Clone)]
pub struct ProviderEntry {
    pub name: String,
    pub provider_type: String,
    pub selected: bool,
}

/// Tracks which phase the create sandbox modal is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreatePhase {
    /// Filling out the form.
    Form,
    /// Creating the sandbox (background task running).
    Creating,
}

/// Minimum time to show the Creating phase before closing.
pub const MIN_CREATING_DISPLAY: Duration = Duration::from_secs(4);

/// State for the create sandbox modal form.
pub struct CreateSandboxForm {
    pub focused_field: CreateFormField,
    pub name: String,
    pub image: String,
    pub command: String,
    pub providers: Vec<ProviderEntry>,
    pub provider_cursor: usize,
    /// Comma-separated port numbers to forward (e.g. "8080,3000").
    pub ports: String,
    /// Status message shown after submit attempt.
    pub status: Option<String>,
    /// Current phase of the create flow.
    pub phase: CreatePhase,
    /// When the create animation started (for pacman timing).
    pub anim_start: Option<Instant>,
    /// Buffered create result — held until min display time elapses.
    pub create_result: Option<Result<String, String>>,
}

// ---------------------------------------------------------------------------
// Create provider form
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateProviderPhase {
    /// Pick provider type from the known list.
    SelectType,
    /// Choose: autodetect from env or enter key manually.
    ChooseMethod,
    /// Enter key manually (BYO or autodetect fallback).
    EnterKey,
    /// Creating provider on gateway (background task).
    Creating,
}

/// Which field is focused in the provider key entry form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKeyField {
    Name,
    /// Focused credential row for known types (index via `cred_cursor`).
    Credential,
    /// Custom env var name (generic / no-known-env-vars types only).
    EnvVarName,
    /// Custom env var value (generic / no-known-env-vars types only).
    GenericValue,
    Submit,
}

pub struct CreateProviderForm {
    pub phase: CreateProviderPhase,
    /// Known provider type slugs.
    pub types: Vec<String>,
    pub type_cursor: usize,
    /// 0 = autodetect, 1 = enter manually.
    pub method_cursor: usize,
    /// Provider name (pre-filled with auto-generated unique name).
    pub name: String,
    /// For known types: `(env_var_name, value)` pairs — all known env vars listed.
    pub credentials: Vec<(String, String)>,
    /// Which credential row is focused.
    pub cred_cursor: usize,
    /// For generic / types with no known env vars: custom env var name.
    pub generic_env_name: String,
    /// For generic / types with no known env vars: custom value.
    pub generic_value: String,
    /// Which field is focused in the key entry form.
    pub key_field: ProviderKeyField,
    /// True when the provider type has no known env vars (generic, outlook).
    pub is_generic: bool,
    /// Status message (errors, validation).
    pub status: Option<String>,
    /// Warning shown at top of EnterKey modal (e.g. autodetect failure).
    pub warning: Option<String>,
    /// Animation start time.
    pub anim_start: Option<Instant>,
    /// Buffered create result.
    pub create_result: Option<Result<String, String>>,
    /// Credentials to send (filled by autodetect or built from form fields on submit).
    pub discovered_credentials: Option<HashMap<String, String>>,
}

// ---------------------------------------------------------------------------
// Provider detail view (Get)
// ---------------------------------------------------------------------------

pub struct ProviderDetailView {
    pub name: String,
    pub provider_type: String,
    pub credential_key: String,
    pub masked_value: String,
}

// ---------------------------------------------------------------------------
// Update provider form
// ---------------------------------------------------------------------------

pub struct UpdateProviderForm {
    pub provider_name: String,
    pub provider_type: String,
    pub credential_key: String,
    pub new_value: String,
    pub status: Option<String>,
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[allow(clippy::struct_excessive_bools)]
pub struct App {
    pub running: bool,
    pub screen: Screen,
    pub input_mode: InputMode,
    pub focus: Focus,
    pub command_input: String,

    /// Active color theme (dark or light).
    pub theme: crate::theme::Theme,

    /// When the splash screen was shown (for auto-dismiss timing).
    pub splash_start: Option<Instant>,

    // Active gateway connection
    pub gateway_name: String,
    pub endpoint: String,
    pub client: OpenShellClient<Channel>,
    pub status_text: String,

    // Gateway list
    pub gateways: Vec<GatewayEntry>,
    pub gateway_selected: usize,
    pub pending_gateway_switch: Option<String>,

    // Provider list
    pub provider_names: Vec<String>,
    pub provider_types: Vec<String>,
    pub provider_cred_keys: Vec<String>,
    pub provider_selected: usize,
    pub provider_count: usize,

    // Provider CRUD
    pub create_provider_form: Option<CreateProviderForm>,
    pub provider_detail: Option<ProviderDetailView>,
    pub update_provider_form: Option<UpdateProviderForm>,
    pub confirm_provider_delete: bool,
    pub pending_provider_get: bool,
    pub pending_provider_delete: bool,
    pub pending_provider_create: bool,
    pub pending_provider_update: bool,

    // Sandbox list
    pub sandbox_ids: Vec<String>,
    pub sandbox_names: Vec<String>,
    pub sandbox_phases: Vec<String>,
    pub sandbox_ages: Vec<String>,
    pub sandbox_created: Vec<String>,
    pub sandbox_images: Vec<String>,
    pub sandbox_notes: Vec<String>,
    pub sandbox_policy_versions: Vec<u32>,
    pub sandbox_selected: usize,
    pub sandbox_count: usize,

    // Sandbox detail / actions
    pub confirm_delete: bool,
    pub pending_log_fetch: bool,
    pub pending_sandbox_delete: bool,
    pub pending_sandbox_detail: bool,
    pub pending_shell_connect: bool,

    // Sandbox policy viewer
    pub sandbox_policy: Option<openshell_core::proto::SandboxPolicy>,
    pub sandbox_providers_list: Vec<String>,
    pub policy_lines: Vec<ratatui::text::Line<'static>>,
    pub policy_scroll: usize,

    // Create sandbox modal
    pub create_form: Option<CreateSandboxForm>,
    pub pending_create_sandbox: bool,
    /// Ports to forward after sandbox creation completes.
    pub pending_forward_ports: Vec<u16>,
    /// Command to exec via SSH after sandbox creation completes.
    pub pending_exec_command: String,
    /// Animation ticker handle — aborted when animation stops.
    pub anim_handle: Option<tokio::task::JoinHandle<()>>,

    // Sandbox logs
    pub sandbox_log_lines: Vec<LogLine>,
    pub sandbox_log_scroll: usize,
    /// Cursor position relative to `sandbox_log_scroll` (0 = first visible line).
    pub log_cursor: usize,
    pub log_source_filter: LogSourceFilter,
    /// When true, new log lines auto-scroll to the bottom (k9s-style).
    pub log_autoscroll: bool,
    /// Visible line count in the log viewport (set by the draw pass).
    pub log_viewport_height: usize,
    /// When `Some(idx)`, a detail popup is shown for the filtered log line at this index.
    pub log_detail_index: Option<usize>,
    /// Anchor index (absolute in filtered list) for visual selection mode.
    /// When `Some`, the user is in visual-select mode (`v`).
    pub log_selection_anchor: Option<usize>,
    /// Handle for the streaming log task. Dropped to cancel.
    pub log_stream_handle: Option<tokio::task::JoinHandle<()>>,

    // Draft policy recommendations
    pub draft_chunks: Vec<openshell_core::proto::PolicyChunk>,
    pub draft_version: u64,
    pub draft_selected: usize,
    pub draft_scroll: usize,
    /// Visible line count in the draft viewport (set by the draw pass).
    pub draft_viewport_height: usize,
    /// When true, the detail popup is shown for the selected draft chunk.
    pub draft_detail_open: bool,

    /// Per-sandbox count of pending draft recommendations (parallel to `sandbox_names`).
    pub sandbox_draft_counts: Vec<usize>,

    // Draft action flags (checked in the main loop after key events).
    pub pending_draft_approve: bool,
    pub pending_draft_reject: bool,
    pub pending_draft_approve_all: bool,

    /// When true, the approve-all confirmation modal is shown.
    pub approve_all_confirm_open: bool,
    /// Snapshot of pending chunks captured when `[A]` was pressed.
    pub approve_all_confirm_chunks: Vec<openshell_core::proto::PolicyChunk>,
}

impl App {
    pub fn new(
        client: OpenShellClient<Channel>,
        gateway_name: String,
        endpoint: String,
        theme: crate::theme::Theme,
    ) -> Self {
        Self {
            running: true,
            screen: Screen::Splash,
            input_mode: InputMode::Normal,
            focus: Focus::Gateways,
            command_input: String::new(),
            theme,
            splash_start: Some(Instant::now()),
            gateway_name,
            endpoint,
            client,
            status_text: String::from("connecting..."),
            gateways: Vec::new(),
            gateway_selected: 0,
            pending_gateway_switch: None,
            provider_names: Vec::new(),
            provider_types: Vec::new(),
            provider_cred_keys: Vec::new(),
            provider_selected: 0,
            provider_count: 0,
            create_provider_form: None,
            provider_detail: None,
            update_provider_form: None,
            confirm_provider_delete: false,
            pending_provider_get: false,
            pending_provider_delete: false,
            pending_provider_create: false,
            pending_provider_update: false,
            sandbox_ids: Vec::new(),
            sandbox_names: Vec::new(),
            sandbox_phases: Vec::new(),
            sandbox_ages: Vec::new(),
            sandbox_created: Vec::new(),
            sandbox_images: Vec::new(),
            sandbox_notes: Vec::new(),
            sandbox_policy_versions: Vec::new(),
            sandbox_selected: 0,
            sandbox_count: 0,
            confirm_delete: false,
            pending_log_fetch: false,
            pending_sandbox_delete: false,
            pending_sandbox_detail: false,
            pending_shell_connect: false,
            sandbox_policy: None,
            sandbox_providers_list: Vec::new(),
            policy_lines: Vec::new(),
            policy_scroll: 0,
            create_form: None,
            pending_create_sandbox: false,
            pending_forward_ports: Vec::new(),
            pending_exec_command: String::new(),
            anim_handle: None,
            sandbox_log_lines: Vec::new(),
            sandbox_log_scroll: 0,
            log_cursor: 0,
            log_source_filter: LogSourceFilter::All,
            log_autoscroll: true,
            log_viewport_height: 0,
            log_detail_index: None,
            log_selection_anchor: None,
            log_stream_handle: None,
            draft_chunks: Vec::new(),
            draft_version: 0,
            draft_selected: 0,
            draft_scroll: 0,
            draft_viewport_height: 0,
            draft_detail_open: false,
            sandbox_draft_counts: Vec::new(),
            pending_draft_approve: false,
            pending_draft_reject: false,
            pending_draft_approve_all: false,
            approve_all_confirm_open: false,
            approve_all_confirm_chunks: Vec::new(),
        }
    }

    // ------------------------------------------------------------------
    // Filtered log helpers
    // ------------------------------------------------------------------

    /// Return log lines matching the current source filter.
    pub fn filtered_log_lines(&self) -> Vec<&LogLine> {
        self.sandbox_log_lines
            .iter()
            .filter(|l| match self.log_source_filter {
                LogSourceFilter::All => true,
                LogSourceFilter::Gateway => l.source == "gateway",
                LogSourceFilter::Sandbox => l.source == "sandbox",
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // Key handling
    // ------------------------------------------------------------------

    /// Dismiss the splash screen and transition to the dashboard.
    pub fn dismiss_splash(&mut self) {
        if self.screen == Screen::Splash {
            self.screen = Screen::Dashboard;
            self.splash_start = None;
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.running = false;
            return;
        }

        // Splash screen: any key dismisses.
        if self.screen == Screen::Splash {
            self.dismiss_splash();
            return;
        }

        // Modals intercept all keys when open.
        if self.create_form.is_some() {
            self.handle_create_form_key(key);
            return;
        }
        if self.create_provider_form.is_some() {
            self.handle_create_provider_key(key);
            return;
        }
        if self.provider_detail.is_some() {
            self.handle_provider_detail_key(key);
            return;
        }
        if self.update_provider_form.is_some() {
            self.handle_update_provider_key(key);
            return;
        }

        match self.input_mode {
            InputMode::Command => self.handle_command_key(key),
            InputMode::Normal => self.handle_normal_key(key),
        }
    }

    fn handle_normal_key(&mut self, key: KeyEvent) {
        match self.focus {
            Focus::Gateways => self.handle_gateways_key(key),
            Focus::Providers => self.handle_providers_key(key),
            Focus::Sandboxes => self.handle_sandboxes_key(key),
            Focus::SandboxPolicy => self.handle_policy_key(key),
            Focus::SandboxLogs => self.handle_logs_key(key),
            Focus::SandboxDraft => self.handle_draft_key(key),
        }
    }

    fn handle_gateways_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.running = false,
            KeyCode::Tab => self.focus = Focus::Providers,
            KeyCode::BackTab => self.focus = Focus::Sandboxes,
            KeyCode::Char(':') => {
                self.input_mode = InputMode::Command;
                self.command_input.clear();
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if !self.gateways.is_empty() {
                    self.gateway_selected =
                        (self.gateway_selected + 1).min(self.gateways.len() - 1);
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.gateway_selected = self.gateway_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if let Some(entry) = self.gateways.get(self.gateway_selected) {
                    if entry.name != self.gateway_name {
                        self.pending_gateway_switch = Some(entry.name.clone());
                    }
                    self.focus = Focus::Providers;
                }
            }
            _ => {}
        }
    }

    fn handle_providers_key(&mut self, key: KeyEvent) {
        if self.confirm_provider_delete {
            match key.code {
                KeyCode::Char('y') => {
                    self.confirm_provider_delete = false;
                    self.pending_provider_delete = true;
                }
                KeyCode::Esc | KeyCode::Char('n') => {
                    self.confirm_provider_delete = false;
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') => self.running = false,
            KeyCode::Tab => self.focus = Focus::Sandboxes,
            KeyCode::BackTab => self.focus = Focus::Gateways,
            KeyCode::Char(':') => {
                self.input_mode = InputMode::Command;
                self.command_input.clear();
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if self.provider_count > 0 {
                    self.provider_selected =
                        (self.provider_selected + 1).min(self.provider_count - 1);
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.provider_selected = self.provider_selected.saturating_sub(1);
            }
            KeyCode::Char('c') => {
                self.open_create_provider_form();
            }
            KeyCode::Enter => {
                // Fetch and show provider detail.
                if self.provider_count > 0 {
                    self.pending_provider_get = true;
                }
            }
            KeyCode::Char('u') => {
                // Open update form for the selected provider.
                if self.provider_count > 0 {
                    self.open_update_provider_form();
                }
            }
            KeyCode::Char('d') => {
                if self.provider_count > 0 {
                    self.confirm_provider_delete = true;
                }
            }
            _ => {}
        }
    }

    fn handle_sandboxes_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.running = false,
            KeyCode::Tab => self.focus = Focus::Gateways,
            KeyCode::BackTab => self.focus = Focus::Providers,
            KeyCode::Char(':') => {
                self.input_mode = InputMode::Command;
                self.command_input.clear();
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if self.sandbox_count > 0 {
                    self.sandbox_selected = (self.sandbox_selected + 1).min(self.sandbox_count - 1);
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.sandbox_selected = self.sandbox_selected.saturating_sub(1);
            }
            KeyCode::Char('c') => {
                self.open_create_form();
            }
            KeyCode::Enter => {
                if self.sandbox_count > 0 {
                    self.screen = Screen::Sandbox;
                    self.focus = Focus::SandboxPolicy;
                    self.confirm_delete = false;
                    self.pending_sandbox_detail = true;
                }
            }
            KeyCode::Esc => {
                self.focus = Focus::Providers;
            }
            _ => {}
        }
    }

    fn handle_policy_key(&mut self, key: KeyEvent) {
        if self.confirm_delete {
            match key.code {
                KeyCode::Char('y') => {
                    self.confirm_delete = false;
                    self.pending_sandbox_delete = true;
                }
                KeyCode::Esc | KeyCode::Char('n') => {
                    self.confirm_delete = false;
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Esc => {
                self.cancel_log_stream();
                self.draft_detail_open = false;
                self.screen = Screen::Dashboard;
                self.focus = Focus::Sandboxes;
            }
            KeyCode::Char('l') => {
                self.sandbox_log_lines.clear();
                self.sandbox_log_scroll = 0;
                self.log_cursor = 0;
                self.log_source_filter = LogSourceFilter::All;
                self.log_autoscroll = true;
                self.log_detail_index = None;
                self.focus = Focus::SandboxLogs;
                self.pending_log_fetch = true;
            }
            KeyCode::Char('r') => {
                self.focus = Focus::SandboxDraft;
            }
            KeyCode::Char('s') => {
                if self.sandbox_count > 0 {
                    self.pending_shell_connect = true;
                }
            }
            KeyCode::Char('d') => {
                self.confirm_delete = true;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.scroll_policy(1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.scroll_policy(-1);
            }
            KeyCode::Char('G') => {
                // Scroll to bottom.
                self.policy_scroll = self.policy_lines.len().saturating_sub(1);
            }
            KeyCode::Char('g') => {
                self.policy_scroll = 0;
            }
            KeyCode::Char('q') => self.running = false,
            _ => {}
        }
    }

    fn handle_draft_key(&mut self, key: KeyEvent) {
        // Approve-all confirmation modal intercepts all keys when open.
        if self.approve_all_confirm_open {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    self.pending_draft_approve_all = true;
                    self.approve_all_confirm_open = false;
                    // Don't clear chunks here — the event loop takes them
                    // via std::mem::take when it processes the flag.
                }
                KeyCode::Esc | KeyCode::Char('n') => {
                    self.approve_all_confirm_open = false;
                    self.approve_all_confirm_chunks.clear();
                }
                _ => {}
            }
            return;
        }

        // Detail popup intercepts most keys when open.
        if self.draft_detail_open {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.draft_detail_open = false;
                }
                // Allow approve/reject toggle from within the popup.
                KeyCode::Char('a') => {
                    let abs = self.draft_scroll + self.draft_selected;
                    if abs < self.draft_chunks.len() {
                        let st = self.draft_chunks[abs].status.as_str();
                        if st == "pending" || st == "rejected" {
                            self.pending_draft_approve = true;
                            self.draft_detail_open = false;
                        }
                    }
                }
                KeyCode::Char('x') => {
                    let abs = self.draft_scroll + self.draft_selected;
                    if abs < self.draft_chunks.len() {
                        let st = self.draft_chunks[abs].status.as_str();
                        if st == "pending" || st == "approved" {
                            self.pending_draft_reject = true;
                            self.draft_detail_open = false;
                        }
                    }
                }
                _ => {}
            }
            return;
        }

        let total = self.draft_chunks.len();
        let vh = self.draft_viewport_height;

        match key.code {
            KeyCode::Esc | KeyCode::Char('p') => {
                // Back to policy view.
                self.focus = Focus::SandboxPolicy;
            }
            KeyCode::Char('l') => {
                self.sandbox_log_lines.clear();
                self.sandbox_log_scroll = 0;
                self.log_cursor = 0;
                self.log_source_filter = LogSourceFilter::All;
                self.log_autoscroll = true;
                self.log_detail_index = None;
                self.focus = Focus::SandboxLogs;
                self.pending_log_fetch = true;
            }
            KeyCode::Enter => {
                if !self.draft_chunks.is_empty() {
                    self.draft_detail_open = true;
                }
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if total == 0 {
                    return;
                }
                let visible = total.saturating_sub(self.draft_scroll).min(vh);
                let max_cursor = visible.saturating_sub(1);
                if self.draft_selected < max_cursor {
                    self.draft_selected += 1;
                } else {
                    let max_scroll = total.saturating_sub(vh.min(total));
                    if self.draft_scroll < max_scroll {
                        self.draft_scroll += 1;
                    }
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if self.draft_selected > 0 {
                    self.draft_selected -= 1;
                } else if self.draft_scroll > 0 {
                    self.draft_scroll -= 1;
                }
            }
            KeyCode::Char('g') => {
                self.draft_scroll = 0;
                self.draft_selected = 0;
            }
            KeyCode::Char('G') => {
                if total > 0 {
                    let max_scroll = total.saturating_sub(vh.min(total));
                    self.draft_scroll = max_scroll;
                    let visible = total.saturating_sub(self.draft_scroll).min(vh);
                    self.draft_selected = visible.saturating_sub(1);
                }
            }
            // Approve selected chunk (pending → approved, rejected → approved).
            KeyCode::Char('a') => {
                if !self.draft_chunks.is_empty() {
                    let abs = self.draft_scroll + self.draft_selected;
                    if abs < total {
                        let st = self.draft_chunks[abs].status.as_str();
                        if st == "pending" || st == "rejected" {
                            self.pending_draft_approve = true;
                        }
                    }
                }
            }
            // Reject selected chunk (pending → rejected, approved → rejected).
            KeyCode::Char('x') => {
                if !self.draft_chunks.is_empty() {
                    let abs = self.draft_scroll + self.draft_selected;
                    if abs < total {
                        let st = self.draft_chunks[abs].status.as_str();
                        if st == "pending" || st == "approved" {
                            self.pending_draft_reject = true;
                        }
                    }
                }
            }
            // Approve all pending chunks — show confirmation modal.
            KeyCode::Char('A') => {
                let pending: Vec<_> = self
                    .draft_chunks
                    .iter()
                    .filter(|c| c.status == "pending")
                    .cloned()
                    .collect();
                if !pending.is_empty() {
                    self.approve_all_confirm_chunks = pending;
                    self.approve_all_confirm_open = true;
                }
            }
            KeyCode::Char('q') => self.running = false,
            _ => {}
        }
    }

    /// Scroll policy pane by a delta (positive = down, negative = up).
    pub fn scroll_policy(&mut self, delta: isize) {
        let max = self.policy_lines.len().saturating_sub(1);
        if delta < 0 {
            self.policy_scroll = self.policy_scroll.saturating_sub(delta.unsigned_abs());
        } else {
            #[allow(clippy::cast_sign_loss)]
            {
                self.policy_scroll = (self.policy_scroll + delta as usize).min(max);
            }
        }
    }

    fn handle_logs_key(&mut self, key: KeyEvent) {
        if self.log_detail_index.is_some() {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.log_detail_index = None;
                }
                _ => {}
            }
            return;
        }

        let filtered_len = self.filtered_log_lines().len();
        let vh = self.log_viewport_height;

        match key.code {
            KeyCode::Esc => {
                if self.log_selection_anchor.is_some() {
                    // Cancel visual selection, stay in log viewer.
                    self.log_selection_anchor = None;
                } else {
                    self.cancel_log_stream();
                    self.log_selection_anchor = None;
                    self.focus = Focus::SandboxPolicy;
                }
            }
            KeyCode::Char('q') => self.running = false,
            KeyCode::Char('y') => {
                if filtered_len == 0 {
                    return;
                }
                let filtered = self.filtered_log_lines();
                if let Some(anchor) = self.log_selection_anchor {
                    // Visual mode: yank selected range.
                    let cursor_abs = self.sandbox_log_scroll + self.log_cursor;
                    let start = anchor.min(cursor_abs);
                    let end = anchor.max(cursor_abs);
                    let text: String = filtered[start..=end.min(filtered.len() - 1)]
                        .iter()
                        .map(|l| crate::ui::sandbox_logs::format_log_line_plain(l))
                        .collect::<Vec<_>>()
                        .join("\n");
                    crate::clipboard::copy_to_clipboard(&text);
                    self.log_selection_anchor = None;
                } else {
                    // Normal mode: yank current line.
                    let abs = self.sandbox_log_scroll + self.log_cursor;
                    if let Some(log) = filtered.get(abs) {
                        let text = crate::ui::sandbox_logs::format_log_line_plain(log);
                        crate::clipboard::copy_to_clipboard(&text);
                    }
                }
            }
            KeyCode::Char('Y') => {
                // Yank all visible lines in the viewport.
                if filtered_len == 0 {
                    return;
                }
                let filtered = self.filtered_log_lines();
                let start = self.sandbox_log_scroll;
                let end = (start + vh).min(filtered.len());
                let text: String = filtered[start..end]
                    .iter()
                    .map(|l| crate::ui::sandbox_logs::format_log_line_plain(l))
                    .collect::<Vec<_>>()
                    .join("\n");
                crate::clipboard::copy_to_clipboard(&text);
            }
            KeyCode::Char('v') => {
                // Toggle visual selection mode.
                if self.log_selection_anchor.is_some() {
                    self.log_selection_anchor = None;
                } else {
                    let abs = self.sandbox_log_scroll + self.log_cursor;
                    self.log_selection_anchor = Some(abs);
                    self.log_autoscroll = false;
                }
            }
            KeyCode::Enter => {
                if filtered_len > 0 && self.log_selection_anchor.is_none() {
                    let abs = self.sandbox_log_scroll + self.log_cursor;
                    if abs < filtered_len {
                        self.log_detail_index = Some(abs);
                    }
                }
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if filtered_len == 0 {
                    return;
                }
                let visible = filtered_len.saturating_sub(self.sandbox_log_scroll).min(vh);
                let max_cursor = visible.saturating_sub(1);
                if self.log_cursor < max_cursor {
                    self.log_cursor += 1;
                } else {
                    let max_scroll = filtered_len.saturating_sub(vh.min(filtered_len));
                    if self.sandbox_log_scroll < max_scroll {
                        self.sandbox_log_scroll += 1;
                    }
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if self.log_cursor > 0 {
                    self.log_cursor -= 1;
                } else if self.sandbox_log_scroll > 0 {
                    self.sandbox_log_scroll -= 1;
                }
                self.log_autoscroll = false;
            }
            KeyCode::Char('G' | 'f') => {
                self.log_selection_anchor = None;
                self.sandbox_log_scroll = self.log_autoscroll_offset();
                self.log_autoscroll = true;
                let visible = filtered_len.saturating_sub(self.sandbox_log_scroll);
                self.log_cursor = visible.saturating_sub(1).min(vh.saturating_sub(1));
            }
            KeyCode::Char('g') => {
                self.sandbox_log_scroll = 0;
                self.log_cursor = 0;
                self.log_autoscroll = false;
            }
            KeyCode::Char('s') => {
                self.log_source_filter = self.log_source_filter.next();
                self.log_selection_anchor = None;
                self.sandbox_log_scroll = 0;
                self.log_cursor = 0;
            }
            KeyCode::Char('r') => {
                self.log_selection_anchor = None;
                self.focus = Focus::SandboxDraft;
            }
            KeyCode::Char('p') => {
                self.log_selection_anchor = None;
                self.focus = Focus::SandboxPolicy;
            }
            _ => {}
        }
    }

    /// Scroll logs by a delta (positive = down, negative = up).
    pub fn scroll_logs(&mut self, delta: isize) {
        let filtered_len = self.filtered_log_lines().len();
        let max_scroll = self.log_autoscroll_offset();
        if delta < 0 {
            self.sandbox_log_scroll = self.sandbox_log_scroll.saturating_sub(delta.unsigned_abs());
            self.log_autoscroll = false;
        } else {
            self.sandbox_log_scroll = (self.sandbox_log_scroll + delta as usize).min(max_scroll);
        }
        let visible = filtered_len
            .saturating_sub(self.sandbox_log_scroll)
            .min(self.log_viewport_height);
        if visible > 0 {
            self.log_cursor = self.log_cursor.min(visible - 1);
        } else {
            self.log_cursor = 0;
        }
    }

    // ------------------------------------------------------------------
    // Create sandbox modal (simplified — pick existing providers by name)
    // ------------------------------------------------------------------

    fn open_create_form(&mut self) {
        let providers: Vec<ProviderEntry> = self
            .provider_names
            .iter()
            .zip(self.provider_types.iter())
            .map(|(name, ptype)| ProviderEntry {
                name: name.clone(),
                provider_type: ptype.clone(),
                selected: false,
            })
            .collect();

        self.create_form = Some(CreateSandboxForm {
            focused_field: CreateFormField::Name,
            name: String::new(),
            image: String::new(),
            command: String::new(),
            providers,
            provider_cursor: 0,
            ports: String::new(),
            status: None,
            phase: CreatePhase::Form,
            anim_start: None,
            create_result: None,
        });
    }

    fn handle_create_form_key(&mut self, key: KeyEvent) {
        let Some(form) = self.create_form.as_mut() else {
            return;
        };

        match form.phase {
            CreatePhase::Creating => {} // no input during creation

            CreatePhase::Form => match key.code {
                KeyCode::Esc => {
                    self.create_form = None;
                }
                KeyCode::Tab => {
                    form.status = None;
                    form.focused_field = form.focused_field.next();
                }
                KeyCode::BackTab => {
                    form.status = None;
                    form.focused_field = form.focused_field.prev();
                }
                _ => match form.focused_field {
                    CreateFormField::Name => Self::handle_text_input(&mut form.name, key),
                    CreateFormField::Image => Self::handle_text_input(&mut form.image, key),
                    CreateFormField::Command => Self::handle_text_input(&mut form.command, key),
                    CreateFormField::Providers => match key.code {
                        KeyCode::Char('j') | KeyCode::Down => {
                            if !form.providers.is_empty() {
                                form.provider_cursor =
                                    (form.provider_cursor + 1).min(form.providers.len() - 1);
                            }
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            form.provider_cursor = form.provider_cursor.saturating_sub(1);
                        }
                        KeyCode::Char(' ') | KeyCode::Enter => {
                            if let Some(p) = form.providers.get_mut(form.provider_cursor) {
                                p.selected = !p.selected;
                            }
                        }
                        _ => {}
                    },
                    CreateFormField::Ports => {
                        // Use the same text input handler as Name/Image/Command,
                        // then strip anything that isn't a digit or comma.
                        Self::handle_text_input(&mut form.ports, key);
                        form.ports.retain(|c| c.is_ascii_digit() || c == ',');
                    }
                    CreateFormField::Submit => {
                        if key.code == KeyCode::Enter {
                            form.anim_start = Some(Instant::now());
                            form.status = None;
                            form.phase = CreatePhase::Creating;
                            self.pending_create_sandbox = true;
                        }
                    }
                },
            },
        }
    }

    /// Build the form data needed for the gRPC `CreateSandbox` request.
    /// Returns `(name, image, command, selected_provider_names, forward_ports)`.
    pub fn create_form_data(&self) -> Option<CreateFormData> {
        let form = self.create_form.as_ref()?;
        let providers: Vec<String> = form
            .providers
            .iter()
            .filter(|p| p.selected)
            .map(|p| p.name.clone())
            .collect();
        let ports: Vec<u16> = form
            .ports
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .filter(|&p| p > 0)
            .collect();
        Some((
            form.name.clone(),
            form.image.clone(),
            form.command.clone(),
            providers,
            ports,
        ))
    }

    // ------------------------------------------------------------------
    // Create provider modal
    // ------------------------------------------------------------------

    fn open_create_provider_form(&mut self) {
        let known = openshell_providers::ProviderRegistry::new().known_types();
        let types: Vec<String> = known.into_iter().map(String::from).collect();

        self.create_provider_form = Some(CreateProviderForm {
            phase: CreateProviderPhase::SelectType,
            types,
            type_cursor: 0,
            method_cursor: 0,
            name: String::new(),
            credentials: Vec::new(),
            cred_cursor: 0,
            generic_env_name: String::new(),
            generic_value: String::new(),
            key_field: ProviderKeyField::Name,
            is_generic: false,
            status: None,
            warning: None,
            anim_start: None,
            create_result: None,
            discovered_credentials: None,
        });
    }

    fn handle_create_provider_key(&mut self, key: KeyEvent) {
        let Some(form) = self.create_provider_form.as_mut() else {
            return;
        };

        match form.phase {
            CreateProviderPhase::SelectType => match key.code {
                KeyCode::Esc => {
                    self.create_provider_form = None;
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    if !form.types.is_empty() {
                        form.type_cursor = (form.type_cursor + 1).min(form.types.len() - 1);
                    }
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    form.type_cursor = form.type_cursor.saturating_sub(1);
                }
                KeyCode::Enter => {
                    let selected = form.types[form.type_cursor].clone();
                    let registry = openshell_providers::ProviderRegistry::new();
                    let env_vars = registry.credential_env_vars(&selected);
                    form.is_generic = env_vars.is_empty();

                    // Populate credential rows from all known env vars.
                    form.credentials = env_vars
                        .iter()
                        .map(|s| (s.to_string(), String::new()))
                        .collect();
                    form.cred_cursor = 0;

                    // Auto-generate a unique name.
                    form.name = unique_provider_name(&selected, &self.provider_names);

                    if form.is_generic {
                        // No known env vars — skip straight to manual entry.
                        form.phase = CreateProviderPhase::EnterKey;
                        form.key_field = ProviderKeyField::Name;
                        form.status = None;
                        form.warning = None;
                    } else {
                        form.phase = CreateProviderPhase::ChooseMethod;
                        form.method_cursor = 0;
                    }
                }
                _ => {}
            },

            CreateProviderPhase::ChooseMethod => match key.code {
                KeyCode::Esc => {
                    form.phase = CreateProviderPhase::SelectType;
                    form.status = None;
                    form.warning = None;
                }
                KeyCode::Char('j') | KeyCode::Down | KeyCode::Char('k') | KeyCode::Up => {
                    form.method_cursor = 1 - form.method_cursor;
                }
                KeyCode::Enter => {
                    let ptype = form.types[form.type_cursor].clone();
                    if form.method_cursor == 0 {
                        // Autodetect — synchronous since we only check env vars now.
                        let registry = openshell_providers::ProviderRegistry::new();
                        if let Ok(Some(discovered)) = registry.discover_existing(&ptype) {
                            form.discovered_credentials = Some(discovered.credentials);
                            if form.name.is_empty() {
                                form.name = unique_provider_name(&ptype, &self.provider_names);
                            }
                            form.phase = CreateProviderPhase::Creating;
                            form.anim_start = Some(Instant::now());
                            self.pending_provider_create = true;
                        } else {
                            // Autodetect failed — fall to manual with warning.
                            form.phase = CreateProviderPhase::EnterKey;
                            form.key_field = ProviderKeyField::Name;
                            form.warning = Some(
                                "No credentials found in environment. Enter manually.".to_string(),
                            );
                            form.status = None;
                        }
                    } else {
                        // Manual entry.
                        form.phase = CreateProviderPhase::EnterKey;
                        form.key_field = ProviderKeyField::Name;
                        form.warning = None;
                        form.status = None;
                    }
                }
                _ => {}
            },

            CreateProviderPhase::EnterKey => match key.code {
                KeyCode::Esc => {
                    form.phase = CreateProviderPhase::SelectType;
                    form.status = None;
                    form.warning = None;
                    form.name.clear();
                    form.credentials.clear();
                    form.cred_cursor = 0;
                    form.generic_env_name.clear();
                    form.generic_value.clear();
                }
                KeyCode::Tab => {
                    if form.is_generic {
                        // Name → EnvVarName → GenericValue → Submit → Name
                        form.key_field = match form.key_field {
                            ProviderKeyField::Name => ProviderKeyField::EnvVarName,
                            ProviderKeyField::EnvVarName => ProviderKeyField::GenericValue,
                            ProviderKeyField::GenericValue => ProviderKeyField::Submit,
                            _ => ProviderKeyField::Name,
                        };
                    } else {
                        // Name → Credential[0..N-1] → Submit → Name
                        match form.key_field {
                            ProviderKeyField::Name => {
                                if form.credentials.is_empty() {
                                    form.key_field = ProviderKeyField::Submit;
                                } else {
                                    form.key_field = ProviderKeyField::Credential;
                                    form.cred_cursor = 0;
                                }
                            }
                            ProviderKeyField::Credential => {
                                if form.cred_cursor < form.credentials.len().saturating_sub(1) {
                                    form.cred_cursor += 1;
                                } else {
                                    form.key_field = ProviderKeyField::Submit;
                                }
                            }
                            _ => {
                                form.key_field = ProviderKeyField::Name;
                            }
                        }
                    }
                }
                KeyCode::BackTab => {
                    if form.is_generic {
                        form.key_field = match form.key_field {
                            ProviderKeyField::EnvVarName => ProviderKeyField::Name,
                            ProviderKeyField::GenericValue => ProviderKeyField::EnvVarName,
                            ProviderKeyField::Submit => ProviderKeyField::GenericValue,
                            _ => ProviderKeyField::Submit,
                        };
                    } else {
                        match form.key_field {
                            ProviderKeyField::Credential => {
                                if form.cred_cursor > 0 {
                                    form.cred_cursor -= 1;
                                } else {
                                    form.key_field = ProviderKeyField::Name;
                                }
                            }
                            ProviderKeyField::Submit => {
                                if form.credentials.is_empty() {
                                    form.key_field = ProviderKeyField::Name;
                                } else {
                                    form.key_field = ProviderKeyField::Credential;
                                    form.cred_cursor = form.credentials.len().saturating_sub(1);
                                }
                            }
                            _ => {
                                form.key_field = ProviderKeyField::Submit;
                            }
                        }
                    }
                }
                _ => match form.key_field {
                    ProviderKeyField::Name => Self::handle_text_input(&mut form.name, key),
                    ProviderKeyField::Credential => {
                        if let Some((_, value)) = form.credentials.get_mut(form.cred_cursor) {
                            Self::handle_text_input(value, key);
                        }
                    }
                    ProviderKeyField::EnvVarName => {
                        Self::handle_text_input(&mut form.generic_env_name, key);
                    }
                    ProviderKeyField::GenericValue => {
                        Self::handle_text_input(&mut form.generic_value, key);
                    }
                    ProviderKeyField::Submit => {
                        if key.code == KeyCode::Enter {
                            // Validate and build credentials map.
                            let mut creds = HashMap::new();
                            if form.is_generic {
                                if form.generic_env_name.is_empty() {
                                    form.status = Some("Env var name is required.".to_string());
                                    return;
                                }
                                if form.generic_value.is_empty() {
                                    form.status = Some("Value is required.".to_string());
                                    return;
                                }
                                creds.insert(
                                    form.generic_env_name.clone(),
                                    form.generic_value.clone(),
                                );
                            } else {
                                for (name, value) in &form.credentials {
                                    if !value.is_empty() {
                                        creds.insert(name.clone(), value.clone());
                                    }
                                }
                                if creds.is_empty() {
                                    form.status =
                                        Some("At least one credential is required.".to_string());
                                    return;
                                }
                            }
                            form.discovered_credentials = Some(creds);
                            form.phase = CreateProviderPhase::Creating;
                            form.anim_start = Some(Instant::now());
                            form.status = None;
                            self.pending_provider_create = true;
                        }
                    }
                },
            },

            CreateProviderPhase::Creating => {} // no input during creation
        }
    }

    // ------------------------------------------------------------------
    // Provider detail (Get) modal
    // ------------------------------------------------------------------

    fn handle_provider_detail_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                self.provider_detail = None;
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // Update provider modal
    // ------------------------------------------------------------------

    fn open_update_provider_form(&mut self) {
        let name = match self.provider_names.get(self.provider_selected) {
            Some(n) => n.clone(),
            None => return,
        };
        let ptype = self
            .provider_types
            .get(self.provider_selected)
            .cloned()
            .unwrap_or_default();
        let cred_key = self
            .provider_cred_keys
            .get(self.provider_selected)
            .cloned()
            .unwrap_or_default();

        // If we don't know the credential key, derive from registry.
        let key = if cred_key.is_empty() {
            let registry = openshell_providers::ProviderRegistry::new();
            registry
                .credential_env_vars(&ptype)
                .first()
                .map_or(String::new(), |s| s.to_string())
        } else {
            cred_key
        };

        self.update_provider_form = Some(UpdateProviderForm {
            provider_name: name,
            provider_type: ptype,
            credential_key: key,
            new_value: String::new(),
            status: None,
        });
    }

    fn handle_update_provider_key(&mut self, key: KeyEvent) {
        let Some(form) = self.update_provider_form.as_mut() else {
            return;
        };

        match key.code {
            KeyCode::Esc => {
                self.update_provider_form = None;
            }
            KeyCode::Enter => {
                if form.new_value.is_empty() {
                    form.status = Some("Value is required.".to_string());
                    return;
                }
                self.pending_provider_update = true;
            }
            KeyCode::Char(c) => form.new_value.push(c),
            KeyCode::Backspace => {
                form.new_value.pop();
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // Shared helpers
    // ------------------------------------------------------------------

    fn handle_text_input(field: &mut String, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => field.push(c),
            KeyCode::Backspace => {
                field.pop();
            }
            _ => {}
        }
    }

    fn handle_command_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.input_mode = InputMode::Normal;
                self.command_input.clear();
            }
            KeyCode::Enter => {
                self.execute_command();
                self.input_mode = InputMode::Normal;
                self.command_input.clear();
            }
            KeyCode::Char(c) => self.command_input.push(c),
            KeyCode::Backspace => {
                self.command_input.pop();
            }
            _ => {}
        }
    }

    fn execute_command(&mut self) {
        let cmd = self.command_input.trim();
        match cmd {
            "q" | "quit" => self.running = false,
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// Get the ID of the currently selected sandbox.
    pub fn selected_sandbox_id(&self) -> Option<&str> {
        self.sandbox_ids
            .get(self.sandbox_selected)
            .map(String::as_str)
    }

    /// Get the name of the currently selected sandbox.
    pub fn selected_sandbox_name(&self) -> Option<&str> {
        self.sandbox_names
            .get(self.sandbox_selected)
            .map(String::as_str)
    }

    /// Get the name of the currently selected provider.
    pub fn selected_provider_name(&self) -> Option<&str> {
        self.provider_names
            .get(self.provider_selected)
            .map(String::as_str)
    }

    pub fn log_autoscroll_offset(&self) -> usize {
        const BOTTOM_PAD: usize = 3;
        let filtered_len = self.filtered_log_lines().len();
        let vh = self.log_viewport_height;
        if vh == 0 || filtered_len == 0 {
            return 0;
        }
        let usable = vh.saturating_sub(BOTTOM_PAD);
        filtered_len.saturating_sub(usable)
    }

    /// Cancel any running log stream task.
    pub fn cancel_log_stream(&mut self) {
        if let Some(handle) = self.log_stream_handle.take() {
            handle.abort();
        }
    }

    /// Stop the animation ticker if running.
    pub fn stop_anim(&mut self) {
        if let Some(h) = self.anim_handle.take() {
            h.abort();
        }
    }

    /// Reset sandbox and provider state after switching gateways.
    pub fn reset_sandbox_state(&mut self) {
        self.stop_anim();
        self.cancel_log_stream();
        self.sandbox_ids.clear();
        self.sandbox_names.clear();
        self.sandbox_phases.clear();
        self.sandbox_ages.clear();
        self.sandbox_created.clear();
        self.sandbox_images.clear();
        self.sandbox_notes.clear();
        self.sandbox_policy_versions.clear();
        self.sandbox_selected = 0;
        self.sandbox_count = 0;
        self.sandbox_log_lines.clear();
        self.sandbox_log_scroll = 0;
        self.log_cursor = 0;
        self.log_autoscroll = true;
        self.log_detail_index = None;
        self.log_selection_anchor = None;
        self.confirm_delete = false;
        self.sandbox_policy = None;
        self.sandbox_providers_list.clear();
        self.policy_lines.clear();
        self.policy_scroll = 0;
        // Reset provider state too.
        self.provider_names.clear();
        self.provider_types.clear();
        self.provider_cred_keys.clear();
        self.provider_selected = 0;
        self.provider_count = 0;
        self.confirm_provider_delete = false;
        self.status_text = String::from("connecting...");
        if self.screen == Screen::Sandbox {
            self.screen = Screen::Dashboard;
            self.focus = Focus::Sandboxes;
        }
    }
}

/// Generate a unique provider name by appending `-1`, `-2`, etc. if needed.
fn unique_provider_name(base: &str, existing: &[String]) -> String {
    if !existing.iter().any(|n| n == base) {
        return base.to_string();
    }
    for i in 1..100 {
        let candidate = format!("{base}-{i}");
        if !existing.iter().any(|n| n == &candidate) {
            return candidate;
        }
    }
    base.to_string()
}
