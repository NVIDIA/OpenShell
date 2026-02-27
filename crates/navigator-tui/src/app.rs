use std::collections::HashMap;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use navigator_core::proto::navigator_client::NavigatorClient;
use tonic::transport::Channel;

// ---------------------------------------------------------------------------
// Screens & focus
// ---------------------------------------------------------------------------

/// Top-level screen (each is a full-screen layout with its own nav bar).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Cluster list + sandbox table.
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
    Clusters,
    Sandboxes,
    // Sandbox screen
    SandboxDetail,
    SandboxLogs,
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
// Cluster entry
// ---------------------------------------------------------------------------

pub struct ClusterEntry {
    pub name: String,
    pub endpoint: String,
    pub is_remote: bool,
}

// ---------------------------------------------------------------------------
// Create sandbox form
// ---------------------------------------------------------------------------

/// Which field is focused in the create sandbox modal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateFormField {
    Name,
    Image,
    Command,
    Providers,
    Submit,
}

impl CreateFormField {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Image,
            Self::Image => Self::Command,
            Self::Command => Self::Providers,
            Self::Providers => Self::Submit,
            Self::Submit => Self::Name,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Name => Self::Submit,
            Self::Image => Self::Name,
            Self::Command => Self::Image,
            Self::Providers => Self::Command,
            Self::Submit => Self::Providers,
        }
    }
}

/// A known provider type for the create form.
#[derive(Debug, Clone)]
pub struct ProviderEntry {
    pub name: String,
    pub selected: bool,
}

/// Tracks which phase the create sandbox modal is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreatePhase {
    /// Filling out the form.
    Form,
    /// Resolving providers (background task running).
    Resolving,
    /// Resolution complete — showing results, waiting for user to confirm.
    Confirm,
    /// Creating the sandbox (background task running).
    Creating,
}

/// Minimum time to show the Creating phase (pacman + results) before closing.
pub const MIN_CREATING_DISPLAY: Duration = Duration::from_secs(4);

/// State for the create sandbox modal form.
pub struct CreateSandboxForm {
    pub focused_field: CreateFormField,
    pub name: String,
    pub image: String,
    pub command: String,
    pub providers: Vec<ProviderEntry>,
    pub provider_cursor: usize,
    /// Status message shown after submit attempt.
    pub status: Option<String>,
    /// Current phase of the create flow.
    pub phase: CreatePhase,
    /// When the create animation started (for pacman timing).
    pub anim_start: Option<Instant>,
    /// Per-provider resolution status, shown during creation.
    pub provider_statuses: Vec<(String, crate::event::ProviderResolution)>,
    /// Providers already registered on the gateway: `(type, name)`.
    pub existing_providers: Vec<(String, String)>,
    /// Missing provider types with user toggle: `(type, should_create)`.
    /// Defaults to `true` (matching CLI's default-yes behavior).
    pub missing_providers: Vec<(String, bool)>,
    /// Cursor position in the confirm view (indexes into missing_providers).
    pub confirm_cursor: usize,
    /// Buffered create result — held until min display time elapses.
    pub create_result: Option<Result<String, String>>,
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

    // Active cluster connection
    pub cluster_name: String,
    pub endpoint: String,
    pub client: NavigatorClient<Channel>,
    pub status_text: String,

    // Cluster list
    pub clusters: Vec<ClusterEntry>,
    pub cluster_selected: usize,
    pub pending_cluster_switch: Option<String>,

    // Sandbox list
    pub sandbox_ids: Vec<String>,
    pub sandbox_names: Vec<String>,
    pub sandbox_phases: Vec<String>,
    pub sandbox_ages: Vec<String>,
    pub sandbox_created: Vec<String>,
    pub sandbox_images: Vec<String>,
    pub sandbox_selected: usize,
    pub sandbox_count: usize,

    // Sandbox detail / actions
    pub confirm_delete: bool,
    pub pending_log_fetch: bool,
    pub pending_sandbox_delete: bool,

    // Create sandbox modal
    pub create_form: Option<CreateSandboxForm>,
    pub pending_create_sandbox: bool,
    /// Set when user confirms creation after provider resolution.
    pub pending_confirm_create: bool,
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
    /// Handle for the streaming log task. Dropped to cancel.
    pub log_stream_handle: Option<tokio::task::JoinHandle<()>>,
}

impl App {
    pub fn new(client: NavigatorClient<Channel>, cluster_name: String, endpoint: String) -> Self {
        Self {
            running: true,
            screen: Screen::Dashboard,
            input_mode: InputMode::Normal,
            focus: Focus::Clusters,
            command_input: String::new(),
            cluster_name,
            endpoint,
            client,
            status_text: String::from("connecting..."),
            clusters: Vec::new(),
            cluster_selected: 0,
            pending_cluster_switch: None,
            sandbox_ids: Vec::new(),
            sandbox_names: Vec::new(),
            sandbox_phases: Vec::new(),
            sandbox_ages: Vec::new(),
            sandbox_created: Vec::new(),
            sandbox_images: Vec::new(),
            sandbox_selected: 0,
            sandbox_count: 0,
            confirm_delete: false,
            pending_log_fetch: false,
            pending_sandbox_delete: false,
            create_form: None,
            pending_create_sandbox: false,
            pending_confirm_create: false,
            anim_handle: None,
            sandbox_log_lines: Vec::new(),
            sandbox_log_scroll: 0,
            log_cursor: 0,
            log_source_filter: LogSourceFilter::All,
            log_autoscroll: true,
            log_viewport_height: 0,
            log_detail_index: None,
            log_stream_handle: None,
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

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.running = false;
            return;
        }

        // Create sandbox modal intercepts all keys when open.
        if self.create_form.is_some() {
            self.handle_create_form_key(key);
            return;
        }

        match self.input_mode {
            InputMode::Command => self.handle_command_key(key),
            InputMode::Normal => self.handle_normal_key(key),
        }
    }

    fn handle_normal_key(&mut self, key: KeyEvent) {
        match self.focus {
            Focus::Clusters => self.handle_clusters_key(key),
            Focus::Sandboxes => self.handle_sandboxes_key(key),
            Focus::SandboxDetail => self.handle_detail_key(key),
            Focus::SandboxLogs => self.handle_logs_key(key),
        }
    }

    fn handle_clusters_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.running = false,
            KeyCode::Tab | KeyCode::BackTab => self.focus = Focus::Sandboxes,
            KeyCode::Char(':') => {
                self.input_mode = InputMode::Command;
                self.command_input.clear();
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if !self.clusters.is_empty() {
                    self.cluster_selected =
                        (self.cluster_selected + 1).min(self.clusters.len() - 1);
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.cluster_selected = self.cluster_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if let Some(entry) = self.clusters.get(self.cluster_selected) {
                    if entry.name != self.cluster_name {
                        // Switch to a different cluster.
                        self.pending_cluster_switch = Some(entry.name.clone());
                    }
                    // Always drop into sandboxes panel on Enter.
                    self.focus = Focus::Sandboxes;
                }
            }
            _ => {}
        }
    }

    fn handle_sandboxes_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.running = false,
            KeyCode::Tab | KeyCode::BackTab => self.focus = Focus::Clusters,
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
                    // Enter the full-screen sandbox view.
                    self.screen = Screen::Sandbox;
                    self.focus = Focus::SandboxDetail;
                    self.confirm_delete = false;
                }
            }
            KeyCode::Esc => {
                // Go back to clusters panel.
                self.focus = Focus::Clusters;
            }
            _ => {}
        }
    }

    fn handle_detail_key(&mut self, key: KeyEvent) {
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
                self.screen = Screen::Dashboard;
                self.focus = Focus::Sandboxes;
            }
            KeyCode::Char('l') => {
                // Immediately show log view with loading placeholder; the
                // actual fetch runs asynchronously in the background.
                self.sandbox_log_lines.clear();
                self.sandbox_log_scroll = 0;
                self.log_cursor = 0;
                self.log_source_filter = LogSourceFilter::All;
                self.log_autoscroll = true;
                self.log_detail_index = None;
                self.focus = Focus::SandboxLogs;
                self.pending_log_fetch = true;
            }
            KeyCode::Char('d') => {
                self.confirm_delete = true;
            }
            KeyCode::Char('q') => self.running = false,
            _ => {}
        }
    }

    fn handle_logs_key(&mut self, key: KeyEvent) {
        // If the detail popup is open, only Enter/Esc close it.
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
                self.cancel_log_stream();
                self.focus = Focus::SandboxDetail;
            }
            KeyCode::Char('q') => self.running = false,
            KeyCode::Enter => {
                // Open detail popup for the line under the cursor.
                if filtered_len > 0 {
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
                    // Move cursor down within viewport.
                    self.log_cursor += 1;
                } else {
                    // Cursor at bottom of viewport — scroll the view down.
                    let max_scroll = filtered_len.saturating_sub(vh.min(filtered_len));
                    if self.sandbox_log_scroll < max_scroll {
                        self.sandbox_log_scroll += 1;
                    }
                }
                // Don't disable autoscroll when moving down — only up.
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if self.log_cursor > 0 {
                    // Move cursor up within viewport.
                    self.log_cursor -= 1;
                } else {
                    // Cursor at top of viewport — scroll the view up.
                    if self.sandbox_log_scroll > 0 {
                        self.sandbox_log_scroll -= 1;
                    }
                }
                self.log_autoscroll = false;
            }
            KeyCode::Char('G' | 'f') => {
                // Jump to bottom and re-enable autoscroll (k9s-style follow).
                self.sandbox_log_scroll = self.log_autoscroll_offset();
                self.log_autoscroll = true;
                // Pin cursor to the last visible line.
                let visible = filtered_len.saturating_sub(self.sandbox_log_scroll);
                self.log_cursor = visible.saturating_sub(1).min(vh.saturating_sub(1));
            }
            KeyCode::Char('g') => {
                self.sandbox_log_scroll = 0;
                self.log_cursor = 0;
                self.log_autoscroll = false;
            }
            KeyCode::Char('s') => {
                // Cycle source filter: all -> gateway -> sandbox -> all
                self.log_source_filter = self.log_source_filter.next();
                self.sandbox_log_scroll = 0;
                self.log_cursor = 0;
                // Keep autoscroll state — user is just filtering.
            }
            _ => {}
        }
    }

    /// Scroll logs by a delta (positive = down, negative = up). Used for mouse scrolling.
    pub fn scroll_logs(&mut self, delta: isize) {
        let filtered_len = self.filtered_log_lines().len();
        let max_scroll = self.log_autoscroll_offset();
        if delta < 0 {
            // Scrolling up — disable autoscroll.
            self.sandbox_log_scroll = self.sandbox_log_scroll.saturating_sub(delta.unsigned_abs());
            self.log_autoscroll = false;
        } else {
            self.sandbox_log_scroll = (self.sandbox_log_scroll + delta as usize).min(max_scroll);
        }
        // Clamp cursor to the visible range after scroll.
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
    // Create sandbox modal
    // ------------------------------------------------------------------

    fn open_create_form(&mut self) {
        let known = navigator_providers::ProviderRegistry::new().known_types();
        let providers = known
            .into_iter()
            .map(|t| ProviderEntry {
                name: t.to_string(),
                selected: false,
            })
            .collect();

        self.create_form = Some(CreateSandboxForm {
            focused_field: CreateFormField::Name,
            name: String::new(),
            image: String::new(),
            command: String::from("/bin/bash"),
            providers,
            provider_cursor: 0,
            status: None,
            phase: CreatePhase::Form,
            anim_start: None,
            provider_statuses: Vec::new(),
            existing_providers: Vec::new(),
            missing_providers: Vec::new(),
            confirm_cursor: 0,
            create_result: None,
        });
    }

    fn handle_create_form_key(&mut self, key: KeyEvent) {
        let Some(form) = self.create_form.as_mut() else {
            return;
        };

        match form.phase {
            // --- Resolving: no input accepted (background task running) ---
            CreatePhase::Resolving => {}

            // --- Confirm: show resolution results, toggle missing providers ---
            CreatePhase::Confirm => match key.code {
                KeyCode::Enter => {
                    form.phase = CreatePhase::Creating;
                    form.anim_start = Some(Instant::now());
                    form.provider_statuses.clear();
                    self.pending_confirm_create = true;
                }
                KeyCode::Esc => {
                    self.create_form = None;
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    if !form.missing_providers.is_empty() {
                        form.confirm_cursor =
                            (form.confirm_cursor + 1).min(form.missing_providers.len() - 1);
                    }
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    form.confirm_cursor = form.confirm_cursor.saturating_sub(1);
                }
                KeyCode::Char(' ') => {
                    if let Some(entry) = form.missing_providers.get_mut(form.confirm_cursor) {
                        entry.1 = !entry.1;
                    }
                }
                _ => {}
            },

            // --- Creating: no input accepted (background task running) ---
            CreatePhase::Creating => {}

            // --- Form: normal form editing ---
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
                    CreateFormField::Providers => {
                        match key.code {
                            KeyCode::Char('j') | KeyCode::Down => {
                                if !form.providers.is_empty() {
                                    form.provider_cursor =
                                        (form.provider_cursor + 1).min(form.providers.len() - 1);
                                }
                            }
                            KeyCode::Char('k') | KeyCode::Up => {
                                form.provider_cursor = form.provider_cursor.saturating_sub(1);
                            }
                            // Space or Enter toggles provider selection.
                            KeyCode::Char(' ') | KeyCode::Enter => {
                                if let Some(p) = form.providers.get_mut(form.provider_cursor) {
                                    p.selected = !p.selected;
                                }
                            }
                            _ => {}
                        }
                    }
                    CreateFormField::Submit => {
                        if key.code == KeyCode::Enter {
                            let has_providers = form.providers.iter().any(|p| p.selected);
                            form.anim_start = Some(Instant::now());
                            form.status = None;
                            form.provider_statuses.clear();
                            if has_providers {
                                // Resolve providers first.
                                form.phase = CreatePhase::Resolving;
                                self.pending_create_sandbox = true;
                            } else {
                                // No providers — go straight to creating.
                                form.phase = CreatePhase::Creating;
                                self.pending_confirm_create = true;
                            }
                        }
                    }
                },
            },
        }
    }

    fn handle_text_input(field: &mut String, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => field.push(c),
            KeyCode::Backspace => {
                field.pop();
            }
            _ => {}
        }
    }

    /// Build the form data needed for the gRPC `CreateSandbox` request.
    /// Returns `(name, image, selected_provider_names)`.
    pub fn create_form_data(&self) -> Option<(String, String, Vec<String>)> {
        let form = self.create_form.as_ref()?;
        let providers: Vec<String> = form
            .providers
            .iter()
            .filter(|p| p.selected)
            .map(|p| p.name.clone())
            .collect();
        Some((form.name.clone(), form.image.clone(), providers))
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

    /// Compute the scroll offset that pins the last log line near the bottom,
    /// leaving a small padding of empty lines (k9s-style).
    pub fn log_autoscroll_offset(&self) -> usize {
        const BOTTOM_PAD: usize = 3;
        let filtered_len = self.filtered_log_lines().len();
        let vh = self.log_viewport_height;
        if vh == 0 || filtered_len == 0 {
            return 0;
        }
        // Show as many lines as fit, with BOTTOM_PAD empty lines at the end.
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

    /// Reset sandbox state after switching clusters.
    pub fn reset_sandbox_state(&mut self) {
        self.stop_anim();
        self.cancel_log_stream();
        self.sandbox_ids.clear();
        self.sandbox_names.clear();
        self.sandbox_phases.clear();
        self.sandbox_ages.clear();
        self.sandbox_created.clear();
        self.sandbox_images.clear();
        self.sandbox_selected = 0;
        self.sandbox_count = 0;
        self.sandbox_log_lines.clear();
        self.sandbox_log_scroll = 0;
        self.log_cursor = 0;
        self.log_autoscroll = true;
        self.log_detail_index = None;
        self.confirm_delete = false;
        self.status_text = String::from("connecting...");
        // Return to dashboard if in sandbox screen.
        if self.screen == Screen::Sandbox {
            self.screen = Screen::Dashboard;
            self.focus = Focus::Sandboxes;
        }
    }
}
