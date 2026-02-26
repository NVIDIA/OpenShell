use std::collections::HashMap;

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

    // Sandbox logs
    pub sandbox_log_lines: Vec<LogLine>,
    pub sandbox_log_scroll: usize,
    pub log_source_filter: LogSourceFilter,
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
            sandbox_log_lines: Vec::new(),
            sandbox_log_scroll: 0,
            log_source_filter: LogSourceFilter::All,
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
                self.log_source_filter = LogSourceFilter::All;
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
        match key.code {
            KeyCode::Esc => {
                self.cancel_log_stream();
                self.focus = Focus::SandboxDetail;
            }
            KeyCode::Char('q') => self.running = false,
            KeyCode::Char('j') | KeyCode::Down => {
                let filtered_len = self.filtered_log_lines().len();
                let max_scroll = filtered_len.saturating_sub(1);
                self.sandbox_log_scroll = (self.sandbox_log_scroll + 1).min(max_scroll);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.sandbox_log_scroll = self.sandbox_log_scroll.saturating_sub(1);
            }
            KeyCode::Char('G') => {
                let filtered_len = self.filtered_log_lines().len();
                self.sandbox_log_scroll = filtered_len.saturating_sub(1);
            }
            KeyCode::Char('g') => {
                self.sandbox_log_scroll = 0;
            }
            KeyCode::Char('s') => {
                // Cycle source filter: all -> gateway -> sandbox -> all
                self.log_source_filter = self.log_source_filter.next();
                self.sandbox_log_scroll = 0;
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

    /// Cancel any running log stream task.
    pub fn cancel_log_stream(&mut self) {
        if let Some(handle) = self.log_stream_handle.take() {
            handle.abort();
        }
    }

    /// Reset sandbox state after switching clusters.
    pub fn reset_sandbox_state(&mut self) {
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
        self.confirm_delete = false;
        self.status_text = String::from("connecting...");
        // Return to dashboard if in sandbox screen.
        if self.screen == Screen::Sandbox {
            self.screen = Screen::Dashboard;
            self.focus = Focus::Sandboxes;
        }
    }
}
