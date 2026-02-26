use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use navigator_core::proto::navigator_client::NavigatorClient;
use tonic::transport::Channel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Dashboard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Clusters,
    Sandboxes,
}

pub struct ClusterEntry {
    pub name: String,
    pub endpoint: String,
    pub is_remote: bool,
}

pub struct App {
    pub running: bool,
    pub view: View,
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
    pub sandbox_names: Vec<String>,
    pub sandbox_phases: Vec<String>,
    pub sandbox_ages: Vec<String>,
    pub sandbox_images: Vec<String>,
    pub sandbox_selected: usize,
    pub sandbox_count: usize,
}

impl App {
    pub fn new(client: NavigatorClient<Channel>, cluster_name: String, endpoint: String) -> Self {
        Self {
            running: true,
            view: View::Dashboard,
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
            sandbox_names: Vec::new(),
            sandbox_phases: Vec::new(),
            sandbox_ages: Vec::new(),
            sandbox_images: Vec::new(),
            sandbox_selected: 0,
            sandbox_count: 0,
        }
    }

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
        match key.code {
            KeyCode::Char('q') => self.running = false,
            KeyCode::Tab | KeyCode::BackTab => self.toggle_focus(),
            KeyCode::Char(':') => {
                self.input_mode = InputMode::Command;
                self.command_input.clear();
            }
            KeyCode::Char('j') | KeyCode::Down => self.select_next(),
            KeyCode::Char('k') | KeyCode::Up => self.select_prev(),
            KeyCode::Enter => self.activate_selection(),
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

    fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Clusters => Focus::Sandboxes,
            Focus::Sandboxes => Focus::Clusters,
        };
    }

    fn select_next(&mut self) {
        match self.focus {
            Focus::Clusters => {
                if !self.clusters.is_empty() {
                    self.cluster_selected =
                        (self.cluster_selected + 1).min(self.clusters.len() - 1);
                }
            }
            Focus::Sandboxes => {
                if self.sandbox_count > 0 {
                    self.sandbox_selected = (self.sandbox_selected + 1).min(self.sandbox_count - 1);
                }
            }
        }
    }

    fn select_prev(&mut self) {
        match self.focus {
            Focus::Clusters => {
                self.cluster_selected = self.cluster_selected.saturating_sub(1);
            }
            Focus::Sandboxes => {
                self.sandbox_selected = self.sandbox_selected.saturating_sub(1);
            }
        }
    }

    fn activate_selection(&mut self) {
        if self.focus == Focus::Clusters {
            if let Some(entry) = self.clusters.get(self.cluster_selected) {
                if entry.name != self.cluster_name {
                    self.pending_cluster_switch = Some(entry.name.clone());
                }
            }
        }
    }

    /// Reset sandbox state after switching clusters.
    pub fn reset_sandbox_state(&mut self) {
        self.sandbox_names.clear();
        self.sandbox_phases.clear();
        self.sandbox_ages.clear();
        self.sandbox_images.clear();
        self.sandbox_selected = 0;
        self.sandbox_count = 0;
        self.status_text = String::from("connecting...");
    }
}
