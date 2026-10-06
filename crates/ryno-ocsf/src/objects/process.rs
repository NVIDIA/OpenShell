// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `process` and `actor` objects.

use serde::{Deserialize, Serialize};

/// OCSF Process object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    /// Process name (e.g., "python3").
    pub name: String,

    /// Process ID.
    pub pid: i64,

    /// Full command line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd_line: Option<String>,

    /// Parent process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_process: Option<Box<Self>>,
}

impl Process {
    /// Create a new process with name and PID.
    #[must_use]
    pub fn new(name: &str, pid: i64) -> Self {
        Self {
            name: name.to_string(),
            pid,
            cmd_line: None,
            parent_process: None,
        }
    }

    /// Set the command line.
    #[must_use]
    pub fn with_cmd_line(mut self, cmd_line: &str) -> Self {
        self.cmd_line = Some(cmd_line.to_string());
        self
    }

    /// Set the parent process.
    #[must_use]
    pub fn with_parent(mut self, parent: Self) -> Self {
        self.parent_process = Some(Box::new(parent));
        self
    }

    /// Build a process chain from bypass detection fields.
    ///
    /// Parses an ancestors string like "bash -> node" into a parent chain.
    #[must_use]
    pub fn from_bypass(binary: &str, pid: &str, ancestors: &str) -> Self {
        let pid = pid.parse::<i64>().unwrap_or(0);
        let mut proc = Self::new(binary, pid);

        // Parse ancestor chain "grandparent -> parent" into nested parent_process
        let parts: Vec<&str> = ancestors.split(" -> ").collect();
        if parts.len() >= 2 {
            let mut parent = Self::new(parts[parts.len() - 1], 0);
            for ancestor in parts[..parts.len() - 1].iter().rev() {
                parent = Self::new(ancestor, 0).with_parent(parent);
            }
            proc.parent_process = Some(Box::new(parent));
        } else if !ancestors.is_empty() && ancestors != binary {
            proc.parent_process = Some(Box::new(Self::new(ancestors, 0)));
        }

        proc
    }
}

/// OCSF Actor object — the entity that initiated the event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// The process that performed the action.
    pub process: Process,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_creation() {
        let proc = Process::new("python3", 42).with_cmd_line("python3 /app/main.py");
        assert_eq!(proc.name, "python3");
        assert_eq!(proc.pid, 42);
        assert_eq!(proc.cmd_line.as_deref(), Some("python3 /app/main.py"));
    }

    #[test]
    fn test_process_with_parent() {
        let proc = Process::new("python3", 42).with_parent(Process::new("bash", 1));
        let parent = proc.parent_process.as_ref().unwrap();
        assert_eq!(parent.name, "bash");
        assert_eq!(parent.pid, 1);
    }

    #[test]
    fn test_process_from_bypass() {
        let proc = Process::from_bypass("node", "1234", "bash -> node");
        assert_eq!(proc.name, "node");
        assert_eq!(proc.pid, 1234);
        let parent = proc.parent_process.as_ref().unwrap();
        assert_eq!(parent.name, "bash");
    }

    #[test]
    fn test_process_from_bypass_deep_chain() {
        let proc = Process::from_bypass("node", "1234", "init -> bash -> node");
        assert_eq!(proc.name, "node");
        let parent = proc.parent_process.as_ref().unwrap();
        assert_eq!(parent.name, "init");
        let grandparent = parent.parent_process.as_ref().unwrap();
        assert_eq!(grandparent.name, "bash");
    }

    #[test]
    fn test_process_serialization() {
        let proc = Process::new("python3", 42);
        let json = serde_json::to_value(&proc).unwrap();
        assert_eq!(json["name"], "python3");
        assert_eq!(json["pid"], 42);
        assert!(json.get("cmd_line").is_none());
        assert!(json.get("parent_process").is_none());
    }

    #[test]
    fn test_actor_serialization() {
        let actor = Actor {
            process: Process::new("python3", 42),
        };
        let json = serde_json::to_value(&actor).unwrap();
        assert_eq!(json["process"]["name"], "python3");
    }
}
