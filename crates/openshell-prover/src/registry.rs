// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Binary capability registry — loads YAML descriptors that describe what each
//! binary can do (protocols, exfiltration, HTTP construction, etc.).

use std::collections::HashMap;
use std::path::Path;

use miette::{IntoDiagnostic, Result, WrapErr};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Serde types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct BinaryCapabilityDef {
    binary: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    protocols: Vec<BinaryProtocolDef>,
    #[serde(default)]
    spawns: Vec<String>,
    #[serde(default)]
    can_exfiltrate: bool,
    #[serde(default)]
    exfil_mechanism: String,
    #[serde(default)]
    can_construct_http: bool,
}

#[derive(Debug, Deserialize)]
struct BinaryProtocolDef {
    #[serde(default)]
    name: String,
    #[serde(default)]
    transport: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    bypasses_l7: bool,
    #[serde(default)]
    actions: Vec<BinaryActionDef>,
}

#[derive(Debug, Deserialize)]
struct BinaryActionDef {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    action_type: String,
    #[serde(default)]
    description: String,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Type of action a binary can perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionType {
    Read,
    Write,
    Destructive,
}

impl ActionType {
    fn from_str(s: &str) -> Self {
        match s {
            "write" => Self::Write,
            "destructive" => Self::Destructive,
            _ => Self::Read,
        }
    }
}

/// A single action a binary protocol supports.
#[derive(Debug, Clone)]
pub struct BinaryAction {
    pub name: String,
    pub action_type: ActionType,
    pub description: String,
}

/// A protocol supported by a binary.
#[derive(Debug, Clone)]
pub struct BinaryProtocol {
    pub name: String,
    pub transport: String,
    pub description: String,
    pub bypasses_l7: bool,
    pub actions: Vec<BinaryAction>,
}

impl BinaryProtocol {
    /// Whether any action in this protocol is a write or destructive action.
    pub fn can_write(&self) -> bool {
        self.actions
            .iter()
            .any(|a| matches!(a.action_type, ActionType::Write | ActionType::Destructive))
    }
}

/// Capability descriptor for a single binary.
#[derive(Debug, Clone)]
pub struct BinaryCapability {
    pub path: String,
    pub description: String,
    pub protocols: Vec<BinaryProtocol>,
    pub spawns: Vec<String>,
    pub can_exfiltrate: bool,
    pub exfil_mechanism: String,
    pub can_construct_http: bool,
}

impl BinaryCapability {
    /// Whether any protocol bypasses L7 inspection.
    pub fn bypasses_l7(&self) -> bool {
        self.protocols.iter().any(|p| p.bypasses_l7)
    }

    /// Whether the binary can perform write actions.
    pub fn can_write(&self) -> bool {
        self.protocols.iter().any(|p| p.can_write()) || self.can_construct_http
    }

    /// Short mechanisms by which this binary can write.
    pub fn write_mechanisms(&self) -> Vec<String> {
        let mut mechanisms = Vec::new();
        for p in &self.protocols {
            if p.can_write() {
                for a in &p.actions {
                    if matches!(a.action_type, ActionType::Write | ActionType::Destructive) {
                        mechanisms.push(format!("{}: {}", p.name, a.name));
                    }
                }
            }
        }
        if self.can_construct_http {
            mechanisms.push("arbitrary HTTP request construction".to_owned());
        }
        mechanisms
    }
}

/// Registry of binary capability descriptors.
#[derive(Debug, Clone, Default)]
pub struct BinaryRegistry {
    binaries: HashMap<String, BinaryCapability>,
}

impl BinaryRegistry {
    /// Look up a binary by exact path.
    pub fn get(&self, path: &str) -> Option<&BinaryCapability> {
        self.binaries.get(path)
    }

    /// Look up a binary, falling back to glob matching, then to a conservative
    /// unknown descriptor.
    pub fn get_or_unknown(&self, path: &str) -> BinaryCapability {
        if let Some(cap) = self.binaries.get(path) {
            return cap.clone();
        }
        // Check glob patterns (e.g., registry has /usr/bin/python* matching /usr/bin/python3.13)
        for (reg_path, cap) in &self.binaries {
            if reg_path.contains('*') && glob_match(reg_path, path) {
                return cap.clone();
            }
        }
        // Conservative default: unknown binary assumed capable of everything.
        BinaryCapability {
            path: path.to_owned(),
            description: "Unknown binary — not in registry".to_owned(),
            protocols: Vec::new(),
            spawns: Vec::new(),
            can_exfiltrate: true,
            exfil_mechanism: String::new(),
            can_construct_http: true,
        }
    }
}

/// Simple glob matching supporting `*` (single segment) and `**` (multiple
/// segments).
fn glob_match(pattern: &str, path: &str) -> bool {
    // Split both on `/` and match segment by segment.
    let pat_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();
    glob_match_segments(&pat_parts, &path_parts)
}

fn glob_match_segments(pat: &[&str], path: &[&str]) -> bool {
    if pat.is_empty() {
        return path.is_empty();
    }
    if pat[0] == "**" {
        // ** matches zero or more segments.
        for i in 0..=path.len() {
            if glob_match_segments(&pat[1..], &path[i..]) {
                return true;
            }
        }
        return false;
    }
    if path.is_empty() {
        return false;
    }
    if segment_match(pat[0], path[0]) {
        return glob_match_segments(&pat[1..], &path[1..]);
    }
    false
}

fn segment_match(pattern: &str, segment: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == segment;
    }
    // Simple wildcard within a segment: split on '*' and check prefix/suffix.
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 2 {
        return segment.starts_with(parts[0]) && segment.ends_with(parts[1]);
    }
    // Fallback: fnmatch-like. For simplicity, just check contains for each part.
    let mut remaining = segment;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !remaining.starts_with(part) {
                return false;
            }
            remaining = &remaining[part.len()..];
        } else if let Some(pos) = remaining.find(part) {
            remaining = &remaining[pos + part.len()..];
        } else {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load a single binary capability descriptor from a YAML file.
fn load_binary_capability(path: &Path) -> Result<BinaryCapability> {
    let contents = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading binary descriptor {}", path.display()))?;
    let raw: BinaryCapabilityDef = serde_yml::from_str(&contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("parsing binary descriptor {}", path.display()))?;

    let protocols = raw
        .protocols
        .into_iter()
        .map(|p| {
            let actions = p
                .actions
                .into_iter()
                .map(|a| BinaryAction {
                    name: a.name,
                    action_type: ActionType::from_str(&a.action_type),
                    description: a.description,
                })
                .collect();
            BinaryProtocol {
                name: p.name,
                transport: p.transport,
                description: p.description,
                bypasses_l7: p.bypasses_l7,
                actions,
            }
        })
        .collect();

    Ok(BinaryCapability {
        path: raw.binary,
        description: raw.description,
        protocols,
        spawns: raw.spawns,
        can_exfiltrate: raw.can_exfiltrate,
        exfil_mechanism: raw.exfil_mechanism,
        can_construct_http: raw.can_construct_http,
    })
}

/// Load all binary capability descriptors from a registry directory.
///
/// Expects `{registry_dir}/binaries/*.yaml`.
pub fn load_binary_registry(registry_dir: &Path) -> Result<BinaryRegistry> {
    let mut binaries = HashMap::new();
    let binaries_dir = registry_dir.join("binaries");
    if binaries_dir.is_dir() {
        let entries = std::fs::read_dir(&binaries_dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading directory {}", binaries_dir.display()))?;
        for entry in entries {
            let entry = entry.into_diagnostic()?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "yaml") {
                let cap = load_binary_capability(&path)?;
                binaries.insert(cap.path.clone(), cap);
            }
        }
    }
    Ok(BinaryRegistry { binaries })
}
