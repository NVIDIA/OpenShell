// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Binary capability registry — loads YAML descriptors that describe what each
//! binary can do (protocols, exfiltration, HTTP construction, etc.).
//!
//! The built-in registry is embedded at compile time via `include_dir!`.
//! A filesystem override can be provided at runtime for custom registries.

use std::collections::HashMap;

use include_dir::{Dir, include_dir};
use miette::{IntoDiagnostic, Result, WrapErr};
use serde::Deserialize;

static EMBEDDED_REGISTRY: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/registry");

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
        for (reg_path, cap) in &self.binaries {
            if reg_path.contains('*') {
                if let Ok(pattern) = glob::Pattern::new(reg_path) {
                    if pattern.matches(path) {
                        return cap.clone();
                    }
                }
            }
        }
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

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

fn parse_binary_capability(contents: &str, source: &str) -> Result<BinaryCapability> {
    let raw: BinaryCapabilityDef = serde_yml::from_str(contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("parsing binary descriptor {source}"))?;

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

/// Load binary registry from the compile-time embedded registry data.
pub fn load_embedded_binary_registry() -> Result<BinaryRegistry> {
    let mut binaries = HashMap::new();
    if let Some(dir) = EMBEDDED_REGISTRY.get_dir("binaries") {
        for file in dir.files() {
            if file.path().extension().is_some_and(|ext| ext == "yaml") {
                let contents = file.contents_utf8().ok_or_else(|| {
                    miette::miette!("non-UTF8 registry file: {}", file.path().display())
                })?;
                let cap = parse_binary_capability(contents, &file.path().display().to_string())?;
                binaries.insert(cap.path.clone(), cap);
            }
        }
    }
    Ok(BinaryRegistry { binaries })
}

/// Load binary registry from a filesystem directory override.
pub fn load_binary_registry_from_dir(registry_dir: &std::path::Path) -> Result<BinaryRegistry> {
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
                let contents = std::fs::read_to_string(&path)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("reading {}", path.display()))?;
                let cap = parse_binary_capability(&contents, &path.display().to_string())?;
                binaries.insert(cap.path.clone(), cap);
            }
        }
    }
    Ok(BinaryRegistry { binaries })
}

/// Accessor for the embedded registry (used by credentials module for API descriptors).
pub fn embedded_registry() -> &'static Dir<'static> {
    &EMBEDDED_REGISTRY
}
