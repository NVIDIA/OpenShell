// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential descriptors and API capability registries.

use std::collections::HashMap;
use std::path::Path;

use miette::{IntoDiagnostic, Result, WrapErr};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Serde types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CredentialsFile {
    #[serde(default)]
    credentials: Vec<CredentialDef>,
}

#[derive(Debug, Deserialize)]
struct CredentialDef {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    cred_type: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    injected_via: String,
    #[serde(default)]
    target_hosts: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ApiRegistryDef {
    #[serde(default)]
    api: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: u32,
    #[serde(default)]
    credential_type: String,
    #[serde(default)]
    scope_capabilities: HashMap<String, Vec<ApiActionDef>>,
    #[serde(default)]
    action_risk: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ApiActionDef {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    action: String,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A credential injected into the sandbox.
#[derive(Debug, Clone)]
pub struct Credential {
    pub name: String,
    pub cred_type: String,
    pub scopes: Vec<String>,
    pub injected_via: String,
    pub target_hosts: Vec<String>,
}

/// A single API action (HTTP method + path + semantic name).
#[derive(Debug, Clone)]
pub struct ApiAction {
    pub method: String,
    pub path: String,
    pub action: String,
}

/// Capability registry for an API (e.g., GitHub REST API).
#[derive(Debug, Clone)]
pub struct ApiCapability {
    pub api: String,
    pub host: String,
    pub port: u32,
    pub credential_type: String,
    pub scope_capabilities: HashMap<String, Vec<ApiAction>>,
    pub action_risk: HashMap<String, String>,
}

impl ApiCapability {
    /// All actions enabled by the given scopes.
    pub fn actions_for_scopes(&self, scopes: &[String]) -> Vec<&ApiAction> {
        let mut result = Vec::new();
        for scope in scopes {
            if let Some(actions) = self.scope_capabilities.get(scope) {
                result.extend(actions.iter());
            }
        }
        result
    }

    /// Write actions (POST, PUT, PATCH, DELETE) enabled by the given scopes.
    pub fn write_actions_for_scopes(&self, scopes: &[String]) -> Vec<&ApiAction> {
        self.actions_for_scopes(scopes)
            .into_iter()
            .filter(|a| {
                let m = a.method.to_uppercase();
                m == "POST" || m == "PUT" || m == "PATCH" || m == "DELETE"
            })
            .collect()
    }

    /// Destructive actions (high or critical risk) enabled by the given scopes.
    pub fn destructive_actions_for_scopes(&self, scopes: &[String]) -> Vec<&ApiAction> {
        self.actions_for_scopes(scopes)
            .into_iter()
            .filter(|a| {
                let risk = self.action_risk.get(&a.action).map(String::as_str);
                matches!(risk, Some("high" | "critical"))
            })
            .collect()
    }
}

/// Combined set of credentials and API registries.
#[derive(Debug, Clone, Default)]
pub struct CredentialSet {
    pub credentials: Vec<Credential>,
    pub api_registries: HashMap<String, ApiCapability>,
}

impl CredentialSet {
    /// Credentials that target a given host.
    pub fn credentials_for_host(&self, host: &str) -> Vec<&Credential> {
        self.credentials
            .iter()
            .filter(|c| c.target_hosts.iter().any(|h| h == host))
            .collect()
    }

    /// API capability registry for a given host.
    pub fn api_for_host(&self, host: &str) -> Option<&ApiCapability> {
        self.api_registries.values().find(|api| api.host == host)
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load credential descriptors from a YAML file.
pub fn load_credentials(path: &Path) -> Result<Vec<Credential>> {
    let contents = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading credentials file {}", path.display()))?;
    let raw: CredentialsFile = serde_yml::from_str(&contents)
        .into_diagnostic()
        .wrap_err("parsing credentials YAML")?;

    Ok(raw
        .credentials
        .into_iter()
        .map(|c| Credential {
            name: c.name,
            cred_type: c.cred_type,
            scopes: c.scopes,
            injected_via: c.injected_via,
            target_hosts: c.target_hosts,
        })
        .collect())
}

/// Load an API capability registry from a YAML file.
fn load_api_registry(path: &Path) -> Result<ApiCapability> {
    let contents = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading API registry {}", path.display()))?;
    let raw: ApiRegistryDef = serde_yml::from_str(&contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("parsing API registry {}", path.display()))?;

    let scope_capabilities = raw
        .scope_capabilities
        .into_iter()
        .map(|(scope, actions)| {
            let actions = actions
                .into_iter()
                .map(|a| ApiAction {
                    method: a.method,
                    path: a.path,
                    action: a.action,
                })
                .collect();
            (scope, actions)
        })
        .collect();

    Ok(ApiCapability {
        api: raw.api,
        host: raw.host,
        port: raw.port,
        credential_type: raw.credential_type,
        scope_capabilities,
        action_risk: raw.action_risk,
    })
}

/// Load credentials and all API registries from the registry directory.
///
/// Expects `{registry_dir}/apis/*.yaml`.
pub fn load_credential_set(
    credentials_path: &Path,
    registry_dir: &Path,
) -> Result<CredentialSet> {
    let creds = load_credentials(credentials_path)?;

    let mut api_registries = HashMap::new();
    let apis_dir = registry_dir.join("apis");
    if apis_dir.is_dir() {
        let entries = std::fs::read_dir(&apis_dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading directory {}", apis_dir.display()))?;
        for entry in entries {
            let entry = entry.into_diagnostic()?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "yaml") {
                let api = load_api_registry(&path)?;
                api_registries.insert(api.api.clone(), api);
            }
        }
    }

    Ok(CredentialSet {
        credentials: creds,
        api_registries,
    })
}
