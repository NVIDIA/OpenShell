// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::paths::xdg_config_dir;
use miette::{IntoDiagnostic, Result, WrapErr};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn stored_kubeconfig_path(name: &str) -> Result<PathBuf> {
    let base = xdg_config_dir()?;
    Ok(base
        .join("navigator")
        .join("clusters")
        .join(name)
        .join("kubeconfig"))
}

pub fn print_kubeconfig(name: &str) -> Result<()> {
    let path = stored_kubeconfig_path(name)?;
    let contents = std::fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read kubeconfig at {}", path.display()))?;
    print!("{contents}");
    Ok(())
}

pub fn update_local_kubeconfig(name: &str, target_path: &Path) -> Result<()> {
    let stored_path = stored_kubeconfig_path(name)?;
    let stored_contents = std::fs::read_to_string(&stored_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read kubeconfig at {}", stored_path.display()))?;
    let stored_config: Kubeconfig = serde_yaml::from_str(&stored_contents)
        .into_diagnostic()
        .wrap_err("failed to parse stored kubeconfig")?;

    let mut target_config = if target_path.exists() {
        let contents = std::fs::read_to_string(target_path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read kubeconfig at {}", target_path.display()))?;
        serde_yaml::from_str(&contents)
            .into_diagnostic()
            .wrap_err("failed to parse target kubeconfig")?
    } else {
        Kubeconfig::default()
    };

    merge_kubeconfig(&mut target_config, stored_config);

    if target_config.api_version.is_empty() {
        target_config.api_version = "v1".to_string();
    }
    if target_config.kind.is_empty() {
        target_config.kind = "Config".to_string();
    }

    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }

    let rendered = serde_yaml::to_string(&target_config)
        .into_diagnostic()
        .wrap_err("failed to serialize kubeconfig")?;
    std::fs::write(target_path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write kubeconfig to {}", target_path.display()))?;
    Ok(())
}

pub fn default_local_kubeconfig_path() -> Result<PathBuf> {
    if let Ok(paths) = std::env::var("KUBECONFIG")
        && let Some(first) = paths.split(':').next()
        && !first.is_empty()
    {
        return Ok(PathBuf::from(first));
    }

    let home = std::env::var("HOME")
        .into_diagnostic()
        .wrap_err("HOME is not set")?;
    Ok(PathBuf::from(home).join(".kube").join("config"))
}

pub fn store_kubeconfig(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(path, contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write kubeconfig to {}", path.display()))?;
    Ok(())
}

/// Rewrite kubeconfig for remote deployment.
///
/// The kubeconfig points to `127.0.0.1:<kube_port>`, which works with an SSH tunnel:
/// `ssh -L <kube_port>:127.0.0.1:6443 user@host`
///
/// The cluster name includes "-remote" suffix to distinguish from local clusters.
pub fn rewrite_kubeconfig_remote(
    contents: &str,
    cluster_name: &str,
    _destination: &str,
    kube_port: Option<u16>,
) -> String {
    let remote_name = format!("{cluster_name}-remote");
    rewrite_kubeconfig(contents, &remote_name, kube_port)
}

/// Rewrite the raw k3s kubeconfig for use on the host.
///
/// When `kube_port` is `Some`, the server URL is rewritten to
/// `https://127.0.0.1:<kube_port>`. When `None`, the original server URL
/// is left intact (the control plane is not exposed on the host).
pub fn rewrite_kubeconfig(contents: &str, cluster_name: &str, kube_port: Option<u16>) -> String {
    let mut replaced = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim_start();
        if let Some(kp) = kube_port {
            if trimmed.starts_with("server:") {
                let indent_len = line.len() - trimmed.len();
                let indent = &line[..indent_len];
                replaced.push(format!("{indent}server: https://127.0.0.1:{kp}"));
                continue;
            }
        }
        // Rename default cluster/context/user to the cluster name
        // Handle both "name: default" and "- name: default" (YAML list item)
        if trimmed == "name: default" || trimmed == "- name: default" {
            let indent_len = line.len() - trimmed.len();
            let indent = &line[..indent_len];
            let prefix = if trimmed.starts_with("- ") { "- " } else { "" };
            replaced.push(format!("{indent}{prefix}name: {cluster_name}"));
            continue;
        }
        if trimmed == "cluster: default" || trimmed == "user: default" {
            let indent_len = line.len() - trimmed.len();
            let indent = &line[..indent_len];
            let key = trimmed.split(':').next().unwrap_or("cluster");
            replaced.push(format!("{indent}{key}: {cluster_name}"));
            continue;
        }
        if trimmed == "current-context: default" {
            replaced.push(format!("current-context: {cluster_name}"));
            continue;
        }
        replaced.push(line.to_string());
    }

    let mut output = replaced.join("\n");
    if contents.ends_with('\n') {
        output.push('\n');
    }
    output
}

fn merge_kubeconfig(target: &mut Kubeconfig, incoming: Kubeconfig) {
    merge_named(&mut target.clusters, incoming.clusters);
    merge_named(&mut target.contexts, incoming.contexts);
    merge_named(&mut target.users, incoming.users);

    if incoming.current_context.is_some() {
        target.current_context = incoming.current_context;
    }
    if incoming.preferences.is_some() {
        target.preferences = incoming.preferences;
    }

    target
        .extra
        .extend(incoming.extra.into_iter().filter(|(k, _)| !k.is_empty()));
}

fn merge_named<T: NamedEntry>(target: &mut Vec<T>, incoming: Vec<T>) {
    for entry in incoming {
        if let Some(existing) = target.iter_mut().find(|item| item.name() == entry.name()) {
            *existing = entry;
        } else {
            target.push(entry);
        }
    }
}

trait NamedEntry {
    fn name(&self) -> &str;
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Kubeconfig {
    #[serde(rename = "apiVersion", default)]
    api_version: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    clusters: Vec<NamedCluster>,
    #[serde(default)]
    contexts: Vec<NamedContext>,
    #[serde(default)]
    users: Vec<NamedUser>,
    #[serde(rename = "current-context", default)]
    current_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preferences: Option<serde_yaml::Value>,
    #[serde(flatten, default)]
    extra: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct NamedCluster {
    name: String,
    cluster: serde_yaml::Value,
}

impl NamedEntry for NamedCluster {
    fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct NamedContext {
    name: String,
    context: serde_yaml::Value,
}

impl NamedEntry for NamedContext {
    fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct NamedUser {
    name: String,
    user: serde_yaml::Value,
}

impl NamedEntry for NamedUser {
    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::rewrite_kubeconfig;

    #[test]
    fn rewrite_updates_server_address_with_kube_port() {
        let input = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443\n";
        let output = rewrite_kubeconfig(input, "test-cluster", Some(6443));
        assert!(output.contains("server: https://127.0.0.1:6443"));
    }

    #[test]
    fn rewrite_updates_server_address_custom_port() {
        let input = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443\n";
        let output = rewrite_kubeconfig(input, "test-cluster", Some(7443));
        assert!(output.contains("server: https://127.0.0.1:7443"));
        assert!(!output.contains("server: https://127.0.0.1:6443"));
    }

    #[test]
    fn rewrite_preserves_server_when_no_kube_port() {
        let input = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443\n";
        let output = rewrite_kubeconfig(input, "test-cluster", None);
        assert!(
            output.contains("server: https://10.0.0.1:6443"),
            "server address should be preserved when kube_port is None"
        );
    }

    #[test]
    fn rewrite_preserves_trailing_newline() {
        let input = "apiVersion: v1\nserver: https://10.0.0.1\n";
        let output = rewrite_kubeconfig(input, "test-cluster", Some(6443));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn rewrite_renames_default_entries() {
        let input = "apiVersion: v1
 clusters:
 - name: default
   cluster:
     server: https://10.0.0.1:6443
 contexts:
 - name: default
   context:
     cluster: default
     user: default
 users:
 - name: default
 current-context: default
 ";
        let output = rewrite_kubeconfig(input, "my-cluster", Some(6443));
        assert!(
            output.contains("name: my-cluster"),
            "should contain 'name: my-cluster'"
        );
        assert!(
            output.contains("cluster: my-cluster"),
            "should contain 'cluster: my-cluster'"
        );
        assert!(
            output.contains("user: my-cluster"),
            "should contain 'user: my-cluster'"
        );
        assert!(
            output.contains("current-context: my-cluster"),
            "should contain 'current-context: my-cluster'"
        );
        assert!(
            !output.contains("name: default"),
            "should not contain 'name: default'"
        );
    }
}
