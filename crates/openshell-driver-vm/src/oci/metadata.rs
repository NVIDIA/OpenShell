// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Normalized launch metadata derived from the OCI image config + sandbox spec.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Guest platform an OCI manifest must match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// `linux/amd64`
    LinuxAmd64,
    /// `linux/arm64`
    LinuxArm64,
}

impl Platform {
    /// Host build target. Returns `None` on unsupported host arches.
    #[must_use]
    pub fn host() -> Option<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Some(Self::LinuxAmd64),
            "aarch64" | "arm64" => Some(Self::LinuxArm64),
            _ => None,
        }
    }

    /// OCI `os` component.
    #[must_use]
    pub const fn os(self) -> &'static str {
        "linux"
    }

    /// OCI `architecture` component.
    #[must_use]
    pub const fn arch(self) -> &'static str {
        match self {
            Self::LinuxAmd64 => "amd64",
            Self::LinuxArm64 => "arm64",
        }
    }

    /// Short string used in cache keys (`amd64`, `arm64`).
    #[must_use]
    pub const fn cache_tag(self) -> &'static str {
        self.arch()
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os(), self.arch())
    }
}

/// Normalized command + environment the guest init will hand to the supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchMetadata {
    /// Exact argv boundaries preserved (no shell split).
    pub argv: Vec<String>,
    /// Ordered env, OCI config < template < sandbox spec.
    pub env: Vec<(String, String)>,
    /// Working directory inside the container rootfs.
    pub workdir: String,
    /// Labels copied from the OCI config (advisory; carried for introspection).
    pub labels: BTreeMap<String, String>,
    /// Stop signal name from the OCI config (e.g. `SIGTERM`). Empty → default.
    pub stop_signal: String,
}

impl LaunchMetadata {
    /// Normalize an OCI image config plus caller-supplied overrides into a
    /// launch descriptor.
    ///
    /// Precedence for env: OCI config < template env < sandbox spec env.
    /// Argv = OCI `Entrypoint` + `Cmd` per OCI spec precedence.
    /// Workdir = OCI `WorkingDir` if absolute and non-empty, else `/sandbox`.
    pub fn build(
        image_config: ImageConfig,
        template_env: &BTreeMap<String, String>,
        spec_env: &BTreeMap<String, String>,
    ) -> Result<Self, BuildError> {
        let argv = resolve_argv(&image_config.entrypoint, &image_config.cmd)?;
        let workdir = resolve_workdir(&image_config.working_dir);
        let env = merge_env(&image_config.env, template_env, spec_env)?;

        Ok(Self {
            argv,
            env,
            workdir,
            labels: image_config.labels,
            stop_signal: image_config.stop_signal,
        })
    }

    /// Render this metadata into env vars the guest init can consume.
    ///
    /// - `OPENSHELL_OCI_ARGC=<n>`, `OPENSHELL_OCI_ARGV_<i>=<arg>` for each i in 0..n.
    /// - `OPENSHELL_OCI_ENV_COUNT=<n>`, `OPENSHELL_OCI_ENV_<i>=<key>=<value>` for each i.
    /// - `OPENSHELL_OCI_WORKDIR=<path>`.
    ///
    /// A single env channel keeps this delivery in-band with the krun
    /// `set_exec` call, avoiding any on-disk metadata file or vsock transfer.
    #[must_use]
    pub fn to_guest_env_vars(&self) -> Vec<(String, String)> {
        let mut out = Vec::with_capacity(self.argv.len() + self.env.len() + 3);
        out.push((
            "OPENSHELL_OCI_ARGC".to_string(),
            self.argv.len().to_string(),
        ));
        for (i, arg) in self.argv.iter().enumerate() {
            out.push((format!("OPENSHELL_OCI_ARGV_{i}"), arg.clone()));
        }
        out.push((
            "OPENSHELL_OCI_ENV_COUNT".to_string(),
            self.env.len().to_string(),
        ));
        for (i, (key, value)) in self.env.iter().enumerate() {
            out.push((format!("OPENSHELL_OCI_ENV_{i}"), format!("{key}={value}")));
        }
        out.push(("OPENSHELL_OCI_WORKDIR".to_string(), self.workdir.clone()));
        out
    }
}

/// Minimal view of the OCI image config we care about.
#[derive(Debug, Clone, Default)]
pub struct ImageConfig {
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub working_dir: String,
    pub labels: BTreeMap<String, String>,
    pub stop_signal: String,
}

/// Errors raised when the image config is missing required data.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("image config has no runnable command (Entrypoint and Cmd are both empty)")]
    EmptyCommand,
    #[error("image env entry is not KEY=VALUE: {0}")]
    MalformedEnv(String),
    #[error("template env entry has empty key")]
    EmptyTemplateEnvKey,
}

fn resolve_argv(entrypoint: &[String], cmd: &[String]) -> Result<Vec<String>, BuildError> {
    let mut argv = Vec::with_capacity(entrypoint.len() + cmd.len());
    argv.extend(entrypoint.iter().cloned());
    argv.extend(cmd.iter().cloned());
    if argv.is_empty() {
        return Err(BuildError::EmptyCommand);
    }
    Ok(argv)
}

fn resolve_workdir(oci_workdir: &str) -> String {
    if oci_workdir.starts_with('/') && !oci_workdir.is_empty() {
        oci_workdir.to_string()
    } else {
        "/sandbox".to_string()
    }
}

fn merge_env(
    oci_env: &[String],
    template: &BTreeMap<String, String>,
    spec: &BTreeMap<String, String>,
) -> Result<Vec<(String, String)>, BuildError> {
    let mut merged: BTreeMap<String, String> = BTreeMap::new();
    for entry in oci_env {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(BuildError::MalformedEnv(entry.clone()));
        };
        merged.insert(key.to_string(), value.to_string());
    }
    for (key, value) in template {
        if key.is_empty() {
            return Err(BuildError::EmptyTemplateEnvKey);
        }
        merged.insert(key.clone(), value.clone());
    }
    for (key, value) in spec {
        merged.insert(key.clone(), value.clone());
    }
    Ok(merged.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(entrypoint: &[&str], cmd: &[&str], env: &[&str], workdir: &str) -> ImageConfig {
        ImageConfig {
            entrypoint: entrypoint.iter().map(|s| (*s).to_string()).collect(),
            cmd: cmd.iter().map(|s| (*s).to_string()).collect(),
            env: env.iter().map(|s| (*s).to_string()).collect(),
            working_dir: workdir.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn argv_is_entrypoint_then_cmd() {
        let meta = LaunchMetadata::build(
            config(&["/bin/sh", "-c"], &["echo hi"], &[], "/app"),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(meta.argv, vec!["/bin/sh", "-c", "echo hi"]);
        assert_eq!(meta.workdir, "/app");
    }

    #[test]
    fn argv_falls_back_to_cmd_only() {
        let meta = LaunchMetadata::build(
            config(&[], &["/bin/busybox", "sh"], &[], ""),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(meta.argv, vec!["/bin/busybox", "sh"]);
    }

    #[test]
    fn empty_command_is_rejected() {
        let err = LaunchMetadata::build(
            config(&[], &[], &[], ""),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .expect_err("empty command must be rejected");
        assert!(matches!(err, BuildError::EmptyCommand));
    }

    #[test]
    fn workdir_falls_back_to_sandbox() {
        let meta = LaunchMetadata::build(
            config(&["/bin/sh"], &[], &[], ""),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(meta.workdir, "/sandbox");

        let meta = LaunchMetadata::build(
            config(&["/bin/sh"], &[], &[], "relative/path"),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(meta.workdir, "/sandbox");
    }

    #[test]
    fn env_precedence_is_oci_then_template_then_spec() {
        let template: BTreeMap<String, String> = [("A", "template"), ("B", "template")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let spec: BTreeMap<String, String> = [("B", "spec"), ("C", "spec")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        let meta = LaunchMetadata::build(
            config(&["/bin/sh"], &[], &["A=oci", "B=oci", "D=oci"], "/app"),
            &template,
            &spec,
        )
        .unwrap();

        let env: BTreeMap<String, String> = meta.env.into_iter().collect();
        assert_eq!(env.get("A"), Some(&"template".to_string()));
        assert_eq!(env.get("B"), Some(&"spec".to_string()));
        assert_eq!(env.get("C"), Some(&"spec".to_string()));
        assert_eq!(env.get("D"), Some(&"oci".to_string()));
    }

    #[test]
    fn malformed_oci_env_entry_is_rejected() {
        let err = LaunchMetadata::build(
            config(&["/bin/sh"], &[], &["BROKEN"], "/app"),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .expect_err("missing '=' should fail");
        assert!(matches!(err, BuildError::MalformedEnv(_)));
    }

    #[test]
    fn to_guest_env_vars_round_trips_argv_with_spaces() {
        let meta = LaunchMetadata::build(
            config(
                &["/bin/sh", "-c"],
                &["echo 'hello world'"],
                &["A=1"],
                "/app",
            ),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();

        let env: BTreeMap<String, String> = meta.to_guest_env_vars().into_iter().collect();
        assert_eq!(env.get("OPENSHELL_OCI_ARGC"), Some(&"3".to_string()));
        assert_eq!(
            env.get("OPENSHELL_OCI_ARGV_0"),
            Some(&"/bin/sh".to_string())
        );
        assert_eq!(env.get("OPENSHELL_OCI_ARGV_1"), Some(&"-c".to_string()));
        assert_eq!(
            env.get("OPENSHELL_OCI_ARGV_2"),
            Some(&"echo 'hello world'".to_string())
        );
        assert_eq!(env.get("OPENSHELL_OCI_ENV_COUNT"), Some(&"1".to_string()));
        assert_eq!(env.get("OPENSHELL_OCI_ENV_0"), Some(&"A=1".to_string()));
        assert_eq!(env.get("OPENSHELL_OCI_WORKDIR"), Some(&"/app".to_string()));
    }

    #[test]
    fn host_platform_is_recognized_on_supported_arches() {
        let platform = Platform::host();
        // On CI/dev machines this should always be amd64 or arm64.
        assert!(matches!(
            platform,
            Some(Platform::LinuxAmd64) | Some(Platform::LinuxArm64)
        ));
    }
}
