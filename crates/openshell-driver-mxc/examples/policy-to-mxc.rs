// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Dev/ops example: map `OpenShell` policy YAML to a coarse MXC `ContainerConfig`.
//!
//! Reuses the canonical `openshell_policy::parse_sandbox_policy` parser and the
//! embedded mapper re-exported from this crate. Windows-only: the embedded
//! mapper API only exists on Windows, so on other platforms this compiles to a
//! no-op `main`.
//!
//! The optional MXC JSON-schema validation path (`--schema` + the `jsonschema`
//! dependency) from the original standalone CLI is **dropped** here to keep the
//! example dep-light. Re-add it behind a feature if in-crate parity validation
//! is ever wanted.

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    imp::run()
}

#[cfg(not(target_os = "windows"))]
fn main() {}

#[cfg(target_os = "windows")]
mod imp {
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result, anyhow, bail};
    use clap::Parser;
    use openshell_driver_mxc::{
        DEFAULT_COMMAND, DEFAULT_CONTAINMENT, DEFAULT_MXC_VERSION, LossItem, MxcMappingOptions,
        build_loss_report, map_to_mxc, render_readme,
    };
    use serde_json::Value;

    #[derive(Parser)]
    #[command(about = "Map OpenShell policy YAML to a coarse MXC ContainerConfig JSON")]
    struct Args {
        /// `OpenShell` policy YAML to map.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Convert every `*policy*.yaml` file found recursively under this dir.
        #[arg(long)]
        examples_root: Option<PathBuf>,

        /// Output directory for a single `--policy` conversion.
        #[arg(long, default_value = "converted/single")]
        out_dir: PathBuf,

        /// Output root for `--examples-root` conversions.
        #[arg(long, default_value = "converted")]
        converted_root: PathBuf,

        #[arg(long, default_value = DEFAULT_MXC_VERSION)]
        mxc_version: String,

        #[arg(long, default_value = DEFAULT_CONTAINMENT)]
        containment: String,

        #[arg(long, default_value = DEFAULT_COMMAND)]
        command: String,

        #[arg(long)]
        container_id: Option<String>,

        #[arg(long)]
        cwd: Option<String>,

        /// `KEY=VALUE` environment variables.
        #[arg(long = "env", action = clap::ArgAction::Append)]
        env: Vec<String>,

        #[arg(long, default_value_t = 0)]
        timeout_ms: u64,

        /// Fail when a lossy mapping (any `error` item) would be emitted.
        #[arg(long)]
        strict: bool,

        /// Emit `OpenShell` wildcard hosts into `allowedHosts` despite lossiness.
        #[arg(long)]
        allow_wildcards: bool,
    }

    pub fn run() -> Result<()> {
        let args = Args::parse();

        if let Some(examples_root) = &args.examples_root {
            let mut examples = discover_example_policies(examples_root)?;
            if examples.is_empty() {
                bail!(
                    "No policy YAML files found under {}",
                    examples_root.display()
                );
            }
            examples.sort();
            let count = examples.len();
            for policy_path in &examples {
                let slug = slug_for_policy(examples_root, policy_path);
                let out_dir = args.converted_root.join(&slug);
                let options = build_options(&args, &slug);
                convert_policy(policy_path, &out_dir, &options, args.strict)?;
            }
            println!(
                "Converted {count} policy file(s) into {}",
                args.converted_root.display()
            );
            return Ok(());
        }

        let policy = args
            .policy
            .as_ref()
            .ok_or_else(|| anyhow!("Provide --policy or --examples-root"))?;
        let stem = policy
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let slug = args.container_id.clone().unwrap_or(stem);
        let options = build_options(&args, &slug);
        convert_policy(policy, &args.out_dir, &options, args.strict)?;
        println!(
            "Converted {} into {}",
            policy.display(),
            args.out_dir.display()
        );
        Ok(())
    }

    fn build_options(args: &Args, slug: &str) -> MxcMappingOptions {
        let container_id = args
            .container_id
            .clone()
            .unwrap_or_else(|| sanitize_container_id(&format!("openshell-{slug}")));
        MxcMappingOptions {
            mxc_version: args.mxc_version.clone(),
            containment: args.containment.clone(),
            command: args.command.clone(),
            container_id,
            cwd: args.cwd.clone(),
            env: args.env.clone(),
            timeout_ms: args.timeout_ms,
            allow_wildcards: args.allow_wildcards,
            proxy_localhost_port: None,
        }
    }

    fn convert_policy(
        policy_path: &Path,
        out_dir: &Path,
        options: &MxcMappingOptions,
        strict: bool,
    ) -> Result<()> {
        let content = std::fs::read_to_string(policy_path)
            .with_context(|| format!("reading {}", policy_path.display()))?;
        let policy = openshell_policy::parse_sandbox_policy(&content)
            .map_err(|e| anyhow!("parsing {}: {e}", policy_path.display()))?;

        let result = map_to_mxc(&policy, options);
        let error_count = result.loss.iter().filter(|i| i.severity == "error").count();

        write_outputs(policy_path, out_dir, options, &result.config, &result.loss)?;

        if strict && error_count > 0 {
            bail!(
                "Strict mapping failed for {}: {error_count} error(s)",
                policy_path.display()
            );
        }
        Ok(())
    }

    fn write_outputs(
        policy_path: &Path,
        out_dir: &Path,
        options: &MxcMappingOptions,
        config: &Value,
        items: &[LossItem],
    ) -> Result<()> {
        std::fs::create_dir_all(out_dir)
            .with_context(|| format!("creating output dir {}", out_dir.display()))?;

        let config_path = out_dir.join("mxc-config.json");
        let report_path = out_dir.join("loss-report.json");
        let readme_path = out_dir.join("README.md");

        let config_json = serde_json::to_string_pretty(config).context("serializing mxc config")?;
        std::fs::write(&config_path, format!("{config_json}\n"))
            .with_context(|| format!("writing {}", config_path.display()))?;

        let report = build_loss_report(
            &policy_path.display().to_string(),
            &config_path.display().to_string(),
            items,
            &[],
            &options.mxc_version,
            &options.containment,
            None,
        );
        let report_json =
            serde_json::to_string_pretty(&report).context("serializing loss report")?;
        std::fs::write(&report_path, format!("{report_json}\n"))
            .with_context(|| format!("writing {}", report_path.display()))?;

        let readme = render_readme(&policy_path.display().to_string(), &report, config);
        std::fs::write(&readme_path, readme)
            .with_context(|| format!("writing {}", readme_path.display()))?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // File discovery & slug helpers
    // -----------------------------------------------------------------------

    fn discover_example_policies(root: &Path) -> Result<Vec<PathBuf>> {
        let mut results = Vec::new();
        collect_policies(root, &mut results)?;
        Ok(results)
    }

    fn collect_policies(dir: &Path, results: &mut Vec<PathBuf>) -> Result<()> {
        for entry in
            std::fs::read_dir(dir).with_context(|| format!("reading dir {}", dir.display()))?
        {
            let path = entry?.path();
            if path.is_dir() {
                collect_policies(&path, results)?;
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && name.contains("policy")
                && path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("yaml"))
            {
                results.push(path);
            }
        }
        Ok(())
    }

    fn slug_for_policy(root: &Path, policy_path: &Path) -> String {
        const STANDARD_NAMES: &[&str] =
            &["policy.yaml", "sandbox-policy.yaml", "policy.template.yaml"];

        let relative = policy_path.strip_prefix(root).unwrap_or(policy_path);
        let parts: Vec<String> = relative
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let filename = policy_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();

        let use_parts: &[String] = if STANDARD_NAMES.contains(&filename.as_ref()) && parts.len() > 1
        {
            &parts[..parts.len() - 1]
        } else {
            &parts
        };

        let joined = if use_parts.is_empty() {
            policy_path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        } else {
            use_parts.join("-")
        };
        sanitize_container_id(&joined)
    }

    /// Replace any character outside `[A-Za-z0-9_.-]` with `-`, collapse runs of
    /// `-`, and trim leading/trailing `-`. Hand-rolled to avoid a `regex` dep.
    fn sanitize_container_id(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        for ch in raw.chars() {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
                out.push(ch);
            } else if !out.ends_with('-') {
                out.push('-');
            }
        }
        let trimmed = out.trim_matches('-');
        if trimmed.is_empty() {
            "openshell-policy".to_owned()
        } else {
            trimmed.to_owned()
        }
    }
}
