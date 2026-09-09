// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Loss-report JSON and human-readable README rendering.

use serde_json::{Value, json};

use super::loss::{LossItem, OPEN_SHELL_SUPERSET_GAPS, summarize_missing_mxc};

/// Build the structured `loss-report.json` value.
pub fn build_loss_report(
    source_policy: &str,
    generated_config: &str,
    items: &[LossItem],
    schema_errors: &[LossItem],
    mxc_version: &str,
    containment: &str,
    schema: Option<&str>,
) -> Value {
    let count = |severity: &str| items.iter().filter(|i| i.severity == severity).count();

    json!({
        "sourcePolicy": source_policy,
        "generatedConfig": generated_config,
        "target": {
            "schemaVersion": mxc_version,
            "containment": containment,
        },
        "schemaValidation": {
            "schema": schema,
            "valid": schema_errors.is_empty(),
        },
        "lossy": !items.is_empty(),
        "counts": {
            "error": count("error"),
            "warning": count("warning"),
            "info": count("info"),
        },
        "items": items,
        "openShellFieldsNotInMxc": summarize_missing_mxc(items),
        "mxcFieldsNotInOpenShellPolicy": OPEN_SHELL_SUPERSET_GAPS,
    })
}

/// Render the human-readable `README.md` summarizing the mapping.
pub fn render_readme(source_policy: &str, report: &Value, config: &Value) -> String {
    let container_id = config["containerId"].as_str().unwrap_or("");
    let containment = config["containment"].as_str().unwrap_or("");
    let schema_valid = report["schemaValidation"]["valid"]
        .as_bool()
        .unwrap_or(false);

    let join_strs = |value: &Value| -> String {
        let parts: Vec<&str> = value
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if parts.is_empty() {
            "(none)".to_owned()
        } else {
            parts.join(", ")
        }
    };

    let allowed = join_strs(&config["network"]["allowedHosts"]);
    let rw = join_strs(&config["filesystem"]["readwritePaths"]);
    let ro = join_strs(&config["filesystem"]["readonlyPaths"]);

    let mut lines: Vec<String> = vec![
        format!("# {container_id}"),
        String::new(),
        "## Generated Files".to_owned(),
        String::new(),
        format!(
            "- `mxc-config.json`: direct MXC `ContainerConfig` generated from `{source_policy}`."
        ),
        "- `loss-report.json`: structured mapping loss report.".to_owned(),
        String::new(),
        "## MXC Consumption".to_owned(),
        String::new(),
        "The generated config is intended to be consumable by MXC's direct JSON path.".to_owned(),
        "It uses a harmless placeholder `process.commandLine`; replace it with the".to_owned(),
        "real workload command before running anything meaningful.".to_owned(),
        String::new(),
        format!("- Containment: `{containment}`"),
        format!("- Schema validation: `{schema_valid}`"),
        format!("- Allowed hosts: `{allowed}`"),
        format!("- Read-write paths: `{rw}`"),
        format!("- Read-only paths: `{ro}`"),
        String::new(),
        "## Missing In MXC For This OpenShell Policy".to_owned(),
        String::new(),
    ];

    let notable: Vec<&Value> = report["items"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|item| matches!(item["severity"].as_str(), Some("error" | "warning")))
                .collect()
        })
        .unwrap_or_default();

    if notable.is_empty() {
        lines.push("- No lossy OpenShell-to-MXC policy mappings were detected.".to_owned());
    } else {
        for item in notable {
            lines.push(format!(
                "- `{}` `{}`: {} Impact: {}",
                item["severity"].as_str().unwrap_or(""),
                item["path"].as_str().unwrap_or(""),
                item["message"].as_str().unwrap_or(""),
                item["mxc_impact"].as_str().unwrap_or(""),
            ));
        }
    }

    lines.extend([
        String::new(),
        "## Missing In OpenShell Policy For MXC".to_owned(),
        String::new(),
    ]);
    if let Some(gaps) = report["mxcFieldsNotInOpenShellPolicy"].as_array() {
        for gap in gaps.iter().filter_map(Value::as_str) {
            lines.push(format!("- {gap}"));
        }
    }

    lines.extend([
        String::new(),
        "## Notes".to_owned(),
        String::new(),
        "- OpenShell network policies are binary-, port-, protocol-, and often L7-scoped.".to_owned(),
        "- This coarse mapper emits only MXC host/IP/CIDR allowlists plus filesystem lists.".to_owned(),
        "- Treat any `error` item in the loss report as a semantic broadening or unsupported parity gap.".to_owned(),
        String::new(),
    ]);

    lines.join("\n")
}
