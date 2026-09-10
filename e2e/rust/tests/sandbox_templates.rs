// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E coverage for reusable sandbox workload templates.

use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use openshell_e2e::harness::binary::{openshell_bin, openshell_cmd};
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;

struct CliResult {
    output: String,
    success: bool,
}

struct TemplateGuard {
    name: String,
}

impl TemplateGuard {
    fn new(name: String) -> Self {
        Self { name }
    }

    async fn cleanup(mut self) {
        delete_template(&self.name).await;
        self.name.clear();
    }
}

impl Drop for TemplateGuard {
    fn drop(&mut self) {
        if self.name.is_empty() {
            return;
        }
        let bin = openshell_bin();
        let _ = std::process::Command::new(&bin)
            .args(["sandbox", "template", "delete", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

async fn run_cli(args: &[&str]) -> CliResult {
    let mut cmd = openshell_cmd();
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell command");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    CliResult {
        output: strip_ansi(&combined),
        success: output.status.success(),
    }
}

async fn delete_template(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.args(["sandbox", "template", "delete", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = cmd.status().await;
}

fn unique_name(prefix: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis();
    let suffix = millis % 1_000_000;
    format!("{prefix}-{suffix:06}")
}

fn output_contains(output: &str, needle: &str) -> bool {
    output.to_lowercase().contains(&needle.to_lowercase())
}

fn output_mentions_template_not_found(output: &str) -> bool {
    output_contains(output, "sandbox template") && output_contains(output, "not found")
}

#[tokio::test]
async fn sandbox_create_from_template_uses_reusable_workload() {
    let template_name = unique_name("tmpl");
    let sandbox_name = unique_name("sb-tmpl");
    let template = TemplateGuard::new(template_name.clone());

    let create_template = run_cli(&[
        "sandbox",
        "template",
        "create",
        &template_name,
        "--cpu",
        "500m",
        "--memory",
        "512Mi",
        "--label",
        "e2e=sandbox-template",
        "--env",
        "FEATURE_FLAG=on",
    ])
    .await;
    assert!(
        create_template.success,
        "sandbox template create failed:\n{}",
        create_template.output
    );

    let get_template = run_cli(&[
        "sandbox",
        "template",
        "get",
        &template_name,
        "--output",
        "json",
    ])
    .await;
    assert!(
        get_template.success,
        "sandbox template get failed:\n{}",
        get_template.output
    );
    let template_json: Value =
        serde_json::from_str(&get_template.output).expect("template JSON output");
    assert_eq!(template_json["name"].as_str(), Some(template_name.as_str()));
    assert_eq!(
        template_json["labels"]["e2e"].as_str(),
        Some("sandbox-template")
    );
    assert_eq!(
        template_json["environment"]["FEATURE_FLAG"].as_str(),
        Some("on")
    );
    assert_eq!(template_json["resources"]["cpu"].as_str(), Some("500m"));
    assert_eq!(template_json["resources"]["memory"].as_str(), Some("512Mi"));

    let list_templates = run_cli(&["sandbox", "template", "list", "--names"]).await;
    assert!(
        list_templates.success,
        "sandbox template list failed:\n{}",
        list_templates.output
    );
    assert!(
        list_templates
            .output
            .lines()
            .any(|line| line.trim() == template_name),
        "template list should include {template_name}:\n{}",
        list_templates.output
    );

    let mut sandbox = SandboxGuard::create(&[
        "--name",
        &sandbox_name,
        "--template",
        &template_name,
        "--",
        "sh",
        "-lc",
        "test \"$FEATURE_FLAG\" = on && echo template-env-ok",
    ])
    .await
    .expect("sandbox create from template should succeed");

    assert!(
        sandbox.create_output.contains("template-env-ok"),
        "sandbox should inherit template environment:\n{}",
        sandbox.create_output
    );

    sandbox.cleanup().await;
    template.cleanup().await;
}

#[tokio::test]
async fn sandbox_template_get_after_delete_returns_not_found() {
    let template_name = unique_name("tmpl-del");
    let template = TemplateGuard::new(template_name.clone());

    let create_template = run_cli(&["sandbox", "template", "create", &template_name]).await;
    assert!(
        create_template.success,
        "sandbox template create failed:\n{}",
        create_template.output
    );

    let delete_template = run_cli(&["sandbox", "template", "delete", &template_name]).await;
    assert!(
        delete_template.success,
        "sandbox template delete failed:\n{}",
        delete_template.output
    );

    let get_deleted = run_cli(&["sandbox", "template", "get", &template_name]).await;
    assert!(
        !get_deleted.success,
        "deleted template should not be fetchable:\n{}",
        get_deleted.output
    );
    assert!(
        output_mentions_template_not_found(&get_deleted.output),
        "deleted template should return not-found:\n{}",
        get_deleted.output
    );

    template.cleanup().await;
}

#[tokio::test]
async fn sandbox_template_create_rejects_duplicate_name() {
    let template_name = unique_name("tmpl-dupe");
    let template = TemplateGuard::new(template_name.clone());

    let create_template = run_cli(&["sandbox", "template", "create", &template_name]).await;
    assert!(
        create_template.success,
        "sandbox template create failed:\n{}",
        create_template.output
    );

    let duplicate = run_cli(&["sandbox", "template", "create", &template_name]).await;
    assert!(
        !duplicate.success,
        "duplicate sandbox template create should fail:\n{}",
        duplicate.output
    );
    assert!(
        output_contains(&duplicate.output, "already exists"),
        "duplicate sandbox template create should report already-exists:\n{}",
        duplicate.output
    );

    template.cleanup().await;
}

#[tokio::test]
async fn sandbox_create_from_missing_template_returns_not_found() {
    let template_name = unique_name("tmpl-missing");
    let sandbox_name = unique_name("sb-missing");

    let create_sandbox = run_cli(&[
        "sandbox",
        "create",
        "--name",
        &sandbox_name,
        "--template",
        &template_name,
        "--",
        "true",
    ])
    .await;

    if create_sandbox.success {
        let _ = run_cli(&["sandbox", "delete", &sandbox_name]).await;
    }

    assert!(
        !create_sandbox.success,
        "sandbox create from missing template should fail:\n{}",
        create_sandbox.output
    );
    assert!(
        output_mentions_template_not_found(&create_sandbox.output),
        "sandbox create from missing template should report not-found:\n{}",
        create_sandbox.output
    );
}
