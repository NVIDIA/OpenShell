// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! Smoke validations for first-class sandbox tool flows.
//!
//! These tests intentionally stay small: they verify that the recognized tool
//! binary exists in the sandbox, that the expected provider can be auto-created
//! from local credentials, and that the sandbox sees only the projected
//! placeholder value rather than the raw secret. For both `claude` and
//! `opencode`, this covers the current placeholder-projection contract rather
//! than full vendor-native Anthropic or GitHub Copilot execution parity.

use std::process::Stdio;
use std::sync::Mutex;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::{extract_field, strip_ansi};

const ANTHROPIC_TEST_API_KEY: &str = "sk-e2e-tool-smoke-anthropic";
const ANTHROPIC_PLACEHOLDER: &str = "openshell:resolve:env:ANTHROPIC_API_KEY";
const GITHUB_TEST_TOKEN: &str = "ghu-e2e-tool-smoke-github";
const GITHUB_PLACEHOLDER: &str = "openshell:resolve:env:GITHUB_TOKEN";

static CLAUDE_PROVIDER_LOCK: Mutex<()> = Mutex::new(());
static GITHUB_PROVIDER_LOCK: Mutex<()> = Mutex::new(());

async fn delete_provider(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.arg("provider")
        .arg("delete")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = cmd.status().await;
}

async fn provider_exists(name: &str) -> bool {
    let mut cmd = openshell_cmd();
    cmd.arg("provider")
        .arg("get")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.status().await.is_ok_and(|status| status.success())
}

async fn delete_sandbox(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.arg("sandbox")
        .arg("delete")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = cmd.status().await;
}

fn sandbox_name(output: &str) -> Option<String> {
    extract_field(output, "Created sandbox").or_else(|| extract_field(output, "Name"))
}

async fn run_tool_smoke(
    provider: &str,
    command: &str,
    env_key: &str,
    env_value: &str,
) -> (String, i32, Option<String>) {
    let mut cmd = openshell_cmd();
    cmd.arg("sandbox")
        .arg("create")
        .arg("--provider")
        .arg(provider)
        .arg("--auto-providers")
        .arg("--no-bootstrap")
        .arg("--")
        .arg("sh")
        .arg("-lc")
        .arg(command)
        .env(env_key, env_value)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell sandbox create");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    let code = output.status.code().unwrap_or(-1);
    (combined.clone(), code, sandbox_name(&combined))
}

#[tokio::test]
async fn claude_code_smoke_with_anthropic_provider() {
    let _provider_lock = CLAUDE_PROVIDER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    assert!(
        !provider_exists("claude").await,
        "existing provider 'claude' makes this smoke test unsafe; remove the shared provider and rerun so the auto-create assertions execute"
    );

    let (output, code, created_sandbox) = run_tool_smoke(
        "claude",
        "command -v claude >/dev/null && (claude --version >/dev/null 2>&1 || claude --help >/dev/null 2>&1) && printenv ANTHROPIC_API_KEY",
        "ANTHROPIC_API_KEY",
        ANTHROPIC_TEST_API_KEY,
    )
    .await;

    if let Some(name) = created_sandbox {
        delete_sandbox(&name).await;
    }
    delete_provider("claude").await;

    let clean = strip_ansi(&output);
    assert_eq!(code, 0, "claude tool smoke should succeed:\n{clean}");
    assert!(
        clean.contains("Created provider claude"),
        "output should confirm claude provider auto-creation:\n{clean}"
    );
    assert!(
        clean.contains(ANTHROPIC_PLACEHOLDER),
        "sandbox should expose the Anthropic placeholder to the tool flow:\n{clean}"
    );
    assert!(
        !clean.contains(ANTHROPIC_TEST_API_KEY),
        "sandbox must not expose the raw Anthropic secret:\n{clean}"
    );
}

#[tokio::test]
async fn opencode_smoke_with_current_github_copilot_targeted_path() {
    let _provider_lock = GITHUB_PROVIDER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    assert!(
        !provider_exists("github").await,
        "existing provider 'github' makes this smoke test unsafe; remove the shared provider and rerun so the auto-create assertions execute"
    );

    let (output, code, created_sandbox) = run_tool_smoke(
        "github",
        "command -v opencode >/dev/null && (opencode --version >/dev/null 2>&1 || opencode --help >/dev/null 2>&1) && printenv GITHUB_TOKEN",
        "GITHUB_TOKEN",
        GITHUB_TEST_TOKEN,
    )
    .await;

    if let Some(name) = created_sandbox {
        delete_sandbox(&name).await;
    }
    delete_provider("github").await;

    let clean = strip_ansi(&output);
    assert_eq!(
        code, 0,
        "opencode smoke for the current GitHub/Copilot-targeted path should succeed:\n{clean}"
    );
    assert!(
        clean.contains("Created provider github"),
        "output should confirm github provider auto-creation for the current Copilot-targeted path:\n{clean}"
    );
    assert!(
        clean.contains(GITHUB_PLACEHOLDER),
        "sandbox should expose the GitHub placeholder for the current Copilot-targeted path:\n{clean}"
    );
    assert!(
        !clean.contains(GITHUB_TEST_TOKEN),
        "sandbox must not expose the raw GitHub token:\n{clean}"
    );
}
