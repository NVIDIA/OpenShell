// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::sandbox::SandboxGuard;

const OPENAI_PROVIDER: &str = "e2e-sandbox-openai";
const ANTHROPIC_PROVIDER: &str = "e2e-sandbox-anthropic";

async fn run_cli(args: &[&str]) -> Result<String, String> {
    let mut cmd = openshell_cmd();
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd
        .output()
        .await
        .map_err(|e| format!("failed to spawn openshell {}: {e}", args.join(" ")))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    if !output.status.success() {
        return Err(format!(
            "openshell {} failed (exit {:?}):\n{combined}",
            args.join(" "),
            output.status.code()
        ));
    }

    Ok(combined)
}

async fn delete_provider(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.arg("provider")
        .arg("delete")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = cmd.status().await;
}

async fn create_mock_openai_provider() -> Result<(), String> {
    delete_provider(OPENAI_PROVIDER).await;
    run_cli(&[
        "provider",
        "create",
        "--name",
        OPENAI_PROVIDER,
        "--type",
        "openai",
        "--credential",
        "OPENAI_API_KEY=dummy",
        "--config",
        "OPENAI_BASE_URL=mock://e2e-openai",
    ])
    .await
    .map(|_| ())
}

async fn create_mock_anthropic_provider() -> Result<(), String> {
    delete_provider(ANTHROPIC_PROVIDER).await;
    run_cli(&[
        "provider",
        "create",
        "--name",
        ANTHROPIC_PROVIDER,
        "--type",
        "anthropic",
        "--credential",
        "ANTHROPIC_API_KEY=dummy",
        "--config",
        "ANTHROPIC_BASE_URL=mock://e2e-anthropic",
    ])
    .await
    .map(|_| ())
}

async fn set_sandbox_inference(sandbox: &str, provider: &str, model: &str) -> Result<(), String> {
    run_cli(&[
        "inference",
        "sandbox",
        "set",
        "--sandbox",
        sandbox,
        "--provider",
        provider,
        "--model",
        model,
    ])
    .await
    .map(|_| ())
}

async fn set_gateway_default(provider: &str, model: &str) -> Result<(), String> {
    run_cli(&["inference", "set", "--provider", provider, "--model", model])
        .await
        .map(|_| ())
}

async fn exec_in_sandbox(sandbox: &str, command: &[&str]) -> Result<String, String> {
    let mut args = vec![
        "sandbox",
        "exec",
        "--name",
        sandbox,
        "--timeout",
        "30",
        "--no-tty",
        "--",
    ];
    args.extend_from_slice(command);
    run_cli(&args).await
}

async fn wait_for_sandbox_output(
    sandbox: &str,
    command: &[&str],
    expected: &str,
) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..45 {
        match exec_in_sandbox(sandbox, command).await {
            Ok(output) => {
                if output.contains(expected) {
                    return Ok(output);
                }
                last = output;
            }
            Err(err) => {
                last = err;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Err(format!(
        "sandbox {sandbox} did not produce expected output {expected:?}. Last output:\n{last}"
    ))
}

#[tokio::test]
async fn sandbox_inference_overrides_isolate_openai_and_anthropic_sandboxes() {
    create_mock_openai_provider()
        .await
        .expect("create OpenAI-compatible mock provider");
    create_mock_anthropic_provider()
        .await
        .expect("create Anthropic-compatible mock provider");

    let mut openai_sandbox = SandboxGuard::create_keep(
        &["sh", "-lc", "echo openai-sandbox-ready; sleep 600"],
        "openai-sandbox-ready",
    )
    .await
    .expect("create first long-lived sandbox");

    set_sandbox_inference(
        &openai_sandbox.name,
        OPENAI_PROVIDER,
        "openai-sandbox-model",
    )
    .await
    .expect("set first sandbox inference override");

    let openai_command = [
        "curl",
        "--silent",
        "--show-error",
        "--max-time",
        "20",
        "https://inference.local/v1/chat/completions",
        "--json",
        r#"{"messages":[{"role":"user","content":"hello"}],"max_tokens":16}"#,
    ];

    wait_for_sandbox_output(
        &openai_sandbox.name,
        &openai_command,
        r#""model":"openai-sandbox-model""#,
    )
    .await
    .expect("first sandbox should route to its OpenAI-compatible override");

    let mut anthropic_sandbox = SandboxGuard::create_keep(
        &["sh", "-lc", "echo anthropic-sandbox-ready; sleep 600"],
        "anthropic-sandbox-ready",
    )
    .await
    .expect("create second long-lived sandbox");

    set_sandbox_inference(
        &anthropic_sandbox.name,
        ANTHROPIC_PROVIDER,
        "anthropic-sandbox-model",
    )
    .await
    .expect("set second sandbox inference override");

    // Simulate the old singleton failure mode: configuring another provider at
    // the gateway default must not change a sandbox with its own override.
    set_gateway_default(ANTHROPIC_PROVIDER, "gateway-default-anthropic-model")
        .await
        .expect("set gateway default to a different provider");

    let anthropic_command = [
        "curl",
        "--silent",
        "--show-error",
        "--max-time",
        "20",
        "https://inference.local/v1/messages",
        "--json",
        r#"{"messages":[{"role":"user","content":"hello"}],"max_tokens":16}"#,
    ];

    wait_for_sandbox_output(
        &anthropic_sandbox.name,
        &anthropic_command,
        r#""model":"anthropic-sandbox-model""#,
    )
    .await
    .expect("second sandbox should route to its Anthropic-compatible override");

    wait_for_sandbox_output(
        &openai_sandbox.name,
        &openai_command,
        r#""model":"openai-sandbox-model""#,
    )
    .await
    .expect("first sandbox should keep its OpenAI-compatible override after the gateway default changes");

    anthropic_sandbox.cleanup().await;
    openai_sandbox.cleanup().await;
}
