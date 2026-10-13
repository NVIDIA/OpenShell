// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rendered help and command-shape checks for the `openshell` binary.

mod common;

use common::run_isolated;

#[test]
fn root_help_shows_top_level_commands() {
    let output = run_isolated(&["--help"]);
    assert_eq!(output.code, 0, "openshell --help:\n{}", output.combined);

    for command in [
        "gateway", "status", "sandbox", "forward", "logs", "policy", "agent",
    ] {
        assert!(
            output.combined.contains(command),
            "expected '{command}' in openshell --help:\n{}",
            output.combined
        );
    }
}

#[test]
fn gateway_help_shows_registration_commands_and_omits_lifecycle_commands() {
    let output = run_isolated(&["gateway", "--help"]);
    assert_eq!(output.code, 0, "gateway --help:\n{}", output.combined);

    for command in ["add", "remove", "login", "logout", "select", "info", "list"] {
        assert!(
            output.combined.contains(command),
            "expected '{command}' in gateway --help:\n{}",
            output.combined
        );
    }
    for removed in ["start", "stop", "destroy"] {
        assert!(
            !output.combined.contains(removed),
            "unexpected removed command '{removed}' in gateway --help:\n{}",
            output.combined
        );
    }
}

#[test]
fn sandbox_help_shows_transfer_and_lifecycle_commands() {
    let output = run_isolated(&["sandbox", "--help"]);
    assert_eq!(output.code, 0, "sandbox --help:\n{}", output.combined);

    for command in [
        "upload", "download", "create", "get", "list", "delete", "connect",
    ] {
        assert!(
            output.combined.contains(command),
            "expected '{command}' in sandbox --help:\n{}",
            output.combined
        );
    }
}

#[test]
fn sandbox_create_help_shows_creation_flags() {
    let output = run_isolated(&["sandbox", "create", "--help"]);
    assert_eq!(
        output.code, 0,
        "sandbox create --help:\n{}",
        output.combined
    );

    for flag in [
        "--gpu",
        "--upload",
        "--no-git-ignore",
        "--editor",
        "--auto-providers",
        "--no-auto-providers",
    ] {
        assert!(
            output.combined.contains(flag),
            "expected '{flag}' in sandbox create --help:\n{}",
            output.combined
        );
    }
}

#[test]
fn sandbox_connect_help_shows_editor_flag() {
    let output = run_isolated(&["sandbox", "connect", "--help"]);
    assert_eq!(
        output.code, 0,
        "sandbox connect --help:\n{}",
        output.combined
    );
    assert!(output.combined.contains("--editor"), "{}", output.combined);
}

#[test]
fn gateway_add_help_shows_endpoint_and_gateway_type_flags() {
    let output = run_isolated(&["gateway", "add", "--help"]);
    assert_eq!(output.code, 0, "gateway add --help:\n{}", output.combined);

    for expected in ["--name", "--remote", "--local"] {
        assert!(
            output.combined.contains(expected),
            "expected '{expected}' in gateway add --help:\n{}",
            output.combined
        );
    }
    assert!(
        output.combined.contains("endpoint") || output.combined.contains("<ENDPOINT>"),
        "expected endpoint argument in gateway add --help:\n{}",
        output.combined
    );
}

#[test]
fn gateway_login_help_describes_authentication() {
    let output = run_isolated(&["gateway", "login", "--help"]);
    assert_eq!(output.code, 0, "gateway login --help:\n{}", output.combined);

    let help = output.combined.to_lowercase();
    assert!(
        ["authenticat", "cloudflare", "login", "browser"]
            .iter()
            .any(|term| help.contains(term)),
        "expected auth-related gateway login help:\n{}",
        output.combined
    );
}

#[test]
fn removed_gateway_lifecycle_subcommands_fail_to_parse() {
    for command in ["start", "stop", "destroy"] {
        let output = run_isolated(&["gateway", command, "--help"]);
        assert_ne!(
            output.code, 0,
            "gateway {command} should fail after lifecycle command removal"
        );
        assert!(
            output.combined.contains("unrecognized subcommand")
                || output.combined.contains("error:"),
            "expected parser error for gateway {command}:\n{}",
            output.combined
        );
    }
}

#[test]
fn gateway_add_rejects_conflicting_type_flags() {
    let conflicting = run_isolated(&[
        "gateway",
        "add",
        "https://example.com",
        "--remote",
        "user@host",
        "--local",
    ]);
    assert_ne!(
        conflicting.code, 0,
        "--remote and --local should conflict:\n{}",
        conflicting.combined
    );
}

#[test]
fn gateway_add_rejects_removed_ssh_key_flag() {
    let removed = run_isolated(&[
        "gateway",
        "add",
        "https://example.com",
        "--ssh-key",
        "/tmp/fake-key",
    ]);
    assert_ne!(
        removed.code, 0,
        "removed --ssh-key flag should fail:\n{}",
        removed.combined
    );
}

/// Upper bound for the agent map. Agent harnesses cap a single tool result
/// (Claude Code moves output over 30,000 characters to a file and shows a
/// preview), so the map must stay well under that to be read in one call.
/// If this fails, leave detail to `--help` rather than raising the bound.
const AGENT_CONTEXT_BUDGET_BYTES: usize = 25_000;

#[test]
fn agent_context_prints_compact_map_for_every_command() {
    // Force color to prove the map stays plain even when styling is on.
    let output = run_isolated(&["--color", "always", "agent", "context"]);
    assert_eq!(output.code, 0, "agent context:\n{}", output.combined);
    let reference = &output.stdout;

    for expected in [
        "## Global flags",
        "## sandbox: Manage sandboxes (alias: sb)",
        "\nopenshell sandbox create [OPTIONS] [-- <COMMAND>...]  # Create a sandbox\n",
        "\n  --from <FROM>  [conflicts: --template]\n",
        "\n  --upload <UPLOAD>  [repeatable] [conflicts: <COMMAND>...]\n",
        "\n  -o, --output <table|yaml|json>  [default: table]\n",
        "\nopenshell sandbox provider attach ",
        "\nopenshell provider refresh configure ",
        "\nopenshell workspace member add ",
        "\nopenshell agent context ",
        "  $ openshell sandbox create",
    ] {
        assert!(
            reference.contains(expected),
            "expected '{expected}' in agent context:\n{reference}"
        );
    }
    for unexpected in ["doctor", "ssh-proxy", "  --keep ", "\x1b"] {
        assert!(
            !reference.contains(unexpected),
            "unexpected '{unexpected}' in agent context:\n{reference}"
        );
    }
    assert!(
        reference.len() <= AGENT_CONTEXT_BUDGET_BYTES,
        "agent context is {} bytes, over the {AGENT_CONTEXT_BUDGET_BYTES}-byte budget",
        reference.len()
    );
}

#[test]
fn agent_context_rejects_arguments() {
    let output = run_isolated(&["agent", "context", "sandbox"]);
    assert_ne!(
        output.code, 0,
        "agent context takes no arguments:\n{}",
        output.combined
    );
}

#[test]
fn agent_without_subcommand_prints_group_help() {
    let output = run_isolated(&["agent"]);
    assert_eq!(output.code, 0, "agent:\n{}", output.combined);
    assert!(
        output.combined.contains("context"),
        "expected context subcommand in agent help:\n{}",
        output.combined
    );
}
