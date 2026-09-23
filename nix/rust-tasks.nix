# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  rustToolchain,
  toolchains,
}:

let
  toolchainEnv = pkgs.lib.foldl' (env: toolchain: env // toolchain.env) { } (
    builtins.attrValues toolchains
  );

  mkRustTask =
    {
      name,
      runtimeInputs ? [ ],
      runtimeEnv ? { },
      text,
    }:
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = [
        pkgs.git
        rustToolchain
      ]
      ++ runtimeInputs;
      runtimeEnv = toolchainEnv // runtimeEnv;
      text = ''
        root=$(git rev-parse --show-toplevel)
        cd "$root"

        ${text}
      '';
    };
in
{
  check = mkRustTask {
    name = "openshell-rust-check";
    text = ''
      cargo check --locked --workspace
      cargo check --locked -p openshell-sandbox --all-targets --features perf-harness
    '';
  };

  lockfiles = mkRustTask {
    name = "openshell-cargo-lockfiles";
    text = ''
      tasks/scripts/check-cargo-lockfiles.sh
    '';
  };

  lint = mkRustTask {
    name = "openshell-rust-lint";
    text = ''
      cargo clippy --locked --workspace --all-targets -- -D warnings
      cargo clippy --locked -p openshell-sandbox --all-targets --features perf-harness -- -D warnings
      cargo clippy --locked --manifest-path e2e/rust/Cargo.toml --all-targets -- -D warnings
      cargo clippy --locked --manifest-path examples/governance-interceptor/Cargo.toml --all-targets -- -D warnings
      cargo clippy --locked --manifest-path examples/supervisor-middleware-content-guard/Cargo.toml --all-targets -- -D warnings
    '';
  };

  formatCheck = mkRustTask {
    name = "openshell-rust-format-check";
    text = ''
      cargo fmt --all -- --check
      cargo fmt --manifest-path e2e/rust/Cargo.toml --all -- --check
      cargo fmt --manifest-path examples/governance-interceptor/Cargo.toml --all -- --check
      cargo fmt --manifest-path examples/supervisor-middleware-content-guard/Cargo.toml --all -- --check
    '';
  };

  denyPolicy = mkRustTask {
    name = "openshell-rust-deny-policy";
    runtimeInputs = [ pkgs.cargo-deny ];
    text = ''
      cargo deny check licenses bans sources
    '';
  };

  test = mkRustTask {
    name = "openshell-rust-test";
    runtimeInputs = [
      pkgs.cargo-nextest
      pkgs.e2fsprogs
    ];
    runtimeEnv.OPENSHELL_TELEMETRY_ENABLED = "false";
    text = ''
      cargo nextest run --locked --profile ci --workspace --features openshell-server/test-support
      cargo nextest run --locked --config-file .config/nextest.toml --profile ci --manifest-path examples/supervisor-middleware-content-guard/Cargo.toml
    '';
  };
}
