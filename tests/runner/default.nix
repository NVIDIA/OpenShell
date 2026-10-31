# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  lib,
  OVMF,
  rustPlatform,
  stdenv,
}:

rustPlatform.buildRustPackage {
  pname = "openshell-test-runner";
  version = "0.0.0";

  # The runner and the tmachine crate it depends on by path, and nothing else,
  # so edits to the suites or the Ansible tree do not rebuild it.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
      ../tmachine/Cargo.toml
      ../tmachine/src
    ];
  };
  cargoRoot = "runner";
  buildAndTestSubdir = "runner";
  cargoLock.lockFile = ./Cargo.lock;

  # tmachine compiles the firmware paths in.
  env = lib.optionalAttrs stdenv.hostPlatform.isAarch64 {
    TMACHINE_FIRMWARE_CODE = OVMF.firmware;
    TMACHINE_FIRMWARE_VARS = OVMF.variables;
  };
}
