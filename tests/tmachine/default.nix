# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  lib,
  OVMF,
  rustPlatform,
  stdenv,
}:

rustPlatform.buildRustPackage {
  pname = "tmachine";
  version = "0.1.0";

  src = lib.cleanSource ./.;
  cargoLock.lockFile = ./Cargo.lock;

  env = lib.optionalAttrs stdenv.hostPlatform.isAarch64 {
    TMACHINE_FIRMWARE_CODE = OVMF.firmware;
    TMACHINE_FIRMWARE_VARS = OVMF.variables;
  };
}
