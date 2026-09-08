# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  rust-overlay,
  commonDevShellPackages,
}:

import ./cross-rust.nix {
  inherit pkgs rust-overlay commonDevShellPackages;
  rustTarget = "aarch64-unknown-linux-musl";
}
