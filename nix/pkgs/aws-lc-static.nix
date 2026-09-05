# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  aws-lc,
  rust-bindgen,
  stdenv,
}:

aws-lc.override {
  inherit stdenv rust-bindgen;
  useSharedLibraries = false;
  withRustBindings = true;
}
