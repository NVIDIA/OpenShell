# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  lib,
  stdenv,
  z3,
}:

(z3.override {
  inherit stdenv;
  pythonBindings = false;
}).overrideAttrs
  (old: {
    cmakeFlags = old.cmakeFlags ++ [
      (lib.cmakeBool "Z3_BUILD_LIBZ3_SHARED" false)
    ];
    doCheck = false;
    doInstallCheck = false;
  })
