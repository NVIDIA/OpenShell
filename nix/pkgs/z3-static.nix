# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ z3, stdenv }:

(z3.override {
  inherit stdenv;
  pythonBindings = false;
}).overrideAttrs
  (old: {
    cmakeFlags = old.cmakeFlags ++ [ "-DZ3_BUILD_LIBZ3_SHARED=OFF" ];
  })
