# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ lib }:

let
  targetSuffix = builtins.replaceStrings [ "-" ] [ "_" ];
in
{
  targetEnvVar = target: name: "${name}_${targetSuffix target}";
  cargoTargetEnvVar = target: name: "CARGO_TARGET_${lib.toUpper (targetSuffix target)}_${name}";
}
