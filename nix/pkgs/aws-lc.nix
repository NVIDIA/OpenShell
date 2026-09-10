# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  lib,
  stdenv,
  aws-lc,
  buildEnv,
  callPackage,
}:

let
  strings = callPackage ../strings.nix { };
  target = stdenv.hostPlatform.rust.cargoShortTarget;
  package =
    (aws-lc.override {
      inherit stdenv;
      useSharedLibraries = false;
      withRustBindings = true;
    }).overrideAttrs
      (old: {
        BINDGEN_EXTRA_CLANG_ARGS = "--target=${target}";
        passthru = old.passthru // {
          env.${strings.targetEnvVar target "AWS_LC_SYS_SYSTEM_DIR"} = "${libraries}";
        };
      });
  libraries = buildEnv {
    name = "${target}-aws-lc-libraries";
    paths = [
      (lib.getLib package)
      (lib.getDev package)
    ];
    pathsToLink = [
      "/include"
      "/lib"
      "/share/rust"
    ];
  };
in
package
