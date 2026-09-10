# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  packages,
}:

let
  inherit (pkgs) stdenv;
  target = stdenv.hostPlatform.rust.cargoShortTarget;
  # The processed Nix SDK removes system stubs such as libiconv and libc++.
  sysroot = pkgs.apple-sdk.src;
in
{
  inherit stdenv sysroot;
  driver = pkgs.buildPackages.writeShellScriptBin "${target}-cc" ''
    exec ${stdenv.cc.cc}/bin/clang \
      "$@" \
      --target=${target} \
      -isysroot ${sysroot} \
      -mmacosx-version-min=${stdenv.hostPlatform.darwinMinVersion} \
      -fuse-ld=${stdenv.cc.bintools.bintools}/bin/ld \
      ${pkgs.lib.escapeShellArgs (map (package: "-L${pkgs.lib.getLib package}/lib") packages)}
  '';
}
