# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  packages,
}:

let
  target = pkgs.stdenv.hostPlatform.rust.cargoShortTarget;
  isMusl = pkgs.stdenv.hostPlatform.isMusl;
  gnu = pkgs.callPackage ./glibc-2.28/stdenv.nix { };
  stdenv = if isMusl then pkgs.stdenv else gnu.stdenv;
  sysroot =
    if isMusl then
      null
    else
      pkgs.callPackage ./glibc-2.28/sysroot.nix {
        buildInputs = packages;
        inherit (gnu) glibc runtime;
      };
  cc = if isMusl then stdenv.cc else gnu.gcc;
  searchFlags =
    pkgs.lib.optionals (!isMusl) [
      "--sysroot=${sysroot}"
      "-isystem${sysroot}/usr/include"
      "-B${sysroot}/usr/lib"
      "-L${sysroot}/usr/lib"
    ]
    ++ pkgs.lib.optionals isMusl (map (package: "-L${pkgs.lib.getLib package}/lib") packages);
  runtimeFlags = pkgs.lib.optionals (!isMusl) [
    "-static-libgcc"
    "-lssp"
  ];
in
{
  inherit stdenv sysroot;
  driver = pkgs.buildPackages.writeShellScriptBin "${target}-cc" ''
    exec ${cc}/bin/${stdenv.cc.targetPrefix}gcc \
      -B${pkgs.buildPackages.mold-unwrapped}/bin \
      -B${pkgs.buildPackages.binutils-unwrapped}/${target}/bin \
      ${pkgs.lib.escapeShellArgs searchFlags} \
      "$@" \
      -fuse-ld=mold ${pkgs.lib.escapeShellArgs runtimeFlags}
  '';
}
