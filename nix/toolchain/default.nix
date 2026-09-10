# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  mkToolchain =
    {
      pkgs,
      buildInputs,
    }:

    let
      strings = pkgs.callPackage ../strings.nix { };
      platform =
        pkgs.callPackage (if pkgs.stdenv.hostPlatform.isDarwin then ./darwin.nix else ./linux.nix)
          {
            inherit packages;
          };
      inherit (platform) stdenv sysroot;
      target = stdenv.hostPlatform.rust.cargoShortTarget;
      packages = buildInputs { inherit pkgs stdenv; };
      toolchain = platform.driver;
      binPrefix =
        "${stdenv.cc.bintools}/bin/"
        + pkgs.lib.optionalString (!stdenv.hostPlatform.isDarwin) stdenv.cc.targetPrefix;
    in
    toolchain.overrideAttrs (old: {
      passthru = (old.passthru or { }) // {
        inherit target stdenv sysroot;
        buildInputs = packages;
        env = pkgs.lib.foldl' (env: package: env // (package.passthru.env or { })) { } packages // {
          ${strings.cargoTargetEnvVar target "LINKER"} = "${toolchain}/bin/${target}-cc";
          ${strings.targetEnvVar target "CC"} = "${toolchain}/bin/${target}-cc";
          ${strings.targetEnvVar target "AS"} = "${binPrefix}as";
          ${strings.targetEnvVar target "AR"} = "${binPrefix}ar";
        };
      };
    });
}
