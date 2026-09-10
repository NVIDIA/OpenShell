# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  glibc,
  runtime,
  buildInputs ? [ ],
}:

let
  target = pkgs.stdenv.targetPlatform.config;

in
pkgs.buildEnv {
  name = "${target}-sysroot";
  paths = [
    glibc
    runtime
    pkgs.linuxHeaders
  ]
  ++ pkgs.lib.concatMap (package: [
    (pkgs.lib.getDev package)
    (pkgs.lib.getLib package)
  ]) buildInputs;
  pathsToLink = [
    "/include"
    "/lib"
  ];
  extraPrefix = "/usr";

  postBuild = ''
    # Linker scripts must resolve libraries through the sysroot, not the store.
    rm "$out/usr/lib/libc.so" "$out/usr/lib/libm.so"
    sed 's|${glibc}/lib/||g' ${glibc}/lib/libc.so > "$out/usr/lib/libc.so"
    sed 's|${glibc}/lib/||g' ${glibc}/lib/libm.so > "$out/usr/lib/libm.so"

    ln -s usr/lib "$out/lib"
    ln -s usr/lib "$out/lib64"
  '';
}
