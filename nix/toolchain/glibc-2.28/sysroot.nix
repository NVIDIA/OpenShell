# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  glibc,
  buildInputs ? [ ],
}:

let
  target = pkgs.stdenv.targetPlatform.config;

in
pkgs.buildEnv {
  name = "${target}-sysroot";
  paths = [
    glibc.out
    glibc.dev
    glibc.static
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
    # Rust explicitly links -lgcc_s, even with -static-libgcc.
    echo 'GROUP ( libgcc.a libgcc_eh.a )' > "$out/usr/lib/libgcc_s.a"

    # Linker scripts must resolve libraries through the sysroot, not the store.
    rm "$out/usr/lib/libc.so" "$out/usr/lib/libm.so"
    sed 's|${glibc.out}/lib/||g' ${glibc.out}/lib/libc.so > "$out/usr/lib/libc.so"
    sed 's|${glibc.out}/lib/||g' ${glibc.out}/lib/libm.so > "$out/usr/lib/libm.so"

    ln -s usr/lib "$out/lib"
    ln -s usr/lib "$out/lib64"
  '';
}
