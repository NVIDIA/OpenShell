# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  fetchurl,
  lib,
  stdenv,
  zstd,
}:

let
  runtime =
    {
      x86_64-linux = {
        platform = "linux-x86_64";
        hash = "sha256-dJauQnv4L+rT003rJfFPbrJNsQwoWpX61X3GlBkuIog=";
        artifacts = [
          "libkrun.so"
          "libkrunfw.so.5"
          "umoci"
        ];
      };
      aarch64-linux = {
        platform = "linux-aarch64";
        hash = "sha256-VvqnmAClehcU1IifoZsd4XrSI6N2Hlu1dskNuPQxME4=";
        artifacts = [
          "libkrun.so"
          "libkrunfw.so.5"
          "umoci"
        ];
      };
      aarch64-darwin = {
        platform = "darwin-aarch64";
        hash = "sha256-orr16ZuCLQ5b2Uwg1NuobjLMpmxZjaGwmb+i/QZ5TZM=";
        artifacts = [
          "libkrun.dylib"
          "libkrunfw.5.dylib"
          "umoci"
        ];
      };
    }
    .${stdenv.hostPlatform.system};
  archive = fetchurl {
    url = "https://github.com/NVIDIA/OpenShell/releases/download/vm-runtime-capability-free/vm-runtime-${runtime.platform}.tar.zst";
    inherit (runtime) hash;
  };
in
stdenv.mkDerivation {
  name = "openshell-vm-runtime-${runtime.platform}";

  nativeBuildInputs = [ zstd ];
  dontUnpack = true;

  installPhase = ''
    runHook preInstall

    mkdir -p "$out"
    tar --extract --file ${archive} --directory "$out"
    mkdir -p "$out/compressed"
    for artifact in ${lib.escapeShellArgs runtime.artifacts}; do
      zstd -19 -T1 "$out/$artifact" -o "$out/compressed/$artifact.zst"
      test -s "$out/compressed/$artifact.zst"
      zstd --test --quiet "$out/compressed/$artifact.zst"
    done

    runHook postInstall
  '';
}
