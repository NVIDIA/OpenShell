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
        hash = "sha256-kA6ZQz53geBp2zHx8tv+D8VcGkSrnC74Op/60H4fmck=";
        artifacts = [
          "libkrun.so"
          "libkrunfw.so.5"
          "umoci"
        ];
      };
      aarch64-linux = {
        platform = "linux-aarch64";
        hash = "sha256-7FNqUtC6ixfw202EyoYCgZOLdyxJYfg/YzdlkTT/+sM=";
        artifacts = [
          "libkrun.so"
          "libkrunfw.so.5"
          "umoci"
        ];
      };
      aarch64-darwin = {
        platform = "darwin-aarch64";
        hash = "sha256-cPfogd7QiPFk76kR1JJeKLaWwFksAZ9BeW/LsmDgsjo=";
        artifacts = [
          "libkrun.dylib"
          "libkrunfw.5.dylib"
          "umoci"
        ];
      };
    }
    .${stdenv.hostPlatform.system};
  archive = fetchurl {
    url = "https://github.com/NVIDIA/OpenShell/releases/download/vm-runtime/vm-runtime-${runtime.platform}.tar.zst";
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
