# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  fetchurl,
  stdenv,
  zstd,
}:

let
  runtime =
    {
      x86_64-linux = {
        platform = "linux-x86_64";
        hash = "sha256-dw3Lc7IapCyNeE7j6dnlgd/b8Yc91/7IOi3XJORyILQ=";
      };
      aarch64-linux = {
        platform = "linux-aarch64";
        hash = "sha256-aJDuDb7AsuH9R+AyXA/JIxE9fJmZ5kP0Lkhg6F0Ot5A=";
      };
      aarch64-darwin = {
        platform = "darwin-aarch64";
        hash = "sha256-BDSeY5XGDozaBZzHTiQQX90jzsSc6shJZs5zdzludX0=";
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

    runHook postInstall
  '';
}
