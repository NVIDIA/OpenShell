# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  rustToolchain,
  toolchains,
}:

let
  isAarch64 = pkgs.stdenv.hostPlatform.isAarch64;
  gnuToolchain = toolchains.${if isAarch64 then "aarch64-gnu" else "x86_64-gnu"};
  muslToolchain = toolchains.${if isAarch64 then "aarch64-musl" else "x86_64-musl"};
  dockerArch = if isAarch64 then "arm64" else "amd64";
  toolchainEnv = pkgs.lib.foldl' (env: toolchain: env // toolchain.env) { } (
    builtins.attrValues toolchains
  );
in
pkgs.writeShellApplication {
  name = "tmachine-artifacts";
  runtimeInputs = [
    pkgs.docker-client
    pkgs.git
    rustToolchain
  ];
  runtimeEnv = toolchainEnv;
  text = ''
    root=$(git rev-parse --show-toplevel)
    cd "$root"

    cargo build --target ${muslToolchain.target} \
      -p openshell-cli \
      -p openshell-conformance-cli \
      -p openshell-sandbox

    cargo build --target ${gnuToolchain.target} \
      -p openshell-gateway

    install -D -m 0755 \
      target/${muslToolchain.target}/debug/openshell-sandbox \
      deploy/docker/.build/prebuilt-binaries/${dockerArch}/openshell-sandbox

    docker build \
      --platform linux/${dockerArch} \
      --file deploy/docker/Dockerfile.supervisor \
      --target supervisor \
      --tag openshell/supervisor:tmachine \
      .

    docker save \
      --output target/openshell-supervisor-tmachine.tar \
      openshell/supervisor:tmachine
  '';
}
