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
rec {
  binaries = pkgs.writeShellApplication {
    name = "build-artifacts-binaries";
    runtimeInputs = [
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
    '';
  };

  images = pkgs.writeShellApplication {
    name = "build-artifacts-images";
    runtimeInputs = [
      pkgs.docker-client
      pkgs.git
    ];
    text = ''
      root=$(git rev-parse --show-toplevel)
      cd "$root"

      install -D -m 0755 \
        target/${gnuToolchain.target}/debug/openshell-gateway \
        deploy/docker/.build/prebuilt-binaries/${dockerArch}/openshell-gateway

      install -D -m 0755 \
        target/${muslToolchain.target}/debug/openshell-sandbox \
        deploy/docker/.build/prebuilt-binaries/${dockerArch}/openshell-sandbox

      docker build \
        --platform linux/${dockerArch} \
        --file deploy/docker/Dockerfile.gateway \
        --target gateway \
        --tag openshell/gateway:tmachine \
        .

      docker build \
        --platform linux/${dockerArch} \
        --file deploy/docker/Dockerfile.supervisor \
        --target supervisor \
        --tag openshell/supervisor:tmachine \
        .

      mkdir -p artifacts/images

      docker save \
        --output artifacts/images/openshell-gateway-tmachine.tar \
        openshell/gateway:tmachine

      docker save \
        --output artifacts/images/openshell-supervisor-tmachine.tar \
        openshell/supervisor:tmachine
    '';
  };

  helm = pkgs.writeShellApplication {
    name = "build-artifacts-helm";
    runtimeInputs = [
      pkgs.git
      pkgs.kubernetes-helm
    ];
    text = ''
      root=$(git rev-parse --show-toplevel)
      cd "$root"

      mkdir -p artifacts/helm
      helm package deploy/helm/openshell --destination artifacts/helm
    '';
  };

  all = pkgs.writeShellApplication {
    name = "build-artifacts";
    runtimeInputs = [
      binaries
      images
      helm
    ];
    text = ''
      build-artifacts-binaries
      build-artifacts-images
      build-artifacts-helm
    '';
  };
}
