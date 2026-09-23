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

  mkTestArchive =
    {
      name,
      workspacePath,
      manifestPath,
      package,
      target,
      output,
      features ? null,
      filter ? "kind(test)",
    }:
    pkgs.writeShellApplication {
      name = "build-${name}-test-archive";
      runtimeInputs = [
        pkgs.cargo-nextest
        pkgs.coreutils
        pkgs.findutils
        pkgs.git
        pkgs.gnutar
        rustToolchain
      ];
      runtimeEnv = toolchainEnv;
      text = ''
        root=$(git rev-parse --show-toplevel)
        manifest_path="$root/${manifestPath}"
        workspace_root="$root/${workspacePath}"
        output="$root/${output}"
        bundle_dir=$(mktemp -d -p /tmp openshell-test-bundle.XXXXXX)
        cleanup() {
          status=$?
          trap - EXIT
          rm -rf -- "$bundle_dir"
          exit "$status"
        }
        trap cleanup EXIT

        mkdir -p "$(dirname "$output")"
        cd "$root"
        cargo nextest archive \
          --manifest-path "$manifest_path" \
          --target ${target} \
          -p ${package} \
          ${pkgs.lib.optionalString (features != null) "--features ${pkgs.lib.escapeShellArg features}"} \
          -E ${pkgs.lib.escapeShellArg filter} \
          --archive-file "$bundle_dir/tests.tar.zst"

        cd "$workspace_root"
        bundle_files=()
        while IFS= read -r -d "" manifest; do
          relative_path="''${manifest#./}"
          install -D -m 0644 "$relative_path" "$bundle_dir/$relative_path"
          bundle_files+=("$relative_path")
        done < <(
          find . \
            \( -path ./.git -o -path ./.worktrees -o -path ./target \) -prune -o \
            -type f -name Cargo.toml -print0
        )

        tar -C "$bundle_dir" -cf "$output" "''${bundle_files[@]}" tests.tar.zst
        echo "Created nextest test bundle: $output"
      '';
    };

  conformanceCliArchive = mkTestArchive {
    name = "openshell-conformance";
    workspacePath = "tests/suites/conformance";
    manifestPath = "tests/suites/conformance/Cargo.toml";
    package = "openshell-test-conformance-cli";
    target = muslToolchain.target;
    output = "artifacts/test-archives/${muslToolchain.target}/openshell-conformance-tests.tar";
  };
  providerRefreshKeycloakArchive = mkTestArchive {
    name = "provider-refresh-keycloak";
    workspacePath = "tests/suites/features";
    manifestPath = "tests/suites/features/Cargo.toml";
    package = "openshell-test-feature-provider-refresh-keycloak";
    target = muslToolchain.target;
    output = "artifacts/test-archives/${muslToolchain.target}/provider-refresh-keycloak-tests.tar";
  };

  # Follow-up: migrate these wrapper-coupled tests once tmachine provides their
  # managed-gateway controls, SPIFFE fixtures, caller driver-config setting,
  # guest tools, and matching workload-image identity behavior. The corporate
  # proxy and gateway-start binaries currently self-skip without wrapper-owned
  # gateway metadata, so exclude them rather than report false passes.
  podmanE2eFollowUpBinaries = [
    "credential_gating"
    "driver_config_volume"
    "forward_proxy_graphql_l7"
    "forward_proxy_jsonrpc_l7"
    "forward_proxy_l7_bypass"
    "host_gateway_alias"
    "landlock"
    "local_driver_token_restart"
    # Standalone tmachine runs can time out while opening the localhost relay.
    # Follow up on making the relay setup deterministic before restoring it.
    "no_proxy"
    "podman_corporate_proxy"
    "podman_gateway_start"
    "podman_oci_identity"
    "provider_auto_create"
    "provider_refresh_handles"
    "provider_token_exchange"
    "proxy_egress_pipeline"
    # Conformance covers stop/start workspace preservation and deletion while
    # stopped. The remaining canonical-main, TTY, attachment replay, and
    # no-keep cases still need migration. Nextest archive filters cannot select
    # individual tests, so keep the complete binary in the follow-up bucket.
    "sandbox_lifecycle"
    # Needs a prebuilt musl DNS probe in guest artifact mode; tracked in #3009.
    "transparent_tcp"
    "websocket_conformance"
    "workspace_lifecycle"
  ];
  podmanE2eArchiveFilter =
    let
      excludedBinaries = map (binary: "binary(=${binary})") podmanE2eFollowUpBinaries;
    in
    "kind(test) and not (${pkgs.lib.concatStringsSep " or " excludedBinaries})";

  podmanDriverArchive = mkTestArchive {
    name = "podman-driver";
    workspacePath = "tests/suites/drivers";
    manifestPath = "tests/suites/drivers/Cargo.toml";
    package = "openshell-test-suite-podman";
    target = muslToolchain.target;
    output = "artifacts/test-archives/${muslToolchain.target}/openshell-podman-tests.tar";
  };
  podmanE2eArchive = mkTestArchive {
    name = "podman-e2e";
    workspacePath = "e2e/rust";
    manifestPath = "e2e/rust/Cargo.toml";
    package = "openshell-e2e";
    target = muslToolchain.target;
    output = "artifacts/test-archives/${muslToolchain.target}/openshell-podman-e2e-tests.tar";
    features = "e2e-podman";
    filter = podmanE2eArchiveFilter;
  };
in
rec {
  inherit
    conformanceCliArchive
    providerRefreshKeycloakArchive
    podmanDriverArchive
    podmanE2eArchive
    ;

  binaries = pkgs.writeShellApplication {
    name = "build-artifacts-binaries";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.git
      rustToolchain
    ];
    runtimeEnv = toolchainEnv;
    text = ''
      root=$(git rev-parse --show-toplevel)
      cd "$root"

      cargo build --target ${muslToolchain.target} \
        -p openshell-cli \
        -p openshell-sandbox

      cargo build --target ${gnuToolchain.target} \
        -p openshell-gateway \
        -p openshell-supervisor

      install -D -m 0755 \
        target/${muslToolchain.target}/debug/openshell \
        artifacts/binaries/${muslToolchain.target}/openshell

      install -D -m 0755 \
        target/${muslToolchain.target}/debug/openshell-sandbox \
        artifacts/binaries/${muslToolchain.target}/openshell-sandbox

      install -D -m 0755 \
        target/${gnuToolchain.target}/debug/openshell-gateway \
        artifacts/binaries/${gnuToolchain.target}/openshell-gateway

      install -D -m 0755 \
        target/${gnuToolchain.target}/debug/openshell-supervisor \
        artifacts/binaries/${gnuToolchain.target}/openshell-supervisor
    '';
  };

  testArchives = pkgs.writeShellApplication {
    name = "build-artifacts-test-archives";
    runtimeInputs = [
      conformanceCliArchive
      providerRefreshKeycloakArchive
      podmanDriverArchive
      podmanE2eArchive
    ];
    text = ''
      build-openshell-conformance-test-archive
      build-provider-refresh-keycloak-test-archive
      build-podman-driver-test-archive
      build-podman-e2e-test-archive
    '';
  };

  images = pkgs.writeShellApplication {
    name = "build-artifacts-images";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.docker-client
      pkgs.git
    ];
    text = ''
      root=$(git rev-parse --show-toplevel)
      cd "$root"

      install -D -m 0755 \
        artifacts/binaries/${gnuToolchain.target}/openshell-gateway \
        deploy/docker/.build/prebuilt-binaries/${dockerArch}/openshell-gateway

      install -D -m 0755 \
        artifacts/binaries/${gnuToolchain.target}/openshell-supervisor \
        deploy/docker/.build/prebuilt-binaries/${dockerArch}/openshell-supervisor

      install -D -m 0755 \
        artifacts/binaries/${muslToolchain.target}/openshell-sandbox \
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

      docker build \
        --platform linux/${dockerArch} \
        --file deploy/docker/Dockerfile.sandbox \
        --target sandbox \
        --tag openshell/sandbox:tmachine \
        .

      mkdir -p artifacts/images

      docker save \
        --output artifacts/images/openshell-gateway-tmachine.tar \
        openshell/gateway:tmachine

      docker save \
        --output artifacts/images/openshell-supervisor-tmachine.tar \
        openshell/supervisor:tmachine

      docker save \
        --output artifacts/images/openshell-sandbox-tmachine.tar \
        openshell/sandbox:tmachine
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
      testArchives
      images
      helm
    ];
    text = ''
      build-artifacts-binaries
      build-artifacts-test-archives
      build-artifacts-images
      build-artifacts-helm
    '';
  };
}
