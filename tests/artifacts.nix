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
  linuxVmRuntime = pkgs.callPackage ../nix/pkgs/vm-runtime.nix {
    stdenv = gnuToolchain.stdenv;
  };
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

  conformanceTestArchive = mkTestArchive {
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
  ociImageArchive = mkTestArchive {
    name = "oci-image";
    workspacePath = "tests/suites/features";
    manifestPath = "tests/suites/features/Cargo.toml";
    package = "openshell-test-feature-oci-image";
    target = muslToolchain.target;
    output = "artifacts/test-archives/${muslToolchain.target}/oci-image-tests.tar";
  };

  # Follow-up: binaries that do not yet run in the rootless tmachine guest. Each
  # entry says what it needs. Entries marked "wrapper lane" still run in the
  # wrapper-based Podman lane (`mise run e2e:podman:ci`), so they are covered
  # there until tmachine provides what they need.
  podmanE2eFollowUpBinaries = [
    # Needs the caller driver-config settings (`allow_driver_config`,
    # `enable_bind_mounts`), which the tmachine gateway does not enable. Wrapper
    # lane.
    "driver_config_volume"
    # The next three self-skip without wrapper-owned gateway metadata (restart
    # and configuration control), so exclude them rather than report false
    # passes. Wrapper lane.
    "local_driver_token_restart"
    "podman_corporate_proxy"
    "podman_gateway_start"
    # Its move to conformance is deferred until the isolation work in #4120; see
    # #4246.
    "provider_auto_create"
    # Needs the SPIFFE fixtures that the wrapper sets up. Wrapper lane.
    "provider_token_exchange"
    # One test times out reaching support-container IPs from the sandbox in the
    # rootless guest; the other tests in the binary pass. Nextest archive
    # filters cannot select individual tests, so keep the complete binary here.
    "proxy_egress_pipeline"
    # Conformance covers stop/start workspace preservation and deletion while
    # stopped. The remaining canonical-main, TTY, attachment replay, and
    # no-keep cases still need migration. Nextest archive filters cannot select
    # individual tests, so keep the complete binary in the follow-up bucket.
    "sandbox_lifecycle"
    # Needs a prebuilt musl DNS probe in guest artifact mode; tracked in #3009.
    "transparent_tcp"
    "workspace_lifecycle"
  ];
  podmanE2eArchiveFilter =
    let
      excludedBinaries = map (binary: "binary(=${binary})") podmanE2eFollowUpBinaries;
    in
    "kind(test) and not (${pkgs.lib.concatStringsSep " or " excludedBinaries})";

  podmanE2eCiTests = pkgs.writeShellApplication {
    name = "generate-podman-e2e-ci-tests";
    runtimeInputs = [
      pkgs.cargo-nextest
      pkgs.git
      pkgs.jq
      rustToolchain
    ];
    runtimeEnv = toolchainEnv;
    text = ''
      root=$(git rev-parse --show-toplevel)
      cd "$root"

      cargo nextest list \
        --manifest-path e2e/rust/Cargo.toml \
        --target ${muslToolchain.target} \
        -p openshell-e2e \
        --features e2e-podman \
        --list-type binaries-only \
        --message-format json \
        | jq -r --argjson excluded ${pkgs.lib.escapeShellArg (builtins.toJSON podmanE2eFollowUpBinaries)} '
          [
            .["rust-binaries"]
            | to_entries[]
            | select(.value.kind == "test")
            | .value["binary-name"]
            | select(. as $name | $excluded | index($name) | not)
          ]
          | sort
          | "PODMAN_CI_TESTS=(\n"
            + (map("  " + @sh) | join("\n"))
            + "\n)"
        '
    '';
  };

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
    conformanceTestArchive
    providerRefreshKeycloakArchive
    ociImageArchive
    podmanDriverArchive
    podmanE2eArchive
    podmanE2eCiTests
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
        -p openshell-sandbox \
        -p openshell-prover-cli

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

      install -D -m 0755 \
        target/${muslToolchain.target}/debug/openshell-prover \
        artifacts/binaries/${muslToolchain.target}/openshell-prover
    '';
  };

  vmDriver = pkgs.writeShellApplication {
    name = "build-artifacts-vm-driver";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.git
      pkgs.zstd
      rustToolchain
    ];
    runtimeEnv = toolchainEnv;
    text = ''
      root=$(git rev-parse --show-toplevel)
      cd "$root"

      cargo build --target ${muslToolchain.target} \
        -p openshell-driver-vm --no-default-features --bin openshell-vm-init

      install -D -m 0755 \
        target/${muslToolchain.target}/debug/openshell-vm-init \
        artifacts/binaries/${muslToolchain.target}/openshell-vm-init

      compressed_dir=$(mktemp -d -p /tmp openshell-vm-runtime.XXXXXX)
      cleanup() {
        status=$?
        trap - EXIT
        rm -rf -- "$compressed_dir"
        exit "$status"
      }
      trap cleanup EXIT
      cp ${linuxVmRuntime}/compressed/*.zst "$compressed_dir/"
      zstd -19 -T1 artifacts/binaries/${muslToolchain.target}/openshell-sandbox \
        -o "$compressed_dir/openshell-sandbox.zst"
      zstd -19 -T1 artifacts/binaries/${gnuToolchain.target}/openshell-supervisor \
        -o "$compressed_dir/openshell-supervisor.zst"
      zstd -19 -T1 artifacts/binaries/${muslToolchain.target}/openshell-vm-init \
        -o "$compressed_dir/openshell-vm-init.zst"
      OPENSHELL_VM_RUNTIME_COMPRESSED_DIR="$compressed_dir" \
        cargo build --target ${gnuToolchain.target} \
          -p openshell-driver-vm --bin openshell-driver-vm

      install -D -m 0755 \
        target/${gnuToolchain.target}/debug/openshell-driver-vm \
        artifacts/binaries/${gnuToolchain.target}/openshell-driver-vm
    '';
  };

  testArchives = pkgs.writeShellApplication {
    name = "build-artifacts-test-archives";
    runtimeInputs = [
      conformanceTestArchive
      providerRefreshKeycloakArchive
      ociImageArchive
      podmanDriverArchive
      podmanE2eArchive
    ];
    text = ''
      build-openshell-conformance-test-archive
      build-provider-refresh-keycloak-test-archive
      build-oci-image-test-archive
      build-podman-driver-test-archive
      build-podman-e2e-test-archive
    '';
  };

  testImages = pkgs.writeShellApplication {
    name = "build-artifacts-test-images";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.docker-client
      pkgs.git
    ];
    text = ''
      root=$(git rev-parse --show-toplevel)
      cd "$root"

      docker build \
        --platform linux/${dockerArch} \
        --file e2e/python/Dockerfile.workload \
        --build-arg "PYTHON_VERSION=$(cat .python-version)" \
        --tag openshell/e2e-python:dev \
        e2e/python

      mkdir -p artifacts/images
      docker save \
        --output artifacts/images/openshell-e2e-python-dev.tar \
        openshell/e2e-python:dev
    '';
  };

  images = pkgs.writeShellApplication {
    name = "build-artifacts-images";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.docker-client
      pkgs.git
      testImages
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

      build-artifacts-test-images
    '';
  };

  deb = pkgs.writeShellApplication {
    name = "build-artifacts-deb";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.dpkg
      pkgs.git
      pkgs.gzip
    ];
    text = ''
      root=$(git rev-parse --show-toplevel)
      cd "$root"

      package_version="''${OPENSHELL_DEB_VERSION:-0.0.0-local}"
      OPENSHELL_CLI_BINARY="$root/artifacts/binaries/${muslToolchain.target}/openshell" \
        OPENSHELL_GATEWAY_BINARY="$root/artifacts/binaries/${gnuToolchain.target}/openshell-gateway" \
        OPENSHELL_PROVER_BINARY="$root/artifacts/binaries/${muslToolchain.target}/openshell-prover" \
        OPENSHELL_DRIVER_VM_BINARY="$root/artifacts/binaries/${gnuToolchain.target}/openshell-driver-vm" \
        OPENSHELL_DEB_VERSION="$package_version" \
        OPENSHELL_DEB_ARCH=${dockerArch} \
        OPENSHELL_OUTPUT_DIR="$root/artifacts/packages" \
        tasks/scripts/package-deb.sh
      install -m 0644 "artifacts/packages/openshell_''${package_version}_${dockerArch}.deb" \
        artifacts/packages/openshell.deb
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
      vmDriver
      deb
      testArchives
      images
      helm
    ];
    text = ''
      build-artifacts-binaries
      build-artifacts-vm-driver
      build-artifacts-deb
      build-artifacts-test-archives
      build-artifacts-images
      build-artifacts-helm
    '';
  };
}
