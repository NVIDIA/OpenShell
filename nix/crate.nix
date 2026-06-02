# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  root,
}:
{
  # Each crate declares the compile-time assets and build tools it needs. The
  # workspace builder collects nativeBuildInputs/buildInputs/env from the
  # transitive Cargo closure.
  openshell-bootstrap = {
    dir = "openshell-bootstrap";
    assets = [ (root + "/proto") ];
  };
  openshell-cli = {
    dir = "openshell-cli";
    nativeCheckInputs = [
      pkgs.cacert
      pkgs.git
    ];
    assets = [
      (root + "/proto")
      (root + "/providers")
      (root + "/crates/openshell-prover/registry")
    ];
  };
  openshell-server = {
    dir = "openshell-server";
    assets = [
      (root + "/proto")
      (root + "/providers")
      (root + "/crates/openshell-prover/registry")
      (root + "/crates/openshell-server/migrations")
      (root + "/deploy/rpm/gateway.toml.default")
    ];
    cargoTestExtraArgs = "--features test-support";
  };
  openshell-core = {
    dir = "openshell-core";
    nativeBuildInputs = [ pkgs.protobuf ];
    assets = [ (root + "/proto") ];
  };
  openshell-driver-docker = {
    dir = "openshell-driver-docker";
    assets = [ (root + "/proto") ];
  };
  openshell-sandbox = {
    dir = "openshell-sandbox";
    nativeCheckInputs = [
      pkgs.bash
      pkgs.coreutils
    ];
    assets = [
      (root + "/proto")
      (root + "/crates/openshell-sandbox/data")
      (root + "/crates/openshell-sandbox/src/skills")
      (root + "/crates/openshell-sandbox/testdata")
    ];
  };
  openshell-driver-vm = {
    dir = "openshell-driver-vm";
    assets = [
      (root + "/proto")
      (root + "/crates/openshell-driver-vm/scripts")
    ];
  };
  openshell-driver-kubernetes = {
    dir = "openshell-driver-kubernetes";
    assets = [ (root + "/proto") ];
  };
  openshell-driver-podman = {
    dir = "openshell-driver-podman";
    assets = [ (root + "/proto") ];
  };
  openshell-ocsf = {
    dir = "openshell-ocsf";
    assets = [ (root + "/crates/openshell-ocsf/schemas") ];
  };
  openshell-policy = {
    dir = "openshell-policy";
    assets = [ (root + "/proto") ];
  };
  openshell-prover = {
    dir = "openshell-prover";
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [ pkgs.z3 ];
    env.LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
    assets = [
      (root + "/crates/openshell-prover/registry")
      (root + "/crates/openshell-prover/testdata")
    ];
  };
  openshell-providers = {
    dir = "openshell-providers";
    assets = [
      (root + "/proto")
      (root + "/providers")
    ];
  };
  openshell-router = {
    dir = "openshell-router";
    assets = [ (root + "/proto") ];
  };
  openshell-server-macros = {
    dir = "openshell-server-macros";
  };
  openshell-tui = {
    dir = "openshell-tui";
    assets = [
      (root + "/proto")
      (root + "/providers")
    ];
  };
  openshell-vfio = {
    dir = "openshell-vfio";
  };
}
