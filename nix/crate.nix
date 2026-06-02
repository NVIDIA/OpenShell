# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  root,
}:
let
  # z3 (found via pkg-config) and libclang (for z3-sys bindgen) are only needed
  # by crates whose closure contains openshell-prover.
  withZ3 = {
    nativeBuildInputs = [
      pkgs.pkg-config
      pkgs.protobuf
    ];
    buildInputs = [ pkgs.z3 ];
    env.LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
  };
in
{
  # Each crate declares the compile-time assets its build needs: its own plus
  # those of its workspace deps (proto/ arrives via openshell-core, providers/
  # via openshell-providers, registry/ via openshell-prover).
  openshell-cli = withZ3 // {
    dir = "openshell-cli";
    assets = [
      (root + "/proto")
      (root + "/providers")
      (root + "/crates/openshell-prover/registry")
    ];
  };
  openshell-server = withZ3 // {
    dir = "openshell-server";
    assets = [
      (root + "/proto")
      (root + "/providers")
      (root + "/crates/openshell-prover/registry")
      (root + "/crates/openshell-server/migrations")
    ];
  };
  openshell-sandbox = {
    dir = "openshell-sandbox";
    nativeBuildInputs = [ pkgs.protobuf ];
    assets = [
      (root + "/proto")
      (root + "/crates/openshell-sandbox/data")
      (root + "/crates/openshell-sandbox/src/skills")
    ];
  };
  openshell-driver-vm = {
    dir = "openshell-driver-vm";
    nativeBuildInputs = [ pkgs.protobuf ];
    assets = [
      (root + "/proto")
      (root + "/crates/openshell-driver-vm/scripts")
    ];
  };
  openshell-driver-kubernetes = {
    dir = "openshell-driver-kubernetes";
    nativeBuildInputs = [ pkgs.protobuf ];
    assets = [ (root + "/proto") ];
  };
  openshell-driver-podman = {
    dir = "openshell-driver-podman";
    nativeBuildInputs = [ pkgs.protobuf ];
    assets = [ (root + "/proto") ];
  };
}
