# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Reconstruct the repository's pinned Nixpkgs input without evaluating the root
# flake. rules_nixpkgs copies this file and flake.lock together.
let
  lock = builtins.fromJSON (builtins.readFile ../../flake.lock);
  root = lock.nodes.${lock.root};
  inputName = root.inputs.nixpkgs;
  source = lock.nodes.${inputName}.locked;
  nixpkgs =
    assert source.type == "github";
    builtins.fetchTarball {
      url = "https://github.com/${source.owner}/${source.repo}/archive/${source.rev}.tar.gz";
      sha256 = source.narHash;
    };
in
import nixpkgs
