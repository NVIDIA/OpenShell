#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
manifest=tests/crypto-consumer/Cargo.toml
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"

for feature in core-minimal core-default core-all sdk policy; do
  echo "Checking isolated consumer: $feature"
  tree=$(cargo tree --locked --manifest-path "$manifest" --no-default-features --features "$feature" --edges normal,build --prefix none)
  if grep -Eq '^(aws-lc-rs|aws-lc-sys|aws-lc-fips-sys|ring) v' <<< "$tree"; then
    echo "ERROR: $feature selected a crypto implementation" >&2
    echo "$tree" >&2
    exit 1
  fi
done

# This graph deliberately includes the host's Ring/RustCrypto implementations.
# AWS-LC would override rcgen's Ring selection, even if both features were set.
tree=$(cargo tree --locked --manifest-path "$manifest" --features runtime --edges normal,build,dev --prefix none)
if grep -Eq '^(aws-lc-rs|aws-lc-sys|aws-lc-fips-sys) v' <<< "$tree"; then
  echo "ERROR: consumer's Ring selection was overridden" >&2
  echo "$tree" >&2
  exit 1
fi

for product in cli gateway supervisor sandbox driver-docker driver-podman driver-kubernetes driver-kubernetes-secrets driver-vault driver-vm prover-cli; do
  for mode in default minimal; do
    args=(--locked -p "openshell-$product")
    if [[ "$mode" == minimal ]]; then args+=(--no-default-features); fi
    tree=$(cargo tree "${args[@]}" --edges normal --prefix none --format '{p} {f}')
    if ! grep -E '^openshell-crypto v.* aws-lc(,|$)' <<< "$tree" >/dev/null; then
      echo "ERROR: openshell-$product ($mode) lost its AWS-LC backend" >&2
      exit 1
    fi
  done
done

cargo check --locked --manifest-path "$manifest" --no-default-features --features core-all,sdk,policy --lib
cargo test --locked --manifest-path "$manifest" --features runtime
