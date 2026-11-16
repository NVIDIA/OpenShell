#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Select shipped packages explicitly: workspace builds unify the Cedar adapter's
# features into the shared policy facade even without an experimental bundle.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

dependencies=$(mktemp)
trap 'rm -f "$dependencies"' EXIT
cargo tree --locked -p openshell-policy -p openshell-server \
  -p openshell-gateway -p openshell-supervisor \
  -p openshell-cli -p openshell-tui -p openshell-sandbox \
  --edges normal,build --prefix none > "$dependencies"
if grep -Eq '^(cedar-policy[^ ]*|openshell-policy-cedar[^ ]*) v' "$dependencies"; then
  echo "ERROR: default product dependencies include Cedar" >&2
  cat "$dependencies" >&2
  exit 1
fi

cargo check --locked -p openshell-gateway -p openshell-supervisor --bins
cargo test --locked --lib -p openshell-policy
# The positional `cedar` below is a test-name filter, not a Cargo feature.
cargo test --locked --lib -p openshell-server -p openshell-supervisor \
  --features openshell-server/test-support cedar
