#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

check_lockfile() {
  local lockfile="$1"
  local manifest="${lockfile%Cargo.lock}Cargo.toml"

  if [[ ! -f "$manifest" ]]; then
    printf 'error: tracked lockfile %s has no adjacent Cargo.toml\n' "$lockfile" >&2
    return 1
  fi

  printf 'Checking %s\n' "$lockfile"
  if ! cargo metadata \
    --locked \
    --format-version 1 \
    --manifest-path "$manifest" \
    >/dev/null; then
    printf 'error: validation failed for %s\n' "$lockfile" >&2
    return 1
  fi
}

main() {
  local lockfile
  local found=0
  local failed=0

  cd "$(git rev-parse --show-toplevel)"

  # Policy: every tracked Cargo.lock represents an intentionally reproducible
  # Cargo workspace and must resolve against its adjacent Cargo.toml. Manifests
  # that intentionally do not own a lockfile are outside this check.
  while IFS= read -r -d '' lockfile; do
    found=1
    check_lockfile "$lockfile" || failed=1
  done < <(git ls-files -z -- ':(glob)**/Cargo.lock')

  if [[ "$found" -eq 0 ]]; then
    echo "error: no tracked Cargo.lock files found" >&2
    return 1
  fi

  if [[ "$failed" -ne 0 ]]; then
    echo "Resolve the reported errors. If a lockfile needs updating, refresh it with Cargo and commit the result." >&2
  fi

  return "$failed"
}

main "$@"
