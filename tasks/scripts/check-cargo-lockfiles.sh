#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

found=0
status=0

while IFS= read -r -d '' lockfile; do
  found=1
  manifest="${lockfile%Cargo.lock}Cargo.toml"

  if [[ ! -f "$manifest" ]]; then
    echo "error: tracked lockfile $lockfile has no adjacent Cargo.toml" >&2
    status=1
    continue
  fi

  echo "Checking $lockfile"
  if ! cargo metadata \
    --locked \
    --format-version 1 \
    --manifest-path "$manifest" \
    >/dev/null; then
    echo "error: $lockfile is out of sync with $manifest" >&2
    status=1
  fi
done < <(git ls-files -z -- ':(glob)**/Cargo.lock')

if [[ "$found" -eq 0 ]]; then
  echo "error: no tracked Cargo.lock files found" >&2
  exit 1
fi

if [[ "$status" -ne 0 ]]; then
  echo "Refresh the reported lockfiles with Cargo and commit the results." >&2
fi

exit "$status"
