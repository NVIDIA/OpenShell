#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Verify the `defaults-without-telemetry` alias still means "every default
# feature except telemetry", and that it cannot be used additively.
#
# Cargo cannot subtract a single default feature, so telemetry-free builds use
# `--no-default-features --features defaults-without-telemetry`. Two failure
# modes follow from that, and this guard covers both:
#
#   1. Drift. The alias enumerates the keep-list by hand, so it silently rots
#      the moment a crate gains a new default feature. Telemetry-free builds
#      would then quietly lose an unrelated default.
#   2. Additive misuse. `--features defaults-without-telemetry` without
#      `--no-default-features` would otherwise compile a telemetry-on binary
#      that reads as telemetry-free. Each crate root carries a `compile_error!`
#      for that combination; this asserts the error is actually wired up.

set -euo pipefail

# Crates that define the alias. Each must forward `telemetry` and define
# `defaults-without-telemetry`.
CRATES=(
  openshell-gateway
  openshell-sandbox
  openshell-driver-vm
)

if ! command -v jq >/dev/null 2>&1; then
  echo "error: 'jq' is required to inspect cargo metadata" >&2
  exit 2
fi

metadata=$(cargo metadata --no-deps --format-version 1)

failed=0
for crate in "${CRATES[@]}"; do
  features=$(jq -c --arg crate "$crate" \
    '.packages[] | select(.name == $crate) | .features' <<<"$metadata")

  if [[ -z $features || $features == "null" ]]; then
    echo "FAIL: crate '$crate' not found in workspace metadata" >&2
    failed=1
    continue
  fi

  if ! jq -e 'has("defaults-without-telemetry")' <<<"$features" >/dev/null; then
    echo "FAIL: $crate defines no 'defaults-without-telemetry' feature" >&2
    failed=1
    continue
  fi

  expected=$(jq -r '(.default // []) - ["telemetry"] | sort | join(",")' <<<"$features")
  actual=$(jq -r '(."defaults-without-telemetry" // []) | sort | join(",")' <<<"$features")

  if [[ $expected != "$actual" ]]; then
    echo "FAIL: $crate 'defaults-without-telemetry' is out of sync with 'default'" >&2
    echo "      default minus telemetry:    [${expected}]" >&2
    echo "      defaults-without-telemetry: [${actual}]" >&2
    echo "      Update 'defaults-without-telemetry' in crates/$crate/Cargo.toml to match." >&2
    failed=1
    continue
  fi

  echo "OK: $crate 'defaults-without-telemetry' == default minus telemetry [${expected}]"
done

# Additive misuse must be a hard error. Match on the `compile_error!` text
# rather than a nonzero exit code: openshell-driver-vm does not build on every
# host, and a check that failed for an unrelated reason would make this guard
# silently vacuous.
for crate in "${CRATES[@]}"; do
  output=$(cargo check -p "$crate" --features defaults-without-telemetry 2>&1 || true)

  if grep -qF "features \`telemetry\` and \`defaults-without-telemetry\` are mutually exclusive" <<<"$output"; then
    echo "OK: $crate rejects 'telemetry' + 'defaults-without-telemetry'"
    continue
  fi

  echo "FAIL: $crate did not reject 'telemetry' + 'defaults-without-telemetry'" >&2
  echo "      Expected the mutual-exclusion compile_error! in crates/$crate/src/lib.rs." >&2
  echo "      Got:" >&2
  sed 's/^/        /' <<<"$output" | tail -20 >&2
  failed=1
done

exit "$failed"
