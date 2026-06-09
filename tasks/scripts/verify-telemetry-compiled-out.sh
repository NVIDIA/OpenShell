#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Verify whether telemetry emission code is present in a compiled binary.
#
# The `telemetry` Cargo feature (default-on, defined in openshell-core) gates the
# telemetry endpoint, HTTP client, and emission code. Building with
# --no-default-features must produce a binary that contains none of it. This
# guard inspects a built binary for telemetry markers that only exist when the
# emission code is compiled in.

set -euo pipefail

# Markers that appear only in compiled-in telemetry emission code. Sourced from
# crates/openshell-core/src/telemetry.rs (DEFAULT_ENDPOINT host and CLIENT_ID).
# Keep in sync with that file; the `present` positive control fails loudly if a
# marker goes stale, so the `absent` checks can never become silently vacuous.
MARKERS=(
  "events.telemetry.data.nvidia.com"
  "415437562476676"
)

usage() {
  echo "Usage: verify-telemetry-compiled-out.sh <present|absent> <binary> [binary ...]" >&2
  echo "  present  assert telemetry markers ARE present (positive control for a telemetry-enabled build)" >&2
  echo "  absent   assert telemetry markers are NOT present (telemetry compiled out)" >&2
}

if [[ $# -lt 2 ]]; then
  usage
  exit 2
fi

mode=$1
shift
case "$mode" in
  present | absent) ;;
  *)
    usage
    exit 2
    ;;
esac

if ! command -v strings >/dev/null 2>&1; then
  echo "error: 'strings' (binutils) is required to inspect the binary" >&2
  exit 2
fi

failed=0
for binary in "$@"; do
  if [[ ! -f $binary ]]; then
    echo "error: binary not found: $binary" >&2
    failed=1
    continue
  fi

  dump=$(strings -a "$binary")
  for marker in "${MARKERS[@]}"; do
    count=$(grep -c -F "$marker" <<<"$dump" || true)
    if [[ $mode == absent && $count -ne 0 ]]; then
      echo "FAIL: telemetry marker '$marker' found in $binary ($count occurrence(s)); telemetry was not compiled out" >&2
      failed=1
    elif [[ $mode == present && $count -eq 0 ]]; then
      echo "FAIL: telemetry marker '$marker' missing from $binary; positive control failed (marker stale or build misconfigured)" >&2
      failed=1
    else
      echo "OK: marker '$marker' $mode in $(basename "$binary") ($count occurrence(s))"
    fi
  done
done

exit "$failed"
