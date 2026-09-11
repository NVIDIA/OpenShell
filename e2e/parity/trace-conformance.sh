#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Retain the conformance runner's stdout as one parseable JSON document while
# forwarding it unchanged to the parity run log. Stderr remains live so
# lifecycle diagnostics and the run ID continue to appear in the raw evidence.

set -euo pipefail

REAL_CONFORMANCE="${OPENSHELL_PARITY_REAL_CONFORMANCE:?OPENSHELL_PARITY_REAL_CONFORMANCE is required}"
CAPTURE="${OPENSHELL_PARITY_CONFORMANCE_REPORT_CAPTURE:?OPENSHELL_PARITY_CONFORMANCE_REPORT_CAPTURE is required}"

if [ ! -x "${REAL_CONFORMANCE}" ]; then
  echo "ERROR: real conformance binary is not executable: ${REAL_CONFORMANCE}" >&2
  exit 2
fi

mkdir -p "$(dirname "${CAPTURE}")"
temporary="$(mktemp "${CAPTURE}.tmp.XXXXXX")"
cleanup() {
  rm -f -- "${temporary}"
}
trap cleanup EXIT

set +e
"${REAL_CONFORMANCE}" "$@" | tee "${temporary}"
statuses=("${PIPESTATUS[@]}")
set -e
status=${statuses[0]}
if [ "${statuses[1]}" -ne 0 ]; then
  echo "ERROR: could not retain conformance stdout: ${CAPTURE}" >&2
  status=${statuses[1]}
else
  mv -f -- "${temporary}" "${CAPTURE}"
fi
exit "${status}"
