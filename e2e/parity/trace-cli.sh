#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Transparently invoke the staged OpenShell CLI while retaining the exact
# stdout bytes produced by the conformance exec probe.

set -uo pipefail

: "${OPENSHELL_PARITY_REAL_CLI:?OPENSHELL_PARITY_REAL_CLI is required}"
: "${OPENSHELL_PARITY_EXEC_STDOUT_CAPTURE:?OPENSHELL_PARITY_EXEC_STDOUT_CAPTURE is required}"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/openshell-parity-cli.XXXXXX")"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

set +e
"${OPENSHELL_PARITY_REAL_CLI}" "$@" >"${tmpdir}/stdout" 2>"${tmpdir}/stderr"
status=$?
set -e

cat "${tmpdir}/stdout"
cat "${tmpdir}/stderr" >&2

if [ "${1:-}" = sandbox ] && [ "${2:-}" = exec ]; then
  install -m 0444 "${tmpdir}/stdout" "${OPENSHELL_PARITY_EXEC_STDOUT_CAPTURE}"
fi

exit "${status}"
