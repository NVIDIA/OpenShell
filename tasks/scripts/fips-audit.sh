#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Reports which dependencies still link `ring` in a FIPS build of the gateway.
#
# A FIPS build routes all of OpenShell's own crypto through AWS-LC in FIPS mode,
# but `ring` remains in the dependency graph. This script makes that concrete so
# the residual surface is a measured number in CI rather than a surprise during
# an audit. It is intentionally reporting-only: it does not fail the build,
# because the remaining paths are tracked work rather than regressions.

set -euo pipefail

PACKAGE="${1:-openshell-server}"

echo "FIPS dependency audit for ${PACKAGE}"
echo

if ! cargo tree -p "${PACKAGE}" --no-default-features --features fips,telemetry -e normal -i aws-lc-fips-sys >/dev/null 2>&1; then
  echo "ERROR: aws-lc-fips-sys is not in the FIPS dependency graph."
  echo "The 'fips' feature is not reaching aws-lc-rs. This is a real failure."
  exit 1
fi
echo "OK: aws-lc-fips-sys is present — the validated module is linked."
echo

echo "Residual 'ring' consumers in the FIPS build:"
echo "  (expected: openshell-crypto links ring unconditionally so the backend"
echo "   choice cannot become ambiguous, plus the AWS SDK's rustls 0.21 leg."
echo "   Neither is invoked for OpenShell crypto — see docs/security/fips.mdx)"
echo
if cargo tree -p "${PACKAGE}" --no-default-features --features fips,telemetry -e normal -i ring 2>/dev/null | sed 's/^/  /'; then
  :
else
  echo "  none — ring is absent from the graph"
fi

echo
echo "Distinct rustls versions in the FIPS build:"
cargo tree -p "${PACKAGE}" --no-default-features --features fips,telemetry -e normal 2>/dev/null \
  | grep -oE 'rustls v[0-9]+\.[0-9]+\.[0-9]+' \
  | sort -u \
  | sed 's/^/  /'
echo
echo "More than one rustls major means a second TLS stack that the installed"
echo "CryptoProvider does not govern."
