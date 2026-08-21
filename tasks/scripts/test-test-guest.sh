#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNNER="${ROOT}/nix/test-guest/run.sh"

if ! grep -Fq \
	'"sudo dnf install -y --nogpgcheck${quoted_packages}"' \
	"${RUNNER}"; then
	echo "FAIL: RPM installation must pass package paths directly to dnf" >&2
	exit 1
fi

if grep -Fq \
	'"sudo dnf install -y --nogpgcheck --${quoted_packages}"' \
	"${RUNNER}"; then
	echo "FAIL: DNF5 rejects the standalone -- before package paths" >&2
	exit 1
fi

echo "test-guest focused tests passed"
