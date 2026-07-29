#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=nix/test-guest/run-lib.sh
. "${script_dir}/run-lib.sh"

test_dir=$(mktemp -d)
trap 'rm -rf "${test_dir}"' EXIT

touch "${test_dir}/-Smalicious.deb"
resolved=$(
	cd "${test_dir}"
	test_guest_resolve_source "-Smalicious.deb"
)
expected=$(realpath -- "${test_dir}/-Smalicious.deb")

if [ "${resolved}" != "${expected}" ] || [[ ${resolved} != /* ]]; then
	echo "leading-hyphen source was not resolved to an absolute path" >&2
	exit 1
fi

if test_guest_resolve_source "${test_dir}/missing" >/dev/null 2>&1; then
	echo "missing source unexpectedly resolved" >&2
	exit 1
fi

echo "test guest runner helper tests passed"
