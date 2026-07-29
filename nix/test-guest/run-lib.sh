#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared helpers for validating host inputs to the test guest runner.

test_guest_resolve_source() {
	local source_path=$1
	local resolved

	resolved=$(realpath -- "${source_path}") || return 1
	[ -f "${resolved}" ] || return 1
	printf '%s\n' "${resolved}"
}
