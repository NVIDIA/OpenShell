#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared build-environment helpers for host-side Rust builds.
#
# Source this file (do not execute it) and call the helpers before invoking
# Cargo on the host.

# openshell_cedar_feature prints the Cargo feature that enables the Cedar
# policy engine when OPENSHELL_BUILD_CEDAR=1, and prints nothing when it is
# unset or 0. Stable builds leave Cedar off; Release Dev enables it. Only
# openshell-gateway and openshell-supervisor define the feature, so callers
# must add it to those packages alone. Fails on any other value, so assign
# the result in its own statement:
#
#   cedar_feature="$(openshell_cedar_feature)"
openshell_cedar_feature() {
    case "${OPENSHELL_BUILD_CEDAR:-0}" in
        0) ;;
        1) echo "cedar" ;;
        *)
            echo "ERROR: OPENSHELL_BUILD_CEDAR must be 0 or 1, not '${OPENSHELL_BUILD_CEDAR}'." >&2
            return 1
            ;;
    esac
}

# ensure_build_nofile_limit raises the per-process open-file limit before a
# host Rust build. Sccache and static *-unknown-linux-musl links can each open
# hundreds of files simultaneously, exceeding macOS's default soft limit of
# 256. The raised limit propagates to the Cargo children the caller spawns.
#
# The limit is read from OPENSHELL_BUILD_NOFILE_LIMIT (default 8192), honoring
# the legacy OPENSHELL_VM_BUILD_NOFILE_LIMIT for back-compat. This is a no-op
# on Linux, so it must be safe to call unconditionally.
ensure_build_nofile_limit() {
    local desired="${OPENSHELL_BUILD_NOFILE_LIMIT:-${OPENSHELL_VM_BUILD_NOFILE_LIMIT:-8192}}"
    local minimum=1024
    local current=""
    local hard=""
    local target=""

    [ "$(uname -s)" = "Darwin" ] || return 0
    current="$(ulimit -Sn 2>/dev/null || echo "")"
    case "${current}" in
        ''|*[!0-9]*)
            return 0
            ;;
    esac

    if [ "${current}" -ge "${desired}" ]; then
        return 0
    fi

    hard="$(ulimit -Hn 2>/dev/null || echo "")"
    target="${desired}"
    case "${hard}" in
        ''|unlimited|infinity)
            ;;
        *[!0-9]*)
            ;;
        *)
            if [ "${hard}" -lt "${target}" ]; then
                target="${hard}"
            fi
            ;;
    esac

    if [ "${target}" -gt "${current}" ] && ulimit -Sn "${target}" 2>/dev/null; then
        echo "==> Raised open file limit for host Cargo build: ${current} -> $(ulimit -Sn)"
    fi

    current="$(ulimit -Sn 2>/dev/null || echo "${current}")"
    case "${current}" in
        ''|*[!0-9]*)
            return 0
            ;;
    esac

    if [ "${current}" -lt "${desired}" ]; then
        echo "WARNING: Open file limit is ${current}; host Cargo builds are more reliable at ${desired}+ on macOS."
    fi

    if [ "${current}" -lt "${minimum}" ]; then
        echo "ERROR: Open file limit (${current}) is too low for host Cargo builds on macOS." >&2
        echo "       Run: ulimit -Sn ${desired}" >&2
        echo "       Then re-run this script." >&2
        exit 1
    fi
}
