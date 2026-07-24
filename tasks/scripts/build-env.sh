#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared build-environment helpers for host-side cross-compilation.
#
# Source this file (do not execute it) and call the helpers before invoking
# cargo-zigbuild on the host.

# ensure_build_nofile_limit raises the per-process open-file limit before a
# host cargo-zigbuild cross-compile. The static *-unknown-linux-musl link opens
# hundreds of .rlib files simultaneously, which exceeds macOS's default soft
# limit of 256 and fails with ProcessFdQuotaExceeded. The raised limit
# propagates to the cargo/zig children the caller spawns.
#
# The limit is read from OPENSHELL_BUILD_NOFILE_LIMIT (default 8192), honoring
# the legacy OPENSHELL_VM_BUILD_NOFILE_LIMIT for back-compat. This is a no-op on
# Linux and when cargo-zigbuild is not installed (native builds, CI Linux
# runners), so it must be safe to call unconditionally.
ensure_build_nofile_limit() {
    local desired="${OPENSHELL_BUILD_NOFILE_LIMIT:-${OPENSHELL_VM_BUILD_NOFILE_LIMIT:-8192}}"
    local minimum=1024
    local current=""
    local hard=""
    local target=""

    [ "$(uname -s)" = "Darwin" ] || return 0
    command -v cargo-zigbuild >/dev/null 2>&1 || return 0

    current="$(ulimit -n 2>/dev/null || echo "")"
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

    if [ "${target}" -gt "${current}" ] && ulimit -n "${target}" 2>/dev/null; then
        echo "==> Raised open file limit for cargo-zigbuild: ${current} -> $(ulimit -n)"
    fi

    current="$(ulimit -n 2>/dev/null || echo "${current}")"
    case "${current}" in
        ''|*[!0-9]*)
            return 0
            ;;
    esac

    if [ "${current}" -lt "${desired}" ]; then
        echo "WARNING: Open file limit is ${current}; cargo-zigbuild is more reliable at ${desired}+ on macOS."
    fi

    if [ "${current}" -lt "${minimum}" ]; then
        echo "ERROR: Open file limit (${current}) is too low for cargo-zigbuild on macOS." >&2
        echo "       Run: ulimit -n ${desired}" >&2
        echo "       Then re-run this script." >&2
        exit 1
    fi
}
