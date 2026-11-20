#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# Load only the function under test, without executing the launcher.
source <(sed -n '/^configure_provider_refresh() {/,/^}/p' "$dir/run.sh")
PROVIDER_0_NAME=codex-gator
PROVIDER_0_REFRESH_CREDENTIAL_KEY=CODEX_AUTH_ACCESS_TOKEN
PROVIDER_0_REFRESH_STRATEGY=oauth2-refresh-token
PROVIDER_0_REFRESH_MATERIAL_COUNT=1
PROVIDER_0_REFRESH_MATERIAL_0_NAME=refresh_token
PROVIDER_0_REFRESH_MATERIAL_0_SECRET=true
PROVIDER_0_REFRESH_MATERIAL_0_KIND=fixture
PROVIDER_0_REFRESH_MATERIAL_0_COMMAND=''
PROVIDER_0_REFRESH_MATERIAL_0_PATH=''
PROVIDER_0_REFRESH_MATERIAL_0_QUERY=''
PROVIDER_0_REFRESH_MATERIAL_0_VALUE=''
log() { :; }
fail() { echo "$*" >&2; exit 1; }
resolve_source_value() { echo read >> "$tmp/reads"; echo fixture-secret; }
openshell_cmd() {
    echo "$1 $2 $3" >> "$tmp/calls"
    case "$3" in
        status) echo "${STATUS:-refreshed}"; return "${STATUS_EXIT:-0}" ;;
        configure) return "${CONFIGURE_EXIT:-0}" ;;
        rotate) return "${ROTATE_EXIT:-0}" ;;
        *) return 90 ;;
    esac
}
reset_calls() { : > "$tmp/calls"; : > "$tmp/reads"; }
RESET_REFRESH=0
reset_calls
configure_provider_refresh 0
[[ ! -s "$tmp/reads" ]]
[[ "$(cat "$tmp/calls")" == 'provider refresh status' ]]
echo 'ok - existing refresh is reused without host material reads or rotation'
reset_calls
if STATUS_EXIT=1 configure_provider_refresh 0; then fail 'ignored status error'; fi
[[ ! -s "$tmp/reads" ]]
[[ "$(wc -l < "$tmp/calls")" -eq 1 ]]
echo 'ok - status errors cannot reset credentials'
reset_calls
STATUS='No refresh configuration found' configure_provider_refresh 0
grep -q 'provider refresh configure' "$tmp/calls"
grep -q 'provider refresh rotate' "$tmp/calls"
reset_calls
RESET_REFRESH=1 configure_provider_refresh 0
[[ "$(wc -l < "$tmp/reads")" -eq 1 ]]
if grep -q 'provider refresh status' "$tmp/calls"; then fail 'reset queried old state'; fi
echo 'ok - first setup and explicit reset configure and rotate once'
reset_calls
if RESET_REFRESH=1 ROTATE_EXIT=1 configure_provider_refresh 0; then fail 'ignored rotation error'; fi
[[ "$(grep -c 'provider refresh configure' "$tmp/calls")" -eq 1 ]]
[[ "$(grep -c 'provider refresh rotate' "$tmp/calls")" -eq 1 ]]
reset_calls
if RESET_REFRESH=1 CONFIGURE_EXIT=1 configure_provider_refresh 0; then fail 'ignored configure error'; fi
if grep -q 'provider refresh rotate' "$tmp/calls"; then fail 'rotated after failed configure'; fi
echo 'ok - configure and rotation failures propagate without fallback or retry'
