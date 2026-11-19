#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/runtime"
cp "$SCRIPT_DIR/launch.sh" "$tmp/runtime/launch.sh"
printf '%s\n' 'touch "${START_MARKER:?}"' > "$tmp/runtime/entrypoint.sh"
export START_MARKER="$tmp/started"
export OPENSHELL_AGENT_ID=gator OPENSHELL_AGENT_PAYLOAD_VERSION=13

expect_rejected() {
    if bash "$tmp/runtime/launch.sh" > "$tmp/log" 2>&1; then
        echo 'incompatible tooling accepted' >&2
        exit 1
    fi
    [[ ! -e "$START_MARKER" ]]
}

expect_rejected
for metadata in \
    '{"protocol":0,"agent_id":"gator","payload_version":13}' \
    '{"protocol":1,"agent_id":"other","payload_version":13}' \
    '{"protocol":1,"agent_id":"gator","payload_version":12}' \
    'invalid json'; do
    printf '%s\n' "$metadata" > "$tmp/tooling.json"
    expect_rejected
done
echo 'ok - legacy, malformed, wrong-agent, and wrong-version images fail before entrypoint'

printf '%s\n' '{"protocol":1,"agent_id":"gator","payload_version":13}' > "$tmp/tooling.json"
bash "$tmp/runtime/launch.sh"
[[ -e "$START_MARKER" ]]
echo 'ok - matching tooling starts the entrypoint'
