#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Smoke test: start the gateway with the VM driver, create a sandbox, then
# signal the gateway (SIGTERM then SIGKILL) and verify that no driver,
# launcher, gvproxy, or libkrun worker processes survive.
#
# Exit codes:
#   0 — both SIGTERM and SIGKILL cleanup passed
#   1 — one or more scenarios leaked survivors

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

PORT="${OPENSHELL_SERVER_PORT:-8091}"
XDG="${TMPDIR:-/tmp}/vm-orphan-xdg-$$"
STATE_DIR="${TMPDIR:-/tmp}/openshell-vm-orphan-$$"
LOG="${TMPDIR:-/tmp}/vm-orphan-$$.log"

cleanup_stray() {
    # Best-effort: kill anything left over from our sandbox ids so repeated
    # runs don't accumulate.
    pkill -9 -f "openshell-vm-orphan-$$" 2>/dev/null || true
    rm -rf "$XDG" "$STATE_DIR" 2>/dev/null || true
    # Preserve the gateway log only on failure so operators can diagnose.
    if [ "${EXIT_CODE:-0}" -ne 0 ]; then
        echo "(log preserved at $LOG)" >&2
    else
        rm -f "$LOG" "$LOG.create" 2>/dev/null || true
    fi
}
trap cleanup_stray EXIT

build_binaries() {
    echo "==> Ensuring binaries are built"
    if [ ! -x "$ROOT/target/debug/openshell-gateway" ] || [ ! -x "$ROOT/target/debug/openshell-driver-vm" ]; then
        cargo build -p openshell-server -p openshell-driver-vm >&2
    fi
    if [ "$(uname -s)" = "Darwin" ]; then
        codesign \
            --entitlements "$ROOT/crates/openshell-driver-vm/entitlements.plist" \
            --force -s - \
            "$ROOT/target/debug/openshell-driver-vm" >/dev/null 2>&1 || true
    fi
}

start_gateway() {
    local health_port=$((PORT + 1))
    echo "==> Starting gateway on port $PORT (state=$STATE_DIR, health=$health_port)"
    mkdir -p "$STATE_DIR"
    OPENSHELL_SERVER_PORT="$PORT" \
    OPENSHELL_HEALTH_PORT="$health_port" \
    OPENSHELL_DB_URL="sqlite:$STATE_DIR/openshell.db" \
    OPENSHELL_DRIVERS=vm \
    OPENSHELL_DRIVER_DIR="$ROOT/target/debug" \
    OPENSHELL_GRPC_ENDPOINT="http://host.containers.internal:$PORT" \
    OPENSHELL_SSH_GATEWAY_HOST=127.0.0.1 \
    OPENSHELL_SSH_GATEWAY_PORT="$PORT" \
    OPENSHELL_SSH_HANDSHAKE_SECRET=dev-vm-driver-secret \
    OPENSHELL_VM_DRIVER_STATE_DIR="$STATE_DIR" \
    OPENSHELL_VM_RUNTIME_COMPRESSED_DIR="$ROOT/target/vm-runtime-compressed" \
    nohup "$ROOT/target/debug/openshell-gateway" --disable-tls \
        > "$LOG" 2>&1 &
    GATEWAY_PID=$!
    echo "gateway pid=$GATEWAY_PID"

    for _ in $(seq 1 60); do
        if grep -q "Server listening" "$LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
            echo "!! gateway died before ready"
            tail -40 "$LOG" >&2
            return 1
        fi
        sleep 1
    done
    echo "!! gateway never reported ready"
    tail -40 "$LOG" >&2
    return 1
}

create_sandbox() {
    echo "==> Creating sandbox (--keep, long-running)"
    mkdir -p "$XDG"
    XDG_CONFIG_HOME="$XDG" "$ROOT/scripts/bin/openshell" gateway add \
        --name vm-orphan http://127.0.0.1:"$PORT" >/dev/null
    XDG_CONFIG_HOME="$XDG" "$ROOT/scripts/bin/openshell" gateway select vm-orphan >/dev/null

    # Run the CLI in the background; it blocks waiting for sleep to finish.
    XDG_CONFIG_HOME="$XDG" "$ROOT/scripts/bin/openshell" sandbox create \
        --name "orphan-$$" --keep -- sleep 99999 \
        > "$LOG.create" 2>&1 &
    CLI_PID=$!

    for _ in $(seq 1 60); do
        if pgrep -f "openshell-vm-orphan-$$|$STATE_DIR/sandboxes/" >/dev/null 2>&1; then
            if pgrep -f gvproxy >/dev/null 2>&1; then
                echo "sandbox came up (cli pid=$CLI_PID)"
                return 0
            fi
        fi
        sleep 2
    done
    echo "!! sandbox never came up"
    tail -40 "$LOG" "$LOG.create" >&2 2>/dev/null || true
    return 1
}

snapshot_kids() {
    # Return all PIDs whose --state-dir or --vm-rootfs references our
    # per-run directory, plus any gvproxy that mentions our socket base.
    pgrep -fl "state-dir $STATE_DIR|$STATE_DIR/sandboxes" 2>/dev/null || true
    pgrep -fl "gvproxy" 2>/dev/null | grep "osd-gv" || true
}

count_alive() {
    local alive
    alive=$(pgrep -f "state-dir $STATE_DIR|$STATE_DIR/sandboxes" 2>/dev/null | wc -l | tr -d ' ')
    local gv
    gv=$(pgrep -f 'gvproxy' 2>/dev/null | xargs -r ps -o pid=,command= -p 2>/dev/null | grep -c 'osd-gv' || true)
    echo $((alive + gv))
}

verify_cleanup() {
    local label="$1"
    local deadline="$2"
    local waited=0
    while [ "$waited" -lt "$deadline" ]; do
        local n
        n=$(count_alive)
        if [ "$n" = "0" ]; then
            echo "   PASS ($label): all descendants gone after ${waited}s"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    echo "   FAIL ($label): $(count_alive) descendants still alive after ${deadline}s:"
    snapshot_kids | sed 's/^/      /'
    return 1
}

run_scenario() {
    local signal="$1"
    local label="$2"
    echo "======================================================"
    echo "Scenario: $label (signal $signal)"
    echo "======================================================"

    start_gateway || return 1
    create_sandbox || { kill -9 "$GATEWAY_PID" 2>/dev/null; return 1; }

    echo "-- process tree before signal --"
    snapshot_kids | sed 's/^/   /'
    echo

    echo "-> kill -$signal $GATEWAY_PID"
    kill "-$signal" "$GATEWAY_PID" 2>/dev/null || true

    verify_cleanup "$label" 15
    local rc=$?

    # Belt-and-braces teardown between scenarios.
    pkill -9 -f "$STATE_DIR/sandboxes|$STATE_DIR " 2>/dev/null || true
    pkill -9 -f 'gvproxy.*osd-gv' 2>/dev/null || true
    rm -rf "$STATE_DIR" /tmp/osd-gv "$XDG" 2>/dev/null || true
    # CLI may still be running; reap it.
    kill "${CLI_PID:-0}" 2>/dev/null || true
    sleep 1

    return $rc
}

main() {
    build_binaries
    local overall=0

    # Clean starting state.
    pkill -9 -f 'openshell-gateway|openshell-driver-vm' 2>/dev/null || true
    pkill -9 -f 'gvproxy.*osd-gv' 2>/dev/null || true
    sleep 1

    if ! run_scenario TERM "graceful SIGTERM"; then
        overall=1
    fi

    if ! run_scenario KILL "abrupt SIGKILL"; then
        overall=1
    fi

    if [ "$overall" -eq 0 ]; then
        echo "ALL SCENARIOS PASSED"
    else
        echo "ONE OR MORE SCENARIOS FAILED"
    fi
    EXIT_CODE=$overall
    return $overall
}

main "$@"
