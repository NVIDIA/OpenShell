#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Integration test for bidirectional file sync with a sandbox.
#
# Verifies the full flow:
#   1. nemoclaw sandbox create --keep  (long-running sandbox for sync tests)
#   2. nemoclaw sandbox sync <name> --up <local> <sandbox-dest>  (push)
#   3. nemoclaw sandbox sync <name> --down <sandbox-path> <local-dest>  (pull)
#   4. Single-file round-trip
#
# Prerequisites:
#   - A running nemoclaw cluster (nemoclaw cluster admin deploy)
#   - The `nemoclaw` binary on PATH (or set NAV_BIN)
#
# Usage:
#   ./e2e/bash/test_sandbox_sync.sh

set -euo pipefail

###############################################################################
# Configuration
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ -n "${NAV_BIN:-}" ]]; then
  NAV="${NAV_BIN}"
elif [[ -x "${PROJECT_ROOT}/target/debug/nemoclaw" ]]; then
  NAV="${PROJECT_ROOT}/target/debug/nemoclaw"
else
  NAV="nemoclaw"
fi

SANDBOX_NAME=""
CREATE_PID=""
TMPDIR_ROOT=""

###############################################################################
# Helpers
###############################################################################

info()  { printf '==> %s\n' "$*" >&2; }
error() { printf 'ERROR: %s\n' "$*" >&2; }

strip_ansi() {
  sed $'s/\x1b\\[[0-9;]*m//g'
}

# Kill a process and all of its children.
kill_tree() {
  local pid=$1
  pkill -P "${pid}" 2>/dev/null || true
  kill "${pid}" 2>/dev/null || true
  wait "${pid}" 2>/dev/null || true
}

cleanup() {
  local exit_code=$?

  if [[ -n "${CREATE_PID}" ]]; then
    info "Stopping sandbox create (pid ${CREATE_PID})"
    kill_tree "${CREATE_PID}"
  fi

  if [[ -n "${SANDBOX_NAME}" ]]; then
    info "Deleting sandbox ${SANDBOX_NAME}"
    "${NAV}" sandbox delete "${SANDBOX_NAME}" 2>/dev/null || true
  fi

  if [[ -n "${TMPDIR_ROOT}" && -d "${TMPDIR_ROOT}" ]]; then
    rm -rf "${TMPDIR_ROOT}"
  fi

  if [[ ${exit_code} -eq 0 ]]; then
    info "PASS"
  else
    error "FAIL (exit ${exit_code})"
  fi
  exit "${exit_code}"
}

trap cleanup EXIT

###############################################################################
# Step 1 — Create a sandbox with --keep so it stays alive for sync tests.
#
# `sandbox create --keep -- sleep infinity` blocks forever, so we run it in
# the background and poll the log for the sandbox name and ready marker.
###############################################################################

info "Creating sandbox with sleep infinity"

CREATE_LOG=$(mktemp)

"${NAV}" sandbox create --keep -- sleep infinity \
  > "${CREATE_LOG}" 2>&1 &
CREATE_PID=$!

# Wait for the sandbox to become ready. The CLI prints the phase label
# "Ready" once the sandbox reaches that state. We also check for "Name:"
# in the header to know the sandbox was created.
info "Waiting for sandbox to be ready"
for i in $(seq 1 120); do
  if [[ -f "${CREATE_LOG}" ]] && strip_ansi < "${CREATE_LOG}" | grep -q 'Name:'; then
    # Name is printed in the header; now wait for Ready phase.
    if strip_ansi < "${CREATE_LOG}" | grep -qw 'Ready'; then
      break
    fi
  fi
  if ! kill -0 "${CREATE_PID}" 2>/dev/null; then
    error "Sandbox create exited prematurely"
    cat "${CREATE_LOG}" >&2
    exit 1
  fi
  sleep 1
done

if ! strip_ansi < "${CREATE_LOG}" | grep -qw 'Ready'; then
  error "Sandbox did not become ready within 120s"
  cat "${CREATE_LOG}" >&2
  exit 1
fi

# Parse sandbox name from the create output.
SANDBOX_NAME=$(
  strip_ansi < "${CREATE_LOG}" | awk '/Name:/ { print $NF }'
) || true

if [[ -z "${SANDBOX_NAME}" ]]; then
  error "Could not parse sandbox name from create output"
  cat "${CREATE_LOG}" >&2
  exit 1
fi

info "Sandbox created: ${SANDBOX_NAME}"

###############################################################################
# Step 2 — Sync up: push a local directory into the sandbox.
###############################################################################

info "Preparing local test files"

TMPDIR_ROOT=$(mktemp -d)
LOCAL_UP="${TMPDIR_ROOT}/upload"
mkdir -p "${LOCAL_UP}/subdir"
echo "hello-from-local" > "${LOCAL_UP}/greeting.txt"
echo "nested-content"   > "${LOCAL_UP}/subdir/nested.txt"

info "Syncing local directory up to sandbox"

SYNC_UP_LOG=$(mktemp)
if ! "${NAV}" sandbox sync "${SANDBOX_NAME}" --up "${LOCAL_UP}" /sandbox/uploaded \
    > "${SYNC_UP_LOG}" 2>&1; then
  error "sync --up failed"
  cat "${SYNC_UP_LOG}" >&2
  exit 1
fi

###############################################################################
# Step 3 — Sync down: pull the uploaded files back and verify contents.
###############################################################################

info "Syncing files back down from sandbox"

LOCAL_DOWN="${TMPDIR_ROOT}/download"
mkdir -p "${LOCAL_DOWN}"

SYNC_DOWN_LOG=$(mktemp)
if ! "${NAV}" sandbox sync "${SANDBOX_NAME}" --down /sandbox/uploaded "${LOCAL_DOWN}" \
    > "${SYNC_DOWN_LOG}" 2>&1; then
  error "sync --down failed"
  cat "${SYNC_DOWN_LOG}" >&2
  exit 1
fi

info "Verifying downloaded files"

# Check top-level file.
if [[ ! -f "${LOCAL_DOWN}/greeting.txt" ]]; then
  error "greeting.txt not found after sync --down"
  ls -lR "${LOCAL_DOWN}" >&2
  exit 1
fi

GREETING_CONTENT=$(cat "${LOCAL_DOWN}/greeting.txt")
if [[ "${GREETING_CONTENT}" != "hello-from-local" ]]; then
  error "greeting.txt content mismatch: got '${GREETING_CONTENT}'"
  exit 1
fi

info "greeting.txt verified"

# Check nested file.
if [[ ! -f "${LOCAL_DOWN}/subdir/nested.txt" ]]; then
  error "subdir/nested.txt not found after sync --down"
  ls -lR "${LOCAL_DOWN}" >&2
  exit 1
fi

NESTED_CONTENT=$(cat "${LOCAL_DOWN}/subdir/nested.txt")
if [[ "${NESTED_CONTENT}" != "nested-content" ]]; then
  error "subdir/nested.txt content mismatch: got '${NESTED_CONTENT}'"
  exit 1
fi

info "subdir/nested.txt verified"

###############################################################################
# Step 4 — Large-file round-trip to exercise multi-chunk SSH transport.
#
# The tar archive is streamed through the SSH channel in 4096-byte chunks.
# Historically, a fire-and-forget tokio::spawn per chunk caused out-of-order
# delivery that corrupted the tar stream.  A ~512 KiB file spans many chunks
# and makes such ordering bugs much more likely to surface.
###############################################################################

info "Generating large test file (~512 KiB)"

LARGE_DIR="${TMPDIR_ROOT}/large_upload"
mkdir -p "${LARGE_DIR}"

# Deterministic pseudo-random content so we can verify with a checksum.
dd if=/dev/urandom bs=1024 count=512 2>/dev/null > "${LARGE_DIR}/large.bin"
EXPECTED_HASH=$(shasum -a 256 "${LARGE_DIR}/large.bin" | awk '{print $1}')

info "Syncing large file up to sandbox"
if ! "${NAV}" sandbox sync "${SANDBOX_NAME}" --up "${LARGE_DIR}" /sandbox/large_test \
    > /dev/null 2>&1; then
  error "sync --up large file failed"
  exit 1
fi

info "Syncing large file back down"
LARGE_DOWN="${TMPDIR_ROOT}/large_download"
mkdir -p "${LARGE_DOWN}"

if ! "${NAV}" sandbox sync "${SANDBOX_NAME}" --down /sandbox/large_test "${LARGE_DOWN}" \
    > /dev/null 2>&1; then
  error "sync --down large file failed"
  exit 1
fi

ACTUAL_HASH=$(shasum -a 256 "${LARGE_DOWN}/large.bin" | awk '{print $1}')
if [[ "${EXPECTED_HASH}" != "${ACTUAL_HASH}" ]]; then
  error "large.bin checksum mismatch after round-trip"
  error "  expected: ${EXPECTED_HASH}"
  error "  actual:   ${ACTUAL_HASH}"
  exit 1
fi

ACTUAL_SIZE=$(wc -c < "${LARGE_DOWN}/large.bin" | tr -d ' ')
if [[ "${ACTUAL_SIZE}" -ne 524288 ]]; then
  error "large.bin size mismatch: expected 524288, got ${ACTUAL_SIZE}"
  exit 1
fi

info "Large file round-trip verified (SHA-256 match, ${ACTUAL_SIZE} bytes)"

###############################################################################
# Step 5 — Sync up a single file and round-trip it.
###############################################################################

info "Testing single-file sync"

SINGLE_FILE="${TMPDIR_ROOT}/single.txt"
echo "single-file-payload" > "${SINGLE_FILE}"

if ! "${NAV}" sandbox sync "${SANDBOX_NAME}" --up "${SINGLE_FILE}" /sandbox \
    > /dev/null 2>&1; then
  error "sync --up single file failed"
  exit 1
fi

LOCAL_SINGLE_DOWN="${TMPDIR_ROOT}/single_down"
mkdir -p "${LOCAL_SINGLE_DOWN}"

if ! "${NAV}" sandbox sync "${SANDBOX_NAME}" --down /sandbox/single.txt "${LOCAL_SINGLE_DOWN}" \
    > /dev/null 2>&1; then
  error "sync --down single file failed"
  exit 1
fi

SINGLE_CONTENT=$(cat "${LOCAL_SINGLE_DOWN}/single.txt")
if [[ "${SINGLE_CONTENT}" != "single-file-payload" ]]; then
  error "single.txt content mismatch: got '${SINGLE_CONTENT}'"
  exit 1
fi

info "Single-file round-trip verified"

###############################################################################
# Cleanup is handled by the EXIT trap.
###############################################################################
