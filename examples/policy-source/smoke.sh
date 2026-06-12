#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TARGET_DIR="${REPO_ROOT}/target/debug"
TMP_PARENT="${OPENSHELL_POLICY_SOURCE_TMPDIR:-/tmp}"
TMP_DIR="$(mktemp -d "${TMP_PARENT}/openshell-policy-source.XXXXXX")"
SOCKET="${TMP_DIR}/policy-source.sock"
SERVER_LOG="${TMP_DIR}/server.log"
SERVER_PID=""

cleanup() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

mkdir -p "${TMP_DIR}/bundle/policies" "${TMP_DIR}/bundle/providers"
cp "${SCRIPT_DIR}/bundle/policies/default.yaml" "${TMP_DIR}/bundle/policies/default.yaml"
cp "${SCRIPT_DIR}/bundle/policies/gitlab.yaml" "${TMP_DIR}/bundle/policies/gitlab.yaml"
cp "${SCRIPT_DIR}/bundle/policies/github.yaml" "${TMP_DIR}/bundle/policies/github.yaml"
cp "${SCRIPT_DIR}/bundle/providers/example.yaml" "${TMP_DIR}/bundle/providers/example.yaml"

echo "Building policy source example binaries"
RUSTC_WRAPPER= cargo build \
  --manifest-path "${REPO_ROOT}/Cargo.toml" \
  -p openshell-policy-source-example \
  --bin policy-source-server \
  --bin policy-source-check

echo "Starting policy source server on ${SOCKET}"
"${TARGET_DIR}/policy-source-server" --socket "${SOCKET}" --root "${TMP_DIR}/bundle" \
  >"${SERVER_LOG}" 2>&1 &
SERVER_PID="$!"

for _ in {1..50}; do
  if [[ -S "${SOCKET}" ]]; then
    break
  fi
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "policy source server exited early" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
  fi
  sleep 0.1
done

if [[ ! -S "${SOCKET}" ]]; then
  echo "policy source socket was not created: ${SOCKET}" >&2
  cat "${SERVER_LOG}" >&2
  exit 1
fi

echo "Checking default, gitlab, and github policy documents over gRPC"
"${TARGET_DIR}/policy-source-check" \
  --socket "${SOCKET}" \
  --expect-policy default \
  --expect-policy gitlab \
  --expect-policy github \
  --expect-provider example

echo "Policy source smoke test passed"
