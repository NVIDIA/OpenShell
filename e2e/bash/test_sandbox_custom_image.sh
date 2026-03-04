#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Integration test for building a custom container image and running a sandbox
# with it.
#
# Verifies the full flow:
#   1. nemoclaw sandbox image push --dockerfile <path>  (build + import into cluster)
#   2. nemoclaw sandbox create --image <tag> -- <cmd>   (run sandbox with custom image)
#
# Prerequisites:
#   - A running nemoclaw cluster (nemoclaw cluster admin deploy)
#   - Docker daemon running (for image build)
#   - The `nemoclaw` binary on PATH (or set NAV_BIN)
#
# Usage:
#   ./e2e/bash/test_sandbox_custom_image.sh

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

IMAGE_TAG="e2e-custom-image:test-$(date +%s)"
SANDBOX_NAME=""
TMPDIR_ROOT=""

###############################################################################
# Helpers
###############################################################################

info()  { printf '==> %s\n' "$*" >&2; }
error() { printf 'ERROR: %s\n' "$*" >&2; }

strip_ansi() {
  sed $'s/\x1b\\[[0-9;]*m//g'
}

cleanup() {
  local exit_code=$?

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
# Step 1 — Create a minimal Dockerfile for testing
###############################################################################

info "Creating temporary Dockerfile"

TMPDIR_ROOT=$(mktemp -d)
DOCKERFILE="${TMPDIR_ROOT}/Dockerfile"

cat > "${DOCKERFILE}" <<'DOCKERFILE_CONTENT'
FROM python:3.12-slim

# Create the sandbox user/group so the supervisor can switch to it.
RUN groupadd -g 1000 sandbox && \
    useradd -m -u 1000 -g sandbox sandbox

# Write a marker file so we can verify this is our custom image.
RUN echo "custom-image-e2e-marker" > /opt/marker.txt

CMD ["sleep", "infinity"]
DOCKERFILE_CONTENT

###############################################################################
# Step 2 — Build and push the image into the cluster
###############################################################################

info "Building and pushing custom image: ${IMAGE_TAG}"

PUSH_LOG=$(mktemp)
if ! "${NAV}" sandbox image push \
    --dockerfile "${DOCKERFILE}" \
    --tag "${IMAGE_TAG}" \
    > "${PUSH_LOG}" 2>&1; then
  error "Image push failed"
  cat "${PUSH_LOG}" >&2
  exit 1
fi

info "Image pushed successfully"

###############################################################################
# Step 3 — Create a sandbox with the custom image and verify it works
###############################################################################

info "Creating sandbox with custom image: ${IMAGE_TAG}"

CREATE_LOG=$(mktemp)
if ! "${NAV}" sandbox create \
    --image "${IMAGE_TAG}" \
    -- cat /opt/marker.txt \
    > "${CREATE_LOG}" 2>&1; then
  error "Sandbox create failed"
  cat "${CREATE_LOG}" >&2
  exit 1
fi

# Parse sandbox name from the create output for cleanup.
SANDBOX_NAME=$(
  strip_ansi < "${CREATE_LOG}" | awk '/Name:/ { print $NF }'
) || true

info "Verifying marker file from custom image"

# The sandbox ran `cat /opt/marker.txt` — check that the expected marker
# appears in the output.
if ! strip_ansi < "${CREATE_LOG}" | grep -q "custom-image-e2e-marker"; then
  error "Marker file content not found in sandbox output"
  cat "${CREATE_LOG}" >&2
  exit 1
fi

info "Custom image marker verified"

###############################################################################
# Cleanup is handled by the EXIT trap.
###############################################################################
