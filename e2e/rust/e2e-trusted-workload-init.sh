#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build an immutable hostile workload fixture and exercise the same trusted
# initialization contract against either local container driver.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENGINE="${1:-}"

case "${ENGINE}" in
  docker|podman) ;;
  *)
    echo "Usage: $0 docker|podman" >&2
    exit 2
    ;;
esac

if [ -n "${OPENSHELL_GATEWAY_ENDPOINT:-}" ]; then
  echo "ERROR: trusted workload initialization e2e requires its managed gateway config." >&2
  echo "       Unset OPENSHELL_GATEWAY_ENDPOINT before running this focused lane." >&2
  exit 2
fi

IMAGE_TAG="openshell/trusted-workload-init-e2e:$$"

cleanup() {
  "${ENGINE}" image rm --force "${IMAGE_TAG}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Building trusted workload initialization fixture with ${ENGINE}..."
"${ENGINE}" build \
  --file "${ROOT}/e2e/trusted-workload-init/Containerfile" \
  --tag "${IMAGE_TAG}" \
  "${ROOT}/e2e/trusted-workload-init"

IMAGE_ID="$("${ENGINE}" image inspect --format '{{.Id}}' "${IMAGE_TAG}")"
if ! [[ "${IMAGE_ID}" =~ ^sha256:[0-9a-fA-F]{64}$ ]]; then
  echo "ERROR: ${ENGINE} returned a non-immutable fixture image ID: ${IMAGE_ID}" >&2
  exit 2
fi

export OPENSHELL_E2E_TRUSTED_INIT_IMAGE="${IMAGE_ID}"

case "${ENGINE}" in
  docker)
    export OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE="${IMAGE_ID}"
    export OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE_PULL_POLICY=Never
    export OPENSHELL_E2E_DOCKER_TEST=trusted_workload_init
    export OPENSHELL_E2E_DOCKER_FEATURES=e2e-docker
    "${ROOT}/e2e/rust/e2e-docker.sh"
    ;;
  podman)
    export OPENSHELL_E2E_PODMAN_SANDBOX_IMAGE="${IMAGE_ID}"
    export OPENSHELL_E2E_PODMAN_TEST=trusted_workload_init
    export OPENSHELL_E2E_PODMAN_FEATURES=e2e-podman
    "${ROOT}/e2e/rust/e2e-podman.sh"
    ;;
esac
