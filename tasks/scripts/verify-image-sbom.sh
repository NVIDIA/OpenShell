#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Validate the final image's SBOM attestation and, for auditable builds, require
# at least one Cargo package discovered from the binary metadata.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/container-engine.sh"

usage() {
  echo "Usage: verify-image-sbom.sh <image-ref> [--require-cargo]" >&2
}

IMAGE=${1:-}
REQUIRE_CARGO=${2:-}
if [[ -z "${IMAGE}" || $# -gt 2 || ( -n "${REQUIRE_CARGO}" && "${REQUIRE_CARGO}" != "--require-cargo" ) ]]; then
  usage
  exit 2
fi

if ! ce_is_docker; then
  echo "Error: SBOM attestations are produced on the Docker/buildx path; ${CONTAINER_ENGINE} has no imagetools equivalent" >&2
  exit 2
fi

echo "==> Inspecting SBOM attestation of ${IMAGE}"
SBOM_JSON="$(ce buildx imagetools inspect "${IMAGE}" --format '{{ json .SBOM }}')"
COUNTS="$(
  jq -r '
    [.. | objects | .SPDX? | select(type == "object")] as $documents
    | [
        ($documents | length),
        ([$documents[] | .. | strings | select(startswith("pkg:cargo/"))] | length)
      ]
    | @tsv
  ' <<<"${SBOM_JSON}"
)"
read -r SPDX_COUNT CARGO_COUNT <<<"${COUNTS}"

if [[ "${SPDX_COUNT}" -eq 0 ]]; then
  echo "Error: ${IMAGE} carries no SPDX SBOM" >&2
  exit 1
fi
if [[ "${REQUIRE_CARGO}" == "--require-cargo" && "${CARGO_COUNT}" -eq 0 ]]; then
  echo "Error: ${IMAGE} SBOM contains no Cargo packages" >&2
  exit 1
fi

echo "SBOM attestation verified: SPDX=${SPDX_COUNT}, Cargo=${CARGO_COUNT}"
