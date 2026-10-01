#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# shellcheck source=tasks/scripts/check-ci-images.sh
source "$(dirname "${BASH_SOURCE[0]}")/check-ci-images.sh"

fixture_dir=$(mktemp -d)
trap 'rm -rf "$fixture_dir"' EXIT
source_tag=9cb72baa2e61a1b5f12407e6e82da7fdba0aa722
digest=67a9a0c32cb99825e6d3e9d9eec45d67149ea1ff7c11a1b1e1b3480d2d3df684
ref="ghcr.io/nvidia/openshell/ci:$source_tag@sha256:$digest"
ci_image_ref_valid "$ref"
for invalid in \
  ghcr.io/nvidia/openshell/ci \
  ghcr.io/nvidia/openshell/ci:latest \
  "ghcr.io/nvidia/openshell/ci:$source_tag" \
  "ghcr.io/nvidia/openshell/ci:$source_tag@sha256:1234" \
  "ghcr.io/nvidia/openshell/ci:latest@sha256:$digest"; do
  if ci_image_ref_valid "$invalid"; then
    echo "Unexpectedly accepted $invalid" >&2
    exit 1
  fi
done

# Quoted/unquoted consumers, duplicates, and the producer's bare repository.
printf 'image: %s\nimage: "%s"\nimage: '\''%s'\''\nCI_IMAGE: ghcr.io/nvidia/openshell/ci\n' \
  "$ref" "$ref" "$ref" > "$fixture_dir/workflow.yml"
[[ "$(ci_image_refs "$fixture_dir")" == "$ref" ]]
printf 'image: ghcr.io/nvidia/openshell/ci:latest\n' >> "$fixture_dir/workflow.yml"
[[ "$(ci_image_refs "$fixture_dir" | wc -l)" -eq 2 ]]
printf 'image: ghcr.io/nvidia/openshell/ci\n' >> "$fixture_dir/workflow.yml"
[[ "$(ci_image_refs "$fixture_dir" | wc -l)" -eq 3 ]]

index='{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
  {"platform":{"os":"linux","architecture":"amd64"}},
  {"platform":{"os":"linux","architecture":"arm64"}},
  {"platform":{"os":"unknown","architecture":"unknown"}}
]}'
ci_image_index_valid <<< "$index"
jq '.mediaType = "application/vnd.docker.distribution.manifest.list.v2+json"' \
  <<< "$index" | ci_image_index_valid

for mutation in \
  '.mediaType = "application/vnd.oci.image.manifest.v1+json"' \
  '.manifests = [.manifests[0]]' \
  '.manifests = [.manifests[1]]' \
  '.manifests[1].platform.os = "windows"' \
  '.manifests += [.manifests[0]]' \
  'del(.manifests)' ; do
  if jq "$mutation" <<< "$index" | ci_image_index_valid 2>/dev/null; then
    echo "Unexpectedly accepted index mutation: $mutation" >&2
    exit 1
  fi
done
if ci_image_index_valid <<< 'not JSON' 2>/dev/null; then
  echo "Unexpectedly accepted invalid JSON" >&2
  exit 1
fi

# A failed registry lookup or invalid index must stop before running an image.
docker() {
  if [[ "$1" == buildx ]]; then
    if [[ "$registry_failure" == true ]]; then
      return 1
    fi
    printf '%s\n' "$smoke_index"
  else
    touch "$fixture_dir/container-ran"
    cat >/dev/null
  fi
}
for registry_failure in true false; do
  smoke_index=$(jq '.manifests = [.manifests[0]]' <<< "$index")
  if ci_image_smoke "$ref" amd64 >/dev/null 2>&1; then
    echo "Unexpectedly accepted an unavailable or incomplete index" >&2
    exit 1
  fi
  [[ ! -e "$fixture_dir/container-ran" ]]
done
smoke_index=$index
ci_image_smoke "$ref" amd64 >/dev/null
[[ -e "$fixture_dir/container-ran" ]]

echo "CI image pin and multiarchitecture validation tests passed"
