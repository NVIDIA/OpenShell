#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

source "${SCRIPT_DIR}/container-engine.sh"

IMAGES_ROOT="${ROOT}/e2e/gpu/images"
BUILD_DIR="${IMAGES_ROOT}/.build"
BASE_IMAGE="${OPENSHELL_SANDBOX_BASE_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"
CUDA_BUILD_IMAGE="${CUDA_BUILD_IMAGE:-nvcr.io/nvidia/cuda:12.8.1-base-ubuntu22.04}"
CUDA_SAMPLES_REPO="${CUDA_SAMPLES_REPO:-https://github.com/NVIDIA/cuda-samples}"
CUDA_SAMPLES_REF="${CUDA_SAMPLES_REF:-v12.8}"
SUPPORTED_IMAGES=(smoke-pass smoke-fail cuda-basic)

shell_quote() {
  local value=$1
  printf "'%s'" "${value//\'/\'\\\'\'}"
}

write_env_var() {
  local name=$1
  local value=$2
  printf 'export %s=%s\n' "${name}" "$(shell_quote "${value}")"
}

yaml_quote() {
  local value=$1
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '"%s"' "${value}"
}

available_image_dirs() {
  local preferred

  for preferred in "${SUPPORTED_IMAGES[@]}"; do
    if [[ -f "${IMAGES_ROOT}/${preferred}/Dockerfile" ]]; then
      echo "${preferred}"
    fi
  done
}

contains_image() {
  local needle=$1
  shift
  local item
  for item in "$@"; do
    [[ "${item}" == "${needle}" ]] && return 0
  done
  return 1
}

image_env_var() {
  case "$1" in
    smoke-pass) echo "OPENSHELL_E2E_GPU_SMOKE_PASS_IMAGE" ;;
    smoke-fail) echo "OPENSHELL_E2E_GPU_SMOKE_FAIL_IMAGE" ;;
    cuda-basic) echo "OPENSHELL_E2E_GPU_CUDA_WORKLOAD_IMAGE" ;;
    *)
      echo "unsupported GPU workload image source directory: $1" >&2
      exit 1
      ;;
  esac
}

image_expectation() {
  case "$1" in
    smoke-fail) echo "fail" ;;
    smoke-pass|cuda-basic) echo "pass" ;;
    *)
      echo "unsupported GPU workload image source directory: $1" >&2
      exit 1
      ;;
  esac
}

workload_input_fingerprint() {
  local -a names=("$@")

  {
    printf 'OPENSHELL_SANDBOX_BASE_IMAGE=%s\n' "${BASE_IMAGE}"
    if contains_image cuda-basic "${names[@]}"; then
      printf 'CUDA_BUILD_IMAGE=%s\n' "${CUDA_BUILD_IMAGE}"
      printf 'CUDA_SAMPLES_REPO=%s\n' "${CUDA_SAMPLES_REPO}"
      printf 'CUDA_SAMPLES_REF=%s\n' "${CUDA_SAMPLES_REF}"
    fi
  } | git -C "${ROOT}" hash-object --stdin | cut -c1-8
}

mapfile -t available < <(available_image_dirs)
if [[ ${#available[@]} -eq 0 ]]; then
  echo "No GPU workload image Dockerfiles found under ${IMAGES_ROOT}" >&2
  exit 1
fi

selected=()
if [[ -n "${OPENSHELL_GPU_WORKLOAD_IMAGES:-}" ]]; then
  IFS=',' read -r -a requested <<< "${OPENSHELL_GPU_WORKLOAD_IMAGES}"
  for raw in "${requested[@]}"; do
    name="${raw//[[:space:]]/}"
    [[ -z "${name}" ]] && continue
    if ! contains_image "${name}" "${available[@]}"; then
      echo "Unknown GPU workload image source directory: ${name}" >&2
      echo "Available: ${available[*]}" >&2
      exit 1
    fi
    selected+=("${name}")
  done
else
  selected=("${available[@]}")
fi

if [[ ${#selected[@]} -eq 0 ]]; then
  echo "No GPU workload images selected" >&2
  exit 1
fi

source_sha="$(git -C "${ROOT}" rev-parse HEAD)"
source_short_sha="$(git -C "${ROOT}" rev-parse --short HEAD)"
source_dirty=false
if [[ -n "$(git -C "${ROOT}" status --short)" ]]; then
  source_dirty=true
fi

if [[ -n "${OPENSHELL_GPU_WORKLOAD_IMAGE_TAG:-}" ]]; then
  image_tag="${OPENSHELL_GPU_WORKLOAD_IMAGE_TAG}"
else
  input_fingerprint="$(workload_input_fingerprint "${selected[@]}")"
  image_tag="${source_short_sha}-${input_fingerprint}"
  if [[ "${source_dirty}" == "true" ]]; then
    image_tag="${image_tag}-dirty"
  fi
fi
input_fingerprint="$(workload_input_fingerprint "${selected[@]}")"

declare -A image_refs=()

echo "Building GPU workload images with ${CONTAINER_ENGINE}"
echo "Source: ${source_short_sha} (dirty: ${source_dirty})"
echo "Tag: ${image_tag}"

for name in "${selected[@]}"; do
  image_name="gpu-workload-${name}"
  image_ref="localhost/openshell/${image_name}:${image_tag}"
  context="${IMAGES_ROOT}/${name}"

  build_args=(
    --build-arg "OPENSHELL_SANDBOX_BASE_IMAGE=${BASE_IMAGE}"
  )
  build_labels=(
    --label "com.nvidia.openshell.gpu-workload.source=${name}"
    --label "com.nvidia.openshell.gpu-workload.base-image=${BASE_IMAGE}"
    --label "com.nvidia.openshell.gpu-workload.input-fingerprint=${input_fingerprint}"
    --label "org.opencontainers.image.revision=${source_sha}"
  )
  if [[ "${name}" == "cuda-basic" ]]; then
    build_args+=(
      --build-arg "CUDA_BUILD_IMAGE=${CUDA_BUILD_IMAGE}"
      --build-arg "CUDA_SAMPLES_REPO=${CUDA_SAMPLES_REPO}"
      --build-arg "CUDA_SAMPLES_REF=${CUDA_SAMPLES_REF}"
    )
    build_labels+=(
      --label "com.nvidia.openshell.gpu-workload.cuda-build-image=${CUDA_BUILD_IMAGE}"
      --label "com.nvidia.openshell.gpu-workload.cuda-samples-repo=${CUDA_SAMPLES_REPO}"
      --label "com.nvidia.openshell.gpu-workload.cuda-samples-ref=${CUDA_SAMPLES_REF}"
    )
  fi

  echo
  echo "Building ${name} as ${image_ref}"
  ce_build \
    --load \
    --provenance=false \
    -t "${image_ref}" \
    "${build_labels[@]}" \
    "${build_args[@]}" \
    "${context}"

  image_refs["${name}"]="${image_ref}"
done

mkdir -p "${BUILD_DIR}"
latest_env="${BUILD_DIR}/latest.env"
manifest_path="${BUILD_DIR}/workloads.yaml"
{
  echo "# Generated by mise run e2e:workloads:build"
  echo "# Source this file to use the most recently built GPU workload images."
  write_env_var OPENSHELL_GPU_WORKLOAD_IMAGE_TAG "${image_tag}"
  write_env_var OPENSHELL_GPU_WORKLOAD_IMAGE_SOURCE_PATH "${IMAGES_ROOT}"
  write_env_var OPENSHELL_GPU_WORKLOAD_IMAGE_SOURCE_SHA "${source_sha}"
  write_env_var OPENSHELL_GPU_WORKLOAD_IMAGE_SOURCE_DIRTY "${source_dirty}"
  write_env_var OPENSHELL_GPU_WORKLOAD_IMAGE_INPUT_FINGERPRINT "${input_fingerprint}"
  write_env_var OPENSHELL_SANDBOX_BASE_IMAGE "${BASE_IMAGE}"
  write_env_var CUDA_BUILD_IMAGE "${CUDA_BUILD_IMAGE}"
  write_env_var CUDA_SAMPLES_REPO "${CUDA_SAMPLES_REPO}"
  write_env_var CUDA_SAMPLES_REF "${CUDA_SAMPLES_REF}"
  write_env_var OPENSHELL_GPU_WORKLOAD_CONTAINER_ENGINE "${CONTAINER_ENGINE}"
  write_env_var OPENSHELL_E2E_WORKLOAD_MANIFEST "${manifest_path}"
  for name in "${selected[@]}"; do
    write_env_var "$(image_env_var "${name}")" "${image_refs[${name}]}"
  done
} > "${latest_env}"

{
  echo "schema_version: 1"
  echo "generated_by: $(yaml_quote "mise run e2e:workloads:build")"
  echo "source:"
  echo "  path: $(yaml_quote "${IMAGES_ROOT}")"
  echo "  revision: $(yaml_quote "${source_sha}")"
  echo "  dirty: ${source_dirty}"
  echo "  input_fingerprint: $(yaml_quote "${input_fingerprint}")"
  echo "  container_engine: $(yaml_quote "${CONTAINER_ENGINE}")"
  echo "  inputs:"
  echo "    openshell_sandbox_base_image: $(yaml_quote "${BASE_IMAGE}")"
  echo "    cuda_build_image: $(yaml_quote "${CUDA_BUILD_IMAGE}")"
  echo "    cuda_samples_repo: $(yaml_quote "${CUDA_SAMPLES_REPO}")"
  echo "    cuda_samples_ref: $(yaml_quote "${CUDA_SAMPLES_REF}")"
  echo "workloads:"
  for name in "${selected[@]}"; do
    echo "  - name: $(yaml_quote "${name}")"
    echo "    image: $(yaml_quote "${image_refs[${name}]}")"
    echo "    command:"
    echo "      - $(yaml_quote "/usr/local/bin/openshell-gpu-workload")"
    echo "    expect: $(yaml_quote "$(image_expectation "${name}")")"
    echo "    requirements:"
    echo "      gpu: true"
  done
} > "${manifest_path}"

echo
echo "Wrote ${latest_env}"
echo "Wrote ${manifest_path}"
echo "Built images:"
for name in "${selected[@]}"; do
  echo "  ${name}: ${image_refs[${name}]}"
done
