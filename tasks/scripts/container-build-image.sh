#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/container-engine.sh"

# Backwards-compatible env var fallbacks: accept CONTAINER_* or DOCKER_*
CONTAINER_BUILD_CACHE_DIR="${CONTAINER_BUILD_CACHE_DIR:-${DOCKER_BUILD_CACHE_DIR:-.cache/buildkit}}"
CONTAINER_BUILDER="${CONTAINER_BUILDER:-${DOCKER_BUILDER:-}}"
CONTAINER_PLATFORM="${CONTAINER_PLATFORM:-${DOCKER_PLATFORM:-}}"
CONTAINER_OUTPUT="${CONTAINER_OUTPUT:-${DOCKER_OUTPUT:-}}"
CONTAINER_PUSH="${CONTAINER_PUSH:-${DOCKER_PUSH:-}}"

normalize_arch() {
	case "$1" in
		x86_64|amd64) echo "amd64" ;;
		aarch64|arm64) echo "arm64" ;;
		*) echo "$1" ;;
	esac
}

prebuilt_arches() {
	if [[ -n "${CONTAINER_PLATFORM:-}" ]]; then
		local raw_platforms=${CONTAINER_PLATFORM//[[:space:]]/}
		local platform
		IFS=',' read -r -a platforms <<< "${raw_platforms}"
		for platform in "${platforms[@]}"; do
			case "${platform}" in
				linux/amd64) echo "amd64" ;;
				linux/arm64) echo "arm64" ;;
				*)
					echo "Error: unsupported CONTAINER_PLATFORM '${platform}'" >&2
					echo "Supported platforms: linux/amd64, linux/arm64" >&2
					exit 1
					;;
			esac
		done
		return
	fi

	normalize_arch "$(ce_info_arch)"
}

required_prebuilt_binaries() {
	case "$1" in
		gateway)
			echo "openshell-gateway"
			;;
		supervisor|supervisor-output)
			echo "openshell-sandbox"
			;;
	esac
}

missing_prebuilt_paths() {
	local target=$1
	local arch
	local binary
	local path

	local arches=()
	while IFS= read -r _a; do arches+=("$_a"); done < <(prebuilt_arches)
	read -r -a binaries <<< "$(required_prebuilt_binaries "${target}")"

	for arch in "${arches[@]}"; do
		for binary in "${binaries[@]}"; do
			path="deploy/container/.build/prebuilt-binaries/${arch}/${binary}"
			if [[ ! -f "${path}" ]]; then
				echo "${path}"
			fi
		done
	done
}

ensure_prebuilt_binaries() {
	local target=$1
	local missing
	local arch

	if [[ -z "${CI:-}" && "${PREBUILT_AUTO_STAGE:-1}" != "0" ]]; then
		echo "Staging prebuilt Rust binaries for container target '${target}'..."
		local arches=()
		while IFS= read -r _a; do arches+=("$_a"); done < <(prebuilt_arches)
		for arch in "${arches[@]}"; do
			PREBUILT_ARCH="${arch}" "${SCRIPT_DIR}/stage-prebuilt-binaries.sh" "${target}"
		done
	fi

	missing="$(missing_prebuilt_paths "${target}")"
	if [[ -n "${missing}" ]]; then
		echo "Error: missing prebuilt Rust binaries required by container target '${target}':" >&2
		printf '  %s\n' ${missing} >&2
		echo "Stage binaries at deploy/container/.build/prebuilt-binaries/<arch>/ before building." >&2
		exit 1
	fi
}

TARGET=${1:?"Usage: container-build-image.sh <gateway|supervisor|supervisor-output> [extra-args...]"}
shift

IS_FINAL_IMAGE=0
IMAGE_NAME=""
CONTAINER_TARGET=""
CONTAINERFILE=""
case "${TARGET}" in
  gateway)
    IS_FINAL_IMAGE=1
    IMAGE_NAME="openshell/gateway"
    CONTAINER_TARGET="gateway"
    CONTAINERFILE=$(ce_resolve_containerfile deploy/container gateway)
    ;;
  supervisor)
    IS_FINAL_IMAGE=1
    IMAGE_NAME="openshell/supervisor"
    CONTAINER_TARGET="supervisor"
    CONTAINERFILE=$(ce_resolve_containerfile deploy/container supervisor)
    ;;
  supervisor-output)
    # Backward-compat alias: same as "supervisor".
    IS_FINAL_IMAGE=1
    IMAGE_NAME="openshell/supervisor"
    CONTAINER_TARGET="supervisor"
    CONTAINERFILE=$(ce_resolve_containerfile deploy/container supervisor)
    ;;
  *)
    echo "Error: unsupported target '${TARGET}'" >&2
    exit 1
    ;;
esac

if [[ -n "${IMAGE_REGISTRY:-}" && "${IS_FINAL_IMAGE}" == "1" ]]; then
	IMAGE_NAME="${IMAGE_REGISTRY}/${IMAGE_NAME#openshell/}"
fi

IMAGE_TAG=${IMAGE_TAG:-dev}
CACHE_PATH="${CONTAINER_BUILD_CACHE_DIR}/images"
mkdir -p "${CACHE_PATH}"

BUILDER_ARGS=()
if ce_is_docker; then
	if [[ -n "${CONTAINER_BUILDER}" ]]; then
		BUILDER_ARGS=(--builder "${CONTAINER_BUILDER}")
	elif [[ -z "${CONTAINER_PLATFORM}" && -z "${CI:-}" ]]; then
		_ctx=$(ce_context_name)
		BUILDER_ARGS=(--builder "${_ctx}")
	fi
fi

CACHE_ARGS=()
if [[ -z "${CI:-}" ]]; then
	if ce_is_docker; then
		if ce_buildx_inspect ${BUILDER_ARGS[@]+"${BUILDER_ARGS[@]}"} 2>/dev/null | grep -q "Driver: docker-container"; then
			CACHE_ARGS=(
				--cache-from "type=local,src=${CACHE_PATH}"
				--cache-to "type=local,dest=${CACHE_PATH},mode=max"
			)
		fi
	fi
fi

ensure_prebuilt_binaries "${TARGET}"

TAG_ARGS=()
if [[ "${IS_FINAL_IMAGE}" == "1" ]]; then
	TAG_ARGS=(-t "${IMAGE_NAME}:${IMAGE_TAG}")
fi

OUTPUT_ARGS=()
if [[ -n "${CONTAINER_OUTPUT}" ]]; then
	OUTPUT_ARGS=(--output "${CONTAINER_OUTPUT}")
elif [[ "${IS_FINAL_IMAGE}" == "1" ]]; then
	if [[ "${CONTAINER_PUSH}" == "1" ]]; then
		OUTPUT_ARGS=(--push)
	elif [[ "${CONTAINER_PLATFORM}" == *","* ]]; then
		OUTPUT_ARGS=(--push)
	else
		OUTPUT_ARGS=(--load)
	fi
else
	echo "Error: CONTAINER_OUTPUT must be set when building target '${TARGET}'" >&2
	exit 1
fi

ce_build \
	${BUILDER_ARGS[@]+"${BUILDER_ARGS[@]}"} \
	${CONTAINER_PLATFORM:+--platform ${CONTAINER_PLATFORM}} \
	${CACHE_ARGS[@]+"${CACHE_ARGS[@]}"} \
	-f "${CONTAINERFILE}" \
	--target "${CONTAINER_TARGET}" \
	${TAG_ARGS[@]+"${TAG_ARGS[@]}"} \
	--provenance=false \
	"$@" \
	${OUTPUT_ARGS[@]+"${OUTPUT_ARGS[@]}"} \
	.
