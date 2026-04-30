#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/container-engine.sh"

normalize_arch() {
	case "$1" in
		x86_64|amd64) echo "amd64" ;;
		aarch64|arm64) echo "arm64" ;;
		*) echo "$1" ;;
	esac
}

prebuilt_arches() {
	if [[ -n "${DOCKER_PLATFORM:-}" ]]; then
		local raw_platforms=${DOCKER_PLATFORM//[[:space:]]/}
		local platform
		IFS=',' read -r -a platforms <<< "${raw_platforms}"
		for platform in "${platforms[@]}"; do
			case "${platform}" in
				linux/amd64) echo "amd64" ;;
				linux/arm64) echo "arm64" ;;
				*)
					echo "Error: unsupported DOCKER_PLATFORM '${platform}'" >&2
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
		supervisor|cluster|supervisor-sideload|supervisor-output)
			echo "openshell-sandbox"
			;;
	esac
}

missing_prebuilt_paths() {
	local target=$1
	local arch
	local binary
	local path

	mapfile -t arches < <(prebuilt_arches)
	read -r -a binaries <<< "$(required_prebuilt_binaries "${target}")"

	for arch in "${arches[@]}"; do
		for binary in "${binaries[@]}"; do
			path="deploy/docker/.build/prebuilt-binaries/${arch}/${binary}"
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
		echo "Staging prebuilt Rust binaries for Docker target '${target}'..."
		mapfile -t arches < <(prebuilt_arches)
		for arch in "${arches[@]}"; do
			PREBUILT_ARCH="${arch}" "${SCRIPT_DIR}/stage-prebuilt-binaries.sh" "${target}"
		done
	fi

	missing="$(missing_prebuilt_paths "${target}")"
	if [[ -n "${missing}" ]]; then
		echo "Error: missing prebuilt Rust binaries required by Docker target '${target}':" >&2
		printf '  %s\n' ${missing} >&2
		echo "Stage binaries at deploy/docker/.build/prebuilt-binaries/<arch>/ before building." >&2
		exit 1
	fi
}

TARGET=${1:?"Usage: docker-build-image.sh <gateway|supervisor|cluster|supervisor-builder|supervisor-output> [extra-args...]"}
shift

DOCKERFILE="deploy/docker/Dockerfile.images"
if [[ ! -f "${DOCKERFILE}" ]]; then
	echo "Error: Dockerfile not found: ${DOCKERFILE}" >&2
	exit 1
fi

IS_FINAL_IMAGE=0
IMAGE_NAME=""
DOCKER_TARGET=""
case "${TARGET}" in
  gateway)
    IS_FINAL_IMAGE=1
    IMAGE_NAME="openshell/gateway"
    DOCKER_TARGET="gateway"
    ;;
  supervisor)
    IS_FINAL_IMAGE=1
    IMAGE_NAME="openshell/supervisor"
    DOCKER_TARGET="supervisor"
    ;;
  cluster)
    IS_FINAL_IMAGE=1
    IMAGE_NAME="openshell/cluster"
    DOCKER_TARGET="cluster"
    ;;
  supervisor-builder)
    DOCKER_TARGET="supervisor-builder"
    ;;
  supervisor-output)
    # Backward-compat alias: same as "supervisor".
    IS_FINAL_IMAGE=1
    IMAGE_NAME="openshell/supervisor"
    DOCKER_TARGET="supervisor"
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
DOCKER_BUILD_CACHE_DIR=${DOCKER_BUILD_CACHE_DIR:-.cache/buildkit}
CACHE_PATH="${DOCKER_BUILD_CACHE_DIR}/images"
mkdir -p "${CACHE_PATH}"

BUILDER_ARGS=()
if ce_is_docker; then
	if [[ -n "${DOCKER_BUILDER:-}" ]]; then
		BUILDER_ARGS=(--builder "${DOCKER_BUILDER}")
	elif [[ -z "${DOCKER_PLATFORM:-}" && -z "${CI:-}" ]]; then
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

# The cluster image embeds the packaged Helm chart.
if [[ "${TARGET}" == "cluster" ]]; then
	mkdir -p deploy/docker/.build/charts
	helm package deploy/helm/openshell -d deploy/docker/.build/charts/ >/dev/null
fi

K3S_ARGS=()
if [[ "${TARGET}" == "cluster" && -n "${K3S_VERSION:-}" ]]; then
	K3S_ARGS=(--build-arg "K3S_VERSION=${K3S_VERSION}")
fi

ensure_prebuilt_binaries "${TARGET}"

TAG_ARGS=()
if [[ "${IS_FINAL_IMAGE}" == "1" ]]; then
	TAG_ARGS=(-t "${IMAGE_NAME}:${IMAGE_TAG}")
fi

OUTPUT_ARGS=()
if [[ -n "${DOCKER_OUTPUT:-}" ]]; then
	OUTPUT_ARGS=(--output "${DOCKER_OUTPUT}")
elif [[ "${IS_FINAL_IMAGE}" == "1" ]]; then
	if [[ "${DOCKER_PUSH:-}" == "1" ]]; then
		OUTPUT_ARGS=(--push)
	elif [[ "${DOCKER_PLATFORM:-}" == *","* ]]; then
		OUTPUT_ARGS=(--push)
	else
		OUTPUT_ARGS=(--load)
	fi
else
	echo "Error: DOCKER_OUTPUT must be set when building target '${TARGET}'" >&2
	exit 1
fi

ce_build \
	${BUILDER_ARGS[@]+"${BUILDER_ARGS[@]}"} \
	${DOCKER_PLATFORM:+--platform ${DOCKER_PLATFORM}} \
	${CACHE_ARGS[@]+"${CACHE_ARGS[@]}"} \
	${K3S_ARGS[@]+"${K3S_ARGS[@]}"} \
	-f "${DOCKERFILE}" \
	--target "${DOCKER_TARGET}" \
	${TAG_ARGS[@]+"${TAG_ARGS[@]}"} \
	--provenance=false \
	"$@" \
	${OUTPUT_ARGS[@]+"${OUTPUT_ARGS[@]}"} \
	.
