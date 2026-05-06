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

sha256_16() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print substr($1, 1, 16)}'
	else
		shasum -a 256 "$1" | awk '{print substr($1, 1, 16)}'
	fi
}

sha256_16_stdin() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum | awk '{print substr($1, 1, 16)}'
	else
		shasum -a 256 | awk '{print substr($1, 1, 16)}'
	fi
}

detect_rust_scope() {
	local dockerfile="$1"
	local rust_from
	rust_from=$(grep -E '^FROM --platform=\$BUILDPLATFORM rust:[^ ]+' "$dockerfile" | head -n1 | sed -E 's/^FROM --platform=\$BUILDPLATFORM rust:([^ ]+).*/\1/' || true)
	if [[ -n "${rust_from}" ]]; then
		echo "rust-${rust_from}"
		return
	fi

	if grep -q "rustup.rs" "$dockerfile"; then
		echo "rustup-stable"
		return
	fi

	echo "no-rust"
}

TARGET=${1:?"Usage: container-build-image.sh <gateway|supervisor|cluster|supervisor-builder|supervisor-output> [extra-args...]"}
shift

CONTAINERFILE=$(ce_resolve_containerfile deploy/docker images)

IS_FINAL_IMAGE=0
IMAGE_NAME=""
BUILD_TARGET=""
case "${TARGET}" in
  gateway)
    IS_FINAL_IMAGE=1
    IMAGE_NAME="openshell/gateway"
    BUILD_TARGET="gateway"
    ;;
  supervisor)
    IS_FINAL_IMAGE=1
    IMAGE_NAME="openshell/supervisor"
    BUILD_TARGET="supervisor"
    ;;
  cluster)
    IS_FINAL_IMAGE=1
    IMAGE_NAME="openshell/cluster"
    BUILD_TARGET="cluster"
    ;;
  supervisor-builder)
    BUILD_TARGET="supervisor-builder"
    ;;
  supervisor-output)
    # Backward-compat alias: same as "supervisor".
    IS_FINAL_IMAGE=1
    IMAGE_NAME="openshell/supervisor"
    BUILD_TARGET="supervisor"
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

SCCACHE_ARGS=()
if [[ -n "${SCCACHE_MEMCACHED_ENDPOINT:-}" ]]; then
	SCCACHE_ARGS=(--build-arg "SCCACHE_MEMCACHED_ENDPOINT=${SCCACHE_MEMCACHED_ENDPOINT}")
fi

VERSION_ARGS=()
if [[ -n "${OPENSHELL_CARGO_VERSION:-}" ]]; then
	VERSION_ARGS=(--build-arg "OPENSHELL_CARGO_VERSION=${OPENSHELL_CARGO_VERSION}")
elif [[ -n "${CI:-}" ]]; then
	CARGO_VERSION=$(uv run python tasks/scripts/release.py get-version --cargo 2>/dev/null || true)
	if [[ -n "${CARGO_VERSION}" ]]; then
		VERSION_ARGS=(--build-arg "OPENSHELL_CARGO_VERSION=${CARGO_VERSION}")
	fi
fi

LOCK_HASH=$(sha256_16 Cargo.lock)
RUST_SCOPE=${RUST_TOOLCHAIN_SCOPE:-$(detect_rust_scope "${CONTAINERFILE}")}
CACHE_SCOPE_INPUT="v2|shared|release|${LOCK_HASH}|${RUST_SCOPE}"
CARGO_TARGET_CACHE_SCOPE=$(printf '%s' "${CACHE_SCOPE_INPUT}" | sha256_16_stdin)

# The cluster image embeds the packaged Helm chart.
if [[ "${TARGET}" == "cluster" ]]; then
	mkdir -p deploy/docker/.build/charts
	helm package deploy/helm/openshell -d deploy/docker/.build/charts/ >/dev/null
fi

K3S_ARGS=()
if [[ "${TARGET}" == "cluster" && -n "${K3S_VERSION:-}" ]]; then
	K3S_ARGS=(--build-arg "K3S_VERSION=${K3S_VERSION}")
fi

# CI builds use codegen-units=1 for maximum optimization; local builds omit
# the arg so cargo uses the Cargo.toml default (parallel codegen, fast links).
CODEGEN_ARGS=()
if [[ -n "${CI:-}" ]]; then
	CODEGEN_ARGS=(--build-arg "CARGO_CODEGEN_UNITS=1")
fi

# OS-128 Phase 4: opt in to consuming pre-built Rust binaries instead of
# compiling inside Docker. Default path (`build`) is unchanged. When
# USE_PREBUILT_BINARIES=true, the Dockerfile's BINARY_SOURCE=prebuilt stages
# are selected, which COPY from deploy/docker/.build/prebuilt-binaries/<arch>/
# in the build context. Callers must stage the binaries before invoking.
BINARY_SOURCE_ARGS=()
if [[ "${USE_PREBUILT_BINARIES:-}" == "true" ]]; then
  case "${TARGET}" in
    gateway|supervisor|cluster|supervisor-output)
      if [[ ! -d deploy/docker/.build/prebuilt-binaries ]]; then
        echo "Error: USE_PREBUILT_BINARIES=true but deploy/docker/.build/prebuilt-binaries/ does not exist" >&2
        echo "  Stage binaries at deploy/docker/.build/prebuilt-binaries/<arch>/openshell-{gateway,sandbox}" >&2
        exit 1
      fi
      BINARY_SOURCE_ARGS=(--build-arg "BINARY_SOURCE=prebuilt")
      ;;
  esac
fi

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

# Default to dev-settings so local builds include test-only settings
# (dummy_bool, dummy_int) that e2e tests depend on, matching CI behaviour.
EXTRA_CARGO_FEATURES="${EXTRA_CARGO_FEATURES:-openshell-core/dev-settings}"

FEATURE_ARGS=()
if [[ -n "${EXTRA_CARGO_FEATURES}" ]]; then
	FEATURE_ARGS=(--build-arg "EXTRA_CARGO_FEATURES=${EXTRA_CARGO_FEATURES}")
fi

ce_build \
	${BUILDER_ARGS[@]+"${BUILDER_ARGS[@]}"} \
	${CONTAINER_PLATFORM:+--platform ${CONTAINER_PLATFORM}} \
	${CACHE_ARGS[@]+"${CACHE_ARGS[@]}"} \
	${SCCACHE_ARGS[@]+"${SCCACHE_ARGS[@]}"} \
	${VERSION_ARGS[@]+"${VERSION_ARGS[@]}"} \
	${K3S_ARGS[@]+"${K3S_ARGS[@]}"} \
	${CODEGEN_ARGS[@]+"${CODEGEN_ARGS[@]}"} \
	${BINARY_SOURCE_ARGS[@]+"${BINARY_SOURCE_ARGS[@]}"} \
	${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"} \
	--build-arg "CARGO_TARGET_CACHE_SCOPE=${CARGO_TARGET_CACHE_SCOPE}" \
	-f "${CONTAINERFILE}" \
	--target "${BUILD_TARGET}" \
	${TAG_ARGS[@]+"${TAG_ARGS[@]}"} \
	--provenance=false \
	"$@" \
	${OUTPUT_ARGS[@]+"${OUTPUT_ARGS[@]}"} \
	.
