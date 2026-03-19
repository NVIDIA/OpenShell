#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

PLATFORM=""
RUNTIME_BUNDLE_URL=""
RUNTIME_BUNDLE_URL_AMD64=""
RUNTIME_BUNDLE_URL_ARM64=""
RUNTIME_BUNDLE_GITHUB_REPO=""
RUNTIME_BUNDLE_RELEASE_TAG=""
RUNTIME_BUNDLE_FILENAME_PREFIX=""
RUNTIME_BUNDLE_VERSION=""

derive_runtime_bundle_url() {
  local arch="$1"

  if [[ -z "$RUNTIME_BUNDLE_GITHUB_REPO" || -z "$RUNTIME_BUNDLE_RELEASE_TAG" || -z "$RUNTIME_BUNDLE_FILENAME_PREFIX" || -z "$RUNTIME_BUNDLE_VERSION" ]]; then
    echo "missing required runtime bundle default metadata" >&2
    exit 1
  fi

  printf 'https://github.com/%s/releases/download/%s/%s_%s_%s.tar.gz\n' \
    "$RUNTIME_BUNDLE_GITHUB_REPO" \
    "$RUNTIME_BUNDLE_RELEASE_TAG" \
    "$RUNTIME_BUNDLE_FILENAME_PREFIX" \
    "$RUNTIME_BUNDLE_VERSION" \
    "$arch"
}

is_supported_multiarch_platform_set() {
  local platform_list="$1"
  local seen_amd64=0
  local seen_arm64=0
  local count=0
  local platform

  IFS=',' read -r -a platforms <<< "$platform_list"
  for platform in "${platforms[@]}"; do
    count=$((count + 1))
    case "$platform" in
      linux/amd64)
        if [[ "$seen_amd64" -eq 1 ]]; then
          return 1
        fi
        seen_amd64=1
        ;;
      linux/arm64)
        if [[ "$seen_arm64" -eq 1 ]]; then
          return 1
        fi
        seen_arm64=1
        ;;
      *)
        return 1
        ;;
    esac
  done

  [[ "$count" -eq 2 && "$seen_amd64" -eq 1 && "$seen_arm64" -eq 1 ]]
}

resolve_runtime_bundle_url() {
  local arch="$1"
  local explicit_url="$2"

  if [[ -n "$explicit_url" ]]; then
    printf '%s\n' "$explicit_url"
    return 0
  fi

  derive_runtime_bundle_url "$arch"
}

resolve_single_arch_runtime_bundle_url() {
  local platform="$1"
  local arch="$2"

  if [[ -n "$RUNTIME_BUNDLE_URL" ]]; then
    printf '%s\n' "$RUNTIME_BUNDLE_URL"
    return 0
  fi

  case "$arch" in
    amd64)
      if [[ -n "$RUNTIME_BUNDLE_URL_ARM64" ]]; then
        echo "--runtime-bundle-url-arm64 is not supported for single-arch platform $platform; use --runtime-bundle-url or --runtime-bundle-url-amd64" >&2
        exit 1
      fi
      resolve_runtime_bundle_url "$arch" "$RUNTIME_BUNDLE_URL_AMD64"
      ;;
    arm64)
      if [[ -n "$RUNTIME_BUNDLE_URL_AMD64" ]]; then
        echo "--runtime-bundle-url-amd64 is not supported for single-arch platform $platform; use --runtime-bundle-url or --runtime-bundle-url-arm64" >&2
        exit 1
      fi
      resolve_runtime_bundle_url "$arch" "$RUNTIME_BUNDLE_URL_ARM64"
      ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)
      PLATFORM="$2"
      shift 2
      ;;
    --runtime-bundle-url)
      RUNTIME_BUNDLE_URL="$2"
      shift 2
      ;;
    --runtime-bundle-url-amd64)
      RUNTIME_BUNDLE_URL_AMD64="$2"
      shift 2
      ;;
    --runtime-bundle-url-arm64)
      RUNTIME_BUNDLE_URL_ARM64="$2"
      shift 2
      ;;
    --runtime-bundle-github-repo)
      RUNTIME_BUNDLE_GITHUB_REPO="$2"
      shift 2
      ;;
    --runtime-bundle-release-tag)
      RUNTIME_BUNDLE_RELEASE_TAG="$2"
      shift 2
      ;;
    --runtime-bundle-filename-prefix)
      RUNTIME_BUNDLE_FILENAME_PREFIX="$2"
      shift 2
      ;;
    --runtime-bundle-version)
      RUNTIME_BUNDLE_VERSION="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$PLATFORM" ]]; then
  echo "missing required argument: --platform" >&2
  exit 1
fi

if [[ "$PLATFORM" == *","* ]]; then
  if [[ -n "$RUNTIME_BUNDLE_URL" ]]; then
    echo "--runtime-bundle-url is not supported for multi-arch builds; use --runtime-bundle-url-amd64 and --runtime-bundle-url-arm64" >&2
    exit 1
  fi

  if ! is_supported_multiarch_platform_set "$PLATFORM"; then
    echo "unsupported multi-arch platform set: $PLATFORM" >&2
    exit 1
  fi

  amd64_url="$(resolve_runtime_bundle_url amd64 "$RUNTIME_BUNDLE_URL_AMD64")"
  arm64_url="$(resolve_runtime_bundle_url arm64 "$RUNTIME_BUNDLE_URL_ARM64")"

  amd64_bundle="$(bash tasks/scripts/download-runtime-bundle.sh --arch amd64 --url "$amd64_url")"
  arm64_bundle="$(bash tasks/scripts/download-runtime-bundle.sh --arch arm64 --url "$arm64_url")"

  DOCKER_REGISTRY="${IMAGE_REGISTRY:?IMAGE_REGISTRY is required for multi-arch cluster builds}" \
  OPENSHELL_RUNTIME_BUNDLE_TARBALL_AMD64="$amd64_bundle" \
  OPENSHELL_RUNTIME_BUNDLE_TARBALL_ARM64="$arm64_bundle" \
  DOCKER_PLATFORMS="$PLATFORM" \
  mise run --no-prepare docker:build:cluster:multiarch
  exit 0
fi

case "$PLATFORM" in
  linux/amd64)
    arch="amd64"
    ;;
  linux/arm64)
    arch="arm64"
    ;;
  *)
    echo "unsupported platform: $PLATFORM" >&2
    exit 1
    ;;
esac

RUNTIME_BUNDLE_URL="$(resolve_single_arch_runtime_bundle_url "$PLATFORM" "$arch")"

runtime_bundle_tarball="$(bash tasks/scripts/download-runtime-bundle.sh --arch "$arch" --url "$RUNTIME_BUNDLE_URL")"

OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_bundle_tarball" \
DOCKER_PLATFORM="$PLATFORM" \
mise run --no-prepare docker:build:cluster
