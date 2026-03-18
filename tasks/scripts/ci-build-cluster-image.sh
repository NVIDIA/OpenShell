#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

PLATFORM=""
RUNTIME_BUNDLE_URL=""
RUNTIME_BUNDLE_URL_AMD64=""
RUNTIME_BUNDLE_URL_ARM64=""

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
  if [[ -z "$RUNTIME_BUNDLE_URL_AMD64" || -z "$RUNTIME_BUNDLE_URL_ARM64" ]]; then
    echo "missing required arguments: --runtime-bundle-url-amd64 and --runtime-bundle-url-arm64" >&2
    exit 1
  fi

  amd64_bundle="$(bash tasks/scripts/download-runtime-bundle.sh --arch amd64 --url "$RUNTIME_BUNDLE_URL_AMD64")"
  arm64_bundle="$(bash tasks/scripts/download-runtime-bundle.sh --arch arm64 --url "$RUNTIME_BUNDLE_URL_ARM64")"

  DOCKER_REGISTRY="${IMAGE_REGISTRY:?IMAGE_REGISTRY is required for multi-arch cluster builds}" \
  OPENSHELL_RUNTIME_BUNDLE_TARBALL_AMD64="$amd64_bundle" \
  OPENSHELL_RUNTIME_BUNDLE_TARBALL_ARM64="$arm64_bundle" \
  DOCKER_PLATFORMS="$PLATFORM" \
  mise run --no-prepare docker:build:cluster:multiarch
  exit 0
fi

if [[ -z "$RUNTIME_BUNDLE_URL" ]]; then
  echo "missing required argument: --runtime-bundle-url" >&2
  exit 1
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

runtime_bundle_tarball="$(bash tasks/scripts/download-runtime-bundle.sh --arch "$arch" --url "$RUNTIME_BUNDLE_URL")"

OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_bundle_tarball" \
DOCKER_PLATFORM="$PLATFORM" \
mise run --no-prepare docker:build:cluster
