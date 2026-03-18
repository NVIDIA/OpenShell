#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ARCH=""
URL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch)
      ARCH="$2"
      shift 2
      ;;
    --url)
      URL="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$ARCH" ]]; then
  echo "missing required argument: --arch" >&2
  exit 1
fi

if [[ -z "$URL" ]]; then
  echo "missing required argument: --url" >&2
  exit 1
fi

CACHE_DIR="deploy/docker/.build/runtime-bundles"
mkdir -p "$CACHE_DIR"

filename="$(basename "$URL")"
if [[ -z "$filename" || "$filename" == "/" || "$filename" == "." ]]; then
  filename="runtime-bundle-${ARCH}.tar.gz"
fi

target_path="$CACHE_DIR/${ARCH}-${filename}"

if [[ ! -f "$target_path" ]]; then
  curl --fail --location --silent --show-error --output "$target_path" "$URL"
fi

printf '%s\n' "$(pwd)/$target_path"
