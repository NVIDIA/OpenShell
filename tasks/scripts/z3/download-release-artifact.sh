#!/bin/sh

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "${SELF_DIR}/common.sh"

TARGET=""
OUTPUT_DIR=""
RELEASE_TAG="${Z3_RELEASE_TAG:-z3-latest}"
REPO="${Z3_RELEASE_REPO:-NVIDIA/OpenShell}"

usage() {
  cat <<'EOF' >&2
Usage: download-release-artifact.sh --target <triple> --output-dir <path> [--release-tag <tag>] [--repo <owner/repo>]

Download a prebuilt Z3 artifact from an OpenShell GitHub release, verify it
against the published checksum file, extract it, and print the extracted root.
EOF
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --target)
      TARGET="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    --release-tag)
      RELEASE_TAG="${2:-}"
      shift 2
      ;;
    --repo)
      REPO="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      ;;
  esac
done

[ -n "$TARGET" ] || usage
[ -n "$OUTPUT_DIR" ] || usage

ASSET_NAME=$(z3_asset_name_for_target "$TARGET")
PACKAGE_DIR_NAME=$(z3_package_dir_name "$TARGET")
CHECKSUMS_NAME="z3-checksums-sha256.txt"

WORKDIR=$(mktemp -d)
cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

ASSET_PATH="${WORKDIR}/${ASSET_NAME}"
CHECKSUMS_PATH="${WORKDIR}/${CHECKSUMS_NAME}"

curl --fail --location --retry 5 --retry-all-errors --silent --show-error \
  --output "$ASSET_PATH" \
  "$(z3_release_url "$REPO" "$RELEASE_TAG" "$ASSET_NAME")"

curl --fail --location --retry 5 --retry-all-errors --silent --show-error \
  --output "$CHECKSUMS_PATH" \
  "$(z3_release_url "$REPO" "$RELEASE_TAG" "$CHECKSUMS_NAME")"

EXPECTED_SHA=$(awk -v asset="$ASSET_NAME" '$2 == asset { print $1 }' "$CHECKSUMS_PATH")
[ -n "$EXPECTED_SHA" ] || {
  echo "checksum entry for ${ASSET_NAME} not found in ${CHECKSUMS_NAME}" >&2
  exit 1
}

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA=$(sha256sum "$ASSET_PATH" | awk '{print $1}')
else
  ACTUAL_SHA=$(shasum -a 256 "$ASSET_PATH" | awk '{print $1}')
fi

[ "$EXPECTED_SHA" = "$ACTUAL_SHA" ] || {
  echo "checksum mismatch for ${ASSET_NAME}" >&2
  echo "expected: ${EXPECTED_SHA}" >&2
  echo "actual:   ${ACTUAL_SHA}" >&2
  exit 1
}

mkdir -p "$OUTPUT_DIR"
rm -rf "${OUTPUT_DIR:?}/${PACKAGE_DIR_NAME}"
tar -xzf "$ASSET_PATH" -C "$OUTPUT_DIR"

EXTRACTED_ROOT="${OUTPUT_DIR}/${PACKAGE_DIR_NAME}"
[ -f "${EXTRACTED_ROOT}/manifest.json" ] || {
  echo "manifest missing from extracted Z3 artifact: ${EXTRACTED_ROOT}" >&2
  exit 1
}
[ -f "${EXTRACTED_ROOT}/lib/pkgconfig/z3.pc" ] || {
  echo "pkg-config metadata missing from extracted Z3 artifact: ${EXTRACTED_ROOT}" >&2
  exit 1
}

printf '%s\n' "$EXTRACTED_ROOT"
