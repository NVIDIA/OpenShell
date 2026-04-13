#!/bin/sh

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "${SELF_DIR}/common.sh"

TARGET=""
Z3_VERSION=""
OUTPUT=""

usage() {
  cat <<'EOF' >&2
Usage: build-artifact.sh --target <triple> --z3-version <version> --output <path>

Build a static Z3 release artifact that contains headers, libz3.a, pkg-config
metadata, and a small manifest for the given target triple.
EOF
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --target)
      TARGET="${2:-}"
      shift 2
      ;;
    --z3-version)
      Z3_VERSION="${2:-}"
      shift 2
      ;;
    --output)
      OUTPUT="${2:-}"
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
[ -n "$Z3_VERSION" ] || usage
[ -n "$OUTPUT" ] || usage

ASSET_NAME=$(z3_asset_name_for_target "$TARGET")
PACKAGE_DIR_NAME=$(z3_package_dir_name "$TARGET")

WORKDIR=$(mktemp -d)
cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

SOURCE_ARCHIVE="${WORKDIR}/z3-source.tar.gz"
SOURCE_ROOT="${WORKDIR}/source"
BUILD_ROOT="${WORKDIR}/build"
PACKAGE_PARENT="${WORKDIR}/package"
PACKAGE_ROOT="${PACKAGE_PARENT}/${PACKAGE_DIR_NAME}"

mkdir -p "$SOURCE_ROOT" "$BUILD_ROOT" "$PACKAGE_ROOT" "$(dirname "$OUTPUT")"

SOURCE_URL="https://github.com/Z3Prover/z3/archive/refs/tags/z3-${Z3_VERSION}.tar.gz"
echo "Downloading Z3 ${Z3_VERSION} source from ${SOURCE_URL}"
curl --fail --location --retry 5 --retry-all-errors --silent --show-error \
  --output "$SOURCE_ARCHIVE" \
  "$SOURCE_URL"
tar -xzf "$SOURCE_ARCHIVE" -C "$SOURCE_ROOT"

set -- "${SOURCE_ROOT}"/*
if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
  echo "expected a single extracted Z3 source directory" >&2
  exit 1
fi
SOURCE_DIR="$1"

set -- \
  -S "$SOURCE_DIR" \
  -B "$BUILD_ROOT" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PACKAGE_ROOT" \
  -DCMAKE_INSTALL_INCLUDEDIR=include \
  -DCMAKE_INSTALL_LIBDIR=lib \
  -DZ3_BUILD_LIBZ3_SHARED=false \
  -DZ3_BUILD_EXECUTABLE=false \
  -DZ3_BUILD_TEST_EXECUTABLES=false

if [ -n "${Z3_CMAKE_SYSTEM_NAME:-}" ]; then
  set -- "$@" "-DCMAKE_SYSTEM_NAME=${Z3_CMAKE_SYSTEM_NAME}"
fi
if [ -n "${Z3_CMAKE_SYSTEM_PROCESSOR:-}" ]; then
  set -- "$@" "-DCMAKE_SYSTEM_PROCESSOR=${Z3_CMAKE_SYSTEM_PROCESSOR}"
fi
if [ -n "${MACOSX_DEPLOYMENT_TARGET:-}" ]; then
  set -- "$@" "-DCMAKE_OSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET}"
fi

cmake "$@"
cmake --build "$BUILD_ROOT" --parallel "$(z3_cpu_count)"
cmake --install "$BUILD_ROOT"

HEADER_PATH=$(find "$PACKAGE_ROOT" -path '*/z3.h' -type f | head -n 1 || true)
LIB_PATH=$(find "$PACKAGE_ROOT" -name 'libz3.a' -type f | head -n 1 || true)

[ -n "$HEADER_PATH" ] || { echo "z3.h missing from packaged artifact" >&2; exit 1; }
[ -n "$LIB_PATH" ] || { echo "libz3.a missing from packaged artifact" >&2; exit 1; }

INCLUDE_DIR_NAME=$(basename "$(dirname "$HEADER_PATH")")
LIB_DIR=$(dirname "$LIB_PATH")
LIB_DIR_NAME=$(basename "$LIB_DIR")
PKGCONFIG_DIR="${LIB_DIR}/pkgconfig"
mkdir -p "$PKGCONFIG_DIR"

cat > "${PKGCONFIG_DIR}/z3.pc" <<EOF
prefix=\${pcfiledir}/../..
libdir=\${prefix}/${LIB_DIR_NAME}
includedir=\${prefix}/${INCLUDE_DIR_NAME}

Name: z3
Description: Z3 theorem prover
Version: ${Z3_VERSION}
Libs: -L\${libdir} -lz3
Cflags: -I\${includedir}
EOF

cat > "${PACKAGE_ROOT}/manifest.json" <<EOF
{
  "asset": "${ASSET_NAME}",
  "target": "${TARGET}",
  "z3_version": "${Z3_VERSION}"
}
EOF

tar -C "$PACKAGE_PARENT" -czf "$OUTPUT" "$PACKAGE_DIR_NAME"
echo "Wrote ${OUTPUT}"
