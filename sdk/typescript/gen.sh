#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Generate idiomatic TypeScript from the OpenShell protos using the pinned
# `protoc` toolchain (mise) + the connect-es plugin (@bufbuild/protoc-gen-es).
# No `buf` required. Well-known types (Struct, Timestamp, ...) resolve via
# protoc's bundled include path and render through @bufbuild/protobuf/wkt, so
# we do not generate them ourselves.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PROTO_DIR="$HERE/../../proto"
OUT="$HERE/src/gen"
PLUGIN="$HERE/node_modules/.bin/protoc-gen-es"

rm -rf "$OUT"
mkdir -p "$OUT"

# Only the files the client-facing surface needs (transitive imports included).
protoc \
  -I "$PROTO_DIR" \
  --plugin=protoc-gen-es="$PLUGIN" \
  --es_out="$OUT" \
  --es_opt=target=ts,import_extension=js \
  datamodel.proto sandbox.proto openshell.proto

echo "generated into $OUT:"
ls -1 "$OUT"
