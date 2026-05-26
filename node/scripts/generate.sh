#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Generate TypeScript gRPC stubs from proto definitions.
# Run from the node/ directory or via: mise exec -- bash node/scripts/generate.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_DIR="$(dirname "$SCRIPT_DIR")"
PROTO_DIR="$(dirname "$NODE_DIR")/proto"
OUT_DIR="$NODE_DIR/src/_proto"
PLUGIN="$NODE_DIR/node_modules/.bin/protoc-gen-ts_proto"

if [[ ! -x "$PLUGIN" ]]; then
  echo "error: ts-proto plugin not found — run 'npm install' first" >&2
  exit 1
fi

if ! command -v protoc &>/dev/null; then
  echo "error: protoc not found — activate mise or install protoc" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/*.ts

protoc \
  --plugin="$PLUGIN" \
  --ts_proto_out="$OUT_DIR" \
  --ts_proto_opt=outputServices=grpc-js \
  --ts_proto_opt=env=node \
  --ts_proto_opt=esModuleInterop=true \
  --ts_proto_opt=useOptionals=messages \
  --ts_proto_opt=oneof=unions \
  --ts_proto_opt=useDate=false \
  -I "$PROTO_DIR" \
  "$PROTO_DIR/datamodel.proto" \
  "$PROTO_DIR/sandbox.proto" \
  "$PROTO_DIR/openshell.proto" \
  "$PROTO_DIR/inference.proto"

echo "generated TypeScript stubs → $OUT_DIR"
