#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

OUTPUT_FORMAT="${1:?Usage: go_proto_check.sh <text|json>}"
if [ "$OUTPUT_FORMAT" != "text" ] && [ "$OUTPUT_FORMAT" != "json" ]; then
  echo "ERROR: output format must be 'text' or 'json'." >&2
  exit 2
fi

SDK_ROOT=$(pwd -P)
REPO_ROOT=$(cd ../.. && pwd -P)

emit_error() {
  local message=$1
  if [ "$OUTPUT_FORMAT" = "json" ]; then
    jq -n -c --arg message "$message" \
      '{sdk:"go", synced:false, files:[], summary:$message, error:$message}'
  else
    echo "ERROR: $message" >&2
  fi
}

TOOLS=(buf protoc-gen-go protoc-gen-go-grpc)
if [ "$OUTPUT_FORMAT" = "json" ]; then
  TOOLS+=(jq)
fi
for tool in "${TOOLS[@]}"; do
  if ! command -v "$tool" &>/dev/null; then
    if [ "$OUTPUT_FORMAT" = "json" ] && [ "$tool" = "jq" ]; then
      echo '{"sdk":"go","synced":false,"files":[],"summary":"jq not found","error":"jq not found"}'
    else
      emit_error "$tool not found. Run 'mise install' to install it."
    fi
    exit 1
  fi
done

if find proto -maxdepth 1 -name '*.proto' -print -quit | grep -q .; then
  emit_error "sdk/go/proto contains copied proto sources; sources belong in the repository root proto/ directory."
  exit 1
fi

WORK_DIR=$(mktemp -d)
RESULTS_FILE=$(mktemp)
GENERATION_LOG=$(mktemp)
trap 'rm -rf "$WORK_DIR"; rm -f "$RESULTS_FILE" "$GENERATION_LOG"' EXIT

CHECK_TEMPLATE=$(sed 's|out: sdk/go|out: '"$WORK_DIR"'|' buf.gen.yaml)
if ! (cd "$REPO_ROOT" && buf generate --template "$CHECK_TEMPLATE") >"$GENERATION_LOG" 2>&1; then
  if [ "$OUTPUT_FORMAT" = "text" ]; then
    cat "$GENERATION_LOG" >&2
  fi
  emit_error "buf generate failed"
  exit 1
fi

while IFS= read -r generated; do
  relative_path=${generated#"$WORK_DIR/proto/"}
  committed="$SDK_ROOT/proto/$relative_path"
  if [ ! -f "$committed" ]; then
    printf '%s\t%s\t%s\n' "$relative_path" "added" "0" >>"$RESULTS_FILE"
    continue
  fi

  diff_lines=$(diff -u "$committed" "$generated" 2>/dev/null | wc -l | tr -d ' ') || true
  if [ "$diff_lines" -gt 0 ]; then
    printf '%s\t%s\t%s\n' "$relative_path" "modified" "$diff_lines" >>"$RESULTS_FILE"
  fi
done < <(find "$WORK_DIR/proto" -name '*.go' -type f | sort)

while IFS= read -r committed; do
  relative_path=${committed#"$SDK_ROOT/proto/"}
  if [ ! -f "$WORK_DIR/proto/$relative_path" ]; then
    printf '%s\t%s\t%s\n' "$relative_path" "removed" "0" >>"$RESULTS_FILE"
  fi
done < <(find "$SDK_ROOT/proto" -name '*.go' -type f | sort)

if [ "$OUTPUT_FORMAT" = "text" ]; then
  if [ ! -s "$RESULTS_FILE" ]; then
    echo "Proto check passed: generated files are up to date."
    exit 0
  fi

  echo "ERROR: Generated proto files are out of date."
  echo "Run 'mise run go:proto:gen' to regenerate."
  echo ""
  while IFS=$'\t' read -r name status diff_lines; do
    echo "$status: $name ($diff_lines diff lines)"
  done <"$RESULTS_FILE"
  exit 1
fi

REPORT=$(jq -R -c -s --arg sdk "go" '
  split("\n") | map(select(length > 0) | split("\t") |
    {name: .[0], status: .[1], diff_lines: (.[2] | tonumber)}) |
  {sdk: $sdk, synced: (length == 0), files: .,
   summary: (if length == 0 then "all files synced"
             else "\(length) file(s) drifted" end)}
' "$RESULTS_FILE")
echo "$REPORT"

SYNCED=$(echo "$REPORT" | jq -r '.synced')
[ "$SYNCED" = "true" ] && exit 0 || exit 1
