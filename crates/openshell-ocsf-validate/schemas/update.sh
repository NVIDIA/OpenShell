#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Fetch vendored schemas from the OCSF schema server: the files given, which
# need not exist yet, or every file under v*/. Each file is
# `v<version>/<class>@<profile>+<profile>.json`.
# Trace variants use the native export or the documented OpenShell composition.
set -euo pipefail
OCSF_SCHEMA_TOOL_DIR="$(cd "$(dirname "$0")" && pwd)"
export OCSF_SCHEMA_TOOL_DIR

fetch() {
  set -euo pipefail
  local file="$1" name version class profiles="" tmp formatted donor
  name="$(basename "$file" .json)"
  version="$(basename "$(dirname "$file")")"
  version="${version#v}"
  class="${name%%@*}"
  if [[ "$name" == *@* ]]; then
    profiles="${name#*@}"
    profiles="${profiles//+/,}"
  fi
  tmp="$(mktemp)"
  formatted="$(mktemp)"
  curl -sSfL --retry 3 --max-time 600 \
    "https://schema.ocsf.io/schema/${version}/classes/${class}?profiles=${profiles}" > "$tmp"
  if [[ ",${profiles}," == *,trace,* ]]; then
    donor="$(mktemp)"
    if [[ -n "${OCSF_TRACE_SCHEMA_EXPORT:-}" ]]; then
      cp "$OCSF_TRACE_SCHEMA_EXPORT" "$donor"
    else
      curl -sSfL --retry 3 --max-time 600 \
        "https://schema.ocsf.io/schema/${version}/classes/http_activity?profiles=container,host,network_proxy,security_control,trace" > "$donor"
    fi
    uv run --no-project python "$OCSF_SCHEMA_TOOL_DIR/trace_schema.py" \
      "$file" "$tmp" "$donor" > "$formatted"
    rm -f "$donor"
  else
    uv run --no-project python -m json.tool --indent 2 "$tmp" > "$formatted"
  fi
  chmod 644 "$formatted"
  mkdir -p "$(dirname "$file")"
  mv "$formatted" "$file"
  rm -f "$tmp"
  echo "fetched v${version}/${name}"
}
export -f fetch

if [[ $# -gt 0 ]]; then
  printf '%s\0' "$@"
else
  find "$(cd "$(dirname "$0")" && pwd)" -path '*/v*/*.json' -print0
fi | xargs -0 -n 1 -P 2 bash -c 'fetch "$0"'
