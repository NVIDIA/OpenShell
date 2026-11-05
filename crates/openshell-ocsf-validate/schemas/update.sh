#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Fetch vendored schemas from the OCSF schema server: the files given, which
# need not exist yet, or every file under v*/. Each file is
# `v<version>/<class>@<profile>+<profile>.json`.
set -euo pipefail

fetch() {
  set -euo pipefail
  local file="$1" name version class profiles="" tmp
  name="$(basename "$file" .json)"
  version="$(basename "$(dirname "$file")")"
  version="${version#v}"
  class="${name%%@*}"
  if [[ "$name" == *@* ]]; then
    profiles="${name#*@}"
    profiles="${profiles//+/,}"
  fi
  tmp="$(mktemp)"
  curl -sSfL --retry 3 --max-time 600 \
    "https://schema.ocsf.io/schema/${version}/classes/${class}?profiles=${profiles}" \
    | python3 -m json.tool --indent 2 > "$tmp"
  chmod 644 "$tmp"
  mkdir -p "$(dirname "$file")"
  mv "$tmp" "$file"
  echo "fetched v${version}/${name}"
}
export -f fetch

if [[ $# -gt 0 ]]; then
  printf '%s\0' "$@"
else
  find "$(cd "$(dirname "$0")" && pwd)" -path '*/v*/*.json' -print0
fi | xargs -0 -n 1 -P 2 bash -c 'fetch "$0"'
