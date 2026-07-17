#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="$(CONTENT_GUARD_SMOKE_HOST=192.0.2.10 "$EXAMPLE_DIR/smoke.sh" --print-config)"

grep -Fq '[[openshell.supervisor.middleware]]' <<<"$OUTPUT"
grep -Eq 'grpc_endpoint = "http://192\.0\.2\.10:[0-9]+"' <<<"$OUTPUT"
grep -Fq 'name = "content-guard-example"' <<<"$OUTPUT"
grep -Fq 'max_body_bytes = 262144' <<<"$OUTPUT"
grep -Fq 'timeout = "500ms"' <<<"$OUTPUT"
grep -Fq 'host: httpbin.org' "$EXAMPLE_DIR/policy.yaml"
grep -Fq 'host: httpbingo.org' "$EXAMPLE_DIR/policy.yaml"

if "$EXAMPLE_DIR/smoke.sh" --unknown >/dev/null 2>&1; then
  echo "smoke.sh accepted an unknown argument" >&2
  exit 1
fi

echo "content guard smoke launcher checks passed"
