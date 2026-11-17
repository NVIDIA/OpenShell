#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
export OPENSHELL_TELEMETRY_ENABLED="${OPENSHELL_TELEMETRY_ENABLED:-false}"

# Requires a registered gateway with TLS configured, or explicit gateway env
# overrides. All calls use that selection; this script never changes it.
repo=$(git rev-parse --show-toplevel)
prefix="mp-$(date +%s)"
# Same pinned tool-capable workload as the repository's E2E harness.
image="${OPENSHELL_METRICS_DEMO_IMAGE:-ghcr.io/astral-sh/uv:0.12.17-python3.12-trixie-slim@sha256:9a59bb7206905ccaae4f7dab222fbac47c125a21e5fc16f43f427cd6c940ade3}"
for suffix in a b; do
  openshell sandbox create --detach --name "${prefix}-${suffix}" \
    --from "$image" \
    --policy "${repo}/deploy/helm/supervisor-metrics-dev/policy.yaml" \
    -- sh -c 'exec sleep infinity'
done

name="${prefix}-a"
openshell sandbox exec --name "$name" --no-tty -- uv run --no-project python -c '
import time, urllib.error, urllib.request
for _ in range(5):
    with urllib.request.urlopen("http://example.com", timeout=10) as response:
        assert response.status == 200
    try:
        urllib.request.urlopen(urllib.request.Request("http://example.com", data=b"metrics-poc", method="POST"), timeout=10)
    except urllib.error.HTTPError as error:
        assert error.code == 403
        assert b"policy_denied" in error.read()
        print("POST denied by HTTP policy", flush=True)
    else:
        raise RuntimeError("Expected POST to be denied by the read-only rule")
    try:
        urllib.request.urlopen("http://example.org", timeout=10)
    except (urllib.error.URLError, OSError):
        print("example.org denied", flush=True)
    else:
        raise RuntimeError("Expected example.org to be denied")
    time.sleep(2)
'
openshell policy update "$name" --add-endpoint example.org:80:read-only:rest \
  --binary '/usr/bin/python*' --binary '/usr/local/bin/python*' --wait
openshell sandbox exec --name "$name" --no-tty -- \
  uv run --no-project python -c '
import urllib.error, urllib.request
try:
    response = urllib.request.urlopen("http://example.org", timeout=10)
except urllib.error.HTTPError as error:
    # An upstream HTTP error is still a completed, policy-allowed request.
    assert b"policy_denied" not in error.read()
    response = error
print("example.org reached upstream; HTTP status:", response.status)
'

echo "Demo sandboxes retained: ${prefix}-a ${prefix}-b"
echo "Observe metrics, then remove them with:"
echo "openshell sandbox delete ${prefix}-a"
echo "openshell sandbox delete ${prefix}-b"
