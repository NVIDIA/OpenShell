#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
component_cli="${OPENSHELL_BIN:-${repo_root}/target/debug/openshell}"

"${component_cli}" sandbox create --name helm-placement --detach -- /bin/sh -c 'sleep 600'
"${component_cli}" sandbox exec helm-placement -- /bin/echo component-migration-ok
kubectl --context "${OPENSHELL_E2E_KUBE_CONTEXT}" \
  -n "${OPENSHELL_E2E_KUBE_NAMESPACE}" get pods -o json \
  | uv run --no-project python -c '
import json
import sys

pods = json.load(sys.stdin)["items"]
accounts = {p["spec"]["serviceAccountName"] for p in pods}
assert {"helm-component-gateway", "helm-component-supervisor", "helm-component-workload"} <= accounts, accounts
for pod in pods:
    spec = pod["spec"]
    if spec["serviceAccountName"] in {"helm-component-gateway", "helm-component-supervisor"}:
        assert spec["nodeSelector"]["kubernetes.io/os"] == "linux"
        assert any(t.get("key") == "dedicated" for t in spec["tolerations"])
print("Component pod scheduling and service accounts verified on live pods")
'
"${component_cli}" sandbox delete helm-placement
