#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCANNER="${REPO_ROOT}/tasks/scripts/trivy-scan.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

make_case() {
  BASE="${TMP_DIR}/$1/base"
  HEAD="${TMP_DIR}/$1/head"
  mkdir -p "${BASE}" "${HEAD}"
}

write_report() {
  local path=$1 count=$2
  jq -n --argjson count "${count}" '
    {
      SchemaVersion: 2,
      ArtifactName: "deploy",
      ArtifactType: "filesystem",
      Results: (if $count == 0 then [] else [{
        Target: "helm/openshell/templates/clusterrole.yaml",
        Misconfigurations: [
          range(0; $count) | {
            ID: "KSV-0041",
            Title: "Manage secrets",
            Message: "Role permits management of secrets",
            Namespace: "builtin.kubernetes.KSV041",
            Severity: "HIGH",
            CauseMetadata: {Provider: "Kubernetes", Service: "RBAC", Resource: "ClusterRole.openshell"}
          }
        ]
      }] end)
    }
  ' >"${path}"
}

expect_status() {
  local expected=$1 description=$2
  shift 2

  set +e
  "$@" >/dev/null 2>&1
  local actual=$?
  set -e
  if [ "${actual}" -ne "${expected}" ]; then
    echo "FAIL: ${description}: expected exit ${expected}, got ${actual}" >&2
    "$@" || true
    exit 1
  fi
}

make_case profile-expansion
write_report "${BASE}/config-defaults.json" 0
write_report "${BASE}/config-fixture-workspace.json" 2
write_report "${HEAD}/config-defaults.json" 1
write_report "${HEAD}/config-fixture-workspace.json" 2
expect_status 10 "finding newly exposed in an existing profile" \
  "${SCANNER}" gate-config-diff "${BASE}" "${HEAD}"

make_case new-profile
write_report "${BASE}/config-defaults.json" 0
write_report "${BASE}/config-fixture-workspace.json" 2
write_report "${HEAD}/config-defaults.json" 0
write_report "${HEAD}/config-fixture-workspace.json" 2
write_report "${HEAD}/config-fixture-new.json" 2
expect_status 0 "new profile repeating known findings" \
  "${SCANNER}" gate-config-diff "${BASE}" "${HEAD}"

make_case malformed
write_report "${BASE}/config-defaults.json" 1
printf '{}\n' >"${HEAD}/config-defaults.json"
expect_status 5 "structurally invalid candidate report" \
  "${SCANNER}" gate-config-diff "${BASE}" "${HEAD}"

cat >"${TMP_DIR}/valid-ignore.yaml" <<'EOF'
misconfigurations:
  - id: KSV-0041
    paths:
      - "**/clusterrole.yaml"
EOF
expect_status 0 "concretely scoped ignore path" \
  env TRIVY_IGNORE_FILE="${TMP_DIR}/valid-ignore.yaml" \
  "${SCANNER}" validate-ignore

cat >"${TMP_DIR}/broad-ignore.yaml" <<'EOF'
misconfigurations:
- id: KSV-0041
  paths:
    - "**/*"
EOF
expect_status 2 "broad ignore path" \
  env TRIVY_IGNORE_FILE="${TMP_DIR}/broad-ignore.yaml" \
  "${SCANNER}" validate-ignore

echo "Trivy scan tests passed."
