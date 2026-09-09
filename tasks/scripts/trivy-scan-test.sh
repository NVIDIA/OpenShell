#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCANNER="${REPO_ROOT}/tasks/scripts/trivy-scan.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
# Synthetic findings must not write to the real Actions summary or outputs.
export GITHUB_OUTPUT="${TMP_DIR}/github-output"
export GITHUB_STEP_SUMMARY="${TMP_DIR}/github-summary"

make_case() {
  BASE="${TMP_DIR}/$1/base"
  HEAD="${TMP_DIR}/$1/head"
  mkdir -p "${BASE}" "${HEAD}"
}

write_report() {
  local path=$1 count=$2 profile
  profile="$(basename "${path}" .json)"
  jq -n --argjson count "${count}" --arg profile "${profile}" '
    {
      SchemaVersion: 2,
      ArtifactName: "deploy",
      ArtifactType: "filesystem",
      TrivyProfile: $profile,
      Results: (if $count == 0 then [] else [{
        Target: "deploy/helm/openshell/templates/clusterrole.yaml",
        Class: "config",
        Type: "kubernetes",
        MisconfSummary: {Successes: 0, Failures: $count, Exceptions: 0},
        Misconfigurations: [
          range(0; $count) | {
            ID: "KSV-0041",
            Title: "Manage secrets",
            Message: "Role permits management of secrets",
            Namespace: "builtin.kubernetes.KSV041",
            Type: "Kubernetes Security Check",
            Status: "FAIL",
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
  "$@" >"${TMP_DIR}/last-command.log" 2>&1
  local actual=$?
  set -e
  if [ "${actual}" -ne "${expected}" ]; then
    echo "FAIL: ${description}: expected exit ${expected}, got ${actual}" >&2
    cat "${TMP_DIR}/last-command.log" >&2
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

make_case occurrence-increase
write_report "${BASE}/config-defaults.json" 1
write_report "${HEAD}/config-defaults.json" 2
expect_status 10 "additional occurrence of an existing finding" \
  "${SCANNER}" gate-config-diff "${BASE}" "${HEAD}"
expect_status 0 "findings below the requested threshold" \
  env TRIVY_SEVERITY=CRITICAL "${SCANNER}" gate-config-diff "${BASE}" "${HEAD}"

make_case malformed
write_report "${BASE}/config-defaults.json" 1
printf '{}\n' >"${HEAD}/config-defaults.json"
expect_status 5 "structurally invalid candidate report" \
  "${SCANNER}" gate-config-diff "${BASE}" "${HEAD}"

make_case no-reports
expect_status 2 "missing reports cannot pass the differential gate" \
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

# Consolidate more than 20 Helm profiles without losing resource identity or
# the per-profile input counts needed by the gate. Exercise real Trivy SARIF
# conversion with synthetic JSON; this requires no network or image downloads.
make_case sarif
write_report "${HEAD}/config-static.json" 0
write_report "${HEAD}/config-defaults.json" 1
for profile in {1..21}; do
  write_report "${HEAD}/config-fixture-${profile}.json" 1
done
write_report "${TMP_DIR}/resource-source.json" 2
jq '
  .TrivyProfile = "config-fixture-resources"
  | .Results[0].Misconfigurations[0].CauseMetadata.StartLine = 40
  | .Results[0].Misconfigurations[1].CauseMetadata.Resource = "ClusterRole.other"
' "${TMP_DIR}/resource-source.json" >"${HEAD}/config-fixture-resources.json"

# Image reports must remain separate, even if they contain identical findings.
for report in {1..25}; do
  write_report "${HEAD}/image-${report}.json" 0
done
expect_status 0 "prepare one config analysis and bounded image upload batches" \
  env TRIVY_SEVERITY=CRITICAL TRIVY_REPORT_DIR="${HEAD}" GITHUB_OUTPUT="${TMP_DIR}/outputs" \
  "${SCANNER}" prepare-sarif
jq -e '
  [.Results[].Misconfigurations[]] as $findings
  | ($findings | length) == 2
    and all($findings[]; .Message | contains("Profiles: "))
    and any($findings[];
      .CauseMetadata.Resource == "ClusterRole.openshell"
      and (.Message | contains("config-defaults"))
      and (.Message | contains("config-fixture-resources")))
' "${HEAD}/consolidated/config.json" >/dev/null
jq -e '.Results[0].Misconfigurations | length == 2' \
  "${HEAD}/config-fixture-resources.json" >/dev/null
jq -e '
  (.runs | length) == 1
  and .runs[0].automationDetails.id == "trivy/config/"
  and (.runs[0].results | length) == 2
  and (.runs[0].originalUriBaseIds == null)
  and (.runs[0] as $run | all($run.results[];
    .ruleId == $run.tool.driver.rules[.ruleIndex].id
    and all(.locations[].physicalLocation.artifactLocation;
      .uri == "deploy/helm/openshell/templates/clusterrole.yaml" and .uriBaseId == null)))
' "${HEAD}/code-scanning/uploads/0/config.sarif" >/dev/null
jq -se '[.[].runs[]] | length == 20' "${HEAD}/code-scanning/uploads/0/"*.sarif >/dev/null
jq -se '[.[].runs[]] | length == 6' "${HEAD}/code-scanning/uploads/1/"*.sarif >/dev/null
[[ "$(<"${TMP_DIR}/outputs")" == 'batches=["0","1"]' ]]

# Report findings and the workflow summary use the same consolidated view.
expect_status 10 "consolidated findings remain blocking" \
  env TRIVY_REPORT_DIR="${HEAD}" GITHUB_STEP_SUMMARY="${TMP_DIR}/summary" \
  "${SCANNER}" gate
test -s "${TMP_DIR}/summary"

# Empty configuration is a valid clearing analysis, not a skipped upload.
make_case empty-sarif
write_report "${HEAD}/config-static.json" 0
write_report "${HEAD}/config-defaults.json" 0
expect_status 0 "empty configuration SARIF" \
  env TRIVY_REPORT_DIR="${HEAD}" "${SCANNER}" prepare-sarif
jq -e '.runs[0].results | length == 0' \
  "${HEAD}/code-scanning/uploads/0/config.sarif" >/dev/null

make_case malformed-sarif
write_report "${HEAD}/config-static.json" 0
printf '{}\n' >"${HEAD}/config-defaults.json"
expect_status 5 "reject malformed input during consolidation" \
  env TRIVY_REPORT_DIR="${HEAD}" "${SCANNER}" prepare-sarif

# Record scan arguments without downloading Trivy's checks database or charts.
# shellcheck disable=SC2329 # Invoked by the scanner subprocess via export -f.
trivy() {
  [ "${TRIVY_TEST_FAIL:-false}" = false ] || return 9
  local output="" previous="" arg
  printf '%s\n' "$@" | jq -Rs 'split("\n")[:-1]' >>"${TRIVY_TEST_CALLS}"
  for arg in "$@"; do
    [ "${previous}" = --output ] && output="${arg}"
    previous="${arg}"
  done
  jq -n --arg target "${!#}" \
    '{SchemaVersion: 2, ArtifactName: $target, ArtifactType: "filesystem", Results: []}' >"${output}"
}
# shellcheck disable=SC2329 # Invoked by the scanner subprocess via export -f.
helm() { touch "${!#}/chart.tgz"; }
export -f trivy helm
export TRIVY_TEST_CALLS="${TMP_DIR}/scan-calls"
expect_status 0 "scan selected profiles and retain distinct packaged chart versions/registries" \
  env TRIVY_REPORT_DIR="${TMP_DIR}/scan-reports" "${SCANNER}" config \
  --chart-ref oci://registry-a.example/charts/helm-chart:1.0.0 \
  --chart-ref oci://registry-a.example/charts/helm-chart:1.1.0 \
  --chart-ref oci://registry-b.example/charts/helm-chart:1.0.0
jq -se '
  length == 21
  and ([.[] | select(.[-1] == "deploy")] | length) == 1
  and ([.[] | select(.[-1] == "deploy/helm")] | length) == 1
  and ([.[] | select(.[-1] == "deploy/helm/openshell")] | length) == 16
  and all(.[]; (join(" ") | contains("values-spire-stack.yaml")) | not)
  and all(.[]; index("UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL") != null)
' "${TRIVY_TEST_CALLS}" >/dev/null
jq -se 'length == 3' "${TMP_DIR}/scan-reports/"config-packaged-*.json >/dev/null
test -z "$(find "${TMP_DIR}/scan-reports" -name '*.sarif' -print -quit)"

expect_status 0 "retain image registry, path and platform identity" \
  env TRIVY_REPORT_DIR="${TMP_DIR}/images" "${SCANNER}" images \
  registry-a.example/ns/image:dev registry-b.example/ns/image:dev \
  registry-a.example/ns-image:dev
jq -se 'length == 6 and (map(.ArtifactName) | unique | length) == 3' \
  "${TMP_DIR}/images/"*.json >/dev/null

expect_status 9 "scanner failures propagate" \
  env TRIVY_TEST_FAIL=true TRIVY_REPORT_DIR="${TMP_DIR}/scan-error" "${SCANNER}" config

# Check missing fixture handling without changing the working checkout.
mkdir -p "${TMP_DIR}/candidate/tasks/scripts" "${TMP_DIR}/baseline"
cp "${SCANNER}" "${TMP_DIR}/candidate/tasks/scripts/trivy-scan.sh"
cp "${REPO_ROOT}/.trivyignore.yaml" "${TMP_DIR}/candidate/"
expect_status 2 "a selected candidate fixture cannot silently disappear" \
  env TRIVY_REPORT_DIR="${TMP_DIR}/missing-candidate" \
  "${TMP_DIR}/candidate/tasks/scripts/trivy-scan.sh" config
expect_status 0 "new candidate profiles may be absent from the baseline" \
  env TRIVY_SOURCE_ROOT="${TMP_DIR}/baseline" TRIVY_REPORT_DIR="${TMP_DIR}/missing-baseline" \
  "${TMP_DIR}/candidate/tasks/scripts/trivy-scan.sh" config
unset -f trivy helm

echo "Trivy scan tests passed."
