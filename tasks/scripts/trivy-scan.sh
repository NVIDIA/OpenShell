#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Scan release artifacts with Trivy.
#
#   trivy-scan.sh config [--chart-ref <oci-ref>]
#   trivy-scan.sh images <image-ref> [<image-ref>...]
#   trivy-scan.sh gate
#   trivy-scan.sh gate-config-diff <baseline-reports> <candidate-reports>
#
# `config` and `images` write full-severity reports and never fail on findings,
# so a report is always available to upload. `gate` then re-reads those reports
# and fails if any finding reaches TRIVY_SEVERITY.
#
# Environment:
#   TRIVY_SEVERITY        severities that fail `gate` (default HIGH,CRITICAL)
#   TRIVY_IGNORE_UNFIXED  skip image vulnerabilities with no fix (default true)
#   TRIVY_PLATFORMS       image platforms (default "linux/amd64 linux/arm64")
#   TRIVY_REPORT_DIR      output directory (default reports/trivy)
#   TRIVY_SOURCE_ROOT     source tree to scan (default repository root)
#   TRIVY_IGNORE_FILE     ignore file to apply (default repository copy)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_ROOT="${TRIVY_SOURCE_ROOT:-${REPO_ROOT}}"
IGNORE_FILE="${TRIVY_IGNORE_FILE:-${REPO_ROOT}/.trivyignore.yaml}"
cd "${SOURCE_ROOT}"

SEVERITY="${TRIVY_SEVERITY:-HIGH,CRITICAL}"
REPORT_DIR="${TRIVY_REPORT_DIR:-reports/trivy}"
IGNORE_UNFIXED="${TRIVY_IGNORE_UNFIXED:-true}"
PLATFORMS="${TRIVY_PLATFORMS:-linux/amd64 linux/arm64}"

# Rendering the chart outside a cluster cannot satisfy the Agent Sandbox API
# discovery check, and that template calls `fail`.
PREFLIGHT_OFF=(--helm-set agentSandbox.preflight.enabled=false)

# These Dockerfiles produce no runnable image: the macOS ones export a binary
# from `FROM scratch`, and the CI image is toolchain, not a release artifact.
SKIP_DOCKERFILES=(
  --skip-files 'deploy/docker/Dockerfile.ci'
  --skip-files 'deploy/docker/Dockerfile.*-macos'
)

# Run one scan. Reports keep every severity; `gate` applies the threshold.
# `prefix` is prepended to SARIF locations, which Trivy reports relative to the
# scanned target while Code Scanning resolves them from the repository root.
scan() {
  local subcommand=$1 slug=$2 prefix=$3
  shift 3

  echo "==> ${slug}"
  trivy "${subcommand}" --skip-version-check --quiet \
    --ignorefile "${IGNORE_FILE}" \
    --format json --output "${REPORT_DIR}/${slug}.json" "$@"
  trivy convert --quiet \
    --format sarif --output "${REPORT_DIR}/${slug}.sarif" \
    "${REPORT_DIR}/${slug}.json"

  if [ -n "${prefix}" ]; then
    jq --arg p "${prefix}" '
      (.. | objects | select(has("artifactLocation")) | .artifactLocation.uri)
        |= $p + (. | sub("^[^:]*\\.tgz:"; ""))
    ' "${REPORT_DIR}/${slug}.sarif" >"${REPORT_DIR}/${slug}.sarif.tmp"
    mv "${REPORT_DIR}/${slug}.sarif.tmp" "${REPORT_DIR}/${slug}.sarif"
  fi
}

# Scanning deploy/ in one pass covers both charts, the published Dockerfiles and
# the raw manifests, and keeps every reported path relative to the same root.
scan_config() {
  scan config config-defaults deploy/ "${PREFLIGHT_OFF[@]}" \
    "${SKIP_DOCKERFILES[@]}" deploy

  # The chart defaults render 10 of its 19 templates. The high-availability
  # Deployment, the Gateway API objects, the OpenShift Route and the wider
  # workspace-mode ClusterRole only render under CI value fixtures.
  local values fixture
  for values in deploy/helm/openshell/ci/values-*.yaml; do
    fixture="$(basename "${values}" .yaml | sed 's/^values-//')"
    scan config "config-fixture-${fixture}" deploy/ "${PREFLIGHT_OFF[@]}" \
      "${SKIP_DOCKERFILES[@]}" --helm-values "${values}" deploy
  done
}

# Trivy has no OCI artifact target and rejects the Helm config media type, so a
# published chart has to be pulled before it can be scanned. It reads the
# archive directly, and skips secret scanning on packaged charts.
scan_packaged_chart() {
  local ref=$1
  if [[ "${ref}" != *:* || "${ref##*/}" != *:* ]]; then
    echo "Error: --chart-ref needs a version tag, e.g. oci://host/chart:1.2.3" >&2
    exit 2
  fi

  local dir
  dir="$(mktemp -d)"
  trap 'rm -rf "${dir}"' RETURN

  helm pull "${ref%:*}" --version "${ref##*:}" --destination "${dir}"
  scan config config-packaged-chart deploy/helm/openshell/ \
    "${PREFLIGHT_OFF[@]}" "$(find "${dir}" -name '*.tgz' -print -quit)"
}

scan_images() {
  local extra=()
  [ "${IGNORE_UNFIXED}" = "true" ] && extra+=(--ignore-unfixed)

  local image platform slug
  for image in "$@"; do
    # Published tags are multi-arch indexes and Trivy defaults to the runner's
    # own platform, so each architecture needs its own scan.
    for platform in ${PLATFORMS}; do
      slug="image-$(printf '%s' "${image#*/}-${platform}" | tr -cs 'A-Za-z0-9._-' '-')"
      scan image "${slug}" "" --platform "${platform}" --scanners vuln \
        "${extra[@]}" "${image}"
    done
  done
}

# Re-read the reports and apply the threshold. The table doubles as the run
# summary, so nothing here reimplements counting.
gate() {
  local report result findings=0

  if ! compgen -G "${REPORT_DIR}/*.json" >/dev/null; then
    echo "Error: no reports in ${REPORT_DIR}; run 'config' or 'images' first" >&2
    exit 2
  fi

  for report in "${REPORT_DIR}"/*.json; do
    set +e
    trivy convert --quiet --exit-code 10 --severity "${SEVERITY}" \
      --format table "${report}"
    result=$?
    set -e

    case "${result}" in
      0) ;;
      10) findings=1 ;;
      *)
        echo "Error: Trivy could not evaluate ${report} (exit ${result})" >&2
        return "${result}"
        ;;
    esac
  done

  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "### Trivy (gate: \`${SEVERITY}\`)"
      echo '```'
      for report in "${REPORT_DIR}"/*.json; do
        trivy convert --quiet --severity "${SEVERITY}" --format table "${report}"
      done
      echo '```'
    } >>"${GITHUB_STEP_SUMMARY}"
  fi

  [ "${findings}" -eq 0 ] || return 10
}

collect_config_findings() {
  local report_dir=$1

  if ! compgen -G "${report_dir}/*.json" >/dev/null; then
    echo "Error: no reports in ${report_dir}" >&2
    return 2
  fi

  jq -s --arg severities "${SEVERITY}" '
    [
      .[]
      | .Results[]? as $result
      | $result.Misconfigurations[]?
      | .Severity as $severity
      | select(($severities | split(",") | index($severity)) != null)
      | {
          key: ([
            .ID,
            $result.Target,
            (.Namespace // ""),
            (.Message // ""),
            (.CauseMetadata.Provider // ""),
            (.CauseMetadata.Service // ""),
            (.CauseMetadata.Resource // "")
          ] | @json),
          severity: .Severity,
          id: .ID,
          target: $result.Target,
          title: .Title
        }
    ]
    | unique_by(.key)
  ' "${report_dir}"/*.json
}

# Compare semantic finding identities instead of line numbers, so unrelated
# edits that move a finding do not make existing debt look newly introduced.
gate_config_diff() (
  set -euo pipefail

  local baseline_dir=$1 candidate_dir=$2
  local inventory_dir baseline candidate new_findings finding_count
  inventory_dir="$(mktemp -d)"
  trap 'rm -rf "${inventory_dir}"' EXIT
  baseline="${inventory_dir}/baseline.json"
  candidate="${inventory_dir}/candidate.json"
  new_findings="${inventory_dir}/new.json"

  collect_config_findings "${baseline_dir}" >"${baseline}"
  collect_config_findings "${candidate_dir}" >"${candidate}"
  jq --slurpfile baseline "${baseline}" '
    ($baseline[0] | map(.key)) as $known
    | [.[] | select(.key as $key | ($known | index($key)) == null)]
  ' "${candidate}" >"${new_findings}"

  finding_count="$(jq 'length' "${new_findings}")"
  if [ "${finding_count}" -eq 0 ]; then
    echo "No new configuration findings at ${SEVERITY}."
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      echo "No new Trivy configuration findings at \`${SEVERITY}\`." \
        >>"${GITHUB_STEP_SUMMARY}"
    fi
    exit 0
  fi

  echo "::error::Trivy reported ${finding_count} new configuration finding(s) at ${SEVERITY}."
  jq -r '.[] | "::error::[\(.severity)] \(.id) in deploy/\(.target): \(.title)"' \
    "${new_findings}"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "### New Trivy configuration findings"
      echo
      jq -r '.[] | "- **\(.severity)** `\(.id)` in `deploy/\(.target)`: \(.title)"' \
        "${new_findings}"
    } >>"${GITHUB_STEP_SUMMARY}"
  fi
  exit 10
)

command -v trivy >/dev/null || { echo "Error: trivy not on PATH; run inside 'nix develop'" >&2; exit 2; }

case "${1:-}" in
  config)
    shift
    mkdir -p "${REPORT_DIR}"
    scan_config
    if [ "${1:-}" = "--chart-ref" ]; then
      [ -n "${2:-}" ] || { echo "Error: --chart-ref needs a value" >&2; exit 2; }
      scan_packaged_chart "$2"
    fi
    ;;
  images)
    shift
    [ $# -gt 0 ] || { echo "Error: images needs at least one reference" >&2; exit 2; }
    mkdir -p "${REPORT_DIR}"
    scan_images "$@"
    ;;
  gate)
    gate
    ;;
  gate-config-diff)
    shift
    [ $# -eq 2 ] || {
      echo "Error: gate-config-diff needs baseline and candidate report directories" >&2
      exit 2
    }
    gate_config_diff "$1" "$2"
    ;;
  *)
    cat >&2 <<'USAGE'
Usage:
  trivy-scan.sh config [--chart-ref <oci-ref>]
  trivy-scan.sh images <image-ref> [<image-ref>...]
  trivy-scan.sh gate
  trivy-scan.sh gate-config-diff <baseline-reports> <candidate-reports>
USAGE
    exit 2
    ;;
esac
