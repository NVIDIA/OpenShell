#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# `config` and `images` write full-severity reports and never fail on findings,
# then `gate` applies TRIVY_SEVERITY (default HIGH,CRITICAL).

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_ROOT="${TRIVY_SOURCE_ROOT:-${REPO_ROOT}}"
IGNORE_FILE="${TRIVY_IGNORE_FILE:-${REPO_ROOT}/.trivyignore.yaml}"
cd "${SOURCE_ROOT}"

SEVERITY="${TRIVY_SEVERITY:-HIGH,CRITICAL}"
REPORT_DIR="${TRIVY_REPORT_DIR:-reports/trivy}"
IGNORE_UNFIXED="${TRIVY_IGNORE_UNFIXED:-true}"
PLATFORMS="${TRIVY_PLATFORMS:-linux/amd64 linux/arm64}"

# Disable cluster discovery while rendering charts offline.
PREFLIGHT_OFF=(--helm-set agentSandbox.preflight.enabled=false)

# These Dockerfiles do not produce release runtime images.
SKIP_DOCKERFILES=(
  --skip-files 'deploy/docker/Dockerfile.ci'
  --skip-files 'deploy/docker/Dockerfile.*-macos'
)

# Reject ignore entries broader than one concrete basename.
validate_ignore_file() {
  [ -f "${IGNORE_FILE}" ] || {
    echo "Error: Trivy ignore file not found: ${IGNORE_FILE}" >&2
    return 2
  }

  command -v yq >/dev/null || {
    echo "Error: yq not on PATH; run inside 'nix develop'" >&2
    return 2
  }
  if ! yq --output-format json '.' "${IGNORE_FILE}" |
    jq -e '
      (.misconfigurations // []) as $entries
      | (($entries | type) == "array")
        and all($entries[];
          . as $entry
          | (($entry.id | type) == "string")
            and (($entry.paths | type) == "array")
            and (($entry.paths | length) > 0)
            and all($entry.paths[];
              . as $path
              | (($path | type) == "string")
                and ($path | startswith("**/"))
                and (($path | ltrimstr("**/") | length) > 0)
                and (($path | ltrimstr("**/") | test("[/*?\\[\\]]")) | not)
            )
        )
    ' >/dev/null; then
    echo "Error: every Trivy ignore must use at least one '**/<concrete-basename>' path" >&2
    return 2
  fi
}

# Run one scan and normalize its SARIF metadata and repository path.
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

  jq --arg p "${prefix}" --arg automation_id "trivy/${slug}/" '
    .runs[] |= (.automationDetails.id = $automation_id)
    | if $p == "" then
        .
      else
        (.. | objects | select(has("artifactLocation")) | .artifactLocation.uri)
          |= $p + (. | sub("^[^:]*\\.tgz:"; ""))
      end
    ' "${REPORT_DIR}/${slug}.sarif" >"${REPORT_DIR}/${slug}.sarif.tmp"
  mv "${REPORT_DIR}/${slug}.sarif.tmp" "${REPORT_DIR}/${slug}.sarif"
}

# Scan deploy/ defaults and conditional Helm fixtures.
scan_config() {
  scan config config-defaults deploy/ "${PREFLIGHT_OFF[@]}" \
    "${SKIP_DOCKERFILES[@]}" deploy

  local values fixture
  for values in deploy/helm/openshell/ci/values-*.yaml; do
    fixture="$(basename "${values}" .yaml | sed 's/^values-//')"
    scan config "config-fixture-${fixture}" deploy/ "${PREFLIGHT_OFF[@]}" \
      "${SKIP_DOCKERFILES[@]}" --helm-values "${values}" deploy
  done
}

# Trivy needs a local chart archive rather than an OCI reference.
scan_packaged_chart() {
  local ref=$1
  if [[ "${ref}" != *:* || "${ref##*/}" != *:* ]]; then
    echo "Error: --chart-ref needs a version tag, e.g. oci://host/chart:1.2.3" >&2
    exit 2
  fi

  local repo chart_name chart_dir="" candidate dir
  repo="${ref%:*}"
  chart_name="${repo##*/}"
  for candidate in deploy/helm/*/; do
    [ -f "${candidate}Chart.yaml" ] || continue
    [ "$(sed -n 's/^name:[[:space:]]*//p' "${candidate}Chart.yaml" | head -1)" \
      = "${chart_name}" ] || continue
    chart_dir="${candidate}"
    break
  done
  if [ -z "${chart_dir}" ]; then
    echo "Error: no chart under deploy/helm declares name '${chart_name}'" >&2
    exit 2
  fi

  dir="$(mktemp -d)"
  trap 'rm -rf "${dir}"' RETURN

  helm pull "${repo}" --version "${ref##*:}" --destination "${dir}"
  scan config "config-packaged-${chart_name}" "${chart_dir}" \
    "${PREFLIGHT_OFF[@]}" "$(find "${dir}" -name '*.tgz' -print -quit)"
}

scan_images() {
  local extra=()
  [ "${IGNORE_UNFIXED}" = "true" ] && extra+=(--ignore-unfixed)

  local image platform slug
  for image in "$@"; do
    for platform in ${PLATFORMS}; do
      slug="image-$(printf '%s' "${image#*/}-${platform}" | tr -cs 'A-Za-z0-9._-' '-')"
      scan image "${slug}" "" --platform "${platform}" --scanners vuln \
        "${extra[@]}" "${image}"
    done
  done
}

gate() {
  local report result findings=0

  if [ -z "$(find "${REPORT_DIR}" -maxdepth 1 -name '*.json' -print -quit)" ]; then
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

  if [ -z "$(find "${report_dir}" -maxdepth 1 -name '*.json' -print -quit)" ]; then
    echo "Error: no reports in ${report_dir}" >&2
    return 2
  fi

  # Preserve report/profile identity while counting repeated findings.
  local report profile
  {
    for report in "${report_dir}"/*.json; do
      profile="$(basename "${report}" .json)"
      jq --arg profile "${profile}" --arg severities "${SEVERITY}" '
        if .SchemaVersion != 2
          or ((.ArtifactName | type) != "string")
          or ((.ArtifactType | type) != "string")
          or (.Results != null and ((.Results | type) != "array"))
        then
          error("invalid Trivy JSON report: " + $profile)
        else
          {
            profile: $profile,
            findings: ([
              .Results[]? as $result
              | $result.Misconfigurations[]?
              | .Severity as $severity
              | select(($severities | split(",") | index($severity)) != null)
              | ([
                  .ID,
                  $result.Target,
                  (.Namespace // ""),
                  (.Message // ""),
                  (.CauseMetadata.Provider // ""),
                  (.CauseMetadata.Service // ""),
                  (.CauseMetadata.Resource // "")
                ] | @json) as $semantic_key
              | {
                  key: ([$profile, $semantic_key] | @json),
                  semantic_key: $semantic_key,
                  profile: $profile,
                  severity: .Severity,
                  id: .ID,
                  target: $result.Target,
                  title: .Title
                }
            ]
            | group_by(.key)
            | map(.[0] + { count: length }))
          }
        end
      ' "${report}"
    done
  } | jq -s '{
    profiles: map(.profile),
    findings: (map(.findings) | add // [])
  }'
}

# Compare semantic identities and occurrence counts, excluding line numbers.
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
    ($baseline[0].findings | map({ (.key): .count }) | add // {}) as $by_profile
    | ($baseline[0].profiles) as $known_profiles
    | ($baseline[0].findings
      | group_by(.semantic_key)
      | map({
          key: .[0].semantic_key,
          value: (map(.count) | max)
        })
      | from_entries) as $across_profiles
    | [
        .findings[]
        | . as $finding
        | (if ($known_profiles | index($finding.profile)) != null
          then (($by_profile[$finding.key]) // 0)
          else (($across_profiles[$finding.semantic_key]) // 0)
          end) as $before
        | select(.count > $before)
        | . + { baseline_count: $before, new_count: (.count - $before) }
      ]
  ' "${candidate}" >"${new_findings}"

  finding_count="$(jq '[.[].new_count] | add // 0' "${new_findings}")"
  if [ "${finding_count}" -eq 0 ]; then
    echo "No new configuration findings at ${SEVERITY}."
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      echo "No new Trivy configuration findings at \`${SEVERITY}\`." \
        >>"${GITHUB_STEP_SUMMARY}"
    fi
    exit 0
  fi

  echo "::error::Trivy reported ${finding_count} new configuration finding(s) at ${SEVERITY}."
  jq -r '.[]
    | "::error::[\(.severity)] \(.id) in \(.profile) (deploy/\(.target)): \(.title)"
      + " (\(.new_count) new, \(.baseline_count) in baseline)"' \
    "${new_findings}"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "### New Trivy configuration findings"
      echo
      jq -r '.[]
        | "- **\(.severity)** `\(.id)` in `\(.profile)`"
          + " (`deploy/\(.target)`): \(.title)"
          + " (\(.new_count) new, \(.baseline_count) in baseline)"' \
        "${new_findings}"
    } >>"${GITHUB_STEP_SUMMARY}"
  fi
  exit 10
)

require_trivy() {
  command -v trivy >/dev/null || {
    echo "Error: trivy not on PATH; run inside 'nix develop'" >&2
    exit 2
  }
}

case "${1:-}" in
  config)
    shift
    require_trivy
    validate_ignore_file
    mkdir -p "${REPORT_DIR}"
    scan_config
    # Reject unparsed arguments so requested charts cannot be silently skipped.
    while [ "${1:-}" = "--chart-ref" ]; do
      [ -n "${2:-}" ] || { echo "Error: --chart-ref needs a value" >&2; exit 2; }
      scan_packaged_chart "$2"
      shift 2
    done
    [ $# -eq 0 ] || { echo "Error: unexpected argument '$1' after config" >&2; exit 2; }
    ;;
  images)
    shift
    [ $# -gt 0 ] || { echo "Error: images needs at least one reference" >&2; exit 2; }
    require_trivy
    validate_ignore_file
    mkdir -p "${REPORT_DIR}"
    scan_images "$@"
    ;;
  gate)
    require_trivy
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
  validate-ignore)
    validate_ignore_file
    ;;
  *)
    cat >&2 <<'USAGE'
Usage:
  trivy-scan.sh config [--chart-ref <oci-ref>]...
  trivy-scan.sh images <image-ref> [<image-ref>...]
  trivy-scan.sh gate
  trivy-scan.sh gate-config-diff <baseline-reports> <candidate-reports>
  trivy-scan.sh validate-ignore
USAGE
    exit 2
    ;;
esac
