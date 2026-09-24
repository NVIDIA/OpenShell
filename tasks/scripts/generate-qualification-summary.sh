#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

die() {
  echo "generate-qualification-summary: $*" >&2
  exit 1
}

require_env() {
  local name
  for name in "$@"; do
    if [[ -z "${!name:-}" ]]; then
      die "required environment variable ${name} is not set"
    fi
  done
}

[[ $# -eq 1 ]] || die "usage: $0 OUTPUT"
output=$1
current_profile_passed=true

require_env \
  RELEASE_TAG SOURCE_SHA IS_PRERELEASE GITHUB_RUN_ID GITHUB_RUN_ATTEMPT \
  GITHUB_SERVER_URL GITHUB_REPOSITORY SECURITY_RESULT CONFORMANCE_RESULT \
  FEATURE_INTEGRATION_RESULT DOCKER_E2E_RESULT VM_E2E_RESULT

for result in \
  "${SECURITY_RESULT}" \
  "${CONFORMANCE_RESULT}" \
  "${FEATURE_INTEGRATION_RESULT}" \
  "${DOCKER_E2E_RESULT}" \
  "${VM_E2E_RESULT}"; do
  if [[ "${result}" != "success" ]]; then
    current_profile_passed=false
    break
  fi
done

mkdir -p "$(dirname "${output}")"
jq -n \
  --arg tag "${RELEASE_TAG}" \
  --arg source_sha "${SOURCE_SHA}" \
  --arg is_prerelease "${IS_PRERELEASE}" \
  --argjson current_profile_passed "${current_profile_passed}" \
  --arg run_id "${GITHUB_RUN_ID}" \
  --arg run_attempt "${GITHUB_RUN_ATTEMPT}" \
  --arg run_url "${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/attempts/${GITHUB_RUN_ATTEMPT}" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg security "${SECURITY_RESULT}" \
  --arg conformance "${CONFORMANCE_RESULT}" \
  --arg feature_integration "${FEATURE_INTEGRATION_RESULT}" \
  --arg docker_e2e "${DOCKER_E2E_RESULT}" \
  --arg vm_e2e "${VM_E2E_RESULT}" \
  '{
    schema_version: 1,
    tag: $tag,
    source_sha: $source_sha,
    is_prerelease: ($is_prerelease == "true"),
    profile: {
      name: "release-tag-v1",
      rfc_0014_complete: false,
      missing_suites: [
        "upgrade",
        "breaking API change review",
        "remaining RFC conformance configurations"
      ]
    },
    current_profile_passed: $current_profile_passed,
    run: {
      id: $run_id,
      attempt: $run_attempt,
      url: $run_url
    },
    generated_at: $generated_at,
    suites: {
      security: $security,
      conformance_integration: $conformance,
      feature_integration: $feature_integration,
      docker_e2e: $docker_e2e,
      vm_e2e: $vm_e2e
    }
  }' > "${output}"

printf '%s\n' "${current_profile_passed}"
