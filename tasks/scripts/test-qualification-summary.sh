#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GENERATOR="${SCRIPT_DIR}/generate-qualification-summary.sh"
TEST_DIR=$(mktemp -d)
trap 'rm -rf "${TEST_DIR}"' EXIT

export RELEASE_TAG=v0.1.0-pre.8
export SOURCE_SHA=0123456789abcdef0123456789abcdef01234567
export IS_PRERELEASE=true
export GITHUB_REPOSITORY=NVIDIA/OpenShell
export GITHUB_SERVER_URL=https://github.com
export GITHUB_RUN_ID=1234
export GITHUB_RUN_ATTEMPT=2
export SECURITY_RESULT=failure
export CONFORMANCE_RESULT=success
export FEATURE_INTEGRATION_RESULT=success
export DOCKER_E2E_RESULT=success
export VM_E2E_RESULT=success

current_profile_passed=$("${GENERATOR}" "${TEST_DIR}/qualification-summary.json")
[[ "${current_profile_passed}" == "false" ]]
jq -e '
  .schema_version == 1
  and .tag == "v0.1.0-pre.8"
  and .source_sha == "0123456789abcdef0123456789abcdef01234567"
  and .is_prerelease == true
  and .current_profile_passed == false
  and .profile.rfc_0014_complete == false
  and .suites.security == "failure"
  and .run.id == "1234"
  and .run.attempt == "2"
' "${TEST_DIR}/qualification-summary.json" >/dev/null

export SECURITY_RESULT=success
current_profile_passed=$("${GENERATOR}" "${TEST_DIR}/qualified-summary.json")
[[ "${current_profile_passed}" == "true" ]]
jq -e '.current_profile_passed == true' "${TEST_DIR}/qualified-summary.json" >/dev/null

echo "qualification summary tests passed"
