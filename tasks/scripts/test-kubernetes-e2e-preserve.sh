#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WRAPPER="${ROOT}/e2e/with-kube-gateway.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/openshell-kube-preserve-test.XXXXXX")"
HARNESS="${ROOT}/e2e/.with-kube-gateway-preserve-test.$$"

cleanup() {
  rm -f "${HARNESS}"
  rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_contains() {
  local file="$1"
  local expected="$2"
  grep -F -- "${expected}" "${file}" >/dev/null \
    || fail "${file} does not contain: ${expected}"
}

# Build a focused harness from the real wrapper. It installs the real cleanup
# trap, then exits with a controlled status before provisioning dependencies.
awk '{ print } /^trap cleanup EXIT$/ { exit }' "${WRAPPER}" >"${HARNESS}"
cat >>"${HARNESS}" <<'EOF'
CLUSTER_CREATED_BY_US="${TEST_CLUSTER_CREATED_BY_US}"
CLUSTER_NAME="test-preserved-cluster"
KUBE_CONTEXT="test-preserved-context"
export KUBECONFIG="${WORKDIR}/kubeconfig"
: >"${KUBECONFIG}"
exit "${TEST_EXIT_CODE}"
EOF
chmod +x "${HARNESS}"

FAKE_BIN="${TMP_ROOT}/fake-bin"
mkdir -p "${FAKE_BIN}"
cat >"${FAKE_BIN}/kubectl" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
cat >"${FAKE_BIN}/k3d" <<'EOF'
#!/usr/bin/env bash
printf 'k3d %s\n' "$*" >>"${FAKE_COMMAND_LOG}"
exit 0
EOF
chmod +x "${FAKE_BIN}/kubectl" "${FAKE_BIN}/k3d"

run_harness() {
  local name="$1"
  local preserve="$2"
  local cluster_created="$3"
  local exit_code="$4"
  local case_tmp="${TMP_ROOT}/${name} with spaces"
  local output="${TMP_ROOT}/${name}.out"
  local command_log="${TMP_ROOT}/${name}.commands"
  local status

  mkdir -p "${case_tmp}"
  : >"${command_log}"
  set +e
  PATH="${FAKE_BIN}:${PATH}" \
  TMPDIR="${case_tmp}" \
  FAKE_COMMAND_LOG="${command_log}" \
  OPENSHELL_E2E_KUBE_PRESERVE_CLUSTER="${preserve}" \
  TEST_CLUSTER_CREATED_BY_US="${cluster_created}" \
  TEST_EXIT_CODE="${exit_code}" \
    bash "${HARNESS}" /bin/true >"${output}" 2>&1
  status=$?
  set -e

  if [ "${status}" -ne "${exit_code}" ]; then
    cat "${output}" >&2
    fail "${name} returned ${status}, expected ${exit_code}"
  fi

  RUN_CASE_TMP="${case_tmp}"
  RUN_OUTPUT="${output}"
  RUN_COMMAND_LOG="${command_log}"
}

# Invalid values fail before the wrapper creates a work directory or cluster.
INVALID_TMP="${TMP_ROOT}/invalid"
INVALID_OUT="${TMP_ROOT}/invalid.out"
mkdir -p "${INVALID_TMP}"
set +e
TMPDIR="${INVALID_TMP}" OPENSHELL_E2E_KUBE_PRESERVE_CLUSTER=invalid \
  bash "${WRAPPER}" /bin/true >"${INVALID_OUT}" 2>&1
invalid_status=$?
set -e
[ "${invalid_status}" -eq 2 ] || fail "invalid value returned ${invalid_status}, expected 2"
assert_contains "${INVALID_OUT}" "OPENSHELL_E2E_KUBE_PRESERVE_CLUSTER must be a boolean"
if find "${INVALID_TMP}" -mindepth 1 -print -quit | grep -q .; then
  fail "invalid value created a work directory"
fi

# Preservation is independent of the wrapped command's success or failure.
run_harness preserve-success 1 1 0
assert_contains "${RUN_OUTPUT}" "Preserving diagnostic k3d cluster test-preserved-cluster."
assert_contains "${RUN_OUTPUT}" "Kubernetes context: test-preserved-context"
assert_contains "${RUN_OUTPUT}" "Inspect it with: kubectl --kubeconfig"
assert_contains "${RUN_OUTPUT}" "Delete the cluster with: k3d cluster delete test-preserved-cluster"
assert_contains "${RUN_OUTPUT}" "Delete the work directory with: rm -rf --"
assert_contains "${RUN_OUTPUT}" "contain temporary test credentials, private keys, and gateway metadata"
find "${RUN_CASE_TMP}" -maxdepth 1 -type d -name 'openshell-e2e-kube.*' -print -quit \
  | grep -q . || fail "successful preserved run removed its work directory"
[ ! -s "${RUN_COMMAND_LOG}" ] || fail "successful preserved run deleted its cluster"

run_harness preserve-failure 1 1 23
assert_contains "${RUN_OUTPUT}" "Preserving diagnostic k3d cluster test-preserved-cluster."
find "${RUN_CASE_TMP}" -maxdepth 1 -type d -name 'openshell-e2e-kube.*' -print -quit \
  | grep -q . || fail "failed preserved run removed its work directory"
[ ! -s "${RUN_COMMAND_LOG}" ] || fail "failed preserved run deleted its cluster"

# Default cleanup still removes both wrapper-owned resources.
run_harness default-cleanup 0 1 0
if find "${RUN_CASE_TMP}" -maxdepth 1 -type d -name 'openshell-e2e-kube.*' -print -quit \
    | grep -q .; then
  fail "default cleanup preserved its work directory"
fi
assert_contains "${RUN_COMMAND_LOG}" "k3d cluster delete test-preserved-cluster"

# Preserve mode does not adopt or retain resources for a caller-owned context.
run_harness external-context 1 0 0
if find "${RUN_CASE_TMP}" -maxdepth 1 -type d -name 'openshell-e2e-kube.*' -print -quit \
    | grep -q .; then
  fail "external-context cleanup preserved its work directory"
fi
[ ! -s "${RUN_COMMAND_LOG}" ] || fail "external-context cleanup invoked k3d"
if grep -F "Preserving diagnostic k3d cluster" "${RUN_OUTPUT}" >/dev/null; then
  fail "external-context cleanup claimed to preserve a wrapper-owned cluster"
fi

echo "Kubernetes E2E preservation tests passed."
