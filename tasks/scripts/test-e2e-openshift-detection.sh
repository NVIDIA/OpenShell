#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-openshift-detect.XXXXXX")"
trap 'rm -rf "${WORKDIR}"' EXIT

# A stand-in kubectl placed earlier on PATH. Behavior is selected by
# FAKE_KUBECTL_MODE and every invocation is counted in FAKE_KUBECTL_STATE so
# tests can assert how many times the probe actually ran.
mkdir -p "${WORKDIR}/bin"
cat >"${WORKDIR}/bin/kubectl" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail

count=0
if [ -s "${FAKE_KUBECTL_STATE}" ]; then
  count="$(cat "${FAKE_KUBECTL_STATE}")"
fi
count=$((count + 1))
printf '%s\n' "${count}" >"${FAKE_KUBECTL_STATE}"

api_resource_list='{"kind":"APIResourceList","groupVersion":"route.openshift.io/v1"}'

case "${FAKE_KUBECTL_MODE}" in
  openshift)
    printf '%s\n' "${api_resource_list}"
    ;;
  vanilla)
    echo 'Error from server (NotFound): the server could not find the requested resource' >&2
    exit 1
    ;;
  transient)
    if [ "${count}" -lt "${FAKE_KUBECTL_SUCCEED_ON:-2}" ]; then
      echo 'Unable to connect to the server: dial tcp 10.0.0.1:6443: i/o timeout' >&2
      exit 1
    fi
    printf '%s\n' "${api_resource_list}"
    ;;
  broken)
    echo 'error: You must be logged in to the server (Unauthorized)' >&2
    exit 1
    ;;
  *)
    echo "fake kubectl: unknown FAKE_KUBECTL_MODE '${FAKE_KUBECTL_MODE}'" >&2
    exit 64
    ;;
esac
FAKE
chmod +x "${WORKDIR}/bin/kubectl"
PATH="${WORKDIR}/bin:${PATH}"
export PATH

DETECT_STDERR="${WORKDIR}/stderr"
DETECT_RESULT=""
DETECT_STATUS=0
PROBE_CALLS=0

# Run the detection helper against the fake kubectl and record its stdout,
# exit status, stderr, and how many times the probe ran.
run_detection() {
  local mode=$1
  shift

  export FAKE_KUBECTL_MODE="${mode}"
  export FAKE_KUBECTL_STATE="${WORKDIR}/calls"
  : >"${FAKE_KUBECTL_STATE}"
  # Keep retries fast; the production default sleeps between attempts.
  export OPENSHELL_E2E_OPENSHIFT_PROBE_DELAY=0

  DETECT_STATUS=0
  DETECT_RESULT="$(env "$@" e2e_detect_openshift_run)" || DETECT_STATUS=$?
  PROBE_CALLS=0
  if [ -s "${FAKE_KUBECTL_STATE}" ]; then
    PROBE_CALLS="$(cat "${FAKE_KUBECTL_STATE}")"
  fi
}

# `env` cannot call a shell function, so route per-test environment through a
# tiny wrapper script that sources the helpers and invokes the function.
cat >"${WORKDIR}/bin/e2e_detect_openshift_run" <<WRAPPER
#!/usr/bin/env bash
set -uo pipefail
source "${ROOT}/e2e/support/gateway-common.sh"
e2e_detect_openshift test-context
WRAPPER
chmod +x "${WORKDIR}/bin/e2e_detect_openshift_run"

fail() {
  echo "FAIL: $1" >&2
  echo "  result='${DETECT_RESULT}' status=${DETECT_STATUS} probe_calls=${PROBE_CALLS}" >&2
  echo "  stderr:" >&2
  sed 's/^/    /' "${DETECT_STDERR}" >&2 || true
  exit 1
}

assert_detection() {
  local description=$1
  local expected_result=$2
  local expected_calls=$3

  if [ "${DETECT_STATUS}" -ne 0 ]; then
    fail "${description}: expected success, got exit ${DETECT_STATUS}"
  fi
  if [ "${DETECT_RESULT}" != "${expected_result}" ]; then
    fail "${description}: expected result '${expected_result}', got '${DETECT_RESULT}'"
  fi
  if [ "${PROBE_CALLS}" -ne "${expected_calls}" ]; then
    fail "${description}: expected ${expected_calls} probe call(s), got ${PROBE_CALLS}"
  fi
}

assert_stderr_contains() {
  local description=$1
  local needle=$2

  if ! grep -qF -- "${needle}" "${DETECT_STDERR}"; then
    fail "${description}: expected stderr to contain '${needle}'"
  fi
}

# An OpenShift cluster answers the route.openshift.io/v1 probe.
run_detection openshift 2>"${DETECT_STDERR}"
assert_detection "OpenShift cluster is detected" 1 1
assert_stderr_contains "OpenShift cluster is detected" "cluster is OpenShift"

# A clean NotFound is a conclusive answer, so it must not be retried and must
# not be reported as an error.
run_detection vanilla 2>"${DETECT_STDERR}"
assert_detection "conclusive absence reports not-OpenShift" 0 1
assert_stderr_contains "conclusive absence is logged" "cluster is not OpenShift"

# A discovery blip must not be mistaken for vanilla Kubernetes.
run_detection transient FAKE_KUBECTL_SUCCEED_ON=3 2>"${DETECT_STDERR}"
assert_detection "transient failure then success is detected" 1 3

# A probe that never reaches a conclusive answer must fail loudly rather than
# silently selecting the vanilla-Kubernetes path.
run_detection broken OPENSHELL_E2E_OPENSHIFT_PROBE_ATTEMPTS=3 2>"${DETECT_STDERR}"
if [ "${DETECT_STATUS}" -eq 0 ]; then
  fail "persistent probe failure must exit non-zero"
fi
if [ "${DETECT_RESULT}" = "0" ]; then
  fail "persistent probe failure must not report a conclusive not-OpenShift answer"
fi
if [ "${PROBE_CALLS}" -ne 3 ]; then
  fail "persistent probe failure should exhaust the configured attempts"
fi
assert_stderr_contains "failure names the probe" "/apis/route.openshift.io/v1"
assert_stderr_contains "failure names the underlying error" "Unauthorized"

# The override short-circuits the probe in both directions.
run_detection broken OPENSHELL_E2E_OPENSHIFT=1 2>"${DETECT_STDERR}"
assert_detection "override forces detection on" 1 0
assert_stderr_contains "override on is logged" "OPENSHELL_E2E_OPENSHIFT"

run_detection openshift OPENSHELL_E2E_OPENSHIFT=false 2>"${DETECT_STDERR}"
assert_detection "override forces detection off" 0 0
assert_stderr_contains "override off is logged" "OPENSHELL_E2E_OPENSHIFT"

# A malformed override is a configuration error, not a silent default.
run_detection openshift OPENSHELL_E2E_OPENSHIFT=maybe 2>"${DETECT_STDERR}"
if [ "${DETECT_STATUS}" -eq 0 ]; then
  fail "malformed override must exit non-zero"
fi
assert_stderr_contains "malformed override is explained" "OPENSHELL_E2E_OPENSHIFT"

echo "E2E OpenShift detection tests passed."
