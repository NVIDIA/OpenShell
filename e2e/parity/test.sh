#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Deterministic contract tests for e2e/parity/run.sh. No container runtime is
# invoked; the Podman wrapper and all three artifacts are tiny local fakes.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-parity-test.XXXXXX")"
trap 'rm -rf "${WORKDIR}"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
assert_contains() { grep -F -- "$2" "$1" >/dev/null || fail "expected $1 to contain: $2"; }
assert_not_contains() { ! grep -F -- "$2" "$1" >/dev/null || fail "expected $1 not to contain: $2"; }
assert_status() { [ "$1" -eq "$2" ] || fail "expected status $2, got $1"; }

# Schema generator behavior is separately deterministic and does not need a
# gateway, certificates, or Podman.
# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"
# shellcheck source=e2e/support/podman-gateway-config.sh
source "${ROOT}/e2e/support/podman-gateway-config.sh"
mkdir -p "${WORKDIR}/pki/client" "${WORKDIR}/jwt"
e2e_write_podman_gateway_config "${WORKDIR}/v1.toml" 1 "${ROOT}" "${WORKDIR}/pki" "${WORKDIR}/jwt" test-gateway 0 socket network 18181 image:test 15 supervisor:test '' '' 0 ''
e2e_write_podman_gateway_config "${WORKDIR}/v2.toml" 2 "${ROOT}" "${WORKDIR}/pki" "${WORKDIR}/jwt" test-gateway 0 socket network 18181 image:test 15 supervisor:test '' '' 0 ''
assert_contains "${WORKDIR}/v1.toml" 'version = 1'
assert_contains "${WORKDIR}/v1.toml" 'compute_drivers = ["podman"]'
assert_contains "${WORKDIR}/v1.toml" 'image_pull_policy = "missing"'
assert_contains "${WORKDIR}/v1.toml" 'health_check_interval_secs = 0'
assert_contains "${WORKDIR}/v1.toml" 'guest_tls_ca = '
assert_contains "${WORKDIR}/v2.toml" 'version = 2'
assert_contains "${WORKDIR}/v2.toml" 'compute_driver = "podman"'
assert_contains "${WORKDIR}/v2.toml" 'image_pull_policy = "if_not_present"'
assert_not_contains "${WORKDIR}/v2.toml" 'health_check_interval_secs = 0'
# V2 guest TLS is emitted before its driver table; V1 is driver-local.
OPENSHELL_E2E_PODMAN_OPTION_PROFILE=podman-options e2e_write_podman_gateway_config "${WORKDIR}/v1-options.toml" 1 "${ROOT}" "${WORKDIR}/pki" "${WORKDIR}/jwt" test-gateway 0 socket network 18181 image:test 15 supervisor:test "" "" 0 ""
OPENSHELL_E2E_PODMAN_OPTION_PROFILE=podman-options e2e_write_podman_gateway_config "${WORKDIR}/v2-options.toml" 2 "${ROOT}" "${WORKDIR}/pki" "${WORKDIR}/jwt" test-gateway 0 socket network 18181 image:test 15 supervisor:test "" "" 0 ""
for config in "${WORKDIR}/v1-options.toml" "${WORKDIR}/v2-options.toml"; do
  assert_contains "${config}" 'sandbox_pids_limit = 31'
  assert_contains "${config}" 'health_check_interval_secs = 7'
  assert_not_contains "${config}" 'app_armor_profile = '
done
assert_contains "${WORKDIR}/v1-options.toml" 'sandbox_ssh_socket_path = "/run/openshell/parity-ssh.sock"'
assert_contains "${WORKDIR}/v2-options.toml" 'ssh_socket_path = "/run/openshell/parity-ssh.sock"'
if OPENSHELL_E2E_PODMAN_OPTION_PROFILE=unknown e2e_podman_option_profile >/dev/null 2>&1; then fail 'unknown option profile unexpectedly accepted'; fi

v1_driver_line="$(grep -n '^\[openshell.drivers.podman\]' "${WORKDIR}/v1.toml" | cut -d: -f1)"
v1_tls_line="$(grep -n '^guest_tls_ca' "${WORKDIR}/v1.toml" | cut -d: -f1)"
v2_driver_line="$(grep -n '^\[openshell.drivers.podman\]' "${WORKDIR}/v2.toml" | cut -d: -f1)"
v2_tls_line="$(grep -n '^guest_tls_ca' "${WORKDIR}/v2.toml" | cut -d: -f1)"
[ "${v1_tls_line}" -gt "${v1_driver_line}" ] || fail 'v1 TLS must be driver-local'
[ "${v2_tls_line}" -lt "${v2_driver_line}" ] || fail 'v2 TLS must be gateway-owned'
if OPENSHELL_E2E_CONFIG_SCHEMA_VERSION=3 e2e_podman_config_schema_version >/dev/null 2>&1; then
  fail 'invalid schema version unexpectedly accepted'
fi
set +e
env -u OPENSHELL_GATEWAY_ENDPOINT \
  OPENSHELL_E2E_CONFIG_SCHEMA_VERSION=3 \
  bash "${ROOT}/e2e/with-podman-gateway.sh" true >"${WORKDIR}/wrapper-schema.out" 2>&1
status=$?
set -e
assert_status "${status}" 2
assert_contains "${WORKDIR}/wrapper-schema.out" 'must be 1 or 2'

HEAD_SHA="$(git -C "${ROOT}" rev-parse HEAD)"
cat >"${WORKDIR}/manifest.toml" <<EOF
manifest_version = 1
baseline_ref = "origin/main"
baseline_commit = "${HEAD_SHA}"
EOF
mkdir -p "${WORKDIR}/bin"
cat >"${WORKDIR}/bin/fake-wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for variable in OPENSHELL_GATEWAY_ENDPOINT OPENSHELL_GATEWAY_CONFIG OPENSHELL_COMPUTE_DRIVER OPENSHELL_COMPUTE_DRIVER_SOCKET OPENSHELL_DRIVERS; do
  [ -z "${!variable:-}" ] || exit 23
done
printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$OPENSHELL_PARITY_VARIANT" "$OPENSHELL_E2E_CONFIG_SCHEMA_VERSION" "$OPENSHELL_GATEWAY_BIN" "$OPENSHELL_BIN" "$OPENSHELL_CONFORMANCE_BIN" "$MISE_TRUSTED_CONFIG_PATHS" "${OPENSHELL_E2E_PODMAN_OPTION_PROFILE:-}" "${OPENSHELL_PARITY_ORACLE_RESULT:-}" "${OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER:-}" "${OPENSHELL_EXTERNAL_DRIVER_BIN:-}" "${OPENSHELL_E2E_SUPERVISOR_BIN:-}" >>"$OPENSHELL_PARITY_TEST_CALLS"
mkdir -p "$XDG_DATA_HOME/containers/storage"
case "${OPENSHELL_E2E_CONFIG_SCHEMA_VERSION}" in
  1) pull_policy=missing ;;
  2) pull_policy=if_not_present ;;
esac
transport=in_tree
external=false
if [ "${OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER:-0}" = 1 ]; then
  transport=remote_uds
  external=true
fi
printf '{"schema_version":%s,"external_compute_driver":%s,"compute_driver_transport":"%s","external_driver_pull_policy":"%s","supervisor_image":"%s","supervisor_image_id":"%064d","supervisor_image_digest":"sha256:%064d","supervisor_runtime_image":"%s"}\n' \
  "${OPENSHELL_E2E_CONFIG_SCHEMA_VERSION}" "${external}" "${transport}" "${pull_policy}" \
  "${OPENSHELL_SUPERVISOR_IMAGE}" 0 0 "${OPENSHELL_SUPERVISOR_IMAGE}" \
  >"${OPENSHELL_PARITY_LAUNCH_MANIFEST_CAPTURE}"
if [ "${OPENSHELL_PARITY_TEST_MUTATE_ARTIFACT:-}" = "${OPENSHELL_PARITY_VARIANT}" ]; then
  replacement="${OPENSHELL_GATEWAY_BIN}.replacement"
  printf '#!/usr/bin/env bash\nexit 0\n# mutated\n' >"${replacement}"
  chmod 0555 "${replacement}"
  mv "${replacement}" "${OPENSHELL_GATEWAY_BIN}"
fi
if [ "${OPENSHELL_E2E_PODMAN_OPTION_PROFILE:-}" = podman-options ]; then
  case "${OPENSHELL_PARITY_VARIANT}" in baseline) pids=2048 ;; candidate) pids=31 ;; esac
  stable=true
  if [ "${OPENSHELL_PARITY_TEST_SEMANTIC_DRIFT:-0}" = 1 ] && [ "${OPENSHELL_PARITY_VARIANT}" = candidate ]; then stable=false; fi
  if [ "${OPENSHELL_PARITY_TEST_SKIP_RESULT:-}" != "${OPENSHELL_PARITY_VARIANT}" ]; then
    printf '%s\n' "{\"scenario\":\"podman-options\",\"stable\":${stable},\"pids_limit\":${pids}}" > "${OPENSHELL_PARITY_ORACLE_RESULT}"
  fi
fi
exec "$@"
EOF
cat >"${WORKDIR}/bin/fake-podman" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$OPENSHELL_PARITY_TEST_PODMAN_CALLS"
[ "$1" = unshare ] || exit 19
shift
exec "$@"
EOF
cat >"${WORKDIR}/bin/fake-conformance" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${OPENSHELL_PARITY_FAIL_VARIANT:-}" = "${OPENSHELL_PARITY_VARIANT:-}" ] || [ "${OPENSHELL_PARITY_FAIL_VARIANT:-}" = both ]; then
  exit 17
fi
printf '{"untrusted":"raw output is intentionally not normalized"}\n'
EOF
for artifact in baseline-gateway baseline-cli candidate-gateway candidate-cli baseline-driver candidate-driver baseline-supervisor candidate-supervisor; do
  cat >"${WORKDIR}/bin/${artifact}" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
done
chmod +x "${WORKDIR}/bin/"*

# shellcheck source=e2e/support/podman-gateway-config.sh
source "${ROOT}/e2e/support/podman-gateway-config.sh"
[ "$(e2e_podman_external_driver_pull_policy 1)" = missing ] || fail 'schema v1 external pull policy mismatch'
[ "$(e2e_podman_external_driver_pull_policy 2)" = if_not_present ] || fail 'schema v2 external pull policy mismatch'

run_harness() {
  OPENSHELL_PARITY_CAPABILITY_MANIFEST="${WORKDIR}/manifest.toml" \
  OPENSHELL_PARITY_BASELINE_WORKTREE="${ROOT}" \
  OPENSHELL_PARITY_PODMAN_WRAPPER="${WORKDIR}/bin/fake-wrapper" \
  OPENSHELL_PARITY_PODMAN_BIN="${WORKDIR}/bin/fake-podman" \
  OPENSHELL_PARITY_PODMAN_OPTIONS_ORACLE="${WORKDIR}/bin/fake-conformance" \
  OPENSHELL_PARITY_BASELINE_GATEWAY_BIN="${WORKDIR}/bin/baseline-gateway" \
  OPENSHELL_PARITY_BASELINE_CLI_BIN="${WORKDIR}/bin/baseline-cli" \
  OPENSHELL_PARITY_BASELINE_CONFORMANCE_BIN="${WORKDIR}/bin/fake-conformance" \
  OPENSHELL_PARITY_CANDIDATE_GATEWAY_BIN="${WORKDIR}/bin/candidate-gateway" \
  OPENSHELL_PARITY_CANDIDATE_CLI_BIN="${WORKDIR}/bin/candidate-cli" \
  OPENSHELL_PARITY_CANDIDATE_CONFORMANCE_BIN="${WORKDIR}/bin/fake-conformance" \
  OPENSHELL_PARITY_BASELINE_EXTERNAL_DRIVER_BIN="${WORKDIR}/bin/baseline-driver" \
  OPENSHELL_PARITY_CANDIDATE_EXTERNAL_DRIVER_BIN="${OPENSHELL_PARITY_TEST_CANDIDATE_DRIVER_OVERRIDE:-${WORKDIR}/bin/candidate-driver}" \
  OPENSHELL_PARITY_BASELINE_SUPERVISOR_BIN="${WORKDIR}/bin/baseline-supervisor" \
  OPENSHELL_PARITY_CANDIDATE_SUPERVISOR_BIN="${WORKDIR}/bin/candidate-supervisor" \
  OPENSHELL_PARITY_RESULTS_DIR="${WORKDIR}/results" \
  OPENSHELL_PARITY_TEST_CALLS="${WORKDIR}/calls" \
  OPENSHELL_PARITY_TEST_PODMAN_CALLS="${WORKDIR}/podman-calls" \
  MISE_TRUSTED_CONFIG_PATHS= \
  bash "${ROOT}/e2e/parity/run.sh" --driver podman "$@"
}

OPENSHELL_GATEWAY_ENDPOINT=http://127.0.0.1:9 \
OPENSHELL_GATEWAY_CONFIG=/tmp/untrusted.toml \
OPENSHELL_COMPUTE_DRIVER=wrong \
OPENSHELL_COMPUTE_DRIVER_SOCKET=/tmp/untrusted.sock \
OPENSHELL_DRIVERS=wrong \
  run_harness
assert_contains "${WORKDIR}/calls" "baseline|1|${WORKDIR}/results/artifacts/baseline/gateway|${WORKDIR}/results/artifacts/baseline/cli|${WORKDIR}/results/artifacts/baseline/conformance"
assert_contains "${WORKDIR}/calls" "candidate|2|${WORKDIR}/results/artifacts/candidate/gateway|${WORKDIR}/results/artifacts/candidate/cli|${WORKDIR}/results/artifacts/candidate/conformance"
assert_contains "${WORKDIR}/calls" "|${ROOT}"
[ "$(sed -n '1s/|.*//p' "${WORKDIR}/calls")" = baseline ] || fail 'baseline was not invoked first'
[ "$(sed -n '2s/|.*//p' "${WORKDIR}/calls")" = candidate ] || fail 'candidate was not invoked second'
assert_contains "${WORKDIR}/results/baseline.json" "\"source_sha\":\"${HEAD_SHA}\""
assert_contains "${WORKDIR}/results/baseline.json" '"schema_version":1'
assert_contains "${WORKDIR}/results/candidate.json" '"schema_version":2'
assert_contains "${WORKDIR}/results/candidate.json" "\"source_sha\":\"${HEAD_SHA}\""
assert_contains "${WORKDIR}/results/candidate.json" '"success":true'
assert_contains "${WORKDIR}/results/comparison.json" '"parity":true'
assert_not_contains "${WORKDIR}/results/baseline.json" 'raw output'
assert_contains "${WORKDIR}/results/baseline.log" 'raw output is intentionally not normalized'
assert_contains "${WORKDIR}/podman-calls" 'unshare rm -rf -- '
assert_contains "${WORKDIR}/podman-calls" 'openshell-parity-run.'

run_harness --scenario external-driver
assert_contains "${WORKDIR}/calls" "|1|${WORKDIR}/results/artifacts/baseline/external-driver|${WORKDIR}/results/artifacts/baseline/supervisor"
assert_contains "${WORKDIR}/calls" "|1|${WORKDIR}/results/artifacts/candidate/external-driver|${WORKDIR}/results/artifacts/candidate/supervisor"
assert_contains "${WORKDIR}/results/baseline.json" '"scenario":"external-driver"'
assert_contains "${WORKDIR}/results/baseline.json" '"command_class":"external_driver_conformance_smoke"'
assert_contains "${WORKDIR}/results/baseline.json" '"gateway_profile":"driver-free"'
assert_contains "${WORKDIR}/results/baseline.json" '"gateway_cargo_features":"--no-default-features --features telemetry"'
assert_contains "${WORKDIR}/results/baseline.json" '"gateway_origin":"supplied_override"'
assert_contains "${WORKDIR}/results/baseline.json" '"external_driver_origin":"supplied_override"'
assert_contains "${WORKDIR}/results/baseline.launch.json" '"compute_driver_transport":"remote_uds"'
assert_contains "${WORKDIR}/results/baseline.launch.json" '"external_driver_pull_policy":"missing"'
assert_contains "${WORKDIR}/results/baseline.launch.json" '"supervisor_image_digest":"sha256:'
assert_contains "${WORKDIR}/results/baseline.launch.json" '"supervisor_runtime_image":"localhost/openshell/supervisor:parity-baseline-'
assert_contains "${WORKDIR}/results/candidate.launch.json" '"external_driver_pull_policy":"if_not_present"'
assert_contains "${WORKDIR}/results/baseline.json" '"gateway_sha256"'
assert_contains "${WORKDIR}/results/baseline.json" '"cli_sha256"'
assert_contains "${WORKDIR}/results/baseline.json" '"conformance_sha256"'
assert_contains "${WORKDIR}/results/baseline.json" '"supervisor_origin":"supplied_override"'
assert_contains "${WORKDIR}/results/baseline.json" '"supervisor_sha256"'
assert_contains "${WORKDIR}/results/baseline.json" '"supervisor_dockerfile_sha256"'
assert_contains "${WORKDIR}/results/baseline.json" '"external_driver_sha256"'
assert_contains "${WORKDIR}/results/comparison.json" '"classification":"pass"'

set +e
OPENSHELL_PARITY_TEST_CANDIDATE_DRIVER_OVERRIDE="${WORKDIR}/bin/baseline-driver" \
  run_harness --scenario external-driver >"${WORKDIR}/same-driver.out" 2>&1
status=$?
set -e
assert_status "${status}" 2
assert_contains "${WORKDIR}/same-driver.out" 'requires distinct baseline and candidate driver artifacts'

run_harness --scenario podman-options
assert_contains "${WORKDIR}/calls" "baseline|1|${WORKDIR}/results/artifacts/baseline/gateway|${WORKDIR}/results/artifacts/baseline/cli|${WORKDIR}/results/artifacts/baseline/conformance|${ROOT}|podman-options"
assert_contains "${WORKDIR}/calls" "candidate|2|${WORKDIR}/results/artifacts/candidate/gateway|${WORKDIR}/results/artifacts/candidate/cli|${WORKDIR}/results/artifacts/candidate/conformance|${ROOT}|podman-options"
assert_contains "${WORKDIR}/results/baseline.json" '"scenario":"podman-options"'
assert_contains "${WORKDIR}/results/baseline.json" '"command_class":"podman_options"'
assert_contains "${WORKDIR}/results/baseline.json" '"normalized_result":"baseline.normalized.json"'
assert_contains "${WORKDIR}/results/baseline.normalized.json" '"stable":true'
assert_contains "${WORKDIR}/results/baseline.normalized.json" '"pids_limit":2048'
assert_contains "${WORKDIR}/results/candidate.normalized.json" '"pids_limit":31'
assert_not_contains "${WORKDIR}/results/baseline.json" 'raw output'
assert_contains "${WORKDIR}/results/baseline.log" 'raw output is intentionally not normalized'
assert_contains "${WORKDIR}/results/comparison.json" '"scenario":"podman-options"'
assert_contains "${WORKDIR}/results/comparison.json" '"parity":false'
assert_contains "${WORKDIR}/results/comparison.json" '"classification":"intentional_change"'
assert_contains "${WORKDIR}/results/comparison.json" '"intentional_change_id":"podman-pid-limit-restored"'
assert_contains "${WORKDIR}/results/comparison.json" '"accepted":true'

set +e
OPENSHELL_PARITY_TEST_SEMANTIC_DRIFT=1 run_harness --scenario podman-options >"${WORKDIR}/drift.out" 2>&1
status=$?
set -e
assert_status "${status}" 1
assert_contains "${WORKDIR}/results/comparison.json" '"classification":"regression"'
assert_contains "${WORKDIR}/results/comparison.json" '"accepted":false'

rm -f "${WORKDIR}/results/candidate.normalized.json"
set +e
OPENSHELL_PARITY_TEST_SKIP_RESULT=candidate run_harness --scenario podman-options >"${WORKDIR}/missing-result.out" 2>&1
status=$?
set -e
assert_status "${status}" 1
assert_contains "${WORKDIR}/results/comparison.json" '"classification":"regression"'
assert_contains "${WORKDIR}/results/comparison.json" '"accepted":false'

set +e
OPENSHELL_PARITY_FAIL_VARIANT=both run_harness >"${WORKDIR}/failure.out" 2>&1
status=$?
set -e
assert_status "${status}" 1
assert_contains "${WORKDIR}/results/baseline.json" '"success":false'
assert_contains "${WORKDIR}/results/candidate.json" '"success":false'
assert_contains "${WORKDIR}/results/comparison.json" '"parity":false'
[ "$(wc -l <"${WORKDIR}/calls")" -eq 12 ] || fail 'candidate did not run after baseline failure'

set +e
OPENSHELL_PARITY_TEST_MUTATE_ARTIFACT=candidate run_harness >"${WORKDIR}/mutation.out" 2>&1
status=$?
set -e
assert_status "${status}" 1
assert_contains "${WORKDIR}/mutation.out" 'candidate gateway changed after it was staged for execution'
assert_contains "${WORKDIR}/results/candidate.json" '"success":false'
assert_contains "${WORKDIR}/results/comparison.json" '"classification":"regression"'

set +e
bash "${ROOT}/e2e/parity/run.sh" --driver docker >"${WORKDIR}/driver.out" 2>&1
status=$?
set -e
assert_status "${status}" 2
assert_contains "${WORKDIR}/driver.out" 'only --driver podman is supported'

set +e
bash "${ROOT}/e2e/parity/run.sh" --driver >"${WORKDIR}/option.out" 2>&1
status=$?
set -e
assert_status "${status}" 2
assert_contains "${WORKDIR}/option.out" '--driver requires a value'

echo 'e2e parity deterministic tests passed.'
