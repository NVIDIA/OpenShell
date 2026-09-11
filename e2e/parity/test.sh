#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Deterministic contract tests for e2e/parity/run.sh. No container runtime is
# invoked; the Podman wrapper and all three artifacts are tiny local fakes.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_ROOT="${TMPDIR:-/tmp}"
TMP_ROOT="${TMP_ROOT%/}"
WORKDIR="$(mktemp -d "${TMP_ROOT}/openshell-parity-test.XXXXXX")"
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

cat >"${WORKDIR}/trace-cli-fixture" <<'EOF'
#!/usr/bin/env bash
printf 'openshell-conformance-tracefixture\n'
printf 'trace fixture stderr\n' >&2
EOF
chmod +x "${WORKDIR}/trace-cli-fixture"
OPENSHELL_PARITY_REAL_CLI="${WORKDIR}/trace-cli-fixture" \
OPENSHELL_PARITY_EXEC_STDOUT_CAPTURE="${WORKDIR}/trace-cli.stdout" \
  bash "${ROOT}/e2e/parity/trace-cli.sh" sandbox exec -- echo marker \
  >"${WORKDIR}/trace-cli.forwarded.stdout" \
  2>"${WORKDIR}/trace-cli.forwarded.stderr"
cmp -s "${WORKDIR}/trace-cli.stdout" "${WORKDIR}/trace-cli.forwarded.stdout" \
  || fail 'CLI trace wrapper did not preserve exact exec stdout'
assert_contains "${WORKDIR}/trace-cli.forwarded.stderr" 'trace fixture stderr'

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
for variable in \
  OPENSHELL_GATEWAY_ENDPOINT OPENSHELL_GATEWAY_CONFIG OPENSHELL_COMPUTE_DRIVER \
  OPENSHELL_COMPUTE_DRIVER_SOCKET OPENSHELL_DRIVERS OPENSHELL_PODMAN_SOCKET \
  CONTAINER_HOST CONTAINER_CONNECTION CONTAINERS_STORAGE_CONF CONTAINERS_CONF \
  CONTAINERS_REGISTRIES_CONF CONTAINERS_REGISTRIES_CONF_DIR CONTAINERS_POLICY \
  PODMAN_CONNECTIONS_CONF DOCKER_HOST OPENSHELL_SANDBOX_IMAGE \
  OPENSHELL_GRPC_ENDPOINT OPENSHELL_PODMAN_HOST_GATEWAY_IP OPENSHELL_PODMAN_USERNS \
  OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET OPENSHELL_E2E_PROVIDER_SPIFFE_SOCKET \
  OPENSHELL_APP_ARMOR_PROFILE OPENSHELL_SANDBOX_HTTPS_PROXY OPENSHELL_SANDBOX_NO_PROXY \
  OPENSHELL_SANDBOX_PROXY_AUTH_FILE OPENSHELL_SANDBOX_PROXY_AUTH_ALLOW_INSECURE \
  OPENSHELL_SANDBOX_PROXY_CONNECT_BY_HOSTNAME OPENSHELL_SANDBOX_PROXY_CA_BUNDLE \
  OPENSHELL_OTLP_ENDPOINT OPENSHELL_GATEWAY_NAME OPENSHELL_COMPUTE_DRIVER_BIND; do
  [ -z "${!variable:-}" ] || exit 23
done
expected_sandbox="ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:$(printf '%064d' 0)"
[ "${OPENSHELL_E2E_REQUIRE_DIGEST_PINNED_SANDBOX_IMAGE:-0}" = 1 ] || exit 24
[ "${OPENSHELL_E2E_PODMAN_SANDBOX_IMAGE:-}" = "${expected_sandbox}" ] || exit 25
[ "${OPENSHELL_COMMUNITY_REGISTRY:-}" = "ghcr.io/nvidia/openshell-community/sandboxes" ] || exit 28
expected_base="docker.io/library/alpine@sha256:$(printf '%064d' 0)"
[ "${OPENSHELL_E2E_SUPERVISOR_BASE_IMAGE:-}" = alpine:3.22 ] || exit 26
[ "${OPENSHELL_E2E_SUPERVISOR_BASE_RUNTIME_IMAGE:-}" = "${expected_base}" ] || exit 27
printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$OPENSHELL_PARITY_VARIANT" "$OPENSHELL_E2E_CONFIG_SCHEMA_VERSION" "$OPENSHELL_GATEWAY_BIN" "$OPENSHELL_BIN" "$OPENSHELL_CONFORMANCE_BIN" "$MISE_TRUSTED_CONFIG_PATHS" "${OPENSHELL_E2E_PODMAN_OPTION_PROFILE:-}" "${OPENSHELL_PARITY_ORACLE_RESULT:-}" "${OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER:-}" "${OPENSHELL_EXTERNAL_DRIVER_BIN:-}" "${OPENSHELL_E2E_SUPERVISOR_BIN:-}" >>"$OPENSHELL_PARITY_TEST_CALLS"
mkdir -p "$XDG_DATA_HOME/containers/storage"
printf 'fixture-package-1.0-r0\n' >"${OPENSHELL_PARITY_SUPERVISOR_PACKAGE_CAPTURE}"
package_hash="$(sha256sum "${OPENSHELL_PARITY_SUPERVISOR_PACKAGE_CAPTURE}" | cut -d' ' -f1)"
OPENSHELL_PARITY_FIXTURE_PACKAGE_HASH="${package_hash}" python3 - <<'PY'
import json
import os
from pathlib import Path

variant = os.environ["OPENSHELL_PARITY_VARIANT"]
schema = int(os.environ["OPENSHELL_E2E_CONFIG_SCHEMA_VERSION"])
external = os.environ.get("OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER") == "1"
zero = "0" * 64
image_digest = f"sha256:{zero}"
sandbox_runtime = f"ghcr.io/nvidia/openshell-community/sandboxes/base@{image_digest}"
supervisor_runtime = f"localhost/openshell/supervisor@{image_digest}"
base_runtime = f"docker.io/library/alpine@{image_digest}"
pull_policy = "missing" if schema == 1 else "if_not_present"
gateway_port = 18181
callback = f"https://host.containers.internal:{gateway_port}"
driver_socket = f"/tmp/{variant}-driver.sock"
podman_socket = f"/tmp/{variant}-podman.sock"
network = f"{variant}-network"

selector = (
    'compute_drivers = ["podman"]'
    if schema == 1
    else 'compute_driver = "podman"'
)
config_lines = [
    "[openshell]",
    f"version = {schema}",
    "[openshell.gateway]",
    selector,
    "[openshell.drivers.podman]",
    f'socket_path = "{driver_socket}"',
]
if not external:
    config_lines.extend(
        [
            f'network_name = "{network}"',
            f'default_image = "{sandbox_runtime}"',
            f'image_pull_policy = "{pull_policy}"',
            f'supervisor_image = "{supervisor_runtime}"',
        ]
    )
Path(os.environ["OPENSHELL_PARITY_GATEWAY_CONFIG_CAPTURE"]).write_text(
    "\n".join(config_lines) + "\n", encoding="utf-8"
)

launch = {
    "schema_version": schema,
    "gateway_port": gateway_port,
    "external_compute_driver": external,
    "compute_driver_transport": "remote_uds" if external else "in_tree",
    "external_driver_pull_policy": pull_policy,
    "supervisor_image": os.environ["OPENSHELL_SUPERVISOR_IMAGE"],
    "supervisor_image_id": zero,
    "supervisor_image_digest": image_digest,
    "supervisor_runtime_image": supervisor_runtime,
    "supervisor_base_image": "alpine:3.22",
    "supervisor_base_image_id": zero,
    "supervisor_base_image_digest": image_digest,
    "supervisor_base_runtime_image": base_runtime,
    "supervisor_package_manifest_sha256": os.environ[
        "OPENSHELL_PARITY_FIXTURE_PACKAGE_HASH"
    ],
    "sandbox_image_request": sandbox_runtime,
    "sandbox_image_id": zero,
    "sandbox_image_digest": image_digest,
    "sandbox_runtime_image": sandbox_runtime,
    "sandbox_client_image_alias": "ghcr.io/nvidia/openshell-community/sandboxes/base:latest",
    "sandbox_client_image_alias_id": zero,
    "gateway_sha256_before_execution": os.environ[
        "OPENSHELL_E2E_EXPECTED_GATEWAY_SHA256"
    ],
    "cli_sha256_before_execution": os.environ["OPENSHELL_E2E_EXPECTED_CLI_SHA256"],
    "conformance_sha256_before_execution": os.environ[
        "OPENSHELL_E2E_EXPECTED_CONFORMANCE_SHA256"
    ],
    "external_driver_sha256_before_execution": os.environ.get(
        "OPENSHELL_E2E_EXPECTED_EXTERNAL_DRIVER_SHA256", ""
    ),
    "supervisor_sha256_before_execution": os.environ[
        "OPENSHELL_E2E_EXPECTED_SUPERVISOR_SHA256"
    ],
    "supervisor_dockerfile_sha256_before_execution": os.environ[
        "OPENSHELL_E2E_EXPECTED_SUPERVISOR_DOCKERFILE_SHA256"
    ],
    "cli_trace_wrapper_sha256_before_execution": os.environ[
        "OPENSHELL_E2E_EXPECTED_CLI_TRACE_WRAPPER_SHA256"
    ],
}
if external:
    launch.update(
        {
            "external_driver_grpc_endpoint": callback,
            "external_driver_host_gateway_ip": "host-gateway",
            "external_driver_userns": None,
            "external_driver_spiffe": False,
            "external_driver_proxy": False,
            "external_driver_app_armor": False,
            "external_driver_environment": {
                "OPENSHELL_COMPUTE_DRIVER_SOCKET": driver_socket,
                "OPENSHELL_PODMAN_SOCKET": podman_socket,
                "OPENSHELL_SANDBOX_IMAGE": sandbox_runtime,
                "OPENSHELL_SANDBOX_IMAGE_PULL_POLICY": pull_policy,
                "OPENSHELL_HEALTH_CHECK_INTERVAL_SECS": 10,
                "OPENSHELL_GRPC_ENDPOINT": callback,
                "OPENSHELL_GATEWAY_PORT": gateway_port,
                "OPENSHELL_NETWORK_NAME": network,
                "OPENSHELL_STOP_TIMEOUT": 15,
                "OPENSHELL_SUPERVISOR_IMAGE": supervisor_runtime,
                "OPENSHELL_PODMAN_TLS_CA": {
                    "path": f"/tmp/{variant}-pki/ca.crt",
                    "sha256": "8" * 64,
                },
                "OPENSHELL_PODMAN_TLS_CERT": {
                    "path": f"/tmp/{variant}-pki/tls.crt",
                    "sha256": "9" * 64,
                },
                "OPENSHELL_PODMAN_TLS_KEY": {
                    "path": f"/tmp/{variant}-pki/tls.key",
                    "sha256": "a" * 64,
                },
                "OPENSHELL_ENABLE_BIND_MOUNTS": True,
            },
        }
    )
Path(os.environ["OPENSHELL_PARITY_LAUNCH_MANIFEST_CAPTURE"]).write_text(
    json.dumps(launch, separators=(",", ":")) + "\n", encoding="utf-8"
)
PY
run_id="fixture${OPENSHELL_PARITY_VARIANT}"
printf 'openshell-conformance-%s\n' "${run_id}" >"${OPENSHELL_PARITY_EXEC_STDOUT_CAPTURE}"
printf 'CLI conformance run ID: %s\n' "${run_id}" >&2
printf 'gateway preflight connected: gateway=fixture, authentication=authenticated\n' >&2
for marker in status create get-ready list-visible/0 exec delete list-empty/query/0; do
  printf '[run %s][smoke/%s] completed in 1ms: exit 0\n' "${run_id}" "${marker}" >&2
done
printf '%s %064d sha256:%064d %s %s %s %s\n' \
  "${expected_sandbox}" 0 0 "${expected_base}" \
  "localhost/openshell/supervisor@sha256:$(printf '%064d' 0)" \
  "ghcr.io/nvidia/openshell-community/sandboxes/base:latest" \
  "${package_hash}" >&2
if [ "${OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER:-0}" = 1 ]; then
  printf 'fixture external driver log\n' >"${OPENSHELL_PARITY_EXTERNAL_DRIVER_LOG_CAPTURE}"
fi
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
case "$1" in
  pull) exit 0 ;;
  image)
    [ "$2" = inspect ] || exit 19
    case "$4" in
      '{{.Id}}') printf 'sha256:%064d\n' 0 ;;
      '{{.Digest}}') printf 'sha256:%064d\n' 0 ;;
      '{{index .RepoDigests 0}}') printf 'docker.io/library/alpine@sha256:%064d\n' 0 ;;
      *) exit 19 ;;
    esac
    ;;
  unshare)
    shift
    exec "$@"
    ;;
  *) exit 19 ;;
esac
EOF
cat >"${WORKDIR}/bin/fake-conformance" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${OPENSHELL_PARITY_FAIL_VARIANT:-}" = "${OPENSHELL_PARITY_VARIANT:-}" ] || [ "${OPENSHELL_PARITY_FAIL_VARIANT:-}" = both ]; then
  exit 17
fi
if [ "${OPENSHELL_PARITY_TEST_INVALID_REPORT:-0}" = 1 ]; then
  # Prove the verifier parses retained stdout instead of accepting a success
  # substring injected into unrelated raw stderr.
  printf '%s\n' '"passed": true' >&2
  printf '%s\n' '{"scenarios":[{"name":"smoke","passed":false,"diagnostic":"fixture failure"}],"passed":false}'
else
  printf '%s\n' '{'
  printf '%s\n' '  "scenarios": [{"name":"smoke","passed":true,"diagnostic":null}],'
  printf '%s\n' '  "passed": true'
  printf '%s\n' '}'
fi
EOF
for artifact in baseline-gateway baseline-cli candidate-gateway candidate-cli baseline-driver candidate-driver baseline-supervisor candidate-supervisor; do
  printf '#!/usr/bin/env bash\n# %s\nexit 0\n' "${artifact}" >"${WORKDIR}/bin/${artifact}"
done
chmod +x "${WORKDIR}/bin/"*

# shellcheck source=e2e/support/podman-gateway-config.sh
source "${ROOT}/e2e/support/podman-gateway-config.sh"
[ "$(e2e_podman_external_driver_pull_policy 1)" = missing ] || fail 'schema v1 external pull policy mismatch'
[ "$(e2e_podman_external_driver_pull_policy 2)" = if_not_present ] || fail 'schema v2 external pull policy mismatch'

run_harness() {
  if [ "${OPENSHELL_PARITY_TEST_KEEP_RESULTS_DIR:-0}" != 1 ]; then
    rm -rf -- "${WORKDIR}/results"
  fi
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
OPENSHELL_PODMAN_SOCKET=/tmp/untrusted-podman.sock \
CONTAINER_HOST=tcp://untrusted.invalid:9999 \
CONTAINER_CONNECTION=untrusted \
CONTAINERS_STORAGE_CONF=/tmp/untrusted-storage.conf \
CONTAINERS_CONF=/tmp/untrusted-containers.conf \
CONTAINERS_REGISTRIES_CONF=/tmp/untrusted-registries.conf \
CONTAINERS_REGISTRIES_CONF_DIR=/tmp/untrusted-registries.d \
CONTAINERS_POLICY=/tmp/untrusted-policy.json \
PODMAN_CONNECTIONS_CONF=/tmp/untrusted-connections.json \
DOCKER_HOST=tcp://untrusted.invalid:2375 \
OPENSHELL_SANDBOX_IMAGE=untrusted.invalid/sandbox:latest \
OPENSHELL_GRPC_ENDPOINT=http://untrusted.invalid:1 \
OPENSHELL_PODMAN_HOST_GATEWAY_IP=192.0.2.1 \
OPENSHELL_PODMAN_USERNS=keep-id \
OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET=/tmp/untrusted-spiffe.sock \
OPENSHELL_E2E_PROVIDER_SPIFFE_SOCKET=/tmp/untrusted-e2e-spiffe.sock \
OPENSHELL_APP_ARMOR_PROFILE=Unconfined \
OPENSHELL_SANDBOX_HTTPS_PROXY=http://untrusted.invalid:8080 \
OPENSHELL_SANDBOX_NO_PROXY=untrusted.invalid \
OPENSHELL_SANDBOX_PROXY_AUTH_FILE=/tmp/untrusted-proxy-auth \
OPENSHELL_SANDBOX_PROXY_AUTH_ALLOW_INSECURE=true \
OPENSHELL_SANDBOX_PROXY_CONNECT_BY_HOSTNAME=true \
OPENSHELL_SANDBOX_PROXY_CA_BUNDLE=/tmp/untrusted-proxy-ca \
OPENSHELL_OTLP_ENDPOINT=http://untrusted.invalid:4317 \
OPENSHELL_GATEWAY_NAME=untrusted \
OPENSHELL_COMPUTE_DRIVER_BIND=192.0.2.2:50061 \
OPENSHELL_COMMUNITY_REGISTRY=untrusted.invalid/community \
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
assert_contains "${WORKDIR}/results/semantic-verification.json" '"accepted": true'
assert_not_contains "${WORKDIR}/results/baseline.json" '"scenarios"'
assert_contains "${WORKDIR}/results/baseline.log" '"scenarios"'
assert_contains "${WORKDIR}/results/baseline.conformance.json" '"passed":true'
assert_contains "${WORKDIR}/podman-calls" 'pull ghcr.io/nvidia/openshell-community/sandboxes/base:latest'
assert_contains "${WORKDIR}/podman-calls" 'pull alpine:3.22'
assert_contains "${WORKDIR}/podman-calls" 'unshare rm -rf -- '
assert_contains "${WORKDIR}/podman-calls" 'openshell-parity-run.'

set +e
OPENSHELL_PARITY_TEST_INVALID_REPORT=1 run_harness >"${WORKDIR}/invalid-report.out" 2>&1
status=$?
set -e
assert_status "${status}" 1
assert_contains "${WORKDIR}/invalid-report.out" 'conformance report did not pass'
assert_contains "${WORKDIR}/invalid-report.out" 'semantic verification failed for smoke'
assert_contains "${WORKDIR}/results/comparison.json" '"classification":"regression"'
assert_contains "${WORKDIR}/results/comparison.json" '"accepted":false'

set +e
OPENSHELL_E2E_PODMAN_SANDBOX_IMAGE=untrusted.invalid/sandbox:latest \
  run_harness >"${WORKDIR}/mutable-sandbox.out" 2>&1
status=$?
set -e
assert_status "${status}" 2
assert_contains "${WORKDIR}/mutable-sandbox.out" 'must be digest-pinned for parity runs'

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
assert_contains "${WORKDIR}/results/baseline.launch.json" '"supervisor_runtime_image":"localhost/openshell/supervisor@sha256:'
assert_contains "${WORKDIR}/results/candidate.launch.json" '"external_driver_pull_policy":"if_not_present"'
assert_contains "${WORKDIR}/results/baseline.json" '"gateway_sha256"'
assert_contains "${WORKDIR}/results/baseline.json" '"cli_sha256"'
assert_contains "${WORKDIR}/results/baseline.json" '"conformance_sha256"'
assert_contains "${WORKDIR}/results/baseline.json" '"supervisor_origin":"supplied_override"'
assert_contains "${WORKDIR}/results/baseline.json" '"supervisor_sha256"'
assert_contains "${WORKDIR}/results/baseline.json" '"supervisor_dockerfile_sha256"'
assert_contains "${WORKDIR}/results/baseline.json" '"external_driver_sha256"'
assert_contains "${WORKDIR}/results/comparison.json" '"classification":"pass"'
assert_contains "${WORKDIR}/results/semantic-verification.json" '"scenario": "external-driver"'

set +e
OPENSHELL_PARITY_TEST_CANDIDATE_DRIVER_OVERRIDE="${WORKDIR}/bin/baseline-driver" \
  run_harness --scenario external-driver >"${WORKDIR}/same-driver.out" 2>&1
status=$?
set -e
assert_status "${status}" 2
assert_contains "${WORKDIR}/same-driver.out" 'requires distinct baseline and candidate driver artifacts'

cp "${WORKDIR}/bin/baseline-driver" "${WORKDIR}/bin/same-content-driver"
set +e
OPENSHELL_PARITY_TEST_CANDIDATE_DRIVER_OVERRIDE="${WORKDIR}/bin/same-content-driver" \
  run_harness --scenario external-driver >"${WORKDIR}/same-driver-content.out" 2>&1
status=$?
set -e
assert_status "${status}" 2
assert_contains "${WORKDIR}/same-driver-content.out" 'requires different baseline and candidate driver content'

run_harness --scenario podman-options
assert_contains "${WORKDIR}/calls" "baseline|1|${WORKDIR}/results/artifacts/baseline/gateway|${WORKDIR}/results/artifacts/baseline/cli|${WORKDIR}/results/artifacts/baseline/conformance|${ROOT}|podman-options"
assert_contains "${WORKDIR}/calls" "candidate|2|${WORKDIR}/results/artifacts/candidate/gateway|${WORKDIR}/results/artifacts/candidate/cli|${WORKDIR}/results/artifacts/candidate/conformance|${ROOT}|podman-options"
assert_contains "${WORKDIR}/results/baseline.json" '"scenario":"podman-options"'
assert_contains "${WORKDIR}/results/baseline.json" '"command_class":"podman_options"'
assert_contains "${WORKDIR}/results/baseline.json" '"normalized_result":"baseline.normalized.json"'
assert_contains "${WORKDIR}/results/baseline.normalized.json" '"stable":true'
assert_contains "${WORKDIR}/results/baseline.normalized.json" '"pids_limit":2048'
assert_contains "${WORKDIR}/results/candidate.normalized.json" '"pids_limit":31'
assert_not_contains "${WORKDIR}/results/baseline.json" '"scenarios"'
assert_contains "${WORKDIR}/results/baseline.log" '"scenarios"'
assert_not_contains "${WORKDIR}/results/baseline.json" 'raw output'
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

# Refuse an existing output path instead of consuming stale evidence from it.
[ -s "${WORKDIR}/results/candidate.normalized.json" ] || fail 'stale result fixture is missing'
set +e
OPENSHELL_PARITY_TEST_KEEP_RESULTS_DIR=1 run_harness --scenario podman-options >"${WORKDIR}/stale-results.out" 2>&1
status=$?
set -e
assert_status "${status}" 2
assert_contains "${WORKDIR}/stale-results.out" 'parity results directory already exists'

# A fresh run whose wrapper emits no candidate result must fail.
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
[ "$(wc -l <"${WORKDIR}/calls")" -eq 14 ] || fail 'candidate did not run after baseline failure'

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
