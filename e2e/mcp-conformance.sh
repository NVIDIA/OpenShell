#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=e2e/support/gateway-common.sh disable=SC1091
source "${ROOT}/e2e/support/gateway-common.sh"
CONFORMANCE_DIR="${OPENSHELL_MCP_CONFORMANCE_DIR:-${ROOT}/.cache/mcp-conformance}"
# Pinned after v0.1.16 for the upstream tools_call fixture fix. The current
# checkout still needs temporary client-fixture patches for
# modelcontextprotocol/conformance#345; remove patch_conformance_clients when
# OPENSHELL_MCP_CONFORMANCE_REF points at a release containing those fixes.
CONFORMANCE_REF="${OPENSHELL_MCP_CONFORMANCE_REF:-b9041ea41b0188581803459dbae71bc7e02fd995}"
CLIENT_IMAGE="${OPENSHELL_MCP_CONFORMANCE_CLIENT_IMAGE:-openshell-mcp-conformance-client:local}"
SCENARIOS="${OPENSHELL_MCP_CONFORMANCE_SCENARIOS:-}"
SPEC_VERSION="${OPENSHELL_MCP_CONFORMANCE_SPEC_VERSION:-2025-11-25}"
TIMEOUT_MS="${OPENSHELL_MCP_CONFORMANCE_TIMEOUT_MS:-900000}"
FORCE_REBUILD="${OPENSHELL_MCP_CONFORMANCE_FORCE_REBUILD:-0}"
DOCKER_PULL="${OPENSHELL_MCP_CONFORMANCE_DOCKER_PULL:-0}"
CLIENT_IMAGE_REF_LABEL="org.openshell.mcp-conformance.ref"
CLIENT_IMAGE_DOCKERFILE_LABEL="org.openshell.mcp-conformance.dockerfile"
CLIENT_IMAGE_DOCKERIGNORE_LABEL="org.openshell.mcp-conformance.dockerignore"
CLIENT_IMAGE_FIXTURE_HASH_LABEL="org.openshell.mcp-conformance.fixture-hash"
RUN_SCENARIOS_COMMAND="__openshell_mcp_run_scenarios"
CLIENT_SANDBOX_MANAGED=0
HOST_BRIDGE_PID=""
HOST_BRIDGE_LOG=""
HOST_BRIDGE_TOKEN=""
RUNNER_CONTAINER_IP=""
RUNNER_CONTAINER=""

# Static default scenarios for the pinned CONFORMANCE_REF and default
# SPEC_VERSION. To refresh this list after changing either value, list the
# scenarios from the built client image:
#
#   docker run --rm openshell-mcp-conformance-client:local \
#     ./node_modules/.bin/tsx src/index.ts list --client --spec-version 2025-11-25
#
# Then confirm each scenario has a compatible handler in the pinned
# examples/clients/typescript/everything-client.ts. Keep auth/OAuth scenarios
# and the slow sse-retry scenario opt-in unless intentionally broadening the
# default MCP e2e coverage.
DEFAULT_SCENARIOS=(
  initialize
  tools_call
  elicitation-sep1034-client-defaults
)

require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "ERROR: ${name} is required to run MCP conformance e2e tests." >&2
    exit 2
  fi
}

is_commit_ref() {
  [[ "$1" =~ ^[0-9a-fA-F]{40}$ ]]
}

checkout_conformance() {
  mkdir -p "$(dirname "${CONFORMANCE_DIR}")"

  if [ ! -e "${CONFORMANCE_DIR}" ]; then
    git init "${CONFORMANCE_DIR}"
    git -C "${CONFORMANCE_DIR}" remote add origin \
      https://github.com/modelcontextprotocol/conformance.git
  fi

  if [ ! -d "${CONFORMANCE_DIR}/.git" ]; then
    echo "ERROR: ${CONFORMANCE_DIR} exists but is not a git checkout." >&2
    echo "       Set OPENSHELL_MCP_CONFORMANCE_DIR to another path or remove the directory." >&2
    exit 2
  fi

  if is_commit_ref "${CONFORMANCE_REF}"; then
    local current_head=""
    current_head="$(git -C "${CONFORMANCE_DIR}" rev-parse HEAD 2>/dev/null || true)"
    if [ "${current_head}" = "${CONFORMANCE_REF}" ] \
      && git -C "${CONFORMANCE_DIR}" diff --quiet \
      && git -C "${CONFORMANCE_DIR}" diff --cached --quiet; then
      echo "Using cached MCP conformance checkout ${CONFORMANCE_REF}." >&2
      return
    fi
  fi

  git -C "${CONFORMANCE_DIR}" fetch --depth 1 origin "${CONFORMANCE_REF}"
  git -C "${CONFORMANCE_DIR}" checkout --force --detach FETCH_HEAD
}

docker_image_label() {
  local image=$1
  local label=$2

  docker image inspect \
    --format "{{ index .Config.Labels \"${label}\" }}" \
    "${image}" 2>/dev/null || true
}

openshell_bin() {
  if [ -n "${OPENSHELL_BIN:-}" ]; then
    printf '%s\n' "${OPENSHELL_BIN}"
    return
  fi

  local target_dir
  target_dir="$(e2e_cargo_target_dir "${ROOT}")"
  printf '%s\n' "${target_dir}/debug/openshell"
}

patch_conformance_clients() {
  node - "${CONFORMANCE_DIR}" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');

const root = process.argv[2];

function rewrite(file, rewriter) {
  const target = path.join(root, file);
  const source = fs.readFileSync(target, 'utf8');
  const next = rewriter(source, file);

  if (next !== source) {
    fs.writeFileSync(target, next);
    console.error(`Patched upstream MCP conformance fixture: ${file}`);
  }
}

function patchApplyDefaults(source, file) {
  if (/elicitation:\s*{\s*form:\s*{\s*applyDefaults:\s*true\s*}\s*}/m.test(source)) {
    return source;
  }

  const broken = /elicitation:\s*{\s*applyDefaults:\s*true\s*}/m;
  if (!broken.test(source)) {
    throw new Error(`${file}: could not find the known elicitation defaults fixture`);
  }

  return source.replace(
    broken,
    `elicitation: {
            form: {
              applyDefaults: true
            }
          }`
  );
}

rewrite('examples/clients/typescript/everything-client.ts', (source, file) => {
  let next = patchApplyDefaults(source, file);
  if (next.includes('elicitation-sep1034-client-defaults')) {
    return next;
  }

  const oldRegistration = "registerScenario('elicitation-defaults', runElicitationDefaultsClient);";
  const newRegistration = `registerScenarios(
  ['elicitation-defaults', 'elicitation-sep1034-client-defaults'],
  runElicitationDefaultsClient
);`;

  if (!next.includes(oldRegistration)) {
    throw new Error(`${file}: could not find the known elicitation scenario registration`);
  }

  return next.replace(oldRegistration, newRegistration);
});

rewrite('examples/clients/typescript/elicitation-defaults-test.ts', patchApplyDefaults);
NODE
}

start_host_bridge() {
  local port=$1
  local openshell runner_ip
  HOST_BRIDGE_LOG="${ROOT}/.cache/mcp-conformance/host-bridge.log"
  mkdir -p "$(dirname "${HOST_BRIDGE_LOG}")"

  if ! openshell="$(openshell_bin)"; then
    return 1
  fi
  if ! runner_ip="$(runner_container_ip)"; then
    return 1
  fi

  RUNNER_CONTAINER_IP="${runner_ip}"
  HOST_BRIDGE_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
  OPENSHELL_BIN="${openshell}" \
    OPENSHELL_MCP_CONFORMANCE_RUNNER_IP="${runner_ip}" \
    OPENSHELL_MCP_CONFORMANCE_BRIDGE_TOKEN="${HOST_BRIDGE_TOKEN}" \
    python3 "${ROOT}/e2e/mcp-conformance/host-bridge.py" \
    "${port}" "${ROOT}" "${HOST_BRIDGE_LOG}" &
  HOST_BRIDGE_PID=$!

  local deadline
  deadline=$((SECONDS + ${OPENSHELL_MCP_CONFORMANCE_HOST_BRIDGE_START_TIMEOUT_SECONDS:-10}))
  until python3 - "${port}" <<'PY'
import socket
import sys

try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2):
        pass
except OSError:
    raise SystemExit(1)
PY
  do
    if ! kill -0 "${HOST_BRIDGE_PID}" 2>/dev/null; then
      echo "ERROR: MCP conformance host bridge exited before becoming ready (see ${HOST_BRIDGE_LOG})." >&2
      return 1
    fi
    if [ "${SECONDS}" -ge "${deadline}" ]; then
      echo "ERROR: MCP conformance host bridge did not become ready on 127.0.0.1:${port} (see ${HOST_BRIDGE_LOG})." >&2
      return 1
    fi
    sleep 0.1
  done
}

# Resolve the hostname the runner container uses to reach the host bridge.
# In CI, e2e/with-docker-gateway.sh connects the job container (which hosts the
# bridge) to the e2e Docker network with the host.openshell.internal alias. On
# local Docker Desktop, host.docker.internal reaches the host. On local Linux,
# the runner container is started with --add-host ...:host-gateway.
host_bridge_hostname() {
  if [ -n "${OPENSHELL_MCP_CONFORMANCE_HOST_BRIDGE_HOSTNAME:-}" ]; then
    printf '%s\n' "${OPENSHELL_MCP_CONFORMANCE_HOST_BRIDGE_HOSTNAME}"
    return
  fi

  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    printf '%s\n' "host.openshell.internal"
  elif [ "$(uname -s)" = "Darwin" ]; then
    printf '%s\n' "host.docker.internal"
  else
    printf '%s\n' "host.openshell.internal"
  fi
}

runner_container_ip() {
  local network ip

  network="${OPENSHELL_E2E_DOCKER_NETWORK_NAME:-${OPENSHELL_E2E_NETWORK_NAME:-}}"
  if [ -z "${network}" ]; then
    echo "ERROR: no e2e Docker network resolved for the MCP conformance runner container." >&2
    return 1
  fi
  if [ -z "${RUNNER_CONTAINER}" ]; then
    echo "ERROR: MCP conformance runner container has not been started." >&2
    return 1
  fi

  ip="$(docker inspect \
    --format "{{with index .NetworkSettings.Networks \"${network}\"}}{{.IPAddress}}{{end}}" \
    "${RUNNER_CONTAINER}")"
  if [ -z "${ip}" ]; then
    echo "ERROR: failed to resolve MCP conformance runner IP on Docker network ${network}." >&2
    return 1
  fi
  printf '%s\n' "${ip}"
}

stop_host_bridge() {
  if [ -n "${HOST_BRIDGE_PID}" ] && kill -0 "${HOST_BRIDGE_PID}" 2>/dev/null; then
    kill "${HOST_BRIDGE_PID}" 2>/dev/null || true
    wait "${HOST_BRIDGE_PID}" 2>/dev/null || true
  fi
  HOST_BRIDGE_PID=""
  HOST_BRIDGE_TOKEN=""
  RUNNER_CONTAINER_IP=""
}

build_client_image() {
  local conformance_head dockerfile_hash dockerignore_hash fixture_hash
  local image_ref image_dockerfile image_dockerignore image_fixture_hash
  local -a pull_args=()

  conformance_head="$(git -C "${CONFORMANCE_DIR}" rev-parse HEAD)"
  dockerfile_hash="$(git -C "${ROOT}" hash-object "${ROOT}/e2e/mcp-conformance/Dockerfile.client")"
  dockerignore_hash="$(git -C "${ROOT}" hash-object "${ROOT}/e2e/mcp-conformance/Dockerfile.client.dockerignore")"
  fixture_hash="$(
    git -C "${CONFORMANCE_DIR}" diff -- \
      examples/clients/typescript/everything-client.ts \
      examples/clients/typescript/elicitation-defaults-test.ts |
      git hash-object --stdin
  )"

  image_ref="$(docker_image_label "${CLIENT_IMAGE}" "${CLIENT_IMAGE_REF_LABEL}")"
  image_dockerfile="$(docker_image_label "${CLIENT_IMAGE}" "${CLIENT_IMAGE_DOCKERFILE_LABEL}")"
  image_dockerignore="$(docker_image_label "${CLIENT_IMAGE}" "${CLIENT_IMAGE_DOCKERIGNORE_LABEL}")"
  image_fixture_hash="$(docker_image_label "${CLIENT_IMAGE}" "${CLIENT_IMAGE_FIXTURE_HASH_LABEL}")"
  if [ "${FORCE_REBUILD}" != "1" ] \
    && [ "${image_ref}" = "${conformance_head}" ] \
    && [ "${image_dockerfile}" = "${dockerfile_hash}" ] \
    && [ "${image_dockerignore}" = "${dockerignore_hash}" ] \
    && [ "${image_fixture_hash}" = "${fixture_hash}" ]; then
    echo "Using cached MCP conformance client image ${CLIENT_IMAGE} (${conformance_head})." >&2
    return
  fi

  if [ "${DOCKER_PULL}" = "1" ]; then
    pull_args=(--pull)
  fi

  docker build "${pull_args[@]}" \
    --label "${CLIENT_IMAGE_REF_LABEL}=${conformance_head}" \
    --label "${CLIENT_IMAGE_DOCKERFILE_LABEL}=${dockerfile_hash}" \
    --label "${CLIENT_IMAGE_DOCKERIGNORE_LABEL}=${dockerignore_hash}" \
    --label "${CLIENT_IMAGE_FIXTURE_HASH_LABEL}=${fixture_hash}" \
    -f "${ROOT}/e2e/mcp-conformance/Dockerfile.client" \
    -t "${CLIENT_IMAGE}" \
    "${CONFORMANCE_DIR}"
}

create_client_sandbox() {
  if [ -n "${OPENSHELL_MCP_CONFORMANCE_CLIENT_SANDBOX:-}" ]; then
    echo "Using existing MCP conformance client sandbox ${OPENSHELL_MCP_CONFORMANCE_CLIENT_SANDBOX}." >&2
    return
  fi

  local sandbox_name policy_file openshell
  sandbox_name="openshell-mcp-client-$$"
  policy_file="$(mktemp "${TMPDIR:-/tmp}/openshell-mcp-conformance-base-policy.XXXXXX.yaml")"
  openshell="$(openshell_bin)"

  # The upstream runner binds its per-scenario test server with listen(0), and
  # the port can be outside the OS ephemeral range. Create the reusable sandbox
  # with a harmless placeholder; the client wrapper installs the exact policy
  # for each scenario URL before executing the TypeScript client.
  python3 "${ROOT}/e2e/mcp-conformance/render-policy.py" \
    "http://192.0.2.1:1/" "${policy_file}" \
    "${ROOT}/e2e/mcp-conformance/policy-template.yaml" >/dev/null

  echo "Creating MCP conformance client sandbox ${sandbox_name}..." >&2
  if ! "${openshell}" sandbox create \
    --name "${sandbox_name}" \
    --from "${CLIENT_IMAGE}" \
    --policy "${policy_file}" \
    --no-tty \
    -- true; then
    rm -f "${policy_file}"
    return 1
  fi
  rm -f "${policy_file}"

  export OPENSHELL_MCP_CONFORMANCE_CLIENT_SANDBOX="${sandbox_name}"
  export OPENSHELL_MCP_CONFORMANCE_POLICY_WAIT="${OPENSHELL_MCP_CONFORMANCE_POLICY_WAIT:-1}"
  CLIENT_SANDBOX_MANAGED=1
}

cleanup_client_sandbox() {
  if [ "${CLIENT_SANDBOX_MANAGED}" != "1" ]; then
    return
  fi

  local openshell
  openshell="$(openshell_bin)"
  echo "Deleting MCP conformance client sandbox ${OPENSHELL_MCP_CONFORMANCE_CLIENT_SANDBOX}..." >&2
  "${openshell}" sandbox delete "${OPENSHELL_MCP_CONFORMANCE_CLIENT_SANDBOX}" >/dev/null 2>&1 || true
}

# Start the upstream conformance runner in a plain Docker container on the e2e
# network. The runner runs node (and the bundled MCP test server) off the host
# for isolation, but unlike an OpenShell sandbox it has an ordinary,
# externally-routable network address: its listen(0) test server is reachable
# from the client sandbox, and it can call the host bridge back directly.
create_runner_container() {
  local network
  local -a add_host_args=()

  network="${OPENSHELL_E2E_DOCKER_NETWORK_NAME:-${OPENSHELL_E2E_NETWORK_NAME:-}}"
  if [ -z "${network}" ]; then
    echo "ERROR: no e2e Docker network resolved for the MCP conformance runner container." >&2
    return 1
  fi

  RUNNER_CONTAINER="openshell-mcp-runner-$$"

  # On local Linux the host bridge runs on the host, so map the bridge hostnames
  # to the Docker host gateway. CI (job-container network alias) and Docker
  # Desktop resolve these names without an explicit mapping.
  if [ "${GITHUB_ACTIONS:-}" != "true" ] && [ "$(uname -s)" != "Darwin" ]; then
    add_host_args=(--add-host "host.openshell.internal:host-gateway" --add-host "host.docker.internal:host-gateway")
  fi

  echo "Starting MCP conformance runner container ${RUNNER_CONTAINER} on Docker network ${network}..." >&2
  if ! docker run -d --rm \
    --name "${RUNNER_CONTAINER}" \
    --network "${network}" \
    "${add_host_args[@]}" \
    "${CLIENT_IMAGE}" \
    sleep infinity >/dev/null; then
    RUNNER_CONTAINER=""
    return 1
  fi

  if ! docker cp "${ROOT}/e2e/mcp-conformance/runner-shim.mjs" "${RUNNER_CONTAINER}:/tmp/openshell-mcp-runner-shim.mjs" \
    || ! docker cp "${ROOT}/e2e/mcp-conformance/expected-failures.yml" "${RUNNER_CONTAINER}:/tmp/expected-failures.yml"; then
    return 1
  fi
}

cleanup_runner_container() {
  if [ -n "${RUNNER_CONTAINER}" ]; then
    docker rm -f "${RUNNER_CONTAINER}" >/dev/null 2>&1 || true
  fi
  RUNNER_CONTAINER=""
}

scenario_list_for_args() {
  local scenario_list
  local -a scenario_args=("$@")

  if [ "${#scenario_args[@]}" -gt 0 ]; then
    scenario_list="${scenario_args[*]}"
  elif [ -n "${SCENARIOS}" ]; then
    scenario_list="${SCENARIOS}"
  else
    scenario_list="${DEFAULT_SCENARIOS[*]}"
  fi

  printf '%s\n' "${scenario_list}"
}

run_scenarios_in_runner_container() {
  local bridge_host bridge_port scenario scenario_list
  local -a passed=()
  local -a failed=()

  scenario_list="$(scenario_list_for_args "$@")"
  if [ -z "${scenario_list}" ]; then
    echo "ERROR: no MCP conformance scenarios resolved." >&2
    return 2
  fi

  bridge_port="$(e2e_pick_port)"
  create_client_sandbox || return 1
  create_runner_container || return 1
  start_host_bridge "${bridge_port}" || return 1

  bridge_host="$(host_bridge_hostname)"
  echo "MCP conformance host bridge callback: http://${bridge_host}:${bridge_port}/run" >&2

  for scenario in ${scenario_list}; do
    echo "=== MCP conformance: ${scenario} ==="
    # shellcheck disable=SC2016
    if docker exec \
      --env "MCP_CONFORMANCE_HOST_BRIDGE_URL=http://${bridge_host}:${bridge_port}/run" \
      --env "MCP_CONFORMANCE_HOST_BRIDGE_TOKEN=${HOST_BRIDGE_TOKEN}" \
      --env "MCP_CONFORMANCE_RUNNER_IP=${RUNNER_CONTAINER_IP}" \
      "${RUNNER_CONTAINER}" \
      sh -c 'cd /opt/mcp-conformance && exec node dist/index.js client --command "node /tmp/openshell-mcp-runner-shim.mjs" --scenario "$1" --spec-version "$2" --expected-failures "$3" --timeout "$4"' \
      sh "${scenario}" "${SPEC_VERSION}" "/tmp/expected-failures.yml" "${TIMEOUT_MS}" \
      </dev/null; then
      passed+=("${scenario}")
    else
      failed+=("${scenario}")
    fi
  done

  echo "=== MCP conformance summary ==="
  echo "Passed (${#passed[@]}): ${passed[*]:-<none>}"
  echo "Failed (${#failed[@]}): ${failed[*]:-<none>}"

  if [ "${#failed[@]}" -ne 0 ]; then
    return 1
  fi
}

cleanup_scenario_resources() {
  cleanup_runner_container
  stop_host_bridge
  cleanup_client_sandbox
}

run_scenarios_with_client_sandbox() {
  # Tear down the runner container, host bridge, and client sandbox on any exit,
  # including Ctrl-C / SIGTERM. The cleanups are no-ops if their resource was
  # never created, so an early failure is safe too.
  trap cleanup_scenario_resources EXIT
  trap 'exit 130' INT TERM

  run_scenarios_in_runner_container "$@"
}

run_scenarios_under_gateway() {
  export OPENSHELL_MCP_CONFORMANCE_CLIENT_IMAGE="${CLIENT_IMAGE}"
  export OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE="${OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE:-${CLIENT_IMAGE}}"

  "${ROOT}/e2e/with-docker-gateway.sh" bash "${BASH_SOURCE[0]}" "${RUN_SCENARIOS_COMMAND}" "$@"
}

main() {
  cd "${ROOT}"

  if [ "${1:-}" = "${RUN_SCENARIOS_COMMAND}" ]; then
    shift
    run_scenarios_with_client_sandbox "$@"
    return
  fi

  # git fetches and pins the upstream conformance repo; node patches temporary
  # fixture drift before the image build; docker builds and runs the
  # runner/client containers; python3 runs the host bridge and renders policies.
  # npm and tsx run inside the container image, not on the host.
  require_command git
  require_command node
  require_command docker
  require_command python3

  echo "MCP conformance spec version: ${SPEC_VERSION}" >&2
  checkout_conformance
  patch_conformance_clients
  build_client_image
  run_scenarios_under_gateway "$@"
}

main "$@"
