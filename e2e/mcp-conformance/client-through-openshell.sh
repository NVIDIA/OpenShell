#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Runs the upstream MCP conformance client in an OpenShell-managed sandbox.
#
# The modelcontextprotocol/conformance runner runs in a separate container and
# posts the URL of its MCP test server to a host bridge, which invokes this
# script with that URL. The parent harness creates one reusable conformance
# client sandbox for the whole scenario list before this script is invoked. This
# wrapper verifies the active gateway is reachable, applies the per-scenario
# server policy to that sandbox, and runs the upstream TypeScript
# everything-client inside it so its MCP traffic crosses the sandbox proxy.

set -euo pipefail

usage() {
  echo "usage: $0 <conformance-server-url>" >&2
}

if [ "$#" -ne 1 ]; then
  usage
  exit 2
fi

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

# shellcheck source=e2e/support/gateway-common.sh disable=SC1091
source "${ROOT}/e2e/support/gateway-common.sh"
TARGET_DIR="$(e2e_cargo_target_dir "${ROOT}")"
OPENSHELL_BIN="${OPENSHELL_BIN:-${TARGET_DIR}/debug/openshell}"

require_active_gateway() {
  local status_output

  if ! status_output="$("${OPENSHELL_BIN}" status 2>&1)"; then
    echo "ERROR: no reachable active OpenShell gateway for MCP conformance." >&2
    echo "       Run e2e/mcp-conformance.sh so it starts one shared Docker-backed gateway." >&2
    echo "=== openshell status output ===" >&2
    printf '%s\n' "${status_output}" >&2
    echo "=== end openshell status output ===" >&2
    exit 2
  fi
}

SERVER_URL="$1"
CLIENT_SANDBOX="${OPENSHELL_MCP_CONFORMANCE_CLIENT_SANDBOX:?set OPENSHELL_MCP_CONFORMANCE_CLIENT_SANDBOX to the reusable conformance client sandbox name}"
POLICY_TEMPLATE="${ROOT}/e2e/mcp-conformance/policy-template.yaml"
POLICY_WAIT="${OPENSHELL_MCP_CONFORMANCE_POLICY_WAIT:-0}"
POLICY_WAIT_TIMEOUT="${OPENSHELL_MCP_CONFORMANCE_POLICY_WAIT_TIMEOUT:-60}"
CLIENT_TIMEOUT_SECONDS="${OPENSHELL_MCP_CONFORMANCE_CLIENT_TIMEOUT_SECONDS:-120}"

require_active_gateway

POLICY_FILE="$(mktemp "${TMPDIR:-/tmp}/openshell-mcp-conformance-policy.XXXXXX.yaml")"
trap 'rm -f "${POLICY_FILE}"' EXIT

CLIENT_SERVER_URL="$(python3 "${ROOT}/e2e/mcp-conformance/render-policy.py" "${SERVER_URL}" "${POLICY_FILE}" "${POLICY_TEMPLATE}")"

ENV_ARGS=()
# These environment variables are set by the upstream conformance test runner
# before it invokes the configured client command. Forward them into the
# sandbox because the sandboxed TypeScript client depends on them to select the
# scenario and read scenario-specific context.
for NAME in MCP_CONFORMANCE_SCENARIO MCP_CONFORMANCE_CONTEXT MCP_CONFORMANCE_PROTOCOL_VERSION; do
  if [ -n "${!NAME+x}" ]; then
    ENV_ARGS+=(--env "${NAME}=${!NAME}")
  fi
done

POLICY_SET_COMMAND=(
  "${OPENSHELL_BIN}" policy set "${CLIENT_SANDBOX}"
  --policy "${POLICY_FILE}"
)
if [ "${POLICY_WAIT}" = "1" ]; then
  POLICY_SET_COMMAND+=(--wait --timeout "${POLICY_WAIT_TIMEOUT}")
fi
"${POLICY_SET_COMMAND[@]}"

# shellcheck disable=SC2016
SANDBOX_COMMAND=(
  "${OPENSHELL_BIN}" sandbox exec
  --name "${CLIENT_SANDBOX}"
  --no-tty
  --timeout "${CLIENT_TIMEOUT_SECONDS}"
  "${ENV_ARGS[@]}"
  --
  sh -c 'cd /opt/mcp-conformance && exec ./node_modules/.bin/tsx examples/clients/typescript/everything-client.ts "$1"'
  sh "${CLIENT_SERVER_URL}"
)

"${SANDBOX_COMMAND[@]}" </dev/null
