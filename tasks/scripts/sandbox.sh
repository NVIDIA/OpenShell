#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Create or reconnect to the persistent "dev" sandbox.
#
# - Ensures the cluster is running (bootstraps if needed).
# - Redeploys if local source has changed since last deploy.
# - Recreates the sandbox if the cluster was redeployed since the sandbox
#   was last created.
# - Provisions an "anthropic" provider from $ANTHROPIC_API_KEY when available.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/container-engine.sh"

SANDBOX_NAME="dev"
CLUSTER_NAME=${CLUSTER_NAME:-$(basename "$PWD")}
CONTAINER_NAME="openshell-cluster-${CLUSTER_NAME}"
STATE_DIR=${SANDBOX_STATE_DIR:-.cache}
SANDBOX_STATE_FILE=${STATE_DIR}/sandbox-dev.state
DEPLOY_STATE_FILE=${DEPLOY_FAST_STATE_FILE:-${STATE_DIR}/cluster-deploy-fast.state}
CMD=(${usage_command:-claude})

# -------------------------------------------------------------------
# 1. Ensure the cluster is running; redeploy if dirty
# -------------------------------------------------------------------
if ! ce ps -q --filter "name=${CONTAINER_NAME}" | grep -q .; then
  echo "No running cluster found. Bootstrapping..."
  mise run cluster
else
  # Run incremental deploy — it no-ops when nothing has changed.
  mise run cluster
fi

# Capture the current deploy fingerprint so we can tell later whether the
# sandbox predates the most recent deploy.
deploy_fingerprint=""
if [[ -f "${DEPLOY_STATE_FILE}" ]]; then
  deploy_fingerprint=$(shasum -a 256 "${DEPLOY_STATE_FILE}" | cut -d ' ' -f 1)
fi

# -------------------------------------------------------------------
# 2. Decide whether to (re)create the sandbox
# -------------------------------------------------------------------
need_create=1

if openshell sandbox get "${SANDBOX_NAME}" >/dev/null 2>&1; then
  # Sandbox exists — only recreate if the cluster has been redeployed.
  # The command passed via `-- <cmd>` only affects the SSH exec session,
  # not the sandbox pod itself (which always runs `sleep infinity`), so
  # a command change never requires recreation.
  previous_deploy_fingerprint=""
  if [[ -f "${SANDBOX_STATE_FILE}" ]]; then
    while IFS='=' read -r key value; do
      case "${key}" in
        deploy) previous_deploy_fingerprint="${value}" ;;
      esac
    done < "${SANDBOX_STATE_FILE}"
  fi

  if [[ -n "${deploy_fingerprint}" && "${deploy_fingerprint}" == "${previous_deploy_fingerprint}" ]]; then
    need_create=0
  else
    echo "Cluster has been redeployed since sandbox '${SANDBOX_NAME}' was created. Recreating..."
    openshell sandbox delete "${SANDBOX_NAME}" || true
  fi
fi

# -------------------------------------------------------------------
# 3. Ensure the anthropic provider exists when the key is available
# -------------------------------------------------------------------
ensure_anthropic_provider() {
  if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    return
  fi

  if openshell provider get anthropic >/dev/null 2>&1; then
    # Provider already registered — nothing to do.
    return
  fi

  echo "Registering anthropic provider..."
  openshell provider create \
    --name anthropic \
    --type claude \
    --credential "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}"
}

ensure_anthropic_provider

# -------------------------------------------------------------------
# 4. Create or connect to the sandbox
# -------------------------------------------------------------------
PROVIDER_ARGS=()
if openshell provider get anthropic >/dev/null 2>&1; then
  PROVIDER_ARGS+=(--provider anthropic)
fi

if [[ "${need_create}" == "1" ]]; then
  echo "Creating sandbox '${SANDBOX_NAME}'..."
  openshell sandbox create --name "${SANDBOX_NAME}" "${PROVIDER_ARGS[@]}" --tty -- "${CMD[@]}"
else
  echo "Connecting to existing sandbox '${SANDBOX_NAME}'..."
  openshell sandbox connect "${SANDBOX_NAME}"
fi

# Record state so we know this sandbox matches the current deploy.
mkdir -p "$(dirname "${SANDBOX_STATE_FILE}")"
cat > "${SANDBOX_STATE_FILE}" <<EOF
deploy=${deploy_fingerprint}
EOF
