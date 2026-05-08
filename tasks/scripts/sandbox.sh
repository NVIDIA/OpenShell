#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Create or reconnect to the persistent "dev" sandbox on the active gateway.
#
# Start a gateway first with `mise run gateway:docker`, a package-managed
# openshell-gateway service, or a registered remote gateway.
#
# Provisions an "anthropic" provider from $ANTHROPIC_API_KEY when available.

set -euo pipefail

SANDBOX_NAME="dev"
read -r -a CMD <<< "${usage_command:-claude}"

# -------------------------------------------------------------------
# 1. Ensure a gateway is reachable
# -------------------------------------------------------------------
if ! openshell status >/dev/null 2>&1; then
  echo "No reachable OpenShell gateway." >&2
  echo "Start one in another shell with: mise run gateway:docker" >&2
  echo "Or register/select an existing gateway with: openshell gateway add <endpoint>" >&2
  exit 2
fi

# -------------------------------------------------------------------
# 2. Decide whether to create the sandbox
# -------------------------------------------------------------------
need_create=1

if openshell sandbox get "${SANDBOX_NAME}" >/dev/null 2>&1; then
  need_create=0
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
