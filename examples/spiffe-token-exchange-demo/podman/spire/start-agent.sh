#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

require_cmd podman
require_cmd awk
require_cmd sed

if [[ -z "$SPIRE_STATE_DIR" ]]; then
    SPIRE_STATE_DIR="$(mktemp -d)"
fi

if ! PODMAN_SOCKET="$(detect_podman_socket)"; then
    printf "could not find a Podman API socket; set PODMAN_SOCKET\n" >&2
    exit 1
fi

reset_env_file
ensure_network

agent_dir="${SPIRE_STATE_DIR}/agent"
mount_dir="${SPIRE_STATE_DIR}/mounts"
agent_conf_mount="${mount_dir}/agent.conf"
SPIRE_AGENT_SOCKET_HOST_PATH="${SPIRE_AGENT_SOCKET_HOST_PATH:-${agent_dir}/sockets/agent.sock}"

mkdir -p "${agent_dir}/data" "${agent_dir}/sockets" "$mount_dir"
chmod 0777 "$SPIRE_STATE_DIR" "$agent_dir" "${agent_dir}/data" "${agent_dir}/sockets"
copy_config "${SPIRE_SCRIPT_DIR}/agent.conf" "$agent_conf_mount"

if [[ "$CLEANUP_EXISTING" == "1" ]]; then
    cleanup_container "$SPIRE_AGENT_CONTAINER"
fi

join_token="$(
    podman exec "$SPIRE_SERVER_CONTAINER" "$SPIRE_SERVER_BIN" token generate \
        -socketPath /run/spire/server/private/api.sock \
        -spiffeID "$SPIRE_AGENT_PARENT_ID" |
        awk '/Token:/ { print $2; exit }'
)"
if [[ -z "$join_token" ]]; then
    printf "failed to generate SPIRE agent join token\n" >&2
    exit 1
fi

run podman run -d \
    --name "$SPIRE_AGENT_CONTAINER" \
    --network "$PODMAN_NETWORK" \
    --pid=host \
    --security-opt label=disable \
    -v "${agent_conf_mount}:/run/spire/config/agent.conf:ro,z" \
    -v "${agent_dir}:/run/spire/agent:z" \
    -v "$(podman_socket_volume "$PODMAN_SOCKET" /run/podman/podman.sock)" \
    "$SPIRE_AGENT_IMAGE" \
    -config /run/spire/config/agent.conf -joinToken "$join_token"

if ! wait_for_socket "$SPIRE_AGENT_SOCKET_HOST_PATH" "SPIRE agent Workload API socket"; then
    podman logs "$SPIRE_AGENT_CONTAINER" >&2 || true
    exit 1
fi

write_env_line SPIRE_STATE_DIR "$SPIRE_STATE_DIR"
write_env_line SPIRE_AGENT_DIR "$agent_dir"
write_env_line SPIRE_AGENT_SOCKET_HOST_PATH "$SPIRE_AGENT_SOCKET_HOST_PATH"
write_env_line PODMAN_SOCKET "$PODMAN_SOCKET"

printf "SPIRE agent container: %s\n" "$SPIRE_AGENT_CONTAINER"
printf "SPIRE agent parent ID: %s\n" "$SPIRE_AGENT_PARENT_ID"
printf "SPIRE agent Workload API socket: %s\n" "$SPIRE_AGENT_SOCKET_HOST_PATH"
if [[ -n "$SPIRE_ENV_FILE" ]]; then
    printf "Wrote environment file: %s\n" "$SPIRE_ENV_FILE"
fi
