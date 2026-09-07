#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

require_cmd podman
require_cmd curl

if [[ -z "$SPIRE_STATE_DIR" ]]; then
    SPIRE_STATE_DIR="$(mktemp -d)"
fi

reset_env_file
ensure_network

server_dir="${SPIRE_STATE_DIR}/server"
mount_dir="${SPIRE_STATE_DIR}/mounts"
server_conf_mount="${mount_dir}/server.conf"
oidc_conf_mount="${mount_dir}/oidc-discovery-provider.conf"
server_socket_host_path="${server_dir}/private/api.sock"

mkdir -p "${server_dir}/data" "${server_dir}/private" "$mount_dir"
chmod 0777 "$SPIRE_STATE_DIR" "$server_dir" "${server_dir}/data" "${server_dir}/private"
copy_config "${SPIRE_SCRIPT_DIR}/server.conf" "$server_conf_mount"
copy_config "${SPIRE_SCRIPT_DIR}/oidc-discovery-provider.conf" "$oidc_conf_mount"

if [[ "$CLEANUP_EXISTING" == "1" ]]; then
    cleanup_container "$SPIRE_OIDC_CONTAINER"
    cleanup_container "$SPIRE_SERVER_CONTAINER"
fi

printf "Starting SPIRE server container: %s\n" "$SPIRE_SERVER_CONTAINER" >&2
run podman run -d \
    --name "$SPIRE_SERVER_CONTAINER" \
    --network "$PODMAN_NETWORK" \
    --network-alias spire-server \
    -v "${server_conf_mount}:/run/spire/config/server.conf:ro,z" \
    -v "${server_dir}:/run/spire/server:z" \
    "$SPIRE_SERVER_IMAGE" \
    -config /run/spire/config/server.conf

if ! wait_for_socket "$server_socket_host_path" "SPIRE server API socket"; then
    podman logs "$SPIRE_SERVER_CONTAINER" >&2 || true
    exit 1
fi

printf "Starting SPIRE OIDC discovery provider container: %s\n" "$SPIRE_OIDC_CONTAINER" >&2
run podman run -d \
    --name "$SPIRE_OIDC_CONTAINER" \
    --network "$PODMAN_NETWORK" \
    --network-alias spire-oidc \
    -p "127.0.0.1:${OIDC_PORT}:8080" \
    -v "${oidc_conf_mount}:/run/spire/config/oidc-discovery-provider.conf:ro,z" \
    -v "${server_dir}/private:/run/spire/server/private:z" \
    "$SPIRE_OIDC_IMAGE" \
    -config /run/spire/config/oidc-discovery-provider.conf

if ! wait_for_http "http://127.0.0.1:${OIDC_PORT}/keys" "SPIRE OIDC discovery provider"; then
    podman logs "$SPIRE_OIDC_CONTAINER" >&2 || true
    exit 1
fi

write_env_line SPIRE_STATE_DIR "$SPIRE_STATE_DIR"
write_env_line SPIRE_SERVER_DIR "$server_dir"
write_env_line SPIRE_SERVER_SOCKET_HOST_PATH "$server_socket_host_path"
write_env_line SPIRE_OIDC_KEYS_URL "http://127.0.0.1:${OIDC_PORT}/keys"

printf "SPIRE server container: %s\n" "$SPIRE_SERVER_CONTAINER"
printf "SPIRE server API socket: %s\n" "$server_socket_host_path"
printf "SPIRE OIDC discovery provider container: %s\n" "$SPIRE_OIDC_CONTAINER"
printf "SPIRE OIDC JWKS URL: http://127.0.0.1:%s/keys\n" "$OIDC_PORT"
if [[ -n "$SPIRE_ENV_FILE" ]]; then
    printf "Wrote environment file: %s\n" "$SPIRE_ENV_FILE"
fi
