#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Generate the gateway environment file if needed, export the generated
# first-start SSH handshake secret, then exec the gateway. systemd reads
# EnvironmentFile= before ExecStartPre=, so a file generated during service
# startup is not visible to the first ExecStart= process.

set -euo pipefail

if [ "$#" -lt 3 ]; then
    echo "Usage: openshell-gateway-start.sh <env-generator> <env-file> <gateway> [args...]" >&2
    exit 2
fi

ENV_GENERATOR="$1"
ENV_FILE="$2"
shift 2

"${ENV_GENERATOR}" "${ENV_FILE}"

if [ -z "${OPENSHELL_SSH_HANDSHAKE_SECRET:-}" ]; then
    while IFS= read -r line || [ -n "${line}" ]; do
        case "${line}" in
            OPENSHELL_SSH_HANDSHAKE_SECRET=*)
                export OPENSHELL_SSH_HANDSHAKE_SECRET="${line#OPENSHELL_SSH_HANDSHAKE_SECRET=}"
                break
                ;;
        esac
    done < "${ENV_FILE}"
fi

if [ -z "${OPENSHELL_SSH_HANDSHAKE_SECRET:-}" ]; then
    echo "OPENSHELL_SSH_HANDSHAKE_SECRET is not set in ${ENV_FILE}" >&2
    exit 1
fi

exec "$@"
