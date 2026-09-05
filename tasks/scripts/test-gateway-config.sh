#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
UV="$(mise which uv)"
trap 'rm -rf "${WORK}"' EXIT

# shellcheck source=tasks/scripts/gateway-toml.sh
source "${ROOT}/tasks/scripts/gateway-toml.sh"

raw=$'quote" slash\\ newline\ncarriage\rtab\t'
printf 'value = "' > "${WORK}/escaped.toml"
toml_escape "${raw}" >> "${WORK}/escaped.toml"
printf '"\n' >> "${WORK}/escaped.toml"

printf '%s\n' 'import sys, tomllib' 'from pathlib import Path' 'assert tomllib.loads(Path(sys.argv[1]).read_text())["value"] == sys.argv[2]' > "${WORK}/check_escape.py"
"${UV}" run --no-project python "${WORK}/check_escape.py" "${WORK}/escaped.toml" "${raw}"

mkdir -p "${WORK}/bin"
ln -s /usr/bin/true "${WORK}/bin/mise"
ln -s /usr/bin/false "${WORK}/bin/lsof"
ln -s /bin/bash "${WORK}/bin/gateway"

printf '%s\n' 'exec() {' '  config=""' '  while [ "$#" -gt 0 ]; do' '    if [ "$1" = "--config" ]; then config="$2"; shift 2; else shift; fi' '  done' '  cp "${config}" "${CAPTURED_CONFIG}"' '  builtin exit 0' '}' > "${WORK}/fake-gateway-env"

CAPTURED_CONFIG="${WORK}/generated.toml"
BASH_ENV="${WORK}/fake-gateway-env" CAPTURED_CONFIG="${CAPTURED_CONFIG}" PATH="${WORK}/bin:${PATH}" KUBERNETES_SERVICE_HOST=fixture OPENSHELL_GATEWAY_BIN=/bin/true OPENSHELL_GATEWAY_STATE_DIR="${WORK}/state" OPENSHELL_SANDBOX_IMAGE_PULL_POLICY=IfNotPresent OPENSHELL_GRPC_ENDPOINT=https://callback.example.test:9443 bash "${ROOT}/tasks/scripts/gateway.sh"

printf '%s\n' 'import sys, tomllib' 'from pathlib import Path' 'config = tomllib.loads(Path(sys.argv[1]).read_text())' 'gateway = config["openshell"]["gateway"]' 'driver = config["openshell"]["drivers"]["kubernetes"]' 'assert config["openshell"]["version"] == 2' 'assert gateway["compute_driver"] == "kubernetes"' 'assert "compute_drivers" not in gateway' 'assert driver["image_pull_policy"] == "if_not_present"' 'assert driver["grpc_endpoint"] == "https://callback.example.test:9443"' > "${WORK}/check_generated.py"
"${UV}" run --no-project python "${WORK}/check_generated.py" "${CAPTURED_CONFIG}"
echo "gateway generated-TOML tests passed"
