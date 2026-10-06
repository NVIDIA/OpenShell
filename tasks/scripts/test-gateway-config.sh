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
printf '%s\n' '#!/usr/bin/env bash' 'config=""' 'while [ "$#" -gt 0 ]; do' '  if [ "$1" = "--config" ]; then config="$2"; shift 2; else shift; fi' 'done' 'if [ -n "${config}" ]; then cp "${config}" "${CAPTURED_CONFIG}"; fi' > "${WORK}/bin/gateway"
chmod +x "${WORK}/bin/gateway"

CAPTURED_CONFIG="${WORK}/generated.toml"
CAPTURED_CONFIG="${WORK}/generated.toml" PATH="${WORK}/bin:${PATH}" KUBERNETES_SERVICE_HOST=fixture RYNO_GATEWAY_BIN="${WORK}/bin/gateway" RYNO_GATEWAY_STATE_DIR="${WORK}/state" RYNO_SANDBOX_IMAGE_PULL_POLICY=IfNotPresent RYNO_GRPC_ENDPOINT=https://callback.example.test:9443 bash "${ROOT}/tasks/scripts/gateway.sh"

printf '%s\n' 'import sys, tomllib' 'from pathlib import Path' 'config = tomllib.loads(Path(sys.argv[1]).read_text())' 'gateway = config["ryno"]["gateway"]' 'driver = config["ryno"]["drivers"]["kubernetes"]' 'assert config["ryno"]["version"] == 2' 'assert gateway["compute_driver"] == "kubernetes"' 'assert "compute_drivers" not in gateway' 'assert driver["image_pull_policy"] == "if_not_present"' 'assert driver["grpc_endpoint"] == "https://callback.example.test:9443"' > "${WORK}/check_generated.py"
"${UV}" run --no-project python "${WORK}/check_generated.py" "${CAPTURED_CONFIG}"

# Keep the Podman E2E generator on the current gateway schema and preserve the
# in-tree versus external-driver ownership boundary without starting Podman.
# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"
# shellcheck source=e2e/support/podman-gateway-config.sh
source "${ROOT}/e2e/support/podman-gateway-config.sh"

mkdir -p "${WORK}/pki/client" "${WORK}/jwt"
e2e_write_podman_gateway_config \
  "${WORK}/podman.toml" "${ROOT}" "${WORK}/pki" "${WORK}/jwt" \
  test-gateway 0 "${WORK}/driver.sock" test-network 18181 \
  workload:test 15 supervisor:test sandbox:test "${WORK}/spiffe.sock" \
  "${WORK}/podman.sock" 0 ""
e2e_write_podman_gateway_config \
  "${WORK}/podman-external.toml" "${ROOT}" "${WORK}/pki" "${WORK}/jwt" \
  test-gateway 1 "${WORK}/driver.sock" test-network 18181 \
  workload:test 15 supervisor:test sandbox:test "${WORK}/spiffe.sock" \
  "${WORK}/podman.sock" 0 ""

printf '%s\n' \
  'import sys, tomllib' \
  'from pathlib import Path' \
  'internal = tomllib.loads(Path(sys.argv[1]).read_text())' \
  'external = tomllib.loads(Path(sys.argv[2]).read_text())' \
  'assert internal["ryno"]["version"] == 2' \
  'gateway = internal["ryno"]["gateway"]' \
  'driver = internal["ryno"]["drivers"]["podman"]' \
  'assert gateway["compute_driver"] == "podman"' \
  'assert gateway["guest_tls_ca"].endswith("/pki/ca.crt")' \
  'assert driver["default_image"] == "workload:test"' \
  'assert driver["image_pull_policy"] == "if_not_present"' \
  'assert driver["supervisor_image"] == "supervisor:test"' \
  'assert driver["sandbox_runtime_image"] == "sandbox:test"' \
  'assert driver["provider_spiffe_workload_api_socket"].endswith("/spiffe.sock")' \
  'assert driver["socket_path"].endswith("/podman.sock")' \
  'assert driver["resource_admission"] == {"enabled": False}' \
  'external_driver = external["ryno"]["drivers"]["podman"]' \
  'assert external["ryno"]["gateway"]["guest_tls_ca"].endswith("/pki/ca.crt")' \
  'assert external_driver == {"socket_path": sys.argv[3]}' \
  >"${WORK}/check_podman_generated.py"
"${UV}" run --no-project python "${WORK}/check_podman_generated.py" \
  "${WORK}/podman.toml" "${WORK}/podman-external.toml" "${WORK}/driver.sock"
echo "gateway generated-TOML tests passed"
