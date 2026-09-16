#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the Rust e2e suite against an OpenShell gateway deployed on Kubernetes
# via Helm. Set OPENSHELL_E2E_KUBE_CONTEXT to target an existing cluster;
# otherwise an ephemeral k3d cluster is created and torn down by
# with-kube-gateway.sh. Set OPENSHELL_E2E_KUBE_TEST to scope to a single
# integration test for local debugging.
#
# Features: the default set includes `e2e-host-gateway` so tests that rely on
# the sandbox-side `host.openshell.internal` alias compile and run. The
# wrapper detects the cluster's host-routable IP and wires it into
# `gatewayConfig.openshell.drivers.kubernetes.host_gateway_ip`. Targeting a
# cluster where the test host is unreachable from pods? Set
# OPENSHELL_E2E_KUBERNETES_FEATURES=e2e to drop the alias-dependent tests.
#
# Results: `run_suite` writes a JUnit + HTML report under `results/`. Set
# `OPENSHELL_E2E_REPORT_NAME` to name it per run when invoking this script repeatedly.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_WITH_GATEWAY_COMMAND="__openshell_run_kubernetes_e2e"
# shellcheck source=e2e/support/conformance.sh
source "${ROOT}/e2e/support/conformance.sh"

E2E_FEATURES="${OPENSHELL_E2E_KUBERNETES_FEATURES-e2e,e2e-host-gateway,e2e-kubernetes}"

# Fixed output path of the `e2e-kubernetes` nextest profile (`.config/nextest.toml`).
JUNIT_XML="${ROOT}/results/e2e-kubernetes.xml"

# Render a sibling HTML report from a JUnit XML. Best-effort: failures only warn.
render_html() {
  local xml="${1:-${JUNIT_XML}}"
  local title="${2:-e2e-kubernetes}"
  [ -f "${xml}" ] || return 0
  local html="${xml%.xml}.html"
  if command -v xsltproc >/dev/null 2>&1; then
    xsltproc --stringparam title "${title}" \
      "${ROOT}/scripts/junit-to-html.xsl" "${xml}" >"${html}" \
      && echo "HTML report: ${html}" \
      || echo "WARNING: failed to render HTML report from ${xml}" >&2
  else
    echo "WARNING: xsltproc not found; skipping HTML report (${xml} still written)" >&2
  fi
}

# Docker and Podman build their local gateway and CLI together in the shared
# gateway wrapper. Kubernetes consumes published gateway images, so only its
# local CLI needs to be built when CI has not supplied a prebuilt one.
if [ -z "${OPENSHELL_BIN:-}" ]; then
  cargo build -p openshell-cli
  export OPENSHELL_BIN="${ROOT}/target/debug/openshell"
fi

test_filter=()
if [ -n "${OPENSHELL_E2E_KUBE_TEST:-}" ]; then
  test_filter+=(--test "${OPENSHELL_E2E_KUBE_TEST}")
fi

is_operator_workspace_mode() {
  [[ ",${E2E_FEATURES}," == *",e2e-kubernetes-workspace-operator,"* ]]
}

run_conformance() {
  if is_operator_workspace_mode; then
    echo "note: skipping standalone CLI conformance in Kubernetes operator workspace mode; default workspace is not operator-allowlisted (see #2971)."
    return 0
  fi

  e2e_run_openshell_conformance "Kubernetes"
}

# `OPENSHELL_E2E_REPORT_NAME` (default `e2e-kubernetes`) names the report
# `results/<name>.{xml,html}` and its heading, so repeated runs do not clobber.
run_suite() {
  local name="${OPENSHELL_E2E_REPORT_NAME:-e2e-kubernetes}"
  local report="${ROOT}/results/${name}.xml"
  local status=0
  "${ROOT}/e2e/with-kube-gateway.sh" \
    bash "${BASH_SOURCE[0]}" "${RUN_WITH_GATEWAY_COMMAND}" || status=$?
  if [ "${report}" != "${JUNIT_XML}" ]; then
    mv -f "${JUNIT_XML}" "${report}" 2>/dev/null || true
  fi
  render_html "${report}" "${name}"
  return "${status}"
}

run_e2e() {
  run_conformance
  if [ -z "${E2E_FEATURES}" ]; then
    return 0
  fi

  # Pin `--target-dir` so the profile `junit.path` resolves regardless of `CARGO_TARGET_DIR`.
  cargo nextest run --profile e2e-kubernetes \
    --config-file "${ROOT}/.config/nextest.toml" \
    --target-dir "${ROOT}/e2e/rust/target" \
    --manifest-path "${ROOT}/e2e/rust/Cargo.toml" \
    --features "${E2E_FEATURES}" \
    ${test_filter[@]+"${test_filter[@]}"}
}

if [ "${1:-}" = "${RUN_WITH_GATEWAY_COMMAND}" ]; then
  run_e2e
  exit 0
fi

# Credential-driver mode: run once per storage backend, each with its own report.
if [ "${OPENSHELL_E2E_CREDENTIAL_DRIVERS:-0}" = "1" ] \
   && [ -z "${OPENSHELL_E2E_CREDENTIAL_DRIVER:-}" ]; then
  OPENSHELL_E2E_CREDENTIAL_DRIVER=kubernetes-secrets \
    OPENSHELL_E2E_REPORT_NAME=e2e-kubernetes-secrets run_suite
  OPENSHELL_E2E_CREDENTIAL_DRIVER=vault \
    OPENSHELL_E2E_REPORT_NAME=e2e-kubernetes-vault run_suite
else
  run_suite
fi
