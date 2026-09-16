#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Render the chart exactly as an operator would, then validate gateway.toml
# with the gateway binary. Helm unit tests cover template-level assertions;
# this test makes the Rust loader the compatibility authority.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
chart="${repo_root}/deploy/helm/openshell"
fixture="${chart}/tests/fixtures/parser-validation-values.yaml"
work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

cargo build --quiet --package openshell-gateway
gateway_bin="${repo_root}/target/debug/openshell-gateway"

render() {
  local output="$1"
  shift
  helm template parser-validation "${chart}" \
    --namespace parser-namespace \
    --set agentSandbox.preflight.enabled=false \
    "$@" >"${output}"
}

extract_toml() {
  local manifest="$1"
  local toml="$2"
  yq ea -e -r \
    'select(.kind == "ConfigMap" and (.data | has("gateway.toml"))) | .data."gateway.toml"' \
    "${manifest}" >"${toml}"
}

preflight() {
  local toml="$1"
  "${gateway_bin}" config preflight --path "${toml}"
}

render "${work_dir}/default.yaml"
extract_toml "${work_dir}/default.yaml" "${work_dir}/default.toml"
preflight "${work_dir}/default.toml"

# Exercise all serializer shapes through a raw driver table and prove that
# string-only tpl expansion, TOML escaping, and null omission survive parsing.
render "${work_dir}/shapes.yaml" --values "${fixture}"
extract_toml "${work_dir}/shapes.yaml" "${work_dir}/shapes.toml"
preflight "${work_dir}/shapes.toml"
grep -F 'name = "parser-namespace/parser-validation' "${work_dir}/shapes.toml" >/dev/null
grep -F 'empty_value = ""' "${work_dir}/shapes.toml" >/dev/null
if grep -Fq 'omitted_value' "${work_dir}/shapes.toml"; then
  echo "null gatewayConfig values must be omitted from gateway.toml" >&2
  exit 1
fi

# The loader gives absent and empty credential-driver selection deliberately
# different meanings: absent retains encrypted storage, while an empty list is
# an invalid and ambiguous external-driver selection.
render "${work_dir}/credential-drivers-absent.yaml" \
  --set-json 'gatewayConfig.openshell\.gateway.credential_drivers=null'
extract_toml "${work_dir}/credential-drivers-absent.yaml" "${work_dir}/credential-drivers-absent.toml"
preflight "${work_dir}/credential-drivers-absent.toml"
if grep -Fq 'credential_drivers' "${work_dir}/credential-drivers-absent.toml"; then
  echo "null credential_drivers must be absent from gateway.toml" >&2
  exit 1
fi
render "${work_dir}/credential-drivers-empty.yaml" \
  --set-json 'gatewayConfig.openshell\.gateway.credential_drivers=[]'
extract_toml "${work_dir}/credential-drivers-empty.yaml" "${work_dir}/credential-drivers-empty.toml"
if preflight "${work_dir}/credential-drivers-empty.toml" >"${work_dir}/credential-drivers-empty.err" 2>&1; then
  echo "the gateway loader accepted empty credential_drivers" >&2
  exit 1
fi

# Unknown non-secret values are intentionally serializable by Helm, but must
# fail at the Rust schema boundary rather than being silently ignored.
render "${work_dir}/unknown.yaml" \
  --set-string 'gatewayConfig.openshell\.gateway.unknown_non_secret=accepted-by-helm'
extract_toml "${work_dir}/unknown.yaml" "${work_dir}/unknown.toml"
if preflight "${work_dir}/unknown.toml" >"${work_dir}/unknown.err" 2>&1; then
  echo "the gateway loader accepted an unknown non-secret field" >&2
  exit 1
fi

# Secrets remain outside the ConfigMap even when their Secret reference is
# rendered into the workload environment.
render "${work_dir}/secret-boundary.yaml" --set server.externalDbSecret=parser-database
extract_toml "${work_dir}/secret-boundary.yaml" "${work_dir}/secret-boundary.toml"
if grep -Eqi 'parser-database|postgresql:|password' "${work_dir}/secret-boundary.toml"; then
  echo "gateway.toml contains Secret-backed database material" >&2
  exit 1
fi

# A ConfigMap-only mutation must change the StatefulSet checksum and trigger a
# rollout. Check this against full Helm output, not just a template fragment.
default_checksum="$(yq ea -e -r 'select(.kind == "StatefulSet") | .spec.template.metadata.annotations."checksum/gateway-config"' "${work_dir}/default.yaml")"
render "${work_dir}/checksum.yaml" \
  --set-string 'gatewayConfig.openshell\.gateway.log_level=debug'
changed_checksum="$(yq ea -e -r 'select(.kind == "StatefulSet") | .spec.template.metadata.annotations."checksum/gateway-config"' "${work_dir}/checksum.yaml")"
if [[ -z "${default_checksum}" || "${default_checksum}" == "${changed_checksum}" ]]; then
  echo "gateway ConfigMap changes must update the StatefulSet checksum" >&2
  exit 1
fi

# All maintained CI/dev overlays must render a loader-valid configuration.
for values in "${chart}"/ci/values-*.yaml; do
  name="$(basename "${values}" .yaml)"
  render "${work_dir}/${name}.yaml" --values "${values}"
  extract_toml "${work_dir}/${name}.yaml" "${work_dir}/${name}.toml"
  preflight "${work_dir}/${name}.toml"
done

echo "rendered gateway TOML passed Rust loader validation"
