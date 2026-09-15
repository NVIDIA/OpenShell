#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Assert relationships that span rendered Kubernetes objects and gateway.toml.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
chart="${repo_root}/deploy/helm/openshell"
work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

render() {
  local name="$1"
  shift
  helm template resource-coherence "${chart}" \
    --namespace resource-namespace \
    --set agentSandbox.preflight.enabled=false \
    "$@" >"${work_dir}/${name}.yaml"

  if ! awk 'BEGIN { RS="---" }
    /^\n?# Source:/ && $0 !~ /\napiVersion:/ {
      print "rendered an empty or invalid Kubernetes document:" $0 > "/dev/stderr"
      exit 1
    }' "${work_dir}/${name}.yaml"; then
    echo "${name}: rendered an invalid Kubernetes document" >&2
    exit 1
  fi
}

toml() {
  yq ea -e -r \
    'select(.kind == "ConfigMap" and (.data | has("gateway.toml"))) | .data."gateway.toml"' \
    "$1" >"$2"
}

workload_value() {
  local manifest="$1"
  local expression="$2"
  yq ea -e -r "select(.kind == \"StatefulSet\" or .kind == \"Deployment\") | ${expression}" "${manifest}"
}

render default
default_manifest="${work_dir}/default.yaml"
default_toml="${work_dir}/default.toml"
toml "${default_manifest}" "${default_toml}"
service_name="$(yq ea -e -r 'select(.kind == "Service") | .metadata.name' "${default_manifest}")"
service_port="$(yq ea -e -r 'select(.kind == "Service") | .spec.ports[] | select(.name == "grpc") | .port' "${default_manifest}")"
workload_port="$(workload_value "${default_manifest}" '.spec.template.spec.containers[] | select(.name == "openshell-gateway") | .ports[] | select(.name == "grpc") | .containerPort')"
config_map="$(yq ea -e -r 'select(.kind == "ConfigMap" and (.data | has("gateway.toml"))) | .metadata.name' "${default_manifest}")"
mounted_config_map="$(workload_value "${default_manifest}" '.spec.template.spec.volumes[] | select(.name == "gateway-config") | .configMap.name')"
[[ "${service_port}" == "${workload_port}" && "${config_map}" == "${mounted_config_map}" ]]
grep -F "bind_address = \"0.0.0.0:${service_port}\"" "${default_toml}" >/dev/null
grep -F "grpc_endpoint = \"https://${service_name}.resource-namespace.svc.cluster.local:${service_port}\"" "${default_toml}" >/dev/null
grep -F '[openshell.gateway.tls]' "${default_toml}" >/dev/null
[[ "$(workload_value "${default_manifest}" '.spec.template.spec.volumes[] | select(.name == "tls-cert") | .secret.secretName')" == "openshell-server-tls" ]]
[[ "$(workload_value "${default_manifest}" '.spec.template.spec.volumes[] | select(.name == "tls-client-ca") | .secret.secretName')" == "openshell-server-tls" ]]

render tls-disabled --values "${chart}/ci/values-tls-disabled.yaml"
tls_disabled_manifest="${work_dir}/tls-disabled.yaml"
tls_disabled_toml="${work_dir}/tls-disabled.toml"
toml "${tls_disabled_manifest}" "${tls_disabled_toml}"
grep -F 'disable_tls = true' "${tls_disabled_toml}" >/dev/null
if grep -Fq '[openshell.gateway.tls]' "${tls_disabled_toml}" \
  || workload_value "${tls_disabled_manifest}" '.spec.template.spec.volumes[]?.name' | grep -Eq '^(tls-cert|tls-client-ca)$'; then
  echo "TLS-disabled runtime configuration and workload mounts disagree" >&2
  exit 1
fi

render openshift-route --values "${chart}/ci/values-openshift-route-cert-manager.yaml"
route_manifest="${work_dir}/openshift-route.yaml"
route_toml="${work_dir}/openshift-route.toml"
toml "${route_manifest}" "${route_toml}"
route_service="$(yq ea -e -r 'select(.kind == "Route") | .spec.to.name' "${route_manifest}")"
route_port="$(yq ea -e -r 'select(.kind == "Route") | .spec.port.targetPort' "${route_manifest}")"
[[ "${route_service}" == "$(yq ea -e -r 'select(.kind == "Service") | .metadata.name' "${route_manifest}")" && "${route_port}" == "grpc" ]]
[[ "$(workload_value "${route_manifest}" '.spec.template.spec.volumes[] | select(.name == "tls-external-cert") | .secret.secretName')" == "${route_service}-server-external-tls" ]]
[[ "$(yq ea -e -r 'select(.kind == "Certificate") | .spec.secretName' "${route_manifest}" | grep -Fx "${route_service}-server-external-tls")" == "${route_service}-server-external-tls" ]]
grep -F 'external_cert_path = "/etc/openshell-tls/server-external/tls.crt"' "${route_toml}" >/dev/null
grep -F 'external_key_path = "/etc/openshell-tls/server-external/tls.key"' "${route_toml}" >/dev/null
grep -F 'external_server_names = ["openshell.example.com"]' "${route_toml}" >/dev/null

echo "gateway Service, TLS, PKI, Route, workload, and runtime config are coherent"
