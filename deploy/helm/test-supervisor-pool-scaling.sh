#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# The shared supervisor always runs as a high-availability pool, which scales
# between one and more replicas without changing anything but the supervisor
# Deployment's replica count: not the gateway configuration (so the gateway
# does not roll), not the supervisor Pod template (so running members are not
# replaced), and not the PodDisruptionBudget or Service. The renders differ
# only in supervisor.replicas.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
chart="${repo_root}/deploy/helm/openshell"
work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

render() {
  local name="$1"
  shift
  helm template scaling "${chart}" \
    --namespace scaling-namespace \
    --set agentSandbox.preflight.enabled=false \
    --set-string 'gatewayConfig.openshell\.drivers\.kubernetes.supervisor_topology=gateway' \
    "$@" >"${work_dir}/${name}.yaml"
}

# Every rendered document except Secrets, whose generated values differ
# between renders, with the supervisor Deployment's replica count removed.
without_replica_count() {
  yq ea -P \
    'select(. != null and .kind != "Secret")
     | (select(.kind == "Deployment" and .metadata.name == "scaling-openshell-supervisor") | .spec) |= del(.replicas)
     | ... comments = ""' \
    "${work_dir}/$1.yaml" >"${work_dir}/$1.normalized.yaml"
}

supervisor_replicas() {
  yq ea -e -r \
    'select(.kind == "Deployment" and .metadata.name == "scaling-openshell-supervisor") | .spec.replicas' \
    "${work_dir}/$1.yaml"
}

fail() {
  echo "supervisor pool scaling: $*" >&2
  exit 1
}

render one --set supervisor.replicas=1
render two --set supervisor.replicas=2
render three --set supervisor.replicas=3

[[ "$(supervisor_replicas one)" == "1" ]] || fail "one-replica pool renders $(supervisor_replicas one) replicas"
[[ "$(supervisor_replicas two)" == "2" ]] || fail "two-replica pool renders $(supervisor_replicas two) replicas"
[[ "$(supervisor_replicas three)" == "3" ]] || fail "three-replica pool renders $(supervisor_replicas three) replicas"

for name in one two three; do
  without_replica_count "${name}"
done

for name in two three; do
  if ! diff -u "${work_dir}/one.normalized.yaml" "${work_dir}/${name}.normalized.yaml"; then
    fail "scaling the pool from 1 to ${name} replicas changed more than the replica count"
  fi
done

# The pool table, with the chart's default recovery deadline, is present at
# every count, and the gateway's config checksum (which rolls the gateway when
# it changes) is the same.
for name in one two three; do
  yq ea -e -r 'select(.kind == "ConfigMap" and (.data | has("gateway.toml"))) | .data."gateway.toml"' \
    "${work_dir}/${name}.yaml" >"${work_dir}/${name}.toml"
  grep -q '^\[openshell\.gateway\.supervisor_pool\]$' "${work_dir}/${name}.toml" \
    || fail "the ${name}-replica pool renders no supervisor_pool table"
  grep -q '^recovery_timeout_secs = 60$' "${work_dir}/${name}.toml" \
    || fail "the ${name}-replica pool renders no recovery deadline"
done

echo "supervisor pool scaling: only the replica count changes across 1, 2, and 3 replicas"

# Enabling the HPA changes only replica ownership and adds the HPA. It must
# not roll the gateway or replace supervisor Pods. Tuning its target and
# bounds must likewise leave every other resource unchanged.
for name in autoscaled tuned; do
  extra=()
  if [[ "${name}" == tuned ]]; then
    extra+=(--set supervisor.autoscaling.minReplicas=3
      --set supervisor.autoscaling.maxReplicas=6
      --set supervisor.autoscaling.targetMemoryAverageValue=768Mi)
  fi
  render "${name}" --set supervisor.autoscaling.enabled=true "${extra[@]}"
  yq ea -e 'select(.kind == "Deployment" and .metadata.name == "scaling-openshell-supervisor") | .spec | has("replicas") == false' \
    "${work_dir}/${name}.yaml" >/dev/null || fail "the HPA does not own supervisor replicas"
  yq ea -P 'select(. != null and .kind != "HorizontalPodAutoscaler")' \
    "${work_dir}/${name}.yaml" >"${work_dir}/${name}.without-hpa.yaml"
  without_replica_count "${name}.without-hpa"
  diff -u "${work_dir}/one.normalized.yaml" "${work_dir}/${name}.without-hpa.normalized.yaml" \
    || fail "supervisor autoscaling changed the gateway or supervisor Pod template"
done
echo "supervisor autoscaling: enabling and tuning the HPA preserves gateway and supervisor Pod templates"
