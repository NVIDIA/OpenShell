#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# A shared supervisor high-availability pool scales between one and more
# replicas without changing anything but the supervisor Deployment's replica
# count: not the gateway configuration (so the gateway does not roll), not the
# supervisor Pod template (so running members are not replaced), and not the
# PodDisruptionBudget or Service. Switching a single shared supervisor to a
# pool does change them; that switch interrupts running sandboxes.
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
    --set supervisor.recoveryTimeoutSeconds=60 \
    "$@" >"${work_dir}/${name}.yaml"
}

# Every rendered document except Secrets, whose generated values differ
# between renders, with the supervisor Deployment's replica count removed.
without_replica_count() {
  yq ea -P \
    'select(. != null and .kind != "Secret")
     | (select(.kind == "Deployment" and .metadata.name == "scaling-openshell-supervisor") | .spec) |= del(.replicas)' \
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

render one --set supervisor.highAvailability=true --set supervisor.replicas=1
render two --set supervisor.highAvailability=true --set supervisor.replicas=2
render three --set supervisor.highAvailability=true --set supervisor.replicas=3
render legacy --set supervisor.replicas=1

[[ "$(supervisor_replicas one)" == "1" ]] || fail "one-replica pool renders $(supervisor_replicas one) replicas"
[[ "$(supervisor_replicas two)" == "2" ]] || fail "two-replica pool renders $(supervisor_replicas two) replicas"
[[ "$(supervisor_replicas three)" == "3" ]] || fail "three-replica pool renders $(supervisor_replicas three) replicas"

for name in one two three legacy; do
  without_replica_count "${name}"
done

for name in two three; do
  if ! diff -u "${work_dir}/one.normalized.yaml" "${work_dir}/${name}.normalized.yaml"; then
    fail "scaling the pool from 1 to ${name} replicas changed more than the replica count"
  fi
done

# The pool table is present at every count, and the gateway's config checksum
# (which rolls the gateway when it changes) is the same.
for name in one two three; do
  yq ea -e -r 'select(.kind == "ConfigMap" and (.data | has("gateway.toml"))) | .data."gateway.toml"' \
    "${work_dir}/${name}.yaml" | grep -q '^\[openshell\.gateway\.supervisor_pool\]$' \
    || fail "the ${name}-replica pool renders no supervisor_pool table"
done

# Switching from a single shared supervisor to a pool is a different
# deployment, not a scaling step.
if diff -q "${work_dir}/legacy.normalized.yaml" "${work_dir}/one.normalized.yaml" >/dev/null; then
  fail "a one-replica pool renders the same as a single shared supervisor"
fi

echo "supervisor pool scaling: only the replica count changes across 1, 2, and 3 replicas"
