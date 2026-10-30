#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Waits until the Agent Sandbox controller reconciles Sandboxes on a k3s guest.
# Deployment readiness does not establish that the controller is the leader or
# reconciling, and a booted guest restarts it, so the first test would
# otherwise race it. A Sandbox with a scheduling-gated Pod proves the
# controller reconciles without running the Pod or pulling its image.
# The same check as tests/tmachine/ansible/playbooks/k3s-controller-ready.yaml.
set -u
k3s=/usr/local/bin/k3s
gate=openshell.ai/conformance-startup
name="conformance-startup-$RANDOM$RANDOM"
retries=60
delay=5

cleanup() {
  timeout 30s "$k3s" kubectl --request-timeout=5s --namespace=openshell \
    delete sandboxes.agents.x-k8s.io "$name" --ignore-not-found=true \
    --cascade=foreground --wait=true --timeout=20s >/dev/null 2>&1
}
trap cleanup EXIT

uid=
for _ in $(seq "$retries"); do
  uid=$(timeout 15s "$k3s" kubectl --request-timeout=10s apply --filename=- \
    --output=jsonpath='{.metadata.uid}' <<EOF
apiVersion: agents.x-k8s.io/v1beta1
kind: Sandbox
metadata:
  name: "$name"
  namespace: openshell
spec:
  podTemplate:
    spec:
      automountServiceAccountToken: false
      schedulingGates:
        - name: $gate
      containers:
        - name: probe
          image: registry.k8s.io/pause:3.9
EOF
  ) && [ -n "$uid" ] && break
  uid=
  sleep "$delay"
done
if [ -z "$uid" ]; then
  echo "could not create the controller probe Sandbox $name" >&2
  exit 1
fi

# The Sandbox (by uid) controls the Pod the controller creates, and the gate
# keeps it unscheduled.
want="$uid|$gate|"
got=
for _ in $(seq "$retries"); do
  got=$(timeout 10s "$k3s" kubectl --request-timeout=5s --namespace=openshell \
    get pod "$name" --output=jsonpath='{.metadata.ownerReferences[?(@.controller==true)].uid}|{.spec.schedulingGates[*].name}|{.spec.nodeName}' 2>/dev/null)
  if [ "$got" = "$want" ]; then
    exit 0
  fi
  sleep "$delay"
done
echo "the Agent Sandbox controller did not reconcile the probe Sandbox $name; last observation: ${got:-none}" >&2
exit 1
