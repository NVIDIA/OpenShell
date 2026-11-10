#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Prints the diagnostics for a failed run on a k3s guest to stdout; the runner
# saves them. Carried over from the tmachine conformance playbook's diagnostics
# role. No kubeconfig, Secrets, environment dumps, or complete Pod specifications.
set -u
umask 077

collect() {
  printf '\n### %s\n' "$1"
  shift
  # Bound both stalled commands and unusually large log streams.
  timeout 10s "$@" 2>&1 | tail -c 262144
  printf '\ncommand status: %s\n' "${PIPESTATUS[0]}"
}

collect_log() {
  printf '\n### %s\n' "$1"
  shift
  # Retain startup and recent evidence when later scenarios fill the log.
  timeout 10s "$@" 2>&1 | {
    head -c 131072
    printf '\n### Remaining log tail\n'
    tail -c 131072
  }
  printf '\ncommand status: %s\n' "${PIPESTATUS[0]}"
}

# Gateway logs cover the whole run, so a failing test's window is included.
# The runner records when the run started; without that, use a fixed window.
# The tail is larger than for other logs because a gateway logs many lines.
RUN_STARTED_FILE=/var/tmp/openshell-run-started
log_since=--since=30m
if run_started=$(cat "$RUN_STARTED_FILE" 2>/dev/null) &&
  [[ $run_started =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
  log_since=--since-time=$run_started
fi

collect_gateway_log() {
  printf '\n### %s (%s)\n' "$1" "$log_since"
  shift
  timeout 20s "$@" 2>&1 | {
    head -c 65536
    printf '\n### Remaining log tail\n'
    tail -c 524288
  }
  printf '\ncommand status: %s\n' "${PIPESTATUS[0]}"
}

{
  date --utc --iso-8601=seconds
  collect 'K3s service state' systemctl show k3s.service \
    -p ActiveState -p SubState -p Result -p NRestarts -p ExecMainStatus \
    -p ExecMainPID -p ActiveEnterTimestamp -p ExecMainStartTimestamp \
    -p StartLimitIntervalUSec -p StartLimitBurst -p RestartUSec
  collect 'K3s boot journal' journalctl -b --no-pager --lines=500 -u k3s.service
  # kube-proxy may program either iptables backend; dump whichever exist.
  # shellcheck disable=SC2016 # Expanded by the inner shell.
  collect 'Gateway Service routing rules' bash -c '
    for save in iptables-nft-save iptables-legacy-save; do
      command -v "$save" >/dev/null || continue
      echo "# $save"
      "$save" 2>/dev/null | awk "/openshell\/openshell:grpc/ { print }"
    done'
  collect 'K3s version' /usr/local/bin/k3s --version
  collect 'API readiness' /usr/local/bin/k3s kubectl --request-timeout=5s get --raw=/readyz
  collect 'Nodes' /usr/local/bin/k3s kubectl --request-timeout=5s get nodes -o wide
  collect 'Agent Sandbox controller deployment' /usr/local/bin/k3s kubectl --request-timeout=5s -n agent-sandbox-system get deployment agent-sandbox-controller \
    -o 'custom-columns=NAME:.metadata.name,GENERATION:.metadata.generation,STATUS:.status'
  collect 'Agent Sandbox controller Pods' /usr/local/bin/k3s kubectl --request-timeout=5s -n agent-sandbox-system get pods \
    -o 'custom-columns=NAME:.metadata.name,UID:.metadata.uid,PHASE:.status.phase,CONDITIONS:.status.conditions,CONTAINERS:.status.containerStatuses'
  collect 'Agent Sandbox leader leases' /usr/local/bin/k3s kubectl --request-timeout=5s -n agent-sandbox-system get leases \
    -o 'custom-columns=NAME:.metadata.name,HOLDER:.spec.holderIdentity,ACQUIRED:.spec.acquireTime,RENEWED:.spec.renewTime,DURATION:.spec.leaseDurationSeconds,TRANSITIONS:.spec.leaseTransitions'
  collect 'Agent Sandbox controller events' /usr/local/bin/k3s kubectl --request-timeout=5s -n agent-sandbox-system get events --sort-by=.lastTimestamp
  collect 'Sandbox reconciliation status' /usr/local/bin/k3s kubectl --request-timeout=5s -n openshell get sandboxes.agents.x-k8s.io \
    -o 'custom-columns=NAME:.metadata.name,UID:.metadata.uid,CREATED:.metadata.creationTimestamp,GENERATION:.metadata.generation,STATUS:.status'
  mapfile -t controller_pods < <(timeout 10s /usr/local/bin/k3s kubectl --request-timeout=5s -n agent-sandbox-system get pods \
    --selector app=agent-sandbox-controller --output name 2>/dev/null)
  for pod in "${controller_pods[@]}"; do
    collect_log "Agent Sandbox current logs ($pod)" /usr/local/bin/k3s kubectl --request-timeout=5s -n agent-sandbox-system logs "$pod" --since=30m --timestamps
    collect_log "Agent Sandbox previous logs ($pod)" /usr/local/bin/k3s kubectl --request-timeout=5s -n agent-sandbox-system logs "$pod" --previous --since=30m --timestamps
  done
  collect 'Gateway Pod identity and state' /usr/local/bin/k3s kubectl --request-timeout=5s -n openshell get pods \
    -o 'custom-columns=NAME:.metadata.name,UID:.metadata.uid,PHASE:.status.phase,CONDITIONS:.status.conditions,CONTAINERS:.status.containerStatuses'
  collect 'Gateway Services' /usr/local/bin/k3s kubectl --request-timeout=5s -n openshell get services \
    -o 'custom-columns=NAME:.metadata.name,TYPE:.spec.type,CLUSTERIP:.spec.clusterIP,SELECTOR:.spec.selector,PORTS:.spec.ports'
  collect 'Test client gateway registrations' runuser -u tmachine -- openshell gateway list --output json
  collect 'Test client gateway status' runuser -u tmachine -- openshell status --output json
  collect 'Endpoint readiness' /usr/local/bin/k3s kubectl --request-timeout=5s -n openshell get endpointslices \
    -o 'custom-columns=NAME:.metadata.name,PORTS:.ports,ADDRESSES:.endpoints[*].addresses,CONDITIONS:.endpoints[*].conditions'
  collect 'Gateway events' /usr/local/bin/k3s kubectl --request-timeout=5s -n openshell get events --sort-by=.lastTimestamp
  # Gateway Pods are named by a StatefulSet or a Deployment, depending on the installer.
  mapfile -t gateway_pods < <(timeout 10s /usr/local/bin/k3s kubectl --request-timeout=5s -n openshell get pods \
    --selector app.kubernetes.io/name=openshell,app.kubernetes.io/instance=openshell --output name 2>/dev/null)
  for pod in "${gateway_pods[@]}"; do
    collect_gateway_log "Gateway current logs ($pod)" /usr/local/bin/k3s kubectl --request-timeout=5s -n openshell logs "$pod" -c openshell-gateway "$log_since" --timestamps
    collect_gateway_log "Gateway previous logs ($pod)" /usr/local/bin/k3s kubectl --request-timeout=5s -n openshell logs "$pod" -c openshell-gateway --previous "$log_since" --timestamps
  done
  collect 'Memory' free -m
  collect 'Disk' df -h / /var/lib/rancher/k3s
} | sed -E \
  -e 's/(Bearer )[A-Za-z0-9._~+\/-]+/\1[REDACTED]/gI' \
  -e 's/((token|password|secret|authorization)[" ]*[=:][" ]*)[^ ,"]+/\1[REDACTED]/gI'
