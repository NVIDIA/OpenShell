#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# No kubeconfig, Secrets, environment dumps, or complete Pod specifications.
set -u
umask 077
mkdir -p /var/lib/openshell/diagnostics
output=/var/lib/openshell/diagnostics/k3s.txt

collect() {
  printf '\n### %s\n' "$1"
  shift
  # Bound both stalled commands and unusually large log streams.
  timeout 10s "$@" 2>&1 | tail -c 262144
  printf '\ncommand status: %s\n' "${PIPESTATUS[0]}"
}

{
  date --utc --iso-8601=seconds
  collect 'Service state' systemctl show k3s.service openshell-k3s-port-forward.service \
    -p ActiveState -p SubState -p Result -p NRestarts -p ExecMainStatus \
    -p ExecMainPID -p ActiveEnterTimestamp -p ExecMainStartTimestamp \
    -p StartLimitIntervalUSec -p StartLimitBurst -p RestartUSec
  collect 'Forwarder unit' systemctl cat openshell-k3s-port-forward.service
  collect 'K3s and forwarder boot journals' journalctl -b --no-pager --lines=500 \
    -u k3s.service -u openshell-k3s-port-forward.service
  collect 'Gateway listener' ss -ltnp 'sport = :17670'
  collect 'K3s version' /usr/local/bin/k3s --version
  collect 'API readiness' /usr/local/bin/k3s kubectl --request-timeout=5s get --raw=/readyz
  collect 'Nodes' /usr/local/bin/k3s kubectl --request-timeout=5s get nodes -o wide
  collect 'Gateway Pod identity and state' /usr/local/bin/k3s kubectl --request-timeout=5s -n openshell get pods \
    -o 'custom-columns=NAME:.metadata.name,UID:.metadata.uid,PHASE:.status.phase,CONDITIONS:.status.conditions,CONTAINERS:.status.containerStatuses'
  collect 'Gateway Services' /usr/local/bin/k3s kubectl --request-timeout=5s -n openshell get services \
    -o 'custom-columns=NAME:.metadata.name,SELECTOR:.spec.selector,PORTS:.spec.ports'
  collect 'Endpoint readiness' /usr/local/bin/k3s kubectl --request-timeout=5s -n openshell get endpointslices \
    -o 'custom-columns=NAME:.metadata.name,PORTS:.ports,ADDRESSES:.endpoints[*].addresses,CONDITIONS:.endpoints[*].conditions'
  collect 'Gateway events' /usr/local/bin/k3s kubectl --request-timeout=5s -n openshell get events --sort-by=.lastTimestamp
  collect 'Gateway current logs' /usr/local/bin/k3s kubectl --request-timeout=5s -n openshell logs openshell-0 -c openshell-gateway --tail=300 --timestamps
  collect 'Gateway previous logs' /usr/local/bin/k3s kubectl --request-timeout=5s -n openshell logs openshell-0 -c openshell-gateway --previous --tail=300 --timestamps
  collect 'Memory' free -m
  collect 'Disk' df -h / /var/lib/rancher/k3s
} | sed -E \
  -e 's/(Bearer )[A-Za-z0-9._~+\/-]+/\1[REDACTED]/gI' \
  -e 's/((token|password|secret|authorization)[" ]*[=:][" ]*)[^ ,"]+/\1[REDACTED]/gI' \
  > "$output"
cat "$output"
