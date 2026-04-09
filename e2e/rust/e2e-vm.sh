#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the Rust e2e smoke test against an openshell-vm gateway.
#
# Usage:
#   mise run e2e:vm                                          # start new named VM on random port
#   mise run e2e:vm -- --vm-port=30051                       # reuse existing VM on port 30051
#   mise run e2e:vm -- --vm-port=30051 --vm-name=my-vm       # reuse existing named VM and run exec check
#
# Options:
#   --vm-port=PORT  Skip VM startup and test against this port.
#   --vm-name=NAME  VM instance name. Auto-generated for fresh VMs.
#
# When --vm-port is omitted:
#   1. Picks a random free host port
#   2. Starts the VM with --name <auto> --port <random>:30051
#   3. Waits for the VM to fully bootstrap (mTLS certs + gRPC health)
#   4. Verifies `openshell-vm exec` works
#   5. Runs the Rust smoke test
#   6. Tears down the VM
#
# When --vm-port is given the script assumes the VM is already running
# on that port and runs the smoke test. The VM exec check runs only when
# --vm-name is provided (so the script can target the correct instance).
#
# Prerequisites (when starting a new VM): `mise run vm:build` must already
# be done (the e2e:vm mise task handles this via depends).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="${ROOT}/target/debug/openshell-vm.runtime"
GATEWAY_BIN="${ROOT}/target/debug/openshell-vm"
VM_GATEWAY_IMAGE="${IMAGE_REPO_BASE:-openshell}/gateway:${IMAGE_TAG:-dev}"
VM_GATEWAY_TAR_REL="var/lib/rancher/k3s/agent/images/openshell-server.tar.zst"
GUEST_PORT=30051
TIMEOUT=180

named_vm_rootfs() {
  local vm_version

  vm_version=$("${GATEWAY_BIN}" --version | awk '{print $2}')
  printf '%s\n' "${XDG_DATA_HOME:-${HOME}/.local/share}/openshell/openshell-vm/${vm_version}/instances/${VM_NAME}/rootfs"
}

vm_exec() {
  local rootfs_args=()
  if [ -n "${VM_ROOTFS_DIR:-}" ]; then
    rootfs_args=(--rootfs "${VM_ROOTFS_DIR}")
  fi
  "${GATEWAY_BIN}" "${rootfs_args[@]}" --name "${VM_NAME}" exec -- "$@"
}

prepare_named_vm_rootfs() {
  if [ -z "${VM_NAME}" ]; then
    return 0
  fi

  echo "Preparing named VM rootfs '${VM_NAME}'..."
  VM_ROOTFS_DIR="$("${ROOT}/tasks/scripts/vm/ensure-vm-rootfs.sh" --name "${VM_NAME}" \
    | tail -n 1 | sed 's/^using openshell-vm rootfs at //')"
  "${ROOT}/tasks/scripts/vm/sync-vm-rootfs.sh" --name "${VM_NAME}"
}

refresh_vm_gateway() {
  if [ -z "${VM_NAME}" ]; then
    return 0
  fi

  echo "Refreshing VM gateway StatefulSet image to ${VM_GATEWAY_IMAGE}..."
  # Re-import the host-synced :dev image into the VM's containerd, then
  # force a rollout when the StatefulSet already points at the same tag.
  vm_exec sh -lc "set -eu; \
    image_tar='/${VM_GATEWAY_TAR_REL}'; \
    k3s ctr -n k8s.io images import \"\${image_tar}\" >/dev/null; \
    current_image=\$(kubectl -n openshell get statefulset/openshell -o jsonpath='{.spec.template.spec.containers[?(@.name==\"openshell\")].image}'); \
    if [ \"\${current_image}\" = \"${VM_GATEWAY_IMAGE}\" ]; then \
      kubectl -n openshell rollout restart statefulset/openshell >/dev/null; \
    else \
      kubectl -n openshell set image statefulset/openshell openshell=${VM_GATEWAY_IMAGE} >/dev/null; \
    fi; \
    kubectl -n openshell rollout status statefulset/openshell --timeout=300s"
  echo "Gateway rollout complete."
}

wait_for_gateway_health() {
  local elapsed=0 timeout=60 consecutive_ok=0

  echo "Waiting for refreshed gateway health..."
  while [ "${elapsed}" -lt "${timeout}" ]; do
    if "${ROOT}/target/debug/openshell" status >/dev/null 2>&1; then
      consecutive_ok=$((consecutive_ok + 1))
      if [ "${consecutive_ok}" -ge 3 ]; then
        echo "Gateway health confirmed after refresh."
        return 0
      fi
    else
      consecutive_ok=0
    fi

    sleep 2
    elapsed=$((elapsed + 2))
  done

  echo "ERROR: refreshed gateway did not become healthy after ${timeout}s"
  return 1
}

# ── Parse arguments ──────────────────────────────────────────────────
VM_PORT=""
VM_NAME=""
VM_ROOTFS_DIR=""
for arg in "$@"; do
  case "$arg" in
    --vm-port=*) VM_PORT="${arg#--vm-port=}" ;;
    --vm-name=*) VM_NAME="${arg#--vm-name=}" ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

# ── Determine mode ───────────────────────────────────────────────────
if [ -n "${VM_PORT}" ]; then
  # Point at an already-running VM.
  HOST_PORT="${VM_PORT}"
  echo "Using existing VM on port ${HOST_PORT}."
  if [ -n "${VM_NAME}" ]; then
    prepare_named_vm_rootfs
  fi
else
  # Pick a random free port and start a new VM.
  HOST_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
  if [ -z "${VM_NAME}" ]; then
    VM_NAME="e2e-${HOST_PORT}-$$"
  fi

  cleanup() {
    local exit_code=$?
    if [ -n "${VM_PID:-}" ] && kill -0 "$VM_PID" 2>/dev/null; then
      echo "Stopping openshell-vm (pid ${VM_PID})..."
      kill "$VM_PID" 2>/dev/null || true
      wait "$VM_PID" 2>/dev/null || true
    fi
    # On failure, preserve the VM console log for post-mortem debugging.
    if [ "$exit_code" -ne 0 ] && [ -n "${VM_NAME:-}" ]; then
      local console_log
      console_log="$(named_vm_rootfs)-console.log"
      if [ -f "$console_log" ]; then
        echo "=== VM console log (preserved for debugging) ==="
        cat "$console_log"
        echo "=== end VM console log ==="
      fi
    fi
    rm -f "${VM_LOG:-}" 2>/dev/null || true
    if [ -n "${VM_NAME:-}" ]; then
      rm -rf "$(dirname "$(named_vm_rootfs)")" 2>/dev/null || true
    fi
  }
  trap cleanup EXIT

  prepare_named_vm_rootfs

  echo "Starting openshell-vm '${VM_NAME}' on port ${HOST_PORT}..."
  if [ "$(uname -s)" = "Darwin" ]; then
    export DYLD_FALLBACK_LIBRARY_PATH="${RUNTIME_DIR}${DYLD_FALLBACK_LIBRARY_PATH:+:${DYLD_FALLBACK_LIBRARY_PATH}}"
  fi

  VM_LOG=$(mktemp /tmp/openshell-vm-e2e.XXXXXX)
  rootfs_args=()
  if [ -n "${VM_ROOTFS_DIR}" ]; then
    rootfs_args=(--rootfs "${VM_ROOTFS_DIR}")
  fi
  "${GATEWAY_BIN}" "${rootfs_args[@]}" --name "${VM_NAME}" --port "${HOST_PORT}:${GUEST_PORT}" 2>"${VM_LOG}" &
  VM_PID=$!

  # ── Wait for full bootstrap (mTLS certs + gRPC health) ─────────────
  # The VM prints "Ready [Xs total]" to stderr after bootstrap_gateway()
  # stores mTLS certs and wait_for_gateway_ready() confirms the gRPC
  # service is responding. Waiting only for TCP port reachability (nc -z)
  # is insufficient because port forwarding is established before the
  # mTLS certs are written, causing `openshell status` to fail.
  echo "Waiting for VM bootstrap to complete (timeout ${TIMEOUT}s)..."
  elapsed=0
  while ! grep -q "^Ready " "${VM_LOG}" 2>/dev/null; do
    if ! kill -0 "$VM_PID" 2>/dev/null; then
      echo "ERROR: openshell-vm exited before becoming ready"
      echo "VM log:"
      cat "${VM_LOG}"
      exit 1
    fi
    if [ "$elapsed" -ge "$TIMEOUT" ]; then
      echo "ERROR: openshell-vm did not become ready after ${TIMEOUT}s"
      echo "VM log:"
      cat "${VM_LOG}"
      exit 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  echo "Gateway is ready (${elapsed}s)."
  echo "VM log:"
  cat "${VM_LOG}"
fi

# ── Exec into the VM (when instance name is known) ───────────────────
if [ -n "${VM_NAME}" ]; then
  echo "Verifying openshell-vm exec for '${VM_NAME}'..."
  exec_elapsed=0
  exec_timeout=60
  until vm_exec /bin/true; do
    if [ "$exec_elapsed" -ge "$exec_timeout" ]; then
      echo "ERROR: openshell-vm exec did not become ready after ${exec_timeout}s"
      exit 1
    fi
    sleep 2
    exec_elapsed=$((exec_elapsed + 2))
  done
  echo "VM exec succeeded."
else
  echo "Skipping openshell-vm exec check (provide --vm-name for existing VMs)."
fi

refresh_vm_gateway

# ── Run the smoke test ───────────────────────────────────────────────
# The openshell CLI reads OPENSHELL_GATEWAY_ENDPOINT to connect to the
# gateway directly, and OPENSHELL_GATEWAY to resolve mTLS certs from
# ~/.config/openshell/gateways/<name>/mtls/.
# In the VM, the overlayfs snapshotter re-extracts all image layers on
# every boot. The 1GB sandbox base image extraction can take >300s
# under contention, so allow 600s for sandbox provisioning.
export OPENSHELL_PROVISION_TIMEOUT=600
export OPENSHELL_GATEWAY_ENDPOINT="https://127.0.0.1:${HOST_PORT}"
if [ -n "${VM_NAME}" ]; then
  export OPENSHELL_GATEWAY="openshell-vm-${VM_NAME}"
else
  export OPENSHELL_GATEWAY="openshell-vm"
fi

echo "Running e2e smoke test (gateway: ${OPENSHELL_GATEWAY}, endpoint: ${OPENSHELL_GATEWAY_ENDPOINT})..."
cargo build -p openshell-cli --features openshell-core/dev-settings
wait_for_gateway_health
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e --test smoke -- --nocapture

echo "Smoke test passed."
