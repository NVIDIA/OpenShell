#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Create, inspect, and tear down a CentOS Stream 10 VM under QEMU for
# Docker/Podman/SELinux compatibility testing.
#
# RHEL-family distros (RHEL, CentOS Stream) ship Podman but not Docker, and
# enforce SELinux by default — unlike the Ubuntu-based
# ghcr.io/nvidia/openshell/ci image our other e2e lanes run in. This script
# boots a real CentOS Stream 10 guest under hardware-accelerated QEMU so both
# engines, and any SELinux-sensitive behavior (e.g. bind-mount `:z`/`:Z`
# relabeling), can be exercised against a kernel that actually enforces
# SELinux.
#
# This is the same script `.github/workflows/e2e-centos-selinux.yml` uses to
# boot the guest in CI. Run it locally to reproduce that environment:
#
#   mise run vm:centos-selinux:create
#   mise run vm:centos-selinux:ssh
#   # ... install/exercise docker, podman, mise run e2e:docker, etc ...
#   mise run vm:centos-selinux:destroy
#
# Usage:
#   centos-selinux-vm.sh create [--force]
#   centos-selinux-vm.sh destroy
#   centos-selinux-vm.sh status
#   centos-selinux-vm.sh ssh [-- <command>...]
#
# Environment overrides (all optional):
#   OPENSHELL_CENTOS_SELINUX_VM_STATE_DIR  State dir (default: <repo>/.cache/vm/centos-selinux)
#   CENTOS_IMAGE_URL      CentOS Stream 10 GenericCloud qcow2 image URL
#   VM_MEMORY_MB          Guest memory in MB (default: 8192)
#   VM_CPUS               Guest vCPUs (default: 4)
#   VM_DISK_GB            Guest root disk size in GB after resize (default: 40)
#   SSH_PORT              Host TCP port forwarded to the guest SSH daemon (default: 2222)
#   VM_BOOT_TIMEOUT_MINUTES  Minutes to wait for guest SSH to come up (default: 10)
#   VM_ACCEL               Force QEMU accelerator: kvm, hvf, or tcg (default: auto-detect)
#   GUEST_USER             Guest username created via cloud-init (default: e2e)
#
# The base cloud image is downloaded once and cached; each `create` boots a
# fresh copy-on-write overlay disk, so repeated local runs don't re-download
# or mutate the cached base image.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tasks/scripts/vm/_lib.sh
source "${SCRIPT_DIR}/_lib.sh"
ROOT="$(vm_lib_root)"

STATE_DIR="${OPENSHELL_CENTOS_SELINUX_VM_STATE_DIR:-${ROOT}/.cache/vm/centos-selinux}"
CENTOS_IMAGE_URL="${CENTOS_IMAGE_URL:-https://cloud.centos.org/centos/10-stream/x86_64/images/CentOS-Stream-GenericCloud-10-latest.x86_64.qcow2}"
VM_MEMORY_MB="${VM_MEMORY_MB:-8192}"
VM_CPUS="${VM_CPUS:-4}"
VM_DISK_GB="${VM_DISK_GB:-40}"
SSH_PORT="${SSH_PORT:-2222}"
VM_BOOT_TIMEOUT_MINUTES="${VM_BOOT_TIMEOUT_MINUTES:-10}"
VM_ACCEL="${VM_ACCEL:-auto}"
GUEST_USER="${GUEST_USER:-e2e}"
GUEST_NAME="openshell-e2e-centos"

BASE_IMAGE="${STATE_DIR}/centos-base.qcow2"
DISK_IMAGE="${STATE_DIR}/disk.qcow2"
SEED_ISO="${STATE_DIR}/seed.iso"
GUEST_KEY="${STATE_DIR}/guest_ed25519"
PID_FILE="${STATE_DIR}/qemu.pid"
CONSOLE_LOG="${STATE_DIR}/console.log"
CONNECTION_ENV="${STATE_DIR}/connection.env"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes)

usage() {
  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

log() { echo "==> $*"; }
err() { echo "ERROR: $*" >&2; }

require_tool() {
  local tool="$1" hint="$2"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    err "missing required tool '${tool}'."
    echo "       ${hint}" >&2
    exit 1
  fi
}

check_dependencies() {
  require_tool qemu-img "Install QEMU (e.g. 'sudo apt-get install qemu-utils' or 'brew install qemu')."
  require_tool qemu-system-x86_64 "Install QEMU (e.g. 'sudo apt-get install qemu-system-x86' or 'brew install qemu')."
  require_tool ssh "Install an OpenSSH client."
  require_tool ssh-keygen "Install an OpenSSH client."
  require_tool curl "Install curl."
  if ! command -v genisoimage >/dev/null 2>&1 \
      && ! command -v mkisofs >/dev/null 2>&1 \
      && ! command -v xorriso >/dev/null 2>&1; then
    err "missing an ISO-building tool (genisoimage, mkisofs, or xorriso)."
    echo "       Install one, e.g. 'sudo apt-get install genisoimage' or 'brew install cdrtools'." >&2
    exit 1
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

build_seed_iso() {
  local out="$1" volid="$2" dir="$3"
  if command -v genisoimage >/dev/null 2>&1; then
    genisoimage -output "${out}" -volid "${volid}" -joliet -rock "${dir}/user-data" "${dir}/meta-data" >/dev/null
  elif command -v mkisofs >/dev/null 2>&1; then
    mkisofs -output "${out}" -volid "${volid}" -joliet -rock "${dir}/user-data" "${dir}/meta-data" >/dev/null
  else
    xorriso -as genisoimage -output "${out}" -volid "${volid}" -joliet -rock "${dir}/user-data" "${dir}/meta-data" >/dev/null
  fi
}

detect_accel() {
  if [ "${VM_ACCEL}" != "auto" ]; then
    echo "${VM_ACCEL}"
    return
  fi
  case "$(uname -s)" in
    Linux)
      if [ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        echo "kvm"
      else
        echo "tcg"
      fi
      ;;
    Darwin)
      if [ "$(uname -m)" = "x86_64" ]; then
        echo "hvf"
      else
        echo "tcg"
      fi
      ;;
    *)
      echo "tcg"
      ;;
  esac
}

vm_pid_alive() {
  [ -f "${PID_FILE}" ] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null
}

download_base_image() {
  mkdir -p "${STATE_DIR}"
  if [ -f "${BASE_IMAGE}" ]; then
    log "Using cached base image: ${BASE_IMAGE}"
    return
  fi
  log "Downloading CentOS Stream 10 GenericCloud image..."
  local tmp="${BASE_IMAGE}.part"
  curl -fsSL -o "${tmp}" "${CENTOS_IMAGE_URL}"
  if curl -fsSL -o "${STATE_DIR}/centos-base.qcow2.SHA256SUM" "${CENTOS_IMAGE_URL}.SHA256SUM" 2>/dev/null; then
    local expected actual
    expected="$(grep -oE '[0-9a-f]{64}' "${STATE_DIR}/centos-base.qcow2.SHA256SUM" | head -n1)"
    actual="$(sha256_file "${tmp}")"
    if [ "${expected}" != "${actual}" ]; then
      rm -f "${tmp}"
      err "CentOS Stream image checksum mismatch (expected ${expected}, got ${actual})"
      exit 1
    fi
    log "Verified image checksum: ${actual}"
  else
    echo "WARNING: no SHA256SUM published alongside the image; skipping checksum verification" >&2
  fi
  mv "${tmp}" "${BASE_IMAGE}"
}

ensure_ssh_key() {
  if [ -f "${GUEST_KEY}" ]; then
    return
  fi
  log "Generating ephemeral guest SSH keypair..."
  ssh-keygen -t ed25519 -N "" -C "openshell-e2e-centos" -f "${GUEST_KEY}" >/dev/null
}

build_overlay_disk() {
  log "Creating ${VM_DISK_GB}G writable overlay disk from cached base image..."
  rm -f "${DISK_IMAGE}"
  qemu-img create -f qcow2 -F qcow2 -b "${BASE_IMAGE}" "${DISK_IMAGE}" >/dev/null
  qemu-img resize "${DISK_IMAGE}" "${VM_DISK_GB}G" >/dev/null
}

# Written line-by-line (not an indented heredoc) so the generated files have
# no leading whitespace: cloud-init requires "#cloud-config" to be the exact
# first bytes of user-data to recognize the format.
build_cloud_init_seed() {
  log "Building cloud-init seed image..."
  local guest_pubkey
  guest_pubkey="$(cat "${GUEST_KEY}.pub")"
  {
    echo "instance-id: ${GUEST_NAME}"
    echo "local-hostname: ${GUEST_NAME}"
  } >"${STATE_DIR}/meta-data"
  {
    echo "#cloud-config"
    echo "hostname: openshell-e2e-guest"
    echo "manage_etc_hosts: true"
    echo "disable_root: true"
    echo "ssh_pwauth: false"
    echo "users:"
    echo "  - name: ${GUEST_USER}"
    echo "    gecos: OpenShell E2E"
    echo "    groups: [wheel]"
    echo "    sudo: [\"ALL=(ALL) NOPASSWD:ALL\"]"
    echo "    shell: /bin/bash"
    echo "    lock_passwd: true"
    echo "    ssh_authorized_keys:"
    echo "      - ${guest_pubkey}"
    echo "package_update: false"
    echo "package_upgrade: false"
  } >"${STATE_DIR}/user-data"
  head -n1 "${STATE_DIR}/user-data" | grep -qx '#cloud-config'
  build_seed_iso "${SEED_ISO}" cidata "${STATE_DIR}"
}

boot_vm() {
  local accel
  accel="$(detect_accel)"
  if [ "${accel}" = "kvm" ] && { [ ! -c /dev/kvm ] || [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; }; then
    err "/dev/kvm is not available or not accessible."
    echo "       This host cannot provide hardware-accelerated KVM. Set VM_ACCEL=tcg to fall back" >&2
    echo "       to (slow) software emulation, or run on a host/container with /dev/kvm exposed." >&2
    exit 1
  fi
  if [ "${accel}" = "tcg" ]; then
    echo "WARNING: no hardware acceleration available; booting with software emulation (tcg)." >&2
    echo "         This will be significantly slower to boot and run." >&2
  fi

  local cpu_flag="host"
  [ "${accel}" = "tcg" ] && cpu_flag="max"

  log "Booting CentOS Stream 10 VM (accel=${accel})..."
  # -display none + -monitor none (rather than -nographic) because
  # -nographic redirects the serial/monitor console to the controlling tty,
  # which QEMU refuses to combine with -daemonize ("cannot be used with
  # -daemonize"). -serial file:... captures the console independently.
  qemu-system-x86_64 \
    -name "${GUEST_NAME}" \
    -machine "q35,accel=${accel}" -cpu "${cpu_flag}" \
    -smp "${VM_CPUS}" -m "${VM_MEMORY_MB}" \
    -drive file="${DISK_IMAGE}",if=virtio,format=qcow2 \
    -drive file="${SEED_ISO}",if=virtio,format=raw \
    -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22" \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    -monitor none \
    -serial file:"${CONSOLE_LOG}" \
    -pidfile "${PID_FILE}" \
    -daemonize
}

wait_for_guest_ssh() {
  log "Waiting for guest SSH on 127.0.0.1:${SSH_PORT} (timeout: ${VM_BOOT_TIMEOUT_MINUTES}m)..."
  local deadline=$(($(date +%s) + VM_BOOT_TIMEOUT_MINUTES * 60))
  until ssh -p "${SSH_PORT}" -i "${GUEST_KEY}" "${SSH_OPTS[@]}" "${GUEST_USER}@127.0.0.1" true 2>/dev/null; do
    if [ "$(date +%s)" -ge "${deadline}" ]; then
      err "guest SSH did not become reachable within ${VM_BOOT_TIMEOUT_MINUTES} minutes."
      echo "=== console log (${CONSOLE_LOG}) ===" >&2
      tail -n 200 "${CONSOLE_LOG}" >&2 2>/dev/null || true
      exit 1
    fi
    sleep 5
  done
  log "Guest SSH is reachable."
}

write_connection_env() {
  cat >"${CONNECTION_ENV}" <<EOF
GUEST_USER=${GUEST_USER}
GUEST_KEY=${GUEST_KEY}
SSH_PORT=${SSH_PORT}
STATE_DIR=${STATE_DIR}
EOF
}

cmd_create() {
  local force=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --force) force=1; shift ;;
      *) err "unknown option '$1' for create"; exit 2 ;;
    esac
  done

  if vm_pid_alive; then
    if [ "${force}" -eq 1 ]; then
      log "VM already running; --force given, destroying first."
      cmd_destroy
    else
      log "VM already running (pid $(cat "${PID_FILE}")). Use --force to recreate, or 'destroy' to stop it."
      write_connection_env
      print_connection_info
      return 0
    fi
  fi

  check_dependencies
  mkdir -p "${STATE_DIR}"
  download_base_image
  ensure_ssh_key
  build_overlay_disk
  build_cloud_init_seed
  boot_vm
  wait_for_guest_ssh
  write_connection_env
  print_connection_info
}

print_connection_info() {
  echo
  echo "CentOS Stream 10 SELinux compat VM is up:"
  echo "  ssh -p ${SSH_PORT} -i ${GUEST_KEY} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${GUEST_USER}@127.0.0.1"
  echo "  (or: mise run vm:centos-selinux:ssh)"
  echo
}

cmd_status() {
  if vm_pid_alive; then
    echo "running (pid $(cat "${PID_FILE}"), ssh port ${SSH_PORT})"
    return 0
  fi
  echo "not running"
  return 1
}

cmd_destroy() {
  if [ -f "${CONNECTION_ENV}" ] && vm_pid_alive; then
    log "Requesting graceful guest shutdown..."
    # shellcheck disable=SC1090
    source "${CONNECTION_ENV}"
    ssh -p "${SSH_PORT}" -i "${GUEST_KEY}" "${SSH_OPTS[@]}" "${GUEST_USER}@127.0.0.1" sudo poweroff 2>/dev/null || true
  fi
  if [ -f "${PID_FILE}" ]; then
    local pid
    pid="$(cat "${PID_FILE}")"
    for _ in $(seq 1 20); do
      kill -0 "${pid}" 2>/dev/null || break
      sleep 1
    done
    kill -9 "${pid}" 2>/dev/null || true
    rm -f "${PID_FILE}"
  fi
  rm -f "${DISK_IMAGE}" "${SEED_ISO}" "${CONSOLE_LOG}" "${CONNECTION_ENV}" \
    "${STATE_DIR}/user-data" "${STATE_DIR}/meta-data"
  log "VM stopped. Cached base image and guest SSH key preserved under ${STATE_DIR}."
}

cmd_ssh() {
  if ! vm_pid_alive; then
    err "VM is not running. Run 'centos-selinux-vm.sh create' first."
    exit 1
  fi
  if [ "$#" -gt 0 ] && [ "$1" = "--" ]; then
    shift
  fi
  exec ssh -p "${SSH_PORT}" -i "${GUEST_KEY}" "${SSH_OPTS[@]}" "${GUEST_USER}@127.0.0.1" "$@"
}

main() {
  local subcommand="${1:-}"
  [ "$#" -gt 0 ] && shift || true
  case "${subcommand}" in
    create) cmd_create "$@" ;;
    destroy) cmd_destroy "$@" ;;
    status) cmd_status "$@" ;;
    ssh) cmd_ssh "$@" ;;
    -h|--help|help|"") usage ;;
    *)
      err "unknown subcommand '${subcommand}'"
      usage
      exit 2
      ;;
  esac
}

main "$@"
