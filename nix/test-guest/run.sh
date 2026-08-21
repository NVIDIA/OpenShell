#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# PROTOTYPE: Boot and configure a disposable cloud image, then install artifacts.

set -Eeuo pipefail

usage() {
	cat <<'EOF'
Usage:
  nix run .#test-guest -- --distro DISTRO [OPTIONS] [-- COMMAND...]

Options:
  --distro NAME       Base distro: ubuntu, centos, fedora, or rocky
  --with NAME         Apply a configuration; repeatable (docker, podman, selinux)
  --install PATH      Install a .deb or .rpm package; repeatable
  --copy SRC:DEST     Copy an executable to an absolute guest path; repeatable
  --ssh-port PORT     Use a specific loopback SSH forwarding port
  --forward-port HOST_PORT:GUEST_PORT
                      Forward a loopback host port to a guest port; repeatable
  --keep              Keep the disposable disk and logs after shutdown
  --list              List distros and configurations
  -h, --help          Show this help

With no COMMAND, the runner opens an interactive SSH session.
EOF
}

if [ "${OPENSHELL_TEST_GUEST_RUNTIME:-}" != 1 ] ||
	[ ! -d "${OPENSHELL_TEST_GUEST_DISTROS:-}" ] ||
	[ ! -d "${OPENSHELL_TEST_GUEST_CONFIGURATIONS:-}" ] ||
	[ ! -r "${OPENSHELL_TEST_GUEST_CACHE_LIB:-}" ] ||
	[ ! -r "${OPENSHELL_TEST_GUEST_CACHE_RUNNER:-}" ]; then
	echo "run this script through 'nix run .#test-guest -- ...'" >&2
	exit 2
fi

require_value() {
	if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then
		echo "$1 requires a value" >&2
		exit 2
	fi
}

distro=
requested_ssh_port=
keep=0
list=0
configurations=()
packages=()
copies=()
forward_ports=()
guest_command=()

while [ "$#" -gt 0 ]; do
	case "$1" in
	--distro)
		require_value "$@"
		distro=$2
		shift 2
		;;
	--with)
		require_value "$@"
		configurations+=("$2")
		shift 2
		;;
	--install)
		require_value "$@"
		packages+=("$2")
		shift 2
		;;
	--copy)
		require_value "$@"
		copies+=("$2")
		shift 2
		;;
	--ssh-port)
		require_value "$@"
		requested_ssh_port=$2
		shift 2
		;;
	--forward-port)
		if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then
			echo "--forward-port requires HOST_PORT:GUEST_PORT" >&2
			exit 2
		fi
		forward_ports+=("${2:-}")
		shift 2
		;;
	--keep)
		keep=1
		shift
		;;
	--list)
		list=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	--)
		shift
		guest_command=("$@")
		break
		;;
	*)
		echo "unknown test guest argument: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

if [ "${list}" -eq 1 ]; then
	echo "Distros:"
	for entry in "${OPENSHELL_TEST_GUEST_DISTROS}"/*; do
		printf '  %s\n' "${entry##*/}"
	done
	echo "Configurations:"
	for entry in "${OPENSHELL_TEST_GUEST_CONFIGURATIONS}"/*; do
		printf '  %s\n' "${entry##*/}"
	done
	exit 0
fi

if [ -z "${distro}" ]; then
	echo "--distro is required" >&2
	usage >&2
	exit 2
fi
if [[ ! ${distro} =~ ^[a-z0-9][a-z0-9-]*$ ]] ||
	[ ! -r "${OPENSHELL_TEST_GUEST_DISTROS}/${distro}" ]; then
	echo "unknown distro: ${distro}" >&2
	exit 2
fi
# Distro profiles contain only trusted values generated into the Nix store.
# shellcheck disable=SC1090
. "${OPENSHELL_TEST_GUEST_DISTROS}/${distro}"

for item in "${configurations[@]}"; do
	if [[ ! ${item} =~ ^[a-z0-9][a-z0-9-]*$ ]] ||
		[ ! -r "${OPENSHELL_TEST_GUEST_CONFIGURATIONS}/${item}" ]; then
		echo "unknown configuration: ${item:-<empty>}" >&2
		exit 2
	fi
done

if [ -n "${requested_ssh_port}" ] && {
	[[ ! ${requested_ssh_port} =~ ^[0-9]+$ ]] ||
		[ "${requested_ssh_port}" -lt 1024 ] ||
		[ "${requested_ssh_port}" -gt 65535 ]
	}; then
	echo "--ssh-port must be an integer between 1024 and 65535" >&2
	exit 2
fi

forward_host_ports=()
for forward_spec in "${forward_ports[@]}"; do
	host_port=${forward_spec%%:*}
	guest_port=${forward_spec#*:}
	if [ "${host_port}" = "${forward_spec}" ] ||
		[[ ! ${host_port} =~ ^[1-9][0-9]*$ ]] ||
		[[ ! ${guest_port} =~ ^[1-9][0-9]*$ ]] ||
		[ "${host_port}" -lt 1024 ] ||
		[ "${host_port}" -gt 65535 ] ||
		[ "${guest_port}" -lt 1024 ] ||
		[ "${guest_port}" -gt 65535 ]; then
		echo "--forward-port must be HOST_PORT:GUEST_PORT with both ports between 1024 and 65535: ${forward_spec:-<empty>}" >&2
		exit 2
	fi
	for existing_host_port in "${forward_host_ports[@]}"; do
		if [ "${host_port}" = "${existing_host_port}" ]; then
			echo "duplicate --forward-port host port: ${host_port}" >&2
			exit 2
		fi
	done
	if [ -n "${requested_ssh_port}" ] && [ "${host_port}" = "${requested_ssh_port}" ]; then
		echo "--forward-port host port conflicts with --ssh-port: ${host_port}" >&2
		exit 2
	fi
	if ! python3 - "${host_port}" <<'PY'
import socket
import sys

sock = socket.socket()
try:
    sock.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
	then
		echo "--forward-port host port is unavailable: ${host_port}" >&2
		exit 2
	fi
	forward_host_ports+=("${host_port}")
done

resolved_packages=()
for package in "${packages[@]}"; do
	package_input=${package}
	if ! package=$(realpath -- "${package}"); then
		echo "package does not exist: ${package_input}" >&2
		exit 2
	fi
	if [ ! -f "${package}" ]; then
		echo "package does not exist: ${package_input}" >&2
		exit 2
	fi
	case "${TEST_GUEST_PACKAGE_FAMILY}:${package}" in
	deb:*.deb | rpm:*.rpm) ;;
	*)
		echo "${package} does not match the ${TEST_GUEST_PACKAGE_FAMILY} package family" >&2
		exit 2
		;;
	esac
	resolved_packages+=("${package}")
done
packages=("${resolved_packages[@]}")

resolved_copies=()
for copy_spec in "${copies[@]}"; do
	source_path=${copy_spec%%:*}
	destination=${copy_spec#*:}
	if [ "${source_path}" = "${copy_spec}" ] ||
		! source_path=$(realpath -- "${source_path}") ||
		[ ! -f "${source_path}" ]; then
		echo "invalid --copy source: ${copy_spec}" >&2
		exit 2
	fi
	case "${destination}" in
	/*)
		if [[ ${destination} == *"/../"* ]] || [[ ${destination} == */.. ]]; then
			echo "--copy destination must not contain '..': ${destination}" >&2
			exit 2
		fi
		if [[ ! ${destination} =~ ^/[A-Za-z0-9._+~/-]+$ ]]; then
			echo "--copy destination contains unsupported characters: ${destination}" >&2
			exit 2
		fi
		;;
	*)
		echo "--copy destination must be absolute: ${destination}" >&2
		exit 2
		;;
	esac
	resolved_copies+=("${source_path}:${destination}")
done
copies=("${resolved_copies[@]}")

test_vm_cpu=host
ssh_wait_seconds=180
if [ "${TEST_GUEST_ACCELERATOR}" = kvm ] &&
	{ [ ! -c /dev/kvm ] || [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; }; then
	echo "==> /dev/kvm is unavailable; falling back to QEMU/TCG"
	TEST_GUEST_ACCELERATOR=tcg
	test_vm_cpu=max
	ssh_wait_seconds=600
fi

# shellcheck disable=SC1090
. "${OPENSHELL_TEST_GUEST_CACHE_LIB}"

report_timing() {
	local label=$1
	local started_at=$2

	echo "==> Timing: ${label}: $((SECONDS - started_at))s"
}

phase_started_at=${SECONDS}
prepared_image=0
TEST_GUEST_IMAGE=
if [ -n "${OPENSHELL_TEST_GUEST_IMAGE_OVERRIDE:-}" ]; then
	if [ ! -f "${OPENSHELL_TEST_GUEST_IMAGE_OVERRIDE}" ]; then
		echo "prepared guest image does not exist: ${OPENSHELL_TEST_GUEST_IMAGE_OVERRIDE}" >&2
		exit 2
	fi
	TEST_GUEST_IMAGE=${OPENSHELL_TEST_GUEST_IMAGE_OVERRIDE}
	prepared_image=1
	echo "==> Using explicit prepared guest image"
elif [ "${OPENSHELL_TEST_GUEST_CACHE_DISABLE:-0}" -ne 1 ]; then
	cache_root=$(test_vm_cache_root)
	cache_key=$(test_vm_cache_key "${distro}" "${configurations[@]}")
	cache_entry=$(test_vm_cache_entry_dir "${cache_root}" "${cache_key}")
	if ! test_vm_cache_local_entry_valid \
		"${cache_root}" "${cache_key}" "${distro}" "${configurations[@]}"; then
		cache_args=(--distro "${distro}")
		for item in "${configurations[@]}"; do
			cache_args+=(--with "${item}")
		done
		echo "==> Cache local miss: populating ${cache_entry}"
		OPENSHELL_TEST_GUEST_CACHE_DISABLE=1 \
			"${TEST_GUEST_BASH}" "${OPENSHELL_TEST_GUEST_CACHE_RUNNER}" \
			"${cache_args[@]}"
		if ! test_vm_cache_local_entry_valid \
			"${cache_root}" "${cache_key}" "${distro}" "${configurations[@]}"; then
			echo "cache builder did not produce a valid entry: ${cache_entry}" >&2
			exit 1
		fi
		echo "==> Cache populated: ${cache_entry}"
	else
		echo "==> Cache local hit: ${cache_entry}"
	fi
	TEST_GUEST_IMAGE="${cache_entry}/disk.qcow2"
	prepared_image=1
fi

if [ "${prepared_image}" -eq 0 ]; then
	echo "==> Realizing the pinned ${distro} cloud image"
	TEST_GUEST_IMAGE=$(nix build --no-link --print-out-paths "${TEST_GUEST_IMAGE_DRV}^out")
fi
report_timing "guest image resolution" "${phase_started_at}"

phase_started_at=${SECONDS}
umask 077
run_parent=${TMPDIR:-/tmp}/openshell-test-guest
mkdir -p "${run_parent}"
run_dir=$(mktemp -d "${run_parent%/}/run.XXXXXX")
ssh_control_dir=$(mktemp -d /tmp/openshell-test-guest-ssh.XXXXXX)
overlay=${run_dir}/disk.qcow2
seed=${run_dir}/seed.iso
vars=${run_dir}/firmware-vars.fd
vars_json=${run_dir}/firmware-vars.json
private_key=${run_dir}/id_ed25519
ssh_control_path=${ssh_control_dir}/ctl
serial_log=${run_dir}/serial.log
qemu_log=${run_dir}/qemu.log
qemu_pid=
ssh_port=
ssh_args=()
ssh_forward_args=()
scp_args=()
ansible_config=${run_dir}/ansible.cfg
ansible_inventory=${run_dir}/inventory.ini

show_logs() {
	if [ -s "${qemu_log}" ]; then
		echo "=== QEMU log ===" >&2
		tail -n 100 "${qemu_log}" >&2 || true
	fi
	if [ -s "${serial_log}" ]; then
		echo "=== serial log ===" >&2
		tail -n 200 "${serial_log}" >&2 || true
	fi
}

cleanup() {
	status=$?
	trap - EXIT INT TERM
	if [ -n "${qemu_pid}" ] && kill -0 "${qemu_pid}" 2>/dev/null; then
		kill "${qemu_pid}" 2>/dev/null || true
		wait "${qemu_pid}" 2>/dev/null || true
	fi
	if [ "${status}" -ne 0 ]; then
		show_logs
	fi
	if [ "${keep}" -eq 1 ]; then
		echo "Kept test guest state at ${run_dir}" >&2
	else
		rm -rf "${run_dir}"
	fi
	rm -rf "${ssh_control_dir}"
	exit "${status}"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

pick_free_port() {
	python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

port_is_forwarded() {
	local candidate=$1
	local forwarded
	for forwarded in "${forward_host_ports[@]}"; do
		if [ "${candidate}" = "${forwarded}" ]; then
			return 0
		fi
	done
	return 1
}

ssh-keygen -q -t ed25519 -N "" -f "${private_key}"
public_key=$(<"${private_key}.pub")

cat >"${run_dir}/meta-data" <<EOF
instance-id: openshell-test-guest-${distro}-$$-${RANDOM}
local-hostname: openshell-test-guest
EOF
cat >"${run_dir}/user-data" <<EOF
#cloud-config
users:
  - name: openshell
    lock_passwd: true
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ${public_key}
ssh_pwauth: false
disable_root: true
EOF
(
	cd "${run_dir}"
	xorriso -as mkisofs -quiet -output "${seed}" -volid cidata -joliet -rock user-data meta-data
)

qemu-img create -q -f qcow2 -F qcow2 -b "${TEST_GUEST_IMAGE}" "${overlay}"
if [ "${prepared_image}" -eq 0 ]; then
	qemu-img resize -q "${overlay}" +16G
fi
cp "${TEST_GUEST_FIRMWARE_VARS}" "${vars}"
chmod 0600 "${vars}"
# The generic EDK2 varstore defaults to a five-second boot-manager timeout.
# Seed the standard global Timeout variable before the disposable VM starts.
cat >"${vars_json}" <<'EOF'
{"version":2,"variables":[{"name":"Timeout","guid":"8be4df61-93ca-11d2-aa0d-00e098032b8c","attr":7,"data":"0000"}]}
EOF
virt-fw-vars \
	--loglevel WARNING \
	--inplace "${vars}" \
	--set-json "${vars_json}"
report_timing "VM runtime preparation" "${phase_started_at}"

phase_started_at=${SECONDS}
for attempt in $(seq 1 5); do
	if [ -n "${requested_ssh_port}" ]; then
		ssh_port=${requested_ssh_port}
	else
		while :; do
			ssh_port=$(pick_free_port)
			if ! port_is_forwarded "${ssh_port}"; then
				break
			fi
		done
	fi
	netdev_arg="user,id=net0,hostfwd=tcp:127.0.0.1:${ssh_port}-:22"
	: >"${qemu_log}"
	echo "==> Booting ${distro} (${TEST_GUEST_ARCHITECTURE}) with QEMU/${TEST_GUEST_ACCELERATOR}"
	"${TEST_GUEST_QEMU}" \
		-name "openshell-test-${distro}" \
		-machine "${TEST_GUEST_MACHINE},accel=${TEST_GUEST_ACCELERATOR}" \
		-cpu "${test_vm_cpu}" \
		-smp 4 \
		-m 4096 \
		-drive "if=pflash,format=raw,readonly=on,file=${TEST_GUEST_FIRMWARE_CODE}" \
		-drive "if=pflash,format=raw,file=${vars}" \
		-drive "if=none,format=qcow2,file=${overlay},id=osdisk" \
		-device virtio-blk-pci,drive=osdisk,bootindex=1 \
		-drive "if=none,format=raw,readonly=on,file=${seed},id=seed" \
		-device virtio-blk-pci,drive=seed \
		-boot strict=on \
		-netdev "${netdev_arg}" \
		-device virtio-net-pci,netdev=net0 \
		-display none \
		-monitor none \
		-serial "file:${serial_log}" \
		-no-reboot \
		>/dev/null 2>"${qemu_log}" &
	qemu_pid=$!

	sleep 0.25
	if kill -0 "${qemu_pid}" 2>/dev/null; then
		break
	fi
	wait "${qemu_pid}" || true
	qemu_pid=
	if ! grep -q "Could not set up host forwarding rule" "${qemu_log}" ||
		[ -n "${requested_ssh_port}" ] ||
		[ "${#forward_ports[@]}" -gt 0 ]; then
		echo "QEMU exited during startup" >&2
		exit 1
	fi
	echo "SSH port was claimed concurrently; retrying (${attempt}/5)" >&2
done

if [ -z "${qemu_pid}" ]; then
	echo "QEMU could not allocate an SSH forwarding port" >&2
	exit 1
fi

ssh_args=(
	-F /dev/null
	-i "${private_key}"
	-p "${ssh_port}"
	-o BatchMode=yes
	-o Compression=yes
	-o ConnectTimeout=5
	-o ControlMaster=auto
	-o ControlPersist=60
	-o "ControlPath=${ssh_control_path}"
	-o IdentitiesOnly=yes
	-o LogLevel=ERROR
	-o StrictHostKeyChecking=no
	-o UserKnownHostsFile=/dev/null
)
scp_args=(
	-F /dev/null
	-C
	-i "${private_key}"
	-P "${ssh_port}"
	-o BatchMode=yes
	-o Compression=yes
	-o ConnectTimeout=5
	-o ControlMaster=auto
	-o ControlPersist=60
	-o "ControlPath=${ssh_control_path}"
	-o IdentitiesOnly=yes
	-o LogLevel=ERROR
	-o StrictHostKeyChecking=no
	-o UserKnownHostsFile=/dev/null
)
if [ "${#forward_ports[@]}" -gt 0 ]; then
	ssh_forward_args+=(-o ExitOnForwardFailure=yes)
	for forward_spec in "${forward_ports[@]}"; do
		host_port=${forward_spec%%:*}
		guest_port=${forward_spec#*:}
		ssh_forward_args+=(
			-L "127.0.0.1:${host_port}:127.0.0.1:${guest_port}"
		)
	done
fi

echo "==> Waiting up to ${ssh_wait_seconds} seconds for SSH on 127.0.0.1:${ssh_port}"
ssh_ready=0
for _ in $(seq 1 "$((ssh_wait_seconds * 4))"); do
	if ! kill -0 "${qemu_pid}" 2>/dev/null; then
		wait "${qemu_pid}" || true
		qemu_pid=
		echo "QEMU exited before SSH became ready" >&2
		exit 1
	fi
	if ssh "${ssh_args[@]}" -o ConnectTimeout=1 openshell@127.0.0.1 true 2>/dev/null; then
		ssh_ready=1
		break
	fi
	sleep 0.25
done
if [ "${ssh_ready}" -ne 1 ]; then
	echo "SSH did not become ready within ${ssh_wait_seconds} seconds" >&2
	exit 1
fi
report_timing "VM boot and SSH" "${phase_started_at}"

phase_started_at=${SECONDS}
echo "==> Validating ${distro}"
# Profile values come from the trusted Nix-generated catalog.
# shellcheck disable=SC2029
ssh "${ssh_args[@]}" openshell@127.0.0.1 \
	"set -eu; set +e; sudo cloud-init status --wait >/dev/null; status=\$?; set -e; [ \"\${status}\" -eq 0 ] || [ \"\${status}\" -eq 2 ]; . /etc/os-release; test \"\${ID}\" = '${TEST_GUEST_OS_ID}'; case \"\${VERSION_ID}\" in '${TEST_GUEST_OS_VERSION}'*) ;; *) exit 1 ;; esac; test \"\$(uname -m)\" = '${TEST_GUEST_ARCHITECTURE}'"
# cloud-init returns 2 when it completes with recoverable errors. Fedora can
# report that status for an initial transient-hostname warning even though the
# requested user and SSH configuration were applied successfully.
report_timing "guest validation" "${phase_started_at}"

cat >"${ansible_config}" <<EOF
[defaults]
host_key_checking = False
inventory = ${ansible_inventory}
interpreter_python = /usr/bin/python3
retry_files_enabled = False

[ssh_connection]
ssh_args = -F /dev/null -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null
EOF
cat >"${ansible_inventory}" <<EOF
[test_vm]
guest ansible_host=127.0.0.1 ansible_port=${ssh_port} ansible_user=openshell ansible_ssh_private_key_file=${private_key} ansible_python_interpreter=/usr/bin/python3
EOF

if [ "${prepared_image}" -eq 0 ]; then
	for item in "${configurations[@]}"; do
		echo "==> Applying configuration: ${item}"
		ANSIBLE_CONFIG="${ansible_config}" ANSIBLE_NOCOLOR=1 \
			ansible-playbook "${OPENSHELL_TEST_GUEST_CONFIGURATIONS}/${item}"
	done
else
	echo "==> Reusing cached configuration: ${configurations[*]:-base image}"
fi

if [ "${#packages[@]}" -gt 0 ] || [ "${#copies[@]}" -gt 0 ]; then
	phase_started_at=${SECONDS}
	artifact_staging_dir=/tmp/openshell-test-guest-artifacts-$$
	ssh "${ssh_args[@]}" openshell@127.0.0.1 \
		"install -d -m 0700 -- '${artifact_staging_dir}'"

	remote_packages=()
	artifact_index=0
	for package in "${packages[@]}"; do
		remote_path=${artifact_staging_dir}/package-${artifact_index}.${TEST_GUEST_PACKAGE_FAMILY}
		echo "==> Copying package: ${package##*/}"
		scp -q "${scp_args[@]}" \
			"${package}" "openshell@127.0.0.1:${remote_path}"
		remote_packages+=("${remote_path}")
		artifact_index=$((artifact_index + 1))
	done

	if [ "${#remote_packages[@]}" -gt 0 ]; then
		printf -v quoted_packages ' %q' "${remote_packages[@]}"
		case "${TEST_GUEST_PACKAGE_FAMILY}" in
		deb)
			ssh "${ssh_args[@]}" openshell@127.0.0.1 \
				"sudo apt-get update >/dev/null && sudo apt-get install -y --${quoted_packages}"
			;;
		rpm)
			ssh "${ssh_args[@]}" openshell@127.0.0.1 \
				"sudo dnf install -y --nogpgcheck ${quoted_packages}"
			;;
		esac
	fi

	artifact_index=0
	for copy_spec in "${copies[@]}"; do
		source_path=${copy_spec%%:*}
		destination=${copy_spec#*:}
		remote_path=${artifact_staging_dir}/copy-${artifact_index}
		echo "==> Copying artifact: ${destination}"
		scp -q "${scp_args[@]}" \
			"${source_path}" "openshell@127.0.0.1:${remote_path}"
		printf -v install_command \
			'sudo install -D -m 0755 -- %q %q' \
			"${remote_path}" "${destination}"
		ssh "${ssh_args[@]}" openshell@127.0.0.1 "${install_command}"
		artifact_index=$((artifact_index + 1))
	done

	ssh "${ssh_args[@]}" openshell@127.0.0.1 \
		"rm -rf -- '${artifact_staging_dir}'"
	report_timing "artifact transfer" "${phase_started_at}"
fi

# Configuration may change the test user's groups. Close the SSH control
# connection established before provisioning so subsequent commands start with
# the guest's current credentials.
ssh "${ssh_args[@]}" -O exit openshell@127.0.0.1 >/dev/null 2>&1 || true

echo "==> Test guest ready: ${distro} (SSH port ${ssh_port})"
if [ "${#guest_command[@]}" -eq 0 ]; then
	ssh -t "${ssh_args[@]}" "${ssh_forward_args[@]}" openshell@127.0.0.1
else
	printf -v quoted_command '%q ' "${guest_command[@]}"
	# quoted_command is shell-escaped locally before it reaches the guest.
	# shellcheck disable=SC2029
	ssh "${ssh_args[@]}" "${ssh_forward_args[@]}" \
		openshell@127.0.0.1 "bash -lc $(printf '%q' "${quoted_command}")"
fi

echo "==> Shutting down ${distro}"
if [ "${keep}" -eq 1 ]; then
	ssh "${ssh_args[@]}" openshell@127.0.0.1 'sudo systemctl poweroff' >/dev/null 2>&1 || true
	for _ in $(seq 1 120); do
		if ! kill -0 "${qemu_pid}" 2>/dev/null; then
			wait "${qemu_pid}" || true
			qemu_pid=
			break
		fi
		sleep 0.25
	done
else
	kill "${qemu_pid}" 2>/dev/null || true
	wait "${qemu_pid}" 2>/dev/null || true
	qemu_pid=
fi
