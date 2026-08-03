#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build the current checkout, run its gateway on the host or in a disposable
# Nix test guest, and execute one named host-side E2E suite against that gateway.

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1091
source "${ROOT}/e2e/support/gateway-common.sh"
# shellcheck disable=SC1091
source "${ROOT}/tasks/scripts/build-env.sh"

e2e_preserve_mise_dirs

usage() {
	cat <<'EOF'
Usage:
  e2e/run.sh [--vm DISTRO] [--with CONFIG ...] \
    --gateway-config PATH --suite NAME

Options:
  --vm DISTRO          Run the gateway in a Nix test guest
  --with CONFIG        Apply a Nix test-guest configuration; repeatable
  --gateway-config PATH
                       Fully resolved gateway TOML
  --suite NAME         Rust suite at e2e/rust/tests/NAME.rs
  -h, --help           Show this help

Omit --vm and --with to run the gateway on the host. Supplying --with without
--vm selects Fedora for the Podman driver and Ubuntu otherwise. Set
OPENSHELL_E2E_KEEP=1 to retain state.
EOF
}

die() {
	echo "ERROR: $*" >&2
	exit 2
}

require_value() {
	local option=$1
	local count=$2
	local value=${3:-}

	if [ "${count}" -lt 2 ] || [ -z "${value}" ]; then
		die "${option} requires a value"
	fi
	case "${value}" in
	--*) die "${option} requires a value" ;;
	esac
}

resolve_file() {
	local path=$1

	if [ ! -f "${path}" ]; then
		return 1
	fi
	python3 - "${path}" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
}

catalog_has_entry() {
	local catalog=$1
	local section=$2
	local name=$3

	printf '%s\n' "${catalog}" | awk -v wanted_section="${section}:" -v wanted_name="${name}" '
		$0 == wanted_section {
			in_section = 1
			next
		}
		/^[^[:space:]]/ {
			in_section = 0
		}
		in_section && $0 == "  " wanted_name {
			found = 1
		}
		END {
			exit(found ? 0 : 1)
		}
	'
}

vm=
gateway_config=
suite_name=
with_configurations=()

while [ "$#" -gt 0 ]; do
	case "$1" in
	--vm)
		require_value "$1" "$#" "${2:-}"
		vm=$2
		shift 2
		;;
	--with)
		require_value "$1" "$#" "${2:-}"
		with_configurations+=("$2")
		shift 2
		;;
	--gateway-config)
		require_value "$1" "$#" "${2:-}"
		gateway_config=$2
		shift 2
		;;
	--suite)
		require_value "$1" "$#" "${2:-}"
		suite_name=$2
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		die "unknown argument: $1"
		;;
	esac
done

if [ -z "${gateway_config}" ]; then
	die "--gateway-config is required"
fi
if [ -z "${suite_name}" ]; then
	die "--suite is required"
fi
if ! command -v python3 >/dev/null 2>&1; then
	die "python3 is required"
fi
gateway_config_source=${gateway_config}
if ! gateway_config="$(resolve_file "${gateway_config_source}")"; then
	die "gateway config does not exist: ${gateway_config_source}"
fi
gateway_driver="$(python3 -c '
import sys, tomllib
print(tomllib.load(open(sys.argv[1], "rb"))["openshell"]["gateway"]["compute_drivers"][0])
' "${gateway_config}")"
if [[ ! ${suite_name} =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
	die "suite name must contain only lowercase letters, digits, and hyphens: ${suite_name}"
fi
suite_path="${ROOT}/e2e/rust/tests/${suite_name}.rs"
if [ ! -f "${suite_path}" ]; then
	die "unknown suite: ${suite_name}"
fi
mode=host
if [ -n "${vm}" ] || [ "${#with_configurations[@]}" -gt 0 ]; then
	mode=vm
	if [ -z "${vm}" ]; then
		if [ "${gateway_driver}" = podman ]; then
			vm=fedora
		else
			vm=ubuntu
		fi
	fi
fi
if [ "${mode}" = vm ]; then
	if [[ ! ${vm} =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
		die "invalid VM distro name: ${vm}"
	fi
	for configuration in "${with_configurations[@]}"; do
		if [[ ! ${configuration} =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
			die "invalid VM configuration name: ${configuration}"
		fi
	done
	if [ "${gateway_driver}" = podman ] && [ "${vm}" = ubuntu ]; then
		die "the Ubuntu 24.04 guest lacks the Podman 5 pasta helper required for sandbox callbacks; use --vm fedora --with podman"
	fi
	if ! command -v nix >/dev/null 2>&1; then
		die "Nix is required for VM mode"
	fi
	if ! command -v base64 >/dev/null 2>&1; then
		die "base64 is required for VM mode"
	fi
	if ! vm_catalog="$(cd "${ROOT}" && nix run .#test-guest -- --list)"; then
		die "failed to read the Nix test-guest catalog"
	fi
	if ! catalog_has_entry "${vm_catalog}" Distros "${vm}"; then
		die "unknown VM distro in the Nix test-guest catalog: ${vm}"
	fi
	for configuration in "${with_configurations[@]}"; do
		if ! catalog_has_entry "${vm_catalog}" Configurations "${configuration}"; then
			die "unknown VM configuration in the Nix test-guest catalog: ${configuration}"
		fi
	done
fi

gateway_ready_timeout=${OPENSHELL_E2E_GATEWAY_READY_TIMEOUT:-600}
if [[ ! ${gateway_ready_timeout} =~ ^[1-9][0-9]*$ ]]; then
	die "OPENSHELL_E2E_GATEWAY_READY_TIMEOUT must be a positive integer"
fi
if ! command -v mise >/dev/null 2>&1; then
	die "mise is required to build OpenShell"
fi
if ! command -v openssl >/dev/null 2>&1; then
	die "OpenSSL is required to generate sandbox JWT keys"
fi

case "$(uname -m)" in
x86_64 | amd64)
	linux_musl_target=x86_64-unknown-linux-musl
	linux_gateway_rust_target=x86_64-unknown-linux-gnu
	linux_gateway_zig_target=x86_64-unknown-linux-gnu.2.28
	;;
aarch64 | arm64)
	linux_musl_target=aarch64-unknown-linux-musl
	linux_gateway_rust_target=aarch64-unknown-linux-gnu
	linux_gateway_zig_target=aarch64-unknown-linux-gnu.2.28
	;;
*)
	die "unsupported host architecture: $(uname -m)"
	;;
esac

cargo_jobs=()
if [ -n "${CARGO_BUILD_JOBS:-}" ]; then
	cargo_jobs=(-j "${CARGO_BUILD_JOBS}")
fi

cd "${ROOT}"
target_dir="$(e2e_cargo_target_dir "${ROOT}" mise x -- cargo)"

ensure_build_nofile_limit

echo "==> Building native host openshell CLI"
mise x -- cargo build "${cargo_jobs[@]}" -p openshell-cli --bin openshell
host_cli_bin="${target_dir}/debug/openshell"

echo "==> Preparing ${linux_musl_target} build target"
mise x -- rustup target add "${linux_musl_target}" >/dev/null

echo "==> Building Linux openshell-sandbox (${linux_musl_target})"
mise x -- cargo zigbuild "${cargo_jobs[@]}" \
	--release \
	--target "${linux_musl_target}" \
	-p openshell-sandbox \
	--bin openshell-sandbox
linux_sandbox_bin="${target_dir}/${linux_musl_target}/release/openshell-sandbox"

host_gateway_bin=
guest_gateway_bin=
if [ "${mode}" = host ]; then
	echo "==> Building native host openshell-gateway"
	mise x -- cargo build "${cargo_jobs[@]}" \
		-p openshell-server \
		--bin openshell-gateway \
		--features bundled-z3
	host_gateway_bin="${target_dir}/debug/openshell-gateway"
else
	echo "==> Preparing ${linux_gateway_rust_target} build target"
	mise x -- rustup target add "${linux_gateway_rust_target}" >/dev/null
	echo "==> Building Linux openshell-gateway (${linux_gateway_zig_target})"
	(
		eval "$(
			"${ROOT}/tasks/scripts/setup-zig-cc-wrapper.sh" \
				"${linux_gateway_zig_target}" \
				"${linux_gateway_zig_target}" \
				"${target_dir}/zig-gnu-wrapper/e2e"
		)"
		mise x -- cargo zigbuild "${cargo_jobs[@]}" \
			--release \
			--target "${linux_gateway_zig_target}" \
			-p openshell-server \
			--bin openshell-gateway \
			--features bundled-z3
	)
	guest_gateway_bin="${target_dir}/${linux_gateway_rust_target}/release/openshell-gateway"
fi

expected_binaries=("${host_cli_bin}" "${linux_sandbox_bin}")
if [ "${mode}" = host ]; then
	expected_binaries+=("${host_gateway_bin}")
else
	expected_binaries+=("${guest_gateway_bin}")
fi
for binary in "${expected_binaries[@]}"; do
	if [ ! -x "${binary}" ]; then
		echo "ERROR: expected built binary at ${binary}" >&2
		exit 1
	fi
done

run_parent="${ROOT}/.cache/openshell-e2e/runs"
mkdir -p "${run_parent}"
run_dir="$(mktemp -d "${run_parent%/}/run.XXXXXX")"
if ! command -v tar >/dev/null 2>&1; then
	die "tar is required to package the supervisor image"
fi
supervisor_image=localhost/openshell/supervisor:e2e-vm
supervisor_rootfs="${run_dir}/supervisor-rootfs"
supervisor_archive="${run_dir}/supervisor.tar"
mkdir -p "${supervisor_rootfs}"
install -m 0555 "${linux_sandbox_bin}" "${supervisor_rootfs}/openshell-sandbox"
tar -C "${supervisor_rootfs}" -cf "${supervisor_archive}" openshell-sandbox
child_pid=
runtime_log=
keep=0
if [ "${OPENSHELL_E2E_KEEP:-0}" = 1 ]; then
	keep=1
fi

start_child() {
	local working_dir=$1
	local log_path=$2
	shift 2

	(
		cd "${working_dir}"
		exec python3 -c \
			'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
			"$@"
	) >"${log_path}" 2>&1 &
	child_pid=$!
}

# Invoked by the EXIT trap through cleanup.
# shellcheck disable=SC2329
stop_child() {
	local pid=$1
	local signal_target="-${pid}"

	if [ -z "${pid}" ] || ! kill -0 "${pid}" 2>/dev/null; then
		return
	fi
	kill -TERM -- "${signal_target}" 2>/dev/null || true
	for _ in $(seq 1 30); do
		if ! kill -0 "${pid}" 2>/dev/null; then
			break
		fi
		sleep 1
	done
	if kill -0 "${pid}" 2>/dev/null; then
		kill -KILL -- "${signal_target}" 2>/dev/null || true
	fi
	wait "${pid}" 2>/dev/null || true
}

# Invoked by EXIT, INT, and TERM traps.
# shellcheck disable=SC2329
cleanup() {
	local status=$?

	trap - EXIT INT TERM
	stop_child "${child_pid}"
	if [ "${status}" -ne 0 ] && [ -n "${runtime_log}" ] && [ -f "${runtime_log}" ]; then
		echo "=== ${mode} gateway log ===" >&2
		cat "${runtime_log}" >&2
		echo "=== end ${mode} gateway log ===" >&2
	fi
	if [ "${keep}" -eq 1 ]; then
		echo "Kept E2E runner state at ${run_dir}" >&2
	else
		rm -rf "${run_dir}"
	fi
	exit "${status}"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

jwt_source_dir="${run_dir}/gateway-jwt"
host_runtime_dir=
if [ "${mode}" = host ]; then
	host_runtime_dir="${run_dir}/host-runtime"
	jwt_source_dir="${host_runtime_dir}/.cache/openshell-e2e/gateway-jwt"
fi
e2e_generate_gateway_jwt "${jwt_source_dir}"

host_port="$(e2e_pick_port)"
guest_port=
if [ "${mode}" = vm ]; then
	guest_port=8080
fi

export XDG_CONFIG_HOME="${run_dir}/host/config"
export XDG_DATA_HOME="${run_dir}/host/data"
export XDG_STATE_HOME="${run_dir}/host/state"
mkdir -p "${XDG_CONFIG_HOME}" "${XDG_DATA_HOME}" "${XDG_STATE_HOME}"

gateway_name="openshell-e2e-${mode}-${host_port}"
gateway_endpoint="http://127.0.0.1:${host_port}"
export OPENSHELL_GATEWAY_ENDPOINT="${gateway_endpoint}"
export OPENSHELL_GATEWAY="${gateway_name}"
export OPENSHELL_BIN="${host_cli_bin}"

if [ "${mode}" = host ]; then
	case "${gateway_driver}" in
	docker)
		e2e_align_docker_host_with_cli_context
		docker import \
			--change 'ENTRYPOINT ["/openshell-sandbox"]' \
			"${supervisor_archive}" \
			"${supervisor_image}" >/dev/null
		;;
	podman)
		podman import \
			--change 'ENTRYPOINT ["/openshell-sandbox"]' \
			"${supervisor_archive}" \
			"${supervisor_image}" >/dev/null
		;;
	esac

	runtime_log="${run_dir}/gateway.log"
	echo "==> Starting host gateway at ${gateway_endpoint}"
	start_child \
		"${host_runtime_dir}" \
		"${runtime_log}" \
		"${host_gateway_bin}" \
		--config "${gateway_config}" \
		--bind-address 127.0.0.1 \
		--port "${host_port}" \
		--disable-tls
else
	runtime_log="${run_dir}/vm.log"
	guest_launcher="${run_dir}/launch-gateway.sh"
	guest_launcher_path=/home/openshell/.cache/openshell-e2e/bin/launch-gateway
	guest_supervisor_archive_path=/home/openshell/.cache/openshell-e2e/supervisor.tar
	config_payload="$(base64 <"${gateway_config}" | tr -d '\r\n')"
	jwt_signing_payload="$(base64 <"${jwt_source_dir}/signing.pem" | tr -d '\r\n')"
	jwt_public_payload="$(base64 <"${jwt_source_dir}/public.pem" | tr -d '\r\n')"
	jwt_kid_payload="$(base64 <"${jwt_source_dir}/kid" | tr -d '\r\n')"
	cat >"${guest_launcher}" <<EOF
#!/usr/bin/env bash
set -euo pipefail

report_timing() {
	local label=\$1
	local started_at=\$2

	echo "==> Timing: \${label}: \$((SECONDS - started_at))s"
}

phase_started_at=\${SECONDS}
umask 077
state_root=/home/openshell/.cache/openshell-e2e
config_path=\${state_root}/gateway.toml
jwt_root=\${state_root}/gateway-jwt
sudo chown -R "\$(id -u):\$(id -g)" /home/openshell/.cache
chmod 0700 "\${state_root}"
mkdir -p "\${state_root}/xdg/cache" "\${state_root}/xdg/config" "\${state_root}/xdg/data" "\${state_root}/xdg/state" "\${jwt_root}"
printf '%s' '${config_payload}' | base64 --decode >"\${config_path}"
printf '%s' '${jwt_signing_payload}' | base64 --decode >"\${jwt_root}/signing.pem"
printf '%s' '${jwt_public_payload}' | base64 --decode >"\${jwt_root}/public.pem"
printf '%s' '${jwt_kid_payload}' | base64 --decode >"\${jwt_root}/kid"
chmod 0600 "\${config_path}"
chmod 0600 "\${jwt_root}/signing.pem" "\${jwt_root}/public.pem" "\${jwt_root}/kid"
export XDG_CONFIG_HOME=\${state_root}/xdg/config
export XDG_CACHE_HOME=\${state_root}/xdg/cache
export XDG_DATA_HOME=\${state_root}/xdg/data
export XDG_STATE_HOME=\${state_root}/xdg/state
report_timing "guest gateway setup" "\${phase_started_at}"
phase_started_at=\${SECONDS}
case '${gateway_driver}' in
docker)
	docker import \
		--change 'ENTRYPOINT ["/openshell-sandbox"]' \
		"${guest_supervisor_archive_path}" \
		"${supervisor_image}" >/dev/null
	;;
podman)
	podman --url "unix:///run/user/\$(id -u)/podman/podman.sock" import \
		--change 'ENTRYPOINT ["/openshell-sandbox"]' \
		"${guest_supervisor_archive_path}" \
		"${supervisor_image}" >/dev/null
	;;
esac
report_timing "${gateway_driver} supervisor import" "\${phase_started_at}"
cd /home/openshell
exec /usr/local/bin/openshell-gateway \
	--config "\${config_path}" \
	--bind-address 127.0.0.1 \
	--port ${guest_port} \
	--disable-tls
EOF
	chmod 0700 "${guest_launcher}"

	vm_args=(
		nix run .#test-guest --
		--distro "${vm}"
	)
	for configuration in "${with_configurations[@]}"; do
		vm_args+=(--with "${configuration}")
	done
	vm_args+=(
		--copy "${guest_gateway_bin}:/usr/local/bin/openshell-gateway"
		--copy "${guest_launcher}:${guest_launcher_path}"
		--copy "${supervisor_archive}:${guest_supervisor_archive_path}"
		--forward-port "${host_port}:${guest_port}"
	)
	if [ "${keep}" -eq 1 ]; then
		vm_args+=(--keep)
	fi
	vm_args+=(-- "${guest_launcher_path}")

	echo "==> Starting ${vm} test guest gateway at ${gateway_endpoint}"
	start_child "${ROOT}" "${runtime_log}" "${vm_args[@]}"
fi

probe_gateway() {
	python3 - "${OPENSHELL_BIN}" "${1}" <<'PY'
import os
import subprocess
import sys

with open(sys.argv[2], "wb") as output:
    try:
        result = subprocess.run(
            [sys.argv[1], "status"],
            env={**os.environ, "NO_COLOR": "1"},
            stdout=output,
            stderr=subprocess.STDOUT,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit(124)
raise SystemExit(result.returncode)
PY
}

wait_for_gateway() {
	local started_at=${SECONDS}
	local elapsed=0
	local process_status
	local probe_log="${run_dir}/gateway-probe.log"
	local reported_timings=0
	local timing_count

	report_vm_progress() {
		if [ "${mode}" != vm ]; then
			return
		fi
		timing_count="$(grep -c '^==> Timing:' "${runtime_log}" || true)"
		if [ "${timing_count}" -le "${reported_timings}" ]; then
			return
		fi
		sed -n 's/^==> Timing: /    /p' "${runtime_log}" |
			sed -n "$((reported_timings + 1)),${timing_count}p"
		reported_timings=${timing_count}
	}

	echo "==> Waiting up to ${gateway_ready_timeout}s for gateway readiness"
	while :; do
		elapsed=$((SECONDS - started_at))
		if [ "${elapsed}" -ge "${gateway_ready_timeout}" ]; then
			break
		fi
		if ! kill -0 "${child_pid}" 2>/dev/null; then
			if wait "${child_pid}"; then
				process_status=0
			else
				process_status=$?
			fi
			child_pid=
			echo "ERROR: ${mode} gateway process exited before becoming ready" >&2
			if [ "${process_status}" -eq 0 ]; then
				return 1
			fi
			return "${process_status}"
		fi
		report_vm_progress
		if probe_gateway "${probe_log}" &&
			grep -q "Connected" "${probe_log}"; then
			report_vm_progress
			echo "==> Gateway ready after ${elapsed}s"
			return 0
		fi
		sleep 1
	done

	echo "ERROR: gateway did not become ready within ${gateway_ready_timeout}s" >&2
	if [ -s "${probe_log}" ]; then
		echo "=== last gateway probe ===" >&2
		cat "${probe_log}" >&2
		echo "=== end last gateway probe ===" >&2
	fi
	return 1
}

wait_for_gateway

echo "==> Running E2E suite: ${suite_name}"
cd "${ROOT}"
cargo test \
	--manifest-path e2e/rust/Cargo.toml \
	--features e2e \
	--test "${suite_name}" \
	-- --nocapture
