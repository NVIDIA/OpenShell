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
--vm selects the Ubuntu test guest. Set OPENSHELL_E2E_KEEP=1 to retain state.
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
vm_set=0
gateway_config=
gateway_config_set=0
suite_name=
suite_set=0
with_configurations=()

while [ "$#" -gt 0 ]; do
	case "$1" in
	--vm)
		require_value "$1" "$#" "${2:-}"
		if [ "${vm_set}" -eq 1 ]; then
			die "--vm may be supplied only once"
		fi
		vm=$2
		vm_set=1
		shift 2
		;;
	--with)
		require_value "$1" "$#" "${2:-}"
		with_configurations+=("$2")
		shift 2
		;;
	--gateway-config)
		require_value "$1" "$#" "${2:-}"
		if [ "${gateway_config_set}" -eq 1 ]; then
			die "--gateway-config may be supplied only once"
		fi
		gateway_config=$2
		gateway_config_set=1
		shift 2
		;;
	--suite)
		require_value "$1" "$#" "${2:-}"
		if [ "${suite_set}" -eq 1 ]; then
			die "--suite may be supplied only once"
		fi
		suite_name=$2
		suite_set=1
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

if [ "${gateway_config_set}" -ne 1 ]; then
	die "--gateway-config is required"
fi
if [ "${suite_set}" -ne 1 ]; then
	die "--suite is required"
fi
if ! command -v python3 >/dev/null 2>&1; then
	die "python3 is required"
fi
gateway_config_source=${gateway_config}
if ! gateway_config="$(resolve_file "${gateway_config_source}")"; then
	die "gateway config does not exist: ${gateway_config_source}"
fi
if [[ ! ${suite_name} =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
	die "suite name must contain only lowercase letters, digits, and hyphens: ${suite_name}"
fi
suite_path="${ROOT}/e2e/rust/tests/${suite_name}.rs"
if [ ! -f "${suite_path}" ]; then
	die "unknown suite: ${suite_name}"
fi
mode=host
if [ "${vm_set}" -eq 1 ] || [ "${#with_configurations[@]}" -gt 0 ]; then
	mode=vm
	if [ "${vm_set}" -eq 0 ]; then
		vm=ubuntu
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
	if ! command -v nix >/dev/null 2>&1; then
		die "Nix is required for VM mode"
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
target_dir="$(
	mise x -- cargo metadata --format-version=1 --no-deps |
		python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
)"

echo "==> Building native host openshell CLI"
mise x -- cargo build "${cargo_jobs[@]}" -p openshell-cli --bin openshell
host_cli_bin="${target_dir}/debug/openshell"

echo "==> Preparing ${linux_musl_target} build target"
mise x -- rustup target add "${linux_musl_target}" >/dev/null
ensure_build_nofile_limit

echo "==> Building Linux openshell-sandbox (${linux_musl_target})"
mise x -- cargo zigbuild "${cargo_jobs[@]}" \
	--release \
	--target "${linux_musl_target}" \
	-p openshell-sandbox \
	--bin openshell-sandbox
linux_sandbox_bin="${target_dir}/${linux_musl_target}/release/openshell-sandbox"

host_gateway_bin=
guest_cli_bin=
guest_gateway_bin=
if [ "${mode}" = host ]; then
	echo "==> Building native host openshell-gateway"
	mise x -- cargo build "${cargo_jobs[@]}" \
		-p openshell-server \
		--bin openshell-gateway \
		--features bundled-z3
	host_gateway_bin="${target_dir}/debug/openshell-gateway"
else
	if ! command -v base64 >/dev/null 2>&1; then
		die "base64 is required for VM mode"
	fi
	echo "==> Building Linux openshell CLI (${linux_musl_target})"
	CXXSTDLIB=c++ mise x -- cargo zigbuild "${cargo_jobs[@]}" \
		--release \
		--target "${linux_musl_target}" \
		-p openshell-cli \
		--bin openshell
	guest_cli_bin="${target_dir}/${linux_musl_target}/release/openshell"

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

for binary in "${host_cli_bin}" "${linux_sandbox_bin}"; do
	if [ ! -x "${binary}" ]; then
		echo "ERROR: expected built binary at ${binary}" >&2
		exit 1
	fi
done
if [ "${mode}" = host ] && [ ! -x "${host_gateway_bin}" ]; then
	echo "ERROR: expected built gateway at ${host_gateway_bin}" >&2
	exit 1
fi
if [ "${mode}" = vm ]; then
	for binary in "${guest_cli_bin}" "${guest_gateway_bin}"; do
		if [ ! -x "${binary}" ]; then
			echo "ERROR: expected built guest binary at ${binary}" >&2
			exit 1
		fi
	done
fi

run_parent="${ROOT}/.cache/openshell-e2e/runs"
mkdir -p "${run_parent}"
run_dir="$(mktemp -d "${run_parent%/}/run.XXXXXX")"
child_pid=
child_process_group=0
runtime_log=
portable_jwt_dir="${ROOT}/.cache/openshell-e2e/gateway-jwt"
keep=0
if [ "${OPENSHELL_E2E_KEEP:-0}" = 1 ]; then
	keep=1
fi

# Invoked by the EXIT trap through cleanup.
# shellcheck disable=SC2329
stop_child() {
	local pid=$1
	local process_group=$2
	local signal_target=${pid}

	if [ -z "${pid}" ] || ! kill -0 "${pid}" 2>/dev/null; then
		return
	fi
	if [ "${process_group}" -eq 1 ]; then
		signal_target="-${pid}"
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
	local incoming_status=$?
	local status=${1:-${incoming_status}}

	trap - EXIT INT TERM
	stop_child "${child_pid}" "${child_process_group}"
	if [ "${status}" -ne 0 ] && [ -n "${runtime_log}" ] && [ -f "${runtime_log}" ]; then
		echo "=== ${mode} gateway log ===" >&2
		cat "${runtime_log}" >&2
		echo "=== end ${mode} gateway log ===" >&2
	fi
	if [ "${keep}" -eq 1 ]; then
		echo "Kept E2E wrapper state at ${run_dir}" >&2
	else
		rm -f \
			"${portable_jwt_dir}/signing.pem" \
			"${portable_jwt_dir}/public.pem" \
			"${portable_jwt_dir}/kid"
		rmdir "${portable_jwt_dir}" 2>/dev/null || true
		rm -rf "${run_dir}"
	fi
	exit "${status}"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

jwt_source_dir="${run_dir}/gateway-jwt"
e2e_generate_gateway_jwt "${jwt_source_dir}"
mkdir -p "${portable_jwt_dir}"
install -m 0600 "${jwt_source_dir}/signing.pem" "${portable_jwt_dir}/signing.pem"
install -m 0600 "${jwt_source_dir}/public.pem" "${portable_jwt_dir}/public.pem"
install -m 0600 "${jwt_source_dir}/kid" "${portable_jwt_dir}/kid"

host_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
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
e2e_register_plaintext_gateway \
	"${XDG_CONFIG_HOME}" \
	"${gateway_name}" \
	"${gateway_endpoint}" \
	"${host_port}"

with_contract="${with_configurations[*]}"
export OPENSHELL_GATEWAY_ENDPOINT="${gateway_endpoint}"
export OPENSHELL_GATEWAY="${gateway_name}"
export OPENSHELL_BIN="${host_cli_bin}"
export OPENSHELL_E2E_MODE="${mode}"
export OPENSHELL_E2E_VM="${vm}"
export OPENSHELL_E2E_WITH="${with_contract}"
export OPENSHELL_E2E_GATEWAY_CONFIG="${gateway_config}"
export OPENSHELL_E2E_HOST_PORT="${host_port}"
export OPENSHELL_E2E_GUEST_PORT="${guest_port}"

staged_supervisor="${ROOT}/.cache/openshell-e2e/bin/openshell-sandbox"
mkdir -p "$(dirname "${staged_supervisor}")"
ln -sfn "${linux_sandbox_bin}" "${staged_supervisor}"

if [ "${mode}" = host ]; then
	e2e_align_docker_host_with_cli_context
	runtime_log="${run_dir}/gateway.log"
	echo "==> Starting host gateway at ${gateway_endpoint}"
	(
		cd "${ROOT}"
		exec "${host_gateway_bin}" \
			--config "${gateway_config}" \
			--bind-address 127.0.0.1 \
			--port "${host_port}" \
			--disable-tls
	) >"${runtime_log}" 2>&1 &
	child_pid=$!
	child_process_group=0
else
	runtime_log="${run_dir}/vm.log"
	guest_launcher="${run_dir}/launch-gateway.sh"
	guest_launcher_path="/home/openshell/.cache/openshell-e2e/bin/launch-gateway"
	config_payload="$(base64 <"${gateway_config}" | tr -d '\r\n')"
	jwt_signing_payload="$(base64 <"${jwt_source_dir}/signing.pem" | tr -d '\r\n')"
	jwt_public_payload="$(base64 <"${jwt_source_dir}/public.pem" | tr -d '\r\n')"
	jwt_kid_payload="$(base64 <"${jwt_source_dir}/kid" | tr -d '\r\n')"
	cat >"${guest_launcher}" <<EOF
#!/usr/bin/env bash
set -euo pipefail

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
cd /home/openshell
exec /usr/local/bin/openshell-gateway \
	--config "\${config_path}" \
	--bind-address 0.0.0.0 \
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
		--copy "${guest_cli_bin}:/usr/local/bin/openshell"
		--copy "${guest_gateway_bin}:/usr/local/bin/openshell-gateway"
		--copy "${linux_sandbox_bin}:/home/openshell/.cache/openshell-e2e/bin/openshell-sandbox"
		--copy "${guest_launcher}:${guest_launcher_path}"
		--forward-port "${host_port}:${guest_port}"
	)
	if [ "${keep}" -eq 1 ]; then
		vm_args+=(--keep)
	fi
	vm_args+=(-- "${guest_launcher_path}")

	echo "==> Starting ${vm} test guest gateway at ${gateway_endpoint}"
	(
		cd "${ROOT}"
		exec python3 -c \
			'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
			"${vm_args[@]}"
	) >"${runtime_log}" 2>&1 &
	child_pid=$!
	child_process_group=1
fi
export OPENSHELL_E2E_RUNTIME_LOG="${runtime_log}"

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

	echo "==> Waiting up to ${gateway_ready_timeout}s for gateway readiness"
	while :; do
		elapsed=$((SECONDS - started_at))
		if [ "${elapsed}" -ge "${gateway_ready_timeout}" ]; then
			break
		fi
		if ! kill -0 "${child_pid}" 2>/dev/null; then
			wait "${child_pid}"
			process_status=$?
			child_pid=
			echo "ERROR: ${mode} gateway process exited before becoming ready" >&2
			if [ "${process_status}" -eq 0 ]; then
				return 1
			fi
			return "${process_status}"
		fi
		if probe_gateway "${probe_log}" &&
			grep -q "Connected" "${probe_log}"; then
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

set +e
wait_for_gateway
readiness_status=$?
set -e
if [ "${readiness_status}" -ne 0 ]; then
	cleanup "${readiness_status}"
fi

echo "==> Running E2E suite: ${suite_name}"
cd "${ROOT}"
set +e
cargo test \
	--manifest-path e2e/rust/Cargo.toml \
	--features e2e \
	--test "${suite_name}" \
	-- --nocapture
suite_status=$?
set -e
cleanup "${suite_status}"
