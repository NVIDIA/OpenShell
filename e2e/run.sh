#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build the current checkout, run its gateway on the host or in a disposable
# Nix test guest, and execute E2E tests against that gateway.

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
    --gateway-config PATH [--features FEATURES] [--suite NAME]

Options:
  --vm DISTRO          Run the gateway in a Nix test guest
  --with CONFIG        Apply a Nix test-guest configuration; repeatable
  --tests-in-vm        Prebuild Linux Rust E2E test binaries on the host,
                       copy them into the Nix test guest, and run them there
  --cli-bin PATH       Use a prebuilt openshell CLI instead of building it
  --gateway-bin PATH   Use a prebuilt openshell-gateway instead of building it
  --sandbox-bin PATH   Use a prebuilt openshell-sandbox instead of building it
  --gateway-config PATH
                       Fully resolved gateway TOML
  --features FEATURES  Rust e2e feature set to enable (default: e2e)
  --suite NAME         Rust suite at e2e/rust/tests/NAME.rs
  -h, --help           Show this help

Omit --vm and --with to run the gateway on the host. Supplying --with without
--vm selects Fedora for the Podman driver and Ubuntu otherwise. Set
OPENSHELL_CLI_BIN for a default --cli-bin; otherwise --tests-in-vm
cross-builds the guest CLI with cargo-zigbuild. Set OPENSHELL_E2E_KEEP=1 to
retain state.
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
gateway_bin=
cli_bin=
sandbox_bin=
e2e_features=e2e
suite_name=
tests_in_vm=0
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
	--tests-in-vm)
		tests_in_vm=1
		shift
		;;
	--cli-bin)
		require_value "$1" "$#" "${2:-}"
		cli_bin="$(resolve_file "$2")" || die "--cli-bin does not name a file: $2"
		shift 2
		;;
	--gateway-bin)
		require_value "$1" "$#" "${2:-}"
		gateway_bin="$(resolve_file "$2")" || die "--gateway-bin does not name a file: $2"
		shift 2
		;;
	--sandbox-bin)
		require_value "$1" "$#" "${2:-}"
		sandbox_bin="$(resolve_file "$2")" || die "--sandbox-bin does not name a file: $2"
		shift 2
		;;
	--gateway-config)
		require_value "$1" "$#" "${2:-}"
		gateway_config=$2
		shift 2
		;;
	--features)
		require_value "$1" "$#" "${2:-}"
		e2e_features=$2
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
if ! command -v python3 >/dev/null 2>&1; then
	die "python3 is required"
fi
if ! command -v mise >/dev/null 2>&1; then
	die "mise is required to build OpenShell"
fi
gateway_config_source=${gateway_config}
if ! gateway_config="$(resolve_file "${gateway_config_source}")"; then
	die "gateway config does not exist: ${gateway_config_source}"
fi
gateway_driver="$(mise x -- python3 -c '
import sys, tomllib
print(tomllib.load(open(sys.argv[1], "rb"))["openshell"]["gateway"]["compute_drivers"][0])
' "${gateway_config}")"
if [ -z "${e2e_features}" ]; then
	die "--features must not be empty"
fi
if [ -n "${suite_name}" ]; then
	if [[ ! ${suite_name} =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
		die "suite name must contain only lowercase letters, digits, underscores, and hyphens: ${suite_name}"
	fi
	suite_path="${ROOT}/e2e/rust/tests/${suite_name}.rs"
	if [ ! -f "${suite_path}" ]; then
		die "unknown suite: ${suite_name}"
	fi
fi
mode=host
if [ -n "${vm}" ] || [ "${#with_configurations[@]}" -gt 0 ]; then
	mode=vm
	if [ -z "${vm}" ]; then
		if [ "${gateway_driver}" = podman ]; then
			vm=fedora
		else
			vm=ubuntu-24-04
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
	if [ "${gateway_driver}" = podman ] && [ "${vm}" = ubuntu-24-04 ]; then
		die "the Ubuntu 24.04 guest lacks the Podman 5 pasta helper required for sandbox callbacks; use --vm ubuntu-26-04 --with podman"
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
elif [ "${tests_in_vm}" -eq 1 ]; then
	die "--tests-in-vm requires --vm"
fi
if [ -z "${cli_bin}" ] && [ -n "${OPENSHELL_CLI_BIN:-}" ]; then
	cli_bin="$(resolve_file "${OPENSHELL_CLI_BIN}")" ||
		die "OPENSHELL_CLI_BIN does not name a file: ${OPENSHELL_CLI_BIN}"
fi
gateway_ready_timeout=${OPENSHELL_E2E_GATEWAY_READY_TIMEOUT:-600}
if [[ ! ${gateway_ready_timeout} =~ ^[1-9][0-9]*$ ]]; then
	die "OPENSHELL_E2E_GATEWAY_READY_TIMEOUT must be a positive integer"
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

if [ "${tests_in_vm}" -eq 1 ]; then
	if [ -n "${cli_bin}" ]; then
		echo "==> Using Linux guest openshell CLI: ${cli_bin}"
	else
		echo "==> Building Linux guest openshell CLI (${linux_musl_target})"
		mise x -- rustup target add "${linux_musl_target}" >/dev/null
		(
			export CXXSTDLIB=c++
			mise x -- cargo zigbuild "${cargo_jobs[@]+"${cargo_jobs[@]}"}" \
				--release \
				--target "${linux_musl_target}" \
				-p openshell-cli \
				--bin openshell
		)
		cli_bin="${target_dir}/${linux_musl_target}/release/openshell"
	fi
elif [ -n "${cli_bin}" ]; then
	echo "==> Using host openshell CLI: ${cli_bin}"
else
	echo "==> Building native host openshell CLI"
	mise x -- cargo build "${cargo_jobs[@]+"${cargo_jobs[@]}"}" -p openshell-cli --bin openshell
	cli_bin="${target_dir}/debug/openshell"
fi

if [ -n "${sandbox_bin}" ]; then
	echo "==> Using Linux openshell-sandbox: ${sandbox_bin}"
	linux_sandbox_bin="${sandbox_bin}"
else
	echo "==> Preparing ${linux_musl_target} build target"
	mise x -- rustup target add "${linux_musl_target}" >/dev/null

	echo "==> Building Linux openshell-sandbox (${linux_musl_target})"
	mise x -- cargo zigbuild "${cargo_jobs[@]+"${cargo_jobs[@]}"}" \
		--release \
		--target "${linux_musl_target}" \
		-p openshell-sandbox \
		--bin openshell-sandbox
	linux_sandbox_bin="${target_dir}/${linux_musl_target}/release/openshell-sandbox"
fi

host_gateway_bin=
guest_gateway_bin=
if [ "${mode}" = host ]; then
	if [ -n "${gateway_bin}" ]; then
		echo "==> Using host openshell-gateway: ${gateway_bin}"
		host_gateway_bin="${gateway_bin}"
	else
		echo "==> Building native host openshell-gateway"
		mise x -- cargo build "${cargo_jobs[@]+"${cargo_jobs[@]}"}" \
			-p openshell-server \
			--bin openshell-gateway \
			--features bundled-z3
		host_gateway_bin="${target_dir}/debug/openshell-gateway"
	fi
else
	if [ -n "${gateway_bin}" ]; then
		echo "==> Using Linux openshell-gateway: ${gateway_bin}"
		guest_gateway_bin="${gateway_bin}"
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
			mise x -- cargo zigbuild "${cargo_jobs[@]+"${cargo_jobs[@]}"}" \
				--release \
				--target "${linux_gateway_zig_target}" \
				-p openshell-server \
				--bin openshell-gateway \
				--features bundled-z3
		)
		guest_gateway_bin="${target_dir}/${linux_gateway_rust_target}/release/openshell-gateway"
	fi
fi

expected_binaries=("${linux_sandbox_bin}")
if [ "${tests_in_vm}" -eq 1 ]; then
	expected_binaries+=("${cli_bin}" "${guest_gateway_bin}")
elif [ "${mode}" = host ]; then
	expected_binaries+=("${cli_bin}" "${host_gateway_bin}")
else
	expected_binaries+=("${cli_bin}" "${guest_gateway_bin}")
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
chmod 0644 "${supervisor_archive}"
test_artifacts=()
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

build_e2e_test_artifacts() {
	local build_log="${run_dir}/e2e-test-build.jsonl"
	local artifacts_file="${run_dir}/e2e-test-artifacts.txt"
	local build_args=(
		mise x -- cargo zigbuild
		--manifest-path e2e/rust/Cargo.toml
		--features "${e2e_features}"
		--target "${linux_gateway_zig_target}"
		--message-format=json
	)
	if [ -n "${suite_name}" ]; then
		build_args+=(--test "${suite_name}")
	else
		build_args+=(--tests)
	fi

	echo "==> Prebuilding E2E test artifacts for guest execution (${linux_gateway_rust_target})"
	if ! (
		eval "$(
			"${ROOT}/tasks/scripts/setup-zig-cc-wrapper.sh" \
				"${linux_gateway_zig_target}" \
				"${linux_gateway_zig_target}" \
				"${target_dir}/zig-gnu-wrapper/e2e-tests"
		)"
		"${build_args[@]}"
	) >"${build_log}"; then
		echo "=== E2E test artifact build output ===" >&2
		cat "${build_log}" >&2
		echo "=== end E2E test artifact build output ===" >&2
		return 1
	fi
	python3 - "${build_log}" >"${artifacts_file}" <<'PY'
import json
import sys

for line in open(sys.argv[1], encoding="utf-8"):
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        continue
    if message.get("reason") != "compiler-artifact":
        continue
    target = message.get("target") or {}
    if "test" not in (target.get("kind") or []):
        continue
    executable = message.get("executable")
    if executable:
        print(executable)
PY
	while IFS= read -r artifact; do
		if [ -n "${artifact}" ]; then
			test_artifacts+=("${artifact}")
		fi
	done <"${artifacts_file}"
	if [ "${#test_artifacts[@]}" -eq 0 ]; then
		die "cargo did not report any E2E test executables"
	fi
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

if [ "${tests_in_vm}" -eq 1 ]; then
	build_e2e_test_artifacts
fi

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
export OPENSHELL_BIN="${cli_bin}"

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
	guest_test_artifact_dir=/home/openshell/.cache/openshell-e2e/tests
	guest_test_manifest="${run_dir}/test-artifacts.txt"
	guest_test_manifest_path=/home/openshell/.cache/openshell-e2e/test-artifacts.txt
	if [ "${tests_in_vm}" -eq 1 ]; then
		: >"${guest_test_manifest}"
		for artifact in "${test_artifacts[@]}"; do
			printf '%s/%s\n' "${guest_test_artifact_dir}" "${artifact##*/}" >>"${guest_test_manifest}"
		done
		chmod 0644 "${guest_test_manifest}"
	fi
	guest_e2e_network_name="$(mise x -- python3 - "${gateway_config}" <<'PY'
import sys, tomllib

config = tomllib.load(open(sys.argv[1], "rb"))
print(config.get("openshell", {}).get("drivers", {}).get("podman", {}).get("network_name", "openshell-e2e"))
PY
)"
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

if [ '${tests_in_vm}' = 1 ]; then
	gateway_log=\${state_root}/gateway.log
	gateway_pid_file=\${state_root}/gateway.pid
	gateway_args_file=\${state_root}/gateway.args
	spiffe_root=\${state_root}/spiffe
	mkdir -p "\${spiffe_root}" "${guest_test_artifact_dir}"

	toml_string() {
		python3 - "\$1" <<'PY'
import json
import sys

print(json.dumps(sys.argv[1]))
PY
	}

	pick_free_port() {
		python3 - <<'PY'
import socket

sock = socket.socket()
sock.bind(("0.0.0.0", 0))
print(sock.getsockname()[1])
sock.close()
PY
	}

	insert_podman_config_key() {
		local key=\$1
		local value=\$2

		python3 - "\${config_path}" "\${key}" "\${value}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]
section = "[openshell.drivers.podman]"
lines = path.read_text(encoding="utf-8").splitlines()
try:
    start = next(index for index, line in enumerate(lines) if line.strip() == section)
except StopIteration:
    raise SystemExit(f"{section} not found in {path}")
end = len(lines)
for index in range(start + 1, len(lines)):
    if lines[index].lstrip().startswith("["):
        end = index
        break
for line in lines[start + 1:end]:
    if line.split("=", 1)[0].strip() == key:
        raise SystemExit(0)
lines.insert(end, f"{key} = {value}")
path.write_text("\\n".join(lines) + "\\n", encoding="utf-8")
PY
	}

	write_gateway_args_file() {
		: >"\${gateway_args_file}"
		for arg in "\$@"; do
			printf '%s\0' "\${arg}" >>"\${gateway_args_file}"
		done
	}

	stop_gateway() {
		local gateway_pid=
		if [ -f "\${gateway_pid_file}" ]; then
			gateway_pid=\$(cat "\${gateway_pid_file}" 2>/dev/null || true)
		fi
		if [ -n "\${gateway_pid}" ] && kill -0 "\${gateway_pid}" 2>/dev/null; then
			kill "\${gateway_pid}" 2>/dev/null || true
			for _ in \$(seq 1 60); do
				kill -0 "\${gateway_pid}" 2>/dev/null || break
				sleep 0.5
			done
			kill -KILL "\${gateway_pid}" 2>/dev/null || true
			wait "\${gateway_pid}" 2>/dev/null || true
		fi
		rm -f "\${gateway_pid_file}" 2>/dev/null || true
	}

	cleanup_guest_tests() {
		local status=\$?
		trap - EXIT INT TERM
		stop_gateway
		if [ "\${status}" -ne 0 ] && [ -f "\${gateway_log}" ]; then
			echo "=== guest gateway log ===" >&2
			cat "\${gateway_log}" >&2
			echo "=== end guest gateway log ===" >&2
		fi
		exit "\${status}"
	}
	trap cleanup_guest_tests EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM

	export OPENSHELL_BIN=/usr/local/bin/openshell
	export OPENSHELL_GATEWAY_ENDPOINT=http://127.0.0.1:${guest_port}
	export OPENSHELL_GATEWAY=openshell-e2e-vm-${guest_port}
	export OPENSHELL_PROVISION_TIMEOUT=\${OPENSHELL_PROVISION_TIMEOUT:-300}
	if [ '${gateway_driver}' = podman ]; then
		export CONTAINER_ENGINE=podman
		export OPENSHELL_E2E_DRIVER=podman
		export OPENSHELL_E2E_NETWORK_NAME='${guest_e2e_network_name}'
		export OPENSHELL_E2E_SANDBOX_NAMESPACE='${guest_e2e_network_name}'
		export XDG_RUNTIME_DIR="\${XDG_RUNTIME_DIR:-/run/user/\$(id -u)}"
		export OPENSHELL_PODMAN_SOCKET="\${XDG_RUNTIME_DIR}/podman/podman.sock"
		export CONTAINER_HOST="unix://\${OPENSHELL_PODMAN_SOCKET}"
		export OPENSHELL_E2E_CONTAINER_ENGINE_UNSET_XDG_CONFIG_HOME=1
		insert_podman_config_key socket_path "\$(toml_string "\${OPENSHELL_PODMAN_SOCKET}")"

		provider_spiffe_port=\$(pick_free_port)
		export OPENSHELL_E2E_GATEWAY_SPIFFE_SOCKET="\${spiffe_root}/gateway.sock"
		export OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET="\${OPENSHELL_E2E_GATEWAY_SPIFFE_SOCKET}"
		export OPENSHELL_E2E_PROVIDER_SPIFFE_LISTEN="0.0.0.0:\${provider_spiffe_port}"
		export OPENSHELL_E2E_PROVIDER_SPIFFE_SOCKET="tcp:169.254.1.2:\${provider_spiffe_port}"
		insert_podman_config_key provider_spiffe_workload_api_socket "\$(toml_string "\${OPENSHELL_E2E_PROVIDER_SPIFFE_SOCKET}")"
	fi

	gateway_args=(
		--config "\${config_path}"
		--bind-address 127.0.0.1
		--port ${guest_port}
		--disable-tls
	)
	write_gateway_args_file "\${gateway_args[@]}"
	export OPENSHELL_E2E_GATEWAY_BIN=/usr/local/bin/openshell-gateway
	export OPENSHELL_E2E_GATEWAY_ARGS_FILE="\${gateway_args_file}"
	export OPENSHELL_E2E_GATEWAY_LOG="\${gateway_log}"
	export OPENSHELL_E2E_GATEWAY_PID_FILE="\${gateway_pid_file}"

	/usr/local/bin/openshell-gateway "\${gateway_args[@]}" >"\${gateway_log}" 2>&1 &
	printf '%s\n' "\$!" >"\${gateway_pid_file}"

	echo "==> Waiting for guest gateway readiness"
	gateway_ready=0
	for _ in \$(seq 1 "${gateway_ready_timeout}"); do
		if ! kill -0 "\$(cat "\${gateway_pid_file}")" 2>/dev/null; then
			echo "ERROR: guest gateway exited before becoming ready" >&2
			exit 1
		fi
		if NO_COLOR=1 /usr/local/bin/openshell status >/tmp/openshell-e2e-status.log 2>&1 &&
			grep -q "Connected" /tmp/openshell-e2e-status.log; then
			gateway_ready=1
			break
		fi
		sleep 1
	done
	if [ "\${gateway_ready}" -ne 1 ]; then
		echo "ERROR: guest gateway did not become ready" >&2
		cat /tmp/openshell-e2e-status.log >&2 || true
		exit 1
	fi

	while IFS= read -r test_bin <&3; do
		[ -n "\${test_bin}" ] || continue
		echo "==> Running guest E2E artifact: \${test_bin##*/}"
		"\${test_bin}" --nocapture </dev/null
	done 3<"${guest_test_manifest_path}"
	exit 0
fi

exec /usr/local/bin/openshell-gateway \
	--config "\${config_path}" \
	--bind-address 127.0.0.1 \
	--port ${guest_port} \
	--disable-tls
EOF
	chmod 0755 "${guest_launcher}"

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
	if [ "${tests_in_vm}" -eq 1 ]; then
		vm_args+=(--copy "${cli_bin}:/usr/local/bin/openshell")
		vm_args+=(--copy "${guest_test_manifest}:${guest_test_manifest_path}")
		for artifact in "${test_artifacts[@]}"; do
			vm_args+=(--copy "${artifact}:${guest_test_artifact_dir}/${artifact##*/}")
		done
	fi
	if [ "${keep}" -eq 1 ]; then
		vm_args+=(--keep)
	fi
	vm_args+=(-- "${guest_launcher_path}")

	if [ "${tests_in_vm}" -eq 1 ]; then
		echo "==> Running prebuilt E2E test artifacts inside ${vm} test guest"
		"${vm_args[@]}"
		exit $?
	fi

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

test_args=(
	cargo test
	--manifest-path e2e/rust/Cargo.toml
	--features "${e2e_features}"
)
echo "==> Running E2E features: ${e2e_features}"
if [ -n "${suite_name}" ]; then
	echo "==> Running E2E suite: ${suite_name}"
	test_args+=(--test "${suite_name}")
fi
test_args+=(-- --nocapture)

cd "${ROOT}"
"${test_args[@]}"
