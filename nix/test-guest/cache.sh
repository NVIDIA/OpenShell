#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Ensure a prepared test guest disk exists locally, optionally backed by OCI.

set -Eeuo pipefail

usage() {
	cat <<'EOF'
Usage:
  nix run .#test-guest-cache -- --distro DISTRO [OPTIONS]

Options:
  --distro NAME       Base distro: ubuntu-24-04, ubuntu-26-04, centos, fedora, or rocky
  --with NAME         Apply a configuration; repeatable (docker, podman-rootless, selinux, snapd)
  --repository REF    OCI repository without a tag
  --digest DIGEST     Trusted OCI manifest digest required for pulls
  --cache-dir PATH    Override the local prepared-disk cache directory
  --push              Publish a newly built or local entry to the repository
  -h, --help          Show this help

The command ensures one exact distro, architecture, and ordered configuration
combination exists locally. OCI pulls require a trusted manifest digest.
Otherwise, the command builds and validates a prepared disk on a miss.
Publishing is explicit and requires both --repository and --push.
EOF
}

if [ "${OPENSHELL_TEST_GUEST_RUNTIME:-}" != 1 ] ||
	[ ! -d "${OPENSHELL_TEST_GUEST_DISTROS:-}" ] ||
	[ ! -d "${OPENSHELL_TEST_GUEST_CONFIGURATIONS:-}" ] ||
	[ ! -r "${OPENSHELL_TEST_GUEST_CACHE_LIB:-}" ] ||
	[ ! -r "${OPENSHELL_TEST_GUEST_CACHE_SEAL:-}" ] ||
	[ ! -r "${OPENSHELL_TEST_GUEST_RUNNER:-}" ]; then
	echo "run this script through 'nix run .#test-guest-cache -- ...'" >&2
	exit 2
fi

# shellcheck disable=SC1090
. "${OPENSHELL_TEST_GUEST_CACHE_LIB}"

require_value() {
	if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then
		echo "$1 requires a value" >&2
		exit 2
	fi
}

distro=
repository=${OPENSHELL_TEST_GUEST_CACHE_REPOSITORY:-}
pull_digest=${OPENSHELL_TEST_GUEST_CACHE_DIGEST:-}
cache_dir=
push=0
configurations=()

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
	--repository)
		require_value "$@"
		repository=$2
		shift 2
		;;
	--digest)
		require_value "$@"
		pull_digest=$2
		shift 2
		;;
	--cache-dir)
		require_value "$@"
		cache_dir=$2
		shift 2
		;;
	--push)
		push=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "unknown test guest cache argument: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

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

if [ "${push}" -eq 1 ] && [ -z "${repository}" ]; then
	echo "--push requires --repository" >&2
	exit 2
fi
if [[ ${repository} == *[[:space:]]* ]] || [[ ${repository} == *@* ]]; then
	echo "--repository must be an untagged OCI repository reference" >&2
	exit 2
fi
if [ -n "${repository}" ] && [ "${push}" -eq 0 ] && [ -z "${pull_digest}" ]; then
	echo "--repository requires --digest for OCI pulls" >&2
	exit 2
fi
if [ -n "${pull_digest}" ] && [ -z "${repository}" ]; then
	echo "--digest requires --repository" >&2
	exit 2
fi
if [ -n "${pull_digest}" ] &&
	[[ ! ${pull_digest} =~ ^sha256:[a-f0-9]{64}$ ]]; then
	echo "--digest must be a lowercase sha256 OCI manifest digest" >&2
	exit 2
fi

if [ -n "${cache_dir}" ]; then
	OPENSHELL_TEST_GUEST_CACHE_DIR=${cache_dir}
	export OPENSHELL_TEST_GUEST_CACHE_DIR
fi

umask 077
cache_root=$(test_vm_cache_root)
cache_key=$(test_vm_cache_key "${distro}" "${configurations[@]}")
cache_tag=$(test_vm_cache_tag "${distro}" "${cache_key}")
entry_dir=$(test_vm_cache_entry_dir "${cache_root}" "${cache_key}")
remote_ref=
pull_ref=
if [ -n "${repository}" ]; then
	remote_ref="${repository}:${cache_tag}"
fi
if [ -n "${pull_digest}" ]; then
	pull_ref="${repository}@${pull_digest}"
fi

mkdir -p "${cache_root}/entries" "${cache_root}/locks" "${cache_root}/staging"

lock_dir=
build_stage=
preserve_build_stage=0

cleanup() {
	local status=$?
	trap - EXIT INT TERM
	if [ -n "${lock_dir}" ]; then
		rmdir "${lock_dir}" 2>/dev/null || true
	fi
	if [ -n "${build_stage}" ] && [ -d "${build_stage}" ]; then
		if [ "${status}" -ne 0 ] && [ "${preserve_build_stage}" -eq 1 ]; then
			echo "Kept failed cache build state at ${build_stage}" >&2
		else
			rm -rf "${build_stage}"
		fi
	fi
	exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for _ in $(seq 1 120); do
	if mkdir "${cache_root}/locks/${cache_key}.lock" 2>/dev/null; then
		lock_dir="${cache_root}/locks/${cache_key}.lock"
		break
	fi
	sleep 1
done
if [ -z "${lock_dir}" ]; then
	echo "timed out waiting for cache lock: ${cache_key}" >&2
	exit 1
fi

install_entry() {
	local disk=$1
	local metadata=$2
	local manifest_digest=${3:-}
	local temporary_entry
	temporary_entry=$(mktemp -d "${cache_root}/entries/.${cache_key}.XXXXXX")
	cp --sparse=always "${disk}" "${temporary_entry}/disk.qcow2"
	chmod 0444 "${temporary_entry}/disk.qcow2"
	install -m 0444 "${metadata}" "${temporary_entry}/metadata.json"
	if [ -n "${manifest_digest}" ]; then
		printf '%s\n' "${manifest_digest}" >"${temporary_entry}/manifest.digest"
		chmod 0444 "${temporary_entry}/manifest.digest"
	fi
	: >"${temporary_entry}/complete"
	chmod 0444 "${temporary_entry}/complete"

	if [ -e "${entry_dir}" ]; then
		if local_entry_valid; then
			rm -rf "${temporary_entry}"
			return
		fi
		echo "cache entry appeared concurrently but is invalid: ${entry_dir}" >&2
		rm -rf "${temporary_entry}"
		return 1
	fi
	mv "${temporary_entry}" "${entry_dir}"
}

local_entry_valid() {
	test_vm_cache_local_entry_valid \
		"${cache_root}" "${cache_key}" "${distro}" "${configurations[@]}" ||
		return 1
	if [ -n "${pull_digest}" ]; then
		[ -f "${entry_dir}/manifest.digest" ] &&
			[ "$(<"${entry_dir}/manifest.digest")" = "${pull_digest}" ]
	fi
}

is_remote_miss() {
	grep -Eqi '404|MANIFEST_UNKNOWN|manifest unknown|not found' "$1"
}

pull_remote() {
	local requested_ref=${1:-${pull_ref}}
	local trusted_digest=${2:-${pull_digest}}
	local install_local=${3:-1}
	local expected_local_sha=${4:-}
	local pull_dir
	local pull_log
	local compressed_size
	local expected_sha
	local actual_sha
	local resolved_digest
	pull_dir=$(mktemp -d "${cache_root}/staging/pull.${cache_key}.XXXXXX")
	pull_log="${pull_dir}/oras.log"

	resolved_digest=$(oras resolve "${requested_ref}") || {
		rm -rf "${pull_dir}"
		return 2
	}
	if [ "${resolved_digest}" != "${trusted_digest}" ]; then
		echo "OCI cache manifest digest does not match trusted digest" >&2
		rm -rf "${pull_dir}"
		return 2
	fi

	if ! oras pull --output "${pull_dir}" "${requested_ref}" >"${pull_log}" 2>&1; then
		if is_remote_miss "${pull_log}"; then
			rm -rf "${pull_dir}"
			return 1
		fi
		cat "${pull_log}" >&2
		rm -rf "${pull_dir}"
		return 2
	fi

	if [ ! -f "${pull_dir}/metadata.json" ] ||
		[ ! -f "${pull_dir}/disk.qcow2.zst" ]; then
		echo "OCI cache artifact is missing metadata.json or disk.qcow2.zst" >&2
		rm -rf "${pull_dir}"
		return 2
	fi
	if ! test_vm_cache_metadata_matches \
		"${pull_dir}/metadata.json" "${cache_key}" "${distro}" "${configurations[@]}"; then
		echo "OCI cache metadata does not match the requested VM" >&2
		rm -rf "${pull_dir}"
		return 2
	fi

	compressed_size=$(wc -c <"${pull_dir}/disk.qcow2.zst")
	if [ "${compressed_size}" -gt 17179869184 ]; then
		echo "OCI cache disk exceeds the 16 GiB compressed size limit" >&2
		rm -rf "${pull_dir}"
		return 2
	fi

	(
		# Limit the decompressed file to 32 GiB before qemu-img parses it.
		ulimit -f 67108864
		zstd -d --sparse -f \
			"${pull_dir}/disk.qcow2.zst" \
			-o "${pull_dir}/disk.qcow2"
	)
	expected_sha=$(jq -r '.disk_sha256' "${pull_dir}/metadata.json")
	if [ -n "${expected_local_sha}" ] && [ "${expected_sha}" != "${expected_local_sha}" ]; then
		echo "OCI cache disk checksum does not match the local cache entry" >&2
		rm -rf "${pull_dir}"
		return 2
	fi
	actual_sha=$(test_vm_cache_sha256 "${pull_dir}/disk.qcow2")
	if [ "${expected_sha}" != "${actual_sha}" ]; then
		echo "OCI cache disk checksum does not match metadata" >&2
		rm -rf "${pull_dir}"
		return 2
	fi
	if ! test_vm_cache_validate_disk "${pull_dir}/disk.qcow2"; then
		echo "OCI cache disk failed QCOW2 validation" >&2
		rm -rf "${pull_dir}"
		return 2
	fi

	if [ "${install_local}" -eq 1 ]; then
		install_entry \
			"${pull_dir}/disk.qcow2" "${pull_dir}/metadata.json" "${resolved_digest}"
	fi
	rm -rf "${pull_dir}"
	if [ "${install_local}" -eq 1 ]; then
		echo "==> Cache remote hit: ${requested_ref}"
	fi
}

build_local() {
	local -a prepare_args
	local -a validate_args
	local -a run_dirs
	local configuration
	local prepared_disk
	local validation
	local configuration_json
	local disk_sha
	local virtual_size
	local created

	build_stage=$(mktemp -d "${cache_root}/staging/build.${cache_key}.XXXXXX")
	preserve_build_stage=1
	mkdir -p "${build_stage}/prepare-tmp" "${build_stage}/validate-tmp"

	prepare_args=(--distro "${distro}" --keep)
	for configuration in "${configurations[@]}"; do
		prepare_args+=(--with "${configuration}")
	done
	prepare_args+=(
		--copy
		"${OPENSHELL_TEST_GUEST_CACHE_SEAL}:/usr/local/sbin/openshell-test-guest-cache-seal"
		--
		sudo
		/usr/local/sbin/openshell-test-guest-cache-seal
	)

	echo "==> Cache miss: preparing ${distro} ($(test_vm_cache_oci_architecture))"
	TMPDIR="${build_stage}/prepare-tmp" \
		OPENSHELL_TEST_GUEST_CACHE_DISABLE=1 \
		"${TEST_GUEST_BASH}" "${OPENSHELL_TEST_GUEST_RUNNER}" "${prepare_args[@]}"

	shopt -s nullglob
	run_dirs=("${build_stage}/prepare-tmp/openshell-test-guest"/run.*)
	shopt -u nullglob
	if [ "${#run_dirs[@]}" -ne 1 ] ||
		[ ! -f "${run_dirs[0]}/disk.qcow2" ]; then
		echo "cache preparation did not retain exactly one guest disk" >&2
		return 1
	fi

	prepared_disk="${build_stage}/disk.qcow2"
	qemu-img convert -q -f qcow2 -O qcow2 \
		"${run_dirs[0]}/disk.qcow2" "${prepared_disk}"
	test_vm_cache_validate_disk "${prepared_disk}"

	validation='test -s /etc/machine-id; test -n "$(find /etc/ssh -name "ssh_host_*_key" -type f -print -quit)"'
	for configuration in "${configurations[@]}"; do
		case "${configuration}" in
		docker) validation+='; docker info >/dev/null' ;;
		podman-rootless) validation+='; podman info >/dev/null' ;;
		selinux) validation+='; test "$(getenforce)" = Enforcing' ;;
		esac
	done

	validate_args=(--distro "${distro}")
	for configuration in "${configurations[@]}"; do
		validate_args+=(--with "${configuration}")
	done
	validate_args+=(-- bash -lc "${validation}")

	echo "==> Validating fresh boot from prepared cache disk"
	TMPDIR="${build_stage}/validate-tmp" \
		OPENSHELL_TEST_GUEST_CACHE_DISABLE=1 \
		OPENSHELL_TEST_GUEST_IMAGE_OVERRIDE="${prepared_disk}" \
		"${TEST_GUEST_BASH}" "${OPENSHELL_TEST_GUEST_RUNNER}" "${validate_args[@]}"

	configuration_json=$(jq -cn --args '$ARGS.positional' "${configurations[@]}")
	disk_sha=$(test_vm_cache_sha256 "${prepared_disk}")
	virtual_size=$(
		qemu-img info --output=json "${prepared_disk}" |
			jq -r '.["virtual-size"]'
	)
	created=$(date -u +%Y-%m-%dT%H:%M:%SZ)

	jq -n \
		--argjson schema "${TEST_GUEST_CACHE_SCHEMA_VERSION}" \
		--arg key "${cache_key}" \
		--arg distro "${distro}" \
		--arg os_version "${TEST_GUEST_OS_VERSION}" \
		--arg architecture "$(test_vm_cache_oci_architecture)" \
		--arg base_image_url "${TEST_GUEST_IMAGE_URL}" \
		--arg base_image_hash "${TEST_GUEST_IMAGE_HASH}" \
		--arg disk_layout "${TEST_GUEST_CACHE_DISK_LAYOUT}" \
		--arg disk_sha256 "${disk_sha}" \
		--arg created "${created}" \
		--argjson virtual_size "${virtual_size}" \
		--argjson configurations "${configuration_json}" \
		'{
			schema: $schema,
			key: $key,
			distro: $distro,
			os_version: $os_version,
			architecture: $architecture,
			base_image_url: $base_image_url,
			base_image_hash: $base_image_hash,
			configurations: $configurations,
			disk_layout: $disk_layout,
			disk_sha256: $disk_sha256,
			virtual_size: $virtual_size,
			created: $created
		}' >"${build_stage}/metadata.json"

	install_entry "${prepared_disk}" "${build_stage}/metadata.json"
	preserve_build_stage=0
	rm -rf "${build_stage}"
	build_stage=
	echo "==> Cache build complete: ${entry_dir}"
}

push_remote() {
	local existing_ref
	local local_disk_sha
	local push_dir
	local manifest_log
	local published_digest
	push_dir=$(mktemp -d "${cache_root}/staging/push.${cache_key}.XXXXXX")
	manifest_log="${push_dir}/manifest.log"

	if oras manifest fetch "${remote_ref}" >"${manifest_log}" 2>&1; then
		published_digest=$(oras resolve "${remote_ref}")
		existing_ref="${repository}@${published_digest}"
		local_disk_sha=$(jq -r '.disk_sha256' "${entry_dir}/metadata.json")
		if ! pull_remote "${existing_ref}" "${published_digest}" 0 "${local_disk_sha}"; then
			echo "existing OCI cache artifact failed validation: ${remote_ref}" >&2
			rm -rf "${push_dir}"
			return 1
		fi
		echo "==> Cache already published and validated: ${remote_ref}"
		echo "==> Cache immutable reference: ${repository}@${published_digest}"
		rm -rf "${push_dir}"
		return
	fi
	if ! is_remote_miss "${manifest_log}"; then
		cat "${manifest_log}" >&2
		rm -rf "${push_dir}"
		return 1
	fi

	install -m 0644 "${entry_dir}/metadata.json" "${push_dir}/metadata.json"
	zstd -T0 -3 -f \
		"${entry_dir}/disk.qcow2" \
		-o "${push_dir}/disk.qcow2.zst"

	(
		cd "${push_dir}"
		oras push \
			--artifact-type "${TEST_GUEST_CACHE_ARTIFACT_TYPE}" \
			"${remote_ref}" \
			"metadata.json:${TEST_GUEST_CACHE_METADATA_TYPE}" \
			"disk.qcow2.zst:${TEST_GUEST_CACHE_DISK_TYPE}"
	)
	published_digest=$(oras resolve "${remote_ref}")
	rm -rf "${push_dir}"
	echo "==> Cache push complete: ${remote_ref}"
	echo "==> Cache immutable reference: ${repository}@${published_digest}"
}

echo "==> Cache key: ${cache_key}"
if local_entry_valid; then
	echo "==> Cache local hit: ${entry_dir}"
else
	if [ -e "${entry_dir}" ]; then
		rejected="${cache_root}/staging/rejected.${cache_key}.$(date +%s)"
		mv "${entry_dir}" "${rejected}"
		echo "Moved invalid cache entry to ${rejected}" >&2
	fi

	pulled=0
	if [ -n "${pull_ref}" ]; then
		if pull_remote; then
			pulled=1
		else
			pull_status=$?
			if [ "${pull_status}" -ne 1 ]; then
				exit "${pull_status}"
			fi
			echo "==> Cache remote miss: ${pull_ref}"
		fi
	fi
	if [ "${pulled}" -eq 0 ]; then
		build_local
	fi
fi

if [ "${push}" -eq 1 ]; then
	push_remote
fi

echo "==> Cache ready: ${entry_dir}"
