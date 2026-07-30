#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared cache identity and validation helpers for the test guest runner.

TEST_GUEST_CACHE_SCHEMA_VERSION=1
TEST_GUEST_CACHE_DISK_LAYOUT=standalone-qcow2-zstd-v1
TEST_GUEST_CACHE_ARTIFACT_TYPE=application/vnd.nvidia.openshell.test-guest.cache.v1
TEST_GUEST_CACHE_METADATA_TYPE=application/vnd.nvidia.openshell.test-guest.cache.metadata.v1+json
TEST_GUEST_CACHE_DISK_TYPE=application/vnd.nvidia.openshell.test-guest.cache.disk.qcow2.v1+zstd

test_vm_cache_root() {
	if [ -n "${OPENSHELL_TEST_GUEST_CACHE_DIR:-}" ]; then
		printf '%s\n' "${OPENSHELL_TEST_GUEST_CACHE_DIR}"
	else
		printf '%s\n' "${XDG_CACHE_HOME:-${HOME}/.cache}/openshell/test-guest"
	fi
}

test_vm_cache_oci_architecture() {
	case "${TEST_GUEST_ARCHITECTURE}" in
	x86_64) printf '%s\n' amd64 ;;
	aarch64) printf '%s\n' arm64 ;;
	*)
		echo "unsupported cache architecture: ${TEST_GUEST_ARCHITECTURE}" >&2
		return 1
		;;
	esac
}

test_vm_cache_sha256() {
	if [ ! -r "$1" ]; then
		echo "cache identity input is not readable: $1" >&2
		return 1
	fi
	sha256sum "$1" | cut -d ' ' -f 1
}

test_vm_cache_key() {
	local distro_name=$1
	shift
	local configuration
	local configuration_hash
	local architecture
	local seal_hash
	local material
	local configuration_line

	architecture=$(test_vm_cache_oci_architecture) || return 1
	seal_hash=$(test_vm_cache_sha256 "${OPENSHELL_TEST_GUEST_CACHE_SEAL}") || return 1
	printf -v material \
		'schema=%s\ngeneration=%s\ndisk_layout=%s\ndistro=%s\nos_version=%s\narchitecture=%s\nbase_url=%s\nbase_hash=%s\noverlay_growth=%s\nansible_version=%s\nseal_sha256=%s\n' \
		"${TEST_GUEST_CACHE_SCHEMA_VERSION}" \
		"${TEST_GUEST_CACHE_GENERATION}" \
		"${TEST_GUEST_CACHE_DISK_LAYOUT}" \
		"${distro_name}" \
		"${TEST_GUEST_OS_VERSION}" \
		"${architecture}" \
		"${TEST_GUEST_IMAGE_URL}" \
		"${TEST_GUEST_IMAGE_HASH}" \
		16G \
		"${TEST_GUEST_ANSIBLE_VERSION}" \
		"${seal_hash}"

	for configuration in "$@"; do
		configuration_hash=$(
			test_vm_cache_sha256 \
				"${OPENSHELL_TEST_GUEST_CONFIGURATIONS}/${configuration}"
		) || return 1
		printf -v configuration_line \
			'configuration=%s:%s\n' \
			"${configuration}" \
			"${configuration_hash}"
		material+=${configuration_line}
	done

	printf '%s' "${material}" | sha256sum | cut -d ' ' -f 1
}

test_vm_cache_tag() {
	local distro_name=$1
	local key=$2
	printf 'v%s-%s-%s-%s\n' \
		"${TEST_GUEST_CACHE_SCHEMA_VERSION}" \
		"${distro_name}" \
		"$(test_vm_cache_oci_architecture)" \
		"${key}"
}

test_vm_cache_entry_dir() {
	local root=$1
	local key=$2
	printf '%s/entries/%s\n' "${root}" "${key}"
}

test_vm_cache_metadata_matches() {
	local metadata=$1
	local key=$2
	local distro_name=$3
	shift 3
	local architecture
	local expected_configurations
	architecture=$(test_vm_cache_oci_architecture) || return 1
	expected_configurations=$(jq -cn --args '$ARGS.positional' "$@") || return 1

	jq -e \
		--argjson schema "${TEST_GUEST_CACHE_SCHEMA_VERSION}" \
		--arg key "${key}" \
		--arg distro "${distro_name}" \
		--arg os_version "${TEST_GUEST_OS_VERSION}" \
		--arg architecture "$(test_vm_cache_oci_architecture)" \
		--arg base_hash "${TEST_GUEST_IMAGE_HASH}" \
		--argjson configurations "${expected_configurations}" \
		'
			.schema == $schema and
			.key == $key and
			.distro == $distro and
			.os_version == $os_version and
			.architecture == $architecture and
			.base_image_hash == $base_hash and
			.configurations == $configurations
		' "${metadata}" >/dev/null
}

test_vm_cache_local_entry_valid() {
	local root=$1
	local key=$2
	local distro_name=$3
	shift 3
	local entry
	local expected_sha
	local actual_sha
	entry=$(test_vm_cache_entry_dir "${root}" "${key}")

	[ -f "${entry}/complete" ] &&
		[ -f "${entry}/disk.qcow2" ] &&
		[ -f "${entry}/metadata.json" ] &&
		test_vm_cache_metadata_matches \
			"${entry}/metadata.json" "${key}" "${distro_name}" "$@" ||
		return 1

	expected_sha=$(jq -er '
		.disk_sha256 |
		select(type == "string" and test("^[a-f0-9]{64}$"))
	' "${entry}/metadata.json") ||
		return 1
	actual_sha=$(test_vm_cache_sha256 "${entry}/disk.qcow2") ||
		return 1

	[ "${actual_sha}" = "${expected_sha}" ] &&
		test_vm_cache_validate_disk "${entry}/disk.qcow2"
}

test_vm_cache_validate_disk() {
	local disk=$1
	local info
	info=$(qemu-img info --output=json "${disk}")

	jq -e '
		.format == "qcow2" and
		(.["backing-filename"]? == null) and
		(.["data-file"]? == null) and
		((.snapshots? // []) | length == 0) and
		(.["virtual-size"] > 0) and
		(.["virtual-size"] <= 68719476736)
	' <<<"${info}" >/dev/null
	qemu-img check "${disk}" >/dev/null
}
