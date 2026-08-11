#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build one standalone prepared QCOW2 from explicit Bazel inputs and outputs.

set -Eeuo pipefail

usage() {
	cat <<'EOF'
Usage: build-image.sh OPTIONS

Required options:
  --runner PATH             Nix-wrapped test-guest runner
  --qemu-img PATH           qemu-img executable
  --jq PATH                 jq executable
  --sha256sum PATH          sha256sum executable
  --seal PATH               guest sealing script
  --base-image PATH         pinned input cloud image
  --output PATH             standalone QCOW2 output
  --metadata-output PATH    JSON metadata output
  --distro NAME             distro catalog name
  --os-id ID                expected guest OS ID
  --os-version VERSION      expected guest OS version
  --package-family FAMILY   guest package family: deb or rpm
  --architecture ARCH       guest architecture
  --base-image-url URL      provenance URL
  --base-image-hash HASH    pinned source hash
  --generation NUMBER       explicit image generation
  --qemu-version-file PATH  Nix-provided QEMU version
  --ansible-version-file PATH
                              Nix-provided Ansible version

Optional:
  --configuration NAME PATH
                             ordered image configuration and playbook; repeatable
EOF
}

require_value() {
	if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then
		echo "$1 requires a value" >&2
		exit 2
	fi
}

runner=
qemu_img=
jq_bin=
sha256sum_bin=
seal=
base_image=
output=
metadata_output=
distro=
os_id=
os_version=
package_family=
architecture=
base_image_url=
base_image_hash=
generation=
qemu_version_file=
ansible_version_file=
configurations=()
configuration_paths=()

while [ "$#" -gt 0 ]; do
	case "$1" in
	--runner) require_value "$@"; runner=$2; shift 2 ;;
	--qemu-img) require_value "$@"; qemu_img=$2; shift 2 ;;
	--jq) require_value "$@"; jq_bin=$2; shift 2 ;;
	--sha256sum) require_value "$@"; sha256sum_bin=$2; shift 2 ;;
	--seal) require_value "$@"; seal=$2; shift 2 ;;
	--base-image) require_value "$@"; base_image=$2; shift 2 ;;
	--output) require_value "$@"; output=$2; shift 2 ;;
	--metadata-output) require_value "$@"; metadata_output=$2; shift 2 ;;
	--distro) require_value "$@"; distro=$2; shift 2 ;;
	--os-id) require_value "$@"; os_id=$2; shift 2 ;;
	--os-version) require_value "$@"; os_version=$2; shift 2 ;;
	--package-family) require_value "$@"; package_family=$2; shift 2 ;;
	--architecture) require_value "$@"; architecture=$2; shift 2 ;;
	--base-image-url) require_value "$@"; base_image_url=$2; shift 2 ;;
	--base-image-hash) require_value "$@"; base_image_hash=$2; shift 2 ;;
	--generation) require_value "$@"; generation=$2; shift 2 ;;
	--qemu-version-file) require_value "$@"; qemu_version_file=$2; shift 2 ;;
	--ansible-version-file) require_value "$@"; ansible_version_file=$2; shift 2 ;;
	--configuration)
		if [ "$#" -lt 3 ] || [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
			echo "--configuration requires NAME PATH" >&2
			exit 2
		fi
		configurations+=("$2")
		configuration_paths+=("$3")
		shift 3
		;;
	-h | --help) usage; exit 0 ;;
	*) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
	esac
done

required=(
	runner qemu_img jq_bin sha256sum_bin seal base_image output
	metadata_output distro os_id os_version package_family architecture
	base_image_url base_image_hash generation qemu_version_file
	ansible_version_file
)
for variable in "${required[@]}"; do
	if [ -z "${!variable}" ]; then
		echo "missing required option for ${variable}" >&2
		exit 2
	fi
done

# qemu-img records backing paths relative to the overlay location. Bazel passes
# execroot-relative paths, so canonicalize files that cross into the runner.
# Keep executable symlinks intact: Nix coreutils uses the symlink basename to
# select the command implemented by its multicall binary.
seal=$(realpath "${seal}")
base_image=$(realpath "${base_image}")
qemu_version_file=$(realpath "${qemu_version_file}")
ansible_version_file=$(realpath "${ansible_version_file}")
for index in "${!configuration_paths[@]}"; do
	configuration_paths[index]=$(realpath "${configuration_paths[index]}")
done
output="$(realpath "$(dirname "${output}")")/$(basename "${output}")"
metadata_output="$(realpath "$(dirname "${metadata_output}")")/$(basename "${metadata_output}")"

scratch_root=${TEST_TMPDIR:-${TMPDIR:-/tmp}}
scratch=$(mktemp -d "${scratch_root%/}/test-guest-image.XXXXXX")
preserve_scratch=0

cleanup() {
	status=$?
	trap - EXIT INT TERM
	if [ "${status}" -ne 0 ]; then
		echo "test-guest image build failed; scratch directory: ${scratch}" >&2
		preserve_scratch=1
	fi
	if [ "${preserve_scratch}" -eq 0 ]; then
		rm -rf "${scratch}"
	fi
	exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "${scratch}/prepare" "${scratch}/validate"
prepare_args=(
	--distro "${distro}"
	--os-id "${os_id}"
	--os-version "${os_version}"
	--package-family "${package_family}"
	--keep
)
for index in "${!configurations[@]}"; do
	prepare_args+=(
		--configuration-file
		"${configurations[index]}"
		"${configuration_paths[index]}"
	)
done
prepare_args+=(
	--copy
	"${seal}:/usr/local/sbin/openshell-test-guest-image-seal"
	--
	sudo
	/usr/local/sbin/openshell-test-guest-image-seal
)

echo "==> Building Bazel test-guest image: ${distro} (${architecture})"
TMPDIR="${scratch}/prepare" \
	OPENSHELL_TEST_GUEST_BASE_IMAGE_OVERRIDE="${base_image}" \
	"${runner}" "${prepare_args[@]}"

shopt -s nullglob
run_dirs=("${scratch}/prepare/openshell-test-guest"/run.*)
shopt -u nullglob
if [ "${#run_dirs[@]}" -ne 1 ] || [ ! -f "${run_dirs[0]}/disk.qcow2" ]; then
	echo "image preparation did not retain exactly one guest disk" >&2
	exit 1
fi

"${qemu_img}" convert -q -c -f qcow2 -O qcow2 \
	"${run_dirs[0]}/disk.qcow2" "${output}"

image_info=$("${qemu_img}" info --output=json "${output}")
"${jq_bin}" -e '
  .format == "qcow2" and
  (. ["backing-filename"]? == null) and
  (. ["data-file"]? == null) and
  ((.snapshots? // []) | length == 0) and
  (. ["virtual-size"] > 0) and
  (. ["virtual-size"] <= 68719476736)
' <<<"${image_info}" >/dev/null
"${qemu_img}" check "${output}" >/dev/null

validation='test -s /etc/machine-id; sudo test -s /etc/ssh/ssh_host_ed25519_key'
for configuration in "${configurations[@]}"; do
	case "${configuration}" in
	docker) validation+='; docker info >/dev/null' ;;
	podman) validation+='; podman info >/dev/null' ;;
	selinux) validation+='; test "$(getenforce)" = Enforcing' ;;
	esac
done

validate_args=(
	--distro "${distro}"
	--os-id "${os_id}"
	--os-version "${os_version}"
	--package-family "${package_family}"
)
for configuration in "${configurations[@]}"; do
	validate_args+=(--with "${configuration}")
done
validate_args+=(-- bash -lc "${validation}")

echo "==> Validating fresh boot from Bazel image output"
TMPDIR="${scratch}/validate" \
	OPENSHELL_TEST_GUEST_IMAGE_OVERRIDE="${output}" \
	"${runner}" "${validate_args[@]}"

configuration_json=$("${jq_bin}" -cn --args '$ARGS.positional' "${configurations[@]}")
disk_sha=$("${sha256sum_bin}" "${output}")
disk_sha=${disk_sha%% *}
virtual_size=$("${jq_bin}" -r '.["virtual-size"]' <<<"${image_info}")
qemu_version=$(<"${qemu_version_file}")
ansible_version=$(<"${ansible_version_file}")

"${jq_bin}" -n \
	--argjson schema 2 \
	--arg distro "${distro}" \
	--arg os_id "${os_id}" \
	--arg os_version "${os_version}" \
	--arg package_family "${package_family}" \
	--arg architecture "${architecture}" \
	--arg base_image_url "${base_image_url}" \
	--arg base_image_hash "${base_image_hash}" \
	--arg disk_sha256 "${disk_sha}" \
	--arg qemu_version "${qemu_version}" \
	--arg ansible_version "${ansible_version}" \
	--argjson generation "${generation}" \
	--argjson virtual_size "${virtual_size}" \
	--argjson configurations "${configuration_json}" \
	'{
	  schema: $schema,
	  generation: $generation,
	  disk_layout: "standalone-qcow2-zlib-v2",
	  distro: $distro,
	  os_id: $os_id,
	  os_version: $os_version,
	  package_family: $package_family,
	  architecture: $architecture,
	  base_image_url: $base_image_url,
	  base_image_hash: $base_image_hash,
	  configurations: $configurations,
	  qemu_version: $qemu_version,
	  ansible_version: $ansible_version,
	  disk_sha256: $disk_sha256,
	  virtual_size: $virtual_size
	}' >"${metadata_output}"

chmod 0444 "${output}" "${metadata_output}"
preserve_scratch=0
echo "==> Bazel test-guest image complete: ${output}"
