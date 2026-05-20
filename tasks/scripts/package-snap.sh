#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Stage a hand-authored OpenShell snap payload from pre-built binaries, then
# optionally invoke `snap pack` against the staged directory.

set -euo pipefail

APP_NAME="openshell"

usage() {
	cat <<'EOF'
Build or stage the openshell snap from supplied binaries.

Required environment:
  OPENSHELL_CLI_BINARY         Path to openshell
  OPENSHELL_GATEWAY_BINARY     Path to openshell-gateway
  OPENSHELL_DOCKER_SUPERVISOR_BINARY
                               Path to the Linux openshell-sandbox supervisor
  OPENSHELL_SNAP_VERSION       Snap version

Optional environment:
  OPENSHELL_SNAP_ARCH          Snap architecture (amd64 or arm64; defaults to host arch)
  OPENSHELL_SNAP_BASE          Snap base (default: core24)
  OPENSHELL_SNAP_GRADE         Snap grade (default: devel)
  OPENSHELL_SNAP_PACK          Set to 0 to only stage the snap root (default: 1)
  OPENSHELL_SNAP_STAGE_DIR     Directory to stage into (default: temporary directory)
  OPENSHELL_OUTPUT_DIR         Output directory for .snap artifacts (default: artifacts)
EOF
}

require_env() {
	local name="$1"
	if [ -z "${!name:-}" ]; then
		echo "error: ${name} is required" >&2
		usage >&2
		exit 2
	fi
}

stage_binary() {
	local src="$1"
	local dst="$2"
	if [ ! -x "$src" ]; then
		echo "error: binary is missing or not executable: ${src}" >&2
		exit 1
	fi
	mkdir -p "$(dirname "$dst")"
	install -m 0755 "$src" "$dst"
}

infer_snap_arch() {
	case "$(uname -m)" in
	x86_64 | amd64) echo "amd64" ;;
	aarch64 | arm64) echo "arm64" ;;
	*) uname -m ;;
	esac
}

normalize_bool() {
	case "${1,,}" in
	1 | true | yes | on) echo "1" ;;
	0 | false | no | off) echo "0" ;;
	*)
		echo "error: invalid boolean value '${1}' (expected true/false, 1/0, yes/no, on/off)" >&2
		exit 2
		;;
	esac
}

prepare_stage_dir() {
	local dir="$1"

	if [ -z "$dir" ]; then
		echo "error: refusing empty OPENSHELL_SNAP_STAGE_DIR" >&2
		exit 2
	fi

	mkdir -p "$dir"

	local canonical_dir
	local canonical_repo_root
	canonical_dir="$(cd "$dir" && pwd -P)"
	canonical_repo_root="$(cd "$repo_root" && pwd -P)"

	if [[ "$canonical_dir" == "/" ||
		"$canonical_dir" == "$canonical_repo_root" ||
		"$canonical_repo_root" == "$canonical_dir/"* ]]; then
		echo "error: refusing unsafe OPENSHELL_SNAP_STAGE_DIR: '${dir}' resolved to '${canonical_dir}'" >&2
		exit 2
	fi

	find "$canonical_dir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
}

render_snap_yaml() {
	local template="$1"
	local output="$2"

	awk \
		-v version="$OPENSHELL_SNAP_VERSION" \
		-v base="$OPENSHELL_SNAP_BASE" \
		-v grade="$OPENSHELL_SNAP_GRADE" \
		-v arch="$OPENSHELL_SNAP_ARCH" '
		{
			gsub(/@VERSION@/, version);
			gsub(/@BASE@/, base);
			gsub(/@GRADE@/, grade);
			gsub(/@ARCH@/, arch);
			print;
		}
	' "$template" >"$output"
}

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

require_env OPENSHELL_CLI_BINARY
require_env OPENSHELL_GATEWAY_BINARY
require_env OPENSHELL_DOCKER_SUPERVISOR_BINARY
require_env OPENSHELL_SNAP_VERSION

OPENSHELL_SNAP_ARCH="${OPENSHELL_SNAP_ARCH:-$(infer_snap_arch)}"
OPENSHELL_SNAP_BASE="${OPENSHELL_SNAP_BASE:-core24}"
OPENSHELL_SNAP_GRADE="${OPENSHELL_SNAP_GRADE:-devel}"
OPENSHELL_SNAP_PACK="$(normalize_bool "${OPENSHELL_SNAP_PACK:-1}")"

case "$OPENSHELL_SNAP_ARCH" in
amd64 | arm64) ;;
*)
	echo "error: OPENSHELL_SNAP_ARCH must be amd64 or arm64, got ${OPENSHELL_SNAP_ARCH}" >&2
	exit 2
	;;
esac

case "$OPENSHELL_SNAP_GRADE" in
devel | stable) ;;
*)
	echo "error: OPENSHELL_SNAP_GRADE must be devel or stable, got ${OPENSHELL_SNAP_GRADE}" >&2
	exit 2
	;;
esac

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
src_dir="${repo_root}/deploy/snap"
template="${src_dir}/meta/snap.yaml.in"
output_dir_input="${OPENSHELL_OUTPUT_DIR:-artifacts}"
case "$output_dir_input" in
/*) output_dir="$output_dir_input" ;;
*) output_dir="${repo_root}/${output_dir_input}" ;;
esac
mkdir -p "$output_dir"

if [ ! -f "$template" ]; then
	echo "error: snap metadata template not found: ${template}" >&2
	exit 1
fi

tmpdir="$(mktemp -d)"
cleanup() {
	rm -rf "$tmpdir"
}
trap cleanup EXIT

if [ -n "${OPENSHELL_SNAP_STAGE_DIR:-}" ]; then
	case "$OPENSHELL_SNAP_STAGE_DIR" in
	/*) snap_root="$OPENSHELL_SNAP_STAGE_DIR" ;;
	*) snap_root="${repo_root}/${OPENSHELL_SNAP_STAGE_DIR}" ;;
	esac
	prepare_stage_dir "$snap_root"
else
	snap_root="${tmpdir}/snap-root"
	mkdir -p "$snap_root"
fi

# ---------------------------------------------------------------------------
# Stage the snap payload
# ---------------------------------------------------------------------------

stage_binary "$OPENSHELL_CLI_BINARY"       "$snap_root/bin/openshell"
stage_binary "$OPENSHELL_GATEWAY_BINARY"   "$snap_root/bin/openshell-gateway"
stage_binary "$OPENSHELL_DOCKER_SUPERVISOR_BINARY" "$snap_root/bin/openshell-sandbox"
install -D -m 0755 "${repo_root}/deploy/snap/bin/openshell-gateway-wrapper" \
	"$snap_root/bin/openshell-gateway-wrapper"

install -D -m 0644 "${repo_root}/LICENSE" "$snap_root/usr/share/doc/openshell/LICENSE"
install -D -m 0644 "${repo_root}/README.md" "$snap_root/usr/share/doc/openshell/README.md"

mkdir -p "$snap_root/meta"
render_snap_yaml "$template" "$snap_root/meta/snap.yaml"

# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------

"$snap_root/bin/openshell" --version
"$snap_root/bin/openshell-gateway" --version
"$snap_root/bin/openshell-sandbox" --version

# ---------------------------------------------------------------------------
# Pack
# ---------------------------------------------------------------------------

if [ "$OPENSHELL_SNAP_PACK" = "0" ]; then
	echo "Staged snap root at ${snap_root}"
	exit 0
fi

if ! command -v snap >/dev/null 2>&1; then
	echo "error: snap command not found; install snapd or set OPENSHELL_SNAP_PACK=0 to only stage the snap root" >&2
	exit 1
fi

snap pack "$snap_root" "$output_dir"
echo "Wrote ${output_dir}/${APP_NAME}_${OPENSHELL_SNAP_VERSION}_${OPENSHELL_SNAP_ARCH}.snap"
