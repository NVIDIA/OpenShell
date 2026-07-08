#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

: "${OPENSHELL_SOURCE_MOUNT:?OPENSHELL_SOURCE_MOUNT must name the mounted host checkout}"
: "${OPENSHELL_GUEST_SOURCE_DIR:?OPENSHELL_GUEST_SOURCE_DIR must name the guest checkout}"
: "${OPENSHELL_CACHE_DISK:?OPENSHELL_CACHE_DISK must name the development cache directory}"
: "${CARGO_TARGET_DIR:?CARGO_TARGET_DIR must name the Cargo target directory}"

if [ ! -f "${OPENSHELL_SOURCE_MOUNT}/mise.toml" ]; then
	echo "mounted OpenShell checkout is missing mise.toml: ${OPENSHELL_SOURCE_MOUNT}" >&2
	exit 1
fi

echo "==> Syncing the mounted OpenShell checkout onto the machine"
mkdir -p "${OPENSHELL_GUEST_SOURCE_DIR}"
rsync -a --delete \
	--exclude='/.cache/' \
	--exclude='/.env' \
	--exclude='/.git/' \
	--exclude='/.jj/' \
	--exclude='/.venv/' \
	--exclude='/e2e/rust/target/' \
	--exclude='/kubeconfig' \
	--exclude='/target/' \
	"${OPENSHELL_SOURCE_MOUNT}/" \
	"${OPENSHELL_GUEST_SOURCE_DIR}/"

mkdir -p "${OPENSHELL_GUEST_SOURCE_DIR}/.cache"
if [ "${OPENSHELL_CACHE_DISK}" = "${OPENSHELL_GUEST_SOURCE_DIR}/.cache" ]; then
	mkdir -p "${OPENSHELL_GUEST_SOURCE_DIR}/.cache/sccache" "${CARGO_TARGET_DIR}"
else
	echo "==> Preparing the persistent Lima development cache disk"
	sudo install -d -o "${USER}" -g "$(id -gn)" "${OPENSHELL_CACHE_DISK}"
	mkdir -p "${OPENSHELL_CACHE_DISK}/sccache" "${CARGO_TARGET_DIR}"
	rm -rf "${OPENSHELL_GUEST_SOURCE_DIR}/.cache/sccache"
	ln -s "${OPENSHELL_CACHE_DISK}/sccache" \
		"${OPENSHELL_GUEST_SOURCE_DIR}/.cache/sccache"
	rm -rf "${OPENSHELL_GUEST_SOURCE_DIR}/target"
	ln -s "${CARGO_TARGET_DIR}" "${OPENSHELL_GUEST_SOURCE_DIR}/target"
fi
