#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${OPENSHELL_E2E_RUNTIME_LOG:?runner must export OPENSHELL_E2E_RUNTIME_LOG}"

cargo test \
	--manifest-path e2e/rust/Cargo.toml \
	--features e2e-podman \
	--test podman_shutdown \
	-- --nocapture

# The base infrastructure suite validates lifecycle behavior. Dependent changes
# can opt into exact shutdown-transport classification assertions.
if [ "${OPENSHELL_E2E_EXPECT_SHUTDOWN_CLOSES:-0}" != 1 ]; then
	exit 0
fi

# Give the VM gateway enough time to flush shutdown-session logs.
sleep 2

if grep -E \
	'supervisor session: stream error|relay stream: inbound errored|StopSignal SIGTERM failed to stop container' \
	"${OPENSHELL_E2E_RUNTIME_LOG}"; then
	echo "ERROR: shutdown emitted a forced-stop or transport-close warning" >&2
	exit 1
fi

for expected in \
	"supervisor session: expected transport close during teardown" \
	"relay stream: expected transport close during sandbox teardown"; do
	if ! grep -Fq "${expected}" "${OPENSHELL_E2E_RUNTIME_LOG}"; then
		echo "ERROR: shutdown log did not contain expected classification: ${expected}" >&2
		exit 1
	fi
done
