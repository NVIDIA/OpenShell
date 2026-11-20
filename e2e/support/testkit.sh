#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run a testkit program, optionally using nextest for parallel execution.
e2e_run_testkit() (
  local program=$1 junit=$2
  if [[ -z "${OPENSHELL_TESTKIT_THREADS:-}" ]]; then
    "${program}" run --junit "${junit}"
    return $?
  fi

  local work status=0
  work="$(mktemp -d)" || return
  trap 'rm -rf "${work}"' EXIT
  "${program}" nextest-metadata "${work}" || return
  cat > "${work}/nextest.toml" <<'EOF'
[profile.openshell]
slow-timeout = { period = "900s", terminate-after = 1, grace-period = "10s" }

[profile.openshell.junit]
path = "junit.xml"
store-success-output = true
EOF
  cargo-nextest nextest run \
    --cargo-metadata "${work}/cargo-metadata.json" \
    --binaries-metadata "${work}/binaries-metadata.json" \
    --config-file "${work}/nextest.toml" --profile openshell \
    --test-threads "${OPENSHELL_TESTKIT_THREADS}" \
    --no-tests fail --no-fail-fast --success-output immediate \
    --failure-output immediate || status=$?
  if [[ -f "${work}/target/nextest/openshell/junit.xml" ]]; then
    mv "${work}/target/nextest/openshell/junit.xml" "${junit}" || return
  fi
  return "${status}"
)
