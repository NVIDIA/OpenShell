#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build the supervisor middleware content-guard example from a released tag and
# print the binary path. Releases do not publish the example, so the e2e suite
# builds it from the tagged sources with that tag's own lockfile. The build is
# cached per tag commit under the Cargo target directory.
#
# Usage: tasks/scripts/e2e-build-legacy-content-guard.sh [tag]
# The tag defaults to OPENSHELL_LEGACY_MIDDLEWARE_TAG, then v0.1.2.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TAG="${1:-${OPENSHELL_LEGACY_MIDDLEWARE_TAG:-v0.1.2}}"
TARGET_ROOT="${CARGO_TARGET_DIR:-${ROOT}/target}"
WORK="${TARGET_ROOT}/legacy-middleware/${TAG}"
SOURCE="${WORK}/source"
EXAMPLE="examples/supervisor-middleware-content-guard"
BINARY="${WORK}/target/debug/supervisor-middleware-content-guard"

if ! git -C "${ROOT}" rev-parse -q --verify "refs/tags/${TAG}^{commit}" >/dev/null; then
  echo "Fetching ${TAG}..." >&2
  fetch_args=(--quiet --no-tags)
  # Fetching with --depth into a full clone would make it shallow.
  if [ "$(git -C "${ROOT}" rev-parse --is-shallow-repository)" = "true" ]; then
    fetch_args+=(--depth=1)
  fi
  git -C "${ROOT}" fetch "${fetch_args[@]}" origin \
    "refs/tags/${TAG}:refs/tags/${TAG}" >&2
fi
COMMIT="$(git -C "${ROOT}" rev-parse "refs/tags/${TAG}^{commit}")"

if [ -x "${BINARY}" ] && [ "$(cat "${WORK}/commit" 2>/dev/null)" = "${COMMIT}" ]; then
  printf '%s\n' "${BINARY}"
  exit 0
fi

echo "Building the ${TAG} content-guard example (${COMMIT})..." >&2
rm -rf "${SOURCE}" "${WORK}/commit"
mkdir -p "${SOURCE}"
git -C "${ROOT}" archive "${COMMIT}" -- \
  Cargo.toml rust-toolchain.toml crates proto "${EXAMPLE}" \
  | tar -x -C "${SOURCE}"

# The tagged openshell-core build script derives its version from git. Keep it
# from reading this checkout's history through the enclosing worktree.
(
  cd "${SOURCE}/${EXAMPLE}"
  GIT_CEILING_DIRECTORIES="${WORK}" cargo build --locked \
    --manifest-path Cargo.toml \
    --target-dir "${WORK}/target" >&2
)
printf '%s\n' "${COMMIT}" >"${WORK}/commit"
printf '%s\n' "${BINARY}"
