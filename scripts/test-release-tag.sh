#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Test the release-tag workflow by pushing a throwaway tag, watching the run,
# then cleaning up the tag and release afterwards.
#
# Usage:
#   ./scripts/test-release-tag.sh          # push tag, watch, clean up
#   ./scripts/test-release-tag.sh --clean  # clean up only (if a previous run was interrupted)

set -euo pipefail

TAG="v0.0.1"
REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"

cleanup() {
  echo
  echo "=== Cleanup ==="
  if git ls-remote --tags origin | grep -q "refs/tags/${TAG}$"; then
    echo "Deleting remote tag ${TAG}..."
    git push origin --delete "${TAG}"
  else
    echo "Remote tag ${TAG} not found, skipping."
  fi

  if git tag -l "${TAG}" | grep -q "${TAG}"; then
    echo "Deleting local tag ${TAG}..."
    git tag -d "${TAG}"
  else
    echo "Local tag ${TAG} not found, skipping."
  fi

  if gh release view "${TAG}" &>/dev/null; then
    echo "Deleting GitHub release ${TAG}..."
    gh release delete "${TAG}" --yes --cleanup-tag
  else
    echo "GitHub release ${TAG} not found, skipping."
  fi

  echo "Done."
}

if [[ "${1:-}" == "--clean" ]]; then
  cleanup
  exit 0
fi

echo "=== Testing release-tag workflow ==="
echo "Tag:  ${TAG}"
echo "Repo: ${REPO}"
echo

# Create and push tag
echo "Creating tag ${TAG} at HEAD..."
git tag "${TAG}"
echo "Pushing tag to origin..."
git push origin "${TAG}"
echo

# Wait for the workflow run to appear
echo "Waiting for workflow run to start..."
for i in $(seq 1 30); do
  RUN_ID=$(gh run list --workflow=release-tag.yml --limit=1 --json databaseId,headBranch \
    --jq ".[] | select(.headBranch == \"${TAG}\") | .databaseId" 2>/dev/null || true)
  if [[ -n "${RUN_ID}" ]]; then
    break
  fi
  sleep 2
done

if [[ -z "${RUN_ID:-}" ]]; then
  echo "ERROR: Could not find a workflow run for tag ${TAG} after 60s."
  echo "Check https://github.com/${REPO}/actions/workflows/release-tag.yml"
  echo
  echo "Run '$0 --clean' to clean up."
  exit 1
fi

echo "Found run: https://github.com/${REPO}/actions/runs/${RUN_ID}"
echo

# Watch the run
echo "=== Watching workflow run ==="
gh run watch "${RUN_ID}" --exit-status || true

echo
gh run view "${RUN_ID}"

# Clean up
cleanup
