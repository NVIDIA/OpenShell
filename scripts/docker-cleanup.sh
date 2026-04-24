#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Clean up stale Docker images, volumes, and build cache that are not in use
# by the currently deployed OpenShell cluster.
#
# Preserves:
#   - Current openshell/* :dev images (and 127.0.0.1:5000 registry mirrors)
#   - Images actively used by running containers
#   - Common base/infrastructure images (registry, k3s, alpine, rust, python, etc.)
#   - Volumes attached to running containers
#
# Usage:
#   ./scripts/docker-cleanup.sh [options]
#
# Options:
#   --dry-run        Show what would be removed without deleting anything
#   --force          Skip the confirmation prompt
#   --skip-cache     Skip build cache pruning (cache speeds up subsequent builds)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../tasks/scripts/container-engine.sh"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
DRY_RUN=false
SKIP_CACHE=false
FORCE=false

usage() {
  sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \?//'
  exit 0
}

for arg in "$@"; do
  case "$arg" in
    --dry-run)    DRY_RUN=true ;;
    --skip-cache) SKIP_CACHE=true ;;
    --force)      FORCE=true ;;
    -h|--help)    usage ;;
    *) echo "Unknown option: $arg"; usage ;;
  esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
RESET='\033[0m'

info()  { echo -e "${BOLD}==> $*${RESET}"; }
note()  { echo -e "    ${DIM}$*${RESET}"; }
ok()    { echo -e "    ${GREEN}$*${RESET}"; }
warn()  { echo -e "    ${YELLOW}$*${RESET}"; }
err()   { echo -e "    ${RED}$*${RESET}"; }
dry()   { echo -e "    ${YELLOW}[dry-run]${RESET} $*"; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
# container-engine.sh already validates that an engine is available.

if ! ce info &>/dev/null; then
  echo "Error: Container engine (${CONTAINER_ENGINE}) is not running" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Image repository prefixes that belong to the CURRENT cluster deployment.
# Any tagged image whose repository starts with one of these is kept.
# ---------------------------------------------------------------------------
CURRENT_IMAGE_PREFIXES=(
  "openshell/"
  "127.0.0.1:5000/openshell/"
)

# ---------------------------------------------------------------------------
# Infrastructure / base images to always keep (matched by repository prefix).
# These are pulled from remote registries and are expensive to re-download.
# ---------------------------------------------------------------------------
KEEP_IMAGE_PREFIXES=(
  "registry"
  "rancher/k3s"
  "ghcr.io/k3d-io/"
  "kindest/"
  "alpine"
  "python"
  "rust"
  "ghcr.io/astral-sh/uv"
  "redis"
  "pgvector/"
  "minio/"
)

# Returns 0 if the image repository should be kept, 1 otherwise.
should_keep_image() {
  local repo="$1"

  # Keep current cluster images
  for prefix in "${CURRENT_IMAGE_PREFIXES[@]}"; do
    if [[ "$repo" == "$prefix"* ]]; then
      return 0
    fi
  done

  # Keep infrastructure / base images
  for prefix in "${KEEP_IMAGE_PREFIXES[@]}"; do
    if [[ "$repo" == "$prefix"* ]]; then
      return 0
    fi
  done

  return 1
}

# ---------------------------------------------------------------------------
# Snapshot disk usage before cleanup
# ---------------------------------------------------------------------------
info "Current disk usage (${CONTAINER_ENGINE})"
ce system df
echo

# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------
if [[ "$DRY_RUN" == true ]]; then
  warn "Running in dry-run mode -- nothing will be deleted"
  echo
elif [[ "$FORCE" != true ]]; then
  echo -e "${BOLD}This will remove stale images, unused volumes, and build cache.${RESET}"
  echo "The currently deployed cluster images and running containers are preserved."
  echo
  read -r -p "Continue? [y/N] " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
  fi
  echo
fi

# Track totals for the summary
TOTAL_IMAGES_REMOVED=0
TOTAL_VOLUMES_REMOVED=0

# ---------------------------------------------------------------------------
# Step 1: Remove dangling (untagged) images
# ---------------------------------------------------------------------------
info "Removing dangling images..."

dangling_count=$(ce images --filter "dangling=true" -q | wc -l | tr -d ' ')
if [[ "$dangling_count" -gt 0 ]]; then
  note "Found $dangling_count dangling image(s)"
  if [[ "$DRY_RUN" == true ]]; then
    dry "Would remove $dangling_count dangling image(s)"
  else
    ce image prune -f | tail -1
    TOTAL_IMAGES_REMOVED=$((TOTAL_IMAGES_REMOVED + dangling_count))
  fi
else
  ok "No dangling images found"
fi
echo

# ---------------------------------------------------------------------------
# Step 2: Remove stale tagged images
# ---------------------------------------------------------------------------
info "Removing stale tagged images..."

# Collect image IDs that are directly used by running containers so we never
# touch them regardless of tag matching.
running_image_ids=$(ce ps -q 2>/dev/null | xargs -r ce inspect --format '{{.Image}}' 2>/dev/null | sort -u)

stale_images=()
while IFS=$'\t' read -r repo tag id; do
  # Skip dangling images (already handled above)
  [[ "$repo" == "<none>" ]] && continue

  # Never remove images actively used by a container
  if echo "$running_image_ids" | grep -q "$id" 2>/dev/null; then
    continue
  fi

  if ! should_keep_image "$repo"; then
    stale_images+=("${repo}:${tag}")
  fi
done < <(ce images --format '{{.Repository}}\t{{.Tag}}\t{{.ID}}')

if [[ ${#stale_images[@]} -gt 0 ]]; then
  for img in "${stale_images[@]}"; do
    if [[ "$DRY_RUN" == true ]]; then
      dry "Would remove $img"
    else
      note "Removing $img"
      ce rmi "$img" >/dev/null 2>&1 || warn "Could not remove $img (may share layers)"
      TOTAL_IMAGES_REMOVED=$((TOTAL_IMAGES_REMOVED + 1))
    fi
  done
else
  ok "No stale tagged images found"
fi
echo

# ---------------------------------------------------------------------------
# Step 3: Remove unused volumes
# ---------------------------------------------------------------------------
info "Removing unused volumes..."

# Identify volumes in use by running containers
in_use_volumes=$(ce ps -q 2>/dev/null \
  | xargs -r ce inspect --format '{{range .Mounts}}{{.Name}} {{end}}' 2>/dev/null \
  | tr ' ' '\n' | sort -u | grep -v '^$')

unused_volumes=()
while read -r vol; do
  [[ -z "$vol" ]] && continue
  if ! echo "$in_use_volumes" | grep -qx "$vol" 2>/dev/null; then
    unused_volumes+=("$vol")
  fi
done < <(ce volume ls -q)

if [[ ${#unused_volumes[@]} -gt 0 ]]; then
  note "Found ${#unused_volumes[@]} unused volume(s)"
  for vol in "${unused_volumes[@]}"; do
    if [[ "$DRY_RUN" == true ]]; then
      dry "Would remove volume $vol"
    else
      ce volume rm "$vol" >/dev/null 2>&1 || warn "Could not remove volume $vol"
      TOTAL_VOLUMES_REMOVED=$((TOTAL_VOLUMES_REMOVED + 1))
    fi
  done
else
  ok "No unused volumes found"
fi
echo

# ---------------------------------------------------------------------------
# Step 4: Prune build cache
# ---------------------------------------------------------------------------
if [[ "$SKIP_CACHE" == true ]]; then
  info "Skipping build cache prune (--skip-cache)"
else
  info "Pruning build cache..."
  cache_size=$(ce system df --format '{{.Size}}' 2>/dev/null | tail -1)
  if [[ "$DRY_RUN" == true ]]; then
    dry "Would prune build cache (current size: ${cache_size:-unknown})"
  else
    ce_builder_prune -af 2>&1 | tail -1
  fi
fi
echo

# ---------------------------------------------------------------------------
# Step 5: Clean up any newly-dangling images left after tagged image removal
# ---------------------------------------------------------------------------
remaining_dangling=$(ce images --filter "dangling=true" -q | wc -l | tr -d ' ')
if [[ "$remaining_dangling" -gt 0 ]]; then
  info "Cleaning up $remaining_dangling residual dangling image(s)..."
  if [[ "$DRY_RUN" != true ]]; then
    ce image prune -f >/dev/null 2>&1
    TOTAL_IMAGES_REMOVED=$((TOTAL_IMAGES_REMOVED + remaining_dangling))
  fi
  echo
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
info "Cleanup complete"
echo
if [[ "$DRY_RUN" == true ]]; then
  warn "Dry run -- no changes were made. Re-run without --dry-run to apply."
else
  ce system df
fi
echo

info "Remaining images:"
ce images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"
