#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build the k3s cluster image with bundled helm charts.
#
# Current GPU runtime path:
#   1. require `OPENSHELL_RUNTIME_BUNDLE_TARBALL`
#   2. validate the per-architecture bundle tarball before any Helm or Docker work
#   3. stage its install-root payload under `deploy/docker/.build/runtime-bundle/<arch>/`
#   4. let `deploy/docker/Dockerfile.cluster` copy the staged local runtime files
#      into the cluster image
#
# Environment:
#   IMAGE_TAG                - Image tag (default: dev)
#   K3S_VERSION              - k3s version override (optional; default in Dockerfile.cluster)
#   OPENSHELL_RUNTIME_BUNDLE_TARBALL
#                            - required path to the verified per-arch runtime bundle tarball
#   OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY
#                            - when set to "1", validate and stage the bundle, then exit
#   DOCKER_PLATFORM          - Target platform (optional)
#   DOCKER_BUILDER           - Buildx builder name (default: auto-select)
#   DOCKER_PUSH              - When set to "1", push instead of loading into local daemon
#   IMAGE_REGISTRY           - Registry prefix for image name (e.g. ghcr.io/org/repo)
set -euo pipefail

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

sha256_16() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print substr($1, 1, 16)}'
  else
    shasum -a 256 "$1" | awk '{print substr($1, 1, 16)}'
  fi
}

sha256_16_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print substr($1, 1, 16)}'
  else
    shasum -a 256 | awk '{print substr($1, 1, 16)}'
  fi
}

detect_rust_scope() {
  local dockerfile="$1"
  local rust_from
  rust_from=$(grep -E '^FROM --platform=\$BUILDPLATFORM rust:[^ ]+' "$dockerfile" | head -n1 | sed -E 's/^FROM --platform=\$BUILDPLATFORM rust:([^ ]+).*/\1/' || true)
  if [[ -n "${rust_from}" ]]; then
    echo "rust-${rust_from}"
    return
  fi

  if grep -q "rustup.rs" "$dockerfile"; then
    echo "rustup-stable"
    return
  fi

  echo "no-rust"
}

target_arch() {
  local platform="${DOCKER_PLATFORM:-}"

  if [[ -n "$platform" ]]; then
    if [[ "$platform" == *,* ]]; then
      fail "runtime bundle validation failed: multi-platform builds are not supported yet: ${platform}"
    fi

    case "$platform" in
      linux/amd64)
        printf 'amd64\n'
        return 0
        ;;
      linux/arm64)
        printf 'arm64\n'
        return 0
        ;;
      *)
        fail "runtime bundle validation failed: unsupported docker platform: ${platform}"
        ;;
    esac
  fi

  case "$(uname -m)" in
    x86_64)
      printf 'amd64\n'
      ;;
    aarch64|arm64)
      printf 'arm64\n'
      ;;
    *)
      fail "runtime bundle validation failed: unsupported host architecture: $(uname -m)"
      ;;
  esac
}

target_multiarch() {
  case "$1" in
    amd64)
      printf 'x86_64-linux-gnu\n'
      ;;
    arm64)
      printf 'aarch64-linux-gnu\n'
      ;;
    *)
      fail "runtime bundle validation failed: unsupported runtime bundle architecture: $1"
      ;;
  esac
}

require_path() {
  local bundle_root="$1"
  local relative_path="$2"

  if [[ ! -e "${bundle_root}/${relative_path}" ]]; then
    fail "runtime bundle validation failed: missing required path: ${relative_path}"
  fi
}

require_regular_file() {
  local bundle_root="$1"
  local relative_path="$2"
  local full_path="${bundle_root}/${relative_path}"

  if [[ ! -f "$full_path" || -L "$full_path" ]]; then
    fail "runtime bundle validation failed: invalid required binary entry type: ${relative_path}"
  fi
}

validate_manifest() {
  local bundle_root="$1"
  local manifest_path="$2"
  local expected_arch="$3"

  python3 - "$bundle_root" "$manifest_path" "$expected_arch" <<'PY'
import hashlib
import json
import os
import sys

bundle_root = os.path.abspath(sys.argv[1])
manifest_path = sys.argv[2]
expected_arch = sys.argv[3]


def fail(reason: str) -> None:
    print(reason)
    sys.exit(1)


try:
    with open(manifest_path, encoding="utf-8") as manifest_file:
        manifest = json.load(manifest_file)
except (OSError, json.JSONDecodeError):
    fail("malformed_manifest")

required_fields = (
    "schema_version",
    "bundle_name",
    "bundle_version",
    "architecture",
    "created_at",
    "components",
    "files",
)

for field in required_fields:
    if field not in manifest:
        fail(f"missing_field:{field}")

if manifest["schema_version"] != 1:
    fail("invalid_field:schema_version")

for field in ("bundle_name", "bundle_version", "architecture", "created_at"):
    value = manifest[field]
    if not isinstance(value, str) or not value.strip():
        fail(f"invalid_field:{field}")

components = manifest["components"]
if not isinstance(components, dict):
    fail("invalid_field:components")

for component_name in ("nvidia_container_toolkit", "libnvidia_container"):
    component = components.get(component_name)
    if not isinstance(component, dict):
        fail(f"missing_field:components.{component_name}")
    for component_field in ("version", "commit"):
        value = component.get(component_field)
        if not isinstance(value, str) or not value.strip():
            fail(f"missing_field:components.{component_name}.{component_field}")

manifest_arch = manifest["architecture"].strip()
if manifest_arch != expected_arch:
    fail(f"arch_mismatch:{manifest_arch}")

files = manifest["files"]
if not isinstance(files, list):
    fail("invalid_field:files")

regular_file_entries = 0
listed_paths = set()

for entry in files:
    if not isinstance(entry, dict):
        fail("invalid_field:files[]")

    path = entry.get("path")
    if not isinstance(path, str) or not path.strip():
        fail("missing_field:files[].path")
    path = path.strip()
    listed_paths.add(path)

    full_path = os.path.abspath(os.path.join(bundle_root, path))
    if os.path.commonpath([bundle_root, full_path]) != bundle_root:
        fail(f"invalid_path:{path}")

    entry_type = entry.get("entry_type")
    if entry_type == "file":
        regular_file_entries += 1

        sha256 = entry.get("sha256")
        size = entry.get("size")
        if not isinstance(sha256, str) or not sha256.strip():
            fail(f"missing_field:files[].sha256:{path}")
        if not isinstance(size, int) or size < 0:
            fail(f"missing_field:files[].size:{path}")
        if not os.path.isfile(full_path) or os.path.islink(full_path):
            fail(f"missing_payload:{path}")

        digest = hashlib.sha256()
        with open(full_path, "rb") as file_obj:
            while True:
                chunk = file_obj.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)

        if digest.hexdigest() != sha256:
            fail(f"checksum_mismatch:{path}")

        if os.path.getsize(full_path) != size:
            fail(f"size_mismatch:{path}")
    elif entry_type == "symlink":
        if not os.path.islink(full_path):
            fail(f"missing_payload:{path}")
    else:
        fail(f"invalid_field:files[].entry_type:{path}")

if regular_file_entries == 0:
    fail("invalid_field:files")

required_manifest_paths = (
    "usr/bin/nvidia-cdi-hook",
    "usr/bin/nvidia-container-runtime",
    "usr/bin/nvidia-container-runtime-hook",
    "usr/bin/nvidia-container-cli",
    "usr/bin/nvidia-ctk",
    "etc/nvidia-container-runtime/config.toml",
)

for path in required_manifest_paths:
    if path not in listed_paths:
        fail(f"required_manifest_path_missing:{path}")

for root, _, filenames in os.walk(bundle_root):
    for filename in filenames:
        full_path = os.path.join(root, filename)
        rel_path = os.path.relpath(full_path, bundle_root)
        if rel_path == "manifest.json":
            continue
        if rel_path not in listed_paths:
            fail(f"unlisted_payload:{rel_path}")

    for filename in [name for name in os.listdir(root) if os.path.islink(os.path.join(root, name))]:
        full_path = os.path.join(root, filename)
        rel_path = os.path.relpath(full_path, bundle_root)
        if rel_path == "manifest.json":
            continue
        if rel_path not in listed_paths:
            fail(f"unlisted_payload:{rel_path}")

print("ok")
PY
}

stage_runtime_bundle() {
  local bundle_tarball="$1"
  local arch="$2"
  local multiarch="$3"
  local extract_dir
  local tar_stderr
  local stage_tmp_root
  local manifest_path
  local manifest_validation
  local bundle_root
  local bundle_name
  local stage_parent_root="deploy/docker/.build/runtime-bundle"
  local stage_root="deploy/docker/.build/runtime-bundle/${arch}"
  local staged_bundle_path

  rm -rf "$stage_root"
  mkdir -p "$stage_parent_root"

  extract_dir="$(mktemp -d)"
  tar_stderr="$(mktemp)"
  stage_tmp_root="$(mktemp -d "$stage_parent_root/${arch}.tmp.XXXXXX")"
  cleanup_stage_runtime_bundle() {
    rm -rf "$extract_dir" "$stage_tmp_root"
    rm -f "$tar_stderr"
  }
  trap cleanup_stage_runtime_bundle RETURN

  if ! tar -xzf "$bundle_tarball" -C "$extract_dir" 2>"$tar_stderr"; then
    fail "runtime bundle validation failed: tar extraction reported warnings or errors"
  fi

  if [[ -s "$tar_stderr" || -n "${TAR_STDERR_MESSAGE:-}" ]]; then
    if [[ -n "${TAR_STDERR_MESSAGE:-}" ]]; then
      printf '%s\n' "${TAR_STDERR_MESSAGE}" > "$tar_stderr"
    fi
    fail "runtime bundle validation failed: tar extraction reported warnings or errors"
  fi

  local extracted_entries=()
  local entry
  shopt -s dotglob nullglob
  for entry in "$extract_dir"/*; do
    extracted_entries+=("$entry")
  done
  shopt -u dotglob nullglob

  if [[ "${#extracted_entries[@]}" -ne 1 || ! -d "${extracted_entries[0]}" ]]; then
    fail "runtime bundle validation failed: expected a single top-level bundle directory"
  fi

  bundle_root="${extracted_entries[0]}"
  bundle_name="$(basename "$bundle_root")"
  manifest_path="$bundle_root/manifest.json"

  if [[ ! -f "$manifest_path" ]]; then
    fail "runtime bundle validation failed: missing bundle manifest.json"
  fi

  if ! manifest_validation="$(validate_manifest "$bundle_root" "$manifest_path" "$arch")"; then
    case "$manifest_validation" in
      malformed_manifest)
        fail "runtime bundle validation failed: malformed manifest.json"
        ;;
      missing_field:*)
        fail "runtime bundle validation failed: missing required manifest field: ${manifest_validation#missing_field:}"
        ;;
      required_manifest_path_missing:*)
        fail "runtime bundle validation failed: required runtime asset missing from manifest.json: ${manifest_validation#required_manifest_path_missing:}"
        ;;
      invalid_field:*)
        fail "runtime bundle validation failed: malformed manifest.json"
        ;;
      arch_mismatch:*)
        fail "runtime bundle validation failed: bundle architecture mismatch: expected ${arch}, got ${manifest_validation#arch_mismatch:}"
        ;;
      checksum_mismatch:*)
        fail "runtime bundle validation failed: checksum mismatch: ${manifest_validation#checksum_mismatch:}"
        ;;
      size_mismatch:*)
        fail "runtime bundle validation failed: size mismatch: ${manifest_validation#size_mismatch:}"
        ;;
      missing_payload:*)
        fail "runtime bundle validation failed: missing manifest-listed payload path: ${manifest_validation#missing_payload:}"
        ;;
      invalid_path:*)
        fail "runtime bundle validation failed: invalid manifest-listed payload path: ${manifest_validation#invalid_path:}"
        ;;
      unlisted_payload:*)
        fail "runtime bundle validation failed: unlisted payload path present on disk: ${manifest_validation#unlisted_payload:}"
        ;;
      *)
        fail "runtime bundle validation failed: malformed manifest.json"
        ;;
    esac
  fi

  require_path "$bundle_root" "usr/bin/nvidia-cdi-hook"
  require_path "$bundle_root" "usr/bin/nvidia-container-runtime"
  require_path "$bundle_root" "usr/bin/nvidia-container-runtime-hook"
  require_path "$bundle_root" "usr/bin/nvidia-container-cli"
  require_path "$bundle_root" "usr/bin/nvidia-ctk"
  require_regular_file "$bundle_root" "usr/bin/nvidia-cdi-hook"
  require_regular_file "$bundle_root" "usr/bin/nvidia-container-runtime"
  require_regular_file "$bundle_root" "usr/bin/nvidia-container-runtime-hook"
  require_regular_file "$bundle_root" "usr/bin/nvidia-container-cli"
  require_regular_file "$bundle_root" "usr/bin/nvidia-ctk"
  require_path "$bundle_root" "etc/nvidia-container-runtime"

  if [[ ! -d "$bundle_root/etc/nvidia-container-runtime" ]]; then
    fail "runtime bundle validation failed: required path is not a directory: etc/nvidia-container-runtime"
  fi

  compgen -G "$bundle_root/usr/lib/${multiarch}/libnvidia-container*.so*" >/dev/null || \
    fail "runtime bundle validation failed: missing required library subtree: usr/lib/${multiarch}/libnvidia-container*.so*"

  staged_bundle_path="$stage_tmp_root/$bundle_name"
  cp -a "$bundle_root" "$staged_bundle_path"
  mv "$stage_tmp_root" "$stage_root"

  printf '%s\n' "$stage_root/$bundle_name"
}

IMAGE_TAG=${IMAGE_TAG:-dev}
IMAGE_NAME="openshell/cluster"
if [[ -n "${IMAGE_REGISTRY:-}" ]]; then
  IMAGE_NAME="${IMAGE_REGISTRY}/cluster"
fi
DOCKER_BUILD_CACHE_DIR=${DOCKER_BUILD_CACHE_DIR:-.cache/buildkit}
CACHE_PATH="${DOCKER_BUILD_CACHE_DIR}/cluster"

mkdir -p "${CACHE_PATH}"

if [[ -z "${OPENSHELL_RUNTIME_BUNDLE_TARBALL:-}" ]]; then
  fail "missing required variable: OPENSHELL_RUNTIME_BUNDLE_TARBALL"
fi

if [[ ! -f "${OPENSHELL_RUNTIME_BUNDLE_TARBALL}" ]]; then
  fail "runtime bundle validation failed: tarball not found: ${OPENSHELL_RUNTIME_BUNDLE_TARBALL}"
fi

TARGET_ARCH="$(target_arch)"
TARGET_MULTIARCH="$(target_multiarch "$TARGET_ARCH")"
STAGED_RUNTIME_BUNDLE="$(stage_runtime_bundle "${OPENSHELL_RUNTIME_BUNDLE_TARBALL}" "$TARGET_ARCH" "$TARGET_MULTIARCH")"

if [[ "${OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY:-}" == "1" ]]; then
  printf 'Runtime bundle staged at %s\n' "$STAGED_RUNTIME_BUNDLE"
  exit 0
fi

# Select builder — prefer native "docker" driver for local single-arch builds
# to avoid slow tarball export from the docker-container driver.
BUILDER_ARGS=()
if [[ -n "${DOCKER_BUILDER:-}" ]]; then
  BUILDER_ARGS=(--builder "${DOCKER_BUILDER}")
elif [[ -z "${DOCKER_PLATFORM:-}" && -z "${CI:-}" ]]; then
  _ctx=$(docker context inspect --format '{{.Name}}' 2>/dev/null || echo default)
  BUILDER_ARGS=(--builder "${_ctx}")
fi

CACHE_ARGS=()
if [[ -z "${CI:-}" ]]; then
  # Local development: use filesystem cache with docker-container driver.
  if docker buildx inspect ${BUILDER_ARGS[@]+"${BUILDER_ARGS[@]}"} 2>/dev/null | grep -q "Driver: docker-container"; then
    CACHE_ARGS=(
      --cache-from "type=local,src=${CACHE_PATH}"
      --cache-to "type=local,dest=${CACHE_PATH},mode=max"
    )
  fi
fi

# Create build directory for charts
mkdir -p deploy/docker/.build/charts

# Runtime-bundle handoff:
# - this script is the required acquisition/verification point before
#   any Helm packaging or `docker buildx build`
# - it validates manifest metadata plus manifest-authoritative payload checks,
#   then stages the extracted install-root tree in `deploy/docker/.build/`
# - `deploy/docker/Dockerfile.cluster` consumes only that staged local payload

# Package helm chart
echo "Packaging helm chart..."
helm package deploy/helm/openshell -d deploy/docker/.build/charts/

# Build cluster image (no bundled component images — they are pulled at runtime
# from the distribution registry; credentials are injected at deploy time)
echo "Building cluster image..."

SCCACHE_ARGS=()
if [[ -n "${SCCACHE_MEMCACHED_ENDPOINT:-}" ]]; then
  SCCACHE_ARGS=(--build-arg "SCCACHE_MEMCACHED_ENDPOINT=${SCCACHE_MEMCACHED_ENDPOINT}")
fi

OUTPUT_FLAG="--load"
if [[ "${DOCKER_PUSH:-}" == "1" ]]; then
  OUTPUT_FLAG="--push"
elif [[ "${DOCKER_PLATFORM:-}" == *","* ]]; then
  # Multi-platform builds cannot use --load; push is required.
  OUTPUT_FLAG="--push"
fi

# Compute cargo version from git tags (same scheme as docker-build-component.sh).
VERSION_ARGS=()
if [[ -n "${OPENSHELL_CARGO_VERSION:-}" ]]; then
  VERSION_ARGS=(--build-arg "OPENSHELL_CARGO_VERSION=${OPENSHELL_CARGO_VERSION}")
else
  CARGO_VERSION=$(uv run python tasks/scripts/release.py get-version --cargo 2>/dev/null || true)
  if [[ -n "${CARGO_VERSION}" ]]; then
    VERSION_ARGS=(--build-arg "OPENSHELL_CARGO_VERSION=${CARGO_VERSION}")
  fi
fi

LOCK_HASH=$(sha256_16 Cargo.lock)
RUST_SCOPE=${RUST_TOOLCHAIN_SCOPE:-$(detect_rust_scope "deploy/docker/Dockerfile.cluster")}
CACHE_SCOPE_INPUT="v1|cluster|base|${LOCK_HASH}|${RUST_SCOPE}"
CARGO_TARGET_CACHE_SCOPE=$(printf '%s' "${CACHE_SCOPE_INPUT}" | sha256_16_stdin)

docker buildx build \
  ${BUILDER_ARGS[@]+"${BUILDER_ARGS[@]}"} \
  ${DOCKER_PLATFORM:+--platform ${DOCKER_PLATFORM}} \
  ${CACHE_ARGS[@]+"${CACHE_ARGS[@]}"} \
  ${SCCACHE_ARGS[@]+"${SCCACHE_ARGS[@]}"} \
  ${VERSION_ARGS[@]+"${VERSION_ARGS[@]}"} \
  --build-arg "CARGO_TARGET_CACHE_SCOPE=${CARGO_TARGET_CACHE_SCOPE}" \
  -f deploy/docker/Dockerfile.cluster \
  -t ${IMAGE_NAME}:${IMAGE_TAG} \
  ${K3S_VERSION:+--build-arg K3S_VERSION=${K3S_VERSION}} \
  --provenance=false \
  ${OUTPUT_FLAG} \
  .

echo "Done! Cluster image: ${IMAGE_NAME}:${IMAGE_TAG}"
