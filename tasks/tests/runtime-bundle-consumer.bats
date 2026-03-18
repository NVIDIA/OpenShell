#!/usr/bin/env bats

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

setup() {
  export TEST_TMPDIR
  TEST_TMPDIR="$(mktemp -d)"
  export FAKE_BIN_DIR="$TEST_TMPDIR/bin"
  export FAKE_DOCKER_LOG="$TEST_TMPDIR/docker.log"
  export FAKE_HELM_LOG="$TEST_TMPDIR/helm.log"
  mkdir -p "$FAKE_BIN_DIR"

  cat > "$FAKE_BIN_DIR/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
if [[ "${1:-}" == "buildx" && "${2:-}" == "build" ]]; then
  if [[ "${ASSERT_RUNTIME_BUNDLE_STAGE_ON_BUILD:-0}" == "1" ]]; then
    staged_root="deploy/docker/.build/runtime-bundle/${ASSERT_RUNTIME_BUNDLE_STAGE_ARCH:-amd64}"
    if [[ ! -d "$staged_root" ]]; then
      printf 'missing staged runtime bundle root: %s\n' "$staged_root" >&2
      exit 19
    fi
    if ! compgen -G "$staged_root/*/usr/bin/nvidia-container-cli" >/dev/null; then
      printf 'missing staged runtime bundle payload under: %s\n' "$staged_root" >&2
      exit 20
    fi
  fi
  exit 0
fi
exit 0
EOF
  chmod +x "$FAKE_BIN_DIR/docker"

  cat > "$FAKE_BIN_DIR/helm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_HELM_LOG"
output_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d)
      output_dir="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$output_dir" ]]; then
  mkdir -p "$output_dir"
  : > "$output_dir/openshell-0.0.0.tgz"
fi
EOF
  chmod +x "$FAKE_BIN_DIR/helm"

  rm -rf deploy/docker/.build/runtime-bundle
}

teardown() {
  rm -rf deploy/docker/.build/runtime-bundle
  rm -rf "$TEST_TMPDIR"
}

run_cluster_build() {
  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    OPENSHELL_CARGO_VERSION=0.0.0-test \
    "$@" \
    bash tasks/scripts/docker-build-cluster.sh
}

assert_no_docker_buildx_build() {
  if [[ -f "$FAKE_DOCKER_LOG" ]]; then
    ! grep -Fq "buildx build" "$FAKE_DOCKER_LOG"
  fi
}

assert_no_docker_commands() {
  if [[ -f "$FAKE_DOCKER_LOG" ]]; then
    [ ! -s "$FAKE_DOCKER_LOG" ]
  fi
}

assert_no_helm_commands() {
  if [[ -f "$FAKE_HELM_LOG" ]]; then
    [ ! -s "$FAKE_HELM_LOG" ]
  fi
}

assert_runtime_bundle_not_staged() {
  [ ! -e deploy/docker/.build/runtime-bundle ]
}

assert_runtime_bundle_arch_not_staged() {
  local arch="$1"
  [ ! -e "deploy/docker/.build/runtime-bundle/$arch" ]
}

seed_stale_runtime_bundle_stage() {
  local arch="$1"
  local staged_root="deploy/docker/.build/runtime-bundle/$arch"
  mkdir -p "$staged_root"
  printf 'stale\n' > "$staged_root/stale.txt"
}

create_runtime_bundle_tarball() {
  local tarball_path="$1"
  local bundle_arch="${2:-amd64}"
  local bundle_dir_name="openshell-gpu-runtime-bundle_0.1.0_${bundle_arch}"
  local bundle_root="$TEST_TMPDIR/${bundle_dir_name}"
  local multiarch="x86_64-linux-gnu"
  local manifest_arch="$bundle_arch"

  if [[ -n "${3:-}" ]]; then
    manifest_arch="$3"
  fi

  if [[ "$bundle_arch" == "arm64" ]]; then
    multiarch="aarch64-linux-gnu"
  fi

  mkdir -p \
    "$bundle_root/usr/bin" \
    "$bundle_root/etc/nvidia-container-runtime" \
    "$bundle_root/usr/lib/$multiarch"

  printf 'cdi-hook\n' > "$bundle_root/usr/bin/nvidia-cdi-hook"
  printf 'runtime\n' > "$bundle_root/usr/bin/nvidia-container-runtime"
  printf 'runtime-hook\n' > "$bundle_root/usr/bin/nvidia-container-runtime-hook"
  printf 'container-cli\n' > "$bundle_root/usr/bin/nvidia-container-cli"
  printf 'ctk\n' > "$bundle_root/usr/bin/nvidia-ctk"
  printf 'config = true\n' > "$bundle_root/etc/nvidia-container-runtime/config.toml"
  printf 'libnvidia-container\n' > "$bundle_root/usr/lib/$multiarch/libnvidia-container.so.1"

  local cdi_hook_sha runtime_sha runtime_hook_sha cli_sha ctk_sha config_sha lib_sha
  cdi_hook_sha="$(sha256sum "$bundle_root/usr/bin/nvidia-cdi-hook" | cut -d ' ' -f 1)"
  runtime_sha="$(sha256sum "$bundle_root/usr/bin/nvidia-container-runtime" | cut -d ' ' -f 1)"
  runtime_hook_sha="$(sha256sum "$bundle_root/usr/bin/nvidia-container-runtime-hook" | cut -d ' ' -f 1)"
  cli_sha="$(sha256sum "$bundle_root/usr/bin/nvidia-container-cli" | cut -d ' ' -f 1)"
  ctk_sha="$(sha256sum "$bundle_root/usr/bin/nvidia-ctk" | cut -d ' ' -f 1)"
  config_sha="$(sha256sum "$bundle_root/etc/nvidia-container-runtime/config.toml" | cut -d ' ' -f 1)"
  lib_sha="$(sha256sum "$bundle_root/usr/lib/$multiarch/libnvidia-container.so.1" | cut -d ' ' -f 1)"

  cat > "$bundle_root/manifest.json" <<EOF
{
  "schema_version": 1,
  "bundle_name": "openshell-gpu-runtime-bundle",
  "bundle_version": "0.1.0",
  "architecture": "${manifest_arch}",
  "created_at": "2026-03-18T12:34:56Z",
    "components": {
      "nvidia_container_toolkit": {
        "version": "1.17.8-openshell.1",
        "commit": "0123456789abcdef0123456789abcdef01234567"
      },
      "libnvidia_container": {
        "version": "1.17.8-openshell.1",
        "commit": "89abcdef0123456789abcdef0123456789abcdef"
      }
    },
    "files": [
      {
        "path": "usr/bin/nvidia-cdi-hook",
        "entry_type": "file",
        "sha256": "${cdi_hook_sha}",
        "size": 9
      },
      {
        "path": "usr/bin/nvidia-container-runtime",
        "entry_type": "file",
        "sha256": "${runtime_sha}",
        "size": 8
      },
      {
        "path": "usr/bin/nvidia-container-runtime-hook",
        "entry_type": "file",
        "sha256": "${runtime_hook_sha}",
        "size": 13
      },
      {
        "path": "usr/bin/nvidia-container-cli",
        "entry_type": "file",
        "sha256": "${cli_sha}",
        "size": 14
      },
      {
        "path": "usr/bin/nvidia-ctk",
        "entry_type": "file",
        "sha256": "${ctk_sha}",
        "size": 4
      },
      {
        "path": "etc/nvidia-container-runtime/config.toml",
        "entry_type": "file",
        "sha256": "${config_sha}",
        "size": 14
      },
      {
        "path": "usr/lib/${multiarch}/libnvidia-container.so.1",
        "entry_type": "file",
        "sha256": "${lib_sha}",
        "size": 20
      }
    ]
  }
EOF

  tar -czf "$tarball_path" -C "$TEST_TMPDIR" "$bundle_dir_name"
}

create_runtime_bundle_tarball_without_manifest() {
  local tarball_path="$1"
  local bundle_dir_name="openshell-gpu-runtime-bundle_0.1.0_amd64"
  local bundle_root="$TEST_TMPDIR/${bundle_dir_name}"

  mkdir -p \
    "$bundle_root/usr/bin" \
    "$bundle_root/etc/nvidia-container-runtime" \
    "$bundle_root/usr/lib/x86_64-linux-gnu"

  printf 'cdi-hook\n' > "$bundle_root/usr/bin/nvidia-cdi-hook"
  printf 'runtime\n' > "$bundle_root/usr/bin/nvidia-container-runtime"
  printf 'runtime-hook\n' > "$bundle_root/usr/bin/nvidia-container-runtime-hook"
  printf 'container-cli\n' > "$bundle_root/usr/bin/nvidia-container-cli"
  printf 'ctk\n' > "$bundle_root/usr/bin/nvidia-ctk"
  printf 'config = true\n' > "$bundle_root/etc/nvidia-container-runtime/config.toml"
  printf 'libnvidia-container\n' > "$bundle_root/usr/lib/x86_64-linux-gnu/libnvidia-container.so.1"

  tar -czf "$tarball_path" -C "$TEST_TMPDIR" "$bundle_dir_name"
}

create_runtime_bundle_tarball_with_missing_required_manifest_field() {
  local tarball_path="$1"

  create_runtime_bundle_tarball "$tarball_path"

  python3 - "$tarball_path" <<'PY'
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile

tarball_path = pathlib.Path(sys.argv[1])

with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = pathlib.Path(temp_dir)
    with tarfile.open(tarball_path, "r:gz") as archive:
        archive.extractall(temp_path)

    bundle_root = next(temp_path.iterdir())
    manifest_path = bundle_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["created_at"]
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    subprocess.run(["tar", "-czf", str(tarball_path), "-C", str(temp_path), bundle_root.name], check=True)
PY
}

create_runtime_bundle_tarball_with_checksum_mismatch() {
  local tarball_path="$1"

  create_runtime_bundle_tarball "$tarball_path"

  python3 - "$tarball_path" <<'PY'
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile

tarball_path = pathlib.Path(sys.argv[1])

with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = pathlib.Path(temp_dir)
    with tarfile.open(tarball_path, "r:gz") as archive:
        archive.extractall(temp_path)

    bundle_root = next(temp_path.iterdir())
    manifest_path = bundle_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    for entry in manifest["files"]:
        if entry.get("path") == "usr/bin/nvidia-container-cli":
            entry["sha256"] = "0" * 64
            break
    else:
        raise AssertionError("missing nvidia-container-cli entry")

    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    subprocess.run(["tar", "-czf", str(tarball_path), "-C", str(temp_path), bundle_root.name], check=True)
PY
}

create_runtime_bundle_tarball_with_missing_required_manifest_entry() {
  local tarball_path="$1"

  create_runtime_bundle_tarball "$tarball_path"

  python3 - "$tarball_path" <<'PY'
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile

tarball_path = pathlib.Path(sys.argv[1])

with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = pathlib.Path(temp_dir)
    with tarfile.open(tarball_path, "r:gz") as archive:
        archive.extractall(temp_path)

    bundle_root = next(temp_path.iterdir())
    manifest_path = bundle_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"] = [
        entry for entry in manifest["files"]
        if entry.get("path") != "usr/bin/nvidia-container-cli"
    ]
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    subprocess.run(["tar", "-czf", str(tarball_path), "-C", str(temp_path), bundle_root.name], check=True)
PY
}

create_runtime_bundle_tarball_with_extra_unlisted_file() {
  local tarball_path="$1"

  create_runtime_bundle_tarball "$tarball_path"

  python3 - "$tarball_path" <<'PY'
import pathlib
import subprocess
import sys
import tarfile
import tempfile

tarball_path = pathlib.Path(sys.argv[1])

with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = pathlib.Path(temp_dir)
    with tarfile.open(tarball_path, "r:gz") as archive:
        archive.extractall(temp_path)

    bundle_root = next(temp_path.iterdir())
    extra_path = bundle_root / "usr/bin/nvidia-container-extra"
    extra_path.write_text("extra\n", encoding="utf-8")

    subprocess.run(["tar", "-czf", str(tarball_path), "-C", str(temp_path), bundle_root.name], check=True)
PY
}

create_runtime_bundle_tarball_with_size_mismatch() {
  local tarball_path="$1"

  create_runtime_bundle_tarball "$tarball_path"

  python3 - "$tarball_path" <<'PY'
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile

tarball_path = pathlib.Path(sys.argv[1])

with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = pathlib.Path(temp_dir)
    with tarfile.open(tarball_path, "r:gz") as archive:
        archive.extractall(temp_path)

    bundle_root = next(temp_path.iterdir())
    manifest_path = bundle_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    for entry in manifest["files"]:
        if entry.get("path") == "usr/bin/nvidia-container-cli":
            entry["size"] = entry["size"] + 1
            break
    else:
        raise AssertionError("missing nvidia-container-cli entry")

    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    subprocess.run(["tar", "-czf", str(tarball_path), "-C", str(temp_path), bundle_root.name], check=True)
PY
}

create_runtime_bundle_tarball_with_invalid_manifest() {
  local tarball_path="$1"
  local bundle_dir_name="openshell-gpu-runtime-bundle_0.1.0_amd64"
  local bundle_root="$TEST_TMPDIR/${bundle_dir_name}"

  mkdir -p \
    "$bundle_root/usr/bin" \
    "$bundle_root/etc/nvidia-container-runtime" \
    "$bundle_root/usr/lib/x86_64-linux-gnu"

  touch "$bundle_root/usr/bin/nvidia-cdi-hook"
  touch "$bundle_root/usr/bin/nvidia-container-runtime"
  touch "$bundle_root/usr/bin/nvidia-container-runtime-hook"
  touch "$bundle_root/usr/bin/nvidia-container-cli"
  touch "$bundle_root/usr/bin/nvidia-ctk"
  touch "$bundle_root/etc/nvidia-container-runtime/config.toml"
  touch "$bundle_root/usr/lib/x86_64-linux-gnu/libnvidia-container.so.1"

  printf '{ invalid json\n' > "$bundle_root/manifest.json"

  tar -czf "$tarball_path" -C "$TEST_TMPDIR" "$bundle_dir_name"
}

create_runtime_bundle_tarball_with_unsafe_entry() {
  local tarball_path="$1"

  python3 - "$tarball_path" <<'PY'
import io
import tarfile
import time
import sys

tarball_path = sys.argv[1]

with tarfile.open(tarball_path, "w:gz") as archive:
    dir_info = tarfile.TarInfo("openshell-gpu-runtime-bundle_0.1.0_amd64")
    dir_info.type = tarfile.DIRTYPE
    dir_info.mode = 0o755
    dir_info.mtime = int(time.time())
    archive.addfile(dir_info)

    manifest = b'{"architecture":"amd64"}'
    manifest_info = tarfile.TarInfo("openshell-gpu-runtime-bundle_0.1.0_amd64/manifest.json")
    manifest_info.size = len(manifest)
    manifest_info.mode = 0o644
    manifest_info.mtime = int(time.time())
    archive.addfile(manifest_info, io.BytesIO(manifest))

    unsafe_data = b'escape\n'
    unsafe_info = tarfile.TarInfo("../../outside.txt")
    unsafe_info.size = len(unsafe_data)
    unsafe_info.mode = 0o644
    unsafe_info.mtime = int(time.time())
    archive.addfile(unsafe_info, io.BytesIO(unsafe_data))
PY
}

create_runtime_bundle_tarball_with_tar_warning() {
  local tarball_path="$1"
  local bundle_dir_name="openshell-gpu-runtime-bundle_0.1.0_amd64"
  local bundle_root="$TEST_TMPDIR/${bundle_dir_name}"

  mkdir -p "$bundle_root/usr/bin" "$bundle_root/etc/nvidia-container-runtime" "$bundle_root/usr/lib/x86_64-linux-gnu"
  touch "$bundle_root/usr/bin/nvidia-cdi-hook"
  touch "$bundle_root/usr/bin/nvidia-container-runtime"
  touch "$bundle_root/usr/bin/nvidia-container-runtime-hook"
  touch "$bundle_root/usr/bin/nvidia-container-cli"
  touch "$bundle_root/usr/bin/nvidia-ctk"
  touch "$bundle_root/etc/nvidia-container-runtime/config.toml"
  touch "$bundle_root/usr/lib/x86_64-linux-gnu/libnvidia-container.so.1"

  cat > "$bundle_root/manifest.json" <<'EOF'
{
  "architecture": "amd64"
}
EOF

  tar -czf "$tarball_path" -C "$TEST_TMPDIR" "$bundle_dir_name"
}

create_runtime_bundle_tarball_with_hidden_top_level_entry() {
  local tarball_path="$1"

  create_runtime_bundle_tarball "$tarball_path"
  printf 'hidden\n' > "$TEST_TMPDIR/.hidden-top-level"
  tar -czf "$tarball_path" -C "$TEST_TMPDIR" ".hidden-top-level" "openshell-gpu-runtime-bundle_0.1.0_amd64"
}

create_runtime_bundle_tarball_with_symlinked_required_binary() {
  local tarball_path="$1"

  create_runtime_bundle_tarball "$tarball_path"

  python3 - "$tarball_path" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile

tarball_path = pathlib.Path(sys.argv[1])

with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = pathlib.Path(temp_dir)
    with tarfile.open(tarball_path, "r:gz") as archive:
        archive.extractall(temp_path)

    bundle_root = next(temp_path.iterdir())
    cli_path = bundle_root / "usr/bin/nvidia-container-cli"
    cli_real_path = bundle_root / "usr/bin/nvidia-container-cli.real"
    cli_real_path.write_bytes(cli_path.read_bytes())
    cli_path.unlink()
    cli_path.symlink_to("nvidia-container-cli.real")

    manifest_path = bundle_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for index, entry in enumerate(manifest["files"]):
        if entry.get("path") == "usr/bin/nvidia-container-cli":
            manifest["files"][index] = {
                "path": "usr/bin/nvidia-container-cli",
                "entry_type": "symlink",
                "target": "nvidia-container-cli.real",
            }
            break
    else:
        raise AssertionError("missing nvidia-container-cli entry")

    real_digest = hashlib.sha256(cli_real_path.read_bytes()).hexdigest()
    manifest["files"].append(
        {
            "path": "usr/bin/nvidia-container-cli.real",
            "entry_type": "file",
            "sha256": real_digest,
            "size": cli_real_path.stat().st_size,
        }
    )

    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    subprocess.run(["tar", "-czf", str(tarball_path), "-C", str(temp_path), bundle_root.name], check=True)
PY
}

@test "docker-build-cluster requires a runtime bundle tarball before helm or docker build by default" {
  run_cluster_build env -u OPENSHELL_RUNTIME_BUNDLE_TARBALL

  [ "$status" -ne 0 ]
  [[ "$output" == *"missing required variable: OPENSHELL_RUNTIME_BUNDLE_TARBALL"* ]]
  assert_no_docker_commands
  assert_no_helm_commands
  assert_runtime_bundle_not_staged
  assert_no_docker_buildx_build
}

@test "docker-build-cluster stages the runtime bundle before invoking docker buildx build by default" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-build-default.tar.gz"

  create_runtime_bundle_tarball "$runtime_tarball"

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    ASSERT_RUNTIME_BUNDLE_STAGE_ON_BUILD=1 \
    ASSERT_RUNTIME_BUNDLE_STAGE_ARCH=amd64 \
    DOCKER_PLATFORM=linux/amd64

  [ "$status" -eq 0 ]
  [[ "$output" == *"Packaging helm chart..."* ]]
  [[ "$output" == *"Building cluster image..."* ]]
  [ -s "$FAKE_HELM_LOG" ]
  [ -s "$FAKE_DOCKER_LOG" ]
  [[ "$(<"$FAKE_DOCKER_LOG")" == *"buildx build"* ]]
  [ -d "deploy/docker/.build/runtime-bundle/amd64" ]
}

@test "docker-build-cluster forwards cluster cache and sccache build args into docker buildx build" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-build-cache-args.tar.gz"

  create_runtime_bundle_tarball "$runtime_tarball"

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    DOCKER_PLATFORM=linux/amd64 \
    SCCACHE_MEMCACHED_ENDPOINT=memcached://cache.internal:11211

  [ "$status" -eq 0 ]
  [[ "$(<"$FAKE_DOCKER_LOG")" == *"--build-arg CARGO_TARGET_CACHE_SCOPE="* ]]
  [[ "$(<"$FAKE_DOCKER_LOG")" == *"--build-arg SCCACHE_MEMCACHED_ENDPOINT=memcached://cache.internal:11211"* ]]
}

@test "docker-build-cluster rejects malformed runtime bundle tarballs before helm or docker" {
  local malformed_tarball="$TEST_TMPDIR/runtime-bundle-malformed.tar.gz"
  mkdir -p "$TEST_TMPDIR/malformed"
  : > "$TEST_TMPDIR/malformed/not-a-bundle.txt"
  tar -czf "$malformed_tarball" -C "$TEST_TMPDIR/malformed" .

  run_cluster_build OPENSHELL_RUNTIME_BUNDLE_TARBALL="$malformed_tarball"

  [ "$status" -ne 0 ]
  [[ "$output" == *"runtime bundle validation failed: expected a single top-level bundle directory"* ]]
  assert_no_docker_commands
  assert_no_helm_commands
  assert_runtime_bundle_arch_not_staged amd64
  assert_no_docker_buildx_build
}

@test "docker-build-cluster accepts current producer-shaped tarballs in script-only verification mode" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-valid-producer-shape.tar.gz"
  local staged_root="deploy/docker/.build/runtime-bundle/amd64"
  local staged_bundle_dir="$staged_root/openshell-gpu-runtime-bundle_0.1.0_amd64"

  create_runtime_bundle_tarball "$runtime_tarball"

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY=1 \
    DOCKER_PLATFORM=linux/amd64

  [ "$status" -eq 0 ]
  [[ "$output" == *"Runtime bundle staged at $staged_bundle_dir"* ]]
  [ -d "$staged_bundle_dir" ]
  [ -f "$staged_bundle_dir/manifest.json" ]
  [ -f "$staged_bundle_dir/usr/bin/nvidia-container-cli" ]
  assert_no_docker_commands
  assert_no_helm_commands
  assert_no_docker_buildx_build
}

@test "docker-build-cluster rejects malformed manifest.json before helm or docker" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-invalid-manifest.tar.gz"
  local staged_root="deploy/docker/.build/runtime-bundle/amd64"

  create_runtime_bundle_tarball_with_invalid_manifest "$runtime_tarball"
  seed_stale_runtime_bundle_stage amd64

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY=1 \
    DOCKER_PLATFORM=linux/amd64

  [ "$status" -ne 0 ]
  [[ "$output" == *"runtime bundle validation failed: malformed manifest.json"* ]]
  assert_no_docker_commands
  assert_no_helm_commands
  [ ! -e "$staged_root" ]
  assert_no_docker_buildx_build
}

@test "docker-build-cluster rejects missing manifest.json before helm or docker" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-missing-manifest.tar.gz"
  local staged_root="deploy/docker/.build/runtime-bundle/amd64"

  create_runtime_bundle_tarball_without_manifest "$runtime_tarball"
  seed_stale_runtime_bundle_stage amd64

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY=1 \
    DOCKER_PLATFORM=linux/amd64

  [ "$status" -ne 0 ]
  [[ "$output" == *"runtime bundle validation failed: missing bundle manifest.json"* ]]
  assert_no_docker_commands
  assert_no_helm_commands
  [ ! -e "$staged_root" ]
  assert_no_docker_buildx_build
}

@test "docker-build-cluster rejects missing required manifest fields before helm or docker" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-missing-manifest-field.tar.gz"
  local staged_root="deploy/docker/.build/runtime-bundle/amd64"

  create_runtime_bundle_tarball_with_missing_required_manifest_field "$runtime_tarball"
  seed_stale_runtime_bundle_stage amd64

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY=1 \
    DOCKER_PLATFORM=linux/amd64

  [ "$status" -ne 0 ]
  [[ "$output" == *"runtime bundle validation failed: missing required manifest field: created_at"* ]]
  assert_no_docker_commands
  assert_no_helm_commands
  [ ! -e "$staged_root" ]
  assert_no_docker_buildx_build
}

@test "docker-build-cluster rejects checksum mismatches before helm or docker" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-checksum-mismatch.tar.gz"
  local staged_root="deploy/docker/.build/runtime-bundle/amd64"

  create_runtime_bundle_tarball_with_checksum_mismatch "$runtime_tarball"
  seed_stale_runtime_bundle_stage amd64

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY=1 \
    DOCKER_PLATFORM=linux/amd64

  [ "$status" -ne 0 ]
  [[ "$output" == *"runtime bundle validation failed: checksum mismatch: usr/bin/nvidia-container-cli"* ]]
  assert_no_docker_commands
  assert_no_helm_commands
  [ ! -e "$staged_root" ]
  assert_no_docker_buildx_build
}

@test "docker-build-cluster rejects required runtime assets omitted from manifest.json before helm or docker" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-missing-required-manifest-entry.tar.gz"
  local staged_root="deploy/docker/.build/runtime-bundle/amd64"

  create_runtime_bundle_tarball_with_missing_required_manifest_entry "$runtime_tarball"
  seed_stale_runtime_bundle_stage amd64

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY=1 \
    DOCKER_PLATFORM=linux/amd64

  [ "$status" -ne 0 ]
  [[ "$output" == *"runtime bundle validation failed: required runtime asset missing from manifest.json: usr/bin/nvidia-container-cli"* ]]
  assert_no_docker_commands
  assert_no_helm_commands
  [ ! -e "$staged_root" ]
  assert_no_docker_buildx_build
}

@test "docker-build-cluster rejects extra unlisted files before helm or docker" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-extra-unlisted-file.tar.gz"
  local staged_root="deploy/docker/.build/runtime-bundle/amd64"

  create_runtime_bundle_tarball_with_extra_unlisted_file "$runtime_tarball"
  seed_stale_runtime_bundle_stage amd64

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY=1 \
    DOCKER_PLATFORM=linux/amd64

  [ "$status" -ne 0 ]
  [[ "$output" == *"runtime bundle validation failed: unlisted payload path present on disk: usr/bin/nvidia-container-extra"* ]]
  assert_no_docker_commands
  assert_no_helm_commands
  [ ! -e "$staged_root" ]
  assert_no_docker_buildx_build
}

@test "docker-build-cluster rejects size mismatches before helm or docker" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-size-mismatch.tar.gz"
  local staged_root="deploy/docker/.build/runtime-bundle/amd64"

  create_runtime_bundle_tarball_with_size_mismatch "$runtime_tarball"
  seed_stale_runtime_bundle_stage amd64

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY=1 \
    DOCKER_PLATFORM=linux/amd64

  [ "$status" -ne 0 ]
  [[ "$output" == *"runtime bundle validation failed: size mismatch: usr/bin/nvidia-container-cli"* ]]
  assert_no_docker_commands
  assert_no_helm_commands
  [ ! -e "$staged_root" ]
  assert_no_docker_buildx_build
}

@test "docker-build-cluster rejects runtime bundle architecture mismatches before helm or docker" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-arm64.tar.gz"

  create_runtime_bundle_tarball "$runtime_tarball" "arm64"

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY=1 \
    DOCKER_PLATFORM=linux/amd64

  [ "$status" -ne 0 ]
  [[ "$output" == *"runtime bundle validation failed: bundle architecture mismatch: expected amd64, got arm64"* ]]
  assert_no_docker_commands
  assert_no_helm_commands
  assert_runtime_bundle_arch_not_staged amd64
  assert_no_docker_buildx_build
}

@test "docker-build-cluster rejects tar extraction warnings and clears stale staged content" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-unsafe-entry.tar.gz"
  local staged_root="deploy/docker/.build/runtime-bundle/amd64"

  create_runtime_bundle_tarball_with_unsafe_entry "$runtime_tarball"
  seed_stale_runtime_bundle_stage amd64

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY=1 \
    DOCKER_PLATFORM=linux/amd64

  [ "$status" -ne 0 ]
  [[ "$output" == *"runtime bundle validation failed: tar extraction reported warnings or errors"* ]]
  assert_no_docker_commands
  assert_no_helm_commands
  [ ! -e "$staged_root" ]
  assert_no_docker_buildx_build
}

@test "docker-build-cluster rejects tar extraction stderr even when tar exits successfully" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-tar-warning.tar.gz"
  local staged_root="deploy/docker/.build/runtime-bundle/amd64"

  create_runtime_bundle_tarball_with_tar_warning "$runtime_tarball"

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY=1 \
    DOCKER_PLATFORM=linux/amd64 \
    TAR_STDERR_MESSAGE="tar: synthetic warning"

  [ "$status" -ne 0 ]
  [[ "$output" == *"runtime bundle validation failed: tar extraction reported warnings or errors"* ]]
  assert_no_docker_commands
  assert_no_helm_commands
  [ ! -e "$staged_root" ]
  assert_no_docker_buildx_build
}

@test "docker-build-cluster rejects hidden top-level tarball entries before helm or docker" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-hidden-top-level.tar.gz"

  create_runtime_bundle_tarball_with_hidden_top_level_entry "$runtime_tarball"

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY=1 \
    DOCKER_PLATFORM=linux/amd64

  [ "$status" -ne 0 ]
  [[ "$output" == *"runtime bundle validation failed: expected a single top-level bundle directory"* ]]
  assert_no_docker_commands
  assert_no_helm_commands
  assert_runtime_bundle_arch_not_staged amd64
  assert_no_docker_buildx_build
}

@test "docker-build-cluster rejects symlinked required binary payload paths before helm or docker" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-symlinked-binary.tar.gz"

  create_runtime_bundle_tarball_with_symlinked_required_binary "$runtime_tarball"

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY=1 \
    DOCKER_PLATFORM=linux/amd64

  [ "$status" -ne 0 ]
  [[ "$output" == *"runtime bundle validation failed: invalid required binary entry type: usr/bin/nvidia-container-cli"* ]]
  assert_no_docker_commands
  assert_no_helm_commands
  assert_runtime_bundle_arch_not_staged amd64
  assert_no_docker_buildx_build
}

@test "docker-build-cluster stages a valid runtime bundle in script-only verification mode" {
  local runtime_tarball="$TEST_TMPDIR/runtime-bundle-valid.tar.gz"
  local staged_root="deploy/docker/.build/runtime-bundle/amd64"
  local staged_bundle_dir="$staged_root/openshell-gpu-runtime-bundle_0.1.0_amd64"

  create_runtime_bundle_tarball "$runtime_tarball"

  run_cluster_build \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_tarball" \
    OPENSHELL_RUNTIME_BUNDLE_VERIFY_ONLY=1 \
    DOCKER_PLATFORM=linux/amd64

  [ "$status" -eq 0 ]
  [[ "$output" == *"Runtime bundle staged at $staged_bundle_dir"* ]]
  [ -d "$staged_root" ]
  [ -d "$staged_bundle_dir" ]
  [ -f "$staged_bundle_dir/usr/bin/nvidia-container-cli" ]
  [ -d "$staged_bundle_dir/etc/nvidia-container-runtime" ]
  [ -f "$staged_bundle_dir/usr/lib/x86_64-linux-gnu/libnvidia-container.so.1" ]
  assert_no_docker_commands
  assert_no_helm_commands
  assert_no_docker_buildx_build
}

@test "Dockerfile.cluster consumes the staged local runtime bundle instead of the apt-installed nvidia-toolkit stage" {
  run python3 - <<'PY'
from pathlib import Path
import sys

dockerfile = Path("deploy/docker/Dockerfile.cluster").read_text(encoding="utf-8")

checks = {
    "removes apt toolkit stage": "FROM ubuntu:24.04 AS nvidia-toolkit" not in dockerfile,
    "removes NVIDIA apt repo install": "nvidia.github.io/libnvidia-container" not in dockerfile,
    "adds local runtime bundle stage": "FROM ubuntu:24.04 AS runtime-bundle" in dockerfile,
    "copies staged runtime bundle context": "deploy/docker/.build/runtime-bundle/" in dockerfile,
    "copies runtime files from local runtime bundle stage": "COPY --from=runtime-bundle /out/usr/bin/nvidia-container-cli /usr/bin/" in dockerfile,
}

failed = [name for name, ok in checks.items() if not ok]
if failed:
    print("; ".join(failed))
    sys.exit(1)
PY

  [ "$status" -eq 0 ]
}
