#!/usr/bin/env bats

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

setup() {
  export TEST_TMPDIR
  TEST_TMPDIR="$(mktemp -d)"
  export FAKE_BIN_DIR="$TEST_TMPDIR/bin"
  export FAKE_BOOTSTRAP_LOG="$TEST_TMPDIR/bootstrap.log"
  export FAKE_OPENSHELL_LOG="$TEST_TMPDIR/openshell.log"
  export FAKE_RSYNC_LOG="$TEST_TMPDIR/rsync.log"
  export FAKE_SSH_LOG="$TEST_TMPDIR/ssh.log"
  export FAKE_SSH_STDIN_DIR="$TEST_TMPDIR/ssh-stdin"
  export FAKE_DOCKER_LOG="$TEST_TMPDIR/docker.log"
  export FAKE_HELM_LOG="$TEST_TMPDIR/helm.log"
  export FAKE_CLUSTER_BUILD_LOG="$TEST_TMPDIR/cluster-build.log"
  mkdir -p "$FAKE_BIN_DIR" "$FAKE_SSH_STDIN_DIR"

  cat > "$FAKE_BIN_DIR/openshell" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_OPENSHELL_LOG"
EOF
  chmod +x "$FAKE_BIN_DIR/openshell"

  cat > "$FAKE_BIN_DIR/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_SSH_LOG"
count_file="$FAKE_SSH_STDIN_DIR/count"
count=0
if [[ -f "$count_file" ]]; then
  count="$(cat "$count_file")"
fi
count=$((count + 1))
printf '%s' "$count" > "$count_file"
stdin_path="$FAKE_SSH_STDIN_DIR/$count.stdin"
cat > "$stdin_path" || true
EOF
  chmod +x "$FAKE_BIN_DIR/ssh"

  cat > "$FAKE_BIN_DIR/rsync" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_RSYNC_LOG"
EOF
  chmod +x "$FAKE_BIN_DIR/rsync"

  cat > "$FAKE_BIN_DIR/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
if [[ "${1:-}" == "buildx" && "${2:-}" == "inspect" ]]; then
  exit 0
fi
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

  cat > "$FAKE_BIN_DIR/uv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "run" ]]; then
  printf '0.0.0-test\n'
  exit 0
fi
exit 1
EOF
  chmod +x "$FAKE_BIN_DIR/uv"
}

teardown() {
  rm -rf "$TEST_TMPDIR"
}

make_bootstrap_harness() {
  local harness_root="$TEST_TMPDIR/bootstrap-harness"
  mkdir -p \
    "$harness_root/tasks/scripts" \
    "$harness_root/deploy/helm/openshell" \
    "$harness_root/deploy/docker"
  cp "tasks/scripts/cluster-bootstrap.sh" "$harness_root/tasks/scripts/cluster-bootstrap.sh"
  cp "tasks/scripts/docker-build-cluster.sh" "$harness_root/tasks/scripts/docker-build-cluster.sh"

  printf 'FROM --platform=$BUILDPLATFORM rust:1.86\n' > "$harness_root/deploy/docker/Dockerfile.cluster"

  cat > "$harness_root/tasks/scripts/cluster-push-component.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_BOOTSTRAP_LOG"
EOF
  chmod +x "$harness_root/tasks/scripts/cluster-push-component.sh"

  printf '%s\n' "$harness_root"
}

make_remote_deploy_harness() {
  local harness_root="$TEST_TMPDIR/remote-deploy-harness"
  mkdir -p "$harness_root/scripts"
  cp "scripts/remote-deploy.sh" "$harness_root/scripts/remote-deploy.sh"
  printf '%s\n' "$harness_root"
}

make_multiarch_harness() {
  local harness_root="$TEST_TMPDIR/multiarch-harness"
  mkdir -p \
    "$harness_root/tasks/scripts" \
    "$harness_root/deploy/docker" \
    "$harness_root/deploy/helm/openshell"

  cp "tasks/scripts/docker-publish-multiarch.sh" "$harness_root/tasks/scripts/docker-publish-multiarch.sh"

  cat > "$harness_root/tasks/scripts/docker-build-cluster.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s|%s|%s\n' "${DOCKER_PLATFORM:-}" "${OPENSHELL_RUNTIME_BUNDLE_TARBALL:-}" "${IMAGE_TAG:-}" >> "$FAKE_CLUSTER_BUILD_LOG"
EOF
  chmod +x "$harness_root/tasks/scripts/docker-build-cluster.sh"

  printf '[[package]]\nname = "openshell"\nversion = "0.0.0"\n' > "$harness_root/Cargo.lock"
  printf 'FROM --platform=$BUILDPLATFORM rust:1.86\n' > "$harness_root/deploy/docker/Dockerfile.gateway"
  printf 'FROM --platform=$BUILDPLATFORM rust:1.86\n' > "$harness_root/deploy/docker/Dockerfile.cluster"

  printf '%s\n' "$harness_root"
}

@test "cluster-bootstrap fails before build orchestration when the runtime bundle tarball is missing" {
  local harness_root
  harness_root="$(make_bootstrap_harness)"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    HOME="$TEST_TMPDIR/home" \
    IMAGE_REPO_BASE=registry.example/openshell \
    bash -lc "cd '$harness_root' && bash tasks/scripts/cluster-bootstrap.sh build"

  [ "$status" -ne 0 ]
  [[ "$output" == *"missing required variable: OPENSHELL_RUNTIME_BUNDLE_TARBALL"* ]]
  [ ! -s "$FAKE_BOOTSTRAP_LOG" ]
  [ ! -s "$FAKE_OPENSHELL_LOG" ]
}

@test "cluster-bootstrap allows skip-build flows without a runtime bundle tarball" {
  local harness_root
  harness_root="$(make_bootstrap_harness)"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    HOME="$TEST_TMPDIR/home" \
    IMAGE_REPO_BASE=registry.example/openshell \
    SKIP_IMAGE_PUSH=1 \
    SKIP_CLUSTER_IMAGE_BUILD=1 \
    OPENSHELL_CLUSTER_IMAGE=registry.example/openshell/cluster:test \
    bash -lc "cd '$harness_root' && bash tasks/scripts/cluster-bootstrap.sh build"

  [ "$status" -eq 0 ]
  [ ! -s "$FAKE_BOOTSTRAP_LOG" ]
  [[ "$(<"$FAKE_OPENSHELL_LOG")" == *"gateway start --name bootstrap-harness --port 8080"* ]]
}

@test "remote-deploy syncs the runtime bundle tarball and exports its remote path for the remote cluster build" {
  local harness_root runtime_tarball remote_tarball
  harness_root="$(make_remote_deploy_harness)"
  runtime_tarball="$TEST_TMPDIR/runtime-bundle-amd64.tar.gz"
  remote_tarball="openshell/.cache/runtime-bundles/$(basename "$runtime_tarball")"
  : > "$runtime_tarball"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    HOME="$TEST_TMPDIR/home" \
    bash -lc "cd '$harness_root' && bash scripts/remote-deploy.sh devbox --runtime-bundle-tarball '$runtime_tarball'"

  [ "$status" -eq 0 ]
  [[ "$(<"$FAKE_RSYNC_LOG")" == *"$runtime_tarball devbox:$remote_tarball"* ]]
  [[ "$(<"$FAKE_SSH_LOG")" == *"$remote_tarball"* ]]
  grep -Fq 'export OPENSHELL_RUNTIME_BUNDLE_TARBALL="${REMOTE_RUNTIME_BUNDLE_PATH}"' "$FAKE_SSH_STDIN_DIR"/*.stdin
}

@test "remote-deploy skip-sync requires an explicit remote runtime bundle tarball path" {
  local harness_root remote_tarball
  harness_root="$(make_remote_deploy_harness)"
  remote_tarball="/srv/openshell/runtime-bundles/runtime-bundle-amd64.tar.gz"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    HOME="$TEST_TMPDIR/home" \
    bash -lc "cd '$harness_root' && bash scripts/remote-deploy.sh devbox --skip-sync --remote-runtime-bundle-tarball '$remote_tarball'"

  [ "$status" -eq 0 ]
  [ ! -s "$FAKE_RSYNC_LOG" ]
  [[ "$(<"$FAKE_SSH_LOG")" == *"$remote_tarball"* ]]
  grep -Fq 'export OPENSHELL_RUNTIME_BUNDLE_TARBALL="${REMOTE_RUNTIME_BUNDLE_PATH}"' "$FAKE_SSH_STDIN_DIR"/*.stdin
}

@test "docker-publish-multiarch builds cluster images per arch with matching runtime bundles" {
  local harness_root amd64_bundle arm64_bundle cluster_log
  harness_root="$(make_multiarch_harness)"
  amd64_bundle="$TEST_TMPDIR/runtime-bundle-amd64.tar.gz"
  arm64_bundle="$TEST_TMPDIR/runtime-bundle-arm64.tar.gz"
  : > "$amd64_bundle"
  : > "$arm64_bundle"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    DOCKER_REGISTRY=registry.example/openshell \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL_AMD64="$amd64_bundle" \
    OPENSHELL_RUNTIME_BUNDLE_TARBALL_ARM64="$arm64_bundle" \
    bash -lc "cd '$harness_root' && bash tasks/scripts/docker-publish-multiarch.sh --mode registry"

  [ "$status" -eq 0 ]
  cluster_log="$(<"$FAKE_CLUSTER_BUILD_LOG")"
  [[ "$cluster_log" == *"linux/amd64|$amd64_bundle|dev-amd64"* ]]
  [[ "$cluster_log" == *"linux/arm64|$arm64_bundle|dev-arm64"* ]]
  [[ "$(<"$FAKE_DOCKER_LOG")" == *"imagetools create --prefer-index=false -t registry.example/openshell/openshell-cluster:dev registry.example/openshell/openshell-cluster:dev-amd64 registry.example/openshell/openshell-cluster:dev-arm64"* ]]
}
