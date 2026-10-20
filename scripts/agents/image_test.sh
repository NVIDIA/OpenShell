#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
export CALLS="$tmp/calls"
export TEST_DIGEST="$(printf 'a%.0s' {1..64})"

cat > "$tmp/bin/openshell" <<'SH'
#!/usr/bin/env bash
printf '{"compute_drivers":[{"name":"%s"}]}\n' "${TEST_DRIVER:-kubernetes}"
SH
cat > "$tmp/bin/kubectl" <<'SH'
#!/usr/bin/env bash
echo "${TEST_CONTEXT:-k3d-local}"
SH
cat > "$tmp/bin/k3d" <<'SH'
#!/usr/bin/env bash
echo "k3d $*" >> "$CALLS"
if [[ "$1" == cluster ]]; then
    echo '[{"name":"local","serversRunning":1}]'
else
    exit "${TEST_IMPORT_STATUS:-0}"
fi
SH
cat > "$tmp/bin/docker" <<'SH'
#!/usr/bin/env bash
set -eu
echo "docker $*" >> "$CALLS"
case "$1" in
    --version) echo 'Docker test stub' ;;
    push) exit "${TEST_PUSH_STATUS:-0}" ;;
    image) printf '["%s@sha256:%s"]\n' "${TEST_INSPECT_REPOSITORY:-registry.test/team/gator}" "$TEST_DIGEST" ;;
esac
SH
chmod +x "$tmp/bin/"*
ln -s docker "$tmp/bin/podman"
export PATH="$tmp/bin:$PATH"

fail() { echo "error: $*" >&2; exit 1; }
log() { echo "$*" >&2; }
require_cmd() { command -v "$1" >/dev/null || fail "missing $1"; }
source "$SCRIPT_DIR/image.sh"

run_transport() (
    OPENSHELL_BIN=openshell
    GATEWAY=test
    AGENT_IMAGE="${TEST_IMAGE:-}"
    K3D_CLUSTER="${TEST_CLUSTER:-}"
    PUBLISH_IMAGE="${TEST_PUBLISH:-}"
    CONTAINER_ENGINE="${TEST_ENGINE:-docker}"
    unset _CONTAINER_ENGINE_LOADED CONTAINER_ENGINE_TARGET
    prepare_agent_image_transport
    if [[ "$IMAGE_MODE" == prebuilt ]]; then
        echo "$AGENT_IMAGE"
    else
        deliver_agent_image "${PUBLISH_IMAGE:-openshell/agent-gator:test}"
        echo "$SANDBOX_FROM"
    fi
)

expect_failure() {
    if "$@" > "$tmp/out" 2> "$tmp/error"; then
        fail 'expected failure'
    fi
}

TEST_CLUSTER=local run_transport > "$tmp/out"
grep -Fq 'k3d image import --cluster local openshell/agent-gator:test' "$CALLS"
grep -Fxq 'openshell/agent-gator:test' "$tmp/out"
echo 'ok - Kubernetes local import targets the explicit k3d cluster'

TEST_PUBLISH=registry.test/team/gator:tooling run_transport > "$tmp/out"
grep -Fq 'docker push registry.test/team/gator:tooling' "$CALLS"
grep -Fxq "registry.test/team/gator@sha256:$TEST_DIGEST" "$tmp/out"
echo 'ok - registry delivery resolves a pinned digest'
TEST_PUBLISH=docker.io/team/gator:tooling TEST_INSPECT_REPOSITORY=team/gator \
    run_transport > "$tmp/out"
grep -Fxq "docker.io/team/gator@sha256:$TEST_DIGEST" "$tmp/out"
echo 'ok - Docker Hub digest normalization preserves the explicit registry'

: > "$CALLS"
TEST_IMAGE="registry.test/team/gator@sha256:$TEST_DIGEST" run_transport > "$tmp/out"
[[ ! -s "$CALLS" ]] || fail 'prebuilt path contacted local image/cluster tools'
echo 'ok - prebuilt path needs no local image engine or kube context'

expect_failure run_transport
grep -Fq 'Kubernetes needs' "$tmp/error"
TEST_CLUSTER=local TEST_CONTEXT=remote expect_failure run_transport
TEST_CLUSTER=missing expect_failure run_transport
TEST_CLUSTER=local TEST_IMPORT_STATUS=1 expect_failure run_transport
TEST_CLUSTER=local TEST_ENGINE=podman expect_failure run_transport
TEST_CLUSTER=local TEST_PUBLISH=registry.test/team/gator:tag expect_failure run_transport
TEST_CLUSTER=local TEST_IMAGE="registry.test/team/gator@sha256:$TEST_DIGEST" expect_failure run_transport
TEST_IMAGE=registry.test/team/gator:latest expect_failure run_transport
TEST_PUBLISH=registry.test/team/gator:tag TEST_PUSH_STATUS=1 expect_failure run_transport
TEST_PUBLISH=registry.test/team/gator:tag TEST_INSPECT_REPOSITORY=other.test/gator expect_failure run_transport
TEST_PUBLISH='implicit-tag' expect_failure run_transport
TEST_PUBLISH=implicit/repository:tag expect_failure run_transport
TEST_DRIVER=vm expect_failure run_transport
echo 'ok - ambiguous targets, conflicting options, and failed delivery fail closed'

TEST_DRIVER=docker run_transport > "$tmp/out"
grep -Fxq 'openshell/agent-gator:test' "$tmp/out"
echo 'ok - Docker delivery retains the local-engine path'
TEST_DRIVER=podman TEST_ENGINE=podman run_transport > "$tmp/out"
grep -Fxq 'openshell/agent-gator:test' "$tmp/out"
echo 'ok - Podman delivery retains the local-engine path'
