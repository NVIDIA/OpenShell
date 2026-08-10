#!/usr/bin/env bash
# Build Konflux images locally using Hermeto prefetched dependencies.
# Replicates the Konflux hermetic build pipeline (--network none).
#
# Prerequisites:
#   - hermeto (pip install git+https://github.com/hermetoproject/hermeto.git)
#   - podman
#
# Usage:
#   ./deploy/konflux/build-local.sh gateway
#   ./deploy/konflux/build-local.sh supervisor
#   ./deploy/konflux/build-local.sh all
#
# Override architecture (default: host arch via uname -m):
#   PLATFORM=linux/arm64 ./deploy/konflux/build-local.sh supervisor
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/hermeto-output"

# Detect or override platform
HOST_ARCH=$(uname -m)
case "${HOST_ARCH}" in
    x86_64)  DEFAULT_PLATFORM="linux/amd64" ;;
    aarch64) DEFAULT_PLATFORM="linux/arm64" ;;
    *)       DEFAULT_PLATFORM="linux/${HOST_ARCH}" ;;
esac
PLATFORM="${PLATFORM:-${DEFAULT_PLATFORM}}"

CLEANUP_PATHS=()
cleanup() {
    for p in "${CLEANUP_PATHS[@]}"; do
        rm -rf "$p"
    done
    git -C "${REPO_ROOT}" checkout .cargo/config.toml 2>/dev/null || true
}
trap cleanup EXIT

build_image() {
    local component="$1"
    local dockerfile konfig_dir output_dir repos_dir

    case "$component" in
        gateway)
            dockerfile="deploy/docker/Dockerfile.konflux.gateway"
            konfig_dir="deploy/konflux/gateway"
            ;;
        supervisor)
            dockerfile="deploy/docker/Dockerfile.konflux.supervisor"
            konfig_dir="deploy/konflux/supervisor"
            ;;
        cli)
            dockerfile="deploy/docker/Dockerfile.konflux.cli"
            konfig_dir="deploy/konflux/cli"
            ;;
        *)
            echo "Unknown component: $component" >&2
            exit 1
            ;;
    esac

    output_dir="${OUTPUT_DIR}/${component}"
    repos_dir=$(mktemp -d)
    CLEANUP_PATHS+=("${repos_dir}")

    echo "=== Prefetching ${component} dependencies ==="
    rm -rf "${output_dir}"
    hermeto fetch-deps \
        --source "${REPO_ROOT}" \
        --output "${output_dir}" \
        "[
            {\"path\": \".\", \"type\": \"cargo\"},
            {\"path\": \"${konfig_dir}\", \"type\": \"rpm\"},
            {\"path\": \"${konfig_dir}\", \"type\": \"generic\", \"lockfile\": \"generic-fetcher.yaml\"}
        ]"

    echo "=== Injecting files ==="
    hermeto inject-files "${output_dir}" --for-output-dir /cachi2/output
    hermeto generate-env "${output_dir}" \
        --format env --for-output-dir /cachi2/output \
        --output "${output_dir}/cachi2.env"

    echo "=== Preparing RPM repos ==="
    find "${output_dir}" -name "hermeto.repo" -execdir cp {} cachi2.repo \;
    local rpm_arch
    case "${PLATFORM}" in
        */amd64|*/x86_64) rpm_arch="x86_64" ;;
        */arm64|*/aarch64) rpm_arch="aarch64" ;;
        *)                 rpm_arch=$(uname -m) ;;
    esac
    cp "${output_dir}/deps/rpm/${rpm_arch}/repos.d/cachi2.repo" "${repos_dir}/"
    chmod -R go+rX "${repos_dir}"

    echo "=== Building ${component} (--network none, platform ${PLATFORM}) ==="
    local hermetic_dockerfile
    hermetic_dockerfile=$(mktemp)
    CLEANUP_PATHS+=("${hermetic_dockerfile}")
    cp "${REPO_ROOT}/${dockerfile}" "${hermetic_dockerfile}"
    sed -i 's|^\s*RUN |RUN . /cachi2/cachi2.env \&\& \\\n    |i' "${hermetic_dockerfile}"

    # Disable subscription-manager so it doesn't inject RHEL repos that fail
    # DNS under --network=none. Same as Konflux Tekton script (unlink rhel secrets).
    local sm_conf
    sm_conf=$(mktemp)
    CLEANUP_PATHS+=("${sm_conf}")
    echo -e "[main]\nenabled=0" > "${sm_conf}"

    # Podman auto-mounts host RHEL subscription secrets into /run/secrets/
    # via /usr/share/containers/mounts.conf. The redhat.repo there adds
    # rhel-* repos that can't resolve under --network=none. Mount an empty
    # directory over /run/secrets to neutralize the injection entirely.
    local empty_secrets
    empty_secrets=$(mktemp -d)
    CLEANUP_PATHS+=("${empty_secrets}")

    podman build \
        -f "${hermetic_dockerfile}" \
        --platform "${PLATFORM}" \
        --volume "$(realpath "${output_dir}"):/cachi2/output:Z" \
        --volume "$(realpath "${output_dir}/cachi2.env"):/cachi2/cachi2.env:Z" \
        --volume "$(realpath "${repos_dir}"):/etc/yum.repos.d:Z" \
        --volume "${sm_conf}:/etc/dnf/plugins/subscription-manager.conf:Z" \
        --volume "${empty_secrets}:/run/secrets:Z" \
        --network none \
        -t "openshell-${component}-konflux" \
        "${REPO_ROOT}"

    echo "=== ${component} built successfully ==="
    podman run --rm --platform "${PLATFORM}" "openshell-${component}-konflux" --help 2>&1 | head -3
    echo ""
}

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 {gateway|supervisor|cli|all}" >&2
    exit 1
fi

target="$1"
if [[ "$target" == "all" ]]; then
    build_image gateway
    build_image supervisor
    build_image cli
else
    build_image "$target"
fi
