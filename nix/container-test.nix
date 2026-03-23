# Smoke-test script for the OpenShell OCI container.
# Loads the image into Docker, runs structural checks, and reports results.
#
# Usage: nix run .#container-test
{
  writeShellApplication,
  docker,
  coreutils,
  gawk,
  constants,
  container,
}:

writeShellApplication {
  name = "openshell-container-test";

  runtimeInputs = [
    docker
    coreutils
    gawk
  ];

  text = ''
    set -euo pipefail

    IMAGE="openshell:${constants.openshellVersion}"
    CONTAINER=""
    PASS=0
    FAIL=0

    cleanup() {
      if [ -n "$CONTAINER" ]; then
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
      fi
    }
    trap cleanup EXIT

    check() {
      local desc="$1"; shift
      if "$@" >/dev/null 2>&1; then
        echo "  PASS  $desc"
        PASS=$((PASS + 1))
      else
        echo "  FAIL  $desc"
        FAIL=$((FAIL + 1))
      fi
    }

    check_output() {
      local desc="$1" expected="$2"; shift 2
      local output
      output=$("$@" 2>&1) || true
      if echo "$output" | grep -qF "$expected"; then
        echo "  PASS  $desc"
        PASS=$((PASS + 1))
      else
        echo "  FAIL  $desc (expected '$expected', got '$output')"
        FAIL=$((FAIL + 1))
      fi
    }

    run_in() {
      docker exec "$CONTAINER" bash -c "$1"
    }

    # ── Load image ──────────────────────────────────────────────
    echo "Loading container image..."
    docker load < ${container}

    # ── Report image size ───────────────────────────────────────
    echo ""
    echo "=== Image Size ==="
    docker image inspect "$IMAGE" --format='{{.Size}}' \
      | awk '{ printf "  Uncompressed: %.0f MiB\n", $1/1024/1024 }'
    TARBALL_SIZE=$(stat -c%s ${container})
    echo "  Compressed tarball: $((TARBALL_SIZE / 1024 / 1024)) MiB"
    echo ""

    # ── Start container ─────────────────────────────────────────
    echo "Starting container..."
    CONTAINER=$(docker create --name openshell-nix-test --entrypoint /bin/bash "$IMAGE" -c "sleep 300")
    docker start "$CONTAINER"

    echo ""
    echo "=== Structural Checks ==="

    # Binaries present
    check "openshell is on PATH"         run_in "command -v openshell"
    check "openshell-server is on PATH"  run_in "command -v openshell-server"
    check "openshell-sandbox is on PATH" run_in "command -v openshell-sandbox"
    check "bash is on PATH"             run_in "command -v bash"

    # Version output
    check "openshell --version works"         run_in "openshell --version"
    check "openshell-server --version works"  run_in "openshell-server --version"
    check "openshell-sandbox --version works" run_in "openshell-sandbox --version"

    # User/permissions
    check_output "runs as uid ${toString constants.user.uid}" "${toString constants.user.uid}" run_in "id -u"
    check_output "runs as gid ${toString constants.user.gid}" "${toString constants.user.gid}" run_in "id -g"

    # passwd/group
    check "/etc/passwd exists" run_in "test -f /etc/passwd"
    check "/etc/group exists"  run_in "test -f /etc/group"

    # Home directory
    check "home dir exists"    run_in "test -d ${constants.user.home}"
    check "home dir writable"  run_in "touch ${constants.user.home}/test && rm ${constants.user.home}/test"

    # SSL certs
    check "CA certs available" run_in "test -f /etc/ssl/certs/ca-bundle.crt"

    # Entrypoint
    check_output "entrypoint contains openshell" "openshell" \
      docker inspect "$IMAGE" --format '{{join .Config.Entrypoint " "}}'

    # ── Summary ─────────────────────────────────────────────────
    echo ""
    TOTAL=$((PASS + FAIL))
    echo "=== Results: $PASS/$TOTAL passed ==="
    if [ "$FAIL" -gt 0 ]; then
      echo "FAILED: $FAIL check(s) did not pass."
      exit 1
    else
      echo "All checks passed."
    fi
  '';
}
