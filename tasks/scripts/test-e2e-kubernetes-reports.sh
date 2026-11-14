#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# Exercise the real entrypoint and its recursive invocation without a cluster,
# Rust builds, or writes to the checkout's results directory.
export REPORT_TEST_ROOT="${WORK}/repo"
mkdir -p "${REPORT_TEST_ROOT}/e2e/rust" "${REPORT_TEST_ROOT}/e2e/support" "${WORK}/bin"
cp "${ROOT}/e2e/rust/e2e-kubernetes.sh" "${REPORT_TEST_ROOT}/e2e/rust/"
cp "${ROOT}/e2e/support/conformance.sh" "${REPORT_TEST_ROOT}/e2e/support/"

cat >"${REPORT_TEST_ROOT}/e2e/with-kube-gateway.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "gateway ${OPENSHELL_E2E_CREDENTIAL_DRIVER:-default}" >>"${REPORT_TEST_ROOT}/calls"
if [ "${REPORT_TEST_GATEWAY_STATUS}" != 0 ]; then
  exit "${REPORT_TEST_GATEWAY_STATUS}"
fi
"$@"
EOF

cat >"${WORK}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "$1 ${OPENSHELL_E2E_CREDENTIAL_DRIVER:-default}" >>"${REPORT_TEST_ROOT}/calls"
case "$1" in
  test) exit 0 ;;
  nextest)
    if [ "${OPENSHELL_E2E_CREDENTIAL_DRIVER:-default}" != "${REPORT_TEST_NO_XML_DRIVER}" ]; then
      printf '<testsuite name="fresh-%s"/>\n' "${OPENSHELL_E2E_CREDENTIAL_DRIVER:-default}" \
        >"${REPORT_TEST_ROOT}/results/e2e-kubernetes.xml"
    fi
    exit "${REPORT_TEST_NEXTEST_STATUS}"
    ;;
  *) echo "unexpected cargo command: $*" >&2; exit 99 ;;
esac
EOF

cat >"${WORK}/bin/xsltproc" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "render $3" >>"${REPORT_TEST_ROOT}/calls"
printf '<html><title>%s</title>\n' "$3"
cat "$5"
echo '</html>'
EOF

cat >"${WORK}/bin/mv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${REPORT_TEST_MOVE_FAIL}" = 1 ]; then
  exit 13
fi
exec /bin/mv "$@"
EOF
chmod +x "${REPORT_TEST_ROOT}/e2e/with-kube-gateway.sh" "${WORK}/bin/"*

export PATH="${WORK}/bin:${PATH}"
export OPENSHELL_BIN="${WORK}/bin/openshell"
cp /usr/bin/true "${OPENSHELL_BIN}"

fail() {
  echo "FAIL: $*" >&2
  cat "${REPORT_TEST_ROOT}/output" >&2
  exit 1
}

reset_case() {
  rm -rf "${REPORT_TEST_ROOT}/results"
  mkdir "${REPORT_TEST_ROOT}/results"
  : >"${REPORT_TEST_ROOT}/calls"
  : >"${REPORT_TEST_ROOT}/output"
  export OPENSHELL_E2E_KUBERNETES_FEATURES=e2e
  export OPENSHELL_E2E_REPORT_NAME=e2e-kubernetes
  export OPENSHELL_E2E_CREDENTIAL_DRIVERS=0
  export OPENSHELL_E2E_CREDENTIAL_DRIVER=""
  export REPORT_TEST_GATEWAY_STATUS=0
  export REPORT_TEST_NEXTEST_STATUS=0
  export REPORT_TEST_NO_XML_DRIVER=""
  export REPORT_TEST_MOVE_FAIL=0
}

seed_stale_reports() {
  local name
  for name in e2e-kubernetes "${OPENSHELL_E2E_REPORT_NAME}"; do
    echo '<testsuite name="stale"/>' >"${REPORT_TEST_ROOT}/results/${name}.xml"
    echo 'stale HTML' >"${REPORT_TEST_ROOT}/results/${name}.html"
  done
  echo 'unrelated report' >"${REPORT_TEST_ROOT}/results/unrelated.xml"
  echo 'unrelated HTML' >"${REPORT_TEST_ROOT}/results/unrelated.html"
}

run_wrapper() {
  local expected=$1 status=0
  bash "${REPORT_TEST_ROOT}/e2e/rust/e2e-kubernetes.sh" \
    >"${REPORT_TEST_ROOT}/output" 2>&1 || status=$?
  [ "${status}" = "${expected}" ] || fail "expected status ${expected}, got ${status}"
  [ "$(cat "${REPORT_TEST_ROOT}/results/unrelated.xml")" = 'unrelated report' ] \
    || fail 'modified an unrelated XML report'
  [ "$(cat "${REPORT_TEST_ROOT}/results/unrelated.html")" = 'unrelated HTML' ] \
    || fail 'modified an unrelated HTML report'
}

assert_absent() {
  [ ! -e "${REPORT_TEST_ROOT}/results/$1" ] || fail "unexpected report: $1"
}

assert_no_render() {
  if grep -q '^render ' "${REPORT_TEST_ROOT}/calls"; then
    fail 'rendered XML when none was produced'
  fi
}

# Reproduction for #3668: conformance-only skips Nextest even with stale default
# XML and a stale destination report. Cover both default and custom names.
for name in e2e-kubernetes custom; do
  reset_case
  export OPENSHELL_E2E_REPORT_NAME="${name}"
  export OPENSHELL_E2E_KUBERNETES_FEATURES=e2e-conformance-only
  seed_stale_reports
  run_wrapper 0
  assert_absent e2e-kubernetes.xml
  assert_absent "${name}.xml"
  assert_absent "${name}.html"
  grep -q '^test ' "${REPORT_TEST_ROOT}/calls" || fail 'did not run conformance'
  if grep -q '^nextest ' "${REPORT_TEST_ROOT}/calls"; then
    fail 'conformance-only unexpectedly ran Nextest'
  fi
  assert_no_render
done

# Setup failures must not publish stale reports or lose their exit status.
for name in e2e-kubernetes custom; do
  reset_case
  export OPENSHELL_E2E_REPORT_NAME="${name}"
  export REPORT_TEST_GATEWAY_STATUS=17
  seed_stale_reports
  run_wrapper 17
  assert_absent e2e-kubernetes.xml
  assert_absent "${name}.xml"
  assert_absent "${name}.html"
  assert_no_render
done

# Fresh output is rendered even when Nextest fails, with the selected title.
for name in e2e-kubernetes custom; do
  for status in 0 100; do
    reset_case
    export OPENSHELL_E2E_REPORT_NAME="${name}"
    export REPORT_TEST_NEXTEST_STATUS="${status}"
    seed_stale_reports
    run_wrapper "${status}"
    grep -q 'fresh-default' "${REPORT_TEST_ROOT}/results/${name}.xml" || fail 'missing fresh XML'
    grep -q 'fresh-default' "${REPORT_TEST_ROOT}/results/${name}.html" || fail 'missing fresh HTML'
    grep -Fq "<title>${name}</title>" "${REPORT_TEST_ROOT}/results/${name}.html" || fail 'incorrect title'
    if [ "${name}" != e2e-kubernetes ]; then
      assert_absent e2e-kubernetes.xml
    fi
  done
done

# A failed rename must not fall through to rendering the destination.
for status in 0 100; do
  reset_case
  export OPENSHELL_E2E_REPORT_NAME=custom
  export REPORT_TEST_MOVE_FAIL=1
  export REPORT_TEST_NEXTEST_STATUS="${status}"
  seed_stale_reports
  run_wrapper "${status}"
  assert_absent custom.xml
  assert_absent custom.html
  assert_no_render
  grep -q 'WARNING:.*report' "${REPORT_TEST_ROOT}/output" || fail 'missing rename warning'
done

# Cleanup errors must stop the run before starting the gateway.
reset_case
seed_stale_reports
rm "${REPORT_TEST_ROOT}/results/e2e-kubernetes.xml"
mkdir "${REPORT_TEST_ROOT}/results/e2e-kubernetes.xml"
run_wrapper 1
[ ! -s "${REPORT_TEST_ROOT}/calls" ] || fail 'started a run after cleanup failed'

# A later credential-driver invocation that emits no XML must not reuse its
# predecessor's report, or an older report under its own name.
reset_case
export OPENSHELL_E2E_CREDENTIAL_DRIVERS=1
export REPORT_TEST_NO_XML_DRIVER=vault
seed_stale_reports
echo '<testsuite name="stale-vault"/>' >"${REPORT_TEST_ROOT}/results/e2e-kubernetes-vault.xml"
echo 'stale vault HTML' >"${REPORT_TEST_ROOT}/results/e2e-kubernetes-vault.html"
run_wrapper 0
grep -q 'fresh-kubernetes-secrets' "${REPORT_TEST_ROOT}/results/e2e-kubernetes-secrets.xml" \
  || fail 'missing first credential-driver XML'
grep -q 'fresh-kubernetes-secrets' "${REPORT_TEST_ROOT}/results/e2e-kubernetes-secrets.html" \
  || fail 'missing first credential-driver HTML'
grep -q '^nextest vault$' "${REPORT_TEST_ROOT}/calls" || fail 'did not run the second driver'
assert_absent e2e-kubernetes.xml
assert_absent e2e-kubernetes-vault.xml
assert_absent e2e-kubernetes-vault.html
if grep -q '^render e2e-kubernetes-vault$' "${REPORT_TEST_ROOT}/calls"; then
  fail 'rendered a stale credential-driver report'
fi

echo 'Kubernetes E2E report tests passed'
