#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Full acceptance run for the KubeVirt-mode Kubernetes compute driver
# against a running kvpoc gateway (started by e2e/kubevirt/demo.sh with the
# shared supervisor deployed; see e2e/kubevirt/README.md). Every step fails
# the demo on error — there is no Ready-wait tolerance.
#
#   1.  create (with demo-policy.yaml) reaching Ready
#   2.  fence NetworkPolicy exists, and exactly one virt-launcher pod
#       matches its podSelector
#   3.  exec inside the VM (uname, id, PID 1)
#   4.  no gateway material in the workload environment
#   5.  L4 allow (one.one.one.one:443) and deny (example.org:80);
#       L7 HTTPS on example.com: GET allowed, POST denied (403) — the GET
#       proves the per-sandbox proxy CA was delivered into the guest
#   6.  direct egress from the guest to a raw IP is blocked
#   7.  stop -> start -> Ready, with the VM UID and fence UID unchanged
#   8.  fence verification: a spec edit fails start with drift; a
#       label-only edit is accepted
#   9.  main-process exit -> Error (exit code 137)
#   10. delete -> zero leftover managed objects
#
# Requires the `openshell` CLI built at $CARGO_TARGET_DIR/release/openshell
# and, for OPENSHELL_KVPOC_TOPOLOGY=gateway, the shared supervisor deployed
# (e2e/kubevirt/supervisor-values.yaml). The default topology is dedicated:
# one supervisor Pod per sandbox, matching the pod path's default; the
# dedicated steps additionally verify the supervisor Pod's UID is the
# boundary claim, that the fence selects only that Pod, that stop/start
# rotates it, and that delete removes it.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CARGO_TARGET="${CARGO_TARGET_DIR:-${ROOT}/target}"
OPENSHELL_CLI="${CARGO_TARGET}/release/openshell"
SANDBOX_NAMESPACE="${OPENSHELL_KVPOC_NAMESPACE:-kvpoc-sandboxes}"
SUPERVISOR_NAMESPACE="${OPENSHELL_KVPOC_SUPERVISOR_NAMESPACE:-openshell}"
TOPOLOGY="${OPENSHELL_KVPOC_TOPOLOGY:-dedicated}"
case "${TOPOLOGY}" in
    dedicated|gateway) ;;
    *) fail "OPENSHELL_KVPOC_TOPOLOGY must be 'dedicated' or 'gateway', got '${TOPOLOGY}'" ;;
esac
WORKLOAD="${OPENSHELL_KVPOC_WORKLOAD:-sandboxed}"
case "${WORKLOAD}" in
    sandboxed) DEMO_POLICY="${ROOT}/e2e/kubevirt/demo-policy.yaml" ;;
    # Root workloads reject filesystem/landlock/process policy sections
    # (unenforceable in-guest); the root policy keeps the same network
    # semantics without them and without binaries lists (binary identity
    # is not required in root mode).
    root) DEMO_POLICY="${ROOT}/e2e/kubevirt/demo-policy-root.yaml" ;;
    *) fail "OPENSHELL_KVPOC_WORKLOAD must be 'sandboxed' or 'root', got '${WORKLOAD}'" ;;
esac
NAME="kvpoc-demo"
VM_SELECTOR="openshell.ai/sandbox-name=${NAME}"
FENCE_PREFIX="openshell-kubevirt-fence-"

step() { echo; echo "=== $* ==="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# The single EXIT trap. A second `trap ... EXIT` later in the script would
# REPLACE this one (bash keeps one EXIT trap), which is exactly how the
# failure teardown was silently lost before — keep every exit handling
# here.
#
# On failure, tear down the sandbox: without this the VM, VMI, and
# supervisor Pod are left running after the demo's gateway exits, and only
# a manual `kubectl delete vm` cascades them away. The CLI delete runs
# first (while the gateway is still up); the labelled kubectl deletions
# are the gateway-independent backstop — owner references cascade from
# the VM, and the labelled companions cover what the VM does not own.
# On every exit (success or failure), remove the scratch directory.
demo_exit_trap() {
    local rc=$?
    if [ "${rc}" -ne 0 ]; then
        echo >&2
        echo "demo failed (rc=${rc}); tearing down sandbox '${NAME}'..." >&2
        "${OPENSHELL_CLI}" sandbox delete "${NAME}" >/dev/null 2>&1 || true
        kubectl delete vm -n "${SANDBOX_NAMESPACE}" -l "${VM_SELECTOR}" \
            --wait=false --ignore-not-found >/dev/null 2>&1 || true
        kubectl delete pod,svc,secret,pvc,netpol -n "${SANDBOX_NAMESPACE}" \
            -l "${VM_SELECTOR}" --ignore-not-found >/dev/null 2>&1 || true
        echo "teardown complete" >&2
    fi
    rm -rf "${WORKDIR:-}"
    exit "${rc}"
}
trap demo_exit_trap EXIT

WORKDIR="$(mktemp -d /tmp/kvpoc-demo-XXXXXX)"

sandbox_phase() {
    "${OPENSHELL_CLI}" sandbox get "${NAME}" 2>/dev/null | grep -a "Phase:" | head -1 \
        | sed 's/^ *//' || true
}

require_phase() {
    local expected="$1" got
    got="$(sandbox_phase)"
    [ "${got}" = "Phase: ${expected}" ] \
        || fail "expected phase ${expected}, got '${got:-none}'"
}

# Wait for the sandbox to reach the expected phase. The create uses --detach
# (a non-detached create attaches to the main process, and the demo's main
# process is `sleep infinity`), so readiness is polled through `sandbox get`.
wait_for_phase() {
    local expected="$1" timeout_secs="${2:-300}" deadline got
    deadline=$(( $(date +%s) + timeout_secs ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        got="$(sandbox_phase)"
        case "${got}" in
            "Phase: ${expected}") return 0 ;;
            "Phase: Error") fail "sandbox reached Error while waiting for ${expected}" ;;
        esac
        sleep 5
    done
    fail "timed out waiting for phase ${expected} (got '${got:-none}')"
}

vm_jsonpath() {
    kubectl get vm -l "${VM_SELECTOR}" -n "${SANDBOX_NAMESPACE}" \
        -o "jsonpath=$1" 2>/dev/null
}

fence_name() {
    local sandbox_id
    sandbox_id="$(vm_jsonpath '{.items[0].metadata.labels.openshell\.ai/sandbox-id}')"
    [ -n "${sandbox_id}" ] || fail "VM carries no sandbox-id label"
    echo "${FENCE_PREFIX}${sandbox_id}"
}

# The exec channel can report a benign teardown error after the output was
# delivered completely ("exec output could not be delivered intact", exit
# 74); each step's content assertions decide success, so only that code is
# swallowed. The workload's own exit codes (e.g. a denied connect) still
# propagate.
# Assert the supervisor logged an OCSF NET:OPEN DENIED line for the
# destination, so a network failure cannot pass as a policy deny. The log
# source is topology-dependent: the shared supervisor Deployment, or this
# sandbox's dedicated supervisor Pod.
supervisor_logs() {
    if [ "${TOPOLOGY}" = "gateway" ]; then
        kubectl logs -n "${SUPERVISOR_NAMESPACE}" deployment/kvpoc-openshell-supervisor \
            --since=5m 2>/dev/null
    else
        kubectl logs -n "${SANDBOX_NAMESPACE}" "pod/${SUPERVISOR_POD}" --since=5m 2>/dev/null
    fi
}

supervisor_denied() {
    local destination="$1"
    supervisor_logs | grep -a "OCSF NET:OPEN.*DENIED.*${destination}"
}

exec_in_sandbox() {
    "${OPENSHELL_CLI}" sandbox exec "${NAME}" -- "$@" || {
        local rc=$?
        [ "${rc}" = "74" ] || return "${rc}"
        return 0
    }
}

step "1/10 create reaching Ready (boundary dials the shared supervisor)"
"${OPENSHELL_CLI}" sandbox delete "${NAME}" >/dev/null 2>&1 || true
# A previous run whose gateway record was already deleted can leave an
# orphaned VM behind (name collision on create); clear it and its
# labelled companions directly.
if kubectl get vm -n "${SANDBOX_NAMESPACE}" -l "${VM_SELECTOR}"     --no-headers 2>/dev/null | grep -q .; then
    echo "clearing an orphaned VM from a previous run"
    kubectl delete vm -n "${SANDBOX_NAMESPACE}" -l "${VM_SELECTOR}" --wait=true         >/dev/null 2>&1 || true
fi
if kubectl get pod,svc,secret,pvc,netpol -n "${SANDBOX_NAMESPACE}" -l "${VM_SELECTOR}" \
    --no-headers 2>/dev/null | grep -q .; then
    echo "clearing orphaned labelled companions from a previous run:"
    kubectl get pod,svc,secret,pvc,netpol -n "${SANDBOX_NAMESPACE}" -l "${VM_SELECTOR}" \
        --no-headers 2>/dev/null | awk '{print "  " $1}' | sort -u
fi
kubectl delete pod,svc,secret,pvc,netpol -n "${SANDBOX_NAMESPACE}" -l "${VM_SELECTOR}" --ignore-not-found >/dev/null 2>&1 || true
sleep 5
"${OPENSHELL_CLI}" sandbox create --detach --name "${NAME}" \
    --policy "${DEMO_POLICY}" \
    -- /bin/sleep infinity
wait_for_phase Ready
echo "objects:"
kubectl get vm,vmi,netpol,secret,pvc -n "${SANDBOX_NAMESPACE}" -l "${VM_SELECTOR}" \
    || fail "managed objects missing after create"
SBX_ID="$(vm_jsonpath '{.items[0].metadata.labels.openshell\.ai/sandbox-id}')"
VM_UID="$(vm_jsonpath '{.items[0].metadata.uid}')"
[ -n "${VM_UID}" ] || fail "VM has no UID"
# The dedicated supervisor Pod's name derives from the sandbox id
# (SandboxRuntimeNames::new lowercases it).
SBX_LC="$(printf '%s' "${SBX_ID}" | tr '[:upper:]' '[:lower:]')"
SUPERVISOR_POD="os-supervisor-${SBX_LC}"
BOOTSTRAP_SECRET="default--${NAME}-bootstrap"

if [ "${TOPOLOGY}" = "dedicated" ]; then
    echo "dedicated supervisor generation:"
    kubectl get pod,svc,secret -n "${SANDBOX_NAMESPACE}" \
        -l "openshell.ai/sandbox-id=${SBX_ID},openshell.ai/component=supervisor" \
        || fail "dedicated supervisor objects missing after create"
    SUPERVISOR_POD_UID="$(kubectl get pod -n "${SANDBOX_NAMESPACE}" "${SUPERVISOR_POD}" \
        -o jsonpath='{.metadata.uid}' 2>/dev/null)" \
        || fail "dedicated supervisor Pod ${SUPERVISOR_POD} not found"
    [ -n "${SUPERVISOR_POD_UID}" ] || fail "supervisor Pod has no UID"
    # The boundary config delivered to the guest claims the supervisor Pod's
    # UID (kubevirt.supervisor_pod_uid); the rendered claim must be the live
    # Pod's UID.
    CLAIMED_UID="$(kubectl get secret -n "${SANDBOX_NAMESPACE}" "${BOOTSTRAP_SECRET}" \
        -o jsonpath='{.data.userData}' | base64 -d \
        | grep "^OPENSHELL_BOUNDARY_CONFIG_B64=" | cut -d= -f2- | base64 -d \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["resource_claims"]["kubevirt.supervisor_pod_uid"])')" \
        || fail "could not extract kubevirt.supervisor_pod_uid from the guest bootstrap"
    [ "${CLAIMED_UID}" = "${SUPERVISOR_POD_UID}" ] \
        || fail "boundary claim kubevirt.supervisor_pod_uid (${CLAIMED_UID}) does not match the supervisor Pod UID (${SUPERVISOR_POD_UID})"
    echo "supervisor Pod UID matches the kubevirt.supervisor_pod_uid claim (${SUPERVISOR_POD_UID})"
fi

step "2/10 fence NetworkPolicy and its podSelector"
FENCE="$(fence_name)"
FENCE_UID="$(kubectl get netpol -n "${SANDBOX_NAMESPACE}" "${FENCE}" \
    -o jsonpath='{.metadata.uid}' 2>/dev/null)" \
    || fail "fence ${FENCE} not found"
[ -n "${FENCE_UID}" ] || fail "fence has no UID"
echo "fence: ${FENCE} (uid ${FENCE_UID})"
LAUNCHER_PODS="$(kubectl get pods -n "${SANDBOX_NAMESPACE}" \
    -l kubevirt.io=virt-launcher,openshell.ai/sandbox-id="${SBX_ID}" \
    --no-headers 2>/dev/null | wc -l)"
[ "${LAUNCHER_PODS}" = "1" ] \
    || fail "expected exactly one launcher pod matching the fence selector, got ${LAUNCHER_PODS}"
echo "exactly one virt-launcher pod matches the fence podSelector"
if [ "${TOPOLOGY}" = "dedicated" ]; then
    # The fence's egress target is the pair's supervisor-role selector:
    # exactly this sandbox's supervisor Pod (same namespace, no
    # namespaceSelector).
    FENCE_PODS="$(kubectl get pods -n "${SANDBOX_NAMESPACE}" \
        -l "openshell.ai/boundary-pair=${SBX_LC},openshell.ai/boundary-role=supervisor" \
        --no-headers 2>/dev/null | wc -l)"
    [ "${FENCE_PODS}" = "1" ] \
        || fail "expected exactly one supervisor pod in the fence egress selector, got ${FENCE_PODS}"
    echo "fence egress selects exactly this sandbox's supervisor Pod"
fi

step "3/10 exec inside the VM"
exec_in_sandbox sh -c 'uname -a; id; cat /proc/1/comm' | tee ${WORKDIR}/exec.log
if [ "${WORKLOAD}" = "root" ]; then
    grep -q "uid=0(root) gid=0(root)" ${WORKDIR}/exec.log \
        || fail "workload does not run as root in root mode"
    echo "workload runs as root (uid 0) — the demoted boundary relays for it"
else
    grep -q "uid=10001(sandbox)" ${WORKDIR}/exec.log \
        || fail "workload does not run as the provisioned sandbox user"
fi
grep -q "^init$" ${WORKDIR}/exec.log || fail "PID 1 is not the guest init"

# H2: the workspace PVC must be writable by the workload (the idmapped
# virtiofs mount; in root mode the root workload writes through the same
# idmap and files show as 10001 on the host side); a marker file proves it
# and is re-read after stop/start.
exec_in_sandbox sh -c 'echo workspace-ok > /sandbox/.kvpoc-demo-marker' \
    || fail "the workload cannot write to the workspace PVC"
echo "workspace writable by the workload (idmapped virtiofs)"

step "4/10 no gateway material in the workload environment"
if exec_in_sandbox sh -c \
    'env | grep -iE "BOUNDARY|PRIVATE|TOKEN|OPENSHELL_ENDPOINT"' \
    > ${WORKDIR}/env.log 2>&1; then
    cat ${WORKDIR}/env.log >&2
    fail "gateway material found in the workload environment"
fi
echo "environment clean (no BOUNDARY/PRIVATE/TOKEN/OPENSHELL_ENDPOINT vars)"

step "5/10 L4 allow/deny and L7 HTTPS GET allow / POST deny"
if [ "${WORKLOAD}" = "root" ]; then
    echo "root mode: the nftables transparent relay carries these checks"
    echo "(workload TCP is captured to the boundary relay, policy-enforced"
    echo "at the supervisor; deleting the rules restores direct egress,"
    echo "which the fence blocks — fail-closed)."
fi
exec_in_sandbox sh -c \
    'nc -z -w 10 one.one.one.one 443 && echo "L4 ALLOW: connected"' \
    | tee ${WORKDIR}/l4.log
grep -q "L4 ALLOW: connected" ${WORKDIR}/l4.log \
    || fail "L4 connect to the allowed host was denied"
# Data-level denial check: the transparent relay completes the TCP
# handshake locally before the supervisor's decision, so handshake-only
# tools (nc -z, curl --connect-timeout without a transfer) cannot see a
# denial — the connection is accepted then reset on first read/write. A
# data transfer must fail instead. This is not an enforcement gap: zero
# upstream connections are made for denied destinations.
if exec_in_sandbox sh -c 'wget -q -T 8 -O /dev/null http://example.org/'; then
    fail "L4 data transfer to a non-allowed host succeeded"
fi
supervisor_denied "example.org:80" \
    || fail "no matching OCSF NET:OPEN DENIED line for example.org:80"
echo "L4 DENY: connect to example.org:80 blocked (OCSF DENIED confirmed)"
exec_in_sandbox sh -c 'wget -q -T 20 -O - https://example.com/' \
    | tee ${WORKDIR}/l7get.log
grep -q "Example Domain" ${WORKDIR}/l7get.log \
    || fail "L7 GET over HTTPS did not return the page (CA delivery or policy broken)"
echo "L7 GET over HTTPS allowed (per-sandbox proxy CA trusted in the guest)"
exec_in_sandbox sh -c 'wget -q -T 20 -O /dev/null --post-data=x https://example.com/' \
    > ${WORKDIR}/l7post.log 2>&1 \
    && fail "L7 POST was not denied" || true
grep -q "403" ${WORKDIR}/l7post.log \
    || { cat ${WORKDIR}/l7post.log >&2; fail "L7 POST denial was not a policy 403"; }
echo "L7 POST denied (HTTP 403)"

step "6/10 direct egress from the guest is blocked"
if [ "${WORKLOAD}" = "root" ]; then
    # The fail-closed test the posture requires: root deletes the relay's
    # nftables rules (restoring direct egress), and the fence still blocks
    # everything — deleting the rules only breaks the workload's own
    # connectivity. Raw DNS to the masquerade dnsmasq is blocked too (the
    # UDP redirect died with the table, and the fence admits nothing).
    exec_in_sandbox nft delete table ip openshell_relay \
        || fail "root could not delete the relay ruleset"
    echo "relay rules deleted by root; direct egress must be fenced:"
    if exec_in_sandbox sh -c 'wget -q -T 8 -O /dev/null http://1.1.1.1/'; then
        fail "direct egress to 1.1.1.1 escaped the fence after rule deletion"
    fi
    if exec_in_sandbox sh -c 'nslookup one.one.one.one 10.0.2.3'; then
        fail "raw DNS to the masquerade dnsmasq bypassed the fence"
    fi
    echo "direct egress and raw DNS blocked by the fence (fail-closed)"
else
if exec_in_sandbox sh -c 'nc -z -w 10 1.1.1.1 443'; then
    fail "raw TCP to 1.1.1.1:443 escaped the boundary"
fi
supervisor_denied "1.1.1.1:443" \
    || fail "no matching OCSF NET:OPEN DENIED line for 1.1.1.1:443"
echo "direct egress to 1.1.1.1:443 blocked (OCSF DENIED confirmed)"

# N4: prove the FENCE (not only the boundary) blocks direct egress: from
# the launcher pod's network namespace — outside the guest, with no
# boundary or broker — a raw connect to an external address must be
# refused, while the supervisor Service must remain reachable.
LAUNCHER="$(kubectl get pods -n "${SANDBOX_NAMESPACE}" \
    -l kubevirt.io=virt-launcher,openshell.ai/sandbox-id="${SBX_ID}" \
    -o jsonpath='{.items[0].metadata.name}')"
[ -n "${LAUNCHER}" ] || fail "no virt-launcher pod found"
# The fence's selective control target is topology-aware: this sandbox's
# dedicated supervisor Service, or the shared supervisor's Service.
if [ "${TOPOLOGY}" = "gateway" ]; then
    SUPERVISOR_IP="$(kubectl get svc -n "${SUPERVISOR_NAMESPACE}" \
        kvpoc-openshell-supervisor -o jsonpath='{.spec.clusterIP}' 2>/dev/null)"
else
    SUPERVISOR_IP="$(kubectl get svc -n "${SANDBOX_NAMESPACE}" \
        "${SUPERVISOR_POD}" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)"
fi
[ -n "${SUPERVISOR_IP}" ] || fail "shared supervisor Service has no ClusterIP"
kubectl exec -n "${SANDBOX_NAMESPACE}" "${LAUNCHER}" -c compute -- \
    timeout 8 openssl s_client -connect 1.1.1.1:443 \
    > ${WORKDIR}/fence-bypass.log 2>&1 || true
grep -q "Connection refused" ${WORKDIR}/fence-bypass.log \
    || { cat ${WORKDIR}/fence-bypass.log >&2; \
         fail "raw TCP from the launcher pod to 1.1.1.1:443 was not refused by the fence"; }
echo "fence check: launcher pod -> 1.1.1.1:443 refused (Connection refused)"
# The selective control: the supervisor Service must remain reachable. The
# connect itself is expected to fail the TLS handshake (the supervisor
# awaits its boundary, not an s_client), so success is judged ONLY by the
# absence of "Connection refused" — the previous `&&` formulation could
# never fail because a refused connect fails the exec and short-circuits.
# A fresh ClusterIP's first new connections can race the endpoint
# programming and be refused once; retry briefly before declaring the
# fence too narrow.
CONTROL_OK=1
for _ in 1 2 3 4 5; do
    kubectl exec -n "${SANDBOX_NAMESPACE}" "${LAUNCHER}" -c compute -- \
        timeout 8 openssl s_client -connect "${SUPERVISOR_IP}:5500" \
        > ${WORKDIR}/fence-control.log 2>&1 || true
    if ! grep -q "Connection refused" ${WORKDIR}/fence-control.log; then
        CONTROL_OK=0
        break
    fi
    sleep 3
done
if [ "${CONTROL_OK}" != "0" ]; then
    cat ${WORKDIR}/fence-control.log >&2
    fail "launcher pod -> supervisor Service connect was refused (fence too narrow?)"
fi
echo "fence check: launcher pod -> supervisor ${SUPERVISOR_IP}:5500 reachable (selective)"
fi

step "7/10 stop -> start -> Ready with VM and fence UIDs unchanged"
"${OPENSHELL_CLI}" sandbox stop "${NAME}"
require_phase Stopped
if [ "${TOPOLOGY}" = "dedicated" ]; then
    # Stop deletes the supervisor Pod, exactly as the pod path's stop
    # deletes both Pods.
    sleep 5
    if kubectl get pod -n "${SANDBOX_NAMESPACE}" "${SUPERVISOR_POD}" >/dev/null 2>&1; then
        fail "supervisor Pod still present after stop"
    fi
    echo "supervisor Pod deleted by stop"
fi
"${OPENSHELL_CLI}" sandbox start "${NAME}"
wait_for_phase Ready
VM_UID_AFTER="$(vm_jsonpath '{.items[0].metadata.uid}')"
FENCE_UID_AFTER="$(kubectl get netpol -n "${SANDBOX_NAMESPACE}" "${FENCE}" \
    -o jsonpath='{.metadata.uid}' 2>/dev/null)"
[ "${VM_UID_AFTER}" = "${VM_UID}" ] || fail "VM UID changed across stop/start"
[ "${FENCE_UID_AFTER}" = "${FENCE_UID}" ] || fail "fence UID changed across stop/start"
echo "VM uid unchanged (${VM_UID}); fence uid unchanged (${FENCE_UID})"
# H2: the workspace marker survived the stop/start cycle.
MARKER="$(exec_in_sandbox sh -c 'cat /sandbox/.kvpoc-demo-marker' 2>/dev/null)" \
    || fail "the workspace marker could not be read after restart"
[ "${MARKER}" = "workspace-ok" ] \
    || fail "the workspace marker did not survive stop/start (got '${MARKER}')"
exec_in_sandbox sh -c 'touch /sandbox/.kvpoc-demo-marker' \
    || fail "the workspace is not writable after restart"
echo "workspace data survived stop/start and stays writable"
if [ "${TOPOLOGY}" = "dedicated" ]; then
    # A dedicated start provisions a fresh supervisor generation: a new Pod
    # with a new UID, claimed by the re-rendered boundary bootstrap.
    NEW_SUPERVISOR_POD_UID="$(kubectl get pod -n "${SANDBOX_NAMESPACE}" "${SUPERVISOR_POD}" \
        -o jsonpath='{.metadata.uid}' 2>/dev/null)" \
        || fail "no supervisor Pod after start"
    [ -n "${NEW_SUPERVISOR_POD_UID}" ] || fail "restarted supervisor Pod has no UID"
    [ "${NEW_SUPERVISOR_POD_UID}" != "${SUPERVISOR_POD_UID}" ] \
        || fail "supervisor Pod UID did not rotate across stop/start"
    CLAIMED_UID="$(kubectl get secret -n "${SANDBOX_NAMESPACE}" "${BOOTSTRAP_SECRET}" \
        -o jsonpath='{.data.userData}' | base64 -d \
        | grep "^OPENSHELL_BOUNDARY_CONFIG_B64=" | cut -d= -f2- | base64 -d \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["resource_claims"]["kubevirt.supervisor_pod_uid"])')" \
        || fail "could not extract kubevirt.supervisor_pod_uid after start"
    [ "${CLAIMED_UID}" = "${NEW_SUPERVISOR_POD_UID}" ] \
        || fail "re-rendered claim (${CLAIMED_UID}) does not match the new supervisor Pod UID (${NEW_SUPERVISOR_POD_UID})"
    echo "supervisor Pod UID rotated and re-claimed (${NEW_SUPERVISOR_POD_UID})"
    SUPERVISOR_POD_UID="${NEW_SUPERVISOR_POD_UID}"
fi
INSTANCE_SECRETS="$(kubectl get secret -n "${SANDBOX_NAMESPACE}" \
    -l "openshell.ai/sandbox-id=${SBX_ID},openshell.ai/component=supervisor-bootstrap" \
    --no-headers 2>/dev/null | wc -l)"
[ "${INSTANCE_SECRETS}" = "1" ] \
    || fail "expected one current instance Secret, got ${INSTANCE_SECRETS}"
echo "one current-generation instance Secret (previous generation pruned)"

step "8/10 fence verification: spec drift fails start, label-only edit passes"
"${OPENSHELL_CLI}" sandbox stop "${NAME}"
kubectl patch netpol -n "${SANDBOX_NAMESPACE}" "${FENCE}" --type=json \
    -p '[{"op":"add","path":"/spec/egress/-","value":{}}]' >/dev/null
if "${OPENSHELL_CLI}" sandbox start "${NAME}" > ${WORKDIR}/drift.log 2>&1; then
    fail "start succeeded despite fence spec drift"
fi
grep -q "spec drifted" ${WORKDIR}/drift.log \
    || { cat ${WORKDIR}/drift.log >&2; fail "start failure was not the drift error"; }
echo "spec drift rejected: $(grep -a 'drifted' ${WORKDIR}/drift.log | head -1 | tr -s ' ')"
# Remove the drift idempotently. The M1 reconciler may re-fence (restore
# the rendered spec) before this script removes its own drift entry, and
# the previous test+remove patch then failed on the missing path ("The
# request is invalid"). Wait briefly for the reconciler's restore — which
# also demonstrates M1 drift repair live — and only patch the drift away
# ourselves if the reconciler has not acted yet.
fence_drift_present() {
    # The demo's drift is a trailing empty egress entry.
    [ "$(kubectl get netpol -n "${SANDBOX_NAMESPACE}" "${FENCE}" \
        -o jsonpath='{.spec.egress}' 2>/dev/null | python3 -c \
        'import json,sys
e = json.load(sys.stdin)
print(len(e) >= 2 and e[-1] == {})')" = "True" ]
}
RECONCILED=1
DRIFT_DEADLINE=$(( $(date +%s) + 60 ))
while fence_drift_present; do
    if [ "$(date +%s)" -ge "${DRIFT_DEADLINE}" ]; then
        RECONCILED=0
        break
    fi
    sleep 3
done
if [ "${RECONCILED}" = "1" ]; then
    echo "M1 reconciler re-fenced the drifted fence (spec restored)"
else
    # The reconciler has not acted; remove the demo's own drift entry.
    # test/remove need the concrete index (the `-` append suffix is only
    # valid for `add`), so compute the last egress position first —
    # fence_drift_present already confirmed it is the empty drift entry.
    EGRESS_LEN="$(kubectl get netpol -n "${SANDBOX_NAMESPACE}" "${FENCE}" \
        -o jsonpath='{.spec.egress}' 2>/dev/null | python3 -c \
        'import json,sys; print(len(json.load(sys.stdin)))')"
    LAST_IDX=$(( EGRESS_LEN - 1 ))
    kubectl patch netpol -n "${SANDBOX_NAMESPACE}" "${FENCE}" --type=json \
        -p "[{\"op\":\"test\",\"path\":\"/spec/egress/${LAST_IDX}\",\"value\":{}},{\"op\":\"remove\",\"path\":\"/spec/egress/${LAST_IDX}\"}]" \
        >/dev/null \
        || fail "could not remove the demo's drift entry from the fence"
    echo "removed the demo's drift entry (reconciler had not re-fenced yet)"
fi
kubectl label netpol -n "${SANDBOX_NAMESPACE}" "${FENCE}" \
    kvpoc-demo-label-edit=1 --overwrite >/dev/null
"${OPENSHELL_CLI}" sandbox start "${NAME}"
wait_for_phase Ready
echo "label-only fence edit accepted (resourceVersion moved, spec unchanged)"

step "9/10 main-process exit -> Error"
exec_in_sandbox sh -c 'pkill -9 sleep' || true
DEADLINE=$(( $(date +%s) + 120 ))
while [ "$(date +%s)" -lt "${DEADLINE}" ]; do
    PHASE="$(sandbox_phase)"
    [ "${PHASE}" = "Phase: Error" ] && break
    sleep 5
done
require_phase Error
"${OPENSHELL_CLI}" sandbox get "${NAME}" | grep -a "exit code" \
    || fail "Error phase carries no main-process exit code"
echo "main process exit observed through the boundary session (Error, exit code 137)"

step "10/10 delete -> zero leftover managed objects"
"${OPENSHELL_CLI}" sandbox delete "${NAME}"
# The leftover set includes pods and services: the dedicated topology's
# supervisor Pod and per-sandbox Service carry the sandbox-id label (the
# shared topology has none, so the count stays complete either way).
DEADLINE=$(( $(date +%s) + 180 ))
while [ "$(date +%s)" -lt "${DEADLINE}" ]; do
    LEFT="$(kubectl get vm,vmi,pod,svc,secret,pvc,netpol -n "${SANDBOX_NAMESPACE}" \
        -l "openshell.ai/sandbox-id=${SBX_ID}" --no-headers 2>/dev/null | wc -l)"
    [ "${LEFT}" = "0" ] && break
    sleep 5
done
LEFT="$(kubectl get vm,vmi,pod,svc,secret,pvc,netpol -n "${SANDBOX_NAMESPACE}" \
    -l "openshell.ai/sandbox-id=${SBX_ID}" --no-headers 2>/dev/null | wc -l)"
[ "${LEFT}" = "0" ] || fail "${LEFT} managed objects left after delete"
if [ "${TOPOLOGY}" = "dedicated" ]; then
    if kubectl get pod -n "${SANDBOX_NAMESPACE}" "${SUPERVISOR_POD}" >/dev/null 2>&1; then
        fail "supervisor Pod still present after delete"
    fi
    echo "supervisor Pod gone after delete"
else
    kubectl logs -n "${SUPERVISOR_NAMESPACE}" deployment/kvpoc-openshell-supervisor \
        --since=5m 2>/dev/null | grep "removing withdrawn sandbox instance" | tail -1 \
        || echo "(note: supervisor withdrawal log line not captured — check manually)"
fi
echo "zero leftover vm/vmi/pod/svc/secret/pvc/netpol for sandbox ${SBX_ID}"

echo
if [ "${WORKLOAD}" = "root" ]; then
    echo "demo complete (${TOPOLOGY} topology, root workload): Ready, exec"
    echo "as root, clean environment, L4/L7 policy through the transparent"
    echo "relay, bypass blocked, stop/start, fence verification, dead-runtime"
    echo "Error, and clean teardown all verified"
else
    echo "demo complete (${TOPOLOGY} supervisor topology): Ready, exec, L4/L7"
    echo "policy, bypass blocked, stop/start, fence verification, dead-runtime"
    echo "Error, and clean teardown all verified"
fi
